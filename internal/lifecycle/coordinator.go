// Copyright 2026 Versity Software
// This file is licensed under the Apache License, Version 2.0.

package lifecycle

import (
	"context"
	"errors"
	"fmt"
	"time"
)

type Clock interface {
	Now() time.Time
}

type realClock struct{}

func (realClock) Now() time.Time { return time.Now() }

type ActionResult struct {
	Action Action
	DryRun bool
	Error  error
}

type ScanResult struct {
	Bucket         string
	Duration       time.Duration
	Candidates     int64
	Protected      int64
	Eligible       int64
	LeaseContended bool
	Error          error
}

type Coordinator struct {
	Store       ConfigurationStore
	Executor    Executor
	Clock       Clock
	PageSize    int32
	DryRun      bool
	Observe     func(ActionResult)
	ObserveScan func(ScanResult)
	OnScanError func(error)
}

func (coordinator *Coordinator) Run(ctx context.Context, interval time.Duration) error {
	if interval <= 0 {
		return fmt.Errorf("lifecycle interval must be positive")
	}
	if err := coordinator.RunOnce(ctx); err != nil && ctx.Err() == nil {
		coordinator.scanError(err)
	}
	ticker := time.NewTicker(interval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return nil
		case <-ticker.C:
			if err := coordinator.RunOnce(ctx); err != nil && ctx.Err() == nil {
				coordinator.scanError(err)
			}
		}
	}
}

func (coordinator *Coordinator) RunOnce(ctx context.Context) error {
	if coordinator.Store == nil || coordinator.Executor == nil {
		return fmt.Errorf("lifecycle coordinator requires store and executor")
	}
	buckets, err := coordinator.Executor.ListLifecycleBuckets(ctx)
	if err != nil {
		return fmt.Errorf("list lifecycle buckets: %w", err)
	}
	var scanErrors []error
	configuredBuckets := make(map[string]struct{}, len(buckets))
	for _, bucket := range buckets {
		configuredBuckets[bucket] = struct{}{}
		if err := coordinator.scanBucket(ctx, bucket); err != nil {
			scanErrors = append(scanErrors, fmt.Errorf("scan bucket %q: %w", bucket, err))
		}
	}
	if source, ok := coordinator.Executor.(ReconciliationSource); ok {
		reconciler, supportsReconciliation := coordinator.Executor.(Reconciler)
		if !supportsReconciliation {
			scanErrors = append(scanErrors, fmt.Errorf("lifecycle reconciliation source requires a reconciler"))
			return errors.Join(scanErrors...)
		}
		reconciliationBuckets, err := source.ListLifecycleReconciliationBuckets(ctx)
		if err != nil {
			scanErrors = append(scanErrors, fmt.Errorf("list lifecycle reconciliation buckets: %w", err))
			return errors.Join(scanErrors...)
		}
		for _, bucket := range reconciliationBuckets {
			if _, configured := configuredBuckets[bucket]; configured {
				continue
			}
			if err := coordinator.reconcileBucket(ctx, bucket, reconciler); err != nil {
				scanErrors = append(scanErrors, fmt.Errorf("reconcile bucket %q: %w", bucket, err))
			}
		}
	}
	return errors.Join(scanErrors...)
}

func (coordinator *Coordinator) scanBucket(ctx context.Context, bucket string) (returnErr error) {
	started := time.Now()
	result := ScanResult{Bucket: bucket}
	defer func() {
		result.Duration = time.Since(started)
		result.Error = returnErr
		coordinator.observeScan(result)
	}()
	lease, err := coordinator.Executor.AcquireLifecycleLease(ctx, bucket)
	if errors.Is(err, ErrLeaseUnavailable) {
		result.LeaseContended = true
		return nil
	}
	if err != nil {
		return fmt.Errorf("acquire lease: %w", err)
	}
	defer func() {
		if err := lease.Close(); err != nil {
			returnErr = errors.Join(returnErr, fmt.Errorf("release lifecycle lease: %w", err))
		}
	}()
	if reconciler, ok := coordinator.Executor.(Reconciler); ok {
		if err := reconciler.ReconcileLifecycle(ctx, bucket); err != nil {
			return fmt.Errorf("reconcile lifecycle state: %w", err)
		}
	}

	configuration, err := coordinator.Store.GetLifecycleConfiguration(ctx, bucket)
	if err != nil {
		return fmt.Errorf("load configuration: %w", err)
	}
	pageSize := coordinator.PageSize
	if pageSize <= 0 {
		pageSize = 1000
	}
	cursor := Cursor{}
	for {
		page, err := coordinator.Executor.ListLifecycleCandidates(ctx, bucket, cursor, pageSize)
		if err != nil {
			return fmt.Errorf("list candidates: %w", err)
		}
		result.Candidates += int64(len(page.Candidates))
		for _, candidate := range page.Candidates {
			if candidate.Protected {
				result.Protected++
			}
		}
		actions := Evaluate(configuration, page.Candidates, coordinator.now())
		result.Eligible += int64(len(actions))
		for _, action := range actions {
			if err := ctx.Err(); err != nil {
				return err
			}
			if coordinator.DryRun {
				coordinator.observe(ActionResult{Action: action, DryRun: true})
				continue
			}
			err := coordinator.Executor.ApplyLifecycleAction(ctx, action)
			coordinator.observe(ActionResult{Action: action, Error: err})
			if errors.Is(err, ErrConflict) {
				continue
			}
			if err != nil {
				return fmt.Errorf("apply %s to %q: %w", action.Kind, action.Key, err)
			}
		}
		if page.Next == nil {
			return nil
		}
		cursor = *page.Next
	}
}

func (coordinator *Coordinator) reconcileBucket(ctx context.Context, bucket string, reconciler Reconciler) (returnErr error) {
	lease, err := coordinator.Executor.AcquireLifecycleLease(ctx, bucket)
	if errors.Is(err, ErrLeaseUnavailable) {
		return nil
	}
	if err != nil {
		return fmt.Errorf("acquire lease: %w", err)
	}
	defer func() {
		if err := lease.Close(); err != nil {
			returnErr = errors.Join(returnErr, fmt.Errorf("release lifecycle lease: %w", err))
		}
	}()
	if err := reconciler.ReconcileLifecycle(ctx, bucket); err != nil {
		return fmt.Errorf("reconcile lifecycle state: %w", err)
	}
	return nil
}

func (coordinator *Coordinator) now() time.Time {
	if coordinator.Clock == nil {
		return realClock{}.Now()
	}
	return coordinator.Clock.Now()
}

func (coordinator *Coordinator) observe(result ActionResult) {
	if coordinator.Observe != nil {
		coordinator.Observe(result)
	}
}

func (coordinator *Coordinator) observeScan(result ScanResult) {
	if coordinator.ObserveScan != nil {
		coordinator.ObserveScan(result)
	}
}

func (coordinator *Coordinator) scanError(err error) {
	if coordinator.OnScanError != nil {
		coordinator.OnScanError(err)
	}
}
