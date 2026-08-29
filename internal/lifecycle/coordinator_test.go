// Copyright 2026 Versity Software
// This file is licensed under the Apache License, Version 2.0.

package lifecycle

import (
	"context"
	"errors"
	"io"
	"testing"
	"time"
)

type fixedClock struct{ now time.Time }

func (clock fixedClock) Now() time.Time { return clock.now }

type testStore struct{ configuration Configuration }

func (store testStore) GetLifecycleConfiguration(context.Context, string) (Configuration, error) {
	return store.configuration, nil
}

type testExecutor struct {
	pages             []Page
	applied           []Action
	closed            int
	reconciliation    []string
	reconciledBuckets []string
	leaseErr          error
	closeErr          error
}

func (executor *testExecutor) ListLifecycleBuckets(context.Context) ([]string, error) {
	return []string{"bucket"}, nil
}
func (executor *testExecutor) AcquireLifecycleLease(context.Context, string) (io.Closer, error) {
	if executor.leaseErr != nil {
		return nil, executor.leaseErr
	}
	return closerFunc(func() error { executor.closed++; return executor.closeErr }), nil
}

func TestCoordinatorObservesScanCountsAndLeaseContention(t *testing.T) {
	t.Parallel()
	now := time.Date(2026, 8, 28, 12, 0, 0, 0, time.UTC)
	days := int32(1)
	executor := &testExecutor{pages: []Page{{Candidates: []Candidate{
		{Kind: CandidateObject, Bucket: "bucket", Key: "eligible", Current: true, Size: 42, LastModified: now.Add(-72 * time.Hour)},
		{Kind: CandidateObject, Bucket: "bucket", Key: "protected", Current: true, Protected: true, LastModified: now.Add(-72 * time.Hour)},
	}}}}
	var observed ScanResult
	coordinator := Coordinator{
		Store:    testStore{configuration: Configuration{Rules: []Rule{{Filter: &Filter{}, Status: "Enabled", Expiration: &Expiration{Days: &days}}}}},
		Executor: executor, Clock: fixedClock{now: now}, ObserveScan: func(result ScanResult) { observed = result },
	}
	if err := coordinator.RunOnce(context.Background()); err != nil {
		t.Fatal(err)
	}
	if observed.Candidates != 2 || observed.Protected != 1 || observed.Eligible != 1 || observed.Duration <= 0 || observed.Error != nil {
		t.Fatalf("scan observation = %#v", observed)
	}
	if len(executor.applied) != 1 || executor.applied[0].Size != 42 {
		t.Fatalf("applied actions = %#v", executor.applied)
	}

	executor.leaseErr = ErrLeaseUnavailable
	if err := coordinator.RunOnce(context.Background()); err != nil {
		t.Fatal(err)
	}
	if !observed.LeaseContended || observed.Error != nil {
		t.Fatalf("lease contention observation = %#v", observed)
	}
	executor.leaseErr = errors.New("lease failure")
	if err := coordinator.RunOnce(context.Background()); err == nil {
		t.Fatal("RunOnce() succeeded with a lease failure")
	}
	if observed.Error == nil || observed.LeaseContended {
		t.Fatalf("lease failure observation = %#v", observed)
	}
}
func (executor *testExecutor) ListLifecycleCandidates(_ context.Context, _ string, cursor Cursor, _ int32) (Page, error) {
	index := 0
	if cursor.Phase == "second" {
		index = 1
	}
	return executor.pages[index], nil
}
func (executor *testExecutor) ApplyLifecycleAction(_ context.Context, action Action) error {
	executor.applied = append(executor.applied, action)
	return nil
}

func (executor *testExecutor) ListLifecycleReconciliationBuckets(context.Context) ([]string, error) {
	return executor.reconciliation, nil
}

func (executor *testExecutor) ReconcileLifecycle(_ context.Context, bucket string) error {
	executor.reconciledBuckets = append(executor.reconciledBuckets, bucket)
	return nil
}

type closerFunc func() error

func (closer closerFunc) Close() error { return closer() }

func TestCoordinatorRunsCatchUpAcrossPagesUnderOneLease(t *testing.T) {
	t.Parallel()

	now := time.Date(2026, 8, 28, 12, 0, 0, 0, time.UTC)
	days := int32(1)
	store := testStore{configuration: Configuration{Rules: []Rule{{Filter: &Filter{}, Status: "Enabled", Expiration: &Expiration{Days: &days}}}}}
	executor := &testExecutor{pages: []Page{
		{Candidates: []Candidate{{Kind: CandidateObject, Bucket: "bucket", Key: "first", Current: true, LastModified: now.Add(-72 * time.Hour)}}, Next: &Cursor{Phase: "second"}},
		{Candidates: []Candidate{{Kind: CandidateObject, Bucket: "bucket", Key: "second", Current: true, LastModified: now.Add(-72 * time.Hour)}}},
	}}
	coordinator := Coordinator{Store: store, Executor: executor, Clock: fixedClock{now: now}}
	if err := coordinator.RunOnce(context.Background()); err != nil {
		t.Fatalf("RunOnce() error = %v", err)
	}
	if len(executor.applied) != 2 || executor.closed != 1 {
		t.Fatalf("applied=%#v closed=%d", executor.applied, executor.closed)
	}
}

func TestCoordinatorReturnsLifecycleLeaseReleaseFailure(t *testing.T) {
	t.Parallel()

	closeErr := errors.New("release failed")
	executor := &testExecutor{pages: []Page{{}}, closeErr: closeErr}
	var observed ScanResult
	coordinator := Coordinator{
		Store:       testStore{},
		Executor:    executor,
		ObserveScan: func(result ScanResult) { observed = result },
	}
	err := coordinator.RunOnce(context.Background())
	if !errors.Is(err, closeErr) {
		t.Fatalf("RunOnce() error = %v, want lease release failure", err)
	}
	if !errors.Is(observed.Error, closeErr) {
		t.Fatalf("observed scan error = %v, want lease release failure", observed.Error)
	}
}

func TestCoordinatorDryRunDoesNotMutate(t *testing.T) {
	t.Parallel()

	now := time.Date(2026, 8, 28, 12, 0, 0, 0, time.UTC)
	days := int32(1)
	executor := &testExecutor{pages: []Page{{Candidates: []Candidate{{Kind: CandidateObject, Key: "key", Current: true, LastModified: now.Add(-72 * time.Hour)}}}}}
	observed := 0
	coordinator := Coordinator{
		Store:    testStore{configuration: Configuration{Rules: []Rule{{Filter: &Filter{}, Status: "Enabled", Expiration: &Expiration{Days: &days}}}}},
		Executor: executor, Clock: fixedClock{now: now}, DryRun: true,
		Observe: func(result ActionResult) {
			if result.DryRun {
				observed++
			}
		},
	}
	if err := coordinator.RunOnce(context.Background()); err != nil {
		t.Fatal(err)
	}
	if len(executor.applied) != 0 || observed != 1 {
		t.Fatalf("applied=%d observed=%d", len(executor.applied), observed)
	}
}

func TestCoordinatorReconcilesArchiveBucketWithoutLifecycleConfiguration(t *testing.T) {
	t.Parallel()

	executor := &testExecutor{
		pages:          []Page{{}},
		reconciliation: []string{"bucket", "archive-only"},
	}
	coordinator := Coordinator{Store: testStore{}, Executor: executor}
	if err := coordinator.RunOnce(context.Background()); err != nil {
		t.Fatalf("RunOnce() error = %v", err)
	}
	if len(executor.reconciledBuckets) != 2 || executor.reconciledBuckets[0] != "bucket" || executor.reconciledBuckets[1] != "archive-only" {
		t.Fatalf("reconciled buckets = %#v", executor.reconciledBuckets)
	}
	if executor.closed != 2 {
		t.Fatalf("closed leases = %d, want 2", executor.closed)
	}
}
