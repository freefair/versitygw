// Copyright 2026 Versity Software
// This file is licensed under the Apache License, Version 2.0.

package embedgw

import (
	"context"
	"errors"
	"log"

	"github.com/versity/versitygw/internal/lifecycle"
	"github.com/versity/versitygw/metrics"
	"github.com/versity/versitygw/s3event"
)

type lifecycleObserver struct {
	ctx     context.Context
	backend string
	region  string
	metrics metrics.BackgroundManager
	events  s3event.S3EventSender
}

func newLifecycleObserver(ctx context.Context, backend, region string, manager metrics.Manager, events s3event.S3EventSender) lifecycleObserver {
	background, _ := manager.(metrics.BackgroundManager)
	return lifecycleObserver{ctx: ctx, backend: backend, region: region, metrics: background, events: events}
}

func (observer lifecycleObserver) ObserveAction(result lifecycle.ActionResult) {
	outcome := "applied"
	switch {
	case result.DryRun:
		outcome = "dry_run"
	case errors.Is(result.Error, lifecycle.ErrConflict):
		outcome = "conflict"
	case result.Error != nil:
		outcome = "failed"
	}
	tags := []metrics.Tag{
		{Key: "backend", Value: observer.backend},
		{Key: "action", Value: string(result.Action.Kind)},
		{Key: "storage_class", Value: result.Action.TargetStorageClass},
		{Key: "outcome", Value: outcome},
	}
	observer.metric("lifecycle_actions_total", 1, tags...)
	if outcome == "applied" {
		switch result.Action.Kind {
		case lifecycle.ActionTransition:
			observer.metric("lifecycle_bytes_transitioned", result.Action.Size, tags...)
		case lifecycle.ActionDeleteVersion:
			observer.metric("lifecycle_versions_expired", 1, tags...)
		case lifecycle.ActionAbortMultipart:
			observer.metric("lifecycle_multipart_uploads_aborted", 1, tags...)
		}
		observer.sendRemovalEvent(result.Action)
	}
	log.Printf("lifecycle audit actor=versitygw:lifecycle backend=%q bucket=%q key=%q version=%q rule=%q action=%q outcome=%q", observer.backend, result.Action.Bucket, result.Action.Key, result.Action.VersionID, result.Action.RuleID, result.Action.Kind, outcome)
}

func (observer lifecycleObserver) ObserveScan(result lifecycle.ScanResult) {
	tags := []metrics.Tag{{Key: "backend", Value: observer.backend}, {Key: "outcome", Value: "success"}}
	if result.Error != nil {
		tags[1].Value = "failed"
	}
	observer.metric("lifecycle_scan_duration_ms", result.Duration.Milliseconds(), tags...)
	observer.metric("lifecycle_candidates_evaluated", result.Candidates, tags...)
	observer.metric("lifecycle_actions_eligible", result.Eligible, tags...)
	observer.metric("lifecycle_actions_protected", result.Protected, tags...)
	if result.LeaseContended {
		observer.metric("lifecycle_lease_contention", 1, metrics.Tag{Key: "backend", Value: observer.backend})
	}
	if result.Error != nil {
		observer.metric("lifecycle_scan_failures", 1, metrics.Tag{Key: "backend", Value: observer.backend})
	}
}

func (observer lifecycleObserver) metric(name string, value int64, tags ...metrics.Tag) {
	if observer.metrics != nil {
		observer.metrics.SendBackground(observer.ctx, name, value, tags...)
	}
}

func (observer lifecycleObserver) sendRemovalEvent(action lifecycle.Action) {
	if observer.events == nil {
		return
	}
	eventName := s3event.EventType("")
	switch action.Kind {
	case lifecycle.ActionDeleteCurrent, lifecycle.ActionDeleteVersion:
		eventName = s3event.EventObjectRemovedDelete
	case lifecycle.ActionCreateDeleteMarker, lifecycle.ActionExpireSuspendedCurrent:
		eventName = s3event.EventObjectRemovedDeleteMarkerCreated
	default:
		return
	}
	var versionID *string
	if action.VersionID != "" {
		value := action.VersionID
		versionID = &value
	}
	observer.events.SendBackgroundEvent(observer.ctx, s3event.BackgroundEventMeta{
		EventMeta: s3event.EventMeta{EventName: eventName, ObjectSize: action.Size, VersionId: versionID},
		Region:    observer.region, Bucket: action.Bucket, Key: action.Key,
		PrincipalID: "versitygw:lifecycle",
	})
}
