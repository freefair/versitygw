// Copyright 2026 Versity Software
// This file is licensed under the Apache License, Version 2.0.

package embedgw

import (
	"context"
	"testing"
	"time"

	"github.com/gofiber/fiber/v3"
	"github.com/versity/versitygw/internal/lifecycle"
	"github.com/versity/versitygw/metrics"
	"github.com/versity/versitygw/s3event"
)

type lifecycleMetricPoint struct {
	name  string
	value int64
	tags  []metrics.Tag
}

type lifecycleMetricRecorder struct{ points []lifecycleMetricPoint }

func (recorder *lifecycleMetricRecorder) Send(fiber.Ctx, error, string, int64, int) {}
func (recorder *lifecycleMetricRecorder) Close()                                    {}
func (recorder *lifecycleMetricRecorder) SendBackground(_ context.Context, name string, value int64, tags ...metrics.Tag) {
	recorder.points = append(recorder.points, lifecycleMetricPoint{name: name, value: value, tags: tags})
}

type lifecycleEventRecorder struct{ events []s3event.BackgroundEventMeta }

func (recorder *lifecycleEventRecorder) SendEvent(fiber.Ctx, s3event.EventMeta) {}
func (recorder *lifecycleEventRecorder) SendBackgroundEvent(_ context.Context, meta s3event.BackgroundEventMeta) {
	recorder.events = append(recorder.events, meta)
}
func (recorder *lifecycleEventRecorder) Close() error { return nil }

func TestLifecycleObserverRecordsMetricsAndServiceEvent(t *testing.T) {
	metricRecorder := &lifecycleMetricRecorder{}
	eventRecorder := &lifecycleEventRecorder{}
	observer := newLifecycleObserver(context.Background(), "Posix Gateway", "us-east-1", metricRecorder, eventRecorder)
	action := lifecycle.Action{Kind: lifecycle.ActionDeleteVersion, Bucket: "bucket", Key: "object", VersionID: "version", RuleID: "rule", Size: 42}
	observer.ObserveAction(lifecycle.ActionResult{Action: action})
	observer.ObserveScan(lifecycle.ScanResult{Duration: 1500 * time.Millisecond, Candidates: 3, Protected: 1, Eligible: 1, LeaseContended: true})

	if len(eventRecorder.events) != 1 {
		t.Fatalf("background events = %#v", eventRecorder.events)
	}
	event := eventRecorder.events[0]
	if event.PrincipalID != "versitygw:lifecycle" || event.EventName != s3event.EventObjectRemovedDelete || event.Bucket != "bucket" || event.Key != "object" {
		t.Fatalf("background event = %#v", event)
	}
	foundVersions, foundContention := false, false
	for _, point := range metricRecorder.points {
		if point.name == "lifecycle_versions_expired" && point.value == 1 {
			foundVersions = true
		}
		if point.name == "lifecycle_lease_contention" && point.value == 1 {
			foundContention = true
		}
		for _, tag := range point.tags {
			if tag.Key == "bucket" || tag.Key == "key" {
				t.Fatalf("unbounded metric tag = %#v", tag)
			}
		}
	}
	if !foundVersions || !foundContention {
		t.Fatalf("metrics = %#v", metricRecorder.points)
	}
}

func TestLifecycleObserverDoesNotEmitDryRunEvent(t *testing.T) {
	events := &lifecycleEventRecorder{}
	observer := newLifecycleObserver(context.Background(), "Posix Gateway", "us-east-1", &lifecycleMetricRecorder{}, events)
	observer.ObserveAction(lifecycle.ActionResult{Action: lifecycle.Action{Kind: lifecycle.ActionDeleteCurrent, Bucket: "bucket", Key: "key"}, DryRun: true})
	if len(events.events) != 0 {
		t.Fatalf("dry-run events = %#v", events.events)
	}
}
