// Copyright 2026 Versity Software
// This file is licensed under the Apache License, Version 2.0.

package metrics

import (
	"context"
	"testing"
)

func TestBackgroundMetricsDoNotRequireFiberContext(t *testing.T) {
	manager := &manager{ctx: context.Background(), addDataChan: make(chan datapoint, 1)}
	manager.SendBackground(context.Background(), "lifecycle_actions", 1, Tag{Key: "outcome", Value: "applied"})
	point := <-manager.addDataChan
	if point.key != "lifecycle_actions" || point.value != 1 || len(point.tags) != 1 || point.tags[0].Value != "applied" {
		t.Fatalf("background metric = %#v", point)
	}
}
