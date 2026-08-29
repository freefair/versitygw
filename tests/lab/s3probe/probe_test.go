// Copyright 2026 Versity Software
// This file is licensed under the Apache License, Version 2.0.

package main

import (
	"path/filepath"
	"testing"
	"time"
)

func TestObjectVersionPathMatchesPOSIXLayout(t *testing.T) {
	path := objectVersionPath("/versions", "bucket", "dir/object", "01K123")
	want := filepath.Join("/versions", "bucket", "3a", "ae", "4b", "3aae4bf56df2dffd7a82102bec3c4aacccada640082fba55b0ce1fcf20b02760", "01K123")
	if path != want {
		t.Fatalf("objectVersionPath() = %q, want %q", path, want)
	}
}

func TestPastLifecycleDateIsPreviousMidnightUTC(t *testing.T) {
	now := time.Date(2026, time.August, 28, 17, 42, 11, 0, time.FixedZone("CEST", 2*60*60))
	want := time.Date(2026, time.August, 27, 0, 0, 0, 0, time.UTC)
	if got := pastLifecycleDate(now); !got.Equal(want) {
		t.Fatalf("pastLifecycleDate() = %s, want %s", got, want)
	}
}

func TestRetainedVersionIDsRequireCurrentAndNewestNoncurrentVersions(t *testing.T) {
	written := []string{"v1", "v2", "v3", "v4"}
	if err := requireRetainedVersionIDs(written, []string{"v4", "v3", "v2"}, 2); err != nil {
		t.Fatalf("requireRetainedVersionIDs() error = %v", err)
	}
	if err := requireRetainedVersionIDs(written, []string{"v4", "v2", "v1"}, 2); err == nil {
		t.Fatal("requireRetainedVersionIDs() accepted the wrong retained versions")
	}
}
