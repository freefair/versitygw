//go:build !windows

// Copyright 2026 Versity Software
// This file is licensed under the Apache License, Version 2.0.

package posix

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"testing"
)

func TestAtomicFileLockContendsAndReleases(t *testing.T) {
	path := filepath.Join(t.TempDir(), "object.lock")
	owner := atomicLockOwner{Hostname: "node-a", BootID: "boot-a", PID: 10, Nonce: "first"}
	first, err := acquireAtomicFileLockWithOwner(context.Background(), path, false, owner, func(int) bool { return true })
	if err != nil {
		t.Fatal(err)
	}
	contender := atomicLockOwner{Hostname: "node-b", BootID: "boot-b", PID: 20, Nonce: "second"}
	if _, err := acquireAtomicFileLockWithOwner(context.Background(), path, false, contender, func(int) bool { return true }); !errors.Is(err, errAtomicLockHeld) {
		t.Fatalf("contender error = %v, want held", err)
	}
	if err := first.Close(); err != nil {
		t.Fatal(err)
	}
	second, err := acquireAtomicFileLockWithOwner(context.Background(), path, false, contender, func(int) bool { return true })
	if err != nil {
		t.Fatalf("acquire after release: %v", err)
	}
	if err := second.Close(); err != nil {
		t.Fatal(err)
	}
}

func TestAtomicFileLockRecoversOnlyDeadLocalOwner(t *testing.T) {
	path := filepath.Join(t.TempDir(), "object.lock")
	dead := atomicLockOwner{Hostname: "node-a", BootID: "boot-a", PID: 10, Nonce: "dead"}
	if _, err := acquireAtomicFileLockWithOwner(context.Background(), path, false, dead, func(int) bool { return true }); err != nil {
		t.Fatal(err)
	}
	current := atomicLockOwner{Hostname: "node-a", BootID: "boot-a", PID: 20, Nonce: "current"}
	lease, err := acquireAtomicFileLockWithOwner(context.Background(), path, false, current, func(pid int) bool { return pid != dead.PID })
	if err != nil {
		t.Fatalf("recover dead local owner: %v", err)
	}
	if err := lease.Close(); err != nil {
		t.Fatal(err)
	}
}

func TestAtomicFileLockDoesNotRecoverAmbiguousOwner(t *testing.T) {
	for _, existing := range []atomicLockOwner{
		{Hostname: "node-b", BootID: "boot-b", PID: 10, Nonce: "remote"},
		{Hostname: "node-a", BootID: "old-boot", PID: 10, Nonce: "old-boot"},
	} {
		t.Run(existing.Nonce, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "object.lock")
			if _, err := acquireAtomicFileLockWithOwner(context.Background(), path, false, existing, func(int) bool { return true }); err != nil {
				t.Fatal(err)
			}
			current := atomicLockOwner{Hostname: "node-a", BootID: "boot-a", PID: 20, Nonce: "current"}
			if _, err := acquireAtomicFileLockWithOwner(context.Background(), path, false, current, func(int) bool { return false }); !errors.Is(err, errAtomicLockHeld) {
				t.Fatalf("ambiguous owner error = %v, want held", err)
			}
			if _, err := os.Stat(path); err != nil {
				t.Fatalf("ambiguous lock was removed: %v", err)
			}
		})
	}
}

func TestAtomicFileLockRefusesReleaseAfterOwnershipChange(t *testing.T) {
	path := filepath.Join(t.TempDir(), "object.lock")
	owner := atomicLockOwner{Hostname: "node-a", BootID: "boot-a", PID: 10, Nonce: "first"}
	lease, err := acquireAtomicFileLockWithOwner(context.Background(), path, false, owner, func(int) bool { return true })
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte("changed\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := lease.Close(); err == nil {
		t.Fatal("release removed a lock whose ownership changed")
	}
	if _, err := os.Stat(path); err != nil {
		t.Fatalf("changed lock was removed: %v", err)
	}
}
