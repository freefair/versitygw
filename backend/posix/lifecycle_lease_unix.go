//go:build !windows

// Copyright 2026 Versity Software
// This file is licensed under the Apache License, Version 2.0.

package posix

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"sync"
	"time"

	"github.com/versity/versitygw/internal/lifecycle"
	"golang.org/x/sys/unix"
)

type lifecycleFileLease struct {
	file     *os.File
	localKey string
}

const (
	lifecycleProbeArgument      = "__versitygw_lifecycle_fcntl_probe__"
	lifecycleProbeContendedExit = 73
	lifecycleProbeAcquiredExit  = 74
	lifecycleProbeFailedExit    = 75
)

var lifecycleLocalLeases sync.Map

func init() {
	if len(os.Args) != 3 || os.Args[1] != lifecycleProbeArgument {
		return
	}
	os.Exit(runLifecycleLockProbe(os.Args[2]))
}

func (p *Posix) AcquireLifecycleLease(ctx context.Context, bucket string) (io.Closer, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if err := p.requireLifecycleBucket(bucket); err != nil {
		return nil, err
	}
	directory := filepath.Join(bucket, MetaTmpDir)
	if err := os.MkdirAll(directory, p.newDirPerm); err != nil {
		return nil, fmt.Errorf("create lifecycle lock directory: %w", err)
	}
	lockPath, err := filepath.Abs(filepath.Join(directory, "lifecycle.lock"))
	if err != nil {
		return nil, fmt.Errorf("resolve lifecycle lock path: %w", err)
	}
	if p.atomicFileLocks {
		lease, err := acquireAtomicFileLock(ctx, lockPath, false)
		if errors.Is(err, errAtomicLockHeld) {
			return nil, lifecycle.ErrLeaseUnavailable
		}
		if err != nil {
			return nil, fmt.Errorf("acquire lifecycle atomic file lock: %w", err)
		}
		return lease, nil
	}
	if _, loaded := lifecycleLocalLeases.LoadOrStore(lockPath, struct{}{}); loaded {
		return nil, lifecycle.ErrLeaseUnavailable
	}
	localHeld := true
	defer func() {
		if localHeld {
			lifecycleLocalLeases.Delete(lockPath)
		}
	}()
	p.lifecycleLeaseProbe.Do(func() {
		p.lifecycleLeaseProbeErr = verifyLifecycleRecordLocks(ctx, lockPath+".probe")
	})
	if p.lifecycleLeaseProbeErr != nil {
		return nil, p.lifecycleLeaseProbeErr
	}
	file, err := os.OpenFile(lockPath, os.O_CREATE|os.O_RDWR, 0o600)
	if err != nil {
		return nil, fmt.Errorf("open lifecycle lock: %w", err)
	}
	lock := unix.Flock_t{Type: unix.F_WRLCK, Whence: 0, Start: 0, Len: 0}
	if err := unix.FcntlFlock(file.Fd(), unix.F_SETLK, &lock); err != nil {
		_ = file.Close()
		if errors.Is(err, unix.EACCES) || errors.Is(err, unix.EAGAIN) {
			return nil, lifecycle.ErrLeaseUnavailable
		}
		return nil, fmt.Errorf("acquire lifecycle fcntl lock: %w", err)
	}
	localHeld = false
	return &lifecycleFileLease{file: file, localKey: lockPath}, nil
}

func (lease *lifecycleFileLease) Close() error {
	if lease == nil || lease.file == nil {
		return nil
	}
	lock := unix.Flock_t{Type: unix.F_UNLCK, Whence: 0, Start: 0, Len: 0}
	unlockErr := unix.FcntlFlock(lease.file.Fd(), unix.F_SETLK, &lock)
	closeErr := lease.file.Close()
	lease.file = nil
	lifecycleLocalLeases.Delete(lease.localKey)
	lease.localKey = ""
	return errors.Join(unlockErr, closeErr)
}

func verifyLifecycleRecordLocks(ctx context.Context, path string) error {
	file, err := os.OpenFile(path, os.O_CREATE|os.O_RDWR, 0o600)
	if err != nil {
		return fmt.Errorf("open lifecycle lock probe: %w", err)
	}
	defer file.Close()
	lock := unix.Flock_t{Type: unix.F_WRLCK, Whence: 0, Start: 0, Len: 0}
	if err := unix.FcntlFlock(file.Fd(), unix.F_SETLK, &lock); err != nil {
		return fmt.Errorf("acquire lifecycle lock probe: %w", err)
	}
	defer func() {
		unlock := unix.Flock_t{Type: unix.F_UNLCK, Whence: 0, Start: 0, Len: 0}
		_ = unix.FcntlFlock(file.Fd(), unix.F_SETLK, &unlock)
	}()
	executable, err := os.Executable()
	if err != nil {
		return fmt.Errorf("resolve lifecycle lock probe executable: %w", err)
	}
	probeContext, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	err = exec.CommandContext(probeContext, executable, lifecycleProbeArgument, path).Run()
	var exitError *exec.ExitError
	if errors.As(err, &exitError) && exitError.ExitCode() == lifecycleProbeContendedExit {
		return nil
	}
	if errors.As(err, &exitError) && exitError.ExitCode() == lifecycleProbeAcquiredExit {
		return fmt.Errorf("lifecycle fcntl contention self-test failed: a second process acquired the lock")
	}
	if err == nil {
		return fmt.Errorf("lifecycle fcntl contention self-test returned no contention status")
	}
	return fmt.Errorf("lifecycle fcntl contention self-test failed: %w", err)
}

func runLifecycleLockProbe(path string) int {
	file, err := os.OpenFile(path, os.O_RDWR, 0)
	if err != nil {
		return lifecycleProbeFailedExit
	}
	defer file.Close()
	lock := unix.Flock_t{Type: unix.F_WRLCK, Whence: 0, Start: 0, Len: 0}
	err = unix.FcntlFlock(file.Fd(), unix.F_SETLK, &lock)
	if errors.Is(err, unix.EACCES) || errors.Is(err, unix.EAGAIN) {
		return lifecycleProbeContendedExit
	}
	if err != nil {
		return lifecycleProbeFailedExit
	}
	unlock := unix.Flock_t{Type: unix.F_UNLCK, Whence: 0, Start: 0, Len: 0}
	_ = unix.FcntlFlock(file.Fd(), unix.F_SETLK, &unlock)
	return lifecycleProbeAcquiredExit
}

func (p *Posix) acquireObjectMutationLock(ctx context.Context, bucket, key string) (func(), error) {
	if ctx.Value(ctxKeyObjectMutationHeld) != nil {
		return func() {}, nil
	}
	digest := sha256.Sum256([]byte(bucket + "\x00" + key))
	local := p.mutationLocks[digest[0]]
	select {
	case <-ctx.Done():
		return nil, ctx.Err()
	case <-local:
	}
	localHeld := true
	defer func() {
		if localHeld {
			local <- struct{}{}
		}
	}()

	directory := filepath.Join(bucket, MetaTmpDir, "object-locks")
	if err := os.MkdirAll(directory, p.newDirPerm); err != nil {
		return nil, fmt.Errorf("create object mutation lock directory: %w", err)
	}
	lockPath := filepath.Join(directory, hex.EncodeToString(digest[:])+".lock")
	if p.atomicFileLocks {
		absolutePath, err := absoluteAtomicLockPath(lockPath)
		if err != nil {
			return nil, err
		}
		lease, err := acquireAtomicFileLock(ctx, absolutePath, true)
		if err != nil {
			return nil, fmt.Errorf("acquire object mutation atomic file lock: %w", err)
		}
		localHeld = false
		return func() {
			_ = lease.Close()
			local <- struct{}{}
		}, nil
	}
	file, err := os.OpenFile(lockPath, os.O_CREATE|os.O_RDWR, 0o600)
	if err != nil {
		return nil, fmt.Errorf("open object mutation lock: %w", err)
	}
	lock := unix.Flock_t{Type: unix.F_WRLCK, Whence: 0, Start: 0, Len: 0}
	for {
		err = unix.FcntlFlock(file.Fd(), unix.F_SETLK, &lock)
		if err == nil {
			break
		}
		if !errors.Is(err, unix.EACCES) && !errors.Is(err, unix.EAGAIN) {
			_ = file.Close()
			return nil, fmt.Errorf("acquire object mutation fcntl lock: %w", err)
		}
		select {
		case <-ctx.Done():
			_ = file.Close()
			return nil, ctx.Err()
		case <-time.After(25 * time.Millisecond):
		}
	}
	localHeld = false
	return func() {
		unlock := unix.Flock_t{Type: unix.F_UNLCK, Whence: 0, Start: 0, Len: 0}
		_ = unix.FcntlFlock(file.Fd(), unix.F_SETLK, &unlock)
		_ = file.Close()
		local <- struct{}{}
	}, nil
}
