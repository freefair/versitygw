//go:build !windows

// Copyright 2026 Versity Software
// This file is licensed under the Apache License, Version 2.0.

package posix

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"golang.org/x/sys/unix"
)

var errAtomicLockHeld = errors.New("atomic file lock is held")

type atomicLockOwner struct {
	Hostname string `json:"hostname"`
	BootID   string `json:"boot_id"`
	PID      int    `json:"pid"`
	Nonce    string `json:"nonce"`
}

type atomicFileLease struct {
	path  string
	body  []byte
	nonce string
	once  sync.Once
	err   error
}

var atomicRecoveryLocalLocks sync.Map

func newAtomicLockOwner() (atomicLockOwner, error) {
	hostname, err := os.Hostname()
	if err != nil {
		return atomicLockOwner{}, fmt.Errorf("read lock hostname: %w", err)
	}
	bootIDBody, err := os.ReadFile("/proc/sys/kernel/random/boot_id")
	if err != nil {
		return atomicLockOwner{}, fmt.Errorf("read Linux boot ID for atomic file locks: %w", err)
	}
	nonceBytes := make([]byte, 16)
	if _, err := rand.Read(nonceBytes); err != nil {
		return atomicLockOwner{}, fmt.Errorf("generate atomic lock nonce: %w", err)
	}
	return atomicLockOwner{
		Hostname: hostname,
		BootID:   strings.TrimSpace(string(bootIDBody)),
		PID:      os.Getpid(),
		Nonce:    hex.EncodeToString(nonceBytes),
	}, nil
}

func acquireAtomicFileLock(ctx context.Context, path string, wait bool) (*atomicFileLease, error) {
	owner, err := newAtomicLockOwner()
	if err != nil {
		return nil, err
	}
	return acquireAtomicFileLockWithOwner(ctx, path, wait, owner, atomicLockProcessAlive)
}

func acquireAtomicFileLockWithOwner(ctx context.Context, path string, wait bool, owner atomicLockOwner, processAlive func(int) bool) (*atomicFileLease, error) {
	body, err := json.Marshal(owner)
	if err != nil {
		return nil, fmt.Errorf("marshal atomic lock owner: %w", err)
	}
	body = append(body, '\n')
	for {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		file, err := os.OpenFile(path, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0o600)
		if err == nil {
			_, writeErr := file.Write(body)
			if writeErr == nil {
				writeErr = file.Sync()
			}
			closeErr := file.Close()
			if writeErr != nil || closeErr != nil {
				_ = os.Remove(path)
				return nil, fmt.Errorf("persist atomic lock owner: %w", errors.Join(writeErr, closeErr))
			}
			return &atomicFileLease{path: path, body: body, nonce: owner.Nonce}, nil
		}
		if !errors.Is(err, os.ErrExist) {
			return nil, fmt.Errorf("create atomic lock file: %w", err)
		}

		recovered, err := recoverLocalAtomicFileLock(ctx, path, owner, processAlive)
		if err != nil {
			return nil, err
		}
		if recovered {
			continue
		}
		if !wait {
			return nil, errAtomicLockHeld
		}
		timer := time.NewTimer(25 * time.Millisecond)
		select {
		case <-ctx.Done():
			if !timer.Stop() {
				<-timer.C
			}
			return nil, ctx.Err()
		case <-timer.C:
		}
	}
}

func recoverLocalAtomicFileLock(ctx context.Context, path string, current atomicLockOwner, processAlive func(int) bool) (bool, error) {
	var recovered bool
	err := withLocalRecoveryLock(ctx, path, func() error {
		body, err := os.ReadFile(path)
		if errors.Is(err, os.ErrNotExist) {
			recovered = true
			return nil
		}
		if err != nil {
			return fmt.Errorf("read atomic lock owner: %w", err)
		}
		var existing atomicLockOwner
		if err := json.Unmarshal(bytes.TrimSpace(body), &existing); err != nil {
			return nil
		}
		if existing.Hostname != current.Hostname || existing.BootID != current.BootID || existing.PID <= 0 || processAlive(existing.PID) {
			return nil
		}
		tombstone := path + ".recovered-" + current.Nonce
		if err := os.Rename(path, tombstone); err != nil {
			if errors.Is(err, os.ErrNotExist) {
				recovered = true
				return nil
			}
			return fmt.Errorf("claim stale atomic lock: %w", err)
		}
		if err := os.Remove(tombstone); err != nil && !errors.Is(err, os.ErrNotExist) {
			return fmt.Errorf("remove stale atomic lock: %w", err)
		}
		recovered = true
		return nil
	})
	return recovered, err
}

func withLocalRecoveryLock(ctx context.Context, path string, operation func() error) error {
	localValue, _ := atomicRecoveryLocalLocks.LoadOrStore(path, make(chan struct{}, 1))
	local := localValue.(chan struct{})
	select {
	case local <- struct{}{}:
	case <-ctx.Done():
		return ctx.Err()
	}
	defer func() { <-local }()

	recoveryPath := path + ".local-recovery"
	file, err := os.OpenFile(recoveryPath, os.O_CREATE|os.O_RDWR, 0o600)
	if err != nil {
		return fmt.Errorf("open atomic lock recovery guard: %w", err)
	}
	defer file.Close()
	lock := unix.Flock_t{Type: unix.F_WRLCK, Whence: 0, Start: 0, Len: 0}
	for {
		err = unix.FcntlFlock(file.Fd(), unix.F_SETLK, &lock)
		if err == nil {
			break
		}
		if !errors.Is(err, unix.EACCES) && !errors.Is(err, unix.EAGAIN) {
			return fmt.Errorf("acquire atomic lock recovery guard: %w", err)
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(25 * time.Millisecond):
		}
	}
	defer func() {
		unlock := unix.Flock_t{Type: unix.F_UNLCK, Whence: 0, Start: 0, Len: 0}
		_ = unix.FcntlFlock(file.Fd(), unix.F_SETLK, &unlock)
	}()
	return operation()
}

func atomicLockProcessAlive(pid int) bool {
	err := unix.Kill(pid, 0)
	return err == nil || !errors.Is(err, unix.ESRCH)
}

func (lease *atomicFileLease) Close() error {
	if lease == nil {
		return nil
	}
	lease.once.Do(func() {
		lease.err = withLocalRecoveryLock(context.Background(), lease.path, func() error {
			body, err := os.ReadFile(lease.path)
			if err != nil {
				return fmt.Errorf("read atomic lock before release: %w", err)
			}
			if !bytes.Equal(body, lease.body) {
				return fmt.Errorf("atomic lock ownership changed; refusing release")
			}
			tombstone := lease.path + ".released-" + lease.nonce
			if err := os.Rename(lease.path, tombstone); err != nil {
				return fmt.Errorf("claim atomic lock for release: %w", err)
			}
			if err := os.Remove(tombstone); err != nil && !errors.Is(err, os.ErrNotExist) {
				return fmt.Errorf("remove released atomic lock: %w", err)
			}
			return nil
		})
	})
	return lease.err
}

func absoluteAtomicLockPath(path string) (string, error) {
	absolute, err := filepath.Abs(path)
	if err != nil {
		return "", fmt.Errorf("resolve atomic lock path: %w", err)
	}
	return absolute, nil
}
