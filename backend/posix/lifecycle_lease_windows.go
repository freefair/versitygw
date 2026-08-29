//go:build windows

// Copyright 2026 Versity Software
// This file is licensed under the Apache License, Version 2.0.

package posix

import (
	"context"
	"fmt"
	"io"
)

func (p *Posix) AcquireLifecycleLease(context.Context, string) (io.Closer, error) {
	return nil, fmt.Errorf("lifecycle execution requires POSIX fcntl record locks")
}

func (p *Posix) acquireObjectMutationLock(context.Context, string, string) (func(), error) {
	return func() {}, nil
}
