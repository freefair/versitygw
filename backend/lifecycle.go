// Copyright 2026 Versity Software
// This file is licensed under the Apache License, Version 2.0.

package backend

import (
	"github.com/versity/versitygw/internal/lifecycle"
)

type LifecycleCursor = lifecycle.Cursor
type LifecyclePage = lifecycle.Page
type LifecycleExecutor = lifecycle.Executor

var ErrLifecycleConflict = lifecycle.ErrConflict
var ErrLifecycleLeaseUnavailable = lifecycle.ErrLeaseUnavailable
