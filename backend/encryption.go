// Copyright 2026 Versity Software
// This file is licensed under the Apache License, Version 2.0.

package backend

import (
	"context"

	"github.com/versity/versitygw/internal/encryption"
)

type EncryptionCapabilities = encryption.Capabilities
type EncryptionIntent = encryption.Intent
type EncryptionResult = encryption.Result

type EncryptionAuditor interface {
	AuditEncryption(context.Context) (encryption.Inventory, error)
}
