// Copyright 2026 Versity Software
// This file is licensed under the Apache License, Version 2.0.

package gwcli

import (
	"bytes"
	"context"
	"os"
	"path/filepath"
	"testing"

	"github.com/versity/versitygw/internal/encryption"
)

func TestParseArchiveTierFlags(t *testing.T) {
	got, err := parseArchiveTierFlags([]string{"glacier=/archive/glacier", "DEEP_ARCHIVE=/archive/deep"})
	if err != nil {
		t.Fatalf("parseArchiveTierFlags() error = %v", err)
	}
	if got["GLACIER"] != "/archive/glacier" || got["DEEP_ARCHIVE"] != "/archive/deep" {
		t.Fatalf("parseArchiveTierFlags() = %#v", got)
	}
	for _, values := range [][]string{{"GLACIER"}, {"=/archive"}, {"GLACIER="}, {"GLACIER=/one", "glacier=/two"}} {
		if _, err := parseArchiveTierFlags(values); err == nil {
			t.Fatalf("parseArchiveTierFlags(%q) succeeded", values)
		}
	}
}

func TestLocalEncryptionProviderDoesNotLoadAWSConfiguration(t *testing.T) {
	oldDirectory, oldActive, oldProvider, oldKeyID := encryptionKeyDir, encryptionActiveKey, encryptionKMSProvider, encryptionKMSKeyID
	t.Cleanup(func() {
		encryptionKeyDir, encryptionActiveKey, encryptionKMSProvider, encryptionKMSKeyID = oldDirectory, oldActive, oldProvider, oldKeyID
	})
	keyDirectory := t.TempDir()
	if err := os.Chmod(keyDirectory, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(keyDirectory, "active.key"), bytes.Repeat([]byte{0x7a}, encryption.DataKeySize), 0o600); err != nil {
		t.Fatal(err)
	}
	t.Setenv("AWS_CONFIG_FILE", filepath.Join(t.TempDir(), "must-not-be-read"))
	t.Setenv("AWS_SHARED_CREDENTIALS_FILE", filepath.Join(t.TempDir(), "must-not-be-read"))
	encryptionKeyDir, encryptionActiveKey, encryptionKMSProvider, encryptionKMSKeyID = keyDirectory, "active", "local", ""
	primary, managed, err := loadEncryptionProviders(context.Background())
	if err != nil {
		t.Fatalf("loadEncryptionProviders() error = %v", err)
	}
	if primary == nil || managed == nil || primary.Name() != "local" || managed.Name() != "local" {
		t.Fatalf("providers = %v, %v", primary, managed)
	}
	if closer, ok := managed.(interface{ Close() }); ok {
		closer.Close()
	}
}
