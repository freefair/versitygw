// Copyright 2026 Versity Software
// This file is licensed under the Apache License, Version 2.0.

package gwcli

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"github.com/urfave/cli/v2"
	"github.com/versity/versitygw/internal/encryption"
)

func TestGenerateEncryptionKeyCreatesProtectedKeyAndAtomicActiveReference(t *testing.T) {
	directory := t.TempDir()
	if err := os.Chmod(directory, 0o700); err != nil {
		t.Fatal(err)
	}
	app := cli.NewApp()
	app.Commands = []*cli.Command{UtilsCommand()}
	arguments := []string{
		"versitygw", "utils", "encryption-key", "generate",
		"--directory", directory, "--key-id", "2026-08", "--activate",
	}
	if err := app.Run(arguments); err != nil {
		t.Fatalf("generate encryption key: %v", err)
	}

	keyPath := filepath.Join(directory, "2026-08.key")
	key, err := os.ReadFile(keyPath)
	if err != nil {
		t.Fatal(err)
	}
	if len(key) != encryption.DataKeySize {
		t.Fatalf("key length = %d, want %d", len(key), encryption.DataKeySize)
	}
	info, err := os.Stat(keyPath)
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode().Perm() != 0o600 {
		t.Fatalf("key permissions = %o, want 600", info.Mode().Perm())
	}
	active, err := os.ReadFile(filepath.Join(directory, "active"))
	if err != nil {
		t.Fatal(err)
	}
	if string(active) != "2026-08\n" {
		t.Fatalf("active key reference = %q", active)
	}

	original := append([]byte(nil), key...)
	if err := app.Run(arguments); err == nil {
		t.Fatal("second generate unexpectedly overwrote the existing key")
	}
	key, err = os.ReadFile(keyPath)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(key, original) {
		t.Fatal("existing key changed after duplicate generation")
	}
	entries, err := os.ReadDir(directory)
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 2 {
		t.Fatalf("key directory entries after duplicate generation = %d, want 2", len(entries))
	}
}

func TestEncryptionInventoryCommandReportsLegacyObjects(t *testing.T) {
	base := t.TempDir()
	root := filepath.Join(base, "objects")
	sidecar := filepath.Join(base, "metadata")
	if err := os.MkdirAll(filepath.Join(root, "bucket"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(sidecar, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(root, "bucket", "legacy"), []byte("plaintext"), 0o600); err != nil {
		t.Fatal(err)
	}

	var output bytes.Buffer
	app := cli.NewApp()
	app.Writer = &output
	app.Commands = []*cli.Command{UtilsCommand()}
	if err := app.Run([]string{
		"versitygw", "utils", "encryption", "inventory",
		"--sidecar", sidecar, root,
	}); err != nil {
		t.Fatalf("encryption inventory: %v", err)
	}
	var inventory encryption.Inventory
	if err := json.Unmarshal(output.Bytes(), &inventory); err != nil {
		t.Fatalf("decode inventory output %q: %v", output.String(), err)
	}
	if inventory.Buckets != 1 || inventory.Objects != 1 || inventory.PlaintextLegacy != 1 {
		t.Fatalf("inventory = %#v", inventory)
	}
}

func TestGenerateEncryptionKeyRejectsUnsafeKeyID(t *testing.T) {
	app := cli.NewApp()
	app.Commands = []*cli.Command{UtilsCommand()}
	err := app.Run([]string{
		"versitygw", "utils", "encryption-key", "generate",
		"--directory", t.TempDir(), "--key-id", "../escape",
	})
	if err == nil {
		t.Fatal("unsafe key ID was accepted")
	}
}

func TestGenerateEncryptionKeyRejectsInsecureDirectory(t *testing.T) {
	directory := t.TempDir()
	if err := os.Chmod(directory, 0o755); err != nil {
		t.Fatal(err)
	}
	app := cli.NewApp()
	app.Commands = []*cli.Command{UtilsCommand()}
	if err := app.Run([]string{
		"versitygw", "utils", "encryption-key", "generate",
		"--directory", directory, "--key-id", "unsafe",
	}); err == nil {
		t.Fatal("key generation accepted an insecure directory")
	}
}
