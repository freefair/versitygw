// Copyright 2026 Versity Software
// This file is licensed under the Apache License, Version 2.0.

package gwcli

import (
	"context"
	"crypto/rand"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"time"

	"github.com/urfave/cli/v2"
	"github.com/versity/versitygw/backend/meta"
	"github.com/versity/versitygw/backend/posix"
	"github.com/versity/versitygw/internal/encryption"
)

func encryptionKeyCommand() *cli.Command {
	return &cli.Command{
		Name:  "encryption-key",
		Usage: "manage local encryption wrapping keys",
		Subcommands: []*cli.Command{{
			Name:   "generate",
			Usage:  "create a protected 256-bit local wrapping key",
			Action: generateEncryptionKey,
			Flags: []cli.Flag{
				&cli.StringFlag{Name: "directory", Usage: "existing protected key directory", Required: true},
				&cli.StringFlag{Name: "key-id", Usage: "new filename-safe key ID", Required: true},
				&cli.BoolFlag{Name: "activate", Usage: "atomically select the new key for subsequent writes"},
			},
		}},
	}
}

func encryptionMaintenanceCommand() *cli.Command {
	command := func(name, usage string, action cli.ActionFunc, dryRun bool) *cli.Command {
		flags := []cli.Flag{
			&cli.StringFlag{Name: "sidecar", Usage: "sidecar metadata directory (default: object xattrs)"},
			&cli.StringFlag{Name: "versioning-dir", Usage: "bucket versioning directory"},
			&cli.StringFlag{Name: "key-directory", Usage: "protected local encryption key directory"},
			&cli.StringFlag{Name: "active-key", Usage: "active local key ID (default: active file)"},
			&cli.StringFlag{Name: "kms-provider", Usage: "SSE-KMS provider: local or aws"},
			&cli.StringFlag{Name: "kms-key-id", Usage: "default AWS KMS key ID or alias"},
			&cli.DurationFlag{Name: "kms-timeout", Usage: "maximum AWS KMS operation duration", Value: 10 * time.Second},
			&cli.StringSliceFlag{Name: "archive-tier", Usage: "repeatable STORAGE_CLASS=/absolute/archive/root mapping"},
		}
		if dryRun {
			flags = append(flags, &cli.BoolFlag{Name: "dry-run", Usage: "report candidates without changing objects"})
		}
		return &cli.Command{Name: name, Usage: usage, ArgsUsage: "ROOT", Action: action, Flags: flags}
	}
	return &cli.Command{
		Name:  "encryption",
		Usage: "audit and maintain POSIX encrypted objects",
		Subcommands: []*cli.Command{
			command("inventory", "report encryption formats and key references without reading payloads", encryptionInventory, false),
			command("rewrap", "rewrap data keys with active provider keys without re-encrypting payloads", encryptionRewrap, true),
			command("reencrypt", "encrypt legacy plaintext objects in place with SSE-S3", encryptionReencrypt, true),
		},
	}
}

func generateEncryptionKey(ctx *cli.Context) error {
	directory := ctx.String("directory")
	keyID := ctx.String("key-id")
	if err := encryption.ValidateKeyID(keyID); err != nil {
		return fmt.Errorf("validate key ID: %w", err)
	}
	if err := encryption.ValidateLocalKeyDirectory(directory); err != nil {
		return fmt.Errorf("validate key directory: %w", err)
	}

	key := make(encryption.SensitiveBytes, encryption.DataKeySize)
	defer key.Destroy()
	if _, err := io.ReadFull(rand.Reader, key); err != nil {
		return fmt.Errorf("generate encryption key: %w", err)
	}
	if err := writeEncryptionKey(directory, keyID, key); err != nil {
		return err
	}

	if ctx.Bool("activate") {
		if err := writeActiveEncryptionKey(directory, keyID); err != nil {
			return err
		}
	}
	_, err := fmt.Fprintf(ctx.App.Writer, "created local encryption key %q\n", keyID)
	return err
}

func writeEncryptionKey(directory, keyID string, key []byte) (returnErr error) {
	temporary, err := os.CreateTemp(directory, ".key-")
	if err != nil {
		return fmt.Errorf("create temporary encryption key: %w", err)
	}
	temporaryPath := temporary.Name()
	defer func() {
		_ = temporary.Close()
		_ = os.Remove(temporaryPath)
	}()
	if err := temporary.Chmod(0o600); err != nil {
		return fmt.Errorf("protect temporary encryption key: %w", err)
	}
	if _, err := temporary.Write(key); err != nil {
		return fmt.Errorf("write encryption key: %w", err)
	}
	if err := temporary.Sync(); err != nil {
		return fmt.Errorf("sync encryption key: %w", err)
	}
	if err := temporary.Close(); err != nil {
		return fmt.Errorf("close encryption key: %w", err)
	}

	keyPath := filepath.Join(directory, keyID+".key")
	if err := os.Link(temporaryPath, keyPath); err != nil {
		return fmt.Errorf("publish encryption key: %w", err)
	}
	if err := os.Remove(temporaryPath); err != nil {
		return fmt.Errorf("remove temporary encryption key: %w", err)
	}
	dir, err := os.Open(directory)
	if err != nil {
		return fmt.Errorf("open key directory: %w", err)
	}
	defer dir.Close()
	if err := dir.Sync(); err != nil {
		return fmt.Errorf("sync key directory: %w", err)
	}
	return nil
}

func writeActiveEncryptionKey(directory, keyID string) (returnErr error) {
	temporary, err := os.CreateTemp(directory, ".active-")
	if err != nil {
		return fmt.Errorf("create active key reference: %w", err)
	}
	temporaryPath := temporary.Name()
	defer func() {
		_ = temporary.Close()
		if returnErr != nil {
			_ = os.Remove(temporaryPath)
		}
	}()
	if err := temporary.Chmod(0o600); err != nil {
		return err
	}
	if _, err := fmt.Fprintf(temporary, "%s\n", keyID); err != nil {
		return fmt.Errorf("write active key reference: %w", err)
	}
	if err := temporary.Sync(); err != nil {
		return fmt.Errorf("sync active key reference: %w", err)
	}
	if err := temporary.Close(); err != nil {
		return fmt.Errorf("close active key reference: %w", err)
	}
	if err := os.Rename(temporaryPath, filepath.Join(directory, "active")); err != nil {
		return fmt.Errorf("publish active key reference: %w", err)
	}
	dir, err := os.Open(directory)
	if err != nil {
		return fmt.Errorf("open key directory: %w", err)
	}
	defer dir.Close()
	if err := dir.Sync(); err != nil {
		return fmt.Errorf("sync key directory: %w", err)
	}
	return nil
}

func encryptionInventory(ctx *cli.Context) error {
	return withEncryptionMaintenanceBackend(ctx, func(callContext context.Context, backend *posix.Posix) (any, error) {
		return backend.AuditEncryption(callContext)
	})
}

func encryptionRewrap(ctx *cli.Context) error {
	return withEncryptionMaintenanceBackend(ctx, func(callContext context.Context, backend *posix.Posix) (any, error) {
		return backend.RewrapEncryption(callContext, ctx.Bool("dry-run"))
	})
}

func encryptionReencrypt(ctx *cli.Context) error {
	return withEncryptionMaintenanceBackend(ctx, func(callContext context.Context, backend *posix.Posix) (any, error) {
		return backend.ReencryptLegacy(callContext, ctx.Bool("dry-run"))
	})
}

func withEncryptionMaintenanceBackend(ctx *cli.Context, operation func(context.Context, *posix.Posix) (any, error)) error {
	root := ctx.Args().First()
	if root == "" {
		return cli.Exit("missing POSIX root directory", 2)
	}
	originalDirectory, err := os.Getwd()
	if err != nil {
		return err
	}
	defer os.Chdir(originalDirectory)

	primary, managed, err := loadEncryptionProvidersFrom(ctx.Context, ctx.String("key-directory"), ctx.String("active-key"), ctx.String("kms-provider"), ctx.String("kms-key-id"), ctx.Duration("kms-timeout"))
	if err != nil {
		return err
	}
	archiveTiers, err := parseArchiveTierFlags(ctx.StringSlice("archive-tier"))
	if err != nil {
		if closer, ok := managed.(interface{ Close() }); ok {
			closer.Close()
		}
		return err
	}

	var metadata meta.MetadataStorer
	if sidecarDirectory := ctx.String("sidecar"); sidecarDirectory != "" {
		metadata, err = meta.NewSideCar(sidecarDirectory)
	} else {
		metadata = meta.XattrMeta{}
		err = meta.XattrMeta{}.Test(root)
	}
	if err != nil {
		if closer, ok := managed.(interface{ Close() }); ok {
			closer.Close()
		}
		return fmt.Errorf("initialize encryption maintenance metadata: %w", err)
	}
	backend, err := posix.New(root, metadata, posix.PosixOpts{
		SideCarDir: ctx.String("sidecar"), VersioningDir: ctx.String("versioning-dir"),
		EncryptionProvider: primary, ManagedEncryptionProvider: managed, EncryptionKeyDirectory: ctx.String("key-directory"),
		ArchiveTiers: archiveTiers, NewDirPerm: 0o755,
	})
	if err != nil {
		if closer, ok := managed.(interface{ Close() }); ok {
			closer.Close()
		}
		return fmt.Errorf("initialize POSIX encryption maintenance: %w", err)
	}
	defer backend.Shutdown()

	result, err := operation(ctx.Context, backend)
	if err != nil {
		return err
	}
	encoder := json.NewEncoder(ctx.App.Writer)
	encoder.SetIndent("", "  ")
	return encoder.Encode(result)
}
