// Copyright 2026 Versity Software
// This file is licensed under the Apache License, Version 2.0.

package gwcli

import (
	"context"
	"encoding/json"
	"fmt"
	"path/filepath"
	"time"

	"github.com/urfave/cli/v2"

	"github.com/versity/versitygw/internal/iamstore"
)

// defaultIAMStoreFile is the gateway's account store. The IAM API server
// stores its user database in iam.json in the same directory layout.
const defaultIAMStoreFile = "users.json"

// IAMEncryptionFlags returns the flags configuring IAM store encryption at
// rest. prefix scopes the flag names: "iam-" for a gateway's global flags,
// empty inside a command whose flags are IAM-scoped already. Environment
// variable names are the same either way, so one deployment configuration
// serves the gateway, the IAM API server, and the maintenance commands.
func IAMEncryptionFlags(prefix string, cfg *iamstore.ProtectorConfig) []cli.Flag {
	return []cli.Flag{
		&cli.StringFlag{
			Name:        prefix + "encryption-key-directory",
			Usage:       "directory containing protected local wrapping keys for the IAM store",
			EnvVars:     []string{"VGW_IAM_ENCRYPTION_KEY_DIRECTORY"},
			Destination: &cfg.KeyDirectory,
		},
		&cli.StringFlag{
			Name:        prefix + "encryption-active-key",
			Usage:       "active local wrapping key ID for the IAM store (defaults to the key directory's active file)",
			EnvVars:     []string{"VGW_IAM_ENCRYPTION_ACTIVE_KEY"},
			Destination: &cfg.ActiveKey,
		},
		&cli.StringFlag{
			Name:        prefix + "encryption-kms-provider",
			Usage:       "IAM store key provider: local or aws; AWS configuration is loaded only when aws is selected",
			EnvVars:     []string{"VGW_IAM_ENCRYPTION_KMS_PROVIDER"},
			Destination: &cfg.KMSProvider,
		},
		&cli.StringFlag{
			Name:        prefix + "encryption-kms-key-id",
			Usage:       "AWS KMS key ID or alias wrapping the IAM store data key",
			EnvVars:     []string{"VGW_IAM_ENCRYPTION_KMS_KEY_ID"},
			Destination: &cfg.KMSKeyID,
		},
		&cli.DurationFlag{
			Name:        prefix + "encryption-kms-timeout",
			Usage:       "maximum AWS KMS operation duration for the IAM store",
			Value:       10 * time.Second,
			EnvVars:     []string{"VGW_IAM_ENCRYPTION_KMS_TIMEOUT"},
			Destination: &cfg.KMSTimeout,
		},
		&cli.BoolFlag{
			Name:        prefix + "encryption-required",
			Usage:       "refuse to start when the IAM store is stored in plaintext",
			EnvVars:     []string{"VGW_IAM_ENCRYPTION_REQUIRED"},
			Destination: &cfg.RequireEncryption,
		},
	}
}

// iamEncryptionCommand returns the "iam-encryption" maintenance subcommand.
// The gateway never changes a store's format on its own, so migrating an
// existing deployment happens here, deliberately, once every gateway sharing
// the directory can reach the wrapping key.
func iamEncryptionCommand() *cli.Command {
	return &cli.Command{
		Name:  "iam-encryption",
		Usage: "inspect and migrate IAM store encryption at rest",
		Subcommands: []*cli.Command{
			iamEncryptionStatusCommand(),
			iamEncryptionMigrateCommand("encrypt",
				"encrypt a plaintext IAM store file and its backup", iamstore.EncryptStore),
			iamEncryptionMigrateCommand("decrypt",
				"convert an encrypted IAM store file and its backup back to plaintext", iamstore.DecryptStore),
			iamEncryptionMigrateCommand("rewrap",
				"rewrap IAM store data keys with the active wrapping key", iamstore.RewrapStore),
		},
	}
}

func iamEncryptionStatusCommand() *cli.Command {
	var dir, file string

	return &cli.Command{
		Name:  "status",
		Usage: "report the stored format and key reference without needing the wrapping key",
		Flags: iamStoreFlags(&dir, &file),
		Action: func(ctx *cli.Context) error {
			if err := validateStoreFile(file); err != nil {
				return err
			}
			statuses, err := iamstore.StoreStatus(dir, file)
			if err != nil {
				return err
			}
			return writeIAMEncryptionResult(ctx, statuses)
		},
	}
}

// migrateFunc converts a store file and its backup between stored formats.
type migrateFunc func(context.Context, string, string, *iamstore.Protector) ([]iamstore.MigrationResult, error)

func iamEncryptionMigrateCommand(name, usage string, migrate migrateFunc) *cli.Command {
	var cfg iamstore.ProtectorConfig
	var dir, file string

	return &cli.Command{
		Name:  name,
		Usage: usage,
		Flags: append(iamStoreFlags(&dir, &file), IAMEncryptionFlags("", &cfg)...),
		Action: func(ctx *cli.Context) error {
			if err := validateStoreFile(file); err != nil {
				return err
			}
			protector, err := iamstore.NewProtectorFromConfig(ctx.Context, cfg)
			if err != nil {
				return err
			}
			defer protector.Close()

			results, err := migrate(ctx.Context, dir, file, protector)
			if err != nil {
				return err
			}
			return writeIAMEncryptionResult(ctx, results)
		},
	}
}

func iamStoreFlags(dir, file *string) []cli.Flag {
	return []cli.Flag{
		&cli.StringFlag{
			Name:        "dir",
			Usage:       "IAM directory holding the store file",
			Required:    true,
			EnvVars:     []string{"VGW_IAM_DIR"},
			Destination: dir,
		},
		&cli.StringFlag{
			Name:        "file",
			Usage:       "store file name: users.json for the gateway, iam.json for the IAM API server",
			Value:       defaultIAMStoreFile,
			Destination: file,
		},
	}
}

// validateStoreFile keeps the file flag a name inside the IAM directory
// rather than a path reaching out of it.
func validateStoreFile(file string) error {
	if file == "" || filepath.Base(file) != file || file == "." || file == ".." {
		return fmt.Errorf("invalid iam store file name %q", file)
	}
	return nil
}

func writeIAMEncryptionResult(ctx *cli.Context, result any) error {
	encoder := json.NewEncoder(ctx.App.Writer)
	encoder.SetIndent("", "  ")
	return encoder.Encode(result)
}
