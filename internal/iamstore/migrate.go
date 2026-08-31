// Copyright 2026 Versity Software
// This file is licensed under the Apache License, Version 2.0
// (the "License"); you may not use this file except in compliance
// with the License.  You may obtain a copy of the License at
//
//   http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing,
// software distributed under the License is distributed on an
// "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
// KIND, either express or implied.  See the License for the
// specific language governing permissions and limitations
// under the License.

package iamstore

import (
	"context"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
)

// BackupSuffix is appended to a store file name to form its backup file.
const BackupSuffix = ".backup"

// FileStatus reports the stored format of one IAM store file.
type FileStatus struct {
	Name      string
	Encrypted bool
	Provider  string
	KeyID     string
	Mode      string
}

// MigrationResult reports what a migration did to one IAM store file.
type MigrationResult struct {
	Name    string
	Changed bool
	// Skipped explains why an unchanged file needed no work.
	Skipped string
}

// StoreStatus reports the format of a store file and its backup without
// needing the wrapping key.
func StoreStatus(dir, file string) ([]FileStatus, error) {
	statuses := make([]FileStatus, 0, 2)

	for _, name := range storeFiles(file) {
		raw, err := readStoreFile(dir, name)
		if errors.Is(err, fs.ErrNotExist) {
			continue
		}
		if err != nil {
			return nil, err
		}

		status := FileStatus{Name: name, Encrypted: IsEncrypted(raw)}
		if status.Encrypted {
			info, err := Inspect(raw)
			if err != nil {
				return nil, fmt.Errorf("inspect %s: %w", name, err)
			}
			status.Mode = string(info.Mode)
			if len(info.KeyReferences) > 0 {
				status.Provider = info.KeyReferences[0].Provider
				status.KeyID = info.KeyReferences[0].KeyID
			}
		}
		statuses = append(statuses, status)
	}

	if len(statuses) == 0 {
		return nil, fmt.Errorf("no iam store file %s in %s", file, dir)
	}

	return statuses, nil
}

// EncryptStore converts a plaintext store file and its backup to the
// encrypted format. The backup is migrated as well, because it holds the same
// credentials as the store itself.
func EncryptStore(ctx context.Context, dir, file string, protector *Protector) ([]MigrationResult, error) {
	return migrateStore(dir, file, func(raw []byte) ([]byte, string, error) {
		if IsEncrypted(raw) {
			return nil, "already encrypted", nil
		}
		out, err := protector.Encode(ctx, file, raw)
		return out, "", err
	})
}

// DecryptStore converts an encrypted store file and its backup back to
// plaintext, for rolling an encrypted deployment back.
func DecryptStore(ctx context.Context, dir, file string, protector *Protector) ([]MigrationResult, error) {
	return migrateStore(dir, file, func(raw []byte) ([]byte, string, error) {
		if !IsEncrypted(raw) {
			return nil, "already plaintext", nil
		}
		out, err := protector.Decode(ctx, file, raw)
		return out, "", err
	})
}

// RewrapStore re-wraps the data keys of a store file and its backup with the
// protector's current wrapping key, without re-encrypting the payload.
func RewrapStore(ctx context.Context, dir, file string, protector *Protector) ([]MigrationResult, error) {
	return migrateStore(dir, file, func(raw []byte) ([]byte, string, error) {
		if !IsEncrypted(raw) {
			return nil, "not encrypted", nil
		}
		out, err := protector.Rewrap(ctx, file, raw)
		return out, "", err
	})
}

// convertFunc returns the new file content, or a reason why the file needs no
// change.
type convertFunc func(raw []byte) ([]byte, string, error)

func migrateStore(dir, file string, convert convertFunc) ([]MigrationResult, error) {
	results := make([]MigrationResult, 0, 2)

	for index, name := range storeFiles(file) {
		raw, err := readStoreFile(dir, name)
		if errors.Is(err, fs.ErrNotExist) {
			// Only the store itself must exist; a deployment that has never
			// been written has no backup yet.
			if index == 0 {
				return nil, fmt.Errorf("read %s: %w", name, err)
			}
			continue
		}
		if err != nil {
			return nil, err
		}

		converted, skipped, err := convert(raw)
		if err != nil {
			return nil, fmt.Errorf("convert %s: %w", name, err)
		}
		if skipped != "" {
			results = append(results, MigrationResult{Name: name, Skipped: skipped})
			continue
		}

		if err := writeStoreFile(dir, name, converted); err != nil {
			return nil, err
		}
		results = append(results, MigrationResult{Name: name, Changed: true})
	}

	return results, nil
}

// storeFiles lists the store file and its backup, store first. Both carry the
// same credentials and are bound to the store file's identity.
func storeFiles(file string) []string {
	return []string{file, file + BackupSuffix}
}

func readStoreFile(dir, name string) ([]byte, error) {
	raw, err := os.ReadFile(filepath.Join(dir, name))
	if err != nil {
		if errors.Is(err, fs.ErrNotExist) {
			return nil, err
		}
		return nil, fmt.Errorf("read %s: %w", name, err)
	}

	return raw, nil
}

// writeStoreFile publishes content through a temporary file so a reader never
// observes a partially written store.
func writeStoreFile(dir, name string, content []byte) (returnErr error) {
	temporary, err := os.CreateTemp(dir, name)
	if err != nil {
		return fmt.Errorf("create temporary %s: %w", name, err)
	}
	temporaryPath := temporary.Name()
	defer func() {
		if returnErr != nil {
			_ = os.Remove(temporaryPath)
		}
	}()

	if err := temporary.Chmod(iamMode); err != nil {
		temporary.Close()
		return fmt.Errorf("protect temporary %s: %w", name, err)
	}
	if _, err := temporary.Write(content); err != nil {
		temporary.Close()
		return fmt.Errorf("write temporary %s: %w", name, err)
	}
	if err := temporary.Sync(); err != nil {
		temporary.Close()
		return fmt.Errorf("sync temporary %s: %w", name, err)
	}
	if err := temporary.Close(); err != nil {
		return fmt.Errorf("close temporary %s: %w", name, err)
	}
	if err := os.Rename(temporaryPath, filepath.Join(dir, name)); err != nil {
		return fmt.Errorf("publish %s: %w", name, err)
	}

	return nil
}
