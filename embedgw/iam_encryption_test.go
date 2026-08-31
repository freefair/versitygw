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

package embedgw

import (
	"bytes"
	"context"
	"os"
	"path/filepath"
	"testing"

	"github.com/versity/versitygw/internal/encryption"
	"github.com/versity/versitygw/internal/iamstore"
)

func TestIAMStoreOptionsRejectsEncryptionForNonFileBackends(t *testing.T) {
	keyDir := t.TempDir()
	writeWrappingKey(t, keyDir, "primary")

	for name, cfg := range map[string]iamstore.ProtectorConfig{
		"key directory": {KeyDirectory: keyDir},
		"required only": {RequireEncryption: true},
	} {
		t.Run(name, func(t *testing.T) {
			// An LDAP, Vault, FreeIPA, or S3-hosted IAM backend cannot honor
			// these settings, and accepting them would be a false assurance.
			if _, err := iamStoreOptions(context.Background(), cfg, false); err == nil {
				t.Fatal("expected iam encryption to be rejected for a non-file-backed IAM backend")
			}
		})
	}
}

func TestIAMStoreOptionsBuildsProtectorForFileBackend(t *testing.T) {
	keyDir := t.TempDir()
	writeWrappingKey(t, keyDir, "primary")

	options, err := iamStoreOptions(context.Background(),
		iamstore.ProtectorConfig{KeyDirectory: keyDir, RequireEncryption: true}, true)
	if err != nil {
		t.Fatalf("iamStoreOptions: %v", err)
	}
	if options.Protector == nil {
		t.Fatal("expected a protector for a file-backed IAM store")
	}
	t.Cleanup(options.Protector.Close)
	if !options.RequireEncryption {
		t.Fatal("expected the strict setting to reach the store")
	}
}

func TestIAMStoreOptionsStaysPlaintextWithoutConfiguration(t *testing.T) {
	options, err := iamStoreOptions(context.Background(), iamstore.ProtectorConfig{}, true)
	if err != nil {
		t.Fatalf("iamStoreOptions: %v", err)
	}
	if options.Protector != nil {
		t.Fatal("expected no protector without encryption settings")
	}
}

func writeWrappingKey(t *testing.T, dir, keyID string) {
	t.Helper()

	if err := os.Chmod(dir, 0o700); err != nil {
		t.Fatalf("chmod key directory: %v", err)
	}
	key := bytes.Repeat([]byte{0x42}, encryption.DataKeySize)
	if err := os.WriteFile(filepath.Join(dir, keyID+".key"), key, 0o600); err != nil {
		t.Fatalf("write wrapping key: %v", err)
	}
	if err := os.WriteFile(filepath.Join(dir, "active"), []byte(keyID+"\n"), 0o600); err != nil {
		t.Fatalf("write active key reference: %v", err)
	}
}
