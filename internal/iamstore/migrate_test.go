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
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestEncryptStoreCoversBackupAndSurvivesRestart(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	plaintext := []byte(`{"users":{"alice":"top-secret"}}`)
	require.NoError(t, os.WriteFile(filepath.Join(dir, testIAMFile), plaintext, 0o600))
	require.NoError(t, os.WriteFile(filepath.Join(dir, testIAMFile+BackupSuffix), plaintext, 0o600))

	protector := newTestProtector(t, "primary")
	results, err := EncryptStore(context.Background(), dir, testIAMFile, protector)
	require.NoError(t, err)
	require.Len(t, results, 2)
	for _, result := range results {
		require.True(t, result.Changed, result.Name)
	}

	for _, name := range storeFiles(testIAMFile) {
		stored, err := os.ReadFile(filepath.Join(dir, name))
		require.NoError(t, err)
		require.True(t, IsEncrypted(stored), name)
		require.NotContains(t, string(stored), "top-secret", name)

		info, err := os.Stat(filepath.Join(dir, name))
		require.NoError(t, err)
		require.Equal(t, os.FileMode(0o600), info.Mode().Perm(), name)
	}

	// The gateway reads the migrated store without further conversion.
	engine := newTestEngine(t, dir, Options{Protector: newTestProtector(t, "primary"), RequireEncryption: true})
	conf, err := engine.GetIAM()
	require.NoError(t, err)
	require.Equal(t, "top-secret", conf.Users["alice"])

	// A second run is a no-op rather than a double encryption.
	results, err = EncryptStore(context.Background(), dir, testIAMFile, protector)
	require.NoError(t, err)
	for _, result := range results {
		require.False(t, result.Changed, result.Name)
		require.Equal(t, "already encrypted", result.Skipped)
	}
}

func TestDecryptStoreRollsBackToPlaintext(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	protector := newTestProtector(t, "primary")
	engine := newTestEngine(t, dir, Options{Protector: protector})
	require.NoError(t, engine.StoreIAM(func(data []byte) ([]byte, error) {
		conf, err := engine.ParseIAM(data)
		if err != nil {
			return nil, err
		}
		conf.Users["alice"] = "rollback"
		return json.Marshal(conf)
	}))

	results, err := DecryptStore(context.Background(), dir, testIAMFile, protector)
	require.NoError(t, err)
	require.Len(t, results, 2)

	stored, err := os.ReadFile(filepath.Join(dir, testIAMFile))
	require.NoError(t, err)
	require.False(t, IsEncrypted(stored))
	require.Contains(t, string(stored), "rollback")

	// A gateway without any key configuration reads the store again.
	plain, err := New(dir, testIAMFile, testBackupFmt, testConfig{Users: map[string]string{}}, normalizeTestConfig)
	require.NoError(t, err)
	conf, err := plain.GetIAM()
	require.NoError(t, err)
	require.Equal(t, "rollback", conf.Users["alice"])
}

func TestRewrapStoreMovesToTheActiveKey(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	keyDir := t.TempDir()
	writeTestKey(t, keyDir, "2026-01", 0x11)
	writeTestKey(t, keyDir, "2026-02", 0x22)

	require.NoError(t, os.WriteFile(filepath.Join(dir, testIAMFile), []byte(`{"users":{"alice":"rotate"}}`), 0o600))
	_, err := EncryptStore(context.Background(), dir, testIAMFile, newProtectorForKey(t, keyDir, "2026-01"))
	require.NoError(t, err)

	next := newProtectorForKey(t, keyDir, "2026-02")
	results, err := RewrapStore(context.Background(), dir, testIAMFile, next)
	require.NoError(t, err)
	require.Len(t, results, 1, "no backup exists yet")
	require.True(t, results[0].Changed)

	statuses, err := StoreStatus(dir, testIAMFile)
	require.NoError(t, err)
	require.Len(t, statuses, 1)
	require.True(t, statuses[0].Encrypted)
	require.Equal(t, "2026-02", statuses[0].KeyID)

	engine := newTestEngine(t, dir, Options{Protector: next})
	conf, err := engine.GetIAM()
	require.NoError(t, err)
	require.Equal(t, "rotate", conf.Users["alice"])
}

func TestStoreStatusReportsPlaintextAndMissingStore(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	_, err := StoreStatus(dir, testIAMFile)
	require.Error(t, err)

	require.NoError(t, os.WriteFile(filepath.Join(dir, testIAMFile), []byte(`{"users":{}}`), 0o600))
	statuses, err := StoreStatus(dir, testIAMFile)
	require.NoError(t, err)
	require.Len(t, statuses, 1)
	require.False(t, statuses[0].Encrypted)
	require.Empty(t, statuses[0].KeyID)
}

func TestProtectorConfigValidatesFlagCombinations(t *testing.T) {
	t.Parallel()

	_, err := ProtectorConfig{ActiveKey: "primary"}.Options(context.Background())
	require.Error(t, err, "an active key without a key directory is a configuration mistake")

	_, err = ProtectorConfig{RequireEncryption: true}.Options(context.Background())
	require.Error(t, err, "requiring encryption without a key cannot be satisfied")

	_, err = ProtectorConfig{KeyDirectory: t.TempDir(), KMSKeyID: "alias/iam"}.Options(context.Background())
	require.Error(t, err, "a KMS key ID needs the aws provider")

	_, err = ProtectorConfig{KeyDirectory: t.TempDir(), KMSProvider: "vault"}.Options(context.Background())
	require.Error(t, err, "unknown providers must be rejected")

	_, err = ProtectorConfig{KMSProvider: "aws"}.Options(context.Background())
	require.Error(t, err, "aws without a key ID would fall back to the S3-managed alias")

	_, err = ProtectorConfig{KMSProvider: "aws", KMSKeyID: "alias/iam", KeyDirectory: t.TempDir()}.Options(context.Background())
	require.Error(t, err, "a local key directory has no meaning for the aws provider")

	options, err := ProtectorConfig{}.Options(context.Background())
	require.NoError(t, err)
	require.Nil(t, options.Protector, "no configuration keeps the plaintext format")
}

func TestProtectorConfigBuildsDerivedLocalProvider(t *testing.T) {
	t.Parallel()

	keyDir := t.TempDir()
	writeTestKey(t, keyDir, "primary", 0x55)

	options, err := ProtectorConfig{KeyDirectory: keyDir, ActiveKey: "primary"}.Options(context.Background())
	require.NoError(t, err)
	require.NotNil(t, options.Protector)
	t.Cleanup(options.Protector.Close)

	require.Equal(t, iamProviderName, options.Protector.ProviderName())
	require.Equal(t, "primary", options.Protector.KeyReference())

	ciphertext, err := options.Protector.Encode(context.Background(), testIAMFile, []byte(`{"users":{}}`))
	require.NoError(t, err)

	// The object wrapping key must not open an IAM container, even though
	// both derive from the same local key file.
	object := newProtectorForKey(t, keyDir, "primary")
	_, err = object.Decode(context.Background(), testIAMFile, ciphertext)
	require.Error(t, err, "the IAM derivation must not be interchangeable with the object key")
}
