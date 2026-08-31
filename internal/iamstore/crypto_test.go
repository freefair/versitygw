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
	"bytes"
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"sync/atomic"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/versity/versitygw/internal/encryption"
)

const (
	testIAMFile   = "users.json"
	testBackupFmt = "users.json.backup"
)

func TestProtectorRoundTripsAndBindsToFileName(t *testing.T) {
	t.Parallel()

	protector := newTestProtector(t, "primary")
	plaintext := []byte(`{"accessAccounts":{"alice":{"secret":"top-secret"}}}`)

	ciphertext, err := protector.Encode(context.Background(), testIAMFile, plaintext)
	require.NoError(t, err)
	require.True(t, IsEncrypted(ciphertext))
	require.NotContains(t, string(ciphertext), "top-secret")

	decoded, err := protector.Decode(context.Background(), testIAMFile, ciphertext)
	require.NoError(t, err)
	require.Equal(t, plaintext, decoded)

	_, err = protector.Decode(context.Background(), "iam.json", ciphertext)
	require.ErrorIs(t, err, encryption.ErrIdentityMismatch)
}

func TestProtectorRejectsForeignKeyAndTamperedContainer(t *testing.T) {
	t.Parallel()

	protector := newTestProtector(t, "primary")
	ciphertext, err := protector.Encode(context.Background(), testIAMFile, []byte(`{"users":{}}`))
	require.NoError(t, err)

	foreign := newTestProtector(t, "foreign")
	_, err = foreign.Decode(context.Background(), testIAMFile, ciphertext)
	require.Error(t, err)

	tampered := append([]byte(nil), ciphertext...)
	tampered[len(tampered)-1] ^= 0xff
	_, err = protector.Decode(context.Background(), testIAMFile, tampered)
	require.ErrorIs(t, err, encryption.ErrAuthentication)
}

func TestProtectorRewrapKeepsPlaintextReadable(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	writeTestKey(t, dir, "2026-01", 0x11)
	writeTestKey(t, dir, "2026-02", 0x22)

	first := newProtectorForKey(t, dir, "2026-01")
	plaintext := []byte(`{"accessAccounts":{"alice":{"secret":"rotate-me"}}}`)
	ciphertext, err := first.Encode(context.Background(), testIAMFile, plaintext)
	require.NoError(t, err)

	second := newProtectorForKey(t, dir, "2026-02")
	rewrapped, err := second.Rewrap(context.Background(), testIAMFile, ciphertext)
	require.NoError(t, err)

	info, err := Inspect(rewrapped)
	require.NoError(t, err)
	require.Len(t, info.KeyReferences, 1)
	require.Equal(t, "2026-02", info.KeyReferences[0].KeyID)

	decoded, err := second.Decode(context.Background(), testIAMFile, rewrapped)
	require.NoError(t, err)
	require.Equal(t, plaintext, decoded)
}

func TestIsEncryptedDistinguishesStoredFormats(t *testing.T) {
	t.Parallel()

	require.False(t, IsEncrypted(nil))
	require.False(t, IsEncrypted([]byte(`{"accessAccounts":{}}`)))

	ciphertext, err := newTestProtector(t, "primary").Encode(context.Background(), testIAMFile, []byte(`{}`))
	require.NoError(t, err)
	require.True(t, IsEncrypted(ciphertext))
}

func TestEngineEncryptsNewStoreAndKeepsSecretsOffDisk(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	engine := newTestEngine(t, dir, Options{Protector: newTestProtector(t, "primary")})

	require.NoError(t, engine.StoreIAM(func(data []byte) ([]byte, error) {
		conf, err := engine.ParseIAM(data)
		if err != nil {
			return nil, err
		}
		conf.Users["alice"] = "top-secret"
		return json.Marshal(conf)
	}))

	stored, err := os.ReadFile(filepath.Join(dir, testIAMFile))
	require.NoError(t, err)
	require.True(t, IsEncrypted(stored))
	require.NotContains(t, string(stored), "top-secret")
	require.NotContains(t, string(stored), "alice")

	backup, err := os.ReadFile(filepath.Join(dir, testBackupFmt))
	require.NoError(t, err)
	require.True(t, IsEncrypted(backup), "backup must not fall back to plaintext")

	conf, err := engine.GetIAM()
	require.NoError(t, err)
	require.Equal(t, "top-secret", conf.Users["alice"])

	// A restart reads the same store through the decrypt path.
	restarted := newTestEngine(t, dir, Options{Protector: newTestProtector(t, "primary")})
	conf, err = restarted.GetIAM()
	require.NoError(t, err)
	require.Equal(t, "top-secret", conf.Users["alice"])
}

func TestEngineKeepsExistingPlaintextStoreUntilMigrated(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	require.NoError(t, os.WriteFile(filepath.Join(dir, testIAMFile), []byte(`{"users":{"bob":"legacy"}}`), 0o600))

	engine := newTestEngine(t, dir, Options{Protector: newTestProtector(t, "primary")})
	require.NoError(t, engine.StoreIAM(func(data []byte) ([]byte, error) {
		conf, err := engine.ParseIAM(data)
		if err != nil {
			return nil, err
		}
		conf.Users["alice"] = "added"
		return json.Marshal(conf)
	}))

	stored, err := os.ReadFile(filepath.Join(dir, testIAMFile))
	require.NoError(t, err)
	require.False(t, IsEncrypted(stored), "an existing plaintext store must not switch format on its own")
	require.Contains(t, string(stored), "legacy")
}

func TestEngineRequireEncryptionRejectsPlaintextStore(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	require.NoError(t, os.WriteFile(filepath.Join(dir, testIAMFile), []byte(`{"users":{}}`), 0o600))

	_, err := NewWithOptions(dir, testIAMFile, testBackupFmt, testConfig{Users: map[string]string{}}, normalizeTestConfig,
		Options{Protector: newTestProtector(t, "primary"), RequireEncryption: true})
	require.ErrorIs(t, err, ErrPlaintextStore)
}

func TestEngineRejectsEncryptedStoreWithoutKey(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	ciphertext, err := newTestProtector(t, "primary").Encode(context.Background(), testIAMFile, []byte(`{"users":{}}`))
	require.NoError(t, err)
	require.NoError(t, os.WriteFile(filepath.Join(dir, testIAMFile), ciphertext, 0o600))

	_, err = New(dir, testIAMFile, testBackupFmt, testConfig{Users: map[string]string{}}, normalizeTestConfig)
	require.ErrorIs(t, err, ErrMissingProtector)
}

func TestEngineServesReadsFromMemoryAndFollowsForeignWrites(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	keyDir := t.TempDir()
	writeTestKey(t, keyDir, "primary", 0x33)

	counter := &countingProvider{KeyProvider: newLocalProvider(t, keyDir, "primary")}
	protector, err := NewProtector(counter, "primary")
	require.NoError(t, err)

	engine := newTestEngine(t, dir, Options{Protector: protector})
	require.NoError(t, engine.StoreIAM(func(data []byte) ([]byte, error) {
		conf, err := engine.ParseIAM(data)
		if err != nil {
			return nil, err
		}
		conf.Users["alice"] = "first"
		return json.Marshal(conf)
	}))

	// The write primed the cache with what it just published, so repeated
	// reads afterwards decrypt nothing.
	afterWrite := counter.unwraps.Load()
	for range 5 {
		conf, err := engine.GetIAM()
		require.NoError(t, err)
		require.Equal(t, "first", conf.Users["alice"])
	}
	require.Equal(t, afterWrite, counter.unwraps.Load(), "cached reads must not touch the key provider")

	// Once the validity window has passed, the file is read again, but
	// unchanged bytes still cost no decryption.
	expireCache(engine)
	conf, err := engine.GetIAM()
	require.NoError(t, err)
	require.Equal(t, "first", conf.Users["alice"])
	require.Equal(t, afterWrite, counter.unwraps.Load(), "unchanged bytes must not be decrypted again")

	// A second gateway on the same directory replaces the file.
	other := newTestEngine(t, dir, Options{Protector: newProtectorForKey(t, keyDir, "primary")})
	require.NoError(t, other.StoreIAM(func(data []byte) ([]byte, error) {
		conf, err := other.ParseIAM(data)
		if err != nil {
			return nil, err
		}
		conf.Users["alice"] = "second"
		return json.Marshal(conf)
	}))

	expireCache(engine)
	conf, err = engine.GetIAM()
	require.NoError(t, err)
	require.Equal(t, "second", conf.Users["alice"], "a foreign write must invalidate the cache")
	require.Equal(t, afterWrite+1, counter.unwraps.Load(), "exactly one unwrap per observed file version")
}

func TestEngineCacheExpiresWithinItsValidityWindow(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	engine := newTestEngine(t, dir, Options{Protector: newTestProtector(t, "primary")})
	require.NoError(t, engine.StoreIAM(func(data []byte) ([]byte, error) {
		conf, err := engine.ParseIAM(data)
		if err != nil {
			return nil, err
		}
		conf.Users["alice"] = "before"
		return json.Marshal(conf)
	}))

	// A foreign writer replaces the file behind the engine's back. Once the
	// window has passed the change must be visible without any restart.
	require.NoError(t, os.WriteFile(filepath.Join(dir, testIAMFile),
		mustEncode(t, engine, `{"users":{"alice":"after"}}`), 0o600))

	conf, err := engine.GetIAM()
	require.NoError(t, err)
	require.Equal(t, "before", conf.Users["alice"], "reads inside the window stay on the cached store")

	expireCache(engine)
	conf, err = engine.GetIAM()
	require.NoError(t, err)
	require.Equal(t, "after", conf.Users["alice"])
}

// expireCache ages the cache past its validity window, the way wall-clock time
// does in a running gateway.
func expireCache(engine *Engine[testConfig]) {
	engine.cache.Lock()
	defer engine.cache.Unlock()

	engine.cache.validated = engine.cache.validated.Add(-2 * cacheValidity)
}

func mustEncode(t *testing.T, engine *Engine[testConfig], plaintext string) []byte {
	t.Helper()

	encoded, err := engine.encode([]byte(plaintext), true)
	require.NoError(t, err)

	return encoded
}

func TestEngineCachedPlaintextCannotBeMutatedByCallers(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	engine := newTestEngine(t, dir, Options{Protector: newTestProtector(t, "primary")})
	require.NoError(t, engine.StoreIAM(func(data []byte) ([]byte, error) {
		conf, err := engine.ParseIAM(data)
		if err != nil {
			return nil, err
		}
		conf.Users["alice"] = "stable"
		return json.Marshal(conf)
	}))

	first, err := engine.ReadIAMData()
	require.NoError(t, err)
	clear(first)

	second, err := engine.ReadIAMData()
	require.NoError(t, err)
	require.Contains(t, string(second), "stable")
}

// countingProvider records unwrap calls so a test can tell a cached read from
// one that reached the key provider.
type countingProvider struct {
	encryption.KeyProvider
	unwraps atomic.Int64
}

func (p *countingProvider) UnwrapKey(ctx context.Context, request encryption.KeyRequest, wrapped encryption.WrappedDataKey) (encryption.SensitiveBytes, error) {
	p.unwraps.Add(1)
	return p.KeyProvider.UnwrapKey(ctx, request, wrapped)
}

func newTestEngine(t *testing.T, dir string, opts Options) *Engine[testConfig] {
	t.Helper()

	engine, err := NewWithOptions(dir, testIAMFile, testBackupFmt, testConfig{Users: map[string]string{}}, normalizeTestConfig, opts)
	require.NoError(t, err)

	return engine
}

func newTestProtector(t *testing.T, keyID string) *Protector {
	t.Helper()

	dir := t.TempDir()
	writeTestKey(t, dir, keyID, 0x42)

	return newProtectorForKey(t, dir, keyID)
}

func newProtectorForKey(t *testing.T, keyDir, keyID string) *Protector {
	t.Helper()

	protector, err := NewProtector(newLocalProvider(t, keyDir, keyID), keyID)
	require.NoError(t, err)

	return protector
}

func newLocalProvider(t *testing.T, keyDir, keyID string) encryption.KeyProvider {
	t.Helper()

	provider, err := encryption.NewLocalProvider(keyDir, keyID)
	require.NoError(t, err)
	t.Cleanup(provider.Close)

	return provider
}

func writeTestKey(t *testing.T, dir, keyID string, fill byte) {
	t.Helper()

	require.NoError(t, os.Chmod(dir, 0o700))
	require.NoError(t, os.WriteFile(filepath.Join(dir, keyID+".key"),
		bytes.Repeat([]byte{fill}, encryption.DataKeySize), 0o600))
}

func normalizeTestConfig(conf *testConfig) {
	if conf.Users == nil {
		conf.Users = map[string]string{}
	}
}
