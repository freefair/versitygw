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
	"crypto/rand"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"maps"
	"os"
	"path/filepath"
	"sync"
	"testing"

	awskms "github.com/aws/aws-sdk-go-v2/service/kms"
	"github.com/stretchr/testify/require"

	"github.com/versity/versitygw/internal/encryption"
)

func TestKMSProtectorRoundTripsAndBindsTheEncryptionContext(t *testing.T) {
	t.Parallel()

	client := newFakeKMS()
	protector := newKMSTestProtector(t, client)
	plaintext := []byte(`{"accessAccounts":{"alice":{"secret":"top-secret"}}}`)

	ciphertext, err := protector.Encode(context.Background(), testIAMFile, plaintext)
	require.NoError(t, err)
	require.NotContains(t, string(ciphertext), "top-secret")

	info, err := Inspect(ciphertext)
	require.NoError(t, err)
	require.Equal(t, encryption.ModeSSEKMS, info.Mode, "a KMS-wrapped store must say so in its header")
	require.Equal(t, "alias/versitygw-iam", info.KeyReferences[0].KeyID)

	decoded, err := protector.Decode(context.Background(), testIAMFile, ciphertext)
	require.NoError(t, err)
	require.Equal(t, plaintext, decoded)

	// The store file name reaches KMS as encryption context, so a container
	// cannot be moved to another store even with the same key.
	_, err = protector.Decode(context.Background(), "iam.json", ciphertext)
	require.Error(t, err)
}

func TestKMSStoreCallsTheProviderOnlyWhenBytesChange(t *testing.T) {
	t.Parallel()

	client := newFakeKMS()
	dir := t.TempDir()
	engine := newTestEngine(t, dir, Options{Protector: newKMSTestProtector(t, client), RequireEncryption: true})

	require.NoError(t, engine.StoreIAM(func(data []byte) ([]byte, error) {
		conf, err := engine.ParseIAM(data)
		if err != nil {
			return nil, err
		}
		conf.Users["alice"] = "kms"
		return json.Marshal(conf)
	}))

	decrypts := client.decrypts()
	for range 5 {
		expireCache(engine)
		conf, err := engine.GetIAM()
		require.NoError(t, err)
		require.Equal(t, "kms", conf.Users["alice"])
	}
	require.Equal(t, decrypts, client.decrypts(),
		"an unchanged store must not spend a KMS call per cache refresh")

	// A restart has to decrypt exactly once, not once per read.
	restarted := newTestEngine(t, dir, Options{Protector: newKMSTestProtector(t, client)})
	for range 3 {
		expireCache(restarted)
		_, err := restarted.GetIAM()
		require.NoError(t, err)
	}
	require.Equal(t, decrypts+1, client.decrypts())
}

func newKMSTestProtector(t *testing.T, client encryption.AWSKMSClient) *Protector {
	t.Helper()

	provider, err := encryption.NewAWSKMSProvider(client, "alias/versitygw-iam", 0)
	require.NoError(t, err)

	protector, err := NewProtector(provider, "alias/versitygw-iam")
	require.NoError(t, err)

	return protector
}

// fakeKMS stands in for AWS KMS: it keeps data keys server-side, keyed by an
// opaque blob, and enforces the encryption context the way KMS does.
type fakeKMS struct {
	mu            sync.Mutex
	keys          map[string]fakeKMSEntry
	decryptCalls  int
	generateCalls int
}

type fakeKMSEntry struct {
	key     []byte
	context map[string]string
}

func newFakeKMS() *fakeKMS {
	return &fakeKMS{keys: map[string]fakeKMSEntry{}}
}

func (f *fakeKMS) GenerateDataKey(_ context.Context, input *awskms.GenerateDataKeyInput, _ ...func(*awskms.Options)) (*awskms.GenerateDataKeyOutput, error) {
	key := make([]byte, encryption.DataKeySize)
	if _, err := io.ReadFull(rand.Reader, key); err != nil {
		return nil, err
	}
	blob := f.store(key, input.EncryptionContext)

	f.mu.Lock()
	f.generateCalls++
	f.mu.Unlock()

	return &awskms.GenerateDataKeyOutput{Plaintext: key, CiphertextBlob: blob}, nil
}

func (f *fakeKMS) Encrypt(_ context.Context, input *awskms.EncryptInput, _ ...func(*awskms.Options)) (*awskms.EncryptOutput, error) {
	return &awskms.EncryptOutput{CiphertextBlob: f.store(input.Plaintext, input.EncryptionContext)}, nil
}

func (f *fakeKMS) Decrypt(_ context.Context, input *awskms.DecryptInput, _ ...func(*awskms.Options)) (*awskms.DecryptOutput, error) {
	f.mu.Lock()
	defer f.mu.Unlock()

	f.decryptCalls++
	entry, ok := f.keys[string(input.CiphertextBlob)]
	if !ok {
		return nil, errors.New("kms: unknown ciphertext blob")
	}
	if !maps.Equal(entry.context, input.EncryptionContext) {
		return nil, errors.New("kms: encryption context mismatch")
	}

	return &awskms.DecryptOutput{Plaintext: append([]byte(nil), entry.key...)}, nil
}

func (f *fakeKMS) store(key []byte, encryptionContext map[string]string) []byte {
	blob := make([]byte, 16)
	if _, err := io.ReadFull(rand.Reader, blob); err != nil {
		panic(fmt.Sprintf("fake kms blob: %v", err))
	}

	f.mu.Lock()
	defer f.mu.Unlock()

	f.keys[string(blob)] = fakeKMSEntry{
		key:     append([]byte(nil), key...),
		context: maps.Clone(encryptionContext),
	}

	return blob
}

func (f *fakeKMS) decrypts() int {
	f.mu.Lock()
	defer f.mu.Unlock()

	return f.decryptCalls
}

func TestEngineHandlesConcurrentReadersAlongsideWriters(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	engine := newTestEngine(t, dir, Options{Protector: newTestProtector(t, "primary")})

	// The IAM services serialize their own writes, so the engine sees many
	// concurrent readers next to one writer at a time.
	const writes = 20
	var writeLock sync.Mutex
	var group sync.WaitGroup

	for reader := range 8 {
		group.Add(1)
		go func() {
			defer group.Done()
			for range 50 {
				conf, err := engine.GetIAM()
				if err != nil {
					t.Errorf("reader %d: %v", reader, err)
					return
				}
				if conf.Users == nil {
					t.Errorf("reader %d saw a store without users", reader)
					return
				}
			}
		}()
	}

	group.Add(1)
	go func() {
		defer group.Done()
		for i := range writes {
			writeLock.Lock()
			err := engine.StoreIAM(func(data []byte) ([]byte, error) {
				conf, err := engine.ParseIAM(data)
				if err != nil {
					return nil, err
				}
				conf.Users[fmt.Sprintf("user-%02d", i)] = "written"
				return json.Marshal(conf)
			})
			writeLock.Unlock()
			if err != nil {
				t.Errorf("writer: %v", err)
				return
			}
		}
	}()

	group.Wait()

	conf, err := engine.GetIAM()
	require.NoError(t, err)
	require.Len(t, conf.Users, writes, "every serialized write must survive")

	stored, err := os.ReadFile(filepath.Join(dir, testIAMFile))
	require.NoError(t, err)
	require.True(t, IsEncrypted(stored))
}
