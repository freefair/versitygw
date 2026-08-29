// Copyright 2026 Versity Software
// This file is licensed under the Apache License, Version 2.0.

package encryption

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestBucketConfigurationRoundTripAndDefaults(t *testing.T) {
	t.Parallel()

	cfg, err := ParseConfiguration([]byte(`<ServerSideEncryptionConfiguration xmlns="http://s3.amazonaws.com/doc/2006-03-01/"><Rule><ApplyServerSideEncryptionByDefault><SSEAlgorithm>AES256</SSEAlgorithm></ApplyServerSideEncryptionByDefault><BucketKeyEnabled>true</BucketKeyEnabled><BlockedEncryptionTypes><EncryptionType>NONE</EncryptionType></BlockedEncryptionTypes></Rule></ServerSideEncryptionConfiguration>`))
	require.NoError(t, err)
	require.Equal(t, AlgorithmAES256, cfg.Rules[0].Default.Algorithm)
	require.False(t, cfg.Rules[0].BlocksSSEC())

	normalized, err := ValidateConfiguration(cfg, Capabilities{SSES3: true, SSEC: true})
	require.NoError(t, err)
	body, err := MarshalConfiguration(normalized)
	require.NoError(t, err)
	require.Contains(t, string(body), `<BucketKeyEnabled>true</BucketKeyEnabled>`)
	require.Contains(t, string(body), `<EncryptionType>NONE</EncryptionType>`)

	defaults := DefaultConfiguration()
	require.Equal(t, AlgorithmAES256, defaults.Rules[0].Default.Algorithm)
	require.True(t, defaults.Rules[0].BlocksSSEC())
}

func TestBucketConfigurationRejectsUnsupportedAlgorithm(t *testing.T) {
	t.Parallel()

	cfg := Configuration{Rules: []Rule{{Default: &DefaultEncryption{Algorithm: AlgorithmAWSKMS}}}}
	_, err := ValidateConfiguration(cfg, Capabilities{SSES3: true})
	require.ErrorIs(t, err, ErrUnsupportedEncryption)
}

func TestLegacyConfigurationKeepsSSECUnblocked(t *testing.T) {
	configuration := LegacyConfiguration()
	require.Len(t, configuration.Rules, 1)
	require.False(t, configuration.Rules[0].BlocksSSEC())
	require.Equal(t, AlgorithmAES256, configuration.Rules[0].Default.Algorithm)
}

func TestBucketConfigurationRejectsUnknownAndDuplicateElements(t *testing.T) {
	t.Parallel()
	for _, body := range []string{
		`<ServerSideEncryptionConfiguration><Rule><Unknown/></Rule></ServerSideEncryptionConfiguration>`,
		`<ServerSideEncryptionConfiguration><Rule><ApplyServerSideEncryptionByDefault><SSEAlgorithm>AES256</SSEAlgorithm><SSEAlgorithm>AES256</SSEAlgorithm></ApplyServerSideEncryptionByDefault></Rule></ServerSideEncryptionConfiguration>`,
	} {
		_, err := ParseConfiguration([]byte(body))
		require.ErrorIs(t, err, ErrInvalidConfiguration)
	}
}

func TestLocalProviderRotationKeepsHistoricalKeysReadable(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	writeKey(t, dir, "old", 0x11)
	writeKey(t, dir, "new", 0x22)
	require.NoError(t, os.WriteFile(filepath.Join(dir, "active"), []byte("old\n"), 0o600))

	provider, err := NewLocalProvider(dir, "")
	require.NoError(t, err)
	plain, wrapped, err := provider.GenerateDataKey(context.Background(), KeyRequest{Context: []byte("bucket/key")})
	require.NoError(t, err)
	require.Equal(t, "old", wrapped.KeyID)

	provider, err = NewLocalProvider(dir, "new")
	require.NoError(t, err)
	unwrapped, err := provider.UnwrapKey(context.Background(), KeyRequest{Context: []byte("bucket/key")}, wrapped)
	require.NoError(t, err)
	require.Equal(t, plain, unwrapped)
	plain.Destroy()
	unwrapped.Destroy()
}

func TestRewrapChangesOnlyManifestAndKeepsCiphertextReadable(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	writeKey(t, dir, "old", 0x11)
	writeKey(t, dir, "new", 0x22)
	oldProvider, err := NewLocalProvider(dir, "old")
	require.NoError(t, err)
	newProvider, err := NewLocalProvider(dir, "new")
	require.NoError(t, err)
	identity := Identity{Bucket: "bucket", Key: "object", VersionID: "version"}
	plaintext := bytes.Repeat([]byte("rewrap payload"), DefaultChunkSize/8)

	var original bytes.Buffer
	writer, err := NewWriter(context.Background(), &original, WriterOptions{
		Identity: identity, Mode: ModeSSES3, PlaintextSize: int64(len(plaintext)),
		Layers: []LayerRequest{{Provider: oldProvider}},
	})
	require.NoError(t, err)
	_, err = writer.Write(plaintext)
	require.NoError(t, err)
	require.NoError(t, writer.Close())

	var rewrapped bytes.Buffer
	info, err := Rewrap(context.Background(), &rewrapped, bytes.NewReader(original.Bytes()), int64(original.Len()), identity, ProviderMap{newProvider.Name(): newProvider})
	require.NoError(t, err)
	require.Equal(t, []KeyReference{{Provider: localProviderName, KeyID: "new"}}, info.KeyReferences)

	originalHeaderLength := int(binary.BigEndian.Uint32(original.Bytes()[len(containerMagic):preambleSize]))
	rewrappedHeaderLength := int(binary.BigEndian.Uint32(rewrapped.Bytes()[len(containerMagic):preambleSize]))
	require.Equal(t, original.Bytes()[preambleSize+originalHeaderLength:], rewrapped.Bytes()[preambleSize+rewrappedHeaderLength:])

	reader, err := Open(context.Background(), bytes.NewReader(rewrapped.Bytes()), int64(rewrapped.Len()), identity, ProviderMap{newProvider.Name(): newProvider})
	require.NoError(t, err)
	decrypted, err := reader.ReadRange(0, int64(len(plaintext)))
	require.NoError(t, err)
	require.Equal(t, plaintext, decrypted)
	require.NoError(t, reader.Close())
}

func TestLocalProviderRejectsInsecureKeyPermissions(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	path := filepath.Join(dir, "active-key.key")
	require.NoError(t, os.WriteFile(path, bytes.Repeat([]byte{0x33}, DataKeySize), 0o644))
	_, err := NewLocalProvider(dir, "active-key")
	require.ErrorIs(t, err, ErrInsecureKeyPermissions)
}

func TestLocalProviderRejectsInsecureDirectoryAndActiveFile(t *testing.T) {
	t.Run("directory", func(t *testing.T) {
		dir := t.TempDir()
		writeKey(t, dir, "active-key", 0x31)
		require.NoError(t, os.Chmod(dir, 0o755))
		_, err := NewLocalProvider(dir, "active-key")
		require.ErrorIs(t, err, ErrInsecureKeyPermissions)
	})

	t.Run("active file", func(t *testing.T) {
		dir := t.TempDir()
		writeKey(t, dir, "active-key", 0x32)
		require.NoError(t, os.WriteFile(filepath.Join(dir, "active"), []byte("active-key\n"), 0o644))
		_, err := NewLocalProvider(dir, "")
		require.ErrorIs(t, err, ErrInsecureKeyPermissions)
	})
}

func TestContainerRoundTripRangesAndCorruption(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	writeKey(t, dir, "active-key", 0x44)
	provider, err := NewLocalProvider(dir, "active-key")
	require.NoError(t, err)

	plaintext := make([]byte, DefaultChunkSize*2+137)
	_, err = rand.Read(plaintext)
	require.NoError(t, err)
	identity := Identity{Bucket: "bucket", Key: "path/object", VersionID: "version"}

	var encrypted bytes.Buffer
	writer, err := NewWriter(context.Background(), &encrypted, WriterOptions{
		Identity:      identity,
		Mode:          ModeSSES3,
		PlaintextSize: int64(len(plaintext)),
		Layers:        []LayerRequest{{Provider: provider}},
	})
	require.NoError(t, err)
	_, err = writer.Write(plaintext)
	require.NoError(t, err)
	require.NoError(t, writer.Close())
	require.Equal(t, int64(encrypted.Len()), writer.CiphertextSize())

	reader, err := Open(context.Background(), bytes.NewReader(encrypted.Bytes()), int64(encrypted.Len()), identity, ProviderMap{provider.Name(): provider})
	require.NoError(t, err)
	require.Equal(t, int64(len(plaintext)), reader.PlaintextSize())
	got, err := reader.ReadRange(DefaultChunkSize-7, 21)
	require.NoError(t, err)
	require.Equal(t, plaintext[DefaultChunkSize-7:DefaultChunkSize+14], got)

	corrupt := append([]byte(nil), encrypted.Bytes()...)
	corrupt[len(corrupt)-1] ^= 0x80
	reader, err = Open(context.Background(), bytes.NewReader(corrupt), int64(len(corrupt)), identity, ProviderMap{provider.Name(): provider})
	require.NoError(t, err)
	_, err = reader.ReadRange(int64(len(plaintext)-1), 1)
	require.ErrorIs(t, err, ErrAuthentication)

	_, err = Open(context.Background(), bytes.NewReader(encrypted.Bytes()), int64(encrypted.Len()), Identity{Bucket: "other", Key: identity.Key, VersionID: identity.VersionID}, ProviderMap{provider.Name(): provider})
	require.ErrorIs(t, err, ErrIdentityMismatch)
}

func TestCustomerKeyProviderDoesNotPersistCustomerKey(t *testing.T) {
	t.Parallel()

	key := bytes.Repeat([]byte{0x5a}, DataKeySize)
	provider, err := NewCustomerKeyProvider(key)
	require.NoError(t, err)
	plain, wrapped, err := provider.GenerateDataKey(context.Background(), KeyRequest{Context: []byte("bucket/key")})
	require.NoError(t, err)
	require.NotContains(t, base64.StdEncoding.EncodeToString(wrapped.Ciphertext), base64.StdEncoding.EncodeToString(key))

	other, err := NewCustomerKeyProvider(bytes.Repeat([]byte{0x6b}, DataKeySize))
	require.NoError(t, err)
	_, err = other.UnwrapKey(context.Background(), KeyRequest{Context: []byte("bucket/key")}, wrapped)
	require.ErrorIs(t, err, ErrAuthentication)
	plain.Destroy()
}

func TestContainerRejectsHeaderTruncationAndReorderedChunks(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	writeKey(t, dir, "active-key", 0x71)
	provider, err := NewLocalProvider(dir, "active-key")
	require.NoError(t, err)
	plaintext := bytes.Repeat([]byte("a"), DefaultChunkSize*2)
	identity := Identity{Bucket: "bucket", Key: "object", VersionID: "version"}
	encrypted := writeTestContainer(t, provider, identity, plaintext)

	truncated := encrypted[:len(encrypted)-1]
	_, err = Open(context.Background(), bytes.NewReader(truncated), int64(len(truncated)), identity, ProviderMap{provider.Name(): provider})
	require.ErrorIs(t, err, ErrInvalidContainer)

	headerLength := int(binary.BigEndian.Uint32(encrypted[len(containerMagic):preambleSize]))
	modifiedHeader := append([]byte(nil), encrypted...)
	modeOffset := bytes.Index(modifiedHeader[preambleSize:preambleSize+headerLength], []byte("SSE-S3"))
	require.NotEqual(t, -1, modeOffset)
	modifiedHeader[preambleSize+modeOffset+len("SSE-")] = 'C'
	_, err = Open(context.Background(), bytes.NewReader(modifiedHeader), int64(len(modifiedHeader)), identity, ProviderMap{provider.Name(): provider})
	require.Error(t, err)

	reordered := append([]byte(nil), encrypted...)
	dataOffset := preambleSize + headerLength
	chunkLength := DefaultChunkSize + gcmTagSize
	first := append([]byte(nil), reordered[dataOffset:dataOffset+chunkLength]...)
	copy(reordered[dataOffset:dataOffset+chunkLength], reordered[dataOffset+chunkLength:dataOffset+2*chunkLength])
	copy(reordered[dataOffset+chunkLength:dataOffset+2*chunkLength], first)
	reader, err := Open(context.Background(), bytes.NewReader(reordered), int64(len(reordered)), identity, ProviderMap{provider.Name(): provider})
	require.NoError(t, err)
	_, err = reader.ReadRange(0, 1)
	require.ErrorIs(t, err, ErrAuthentication)
}

func TestContainerRangeBoundariesAndNonceDomains(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	writeKey(t, dir, "active-key", 0x72)
	provider, err := NewLocalProvider(dir, "active-key")
	require.NoError(t, err)
	plaintext := make([]byte, DefaultChunkSize+1)
	_, err = rand.Read(plaintext)
	require.NoError(t, err)
	identity := Identity{Bucket: "bucket", Key: "object", VersionID: "version"}
	first := writeTestContainer(t, provider, identity, plaintext)
	second := writeTestContainer(t, provider, identity, plaintext)

	for _, position := range []int64{0, DefaultChunkSize - 1, DefaultChunkSize} {
		reader, err := Open(context.Background(), bytes.NewReader(first), int64(len(first)), identity, ProviderMap{provider.Name(): provider})
		require.NoError(t, err)
		got, err := reader.ReadRange(position, 1)
		require.NoError(t, err)
		require.Equal(t, plaintext[position:position+1], got)
	}
	reader, err := Open(context.Background(), bytes.NewReader(first), int64(len(first)), identity, ProviderMap{provider.Name(): provider})
	require.NoError(t, err)
	empty, err := reader.ReadRange(int64(len(plaintext)), 0)
	require.NoError(t, err)
	require.Empty(t, empty)

	firstManifest := decodeTestManifest(t, first)
	secondManifest := decodeTestManifest(t, second)
	require.NotEqual(t, firstManifest.Layers[0].NoncePrefix, secondManifest.Layers[0].NoncePrefix)
	require.NotEqual(t, firstManifest.Layers[0].WrappedDataKey.Ciphertext, secondManifest.Layers[0].WrappedDataKey.Ciphertext)
}

func TestInspectReturnsOnlyContainerMetadataAndKeyReferences(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	writeKey(t, dir, "active-key", 0x77)
	provider, err := NewLocalProvider(dir, "active-key")
	require.NoError(t, err)
	container := writeTestContainer(t, provider, Identity{Bucket: "bucket", Key: "object", VersionID: "version"}, []byte("payload"))
	info, err := Inspect(bytes.NewReader(container), int64(len(container)))
	require.NoError(t, err)
	require.Equal(t, 1, info.FormatVersion)
	require.Equal(t, ModeSSES3, info.Mode)
	require.Equal(t, int64(7), info.PlaintextSize)
	require.Equal(t, []KeyReference{{Provider: localProviderName, KeyID: "active-key"}}, info.KeyReferences)

	_, err = Inspect(bytes.NewReader(container[:len(container)-1]), int64(len(container)-1))
	require.ErrorIs(t, err, ErrInvalidContainer)
}

func TestLocalProviderRejectsSymlinksAndReportsMissingHistoricalKey(t *testing.T) {
	dir := t.TempDir()
	writeKey(t, dir, "old", 0x73)
	writeKey(t, dir, "new", 0x74)
	provider, err := NewLocalProvider(dir, "old")
	require.NoError(t, err)
	plain, wrapped, err := provider.GenerateDataKey(context.Background(), KeyRequest{Context: []byte("context")})
	require.NoError(t, err)
	plain.Destroy()
	require.NoError(t, os.Remove(filepath.Join(dir, "old.key")))
	provider, err = NewLocalProvider(dir, "new")
	require.NoError(t, err)
	_, err = provider.UnwrapKey(context.Background(), KeyRequest{Context: []byte("context")}, wrapped)
	require.ErrorIs(t, err, ErrKeyNotFound)

	target := filepath.Join(t.TempDir(), "target.key")
	require.NoError(t, os.WriteFile(target, bytes.Repeat([]byte{0x75}, DataKeySize), 0o600))
	require.NoError(t, os.Symlink(target, filepath.Join(dir, "linked.key")))
	_, err = NewLocalProvider(dir, "new")
	require.ErrorIs(t, err, ErrInvalidKey)
	require.NoError(t, os.Remove(filepath.Join(dir, "linked.key")))
	nonKeyTarget := filepath.Join(t.TempDir(), "notes")
	require.NoError(t, os.WriteFile(nonKeyTarget, []byte("not key material"), 0o600))
	require.NoError(t, os.Symlink(nonKeyTarget, filepath.Join(dir, "notes-link")))
	_, err = NewLocalProvider(dir, "new")
	require.ErrorIs(t, err, ErrInvalidKey)
	require.NoError(t, os.Remove(filepath.Join(dir, "notes-link")))

	symlinkDir := filepath.Join(t.TempDir(), "keys-link")
	require.NoError(t, os.Symlink(dir, symlinkDir))
	_, err = NewLocalProvider(symlinkDir, "new")
	require.ErrorIs(t, err, ErrInvalidKey)
}

func TestLocalProviderAuthenticatesWrappingContext(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	writeKey(t, dir, "active-key", 0x76)
	provider, err := NewLocalProvider(dir, "active-key")
	require.NoError(t, err)
	plain, wrapped, err := provider.GenerateDataKey(context.Background(), KeyRequest{Context: []byte("first")})
	require.NoError(t, err)
	plain.Destroy()
	_, err = provider.UnwrapKey(context.Background(), KeyRequest{Context: []byte("second")}, wrapped)
	require.True(t, errors.Is(err, ErrAuthentication))
}

func writeTestContainer(t *testing.T, provider KeyProvider, identity Identity, plaintext []byte) []byte {
	t.Helper()
	var destination bytes.Buffer
	writer, err := NewWriter(context.Background(), &destination, WriterOptions{
		Identity: identity, Mode: ModeSSES3, PlaintextSize: int64(len(plaintext)),
		Layers: []LayerRequest{{Provider: provider}},
	})
	require.NoError(t, err)
	_, err = writer.Write(plaintext)
	require.NoError(t, err)
	require.NoError(t, writer.Close())
	return destination.Bytes()
}

func decodeTestManifest(t *testing.T, container []byte) containerManifest {
	t.Helper()
	headerLength := int(binary.BigEndian.Uint32(container[len(containerMagic):preambleSize]))
	var manifest containerManifest
	require.NoError(t, json.Unmarshal(container[preambleSize:preambleSize+headerLength], &manifest))
	return manifest
}

func writeKey(t *testing.T, dir, id string, fill byte) {
	t.Helper()
	require.NoError(t, os.Chmod(dir, 0o700))
	require.NoError(t, os.WriteFile(filepath.Join(dir, id+".key"), bytes.Repeat([]byte{fill}, DataKeySize), 0o600))
}
