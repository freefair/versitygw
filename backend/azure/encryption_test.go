// Copyright 2026 Versity Software
// This file is licensed under the Apache License, Version 2.0.

package azure

import (
	"bytes"
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/versity/versitygw/backend"
	"github.com/versity/versitygw/internal/encryption"
	"github.com/versity/versitygw/s3response"
)

func TestAzureEncryptionCapabilitiesFollowConfiguredProviders(t *testing.T) {
	az := &Azure{}
	if got := az.EncryptionCapabilities(); got != (encryption.Capabilities{}) {
		t.Fatalf("unconfigured capabilities = %+v, want none", got)
	}

	provider := newAzureTestLocalProvider(t)
	az.ConfigureEncryption(provider, provider)

	want := encryption.Capabilities{SSES3: true, SSEC: true, SSEKMS: true, DSSEKMS: true}
	if got := az.EncryptionCapabilities(); got != want {
		t.Fatalf("configured capabilities = %+v, want %+v", got, want)
	}
}

func TestAzureEncryptionOutputOnlyReportsBucketKeyForSSEKMS(t *testing.T) {
	for _, mode := range []encryption.Mode{encryption.ModeSSES3, encryption.ModeSSEC, encryption.ModeDSSEKMS} {
		_, _, _, _, bucketKey := azureEncryptionOutput(&encryption.Result{Mode: mode})
		if bucketKey != nil {
			t.Fatalf("mode %s returned BucketKeyEnabled=%v", mode, *bucketKey)
		}
	}
	_, _, _, _, bucketKey := azureEncryptionOutput(&encryption.Result{Mode: encryption.ModeSSEKMS})
	if bucketKey == nil || *bucketKey {
		t.Fatalf("SSE-KMS returned BucketKeyEnabled=%v", bucketKey)
	}
}

func TestEncryptedMultipartCleanupRemovesMarkerAfterParts(t *testing.T) {
	parts := []s3response.Part{{PartNumber: 2}, {PartNumber: 5}}
	paths := encryptedMultipartCleanupPaths("object", "upload", parts)
	if len(paths) != 3 || paths[2] != createMetaTmpPath("object", "upload") {
		t.Fatalf("cleanup paths = %#v", paths)
	}
	if paths[0] != azureMultipartPartPath("object", "upload", 2) || paths[1] != azureMultipartPartPath("object", "upload", 5) {
		t.Fatalf("cleanup part paths = %#v", paths[:2])
	}
}

func TestCompletedAzureMultipartUploadID(t *testing.T) {
	encoded, err := backend.MarshalMpUploadMetadata(backend.MpUploadMetadata{UploadID: "upload-id", Parts: []int64{5}}, true)
	if err != nil {
		t.Fatal(err)
	}
	value := string(encoded)
	got, ok := completedAzureMultipartUploadID(map[string]*string{string(keyMpMetadata): &value})
	if !ok || got != "upload-id" {
		t.Fatalf("completed upload = %q, %v", got, ok)
	}
	if _, ok := completedAzureMultipartUploadID(map[string]*string{}); ok {
		t.Fatal("missing multipart metadata reported as completed")
	}
}

func TestAzureEnvelopeCopyGetInputForwardsSourceConditions(t *testing.T) {
	bucket, key := "source-bucket", "source-key"
	match, noneMatch := "etag", "other-etag"
	modified := time.Unix(100, 0).UTC()
	unmodified := time.Unix(200, 0).UTC()
	algorithm, customerKey, customerMD5 := "AES256", "key", "md5"

	got := azureEnvelopeCopyGetInput(s3response.CopyObjectInput{
		CopySourceIfMatch:              &match,
		CopySourceIfNoneMatch:          &noneMatch,
		CopySourceIfModifiedSince:      &modified,
		CopySourceIfUnmodifiedSince:    &unmodified,
		CopySourceSSECustomerAlgorithm: &algorithm,
		CopySourceSSECustomerKey:       &customerKey,
		CopySourceSSECustomerKeyMD5:    &customerMD5,
	}, bucket, key)

	if got.Bucket == nil || *got.Bucket != bucket || got.Key == nil || *got.Key != key ||
		got.IfMatch != &match || got.IfNoneMatch != &noneMatch ||
		got.IfModifiedSince != &modified || got.IfUnmodifiedSince != &unmodified ||
		got.SSECustomerAlgorithm != &algorithm || got.SSECustomerKey != &customerKey || got.SSECustomerKeyMD5 != &customerMD5 {
		t.Fatalf("GetObject input did not preserve copy-source conditions: %#v", got)
	}
}

func TestAzureClientTransportDoesNotDecodeObjectContentEncoding(t *testing.T) {
	want := []byte("encrypted-container-bytes")
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Encoding", "gzip")
		_, _ = w.Write(want)
	}))
	defer server.Close()

	request, err := http.NewRequest(http.MethodGet, server.URL, nil)
	if err != nil {
		t.Fatal(err)
	}
	response, err := newAzureClientOptions().Transport.Do(request)
	if err != nil {
		t.Fatal(err)
	}
	defer response.Body.Close()
	got, err := io.ReadAll(response.Body)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, want) {
		t.Fatalf("transport changed stored bytes: got %q, want %q", got, want)
	}
}

func TestAzureEncryptionMetadataRoundTrip(t *testing.T) {
	intent := &encryption.Intent{
		Mode:             encryption.ModeSSEKMS,
		KMSKeyID:         "key-1",
		BucketKeyEnabled: true,
	}
	metadata := map[string]*string{}
	if err := storeAzureEncryptionMetadata(metadata, intent, 1234); err != nil {
		t.Fatalf("store metadata: %v", err)
	}

	result, size, encrypted, err := loadAzureEncryptionMetadata(metadata)
	if err != nil {
		t.Fatalf("load metadata: %v", err)
	}
	if !encrypted || size != 1234 {
		t.Fatalf("encrypted=%v size=%d, want true/1234", encrypted, size)
	}
	if result.Mode != intent.Mode || result.KMSKeyID != intent.KMSKeyID || !result.BucketKeyEnabled {
		t.Fatalf("result = %+v", result)
	}
}

func TestAzureListedObjectSizeUsesPlaintextMetadata(t *testing.T) {
	intent := &encryption.Intent{Mode: encryption.ModeSSES3}
	metadata := map[string]*string{}
	if err := storeAzureEncryptionMetadata(metadata, intent, 0); err != nil {
		t.Fatalf("store metadata: %v", err)
	}
	storedSize := int64(462)

	got, err := azureListedObjectSize(&storedSize, metadata)
	if err != nil {
		t.Fatalf("listed size: %v", err)
	}
	if got == nil || *got != 0 {
		t.Fatalf("listed size = %v, want plaintext size 0", got)
	}
}

func TestAzureListedObjectSizeRejectsCorruptEncryptionMetadata(t *testing.T) {
	corrupt := "not-base64"
	storedSize := int64(462)

	_, err := azureListedObjectSize(&storedSize, map[string]*string{
		string(keyObjectEncryption): &corrupt,
	})
	if err == nil {
		t.Fatal("listed size accepted corrupt encryption metadata")
	}
}

func TestAzureEncryptedBodyRoundTripAndRange(t *testing.T) {
	provider := newAzureTestLocalProvider(t)
	az := &Azure{}
	az.ConfigureEncryption(provider, provider)
	payload := []byte("azure envelope encryption keeps plaintext out of blob storage")
	intent := &encryption.Intent{Mode: encryption.ModeSSES3}

	ciphertext, err := az.encryptBytes(context.Background(), encryption.Identity{
		Bucket: "bucket", Key: "object", VersionID: azureNullVersionID,
	}, intent, payload)
	if err != nil {
		t.Fatalf("encrypt: %v", err)
	}
	if string(ciphertext) == string(payload) {
		t.Fatal("ciphertext equals plaintext")
	}

	reader, result, encrypted, err := az.openEncryptedReader(context.Background(), bytes.NewReader(ciphertext), int64(len(ciphertext)), encryption.Identity{
		Bucket: "bucket", Key: "object", VersionID: azureNullVersionID,
	}, true, "", "", "")
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	if !encrypted || result.Mode != encryption.ModeSSES3 {
		t.Fatalf("encrypted=%v result=%+v", encrypted, result)
	}
	defer reader.Close()

	got, err := reader.ReadRange(6, 8)
	if err != nil {
		t.Fatalf("read range: %v", err)
	}
	if string(got) != string(payload[6:14]) {
		t.Fatalf("range = %q, want %q", got, payload[6:14])
	}
}

func newAzureTestLocalProvider(t *testing.T) *encryption.LocalProvider {
	t.Helper()
	directory := t.TempDir()
	if err := os.Chmod(directory, 0o700); err != nil {
		t.Fatalf("chmod key directory: %v", err)
	}
	if err := os.WriteFile(filepath.Join(directory, "active.key"), make([]byte, encryption.DataKeySize), 0o600); err != nil {
		t.Fatalf("write key: %v", err)
	}
	if err := os.WriteFile(filepath.Join(directory, "active"), []byte("active\n"), 0o600); err != nil {
		t.Fatalf("write active reference: %v", err)
	}
	provider, err := encryption.NewLocalProvider(directory, "")
	if err != nil {
		t.Fatalf("new local provider: %v", err)
	}
	t.Cleanup(provider.Close)
	return provider
}
