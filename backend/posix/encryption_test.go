// Copyright 2026 Versity Software
// This file is licensed under the Apache License, Version 2.0.

package posix

import (
	"bytes"
	"context"
	"crypto/md5"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"testing"

	"github.com/aws/aws-sdk-go-v2/service/s3"
	"github.com/aws/aws-sdk-go-v2/service/s3/types"
	"github.com/versity/versitygw/backend/meta"
	"github.com/versity/versitygw/internal/encryption"
	"github.com/versity/versitygw/s3response"
)

func TestEncryptedObjectRoundTripRangeAndAtRestCiphertext(t *testing.T) {
	backend, root := newEncryptionTestBackend(t, false)
	payload := bytes.Repeat([]byte("plaintext-marker-"), encryption.DefaultChunkSize/8)
	bucket, key := "bucket", "large-object"
	if err := os.Mkdir(filepath.Join(root, bucket), 0o755); err != nil {
		t.Fatal(err)
	}

	put, err := backend.PutObject(context.Background(), s3response.PutObjectInput{
		Bucket: &bucket, Key: &key, ContentLength: int64Ptr(int64(len(payload))), Body: bytes.NewReader(payload),
		Encryption: &encryption.Intent{Mode: encryption.ModeSSES3},
	})
	if err != nil {
		t.Fatalf("PutObject() error = %v", err)
	}
	if put.Encryption == nil || put.Encryption.Mode != encryption.ModeSSES3 {
		t.Fatalf("PutObject() encryption = %#v", put.Encryption)
	}
	stored, err := os.ReadFile(filepath.Join(root, bucket, key))
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(stored, []byte("plaintext-marker-")) {
		t.Fatal("stored object contains a plaintext marker")
	}
	if !bytes.HasPrefix(stored, []byte{'V', 'G', 'W', 'S', 'S', 'E', '1', 0}) {
		t.Fatalf("stored object does not use the encrypted container: %x", stored[:min(8, len(stored))])
	}
	maxKeys, startAfter := int32(1000), ""
	listed, err := backend.ListObjectsV2(context.Background(), &s3.ListObjectsV2Input{
		Bucket: &bucket, MaxKeys: &maxKeys, StartAfter: &startAfter,
	})
	if err != nil {
		t.Fatalf("ListObjectsV2() error = %v", err)
	}
	if len(listed.Contents) != 1 || listed.Contents[0].Size == nil || *listed.Contents[0].Size != int64(len(payload)) {
		t.Fatalf("ListObjectsV2() size = %#v, want %d", listed.Contents, len(payload))
	}

	get, err := backend.GetObject(context.Background(), &s3.GetObjectInput{Bucket: &bucket, Key: &key})
	if err != nil {
		t.Fatalf("GetObject() error = %v", err)
	}
	got, err := io.ReadAll(get.Body)
	if err != nil {
		t.Fatalf("read GetObject body: %v", err)
	}
	if err := get.Body.Close(); err != nil {
		t.Fatalf("close GetObject body: %v", err)
	}
	if !bytes.Equal(got, payload) {
		t.Fatalf("GetObject() returned %d bytes, want %d", len(got), len(payload))
	}
	if get.ContentLength == nil || *get.ContentLength != int64(len(payload)) || get.ServerSideEncryption != types.ServerSideEncryptionAes256 {
		t.Fatalf("GetObject() metadata = length %v, encryption %q", get.ContentLength, get.ServerSideEncryption)
	}

	rangeHeader := "bytes=1048568-1048592"
	ranged, err := backend.GetObject(context.Background(), &s3.GetObjectInput{Bucket: &bucket, Key: &key, Range: &rangeHeader})
	if err != nil {
		t.Fatalf("ranged GetObject() error = %v", err)
	}
	rangeBody, err := io.ReadAll(ranged.Body)
	if err != nil {
		t.Fatalf("read ranged body: %v", err)
	}
	_ = ranged.Body.Close()
	if !bytes.Equal(rangeBody, payload[1048568:1048593]) {
		t.Fatalf("ranged GetObject() = %q, want %q", rangeBody, payload[1048568:1048593])
	}

	head, err := backend.HeadObject(context.Background(), &s3.HeadObjectInput{Bucket: &bucket, Key: &key})
	if err != nil {
		t.Fatalf("HeadObject() error = %v", err)
	}
	if head.ContentLength == nil || *head.ContentLength != int64(len(payload)) || head.ServerSideEncryption != types.ServerSideEncryptionAes256 {
		t.Fatalf("HeadObject() metadata = length %v, encryption %q", head.ContentLength, head.ServerSideEncryption)
	}
}

func TestEncryptedObjectSSECustomerKeyAndVersioning(t *testing.T) {
	backend, root := newEncryptionTestBackend(t, true)
	bucket, key := "bucket", "versioned"
	if err := os.Mkdir(filepath.Join(root, bucket), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := backend.PutBucketVersioning(context.Background(), bucket, types.BucketVersioningStatusEnabled); err != nil {
		t.Fatal(err)
	}

	customerKey := bytes.Repeat([]byte{0x5a}, encryption.DataKeySize)
	keyMD5 := md5.Sum(customerKey)
	encodedKey := base64.StdEncoding.EncodeToString(customerKey)
	encodedMD5 := base64.StdEncoding.EncodeToString(keyMD5[:])
	firstPayload := []byte("first secret version")
	first, err := backend.PutObject(context.Background(), s3response.PutObjectInput{
		Bucket: &bucket, Key: &key, ContentLength: int64Ptr(int64(len(firstPayload))), Body: bytes.NewReader(firstPayload),
		Encryption: &encryption.Intent{Mode: encryption.ModeSSEC, CustomerKey: append(encryption.SensitiveBytes(nil), customerKey...), CustomerKeyMD5: keyMD5},
	})
	if err != nil {
		t.Fatalf("first PutObject() error = %v", err)
	}
	if first.VersionID == "" {
		t.Fatal("versioned PutObject() returned no version ID")
	}

	secondPayload := []byte("second managed version")
	if _, err := backend.PutObject(context.Background(), s3response.PutObjectInput{
		Bucket: &bucket, Key: &key, ContentLength: int64Ptr(int64(len(secondPayload))), Body: bytes.NewReader(secondPayload),
		Encryption: &encryption.Intent{Mode: encryption.ModeSSES3},
	}); err != nil {
		t.Fatalf("second PutObject() error = %v", err)
	}

	versionID := first.VersionID
	old, err := backend.GetObject(context.Background(), &s3.GetObjectInput{
		Bucket: &bucket, Key: &key, VersionId: &versionID,
		SSECustomerAlgorithm: stringTestPtr("AES256"), SSECustomerKey: &encodedKey, SSECustomerKeyMD5: &encodedMD5,
	})
	if err != nil {
		t.Fatalf("GetObject(old SSE-C version) error = %v", err)
	}
	oldBody, err := io.ReadAll(old.Body)
	if err != nil {
		t.Fatal(err)
	}
	_ = old.Body.Close()
	if !bytes.Equal(oldBody, firstPayload) || old.SSECustomerKeyMD5 == nil || *old.SSECustomerKeyMD5 != encodedMD5 {
		t.Fatalf("old version body/metadata mismatch: body=%q md5=%v", oldBody, old.SSECustomerKeyMD5)
	}
	if _, err := backend.GetObjectAttributes(context.Background(), &s3.GetObjectAttributesInput{
		Bucket: &bucket, Key: &key, VersionId: &versionID,
		SSECustomerAlgorithm: stringTestPtr("AES256"), SSECustomerKey: &encodedKey, SSECustomerKeyMD5: &encodedMD5,
	}); err != nil {
		t.Fatalf("GetObjectAttributes(old SSE-C version) error = %v", err)
	}

	wrongKey := base64.StdEncoding.EncodeToString(bytes.Repeat([]byte{0x2a}, encryption.DataKeySize))
	wrongMD5Bytes := md5.Sum(bytes.Repeat([]byte{0x2a}, encryption.DataKeySize))
	wrongMD5 := base64.StdEncoding.EncodeToString(wrongMD5Bytes[:])
	if _, err := backend.GetObject(context.Background(), &s3.GetObjectInput{
		Bucket: &bucket, Key: &key, VersionId: &versionID,
		SSECustomerAlgorithm: stringTestPtr("AES256"), SSECustomerKey: &wrongKey, SSECustomerKeyMD5: &wrongMD5,
	}); err == nil {
		t.Fatal("GetObject() with wrong SSE-C key succeeded")
	}
}

func TestEncryptionOutputValuesOnlyReportsBucketKeyForSSEKMS(t *testing.T) {
	for _, mode := range []encryption.Mode{encryption.ModeSSES3, encryption.ModeSSEC, encryption.ModeDSSEKMS} {
		_, _, _, _, bucketKey := encryptionOutputValues(&encryption.Result{Mode: mode})
		if bucketKey != nil {
			t.Fatalf("mode %s returned BucketKeyEnabled=%v", mode, *bucketKey)
		}
	}
	_, _, _, _, bucketKey := encryptionOutputValues(&encryption.Result{Mode: encryption.ModeSSEKMS})
	if bucketKey == nil || *bucketKey {
		t.Fatalf("SSE-KMS returned BucketKeyEnabled=%v", bucketKey)
	}
}

func TestEncryptedObjectLocalDSSEUsesTwoRecoverableLayers(t *testing.T) {
	backend, root := newEncryptionTestBackend(t, false)
	bucket, key := "bucket", "double-encrypted"
	if err := os.Mkdir(filepath.Join(root, bucket), 0o755); err != nil {
		t.Fatal(err)
	}
	payload := []byte("two independent data-key layers")
	put, err := backend.PutObject(context.Background(), s3response.PutObjectInput{
		Bucket: &bucket, Key: &key, ContentLength: int64Ptr(int64(len(payload))), Body: bytes.NewReader(payload),
		Encryption: &encryption.Intent{Mode: encryption.ModeDSSEKMS},
	})
	if err != nil {
		t.Fatalf("PutObject() error = %v", err)
	}
	if put.Encryption == nil || put.Encryption.Mode != encryption.ModeDSSEKMS {
		t.Fatalf("PutObject() encryption = %#v", put.Encryption)
	}
	get, err := backend.GetObject(context.Background(), &s3.GetObjectInput{Bucket: &bucket, Key: &key})
	if err != nil {
		t.Fatalf("GetObject() error = %v", err)
	}
	got, err := io.ReadAll(get.Body)
	if err != nil {
		t.Fatal(err)
	}
	_ = get.Body.Close()
	if !bytes.Equal(got, payload) || get.ServerSideEncryption != types.ServerSideEncryptionAwsKmsDsse {
		t.Fatalf("GetObject() = %q, encryption %q", got, get.ServerSideEncryption)
	}
}

func TestEncryptedObjectWithCorruptMagicIsNotServedAsPlaintext(t *testing.T) {
	backend, root := newEncryptionTestBackend(t, false)
	bucket, key := "bucket", "corrupt-container"
	if err := os.Mkdir(filepath.Join(root, bucket), 0o755); err != nil {
		t.Fatal(err)
	}
	payload := []byte("secret payload")
	if _, err := backend.PutObject(context.Background(), s3response.PutObjectInput{
		Bucket: &bucket, Key: &key, ContentLength: int64Ptr(int64(len(payload))), Body: bytes.NewReader(payload),
		Encryption: &encryption.Intent{Mode: encryption.ModeSSES3},
	}); err != nil {
		t.Fatal(err)
	}
	file, err := os.OpenFile(filepath.Join(root, bucket, key), os.O_WRONLY, 0)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := file.WriteAt([]byte{'X'}, 0); err != nil {
		_ = file.Close()
		t.Fatal(err)
	}
	if err := file.Close(); err != nil {
		t.Fatal(err)
	}

	if _, err := backend.GetObject(context.Background(), &s3.GetObjectInput{Bucket: &bucket, Key: &key}); !errors.Is(err, encryption.ErrInvalidContainer) {
		t.Fatalf("GetObject() error = %v, want invalid encrypted container", err)
	}
}

func TestLegacyPlaintextWithContainerMagicPrefixRemainsReadable(t *testing.T) {
	backend, root := newEncryptionTestBackend(t, false)
	bucket, key := "bucket", "legacy-magic-prefix"
	if err := os.Mkdir(filepath.Join(root, bucket), 0o755); err != nil {
		t.Fatal(err)
	}
	payload := append([]byte{'V', 'G', 'W', 'S', 'S', 'E', '1', 0}, []byte("ordinary legacy bytes")...)
	if err := os.WriteFile(filepath.Join(root, bucket, key), payload, 0o600); err != nil {
		t.Fatal(err)
	}
	get, err := backend.GetObject(context.Background(), &s3.GetObjectInput{Bucket: &bucket, Key: &key})
	if err != nil {
		t.Fatalf("GetObject() error = %v", err)
	}
	got, err := io.ReadAll(get.Body)
	_ = get.Body.Close()
	if err != nil || !bytes.Equal(got, payload) {
		t.Fatalf("legacy plaintext = %q, %v", got, err)
	}
	inventory, err := backend.AuditEncryption(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if inventory.PlaintextLegacy != 1 || inventory.InvalidContainers != 0 {
		t.Fatalf("inventory = %#v", inventory)
	}
}

func TestBucketEncryptionMigrationStateDistinguishesExistingAndNewBuckets(t *testing.T) {
	backend, root := newEncryptionTestBackend(t, false)
	if err := os.Mkdir(filepath.Join(root, "existing"), 0o755); err != nil {
		t.Fatal(err)
	}
	existing, err := backend.GetEncryptionConfiguration(context.Background(), "existing")
	if err != nil {
		t.Fatal(err)
	}
	if existing.Rules[0].BlocksSSEC() {
		t.Fatal("pre-existing bucket unexpectedly blocks SSE-C")
	}

	newBucket := "new-bucket"
	if err := backend.CreateBucket(context.Background(), &s3.CreateBucketInput{
		Bucket: &newBucket, CreateBucketConfiguration: &types.CreateBucketConfiguration{},
	}, []byte(`{"owner":"test"}`)); err != nil {
		t.Fatal(err)
	}
	created, err := backend.GetEncryptionConfiguration(context.Background(), newBucket)
	if err != nil {
		t.Fatal(err)
	}
	if !created.Rules[0].BlocksSSEC() {
		t.Fatal("new bucket did not receive the SSE-C blocking default")
	}
	if err := backend.DeleteEncryptionConfiguration(context.Background(), newBucket); err != nil {
		t.Fatal(err)
	}
	reset, err := backend.GetEncryptionConfiguration(context.Background(), newBucket)
	if err != nil {
		t.Fatal(err)
	}
	if !reset.Rules[0].BlocksSSEC() {
		t.Fatal("deleting bucket encryption did not restore the new-bucket default")
	}
}

func TestEncryptedObjectResolvesDefaultKMSKeyReference(t *testing.T) {
	backend, root := newEncryptionTestBackend(t, false)
	bucket, key := "bucket", "kms-object"
	if err := os.Mkdir(filepath.Join(root, bucket), 0o755); err != nil {
		t.Fatal(err)
	}

	put, err := backend.PutObject(context.Background(), s3response.PutObjectInput{
		Bucket: &bucket, Key: &key, ContentLength: int64Ptr(3), Body: bytes.NewReader([]byte("kms")),
		Encryption: &encryption.Intent{Mode: encryption.ModeSSEKMS},
	})
	if err != nil {
		t.Fatalf("PutObject() error = %v", err)
	}
	if put.Encryption == nil || put.Encryption.KMSKeyID != "active" {
		t.Fatalf("PutObject() encryption = %#v, want KMS key active", put.Encryption)
	}

	head, err := backend.HeadObject(context.Background(), &s3.HeadObjectInput{Bucket: &bucket, Key: &key})
	if err != nil {
		t.Fatalf("HeadObject() error = %v", err)
	}
	if head.SSEKMSKeyId == nil || *head.SSEKMSKeyId != "active" {
		t.Fatalf("HeadObject() KMS key = %v, want active", head.SSEKMSKeyId)
	}

	multipartKey := "kms-multipart"
	created, err := backend.CreateMultipartUpload(context.Background(), s3response.CreateMultipartUploadInput{
		Bucket: &bucket, Key: &multipartKey, Encryption: &encryption.Intent{Mode: encryption.ModeSSEKMS},
	})
	if err != nil {
		t.Fatalf("CreateMultipartUpload() error = %v", err)
	}
	if created.Encryption == nil || created.Encryption.KMSKeyID != "active" {
		t.Fatalf("CreateMultipartUpload() encryption = %#v, want KMS key active", created.Encryption)
	}
}

func TestEncryptedMultipartPartsAndCompletedObjectStayEncryptedAtRest(t *testing.T) {
	backend, root := newEncryptionTestBackend(t, false)
	bucket, key := "bucket", "multipart-object"
	if err := os.Mkdir(filepath.Join(root, bucket), 0o755); err != nil {
		t.Fatal(err)
	}
	created, err := backend.CreateMultipartUpload(context.Background(), s3response.CreateMultipartUploadInput{
		Bucket: &bucket, Key: &key, Encryption: &encryption.Intent{Mode: encryption.ModeSSES3},
	})
	if err != nil {
		t.Fatalf("CreateMultipartUpload() error = %v", err)
	}
	if created.Encryption == nil || created.Encryption.Mode != encryption.ModeSSES3 {
		t.Fatalf("CreateMultipartUpload() encryption = %#v", created.Encryption)
	}
	payload := bytes.Repeat([]byte("multipart-plaintext-marker"), 70000)
	partNumber := int32(1)
	part, err := backend.UploadPart(context.Background(), &s3.UploadPartInput{
		Bucket: &bucket, Key: &key, UploadId: &created.UploadId, PartNumber: &partNumber,
		ContentLength: int64Ptr(int64(len(payload))), Body: bytes.NewReader(payload),
	})
	if err != nil {
		t.Fatalf("UploadPart() error = %v", err)
	}
	objectHash := sha256.Sum256([]byte(key))
	partPath := filepath.Join(root, bucket, MetaTmpMultipartDir, fmt.Sprintf("%x", objectHash), created.UploadId, "1")
	storedPart, err := os.ReadFile(partPath)
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(storedPart, []byte("multipart-plaintext-marker")) {
		t.Fatal("multipart part contains plaintext at rest")
	}

	completed, _, err := backend.CompleteMultipartUpload(context.Background(), &s3.CompleteMultipartUploadInput{
		Bucket: &bucket, Key: &key, UploadId: &created.UploadId,
		MultipartUpload: &types.CompletedMultipartUpload{Parts: []types.CompletedPart{{PartNumber: &partNumber, ETag: part.ETag}}},
	})
	if err != nil {
		t.Fatalf("CompleteMultipartUpload() error = %v", err)
	}
	if completed.Encryption == nil || completed.Encryption.Mode != encryption.ModeSSES3 {
		t.Fatalf("CompleteMultipartUpload() encryption = %#v", completed.Encryption)
	}
	storedObject, err := os.ReadFile(filepath.Join(root, bucket, key))
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(storedObject, []byte("multipart-plaintext-marker")) {
		t.Fatal("completed multipart object contains plaintext at rest")
	}
	get, err := backend.GetObject(context.Background(), &s3.GetObjectInput{Bucket: &bucket, Key: &key})
	if err != nil {
		t.Fatalf("GetObject() error = %v", err)
	}
	got, err := io.ReadAll(get.Body)
	if err != nil {
		t.Fatal(err)
	}
	_ = get.Body.Close()
	if !bytes.Equal(got, payload) {
		t.Fatalf("completed body has %d bytes, want %d", len(got), len(payload))
	}
}

func TestPlainMultipartCompletesWithXattrMetadata(t *testing.T) {
	original, err := os.Getwd()
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.Chdir(original) })
	root := t.TempDir()
	backend, err := New(root, meta.XattrMeta{}, PosixOpts{NewDirPerm: 0o755, ValidateBucketNames: true})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(backend.Shutdown)
	bucket, key := "bucket", "plain-multipart"
	if err := os.Mkdir(bucket, 0o755); err != nil {
		t.Fatal(err)
	}
	created, err := backend.CreateMultipartUpload(context.Background(), s3response.CreateMultipartUploadInput{Bucket: &bucket, Key: &key})
	if err != nil {
		t.Fatal(err)
	}
	payload := []byte("plain multipart payload")
	partNumber := int32(1)
	part, err := backend.UploadPart(context.Background(), &s3.UploadPartInput{
		Bucket: &bucket, Key: &key, UploadId: &created.UploadId, PartNumber: &partNumber,
		ContentLength: int64Ptr(int64(len(payload))), Body: bytes.NewReader(payload),
	})
	if err != nil {
		t.Fatal(err)
	}
	completeInput := &s3.CompleteMultipartUploadInput{
		Bucket: &bucket, Key: &key, UploadId: &created.UploadId,
		MultipartUpload: &types.CompletedMultipartUpload{Parts: []types.CompletedPart{{PartNumber: &partNumber, ETag: part.ETag}}},
	}
	if _, _, err := backend.CompleteMultipartUpload(context.Background(), completeInput); err != nil {
		t.Fatalf("CompleteMultipartUpload() error = %v", err)
	}
	if _, _, err := backend.CompleteMultipartUpload(context.Background(), completeInput); err != nil {
		t.Fatalf("second CompleteMultipartUpload() error = %v", err)
	}
}

func TestCopyDecryptsSourceAndAppliesDestinationEncryption(t *testing.T) {
	backend, root := newEncryptionTestBackend(t, false)
	bucket, sourceKey, destinationKey := "bucket", "customer-source", "managed-copy"
	if err := os.Mkdir(filepath.Join(root, bucket), 0o755); err != nil {
		t.Fatal(err)
	}
	payload := []byte("copy plaintext must never be persisted")
	customerKey := bytes.Repeat([]byte{0x67}, encryption.DataKeySize)
	digest := md5.Sum(customerKey)
	encodedKey := base64.StdEncoding.EncodeToString(customerKey)
	encodedMD5 := base64.StdEncoding.EncodeToString(digest[:])
	if _, err := backend.PutObject(context.Background(), s3response.PutObjectInput{
		Bucket: &bucket, Key: &sourceKey, ContentLength: int64Ptr(int64(len(payload))), Body: bytes.NewReader(payload),
		Encryption: &encryption.Intent{Mode: encryption.ModeSSEC, CustomerKey: append(encryption.SensitiveBytes(nil), customerKey...), CustomerKeyMD5: digest},
	}); err != nil {
		t.Fatal(err)
	}
	copySource, owner := bucket+"/"+sourceKey, ""
	if _, err := backend.CopyObject(context.Background(), s3response.CopyObjectInput{
		Bucket: &bucket, Key: &destinationKey, CopySource: &copySource, ExpectedBucketOwner: &owner,
		CopySourceSSECustomerAlgorithm: stringTestPtr("AES256"), CopySourceSSECustomerKey: &encodedKey, CopySourceSSECustomerKeyMD5: &encodedMD5,
		DestinationEncryption: &encryption.Intent{Mode: encryption.ModeSSES3},
	}); err != nil {
		t.Fatalf("CopyObject() error = %v", err)
	}
	stored, err := os.ReadFile(filepath.Join(root, bucket, destinationKey))
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(stored, payload) {
		t.Fatal("copied destination contains plaintext")
	}
	get, err := backend.GetObject(context.Background(), &s3.GetObjectInput{Bucket: &bucket, Key: &destinationKey})
	if err != nil {
		t.Fatal(err)
	}
	got, err := io.ReadAll(get.Body)
	if err != nil {
		t.Fatal(err)
	}
	_ = get.Body.Close()
	if !bytes.Equal(got, payload) || get.ServerSideEncryption != types.ServerSideEncryptionAes256 {
		t.Fatalf("copied object = %q, encryption %q", got, get.ServerSideEncryption)
	}
	if _, err := backend.CopyObject(context.Background(), s3response.CopyObjectInput{
		Bucket: &bucket, Key: stringTestPtr("missing-key-copy"), CopySource: &copySource, ExpectedBucketOwner: &owner,
		DestinationEncryption: &encryption.Intent{Mode: encryption.ModeSSES3},
	}); err == nil {
		t.Fatal("CopyObject() read an SSE-C source without its customer key")
	}
}

func TestEncryptedSelfCopyPreservesCopiedTags(t *testing.T) {
	backend, root := newEncryptionTestBackend(t, false)
	bucket, key := "bucket", "self-copy"
	if err := os.Mkdir(filepath.Join(root, bucket), 0o755); err != nil {
		t.Fatal(err)
	}
	payload := []byte("self-copy payload")
	if _, err := backend.PutObject(context.Background(), s3response.PutObjectInput{
		Bucket: &bucket, Key: &key, ContentLength: int64Ptr(int64(len(payload))), Body: bytes.NewReader(payload),
		Tagging: stringTestPtr("keep=yes"), Encryption: &encryption.Intent{Mode: encryption.ModeSSES3},
	}); err != nil {
		t.Fatal(err)
	}
	copySource, owner := bucket+"/"+key, ""
	if _, err := backend.CopyObject(context.Background(), s3response.CopyObjectInput{
		Bucket: &bucket, Key: &key, CopySource: &copySource, ExpectedBucketOwner: &owner,
		MetadataDirective: types.MetadataDirectiveReplace, TaggingDirective: types.TaggingDirectiveCopy,
		DestinationEncryption: &encryption.Intent{Mode: encryption.ModeSSES3},
	}); err != nil {
		t.Fatalf("CopyObject() error = %v", err)
	}
	tags, err := backend.GetObjectTagging(context.Background(), bucket, key, "")
	if err != nil {
		t.Fatal(err)
	}
	if tags["keep"] != "yes" || len(tags) != 1 {
		t.Fatalf("self-copy tags = %#v", tags)
	}
}

func TestUploadPartCopyReencryptsSourceIntoMultipartPart(t *testing.T) {
	backend, root := newEncryptionTestBackend(t, false)
	bucket, sourceKey, destinationKey := "bucket", "copy-part-source", "copy-part-destination"
	if err := os.Mkdir(filepath.Join(root, bucket), 0o755); err != nil {
		t.Fatal(err)
	}
	payload := bytes.Repeat([]byte("copy-part-secret"), 90000)
	if _, err := backend.PutObject(context.Background(), s3response.PutObjectInput{
		Bucket: &bucket, Key: &sourceKey, ContentLength: int64Ptr(int64(len(payload))), Body: bytes.NewReader(payload),
		Encryption: &encryption.Intent{Mode: encryption.ModeSSES3},
	}); err != nil {
		t.Fatal(err)
	}
	created, err := backend.CreateMultipartUpload(context.Background(), s3response.CreateMultipartUploadInput{
		Bucket: &bucket, Key: &destinationKey, Encryption: &encryption.Intent{Mode: encryption.ModeSSES3},
	})
	if err != nil {
		t.Fatal(err)
	}
	partNumber, emptyRange := int32(1), ""
	copySource := bucket + "/" + sourceKey
	part, err := backend.UploadPartCopy(context.Background(), &s3.UploadPartCopyInput{
		Bucket: &bucket, Key: &destinationKey, UploadId: &created.UploadId, PartNumber: &partNumber,
		CopySource: &copySource, CopySourceRange: &emptyRange,
	})
	if err != nil {
		t.Fatalf("UploadPartCopy() error = %v", err)
	}
	if _, _, err := backend.CompleteMultipartUpload(context.Background(), &s3.CompleteMultipartUploadInput{
		Bucket: &bucket, Key: &destinationKey, UploadId: &created.UploadId,
		MultipartUpload: &types.CompletedMultipartUpload{Parts: []types.CompletedPart{{PartNumber: &partNumber, ETag: part.ETag}}},
	}); err != nil {
		t.Fatalf("CompleteMultipartUpload() error = %v", err)
	}
	get, err := backend.GetObject(context.Background(), &s3.GetObjectInput{Bucket: &bucket, Key: &destinationKey})
	if err != nil {
		t.Fatal(err)
	}
	got, err := io.ReadAll(get.Body)
	if err != nil {
		t.Fatal(err)
	}
	_ = get.Body.Close()
	if !bytes.Equal(got, payload) {
		t.Fatalf("copied multipart object has %d bytes, want %d", len(got), len(payload))
	}
}

func TestAuditEncryptionReportsPlaintextAndMissingKeysWithoutDecryptingObjects(t *testing.T) {
	backend, root := newEncryptionTestBackend(t, false)
	bucket := "bucket"
	if err := os.Mkdir(filepath.Join(root, bucket), 0o755); err != nil {
		t.Fatal(err)
	}

	encryptedKey, plaintextKey := "encrypted", "plaintext"
	for _, object := range []struct {
		key        string
		payload    []byte
		encryption *encryption.Intent
	}{
		{key: encryptedKey, payload: []byte("encrypted payload"), encryption: &encryption.Intent{Mode: encryption.ModeSSES3}},
		{key: plaintextKey, payload: []byte("legacy plaintext")},
	} {
		if _, err := backend.PutObject(context.Background(), s3response.PutObjectInput{
			Bucket: &bucket, Key: &object.key, ContentLength: int64Ptr(int64(len(object.payload))),
			Body: bytes.NewReader(object.payload), Encryption: object.encryption,
		}); err != nil {
			t.Fatalf("PutObject(%q) error = %v", object.key, err)
		}
	}

	inventory, err := backend.AuditEncryption(context.Background())
	if err != nil {
		t.Fatalf("AuditEncryption() error = %v", err)
	}
	if inventory.Buckets != 1 || inventory.Objects != 2 || inventory.Encrypted != 1 || inventory.PlaintextLegacy != 1 {
		t.Fatalf("AuditEncryption() inventory = %#v", inventory)
	}
	if inventory.FormatVersions[1] != 1 || !inventory.Healthy() {
		t.Fatalf("AuditEncryption() healthy inventory = %#v", inventory)
	}

	provider := backend.managedEncryptionProvider
	backend.encryptionProvider = nil
	backend.managedEncryptionProvider = nil
	backend.dsseEncryptionProvider = nil
	missing, err := backend.AuditEncryption(context.Background())
	backend.encryptionProvider = provider
	backend.managedEncryptionProvider = provider
	if err != nil {
		t.Fatalf("AuditEncryption() without provider error = %v", err)
	}
	if missing.MissingKeyObjects != 1 || missing.MissingKeyReferences["local:active"] != 1 || missing.Healthy() {
		t.Fatalf("AuditEncryption() missing-key inventory = %#v", missing)
	}
}

func TestRewrapEncryptionRotatesManifestWithoutChangingObjectData(t *testing.T) {
	backend, root := newEncryptionTestBackend(t, false)
	bucket, key := "bucket", "object"
	payload := bytes.Repeat([]byte("rotation payload"), encryption.DefaultChunkSize/16)
	if err := os.Mkdir(filepath.Join(root, bucket), 0o755); err != nil {
		t.Fatal(err)
	}
	if _, err := backend.PutObject(context.Background(), s3response.PutObjectInput{
		Bucket: &bucket, Key: &key, ContentLength: int64Ptr(int64(len(payload))), Body: bytes.NewReader(payload),
		Encryption: &encryption.Intent{Mode: encryption.ModeSSES3},
	}); err != nil {
		t.Fatal(err)
	}

	keyDirectory := filepath.Join(filepath.Dir(root), "keys")
	if err := os.WriteFile(filepath.Join(keyDirectory, "rotated.key"), bytes.Repeat([]byte{0x6b}, encryption.DataKeySize), 0o600); err != nil {
		t.Fatal(err)
	}
	rotated, err := encryption.NewLocalProvider(keyDirectory, "rotated")
	if err != nil {
		t.Fatal(err)
	}
	derived, err := rotated.Derived("local-dsse", "dsse-second-layer")
	if err != nil {
		t.Fatal(err)
	}
	backend.managedEncryptionProvider = rotated
	backend.encryptionProvider = rotated
	backend.dsseEncryptionProvider = derived

	result, err := backend.RewrapEncryption(context.Background(), false)
	if err != nil {
		t.Fatalf("RewrapEncryption() error = %v", err)
	}
	if result.Changed != 1 || result.Failed != 0 {
		t.Fatalf("RewrapEncryption() = %#v", result)
	}
	inventory, err := backend.AuditEncryption(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if inventory.MissingKeyObjects != 0 || inventory.MissingKeyReferences["local:active"] != 0 || inventory.FormatVersions[1] != 1 {
		t.Fatalf("AuditEncryption() after rewrap = %#v", inventory)
	}
	get, err := backend.GetObject(context.Background(), &s3.GetObjectInput{Bucket: &bucket, Key: &key})
	if err != nil {
		t.Fatal(err)
	}
	decrypted, err := io.ReadAll(get.Body)
	if err != nil {
		t.Fatal(err)
	}
	_ = get.Body.Close()
	if !bytes.Equal(decrypted, payload) {
		t.Fatal("rewrapped object payload changed")
	}
}

func TestRewrapEncryptionIncludesIncompleteMultipartParts(t *testing.T) {
	backend, root := newEncryptionTestBackend(t, false)
	bucket, key := "bucket", "incomplete"
	if err := os.Mkdir(filepath.Join(root, bucket), 0o755); err != nil {
		t.Fatal(err)
	}
	created, err := backend.CreateMultipartUpload(context.Background(), s3response.CreateMultipartUploadInput{
		Bucket: &bucket, Key: &key, Encryption: &encryption.Intent{Mode: encryption.ModeSSES3},
	})
	if err != nil {
		t.Fatal(err)
	}
	payload := bytes.Repeat([]byte("multipart rotation"), 400000)
	partNumber := int32(1)
	part, err := backend.UploadPart(context.Background(), &s3.UploadPartInput{
		Bucket: &bucket, Key: &key, UploadId: &created.UploadId, PartNumber: &partNumber,
		ContentLength: int64Ptr(int64(len(payload))), Body: bytes.NewReader(payload),
	})
	if err != nil {
		t.Fatal(err)
	}

	keyDirectory := filepath.Join(filepath.Dir(root), "keys")
	if err := os.WriteFile(filepath.Join(keyDirectory, "rotated.key"), bytes.Repeat([]byte{0x7c}, encryption.DataKeySize), 0o600); err != nil {
		t.Fatal(err)
	}
	rotated, err := encryption.NewLocalProvider(keyDirectory, "rotated")
	if err != nil {
		t.Fatal(err)
	}
	derived, err := rotated.Derived("local-dsse", "dsse-second-layer")
	if err != nil {
		t.Fatal(err)
	}
	backend.managedEncryptionProvider, backend.encryptionProvider, backend.dsseEncryptionProvider = rotated, rotated, derived

	result, err := backend.RewrapEncryption(context.Background(), false)
	if err != nil {
		t.Fatalf("RewrapEncryption() error = %v", err)
	}
	if result.Changed != 1 || result.Failed != 0 {
		t.Fatalf("RewrapEncryption() = %#v", result)
	}
	inventory, err := backend.AuditEncryption(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if inventory.MultipartParts != 1 || inventory.MissingKeyReferences["local:active"] != 0 {
		t.Fatalf("AuditEncryption() = %#v", inventory)
	}

	if _, _, err := backend.CompleteMultipartUpload(context.Background(), &s3.CompleteMultipartUploadInput{
		Bucket: &bucket, Key: &key, UploadId: &created.UploadId,
		MultipartUpload: &types.CompletedMultipartUpload{Parts: []types.CompletedPart{{PartNumber: &partNumber, ETag: part.ETag}}},
	}); err != nil {
		t.Fatalf("CompleteMultipartUpload() error = %v", err)
	}
	get, err := backend.GetObject(context.Background(), &s3.GetObjectInput{Bucket: &bucket, Key: &key})
	if err != nil {
		t.Fatal(err)
	}
	decrypted, err := io.ReadAll(get.Body)
	_ = get.Body.Close()
	if err != nil || !bytes.Equal(decrypted, payload) {
		t.Fatalf("completed payload changed: bytes=%d error=%v", len(decrypted), err)
	}
}

func TestReencryptLegacyEncryptsPlaintextInPlace(t *testing.T) {
	backend, root := newEncryptionTestBackend(t, false)
	bucket, key := "bucket", "legacy"
	payload := []byte("legacy plaintext payload")
	if err := os.Mkdir(filepath.Join(root, bucket), 0o755); err != nil {
		t.Fatal(err)
	}
	put, err := backend.PutObject(context.Background(), s3response.PutObjectInput{
		Bucket: &bucket, Key: &key, ContentLength: int64Ptr(int64(len(payload))), Body: bytes.NewReader(payload),
	})
	if err != nil {
		t.Fatal(err)
	}

	result, err := backend.ReencryptLegacy(context.Background(), false)
	if err != nil {
		t.Fatalf("ReencryptLegacy() error = %v", err)
	}
	if result.Changed != 1 || result.Failed != 0 {
		t.Fatalf("ReencryptLegacy() = %#v", result)
	}
	stored, err := os.ReadFile(filepath.Join(root, bucket, key))
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(stored, payload) {
		t.Fatal("re-encrypted object still contains plaintext")
	}
	get, err := backend.GetObject(context.Background(), &s3.GetObjectInput{Bucket: &bucket, Key: &key})
	if err != nil {
		t.Fatal(err)
	}
	decrypted, err := io.ReadAll(get.Body)
	if err != nil {
		t.Fatal(err)
	}
	_ = get.Body.Close()
	if !bytes.Equal(decrypted, payload) || get.ETag == nil || *get.ETag != put.ETag {
		t.Fatalf("re-encrypted object payload/etag changed: etag %v want %v", get.ETag, put.ETag)
	}
}

func newEncryptionTestBackend(t *testing.T, versioning bool) (*Posix, string) {
	t.Helper()
	original, err := os.Getwd()
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.Chdir(original) })

	base := t.TempDir()
	root, sidecar, keyDir := filepath.Join(base, "objects"), filepath.Join(base, "metadata"), filepath.Join(base, "keys")
	for _, directory := range []string{root, sidecar, keyDir} {
		if err := os.Mkdir(directory, 0o700); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.WriteFile(filepath.Join(keyDir, "active.key"), bytes.Repeat([]byte{0xa5}, encryption.DataKeySize), 0o600); err != nil {
		t.Fatal(err)
	}
	provider, err := encryption.NewLocalProvider(keyDir, "active")
	if err != nil {
		t.Fatal(err)
	}
	store, err := meta.NewSideCar(sidecar)
	if err != nil {
		t.Fatal(err)
	}
	opts := PosixOpts{
		SideCarDir: sidecar, ValidateBucketNames: true, NewDirPerm: 0o755,
		CopyObjectThreshold: 5 * 1024 * 1024 * 1024,
		EncryptionProvider:  provider, ManagedEncryptionProvider: provider, EncryptionKeyDirectory: keyDir,
	}
	if versioning {
		opts.VersioningDir = filepath.Join(base, "versions")
		if err := os.Mkdir(opts.VersioningDir, 0o700); err != nil {
			t.Fatal(err)
		}
	}
	backend, err := New(root, store, opts)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(backend.Shutdown)
	return backend, root
}

func TestEncryptionKeyDirectoryRejectsCanonicalOverlap(t *testing.T) {
	base := t.TempDir()
	root := filepath.Join(base, "objects")
	keyDir := filepath.Join(root, "keys")
	alias := filepath.Join(base, "key-alias")
	for _, directory := range []string{root, keyDir} {
		if err := os.Mkdir(directory, 0o700); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.WriteFile(filepath.Join(keyDir, "active.key"), bytes.Repeat([]byte{0xa5}, encryption.DataKeySize), 0o600); err != nil {
		t.Fatal(err)
	}
	provider, err := encryption.NewLocalProvider(keyDir, "active")
	if err != nil {
		t.Fatal(err)
	}
	defer provider.Close()
	if err := os.Symlink(keyDir, alias); err != nil {
		t.Fatal(err)
	}

	backend, err := New(root, meta.NoMeta{}, PosixOpts{
		EncryptionProvider: provider, ManagedEncryptionProvider: provider, EncryptionKeyDirectory: alias,
	})
	if backend != nil {
		backend.Shutdown()
	}
	if err == nil {
		t.Fatal("New() accepted a key directory that resolves inside the object root")
	}
}

func int64Ptr(value int64) *int64 { return &value }

func stringTestPtr(value string) *string { return &value }
