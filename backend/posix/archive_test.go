// Copyright 2026 Versity Software
// This file is licensed under the Apache License, Version 2.0.

package posix

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/aws/aws-sdk-go-v2/service/s3"
	"github.com/aws/aws-sdk-go-v2/service/s3/types"
	"github.com/versity/versitygw/backend/meta"
	"github.com/versity/versitygw/internal/encryption"
	"github.com/versity/versitygw/internal/lifecycle"
	"github.com/versity/versitygw/s3err"
	"github.com/versity/versitygw/s3response"
)

func TestLifecycleTransitionsEncryptedObjectAndRestoreRoundTripsOpaqueBytes(t *testing.T) {
	backend, root, archiveRoot := newArchiveTestBackend(t)
	bucket, key := "bucket", "encrypted-archive"
	if err := os.Mkdir(filepath.Join(root, bucket), 0o755); err != nil {
		t.Fatal(err)
	}
	payload := bytes.Repeat([]byte("archive-plaintext-marker"), 1024)
	put, err := backend.PutObject(context.Background(), s3response.PutObjectInput{
		Bucket: &bucket, Key: &key, Body: bytes.NewReader(payload), ContentLength: int64Ptr(int64(len(payload))),
		Encryption: &encryption.Intent{Mode: encryption.ModeSSES3},
	})
	if err != nil {
		t.Fatalf("PutObject() error = %v", err)
	}
	old := time.Now().UTC().Add(-48 * time.Hour)
	if err := os.Chtimes(filepath.Join(root, bucket, key), old, old); err != nil {
		t.Fatal(err)
	}
	days := int32(0)
	configuration := lifecycle.Configuration{TransitionDefaultMinimumObjectSize: lifecycle.TransitionMinimumVariesByStorageClass, Rules: []lifecycle.Rule{{
		Filter: &lifecycle.Filter{}, Status: "Enabled",
		Transitions: []lifecycle.Transition{{Days: &days, StorageClass: "GLACIER"}},
	}}}
	if err := backend.PutLifecycleConfiguration(context.Background(), bucket, configuration); err != nil {
		t.Fatalf("PutLifecycleConfiguration() error = %v", err)
	}
	coordinator := lifecycle.Coordinator{Store: backend, Executor: backend, Clock: fixedLifecycleClock{time.Now().UTC()}}
	if err := coordinator.RunOnce(context.Background()); err != nil {
		t.Fatalf("RunOnce() error = %v", err)
	}
	stub, err := os.Stat(filepath.Join(root, bucket, key))
	if err != nil {
		t.Fatal(err)
	}
	if stub.Size() != 0 {
		t.Fatalf("hot stub size = %d, want 0", stub.Size())
	}
	manifest, err := backend.loadArchiveManifest(bucket, key)
	if err != nil || manifest == nil {
		t.Fatalf("loadArchiveManifest() = %#v, %v", manifest, err)
	}
	if manifest.ETag != put.ETag || manifest.Encryption == nil || manifest.Encryption.Mode != encryption.ModeSSES3 || manifest.ArchivePath == "" || filepath.IsAbs(manifest.ArchivePath) {
		t.Fatalf("archive recovery metadata = %#v, put ETag = %q", manifest, put.ETag)
	}
	archivedPath, err := backend.archiveDataPath(*manifest)
	if err != nil {
		t.Fatal(err)
	}
	archivedBytes, err := os.ReadFile(archivedPath)
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(archivedBytes, []byte("archive-plaintext-marker")) || !bytes.HasPrefix(archivedBytes, []byte{'V', 'G', 'W', 'S', 'S', 'E', '1', 0}) {
		t.Fatal("archive tier did not preserve the encrypted container")
	}
	if !stringsHasPathPrefix(archivedPath, archiveRoot) {
		t.Fatalf("archived path %q is outside %q", archivedPath, archiveRoot)
	}
	maintenance, err := backend.RewrapEncryption(context.Background(), false)
	if err != nil {
		t.Fatalf("RewrapEncryption() error = %v", err)
	}
	if maintenance.Changed == 0 {
		t.Fatal("RewrapEncryption() did not process the archived container")
	}
	manifest, err = backend.loadArchiveManifest(bucket, key)
	if err != nil || manifest == nil {
		t.Fatalf("loadArchiveManifest() after rewrap = %#v, %v", manifest, err)
	}
	if err := backend.verifyArchivedData(context.Background(), *manifest); err != nil {
		t.Fatalf("rewrapped archive no longer verifies: %v", err)
	}
	externalBody, err := os.ReadFile(archivedPath + ".json")
	if err != nil {
		t.Fatal(err)
	}
	var external archiveManifest
	if err := json.Unmarshal(externalBody, &external); err != nil {
		t.Fatal(err)
	}
	if external.SHA256 != manifest.SHA256 || external.StoredSize != manifest.StoredSize || external.Encryption == nil || external.Encryption.Mode != encryption.ModeSSES3 {
		t.Fatalf("archive manifest copies diverged after rewrap: metadata=%#v external=%#v", manifest, external)
	}
	if _, err := backend.GetObject(context.Background(), &s3.GetObjectInput{Bucket: &bucket, Key: &key}); !errors.Is(err, s3err.GetAPIError(s3err.ErrInvalidObjectState)) {
		t.Fatalf("GetObject() before restore error = %v", err)
	}
	copySource := bucket + "/" + key
	expectedOwner := ""
	if _, err := backend.CopyObject(context.Background(), s3response.CopyObjectInput{
		Bucket: &bucket, Key: stringTestPtr("copy-before-restore"), CopySource: &copySource, ExpectedBucketOwner: &expectedOwner,
	}); !errors.Is(err, s3err.GetAPIError(s3err.ErrInvalidObjectState)) {
		t.Fatalf("CopyObject() before restore error = %v", err)
	}
	created, err := backend.CreateMultipartUpload(context.Background(), s3response.CreateMultipartUploadInput{
		Bucket: &bucket, Key: stringTestPtr("part-copy-before-restore"),
	})
	if err != nil {
		t.Fatal(err)
	}
	partNumber, emptyRange := int32(1), ""
	if _, err := backend.UploadPartCopy(context.Background(), &s3.UploadPartCopyInput{
		Bucket: &bucket, Key: stringTestPtr("part-copy-before-restore"), UploadId: &created.UploadId, PartNumber: &partNumber,
		CopySource: &copySource, CopySourceRange: &emptyRange,
	}); !errors.Is(err, s3err.GetAPIError(s3err.ErrInvalidObjectState)) {
		t.Fatalf("UploadPartCopy() before restore error = %v", err)
	}
	head, err := backend.HeadObject(context.Background(), &s3.HeadObjectInput{Bucket: &bucket, Key: &key})
	if err != nil {
		t.Fatalf("HeadObject() error = %v", err)
	}
	if head.StorageClass != types.StorageClassGlacier || head.ContentLength == nil || *head.ContentLength != int64(len(payload)) || head.ServerSideEncryption != types.ServerSideEncryptionAes256 {
		t.Fatalf("HeadObject() = class %q, size %v, encryption %q", head.StorageClass, head.ContentLength, head.ServerSideEncryption)
	}
	restoreDays := int32(2)
	if err := backend.RestoreObject(context.Background(), &s3.RestoreObjectInput{
		Bucket: &bucket, Key: &key, RestoreRequest: &types.RestoreRequest{Days: &restoreDays},
	}); err != nil {
		t.Fatalf("RestoreObject() error = %v", err)
	}
	get, err := backend.GetObject(context.Background(), &s3.GetObjectInput{Bucket: &bucket, Key: &key})
	if err != nil {
		t.Fatalf("GetObject() after restore error = %v", err)
	}
	got, err := io.ReadAll(get.Body)
	if err != nil {
		t.Fatal(err)
	}
	_ = get.Body.Close()
	if !bytes.Equal(got, payload) || get.StorageClass != types.StorageClassGlacier || get.Restore == nil {
		t.Fatalf("restored object = %d bytes, class %q, restore %v", len(got), get.StorageClass, get.Restore)
	}
	expired := time.Now().UTC().Add(-time.Hour)
	manifest.RestoredUntil = &expired
	if err := backend.storeArchiveManifest(nil, bucket, key, *manifest); err != nil {
		t.Fatal(err)
	}
	if err := backend.DeleteLifecycleConfiguration(context.Background(), bucket); err != nil {
		t.Fatalf("DeleteLifecycleConfiguration() error = %v", err)
	}
	if err := coordinator.RunOnce(context.Background()); err != nil {
		t.Fatalf("RunOnce() restore expiry error = %v", err)
	}
	stub, err = os.Stat(filepath.Join(root, bucket, key))
	if err != nil {
		t.Fatal(err)
	}
	if stub.Size() != 0 {
		t.Fatalf("expired restore hot size = %d", stub.Size())
	}
	if _, err := backend.GetObject(context.Background(), &s3.GetObjectInput{Bucket: &bucket, Key: &key}); !errors.Is(err, s3err.GetAPIError(s3err.ErrInvalidObjectState)) {
		t.Fatalf("GetObject() after restore expiry error = %v", err)
	}
	head, err = backend.HeadObject(context.Background(), &s3.HeadObjectInput{Bucket: &bucket, Key: &key})
	if err != nil || head.Restore != nil {
		t.Fatalf("HeadObject() after restore expiry restore = %v, error = %v", head.Restore, err)
	}
	if _, err := backend.DeleteObject(context.Background(), &s3.DeleteObjectInput{Bucket: &bucket, Key: &key}); err != nil {
		t.Fatalf("DeleteObject() error = %v", err)
	}
	if _, err := os.Stat(archivedPath); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("archived bytes remain after permanent deletion: %v", err)
	}
}

func TestRestoreMissingObjectReturnsNoSuchKey(t *testing.T) {
	backend, root, _ := newArchiveTestBackend(t)
	bucket, key, days := "bucket", "missing", int32(1)
	if err := os.Mkdir(filepath.Join(root, bucket), 0o755); err != nil {
		t.Fatal(err)
	}
	err := backend.RestoreObject(context.Background(), &s3.RestoreObjectInput{
		Bucket: &bucket, Key: &key, RestoreRequest: &types.RestoreRequest{Days: &days},
	})
	if !errors.Is(err, s3err.GetAPIError(s3err.ErrNoSuchKey)) {
		t.Fatalf("RestoreObject() error = %v, want NoSuchKey", err)
	}
}

func TestReencryptLegacyArchivedObjectUpdatesRecoveryMetadata(t *testing.T) {
	backend, root, _ := newArchiveTestBackend(t)
	bucket, key := "bucket", "legacy-archive"
	if err := os.Mkdir(filepath.Join(root, bucket), 0o755); err != nil {
		t.Fatal(err)
	}
	payload := bytes.Repeat([]byte("legacy archive payload"), 4096)
	putLifecycleTestObject(t, backend, bucket, key, payload)
	ageLifecycleTestPath(t, filepath.Join(root, bucket, key))
	days := int32(0)
	configuration := lifecycle.Configuration{TransitionDefaultMinimumObjectSize: lifecycle.TransitionMinimumVariesByStorageClass, Rules: []lifecycle.Rule{{
		Filter: &lifecycle.Filter{}, Status: "Enabled", Transitions: []lifecycle.Transition{{Days: &days, StorageClass: "GLACIER"}},
	}}}
	if err := backend.PutLifecycleConfiguration(context.Background(), bucket, configuration); err != nil {
		t.Fatal(err)
	}
	coordinator := lifecycle.Coordinator{Store: backend, Executor: backend, Clock: fixedLifecycleClock{time.Now().UTC()}}
	if err := coordinator.RunOnce(context.Background()); err != nil {
		t.Fatal(err)
	}
	result, err := backend.ReencryptLegacy(context.Background(), false)
	if err != nil || result.Changed == 0 {
		t.Fatalf("ReencryptLegacy() = %#v, %v", result, err)
	}
	manifest, err := backend.loadArchiveManifest(bucket, key)
	if err != nil || manifest == nil || manifest.Encryption == nil || manifest.Encryption.Mode != encryption.ModeSSES3 {
		t.Fatalf("archive manifest after re-encryption = %#v, %v", manifest, err)
	}
	if err := backend.verifyArchivedData(context.Background(), *manifest); err != nil {
		t.Fatal(err)
	}
	restoreDays := int32(1)
	if err := backend.RestoreObject(context.Background(), &s3.RestoreObjectInput{
		Bucket: &bucket, Key: &key, RestoreRequest: &types.RestoreRequest{Days: &restoreDays},
	}); err != nil {
		t.Fatal(err)
	}
	object, err := backend.GetObject(context.Background(), &s3.GetObjectInput{Bucket: &bucket, Key: &key})
	if err != nil {
		t.Fatal(err)
	}
	body, err := io.ReadAll(object.Body)
	_ = object.Body.Close()
	if err != nil || !bytes.Equal(body, payload) {
		t.Fatalf("restored re-encrypted body length = %d, error = %v", len(body), err)
	}
}

func TestArchivedRewrapRollsBackBytesWhenMetadataRefreshFails(t *testing.T) {
	backend, root, _ := newArchiveTestBackend(t)
	bucket, key := "bucket", "rollback-archive"
	if err := os.Mkdir(filepath.Join(root, bucket), 0o755); err != nil {
		t.Fatal(err)
	}
	payload := bytes.Repeat([]byte("rollback payload"), 256)
	if _, err := backend.PutObject(context.Background(), s3response.PutObjectInput{
		Bucket: &bucket, Key: &key, Body: bytes.NewReader(payload), ContentLength: int64Ptr(int64(len(payload))),
		Encryption: &encryption.Intent{Mode: encryption.ModeSSES3},
	}); err != nil {
		t.Fatal(err)
	}
	ageLifecycleTestPath(t, filepath.Join(root, bucket, key))
	days := int32(0)
	configuration := lifecycle.Configuration{TransitionDefaultMinimumObjectSize: lifecycle.TransitionMinimumVariesByStorageClass, Rules: []lifecycle.Rule{{
		Filter: &lifecycle.Filter{}, Status: "Enabled", Transitions: []lifecycle.Transition{{Days: &days, StorageClass: "GLACIER"}},
	}}}
	if err := backend.PutLifecycleConfiguration(context.Background(), bucket, configuration); err != nil {
		t.Fatal(err)
	}
	coordinator := lifecycle.Coordinator{Store: backend, Executor: backend, Clock: fixedLifecycleClock{time.Now().UTC()}}
	if err := coordinator.RunOnce(context.Background()); err != nil {
		t.Fatal(err)
	}
	manifest, err := backend.loadArchiveManifest(bucket, key)
	if err != nil || manifest == nil {
		t.Fatalf("manifest = %#v, %v", manifest, err)
	}
	archivePath, err := backend.archiveDataPath(*manifest)
	if err != nil {
		t.Fatal(err)
	}
	before, err := os.ReadFile(archivePath)
	if err != nil {
		t.Fatal(err)
	}
	backend.meta = &failOnceMetadata{MetadataStorer: backend.meta, attribute: encryptionPlainSizeKey, failure: errors.New("injected metadata failure")}
	if _, err := backend.RewrapEncryption(context.Background(), false); err == nil {
		t.Fatal("RewrapEncryption() unexpectedly succeeded")
	}
	after, err := os.ReadFile(archivePath)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(after, before) {
		t.Fatal("archive bytes changed after failed metadata refresh")
	}
	restoredManifest, err := backend.loadArchiveManifest(bucket, key)
	if err != nil || restoredManifest == nil {
		t.Fatalf("restored manifest = %#v, %v", restoredManifest, err)
	}
	if err := backend.verifyArchivedData(context.Background(), *restoredManifest); err != nil {
		t.Fatalf("restored archive verification failed: %v", err)
	}
}

type failOnceMetadata struct {
	meta.MetadataStorer
	attribute string
	failure   error
	failed    bool
}

func (store *failOnceMetadata) StoreAttribute(file *os.File, bucket, object, attribute string, value []byte) error {
	if !store.failed && attribute == store.attribute {
		store.failed = true
		return store.failure
	}
	return store.MetadataStorer.StoreAttribute(file, bucket, object, attribute, value)
}

func TestLifecycleNativeRestorePreservesOfflineInode(t *testing.T) {
	backend, root, _ := newArchiveTestBackend(t)
	bucket, key := "bucket", "native-restore"
	if err := os.Mkdir(filepath.Join(root, bucket), 0o755); err != nil {
		t.Fatal(err)
	}
	payload := bytes.Repeat([]byte("native-stage"), 128*1024)
	putLifecycleTestObject(t, backend, bucket, key, payload)
	ageLifecycleTestPath(t, filepath.Join(root, bucket, key))
	days := int32(0)
	configuration := lifecycle.Configuration{TransitionDefaultMinimumObjectSize: lifecycle.TransitionMinimumVariesByStorageClass, Rules: []lifecycle.Rule{{
		Filter: &lifecycle.Filter{}, Status: "Enabled",
		Transitions: []lifecycle.Transition{{Days: &days, StorageClass: "GLACIER"}},
	}}}
	if err := backend.PutLifecycleConfiguration(context.Background(), bucket, configuration); err != nil {
		t.Fatal(err)
	}
	coordinator := lifecycle.Coordinator{Store: backend, Executor: backend, Clock: fixedLifecycleClock{time.Now().UTC()}}
	if err := coordinator.RunOnce(context.Background()); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(root, bucket, key)
	before, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	restoreDays := int32(1)
	called := false
	err = backend.RestoreLifecycleObject(context.Background(), &s3.RestoreObjectInput{
		Bucket: &bucket, Key: &key, RestoreRequest: &types.RestoreRequest{Days: &restoreDays},
	}, func(path string, source io.Reader, size int64) (int64, error) {
		called = true
		file, err := os.OpenFile(path, os.O_WRONLY, 0)
		if err != nil {
			return 0, err
		}
		defer file.Close()
		return io.Copy(file, source)
	})
	if err != nil {
		t.Fatalf("RestoreLifecycleObject() error = %v", err)
	}
	after, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if !called || !os.SameFile(before, after) {
		t.Fatalf("native restore callback = %v, same inode = %v", called, os.SameFile(before, after))
	}
	get, err := backend.GetObject(context.Background(), &s3.GetObjectInput{Bucket: &bucket, Key: &key})
	if err != nil {
		t.Fatal(err)
	}
	got, err := io.ReadAll(get.Body)
	if err != nil {
		t.Fatal(err)
	}
	_ = get.Body.Close()
	if !bytes.Equal(got, payload) {
		t.Fatalf("restored body length = %d, want %d", len(got), len(payload))
	}
}

func TestArchiveRootsMustNotOverlapGatewayRoots(t *testing.T) {
	root := t.TempDir()
	archive := filepath.Join(root, "archive")
	if err := os.Mkdir(archive, 0o700); err != nil {
		t.Fatal(err)
	}
	if _, err := New(root, meta.XattrMeta{}, PosixOpts{ArchiveTiers: map[string]string{"GLACIER": archive}}); err == nil {
		t.Fatal("New() accepted an archive root inside the object root")
	}
}

func TestLifecycleTransitionsNoncurrentVersionWithoutChangingVersionID(t *testing.T) {
	backend, root, _ := newArchiveTestBackend(t)
	bucket, key := "bucket", "versioned-archive"
	if err := os.Mkdir(filepath.Join(root, bucket), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := backend.PutBucketVersioning(context.Background(), bucket, types.BucketVersioningStatusEnabled); err != nil {
		t.Fatal(err)
	}
	first := putLifecycleTestObject(t, backend, bucket, key, []byte("first-version"))
	oldFirst := time.Now().UTC().Add(-96 * time.Hour)
	if err := os.Chtimes(filepath.Join(root, bucket, key), oldFirst, oldFirst); err != nil {
		t.Fatal(err)
	}
	second := putLifecycleTestObject(t, backend, bucket, key, []byte("second-version"))
	oldSecond := time.Now().UTC().Add(-72 * time.Hour)
	if err := os.Chtimes(filepath.Join(root, bucket, key), oldSecond, oldSecond); err != nil {
		t.Fatal(err)
	}
	if err := os.Chtimes(filepath.Join(backend.genObjVersionPath(bucket, key), first.VersionID), oldFirst, oldFirst); err != nil {
		t.Fatal(err)
	}

	days := int32(0)
	configuration := lifecycle.Configuration{TransitionDefaultMinimumObjectSize: lifecycle.TransitionMinimumVariesByStorageClass, Rules: []lifecycle.Rule{{
		Filter: &lifecycle.Filter{}, Status: "Enabled",
		NoncurrentVersionTransitions: []lifecycle.NoncurrentVersionTransition{{NoncurrentDays: &days, StorageClass: "GLACIER"}},
	}}}
	if err := backend.PutLifecycleConfiguration(context.Background(), bucket, configuration); err != nil {
		t.Fatal(err)
	}
	coordinator := lifecycle.Coordinator{Store: backend, Executor: backend, Clock: fixedLifecycleClock{time.Now().UTC()}}
	if err := coordinator.RunOnce(context.Background()); err != nil {
		t.Fatalf("RunOnce() error = %v", err)
	}

	versions := listLifecycleTestVersions(t, backend, bucket)
	if len(versions.Versions) != 2 {
		t.Fatalf("versions = %#v", versions.Versions)
	}
	classes := make(map[string]types.ObjectVersionStorageClass)
	for _, version := range versions.Versions {
		if version.VersionId != nil {
			classes[*version.VersionId] = version.StorageClass
		}
	}
	if classes[first.VersionID] != types.ObjectVersionStorageClass("GLACIER") || classes[second.VersionID] != types.ObjectVersionStorageClassStandard {
		t.Fatalf("storage classes = %#v", classes)
	}
	if _, err := backend.GetObject(context.Background(), &s3.GetObjectInput{Bucket: &bucket, Key: &key, VersionId: &first.VersionID}); !errors.Is(err, s3err.GetAPIError(s3err.ErrInvalidObjectState)) {
		t.Fatalf("GetObject(noncurrent archived) error = %v", err)
	}
	restoreDays := int32(1)
	if err := backend.RestoreObject(context.Background(), &s3.RestoreObjectInput{
		Bucket: &bucket, Key: &key, VersionId: &first.VersionID, RestoreRequest: &types.RestoreRequest{Days: &restoreDays},
	}); err != nil {
		t.Fatalf("RestoreObject(noncurrent) error = %v", err)
	}
	get, err := backend.GetObject(context.Background(), &s3.GetObjectInput{Bucket: &bucket, Key: &key, VersionId: &first.VersionID})
	if err != nil {
		t.Fatalf("GetObject(restored noncurrent) error = %v", err)
	}
	body, err := io.ReadAll(get.Body)
	if err != nil {
		t.Fatal(err)
	}
	_ = get.Body.Close()
	if string(body) != "first-version" {
		t.Fatalf("restored noncurrent body = %q", body)
	}
}

func TestLifecycleTransitionReconciliationFinishesFailedHotRelease(t *testing.T) {
	backend, root, _ := newArchiveTestBackend(t)
	bucket, key := "bucket", "interrupted-transition"
	if err := os.Mkdir(filepath.Join(root, bucket), 0o755); err != nil {
		t.Fatal(err)
	}
	putLifecycleTestObject(t, backend, bucket, key, []byte("recoverable payload"))
	ageLifecycleTestPath(t, filepath.Join(root, bucket, key))
	days := int32(0)
	configuration := lifecycle.Configuration{TransitionDefaultMinimumObjectSize: lifecycle.TransitionMinimumVariesByStorageClass, Rules: []lifecycle.Rule{{
		Filter: &lifecycle.Filter{}, Status: "Enabled",
		Transitions: []lifecycle.Transition{{Days: &days, StorageClass: "GLACIER"}},
	}}}
	if err := backend.PutLifecycleConfiguration(context.Background(), bucket, configuration); err != nil {
		t.Fatal(err)
	}
	candidates, err := backend.allLifecycleCandidates(context.Background(), bucket)
	if err != nil {
		t.Fatal(err)
	}
	actions := lifecycle.Evaluate(configuration, candidates, time.Now().UTC())
	if len(actions) != 1 {
		t.Fatalf("actions = %#v", actions)
	}
	releaseFailure := errors.New("injected release failure")
	if err := backend.TransitionLifecycleObject(context.Background(), actions[0], func(string) error { return releaseFailure }); !errors.Is(err, releaseFailure) {
		t.Fatalf("TransitionLifecycleObject() error = %v", err)
	}
	before, err := os.Stat(filepath.Join(root, bucket, key))
	if err != nil || before.Size() == 0 {
		t.Fatalf("hot data after failed release = %v, %v", before, err)
	}
	if err := backend.ReconcileLifecycle(context.Background(), bucket); err != nil {
		t.Fatalf("ReconcileLifecycle() error = %v", err)
	}
	after, err := os.Stat(filepath.Join(root, bucket, key))
	if err != nil || after.Size() != 0 {
		t.Fatalf("hot stub after reconciliation = %v, %v", after, err)
	}
}

func TestLifecycleTransitionReconciliationRepairsOfflineStubTimestamp(t *testing.T) {
	backend, root, _ := newArchiveTestBackend(t)
	bucket, key := "bucket", "interrupted-timestamp"
	if err := os.Mkdir(filepath.Join(root, bucket), 0o755); err != nil {
		t.Fatal(err)
	}
	putLifecycleTestObject(t, backend, bucket, key, bytes.Repeat([]byte("payload"), 32))
	ageLifecycleTestPath(t, filepath.Join(root, bucket, key))
	days := int32(0)
	configuration := lifecycle.Configuration{TransitionDefaultMinimumObjectSize: lifecycle.TransitionMinimumVariesByStorageClass, Rules: []lifecycle.Rule{{
		Filter: &lifecycle.Filter{}, Status: "Enabled",
		Transitions: []lifecycle.Transition{{Days: &days, StorageClass: "GLACIER"}},
	}}}
	if err := backend.PutLifecycleConfiguration(context.Background(), bucket, configuration); err != nil {
		t.Fatal(err)
	}
	coordinator := lifecycle.Coordinator{Store: backend, Executor: backend, Clock: fixedLifecycleClock{time.Now().UTC()}}
	if err := coordinator.RunOnce(context.Background()); err != nil {
		t.Fatal(err)
	}
	manifest, err := backend.loadArchiveManifest(bucket, key)
	if err != nil || manifest == nil {
		t.Fatalf("manifest = %#v, %v", manifest, err)
	}
	path := filepath.Join(root, bucket, key)
	wrong := time.Now().UTC().Add(24 * time.Hour)
	if err := os.Chtimes(path, wrong, wrong); err != nil {
		t.Fatal(err)
	}
	if err := backend.ReconcileLifecycle(context.Background(), bucket); err != nil {
		t.Fatal(err)
	}
	info, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if !info.ModTime().Equal(manifest.LastModified) {
		t.Fatalf("stub mtime = %v, want %v", info.ModTime(), manifest.LastModified)
	}
}

func newArchiveTestBackend(t *testing.T) (*Posix, string, string) {
	t.Helper()
	original, err := os.Getwd()
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.Chdir(original) })
	base := t.TempDir()
	root, versionRoot := filepath.Join(base, "objects"), filepath.Join(base, "versions")
	sidecar, keyRoot, archiveRoot := filepath.Join(base, "metadata"), filepath.Join(base, "keys"), filepath.Join(base, "archive")
	for _, directory := range []string{root, versionRoot, sidecar, keyRoot, archiveRoot} {
		if err := os.Mkdir(directory, 0o700); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.WriteFile(filepath.Join(keyRoot, "active.key"), bytes.Repeat([]byte{0xa5}, encryption.DataKeySize), 0o600); err != nil {
		t.Fatal(err)
	}
	provider, err := encryption.NewLocalProvider(keyRoot, "active")
	if err != nil {
		t.Fatal(err)
	}
	store, err := meta.NewSideCar(sidecar)
	if err != nil {
		t.Fatal(err)
	}
	backend, err := New(root, store, PosixOpts{
		VersioningDir: versionRoot, SideCarDir: sidecar, EncryptionKeyDirectory: keyRoot,
		EncryptionProvider: provider, ManagedEncryptionProvider: provider,
		ArchiveTiers:        map[string]string{"GLACIER": archiveRoot},
		ValidateBucketNames: true, NewDirPerm: 0o755,
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(backend.Shutdown)
	return backend, root, archiveRoot
}

func stringsHasPathPrefix(path, root string) bool {
	relative, err := filepath.Rel(root, path)
	return err == nil && relative != ".." && !filepath.IsAbs(relative)
}
