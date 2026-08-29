// Copyright 2026 Versity Software
// This file is licensed under the Apache License, Version 2.0.

package posix

import (
	"bytes"
	"context"
	"crypto/sha256"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/aws/aws-sdk-go-v2/service/s3"
	"github.com/aws/aws-sdk-go-v2/service/s3/types"
	"github.com/oklog/ulid/v2"
	"github.com/versity/versitygw/backend/meta"
	"github.com/versity/versitygw/internal/lifecycle"
	"github.com/versity/versitygw/s3response"
)

func TestLifecycleCoordinatorExpiresExistingUnversionedObject(t *testing.T) {
	original, err := os.Getwd()
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.Chdir(original) })

	backend := newLifecycleTestBackend(t, "")
	if err := os.Mkdir("bucket", 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join("bucket", "expired"), []byte("data"), 0o600); err != nil {
		t.Fatal(err)
	}
	old := time.Now().Add(-72 * time.Hour)
	if err := os.Chtimes(filepath.Join("bucket", "expired"), old, old); err != nil {
		t.Fatal(err)
	}
	days := int32(1)
	configuration := lifecycle.Configuration{Rules: []lifecycle.Rule{{Filter: &lifecycle.Filter{}, Status: "Enabled", Expiration: &lifecycle.Expiration{Days: &days}}}}
	if err := backend.PutLifecycleConfiguration(context.Background(), "bucket", configuration); err != nil {
		t.Fatal(err)
	}

	coordinator := lifecycle.Coordinator{Store: backend, Executor: backend, Clock: fixedLifecycleClock{time.Now()}}
	if err := coordinator.RunOnce(context.Background()); err != nil {
		t.Fatalf("RunOnce() error = %v", err)
	}
	if _, err := os.Stat(filepath.Join("bucket", "expired")); !os.IsNotExist(err) {
		t.Fatalf("expired object still exists: %v", err)
	}
}

func TestListLifecycleCandidatesUsesStableBackendPagination(t *testing.T) {
	backend := newLifecycleTestBackend(t, "")
	createLifecycleTestBucket(t, backend, "")
	bucket := "bucket"
	for _, key := range []string{"a", "b", "c"} {
		putLifecycleTestObject(t, backend, bucket, key, []byte(key))
	}

	var cursor lifecycle.Cursor
	var keys []string
	for pageNumber := 0; ; pageNumber++ {
		if pageNumber > 10 {
			t.Fatal("candidate pagination did not terminate")
		}
		page, err := backend.ListLifecycleCandidates(context.Background(), bucket, cursor, 1)
		if err != nil {
			t.Fatal(err)
		}
		for _, candidate := range page.Candidates {
			if candidate.Kind == lifecycle.CandidateObject {
				keys = append(keys, candidate.Key)
			}
		}
		if page.Next == nil {
			break
		}
		if page.Next.Phase != "objects" && page.Next.Phase != "multipart" {
			t.Fatalf("cursor phase = %q, want backend phase", page.Next.Phase)
		}
		cursor = *page.Next
	}
	if fmt.Sprint(keys) != "[a b c]" {
		t.Fatalf("paginated keys = %v", keys)
	}
}

func TestLifecycleCoordinatorRetainsNewestNoncurrentVersions(t *testing.T) {
	original, err := os.Getwd()
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.Chdir(original) })

	versionRoot := t.TempDir()
	backend := newLifecycleTestBackend(t, versionRoot)
	if err := os.Mkdir("bucket", 0o755); err != nil {
		t.Fatal(err)
	}
	if err := backend.PutBucketVersioning(context.Background(), "bucket", types.BucketVersioningStatusEnabled); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join("bucket", "key"), []byte("current"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := backend.meta.StoreAttribute(nil, "bucket", "key", versionIdKey, []byte("v4")); err != nil {
		t.Fatal(err)
	}

	versionPath := backend.genObjVersionPath("bucket", "key")
	if err := os.MkdirAll(versionPath, 0o755); err != nil {
		t.Fatal(err)
	}
	now := time.Now().UTC()
	versionIDs := make([]string, 0, 3)
	for index := 0; index < 3; index++ {
		modified := now.Add(time.Duration(-144+index*24) * time.Hour)
		id := ulid.MustNew(ulid.Timestamp(modified), ulid.DefaultEntropy()).String()
		versionIDs = append(versionIDs, id)
		path := filepath.Join(versionPath, id)
		if err := os.WriteFile(path, []byte(id), 0o600); err != nil {
			t.Fatal(err)
		}
		if err := os.Chtimes(path, modified, modified); err != nil {
			t.Fatal(err)
		}
	}
	currentTime := now.Add(-48 * time.Hour)
	if err := os.Chtimes(filepath.Join("bucket", "key"), currentTime, currentTime); err != nil {
		t.Fatal(err)
	}

	days, keep := int32(1), int32(2)
	configuration := lifecycle.Configuration{Rules: []lifecycle.Rule{{Filter: &lifecycle.Filter{}, Status: "Enabled", NoncurrentVersionExpiration: &lifecycle.NoncurrentVersionExpiration{NoncurrentDays: &days, NewerNoncurrentVersions: &keep}}}}
	if err := backend.PutLifecycleConfiguration(context.Background(), "bucket", configuration); err != nil {
		t.Fatal(err)
	}
	coordinator := lifecycle.Coordinator{Store: backend, Executor: backend, Clock: fixedLifecycleClock{now}, PageSize: 1}
	if err := coordinator.RunOnce(context.Background()); err != nil {
		t.Fatalf("RunOnce() error = %v", err)
	}

	if _, err := os.Stat(filepath.Join(versionPath, versionIDs[0])); !os.IsNotExist(err) {
		t.Fatalf("oldest version was not expired: %v", err)
	}
	for _, id := range versionIDs[1:] {
		if _, err := os.Stat(filepath.Join(versionPath, id)); err != nil {
			t.Fatalf("retained version %s: %v", id, err)
		}
	}
}

func TestLifecycleCoordinatorRetainsVersionsCreatedThroughPutObject(t *testing.T) {
	versionRoot := t.TempDir()
	backend := newLifecycleTestBackend(t, versionRoot)
	createLifecycleTestBucket(t, backend, types.BucketVersioningStatusEnabled)

	bucket, key := "bucket", "retain/object"
	written := make([]string, 0, 4)
	for index := 0; index < 4; index++ {
		put := putLifecycleTestObject(t, backend, bucket, key, []byte(fmt.Sprintf("version-%d", index)))
		written = append(written, put.VersionID)
	}
	base := time.Now().UTC().Add(-48 * time.Hour)
	if err := os.Chtimes(filepath.Join(bucket, key), base, base); err != nil {
		t.Fatal(err)
	}
	versionPath := backend.genObjVersionPath(bucket, key)
	for index, versionID := range written[:len(written)-1] {
		modified := base.Add(-time.Duration(len(written)-1-index) * 24 * time.Hour)
		if err := os.Chtimes(filepath.Join(versionPath, versionID), modified, modified); err != nil {
			t.Fatal(err)
		}
	}

	days, keep := int32(1), int32(2)
	prefix := "retain/"
	configuration := lifecycle.Configuration{Rules: []lifecycle.Rule{{
		Filter: &lifecycle.Filter{Prefix: &prefix}, Status: "Enabled",
		NoncurrentVersionExpiration: &lifecycle.NoncurrentVersionExpiration{NoncurrentDays: &days, NewerNoncurrentVersions: &keep},
	}}}
	if err := backend.PutLifecycleConfiguration(context.Background(), bucket, configuration); err != nil {
		t.Fatal(err)
	}
	coordinator := lifecycle.Coordinator{Store: backend, Executor: backend, Clock: fixedLifecycleClock{time.Now().UTC()}, PageSize: 1000}
	if err := coordinator.RunOnce(context.Background()); err != nil {
		t.Fatalf("RunOnce() error = %v", err)
	}

	result := listLifecycleTestVersions(t, backend, bucket)
	if len(result.Versions) != 3 {
		t.Fatalf("remaining versions = %d, want 3: %#v", len(result.Versions), result.Versions)
	}
	for _, version := range result.Versions {
		if version.VersionId != nil && *version.VersionId == written[0] {
			t.Fatalf("oldest version %q was retained", written[0])
		}
	}
}

func TestLifecycleCoordinatorCreatesVersionedDeleteMarker(t *testing.T) {
	backend := newLifecycleTestBackend(t, t.TempDir())
	createLifecycleTestBucket(t, backend, types.BucketVersioningStatusEnabled)

	bucket, key := "bucket", "versioned"
	put := putLifecycleTestObject(t, backend, bucket, key, []byte("retained version"))
	ageLifecycleTestPath(t, filepath.Join(bucket, key))
	configureLifecycleExpiration(t, backend, bucket)
	runLifecycleTestCoordinator(t, backend)

	result := listLifecycleTestVersions(t, backend, bucket)
	if len(result.DeleteMarkers) != 1 || result.DeleteMarkers[0].IsLatest == nil || !*result.DeleteMarkers[0].IsLatest {
		t.Fatalf("delete markers = %#v", result.DeleteMarkers)
	}
	if len(result.Versions) != 1 || result.Versions[0].VersionId == nil || *result.Versions[0].VersionId != put.VersionID || result.Versions[0].IsLatest == nil || *result.Versions[0].IsLatest {
		t.Fatalf("versions = %#v, original version = %q", result.Versions, put.VersionID)
	}
}

func TestLifecycleCoordinatorAppliesSuspendedNullVersionRules(t *testing.T) {
	t.Run("null current is replaced by null delete marker", func(t *testing.T) {
		backend := newLifecycleTestBackend(t, t.TempDir())
		createLifecycleTestBucket(t, backend, types.BucketVersioningStatusSuspended)
		bucket, key := "bucket", "null-current"
		putLifecycleTestObject(t, backend, bucket, key, []byte("null data"))
		ageLifecycleTestPath(t, filepath.Join(bucket, key))
		configureLifecycleExpiration(t, backend, bucket)
		runLifecycleTestCoordinator(t, backend)

		result := listLifecycleTestVersions(t, backend, bucket)
		if len(result.Versions) != 0 || len(result.DeleteMarkers) != 1 || result.DeleteMarkers[0].VersionId == nil || *result.DeleteMarkers[0].VersionId != nullVersionId {
			t.Fatalf("versions = %#v, delete markers = %#v", result.Versions, result.DeleteMarkers)
		}
	})

	t.Run("non-null current is retained behind null delete marker", func(t *testing.T) {
		backend := newLifecycleTestBackend(t, t.TempDir())
		createLifecycleTestBucket(t, backend, types.BucketVersioningStatusEnabled)
		bucket, key := "bucket", "non-null-current"
		put := putLifecycleTestObject(t, backend, bucket, key, []byte("versioned data"))
		if err := backend.PutBucketVersioning(context.Background(), bucket, types.BucketVersioningStatusSuspended); err != nil {
			t.Fatal(err)
		}
		ageLifecycleTestPath(t, filepath.Join(bucket, key))
		configureLifecycleExpiration(t, backend, bucket)
		runLifecycleTestCoordinator(t, backend)

		result := listLifecycleTestVersions(t, backend, bucket)
		if len(result.Versions) != 1 || result.Versions[0].VersionId == nil || *result.Versions[0].VersionId != put.VersionID {
			t.Fatalf("versions = %#v, original version = %q", result.Versions, put.VersionID)
		}
		if len(result.DeleteMarkers) != 1 || result.DeleteMarkers[0].VersionId == nil || *result.DeleteMarkers[0].VersionId != nullVersionId {
			t.Fatalf("delete markers = %#v", result.DeleteMarkers)
		}
	})
}

func TestLifecycleCoordinatorAbortsIncompleteMultipartUpload(t *testing.T) {
	backend := newLifecycleTestBackend(t, "")
	createLifecycleTestBucket(t, backend, "")
	bucket, key := "bucket", "multipart"
	created, err := backend.CreateMultipartUpload(context.Background(), s3response.CreateMultipartUploadInput{Bucket: &bucket, Key: &key})
	if err != nil {
		t.Fatal(err)
	}
	container := fmt.Sprintf("%x", sha256.Sum256([]byte(key)))
	ageLifecycleTestPath(t, filepath.Join(bucket, MetaTmpMultipartDir, container, created.UploadId))
	days := int32(1)
	configuration := lifecycle.Configuration{Rules: []lifecycle.Rule{{
		Filter: &lifecycle.Filter{}, Status: "Enabled",
		AbortIncompleteMultipartUpload: &lifecycle.AbortIncompleteMultipartUpload{DaysAfterInitiation: &days},
	}}}
	if err := backend.PutLifecycleConfiguration(context.Background(), bucket, configuration); err != nil {
		t.Fatal(err)
	}
	runLifecycleTestCoordinator(t, backend)
	maxUploads := int32(1000)
	result, err := backend.ListMultipartUploads(context.Background(), &s3.ListMultipartUploadsInput{Bucket: &bucket, MaxUploads: &maxUploads})
	if err != nil {
		t.Fatal(err)
	}
	if len(result.Uploads) != 0 {
		t.Fatalf("remaining multipart uploads = %#v", result.Uploads)
	}
}

func TestLifecycleCoordinatorDoesNotDeleteLegallyHeldObject(t *testing.T) {
	backend := newLifecycleTestBackend(t, "")
	createLifecycleTestBucket(t, backend, "")
	bucket, key := "bucket", "held"
	putLifecycleTestObject(t, backend, bucket, key, []byte("protected"))
	if err := backend.meta.StoreAttribute(nil, bucket, "", bucketLockKey, []byte(`{"Enabled":true}`)); err != nil {
		t.Fatal(err)
	}
	if err := backend.meta.StoreAttribute(nil, bucket, key, objectLegalHoldKey, []byte{1}); err != nil {
		t.Fatal(err)
	}
	ageLifecycleTestPath(t, filepath.Join(bucket, key))
	configureLifecycleExpiration(t, backend, bucket)
	runLifecycleTestCoordinator(t, backend)
	if _, err := os.Stat(filepath.Join(bucket, key)); err != nil {
		t.Fatalf("legally held object was deleted: %v", err)
	}
}

func TestLifecycleCoordinatorFailsClosedOnCorruptRetentionMetadata(t *testing.T) {
	backend := newLifecycleTestBackend(t, "")
	createLifecycleTestBucket(t, backend, "")
	bucket, key := "bucket", "corrupt-retention"
	putLifecycleTestObject(t, backend, bucket, key, []byte("protected until proven otherwise"))
	if err := backend.meta.StoreAttribute(nil, bucket, "", bucketLockKey, []byte(`{"Enabled":true}`)); err != nil {
		t.Fatal(err)
	}
	if err := backend.meta.StoreAttribute(nil, bucket, key, objectRetentionKey, []byte(`{"Mode":"GOVERNANCE"`)); err != nil {
		t.Fatal(err)
	}
	ageLifecycleTestPath(t, filepath.Join(bucket, key))
	configureLifecycleExpiration(t, backend, bucket)

	coordinator := lifecycle.Coordinator{Store: backend, Executor: backend, Clock: fixedLifecycleClock{time.Now().UTC()}}
	if err := coordinator.RunOnce(context.Background()); err == nil {
		t.Fatal("RunOnce() succeeded with corrupt retention metadata")
	}
	if _, err := os.Stat(filepath.Join(bucket, key)); err != nil {
		t.Fatalf("object was deleted while retention state was uncertain: %v", err)
	}
}

func TestLifecycleAbortFindsMultipartUploadAfterFirstPage(t *testing.T) {
	backend := newLifecycleTestBackend(t, "")
	createLifecycleTestBucket(t, backend, "")
	bucket := "bucket"
	var target lifecycle.Candidate
	for index := 0; index < 1001; index++ {
		key := fmt.Sprintf("upload-%04d", index)
		created, err := backend.CreateMultipartUpload(context.Background(), s3response.CreateMultipartUploadInput{Bucket: &bucket, Key: &key})
		if err != nil {
			t.Fatal(err)
		}
		if index == 1000 {
			target = lifecycle.Candidate{
				Kind: lifecycle.CandidateMultipart, Bucket: bucket, Key: key, UploadID: created.UploadId,
			}
			info, err := os.Stat(filepath.Join(bucket, MetaTmpMultipartDir, fmt.Sprintf("%x", sha256.Sum256([]byte(key))), created.UploadId))
			if err != nil {
				t.Fatal(err)
			}
			target.LastModified = info.ModTime()
			target.StorageClass = string(types.StorageClassStandard)
			target.StateToken = lifecycleStateToken(target)
		}
	}

	action := lifecycle.Action{
		Kind: lifecycle.ActionAbortMultipart, Bucket: bucket, Key: target.Key, UploadID: target.UploadID,
		ObservedAt: target.LastModified, StateToken: target.StateToken,
	}
	if err := backend.ApplyLifecycleAction(context.Background(), action); err != nil {
		t.Fatalf("ApplyLifecycleAction() error = %v", err)
	}
}

func TestLifecycleStateTokenIncludesEveryEligibilityInput(t *testing.T) {
	base := lifecycle.Candidate{
		Kind: lifecycle.CandidateObject, Bucket: "bucket", Key: "key", VersionID: "version",
		Current: true, Versioning: lifecycle.VersioningEnabled, Size: 10,
		LastModified: time.Unix(100, 0), NoncurrentSince: time.Unix(200, 0),
		NoncurrentRank: 2, VersionsForKey: 4, StorageClass: "STANDARD",
		Tags: map[string]string{"expire": "yes"},
	}
	baseToken := lifecycleStateToken(base)
	mutations := []lifecycle.Candidate{
		func() lifecycle.Candidate { value := base; value.Protected = true; return value }(),
		func() lifecycle.Candidate {
			value := base
			value.Tags = map[string]string{"expire": "no"}
			return value
		}(),
		func() lifecycle.Candidate { value := base; value.NoncurrentRank++; return value }(),
		func() lifecycle.Candidate { value := base; value.VersionsForKey++; return value }(),
		func() lifecycle.Candidate { value := base; value.StorageClass = "GLACIER"; return value }(),
	}
	for _, mutation := range mutations {
		if lifecycleStateToken(mutation) == baseToken {
			t.Fatalf("state token did not change for mutation %#v", mutation)
		}
	}
}

func TestObjectMutationLockSerializesSameKeyAndHonorsCancellation(t *testing.T) {
	backend := newLifecycleTestBackend(t, "")
	createLifecycleTestBucket(t, backend, "")
	firstRelease, err := backend.acquireObjectMutationLock(context.Background(), "bucket", "key")
	if err != nil {
		t.Fatal(err)
	}
	canceled, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := backend.acquireObjectMutationLock(canceled, "bucket", "key"); !errors.Is(err, context.Canceled) {
		firstRelease()
		t.Fatalf("canceled lock error = %v", err)
	}

	acquired := make(chan func(), 1)
	go func() {
		release, err := backend.acquireObjectMutationLock(context.Background(), "bucket", "key")
		if err == nil {
			acquired <- release
		}
	}()
	select {
	case release := <-acquired:
		release()
		firstRelease()
		t.Fatal("second lock acquired before first release")
	case <-time.After(50 * time.Millisecond):
	}
	firstRelease()
	select {
	case release := <-acquired:
		release()
	case <-time.After(time.Second):
		t.Fatal("second lock did not acquire after first release")
	}
}

func TestLifecycleLeaseRejectsSecondHolderInSameProcess(t *testing.T) {
	backend := newLifecycleTestBackend(t, "")
	createLifecycleTestBucket(t, backend, "")
	first, err := backend.AcquireLifecycleLease(context.Background(), "bucket")
	if err != nil {
		t.Fatal(err)
	}
	defer first.Close()
	second, err := backend.AcquireLifecycleLease(context.Background(), "bucket")
	if second != nil {
		_ = second.Close()
	}
	if !errors.Is(err, lifecycle.ErrLeaseUnavailable) {
		t.Fatalf("second lease error = %v, want ErrLeaseUnavailable", err)
	}
}

func TestLifecycleMutationGuardPreventsDelete(t *testing.T) {
	backend := newLifecycleTestBackend(t, "")
	createLifecycleTestBucket(t, backend, "")
	bucket, key := "bucket", "guarded"
	putLifecycleTestObject(t, backend, bucket, key, []byte("must remain"))
	page, err := backend.ListLifecycleCandidates(context.Background(), bucket, lifecycle.Cursor{}, 1000)
	if err != nil {
		t.Fatal(err)
	}
	var candidate lifecycle.Candidate
	for _, current := range page.Candidates {
		if current.Kind == lifecycle.CandidateObject && current.Key == key {
			candidate = current
			break
		}
	}
	guardErr := errors.New("leadership lost")
	err = backend.ApplyLifecycleActionWithGuard(context.Background(), lifecycle.Action{
		Kind: lifecycle.ActionDeleteCurrent, Bucket: bucket, Key: key, VersionID: candidate.VersionID,
		Current: candidate.Current, StateToken: candidate.StateToken,
	}, func() error { return guardErr })
	if !errors.Is(err, guardErr) {
		t.Fatalf("ApplyLifecycleActionWithGuard() error = %v", err)
	}
	if _, err := os.Stat(filepath.Join(bucket, key)); err != nil {
		t.Fatalf("guarded object was deleted: %v", err)
	}
}

type fixedLifecycleClock struct{ now time.Time }

func (clock fixedLifecycleClock) Now() time.Time { return clock.now }

func newLifecycleTestBackend(t *testing.T, versionRoot string) *Posix {
	t.Helper()
	root, sidecarRoot := t.TempDir(), t.TempDir()
	store, err := meta.NewSideCar(sidecarRoot)
	if err != nil {
		t.Fatal(err)
	}
	backend, err := New(root, store, PosixOpts{VersioningDir: versionRoot, SideCarDir: sidecarRoot, ValidateBucketNames: true, NewDirPerm: 0o755})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(backend.Shutdown)
	return backend
}

func createLifecycleTestBucket(t *testing.T, backend *Posix, versioning types.BucketVersioningStatus) {
	t.Helper()
	if err := os.Mkdir("bucket", 0o755); err != nil {
		t.Fatal(err)
	}
	if versioning != "" {
		if err := backend.PutBucketVersioning(context.Background(), "bucket", versioning); err != nil {
			t.Fatal(err)
		}
	}
}

func putLifecycleTestObject(t *testing.T, backend *Posix, bucket, key string, body []byte) s3response.PutObjectOutput {
	t.Helper()
	length := int64(len(body))
	result, err := backend.PutObject(context.Background(), s3response.PutObjectInput{
		Bucket: &bucket, Key: &key, Body: bytes.NewReader(body), ContentLength: &length,
	})
	if err != nil {
		t.Fatal(err)
	}
	return result
}

func ageLifecycleTestPath(t *testing.T, path string) {
	t.Helper()
	old := time.Now().UTC().Add(-72 * time.Hour)
	if err := os.Chtimes(path, old, old); err != nil {
		t.Fatal(err)
	}
}

func configureLifecycleExpiration(t *testing.T, backend *Posix, bucket string) {
	t.Helper()
	days := int32(1)
	configuration := lifecycle.Configuration{Rules: []lifecycle.Rule{{
		Filter: &lifecycle.Filter{}, Status: "Enabled", Expiration: &lifecycle.Expiration{Days: &days},
	}}}
	if err := backend.PutLifecycleConfiguration(context.Background(), bucket, configuration); err != nil {
		t.Fatal(err)
	}
}

func runLifecycleTestCoordinator(t *testing.T, backend *Posix) {
	t.Helper()
	coordinator := lifecycle.Coordinator{Store: backend, Executor: backend, Clock: fixedLifecycleClock{time.Now().UTC()}}
	if err := coordinator.RunOnce(context.Background()); err != nil {
		t.Fatalf("RunOnce() error = %v", err)
	}
}

func listLifecycleTestVersions(t *testing.T, backend *Posix, bucket string) s3response.ListVersionsResult {
	t.Helper()
	maxKeys := int32(1000)
	result, err := backend.ListObjectVersions(context.Background(), &s3.ListObjectVersionsInput{Bucket: &bucket, MaxKeys: &maxKeys})
	if err != nil {
		t.Fatal(err)
	}
	return result
}
