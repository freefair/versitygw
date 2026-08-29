// Copyright 2026 Versity Software
// This file is licensed under the Apache License, Version 2.0.

// s3probe exercises Lifecycle and Encryption against a running gateway while
// inspecting the backing filesystem at the lowest useful live-test boundary.
package main

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	awsconfig "github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/credentials"
	"github.com/aws/aws-sdk-go-v2/service/s3"
	"github.com/aws/aws-sdk-go-v2/service/s3/types"
	"github.com/aws/smithy-go"
)

const probeTimeout = 45 * time.Second

type probe struct {
	client      *s3.Client
	backend     string
	root        string
	versionRoot string
	archiveRoot string
	prefix      string
}

func main() {
	var endpoint string
	var backend string
	var root string
	var versionRoot string
	var archiveRoot string
	flag.StringVar(&endpoint, "endpoint", "", "S3 endpoint URL")
	flag.StringVar(&backend, "backend", "", "backend name: nfs or scoutfs")
	flag.StringVar(&root, "root", "", "gateway object root visible to this process")
	flag.StringVar(&versionRoot, "version-root", "", "gateway version root visible to this process")
	flag.StringVar(&archiveRoot, "archive-root", "", "gateway archive root visible to this process")
	flag.Parse()

	access := os.Getenv("ROOT_ACCESS_KEY_ID")
	secret := os.Getenv("ROOT_SECRET_ACCESS_KEY")
	if endpoint == "" || backend == "" || root == "" || versionRoot == "" || archiveRoot == "" || access == "" || secret == "" {
		fmt.Fprintln(os.Stderr, "endpoint, backend, root, version-root, archive-root, ROOT_ACCESS_KEY_ID, and ROOT_SECRET_ACCESS_KEY are required")
		os.Exit(2)
	}
	if backend != "nfs" && backend != "scoutfs" {
		fmt.Fprintf(os.Stderr, "unsupported backend %q\n", backend)
		os.Exit(2)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 4*probeTimeout)
	defer cancel()
	configuration, err := awsconfig.LoadDefaultConfig(ctx,
		awsconfig.WithRegion("us-east-1"),
		awsconfig.WithCredentialsProvider(credentials.NewStaticCredentialsProvider(access, secret, "")),
	)
	if err != nil {
		fatalf("load client configuration: %v", err)
	}
	client := s3.NewFromConfig(configuration, func(options *s3.Options) {
		options.BaseEndpoint = &endpoint
		options.UsePathStyle = true
	})
	p := probe{
		client: client, backend: backend, root: root, versionRoot: versionRoot, archiveRoot: archiveRoot,
		prefix: fmt.Sprintf("vgw-live-%s-%d", backend, time.Now().UnixNano()),
	}
	if err := p.run(ctx); err != nil {
		fatalf("%s live probe failed: %v", backend, err)
	}
	fmt.Printf("PASS backend=%s encryption=ok expiration=ok retention=ok transition_restore=ok\n", backend)
}

func fatalf(format string, arguments ...any) {
	fmt.Fprintf(os.Stderr, format+"\n", arguments...)
	os.Exit(1)
}

func (p probe) run(ctx context.Context) error {
	tests := []struct {
		name string
		run  func(context.Context, string) error
	}{
		{name: "encryption", run: p.testEncryption},
		{name: "expiration", run: p.testExpiration},
		{name: "retention", run: p.testRetention},
		{name: "transition", run: p.testTransitionRestore},
	}
	for _, test := range tests {
		bucket := p.prefix + "-" + test.name
		if err := p.createBucket(ctx, bucket); err != nil {
			return fmt.Errorf("create %s bucket: %w", test.name, err)
		}
		defer p.removeBucket(context.Background(), bucket)
		if err := test.run(ctx, bucket); err != nil {
			return fmt.Errorf("%s: %w", test.name, err)
		}
	}
	return nil
}

func (p probe) createBucket(ctx context.Context, bucket string) error {
	_, err := p.client.CreateBucket(ctx, &s3.CreateBucketInput{Bucket: &bucket})
	return err
}

func (p probe) enableDefaultEncryption(ctx context.Context, bucket string) error {
	enabled := true
	_, err := p.client.PutBucketEncryption(ctx, &s3.PutBucketEncryptionInput{
		Bucket: &bucket,
		ServerSideEncryptionConfiguration: &types.ServerSideEncryptionConfiguration{Rules: []types.ServerSideEncryptionRule{{
			ApplyServerSideEncryptionByDefault: &types.ServerSideEncryptionByDefault{SSEAlgorithm: types.ServerSideEncryptionAes256},
			BucketKeyEnabled:                   &enabled,
		}}},
	})
	return err
}

func (p probe) testEncryption(ctx context.Context, bucket string) error {
	if err := p.enableDefaultEncryption(ctx, bucket); err != nil {
		return fmt.Errorf("enable default encryption: %w", err)
	}
	key := "encrypted/object.bin"
	payload := bytes.Repeat([]byte("versitygw-live-encryption-marker-"), 4096)
	put, err := p.client.PutObject(ctx, &s3.PutObjectInput{Bucket: &bucket, Key: &key, Body: bytes.NewReader(payload), ContentLength: aws.Int64(int64(len(payload)))})
	if err != nil {
		return fmt.Errorf("put encrypted object: %w", err)
	}
	if put.ServerSideEncryption != types.ServerSideEncryptionAes256 {
		return fmt.Errorf("put encryption = %q, want AES256", put.ServerSideEncryption)
	}
	if err := requireObjectBody(ctx, p.client, bucket, key, payload, ""); err != nil {
		return err
	}
	rangeStart, rangeEnd := 17, 4096
	if err := requireObjectBody(ctx, p.client, bucket, key, payload[rangeStart:rangeEnd+1], fmt.Sprintf("bytes=%d-%d", rangeStart, rangeEnd)); err != nil {
		return fmt.Errorf("range read: %w", err)
	}
	raw, err := os.ReadFile(filepath.Join(p.root, bucket, filepath.FromSlash(key)))
	if err != nil {
		return fmt.Errorf("read physical encrypted object: %w", err)
	}
	if bytes.Equal(raw, payload) || bytes.Contains(raw, payload[:4096]) {
		return fmt.Errorf("physical object contains plaintext payload")
	}
	listed, err := p.client.ListObjectsV2(ctx, &s3.ListObjectsV2Input{Bucket: &bucket, Prefix: &key})
	if err != nil {
		return fmt.Errorf("list encrypted object: %w", err)
	}
	if len(listed.Contents) != 1 || aws.ToInt64(listed.Contents[0].Size) != int64(len(payload)) {
		return fmt.Errorf("listed encrypted size = %v, want %d", listed.Contents, len(payload))
	}
	if err := p.testEncryptionMode(ctx, bucket, "encrypted/local-kms.bin", []byte("local-kms-payload"), types.ServerSideEncryptionAwsKms); err != nil {
		return err
	}
	if err := p.testEncryptionMode(ctx, bucket, "encrypted/local-dsse.bin", []byte("local-dsse-payload"), types.ServerSideEncryptionAwsKmsDsse); err != nil {
		return err
	}
	copyKey := "encrypted/copy.bin"
	copySource := bucket + "/" + key
	copyOutput, err := p.client.CopyObject(ctx, &s3.CopyObjectInput{Bucket: &bucket, Key: &copyKey, CopySource: &copySource})
	if err != nil {
		return fmt.Errorf("copy encrypted object: %w", err)
	}
	if copyOutput.ServerSideEncryption != types.ServerSideEncryptionAes256 {
		return fmt.Errorf("copy encryption = %q, want AES256", copyOutput.ServerSideEncryption)
	}
	if err := requireObjectBody(ctx, p.client, bucket, copyKey, payload, ""); err != nil {
		return fmt.Errorf("read encrypted copy: %w", err)
	}
	if err := p.testEncryptedMultipart(ctx, bucket); err != nil {
		return err
	}
	return nil
}

func (p probe) testEncryptionMode(ctx context.Context, bucket, key string, payload []byte, algorithm types.ServerSideEncryption) error {
	put, err := p.client.PutObject(ctx, &s3.PutObjectInput{
		Bucket: &bucket, Key: &key, Body: bytes.NewReader(payload), ContentLength: aws.Int64(int64(len(payload))),
		ServerSideEncryption: algorithm,
	})
	if err != nil {
		return fmt.Errorf("put %s object: %w", algorithm, err)
	}
	if put.ServerSideEncryption != algorithm {
		return fmt.Errorf("put encryption = %q, want %q", put.ServerSideEncryption, algorithm)
	}
	if algorithm != types.ServerSideEncryptionAes256 && aws.ToString(put.SSEKMSKeyId) == "" {
		return fmt.Errorf("put %s returned no KMS key ID", algorithm)
	}
	if err := requireObjectBody(ctx, p.client, bucket, key, payload, ""); err != nil {
		return fmt.Errorf("read %s object: %w", algorithm, err)
	}
	return nil
}

func (p probe) testEncryptedMultipart(ctx context.Context, bucket string) error {
	key := "encrypted/multipart.bin"
	first := bytes.Repeat([]byte("m"), 5*1024*1024)
	second := []byte("encrypted-multipart-tail")
	created, err := p.client.CreateMultipartUpload(ctx, &s3.CreateMultipartUploadInput{Bucket: &bucket, Key: &key})
	if err != nil {
		return fmt.Errorf("create encrypted multipart upload: %w", err)
	}
	if created.ServerSideEncryption != types.ServerSideEncryptionAes256 || created.UploadId == nil {
		return fmt.Errorf("multipart encryption = %q, upload ID present = %t", created.ServerSideEncryption, created.UploadId != nil)
	}
	parts := make([]types.CompletedPart, 0, 2)
	for index, payload := range [][]byte{first, second} {
		partNumber := int32(index + 1)
		uploaded, uploadErr := p.client.UploadPart(ctx, &s3.UploadPartInput{
			Bucket: &bucket, Key: &key, UploadId: created.UploadId, PartNumber: &partNumber,
			Body: bytes.NewReader(payload), ContentLength: aws.Int64(int64(len(payload))),
		})
		if uploadErr != nil {
			return fmt.Errorf("upload encrypted part %d: %w", partNumber, uploadErr)
		}
		parts = append(parts, types.CompletedPart{PartNumber: &partNumber, ETag: uploaded.ETag})
	}
	completed, err := p.client.CompleteMultipartUpload(ctx, &s3.CompleteMultipartUploadInput{
		Bucket: &bucket, Key: &key, UploadId: created.UploadId,
		MultipartUpload: &types.CompletedMultipartUpload{Parts: parts},
	})
	if err != nil {
		return fmt.Errorf("complete encrypted multipart upload: %w", err)
	}
	if completed.ServerSideEncryption != types.ServerSideEncryptionAes256 {
		return fmt.Errorf("completed multipart encryption = %q, want AES256", completed.ServerSideEncryption)
	}
	want := append(append([]byte(nil), first...), second...)
	if err := requireObjectBody(ctx, p.client, bucket, key, want, ""); err != nil {
		return fmt.Errorf("read encrypted multipart object: %w", err)
	}
	return nil
}

func (p probe) testExpiration(ctx context.Context, bucket string) error {
	key := "expire/object"
	payload := []byte("delete this object automatically")
	if _, err := p.client.PutObject(ctx, &s3.PutObjectInput{Bucket: &bucket, Key: &key, Body: bytes.NewReader(payload), ContentLength: aws.Int64(int64(len(payload)))}); err != nil {
		return fmt.Errorf("put expiration object: %w", err)
	}
	prefix := "expire/"
	id := "expire-current"
	date := pastLifecycleDate(time.Now())
	if err := p.putLifecycle(ctx, bucket, []types.LifecycleRule{{
		ID: &id, Status: types.ExpirationStatusEnabled,
		Filter: &types.LifecycleRuleFilter{Prefix: &prefix}, Expiration: &types.LifecycleExpiration{Date: &date},
	}}); err != nil {
		return err
	}
	return waitFor(probeTimeout, func() (bool, error) {
		_, err := p.client.HeadObject(ctx, &s3.HeadObjectInput{Bucket: &bucket, Key: &key})
		if apiErrorCode(err) == "NoSuchKey" || apiErrorCode(err) == "NotFound" {
			_, statErr := os.Stat(filepath.Join(p.root, bucket, filepath.FromSlash(key)))
			return errors.Is(statErr, os.ErrNotExist), nil
		}
		return false, err
	})
}

func (p probe) requireAgedVersions(bucket, key string, written []string) error {
	paths := []string{filepath.Join(p.root, bucket, filepath.FromSlash(key))}
	for _, versionID := range written[:len(written)-1] {
		paths = append(paths, objectVersionPath(p.versionRoot, bucket, key, versionID))
	}
	deadline := time.Now().UTC().Add(-24 * time.Hour)
	for _, path := range paths {
		info, err := os.Stat(path)
		if err != nil {
			return err
		}
		if info.ModTime().After(deadline) {
			return fmt.Errorf("%s modified at %s", path, info.ModTime().UTC().Format(time.RFC3339Nano))
		}
	}
	return nil
}

func (p probe) testRetention(ctx context.Context, bucket string) error {
	if err := p.enableDefaultEncryption(ctx, bucket); err != nil {
		return err
	}
	_, err := p.client.PutBucketVersioning(ctx, &s3.PutBucketVersioningInput{
		Bucket: &bucket, VersioningConfiguration: &types.VersioningConfiguration{Status: types.BucketVersioningStatusEnabled},
	})
	if err != nil {
		return fmt.Errorf("enable versioning: %w", err)
	}
	key := "retain/object"
	written := make([]string, 0, 4)
	for version := 1; version <= 4; version++ {
		payload := []byte(fmt.Sprintf("retention-version-%d", version))
		output, putErr := p.client.PutObject(ctx, &s3.PutObjectInput{Bucket: &bucket, Key: &key, Body: bytes.NewReader(payload), ContentLength: aws.Int64(int64(len(payload)))})
		if putErr != nil {
			return fmt.Errorf("put version %d: %w", version, putErr)
		}
		if output.VersionId == nil || *output.VersionId == "" {
			return fmt.Errorf("put version %d returned no version ID", version)
		}
		written = append(written, *output.VersionId)
	}
	if err := p.ageVersions(bucket, key, written); err != nil {
		return err
	}
	days := int32(1)
	keep := int32(2)
	prefix := "retain/"
	id := "retain-two"
	if err := p.putLifecycle(ctx, bucket, []types.LifecycleRule{{
		ID: &id, Status: types.ExpirationStatusEnabled, Filter: &types.LifecycleRuleFilter{Prefix: &prefix},
		NoncurrentVersionExpiration: &types.NoncurrentVersionExpiration{NoncurrentDays: &days, NewerNoncurrentVersions: &keep},
	}}); err != nil {
		return err
	}
	if err := p.requireAgedVersions(bucket, key, written); err != nil {
		return fmt.Errorf("ages after lifecycle configuration: %w", err)
	}
	return waitFor(probeTimeout, func() (bool, error) {
		output, listErr := p.client.ListObjectVersions(ctx, &s3.ListObjectVersionsInput{Bucket: &bucket, Prefix: &key})
		if listErr != nil {
			return false, listErr
		}
		ids := make([]string, 0, len(output.Versions))
		states := make([]string, 0, len(output.Versions))
		for _, version := range output.Versions {
			if aws.ToString(version.Key) == key {
				ids = append(ids, aws.ToString(version.VersionId))
				states = append(states, fmt.Sprintf("%s(latest=%t,modified=%s)", aws.ToString(version.VersionId), aws.ToBool(version.IsLatest), aws.ToTime(version.LastModified).UTC().Format(time.RFC3339Nano)))
			}
		}
		if len(ids) != 3 {
			return false, fmt.Errorf("currently retained versions = %v", states)
		}
		return true, requireRetainedVersionIDs(written, ids, int(keep))
	})
}

func (p probe) ageVersions(bucket, key string, written []string) error {
	base := time.Now().UTC().Add(-48 * time.Hour)
	current := filepath.Join(p.root, bucket, filepath.FromSlash(key))
	if err := os.Chtimes(current, base, base); err != nil {
		return fmt.Errorf("age current version: %w", err)
	}
	if info, err := os.Stat(current); err != nil || info.ModTime().After(base.Add(time.Second)) {
		return fmt.Errorf("verify current version age: modified=%v error=%v", fileModTime(info), err)
	}
	for index := 0; index < len(written)-1; index++ {
		age := base.Add(-time.Duration(len(written)-1-index) * 24 * time.Hour)
		path := objectVersionPath(p.versionRoot, bucket, key, written[index])
		if err := os.Chtimes(path, age, age); err != nil {
			return fmt.Errorf("age version %s: %w", written[index], err)
		}
		if info, err := os.Stat(path); err != nil || info.ModTime().After(age.Add(time.Second)) {
			return fmt.Errorf("verify version %s age: modified=%v error=%v", written[index], fileModTime(info), err)
		}
	}
	return nil
}

func fileModTime(info os.FileInfo) time.Time {
	if info == nil {
		return time.Time{}
	}
	return info.ModTime()
}

func (p probe) testTransitionRestore(ctx context.Context, bucket string) error {
	if err := p.enableDefaultEncryption(ctx, bucket); err != nil {
		return err
	}
	key := "archive/object.bin"
	payload := bytes.Repeat([]byte("archive-encrypted-payload-"), 12*1024)
	if _, err := p.client.PutObject(ctx, &s3.PutObjectInput{Bucket: &bucket, Key: &key, Body: bytes.NewReader(payload), ContentLength: aws.Int64(int64(len(payload)))}); err != nil {
		return fmt.Errorf("put archive object: %w", err)
	}
	prefix := "archive/"
	id := "archive-now"
	date := pastLifecycleDate(time.Now())
	if err := p.putLifecycle(ctx, bucket, []types.LifecycleRule{{
		ID: &id, Status: types.ExpirationStatusEnabled, Filter: &types.LifecycleRuleFilter{Prefix: &prefix},
		Transitions: []types.Transition{{Date: &date, StorageClass: types.TransitionStorageClassGlacier}},
	}}); err != nil {
		return err
	}
	if err := waitFor(probeTimeout, func() (bool, error) {
		head, headErr := p.client.HeadObject(ctx, &s3.HeadObjectInput{Bucket: &bucket, Key: &key})
		return headErr == nil && head.StorageClass == types.StorageClassGlacier, headErr
	}); err != nil {
		return fmt.Errorf("wait for GLACIER transition: %w", err)
	}
	if _, err := p.client.GetObject(ctx, &s3.GetObjectInput{Bucket: &bucket, Key: &key}); apiErrorCode(err) != "InvalidObjectState" {
		return fmt.Errorf("GET before restore error = %v, want InvalidObjectState", err)
	}
	hotInfo, err := os.Stat(filepath.Join(p.root, bucket, filepath.FromSlash(key)))
	if err != nil {
		return fmt.Errorf("stat transitioned hot object: %w", err)
	}
	if p.backend == "nfs" && hotInfo.Size() != 0 {
		return fmt.Errorf("generic POSIX hot stub size = %d, want 0", hotInfo.Size())
	}
	if p.backend == "scoutfs" && hotInfo.Size() == 0 {
		return fmt.Errorf("ScoutFS transition truncated the inode instead of releasing extents")
	}
	archiveData := make([]byte, 0)
	bucketArchiveRoot := filepath.Join(p.archiveRoot, hex.EncodeToString([]byte(bucket)))
	err = filepath.WalkDir(bucketArchiveRoot, func(path string, entry os.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		if !entry.IsDir() && entry.Name() == "data" {
			archiveData, walkErr = os.ReadFile(path)
		}
		return walkErr
	})
	if err != nil || len(archiveData) == 0 {
		return fmt.Errorf("physical archive data missing: bytes=%d error=%v", len(archiveData), err)
	}
	if bytes.Equal(archiveData, payload) || bytes.Contains(archiveData, payload[:4096]) {
		return fmt.Errorf("physical archive contains plaintext payload")
	}
	days := int32(1)
	if _, err := p.client.RestoreObject(ctx, &s3.RestoreObjectInput{Bucket: &bucket, Key: &key, RestoreRequest: &types.RestoreRequest{Days: &days}}); err != nil {
		return fmt.Errorf("restore object: %w", err)
	}
	return waitFor(probeTimeout, func() (bool, error) {
		err := requireObjectBody(ctx, p.client, bucket, key, payload, "")
		if apiErrorCode(err) == "InvalidObjectState" {
			return false, nil
		}
		return err == nil, err
	})
}

func (p probe) putLifecycle(ctx context.Context, bucket string, rules []types.LifecycleRule) error {
	_, err := p.client.PutBucketLifecycleConfiguration(ctx, &s3.PutBucketLifecycleConfigurationInput{
		Bucket: &bucket, LifecycleConfiguration: &types.BucketLifecycleConfiguration{Rules: rules},
		TransitionDefaultMinimumObjectSize: types.TransitionDefaultMinimumObjectSizeAllStorageClasses128k,
	})
	if err != nil {
		return fmt.Errorf("put lifecycle configuration: %w", err)
	}
	return nil
}

func (p probe) removeBucket(ctx context.Context, bucket string) {
	versions, err := p.client.ListObjectVersions(ctx, &s3.ListObjectVersionsInput{Bucket: &bucket})
	if err == nil {
		for _, version := range versions.Versions {
			_, _ = p.client.DeleteObject(ctx, &s3.DeleteObjectInput{Bucket: &bucket, Key: version.Key, VersionId: version.VersionId})
		}
		for _, marker := range versions.DeleteMarkers {
			_, _ = p.client.DeleteObject(ctx, &s3.DeleteObjectInput{Bucket: &bucket, Key: marker.Key, VersionId: marker.VersionId})
		}
	}
	objects, err := p.client.ListObjectsV2(ctx, &s3.ListObjectsV2Input{Bucket: &bucket})
	if err == nil {
		for _, object := range objects.Contents {
			_, _ = p.client.DeleteObject(ctx, &s3.DeleteObjectInput{Bucket: &bucket, Key: object.Key})
		}
	}
	_, _ = p.client.DeleteBucket(ctx, &s3.DeleteBucketInput{Bucket: &bucket})
}

func requireObjectBody(ctx context.Context, client *s3.Client, bucket, key string, expected []byte, byteRange string) error {
	input := &s3.GetObjectInput{Bucket: &bucket, Key: &key}
	if byteRange != "" {
		input.Range = &byteRange
	}
	output, err := client.GetObject(ctx, input)
	if err != nil {
		return err
	}
	defer output.Body.Close()
	body, err := io.ReadAll(output.Body)
	if err != nil {
		return err
	}
	if !bytes.Equal(body, expected) {
		return fmt.Errorf("object body length = %d, want %d", len(body), len(expected))
	}
	return nil
}

func objectVersionPath(versionRoot, bucket, key, versionID string) string {
	sum := fmt.Sprintf("%x", sha256.Sum256([]byte(key)))
	return filepath.Join(versionRoot, bucket, sum[:2], sum[2:4], sum[4:6], sum, versionID)
}

func pastLifecycleDate(now time.Time) time.Time {
	midnight := now.UTC().Truncate(24 * time.Hour)
	return midnight.Add(-24 * time.Hour)
}

func requireRetainedVersionIDs(written, actual []string, keep int) error {
	if keep < 0 || len(written) < keep+1 {
		return fmt.Errorf("invalid retention expectation")
	}
	expected := append([]string(nil), written[len(written)-keep-1:]...)
	sort.Strings(expected)
	actual = append([]string(nil), actual...)
	sort.Strings(actual)
	if strings.Join(expected, "\x00") != strings.Join(actual, "\x00") {
		return fmt.Errorf("retained version IDs = %v, want %v", actual, expected)
	}
	return nil
}

func apiErrorCode(err error) string {
	var apiError smithy.APIError
	if errors.As(err, &apiError) {
		return apiError.ErrorCode()
	}
	return ""
}

func waitFor(timeout time.Duration, condition func() (bool, error)) error {
	deadline := time.Now().Add(timeout)
	var lastErr error
	for time.Now().Before(deadline) {
		ready, err := condition()
		if ready {
			return nil
		}
		if err != nil {
			lastErr = err
		}
		time.Sleep(500 * time.Millisecond)
	}
	if lastErr != nil {
		return fmt.Errorf("timed out: %w", lastErr)
	}
	return fmt.Errorf("timed out")
}
