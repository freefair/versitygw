// Copyright 2026 Versity Software
// This file is licensed under the Apache License, Version 2.0.

package azure

import (
	"context"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/Azure/azure-sdk-for-go/sdk/azcore"
	"github.com/Azure/azure-sdk-for-go/sdk/storage/azblob/blob"
	"github.com/Azure/azure-sdk-for-go/sdk/storage/azblob/bloberror"
	"github.com/Azure/azure-sdk-for-go/sdk/storage/azblob/lease"
	"github.com/Azure/azure-sdk-for-go/sdk/storage/azblob/service"
	"github.com/aws/aws-sdk-go-v2/service/s3"
	"github.com/aws/aws-sdk-go-v2/service/s3/types"
	"github.com/versity/versitygw/internal/lifecycle"
	"github.com/versity/versitygw/s3err"
)

const (
	azureLifecycleLeaseDuration = int32(60)
	azureLifecycleRenewInterval = 30 * time.Second
)

type azureLifecycleLease struct {
	backend *Azure
	bucket  string
	client  *lease.ContainerClient
	cancel  context.CancelFunc
	done    chan struct{}
	lost    atomic.Bool
	once    sync.Once
}

var _ lifecycle.Executor = (*Azure)(nil)

func (az *Azure) LifecycleCapabilities() lifecycle.Capabilities {
	return lifecycle.Capabilities{}
}

func (az *Azure) PutLifecycleConfiguration(ctx context.Context, bucket string, configuration lifecycle.Configuration) error {
	body, err := lifecycle.MarshalStored(configuration)
	if err != nil {
		return err
	}
	return az.setContainerMetaData(ctx, bucket, string(keyLifecycle), body)
}

func (az *Azure) GetLifecycleConfiguration(ctx context.Context, bucket string) (lifecycle.Configuration, error) {
	body, err := az.getContainerMetaData(ctx, bucket, string(keyLifecycle))
	if err != nil {
		return lifecycle.Configuration{}, err
	}
	if len(body) == 0 {
		return lifecycle.Configuration{}, s3err.GetAPIError(s3err.ErrNoSuchLifecycleConfiguration)
	}
	configuration, err := lifecycle.ParseStored(body, az.LifecycleCapabilities())
	if err != nil {
		return lifecycle.Configuration{}, fmt.Errorf("parse stored lifecycle configuration: %w", err)
	}
	return configuration, nil
}

func (az *Azure) DeleteLifecycleConfiguration(ctx context.Context, bucket string) error {
	return az.deleteContainerMetaData(ctx, bucket, string(keyLifecycle))
}

func (az *Azure) ListLifecycleBuckets(ctx context.Context) ([]string, error) {
	pager := az.client.NewListContainersPager(&service.ListContainersOptions{Include: service.ListContainersInclude{Metadata: true}})
	var buckets []string
	for pager.More() {
		page, err := pager.NextPage(ctx)
		if err != nil {
			return nil, azureErrToS3Err(err)
		}
		for _, item := range page.ContainerItems {
			if item.Name == nil {
				continue
			}
			value := item.Metadata[strings.ToLower(string(keyLifecycle))]
			if value == nil {
				value = item.Metadata[string(keyLifecycle)]
			}
			if value != nil && *value != "" {
				buckets = append(buckets, *item.Name)
			}
		}
	}
	return buckets, nil
}

func (az *Azure) AcquireLifecycleLease(ctx context.Context, bucket string) (io.Closer, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	az.lifecycleMu.Lock()
	defer az.lifecycleMu.Unlock()
	if az.lifecycleLeases == nil {
		az.lifecycleLeases = make(map[string]*azureLifecycleLease)
	}
	if _, exists := az.lifecycleLeases[bucket]; exists {
		return nil, lifecycle.ErrLeaseUnavailable
	}
	containerClient, err := az.getContainerClient(bucket)
	if err != nil {
		return nil, err
	}
	leaseClient, err := lease.NewContainerClient(containerClient, nil)
	if err != nil {
		return nil, fmt.Errorf("initialize Azure lifecycle lease: %w", err)
	}
	if _, err := leaseClient.AcquireLease(ctx, azureLifecycleLeaseDuration, nil); err != nil {
		if bloberror.HasCode(err, bloberror.LeaseAlreadyPresent) {
			return nil, lifecycle.ErrLeaseUnavailable
		}
		return nil, fmt.Errorf("acquire Azure lifecycle lease: %w", err)
	}
	renewContext, cancel := context.WithCancel(context.Background())
	result := &azureLifecycleLease{backend: az, bucket: bucket, client: leaseClient, cancel: cancel, done: make(chan struct{})}
	az.lifecycleLeases[bucket] = result
	go result.renew(renewContext)
	return result, nil
}

func (l *azureLifecycleLease) renew(ctx context.Context) {
	defer close(l.done)
	ticker := time.NewTicker(azureLifecycleRenewInterval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			renewContext, cancel := context.WithTimeout(ctx, 10*time.Second)
			_, err := l.client.RenewLease(renewContext, nil)
			cancel()
			if err != nil {
				l.lost.Store(true)
				return
			}
		}
	}
}

func (l *azureLifecycleLease) Close() error {
	var closeErr error
	l.once.Do(func() {
		l.cancel()
		<-l.done
		releaseContext, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		_, closeErr = l.client.ReleaseLease(releaseContext, nil)
		cancel()
		l.backend.lifecycleMu.Lock()
		if l.backend.lifecycleLeases[l.bucket] == l {
			delete(l.backend.lifecycleLeases, l.bucket)
		}
		l.backend.lifecycleMu.Unlock()
	})
	return closeErr
}

func (az *Azure) activeLifecycleLease(bucket string) error {
	az.lifecycleMu.Lock()
	defer az.lifecycleMu.Unlock()
	active := az.lifecycleLeases[bucket]
	if active == nil || active.lost.Load() {
		return lifecycle.ErrLeaseUnavailable
	}
	return nil
}

func (az *Azure) ListLifecycleCandidates(ctx context.Context, bucket string, cursor lifecycle.Cursor, limit int32) (lifecycle.Page, error) {
	if limit <= 0 {
		limit = 1000
	}
	if cursor.Phase == "" || cursor.Phase == "objects" {
		startAfter := ""
		objects, err := az.ListObjectsV2(ctx, &s3.ListObjectsV2Input{
			Bucket: &bucket, MaxKeys: &limit, ContinuationToken: optionalAzureString(cursor.KeyMarker), StartAfter: &startAfter,
		})
		if err != nil {
			return lifecycle.Page{}, err
		}
		page := lifecycle.Page{Candidates: make([]lifecycle.Candidate, 0, len(objects.Contents))}
		for _, object := range objects.Contents {
			if object.Key == nil {
				continue
			}
			candidate, err := az.lifecycleObjectCandidate(ctx, bucket, *object.Key)
			if err != nil {
				return lifecycle.Page{}, err
			}
			page.Candidates = append(page.Candidates, candidate)
		}
		if objects.IsTruncated != nil && *objects.IsTruncated {
			page.Next = &lifecycle.Cursor{Phase: "objects", KeyMarker: getString(objects.NextContinuationToken)}
		} else {
			page.Next = &lifecycle.Cursor{Phase: "multipart"}
		}
		return page, nil
	}
	if cursor.Phase != "multipart" {
		return lifecycle.Page{}, fmt.Errorf("invalid Azure lifecycle cursor phase %q", cursor.Phase)
	}
	uploads, err := az.ListMultipartUploads(ctx, &s3.ListMultipartUploadsInput{
		Bucket: &bucket, KeyMarker: optionalAzureString(cursor.KeyMarker), UploadIdMarker: optionalAzureString(cursor.UploadIDMarker), MaxUploads: &limit,
	})
	if err != nil {
		return lifecycle.Page{}, err
	}
	page := lifecycle.Page{Candidates: make([]lifecycle.Candidate, 0, len(uploads.Uploads))}
	for _, upload := range uploads.Uploads {
		candidate := lifecycle.Candidate{
			Kind: lifecycle.CandidateMultipart, Bucket: bucket, Key: upload.Key, UploadID: upload.UploadID,
			LastModified: upload.Initiated, StorageClass: string(upload.StorageClass),
		}
		candidate.StateToken = azureLifecycleStateToken(candidate)
		page.Candidates = append(page.Candidates, candidate)
	}
	if uploads.IsTruncated {
		page.Next = &lifecycle.Cursor{Phase: "multipart", KeyMarker: uploads.NextKeyMarker, UploadIDMarker: uploads.NextUploadIDMarker}
	}
	return page, nil
}

func (az *Azure) lifecycleObjectCandidate(ctx context.Context, bucket, key string) (lifecycle.Candidate, error) {
	head, err := az.HeadObject(ctx, &s3.HeadObjectInput{Bucket: &bucket, Key: &key})
	if err != nil {
		return lifecycle.Candidate{}, err
	}
	candidate := lifecycle.Candidate{
		Kind: lifecycle.CandidateObject, Bucket: bucket, Key: key, Current: true,
		Versioning: lifecycle.VersioningNever, StorageClass: string(head.StorageClass),
	}
	if head.ETag != nil {
		candidate.ETag = *head.ETag
	}
	if head.ContentLength != nil {
		candidate.Size = *head.ContentLength
	}
	if head.LastModified != nil {
		candidate.LastModified = *head.LastModified
	}
	if tags, err := az.GetObjectTagging(ctx, bucket, key, ""); err == nil {
		candidate.Tags = tags
	}
	hold, holdErr := az.GetObjectLegalHold(ctx, bucket, key, "")
	if holdErr != nil && !isMissingAzureLifecycleLockMetadata(holdErr) {
		return lifecycle.Candidate{}, fmt.Errorf("read legal hold before lifecycle mutation: %w", holdErr)
	}
	if hold != nil && *hold {
		candidate.Protected = true
	} else {
		retention, retentionErr := az.GetObjectRetention(ctx, bucket, key, "")
		protected, err := azureLifecycleObjectProtected(hold, holdErr, retention, retentionErr)
		if err != nil {
			return lifecycle.Candidate{}, err
		}
		candidate.Protected = protected
	}
	candidate.StateToken = azureLifecycleStateToken(candidate)
	return candidate, nil
}

func azureLifecycleObjectProtected(hold *bool, holdErr error, retention []byte, retentionErr error) (bool, error) {
	if holdErr != nil && !isMissingAzureLifecycleLockMetadata(holdErr) {
		return false, fmt.Errorf("read legal hold before lifecycle mutation: %w", holdErr)
	}
	if hold != nil && *hold {
		return true, nil
	}
	if retentionErr != nil {
		if isMissingAzureLifecycleLockMetadata(retentionErr) {
			return false, nil
		}
		return false, fmt.Errorf("read retention before lifecycle mutation: %w", retentionErr)
	}
	var value types.ObjectLockRetention
	if err := json.Unmarshal(retention, &value); err != nil {
		return false, fmt.Errorf("parse retention before lifecycle mutation: %w", err)
	}
	if value.RetainUntilDate == nil {
		return false, fmt.Errorf("parse retention before lifecycle mutation: missing retain-until date")
	}
	return time.Now().Before(*value.RetainUntilDate), nil
}

func isMissingAzureLifecycleLockMetadata(err error) bool {
	return errors.Is(err, s3err.GetAPIError(s3err.ErrNoSuchObjectLockConfiguration)) ||
		errors.Is(err, s3err.GetAPIError(s3err.ErrObjectLockConfigurationNotFound)) ||
		errors.Is(err, s3err.GetAPIError(s3err.ErrMissingObjectLockConfiguration)) ||
		errors.Is(err, s3err.GetAPIError(s3err.ErrMissingObjectLockConfigurationNoSpaces))
}

func azureLifecycleStateToken(candidate lifecycle.Candidate) string {
	candidate.StateToken = ""
	body, err := json.Marshal(candidate)
	if err != nil {
		panic(fmt.Sprintf("marshal Azure lifecycle state token: %v", err))
	}
	return fmt.Sprintf("%x", sha256.Sum256(body))
}

func (az *Azure) ApplyLifecycleAction(ctx context.Context, action lifecycle.Action) error {
	if err := az.activeLifecycleLease(action.Bucket); err != nil {
		return err
	}
	if action.Kind == lifecycle.ActionAbortMultipart {
		candidate, err := az.findLifecycleUpload(ctx, action.Bucket, action.Key, action.UploadID)
		if err != nil || candidate.StateToken != action.StateToken {
			return lifecycle.ErrConflict
		}
		initiated := candidate.LastModified
		if err := az.activeLifecycleLease(action.Bucket); err != nil {
			return err
		}
		err = az.AbortMultipartUpload(ctx, &s3.AbortMultipartUploadInput{
			Bucket: &action.Bucket, Key: &action.Key, UploadId: &action.UploadID, IfMatchInitiatedTime: &initiated,
		})
		if errors.Is(err, s3err.GetAPIError(s3err.ErrPreconditionFailed)) {
			return lifecycle.ErrConflict
		}
		return err
	}
	if action.Kind != lifecycle.ActionDeleteCurrent {
		return encryptionUnsupportedLifecycleAction(action.Kind)
	}
	candidate, err := az.lifecycleObjectCandidate(ctx, action.Bucket, action.Key)
	if err != nil {
		if errors.Is(err, s3err.GetAPIError(s3err.ErrNoSuchKey)) {
			return nil
		}
		return err
	}
	if candidate.StateToken != action.StateToken || candidate.Protected {
		return lifecycle.ErrConflict
	}
	client, err := az.getBlobClient(action.Bucket, action.Key)
	if err != nil {
		return err
	}
	etag := azcore.ETag(candidate.ETag)
	if err := az.activeLifecycleLease(action.Bucket); err != nil {
		return err
	}
	_, err = client.Delete(ctx, &blob.DeleteOptions{AccessConditions: &blob.AccessConditions{
		ModifiedAccessConditions: &blob.ModifiedAccessConditions{IfMatch: &etag},
	}})
	if bloberror.HasCode(err, bloberror.ConditionNotMet) {
		return lifecycle.ErrConflict
	}
	return azureErrToS3Err(err)
}

func (az *Azure) findLifecycleUpload(ctx context.Context, bucket, key, uploadID string) (lifecycle.Candidate, error) {
	limit := int32(1000)
	var keyMarker, uploadMarker string
	for {
		uploads, err := az.ListMultipartUploads(ctx, &s3.ListMultipartUploadsInput{
			Bucket: &bucket, KeyMarker: &keyMarker, UploadIdMarker: &uploadMarker, MaxUploads: &limit,
		})
		if err != nil {
			return lifecycle.Candidate{}, err
		}
		for _, upload := range uploads.Uploads {
			if upload.Key == key && upload.UploadID == uploadID {
				candidate := lifecycle.Candidate{
					Kind: lifecycle.CandidateMultipart, Bucket: bucket, Key: key, UploadID: uploadID,
					LastModified: upload.Initiated, StorageClass: string(upload.StorageClass),
				}
				candidate.StateToken = azureLifecycleStateToken(candidate)
				return candidate, nil
			}
		}
		if !uploads.IsTruncated {
			return lifecycle.Candidate{}, lifecycle.ErrConflict
		}
		keyMarker, uploadMarker = uploads.NextKeyMarker, uploads.NextUploadIDMarker
	}
}

func optionalAzureString(value string) *string {
	if value == "" {
		return nil
	}
	return &value
}

func encryptionUnsupportedLifecycleAction(kind lifecycle.ActionKind) error {
	return fmt.Errorf("Azure lifecycle action %s is not supported", kind)
}
