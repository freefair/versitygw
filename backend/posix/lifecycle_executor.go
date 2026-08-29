// Copyright 2026 Versity Software
// This file is licensed under the Apache License, Version 2.0.

package posix

import (
	"context"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"sort"
	"time"

	"github.com/aws/aws-sdk-go-v2/service/s3"
	"github.com/aws/aws-sdk-go-v2/service/s3/types"
	"github.com/google/uuid"
	"github.com/versity/versitygw/backend/meta"
	"github.com/versity/versitygw/internal/lifecycle"
	"github.com/versity/versitygw/s3err"
)

func (p *Posix) ListLifecycleBuckets(ctx context.Context) ([]string, error) {
	release, err := p.acquireActionSlot(ctx)
	if err != nil {
		return nil, err
	}
	defer release()

	entries, err := os.ReadDir(".")
	if err != nil {
		return nil, fmt.Errorf("read backend root: %w", err)
	}
	buckets := make([]string, 0)
	for _, entry := range entries {
		if !entry.IsDir() && entry.Type()&fs.ModeSymlink == 0 {
			continue
		}
		bucket := entry.Name()
		if !p.isBucketValid(bucket) {
			continue
		}
		_, err := p.meta.RetrieveAttribute(nil, bucket, "", lifecyclekey)
		if errors.Is(err, meta.ErrNoSuchKey) || errors.Is(err, fs.ErrNotExist) {
			continue
		}
		if err != nil {
			return nil, fmt.Errorf("read lifecycle marker for %q: %w", bucket, err)
		}
		buckets = append(buckets, bucket)
	}
	sort.Strings(buckets)
	return buckets, nil
}

func (p *Posix) ListLifecycleCandidates(ctx context.Context, bucket string, cursor lifecycle.Cursor, limit int32) (lifecycle.Page, error) {
	if err := p.requireLifecycleBucket(bucket); err != nil {
		return lifecycle.Page{}, err
	}
	if limit <= 0 {
		limit = 1000
	}
	if cursor.Phase == "" || cursor.Phase == "objects" {
		return p.listLifecycleObjectCandidates(ctx, bucket, cursor, limit)
	}
	if cursor.Phase == "multipart" {
		return p.listLifecycleMultipartCandidates(ctx, bucket, cursor, limit)
	}
	return lifecycle.Page{}, fmt.Errorf("invalid lifecycle cursor phase %q", cursor.Phase)
}

func (p *Posix) listLifecycleObjectCandidates(ctx context.Context, bucket string, cursor lifecycle.Cursor, limit int32) (lifecycle.Page, error) {
	status, err := p.getBucketVersioningStatus(ctx, bucket)
	if err != nil {
		return lifecycle.Page{}, err
	}
	versioning := lifecycle.VersioningNever
	if status == types.BucketVersioningStatusEnabled {
		versioning = lifecycle.VersioningEnabled
	}
	if status == types.BucketVersioningStatusSuspended {
		versioning = lifecycle.VersioningSuspended
	}

	result, err := p.ListObjectVersions(withCtxNoSlot(ctx), &s3.ListObjectVersionsInput{
		Bucket: &bucket, KeyMarker: optionalString(cursor.KeyMarker), VersionIdMarker: optionalString(cursor.VersionIDMarker), MaxKeys: &limit,
	})
	if err != nil {
		return lifecycle.Page{}, err
	}
	candidates := make([]lifecycle.Candidate, 0, len(result.Versions)+len(result.DeleteMarkers))
	for _, version := range result.Versions {
		candidate := lifecycle.Candidate{Kind: lifecycle.CandidateObject, Bucket: bucket, Versioning: versioning, StorageClass: string(version.StorageClass)}
		if version.ETag != nil {
			candidate.ETag = *version.ETag
		}
		candidate.Key = stringValue(version.Key)
		candidate.VersionID = stringValue(version.VersionId)
		if version.IsLatest != nil {
			candidate.Current = *version.IsLatest
		}
		if version.LastModified != nil {
			candidate.LastModified = *version.LastModified
		}
		if version.Size != nil {
			candidate.Size = *version.Size
		}
		candidates = append(candidates, candidate)
	}
	for _, marker := range result.DeleteMarkers {
		candidate := lifecycle.Candidate{
			Kind: lifecycle.CandidateObject, Bucket: bucket, Versioning: versioning, DeleteMarker: true,
			Key: stringValue(marker.Key), VersionID: stringValue(marker.VersionId),
		}
		if marker.IsLatest != nil {
			candidate.Current = *marker.IsLatest
		}
		if marker.LastModified != nil {
			candidate.LastModified = *marker.LastModified
		}
		candidates = append(candidates, candidate)
	}
	sort.SliceStable(candidates, func(i, j int) bool {
		if candidates[i].Key != candidates[j].Key {
			return candidates[i].Key < candidates[j].Key
		}
		return candidates[i].LastModified.After(candidates[j].LastModified)
	})
	previousKey, previousTime, noncurrentRank := cursor.PreviousKey, cursor.PreviousTime, cursor.NoncurrentRank
	for index := range candidates {
		candidate := &candidates[index]
		if candidate.Key != previousKey {
			previousKey, previousTime, noncurrentRank = candidate.Key, time.Time{}, 0
		}
		if !candidate.Current {
			candidate.NoncurrentSince = previousTime
			if !candidate.DeleteMarker {
				noncurrentRank++
				candidate.NoncurrentRank = noncurrentRank
			}
		}
		previousTime = candidate.LastModified
		if candidate.DeleteMarker {
			if candidate.Current {
				only, err := p.lifecycleDeleteMarkerIsOnlyVersion(ctx, bucket, candidate.Key, candidate.VersionID)
				if err != nil {
					return lifecycle.Page{}, err
				}
				if only {
					candidate.VersionsForKey = 1
				} else {
					candidate.VersionsForKey = 2
				}
			}
			candidate.StateToken = lifecycleStateToken(*candidate)
			continue
		}
		versionID := candidate.VersionID
		if candidate.Versioning == lifecycle.VersioningNever {
			versionID = ""
		}
		tags, err := p.GetObjectTagging(withCtxNoSlot(ctx), bucket, candidate.Key, versionID)
		if err == nil {
			candidate.Tags = tags
		}
		candidate.Protected, err = p.lifecycleObjectProtected(ctx, bucket, candidate.Key, versionID)
		if err != nil {
			return lifecycle.Page{}, err
		}
		candidate.StateToken = lifecycleStateToken(*candidate)
	}
	page := lifecycle.Page{Candidates: candidates}
	if result.IsTruncated != nil && *result.IsTruncated {
		page.Next = &lifecycle.Cursor{
			Phase: "objects", KeyMarker: stringValue(result.NextKeyMarker), VersionIDMarker: stringValue(result.NextVersionIdMarker),
			PreviousKey: previousKey, PreviousTime: previousTime, NoncurrentRank: noncurrentRank,
		}
	} else {
		page.Next = &lifecycle.Cursor{Phase: "multipart"}
	}
	return page, nil
}

func (p *Posix) lifecycleDeleteMarkerIsOnlyVersion(ctx context.Context, bucket, key, versionID string) (bool, error) {
	maxKeys := int32(2)
	result, err := p.ListObjectVersions(withCtxNoSlot(ctx), &s3.ListObjectVersionsInput{Bucket: &bucket, Prefix: &key, MaxKeys: &maxKeys})
	if err != nil {
		return false, err
	}
	count := 0
	for _, version := range result.Versions {
		if stringValue(version.Key) == key {
			count++
		}
	}
	for _, marker := range result.DeleteMarkers {
		if stringValue(marker.Key) == key {
			count++
		}
	}
	return count == 1 && len(result.DeleteMarkers) == 1 && stringValue(result.DeleteMarkers[0].VersionId) == versionID, nil
}

func (p *Posix) listLifecycleMultipartCandidates(ctx context.Context, bucket string, cursor lifecycle.Cursor, limit int32) (lifecycle.Page, error) {
	result, err := p.ListMultipartUploads(withCtxNoSlot(ctx), &s3.ListMultipartUploadsInput{
		Bucket: &bucket, KeyMarker: optionalString(cursor.KeyMarker), UploadIdMarker: optionalString(cursor.UploadIDMarker), MaxUploads: &limit,
	})
	if err != nil {
		return lifecycle.Page{}, err
	}
	page := lifecycle.Page{Candidates: make([]lifecycle.Candidate, 0, len(result.Uploads))}
	for _, upload := range result.Uploads {
		candidate := lifecycle.Candidate{
			Kind: lifecycle.CandidateMultipart, Bucket: bucket, Key: upload.Key, UploadID: upload.UploadID,
			LastModified: upload.Initiated, StorageClass: string(upload.StorageClass),
		}
		candidate.StateToken = lifecycleStateToken(candidate)
		page.Candidates = append(page.Candidates, candidate)
	}
	if result.IsTruncated {
		page.Next = &lifecycle.Cursor{Phase: "multipart", KeyMarker: result.NextKeyMarker, UploadIDMarker: result.NextUploadIDMarker}
	}
	return page, nil
}

func (p *Posix) allLifecycleCandidates(ctx context.Context, bucket string) ([]lifecycle.Candidate, error) {
	var candidates []lifecycle.Candidate
	cursor := lifecycle.Cursor{}
	for {
		page, err := p.ListLifecycleCandidates(ctx, bucket, cursor, 1000)
		if err != nil {
			return nil, err
		}
		candidates = append(candidates, page.Candidates...)
		if page.Next == nil {
			return candidates, nil
		}
		cursor = *page.Next
	}
}

func lifecycleStateToken(candidate lifecycle.Candidate) string {
	candidate.StateToken = ""
	body, err := json.Marshal(candidate)
	if err != nil {
		panic(fmt.Sprintf("marshal lifecycle state token: %v", err))
	}
	return fmt.Sprintf("%x", sha256.Sum256(body))
}

func (p *Posix) ApplyLifecycleAction(ctx context.Context, action lifecycle.Action) error {
	return p.ApplyLifecycleActionWithGuard(ctx, action, nil)
}

// ApplyLifecycleActionWithGuard revalidates an external leadership or fencing
// condition immediately before a destructive mutation.
func (p *Posix) ApplyLifecycleActionWithGuard(ctx context.Context, action lifecycle.Action, guard func() error) error {
	if action.Kind == lifecycle.ActionAbortMultipart {
		_, err := p.findLifecycleUpload(ctx, action.Bucket, action.Key, action.UploadID, action.StateToken)
		if err != nil {
			return err
		}
		initiated := action.ObservedAt
		if err := runLifecycleMutationGuard(guard); err != nil {
			return err
		}
		err = p.AbortMultipartUpload(withCtxNoSlot(ctx), &s3.AbortMultipartUploadInput{Bucket: &action.Bucket, Key: &action.Key, UploadId: &action.UploadID, IfMatchInitiatedTime: &initiated})
		if errors.Is(err, s3err.GetAPIError(s3err.ErrPreconditionFailed)) {
			return lifecycle.ErrConflict
		}
		return err
	}
	if action.Kind == lifecycle.ActionTransition {
		return p.TransitionLifecycleObjectGuarded(ctx, action, nil, guard)
	}
	mutationRelease, err := p.acquireObjectMutationLock(ctx, action.Bucket, action.Key)
	if err != nil {
		return err
	}
	defer mutationRelease()
	ctx = withObjectMutationHeld(ctx)

	token, err := p.currentLifecycleStateToken(ctx, action)
	if errors.Is(err, fs.ErrNotExist) {
		return nil
	}
	if err != nil {
		return err
	}
	if token != action.StateToken {
		return lifecycle.ErrConflict
	}
	versionID := action.VersionID
	if action.Kind == lifecycle.ActionDeleteCurrent || action.Kind == lifecycle.ActionCreateDeleteMarker || action.Kind == lifecycle.ActionExpireSuspendedCurrent {
		versionID = ""
	}
	if action.Kind == lifecycle.ActionDeleteVersion {
		protected, err := p.lifecycleObjectProtected(ctx, action.Bucket, action.Key, versionID)
		if err != nil {
			return err
		}
		if protected {
			return nil
		}
	}
	if err := runLifecycleMutationGuard(guard); err != nil {
		return err
	}
	_, err = p.DeleteObject(withCtxNoSlot(ctx), &s3.DeleteObjectInput{Bucket: &action.Bucket, Key: &action.Key, VersionId: optionalString(versionID)})
	return err
}

func runLifecycleMutationGuard(guard func() error) error {
	if guard == nil {
		return nil
	}
	return guard()
}

func (p *Posix) currentLifecycleStateToken(ctx context.Context, action lifecycle.Action) (string, error) {
	cursor := lifecycle.Cursor{}
	for {
		page, err := p.ListLifecycleCandidates(ctx, action.Bucket, cursor, 1000)
		if err != nil {
			return "", err
		}
		for _, candidate := range page.Candidates {
			if candidate.Kind == lifecycle.CandidateObject && candidate.Key == action.Key && candidate.VersionID == action.VersionID && candidate.Current == action.Current {
				return candidate.StateToken, nil
			}
		}
		if page.Next == nil || page.Next.Phase == "multipart" {
			return "", fs.ErrNotExist
		}
		cursor = *page.Next
	}
}

func (p *Posix) lifecycleObjectProtected(ctx context.Context, bucket, object, versionID string) (bool, error) {
	hold, err := p.GetObjectLegalHold(withCtxNoSlot(ctx), bucket, object, versionID)
	if err != nil && !isMissingLifecycleLockMetadata(err) {
		return false, fmt.Errorf("read legal hold before lifecycle mutation: %w", err)
	}
	if hold != nil && *hold {
		return true, nil
	}
	retention, err := p.GetObjectRetention(withCtxNoSlot(ctx), bucket, object, versionID)
	if err != nil {
		if isMissingLifecycleLockMetadata(err) {
			return false, nil
		}
		return false, fmt.Errorf("read retention before lifecycle mutation: %w", err)
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

func (p *Posix) findLifecycleUpload(ctx context.Context, bucket, key, uploadID, token string) (lifecycle.Candidate, error) {
	if err := ctx.Err(); err != nil {
		return lifecycle.Candidate{}, err
	}
	if uuid.Validate(uploadID) != nil {
		return lifecycle.Candidate{}, lifecycle.ErrConflict
	}
	container := fmt.Sprintf("%x", sha256.Sum256([]byte(key)))
	info, err := os.Stat(filepath.Join(bucket, MetaTmpMultipartDir, container, uploadID))
	if errors.Is(err, fs.ErrNotExist) || isErrNotDir(err) {
		return lifecycle.Candidate{}, lifecycle.ErrConflict
	}
	if err != nil {
		return lifecycle.Candidate{}, fmt.Errorf("stat lifecycle multipart upload: %w", err)
	}
	if !info.IsDir() {
		return lifecycle.Candidate{}, lifecycle.ErrConflict
	}
	candidate := lifecycle.Candidate{
		Kind: lifecycle.CandidateMultipart, Bucket: bucket, Key: key, UploadID: uploadID,
		LastModified: info.ModTime(), StorageClass: string(types.StorageClassStandard),
	}
	if lifecycleStateToken(candidate) != token {
		return lifecycle.Candidate{}, lifecycle.ErrConflict
	}
	return candidate, nil
}

func isMissingLifecycleLockMetadata(err error) bool {
	return errors.Is(err, s3err.GetAPIError(s3err.ErrNoSuchObjectLockConfiguration)) ||
		errors.Is(err, s3err.GetAPIError(s3err.ErrObjectLockConfigurationNotFound)) ||
		errors.Is(err, s3err.GetAPIError(s3err.ErrMissingObjectLockConfiguration)) ||
		errors.Is(err, s3err.GetAPIError(s3err.ErrMissingObjectLockConfigurationNoSpaces))
}

func stringValue(value *string) string {
	if value == nil {
		return ""
	}
	return *value
}
func optionalString(value string) *string {
	if value == "" {
		return nil
	}
	return &value
}
