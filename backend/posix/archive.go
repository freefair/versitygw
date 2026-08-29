// Copyright 2026 Versity Software
// This file is licensed under the Apache License, Version 2.0.

package posix

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"net/http"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/aws/aws-sdk-go-v2/service/s3"
	"github.com/aws/aws-sdk-go-v2/service/s3/types"
	"github.com/versity/versitygw/backend/meta"
	"github.com/versity/versitygw/internal/encryption"
	"github.com/versity/versitygw/internal/lifecycle"
	"github.com/versity/versitygw/s3err"
)

const archiveManifestKey = "archive-manifest"

type archiveManifest struct {
	Version        int                `json:"version"`
	Bucket         string             `json:"bucket"`
	Key            string             `json:"key"`
	VersionID      string             `json:"version_id"`
	StorageClass   string             `json:"storage_class"`
	PlaintextSize  int64              `json:"plaintext_size"`
	StoredSize     int64              `json:"stored_size"`
	SHA256         string             `json:"sha256"`
	ETag           string             `json:"etag,omitempty"`
	Checksums      []byte             `json:"checksums,omitempty"`
	Encryption     *encryption.Result `json:"encryption,omitempty"`
	ArchivePath    string             `json:"archive_path"`
	LastModified   time.Time          `json:"last_modified"`
	TransitionedAt time.Time          `json:"transitioned_at"`
	RestoredUntil  *time.Time         `json:"restored_until,omitempty"`
}

func validateArchiveTiers(root, versionRoot, sidecarRoot, keyRoot string, configured map[string]string) (map[string]string, error) {
	if len(configured) == 0 {
		return nil, nil
	}
	protected := []string{root, versionRoot, sidecarRoot, keyRoot}
	validated := make(map[string]string, len(configured))
	for class, path := range configured {
		class = strings.ToUpper(strings.TrimSpace(class))
		if !validArchiveStorageClass(class) {
			return nil, fmt.Errorf("unsupported POSIX archive storage class %q", class)
		}
		if strings.TrimSpace(path) == "" {
			return nil, fmt.Errorf("archive root for %s is empty", class)
		}
		absolute, err := filepath.Abs(path)
		if err != nil {
			return nil, fmt.Errorf("get absolute archive root for %s: %w", class, err)
		}
		absolute, err = filepath.EvalSymlinks(absolute)
		if err != nil {
			return nil, fmt.Errorf("resolve archive root for %s: %w", class, err)
		}
		info, err := os.Stat(absolute)
		if err != nil {
			return nil, fmt.Errorf("stat archive root for %s: %w", class, err)
		}
		if !info.IsDir() {
			return nil, fmt.Errorf("archive root for %s is not a directory", class)
		}
		for _, other := range protected {
			if other == "" {
				continue
			}
			resolved, resolveErr := filepath.EvalSymlinks(other)
			if resolveErr != nil {
				return nil, fmt.Errorf("resolve protected POSIX root: %w", resolveErr)
			}
			if isDirBelowRoot(resolved, absolute) || isDirBelowRoot(absolute, resolved) {
				return nil, fmt.Errorf("archive root %q overlaps a gateway data, version, metadata, or key root", absolute)
			}
		}
		for _, other := range validated {
			if isDirBelowRoot(other, absolute) || isDirBelowRoot(absolute, other) {
				return nil, fmt.Errorf("archive roots %q and %q overlap", absolute, other)
			}
		}
		probe, err := os.CreateTemp(absolute, ".versitygw-archive-probe-")
		if err != nil {
			return nil, fmt.Errorf("archive root for %s is not writable: %w", class, err)
		}
		probeName := probe.Name()
		if err := probe.Close(); err != nil {
			_ = os.Remove(probeName)
			return nil, fmt.Errorf("close archive root probe for %s: %w", class, err)
		}
		if err := os.Remove(probeName); err != nil {
			return nil, fmt.Errorf("remove archive root probe for %s: %w", class, err)
		}
		validated[class] = absolute
	}
	return validated, nil
}

func validArchiveStorageClass(class string) bool {
	switch class {
	case "STANDARD_IA", "ONEZONE_IA", "INTELLIGENT_TIERING", "GLACIER_IR", "GLACIER", "DEEP_ARCHIVE":
		return true
	default:
		return false
	}
}

func (p *Posix) archiveDataPath(manifest archiveManifest) (string, error) {
	root, ok := p.archiveTiers[manifest.StorageClass]
	if !ok {
		return "", fmt.Errorf("archive storage class %q is not configured", manifest.StorageClass)
	}
	segments := []string{root, hex.EncodeToString([]byte(manifest.Bucket)), "keys"}
	encodedKey := hex.EncodeToString([]byte(manifest.Key))
	if encodedKey == "" {
		encodedKey = "empty"
	}
	for len(encodedKey) > 200 {
		segments = append(segments, encodedKey[:200])
		encodedKey = encodedKey[200:]
	}
	segments = append(segments, encodedKey, "versions", hex.EncodeToString([]byte(manifest.VersionID)), "data")
	return filepath.Join(segments...), nil
}

func (p *Posix) loadArchiveManifest(bucket, object string) (*archiveManifest, error) {
	body, err := p.meta.RetrieveAttribute(nil, bucket, object, archiveManifestKey)
	if errors.Is(err, meta.ErrNoSuchKey) || errors.Is(err, fs.ErrNotExist) {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("retrieve archive manifest: %w", err)
	}
	decoder := json.NewDecoder(strings.NewReader(string(body)))
	decoder.DisallowUnknownFields()
	var manifest archiveManifest
	if err := decoder.Decode(&manifest); err != nil {
		return nil, fmt.Errorf("decode archive manifest: %w", err)
	}
	if manifest.Version != 1 || manifest.Bucket == "" || manifest.Key == "" || manifest.VersionID == "" || !validArchiveStorageClass(manifest.StorageClass) || manifest.PlaintextSize < 0 || manifest.StoredSize < 0 || manifest.ArchivePath == "" || filepath.IsAbs(manifest.ArchivePath) || filepath.Clean(manifest.ArchivePath) != manifest.ArchivePath || strings.HasPrefix(manifest.ArchivePath, ".."+string(filepath.Separator)) {
		return nil, fmt.Errorf("invalid archive manifest")
	}
	expected, err := p.archiveDataPath(manifest)
	if err != nil {
		return nil, err
	}
	root := p.archiveTiers[manifest.StorageClass]
	relative, err := filepath.Rel(root, expected)
	if err != nil || relative != manifest.ArchivePath {
		return nil, fmt.Errorf("invalid archive manifest path")
	}
	return &manifest, nil
}

func (p *Posix) storeArchiveManifest(file *os.File, bucket, object string, manifest archiveManifest) error {
	body, err := json.Marshal(manifest)
	if err != nil {
		return fmt.Errorf("encode archive manifest: %w", err)
	}
	if err := p.meta.StoreAttribute(file, bucket, object, archiveManifestKey, body); err != nil {
		return fmt.Errorf("store archive manifest: %w", err)
	}
	return nil
}

func (p *Posix) transitionObject(ctx context.Context, action lifecycle.Action) error {
	return p.TransitionLifecycleObject(ctx, action, nil)
}

// TransitionLifecycleObject archives an object and optionally delegates the
// hot-data release to a filesystem-native implementation such as ScoutFS.
func (p *Posix) TransitionLifecycleObject(ctx context.Context, action lifecycle.Action, release func(string) error) error {
	return p.TransitionLifecycleObjectGuarded(ctx, action, release, nil)
}

// TransitionLifecycleObjectGuarded revalidates an external leadership or
// fencing condition at each point where transition state becomes durable.
func (p *Posix) TransitionLifecycleObjectGuarded(ctx context.Context, action lifecycle.Action, release func(string) error, guard func() error) error {
	mutationRelease, err := p.acquireObjectMutationLock(ctx, action.Bucket, action.Key)
	if err != nil {
		return err
	}
	defer mutationRelease()
	ctx = withObjectMutationHeld(ctx)
	if _, ok := p.archiveTiers[action.TargetStorageClass]; !ok {
		return s3err.GetAPIError(s3err.ErrInvalidRequest)
	}
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
	physicalBucket, physicalObject, err := p.resolvePhysicalObject(action.Bucket, action.Key, action.VersionID)
	if err != nil {
		return err
	}
	sourcePath := filepath.Join(physicalBucket, physicalObject)
	info, err := os.Stat(sourcePath)
	if err != nil {
		return err
	}
	plainSize, err := p.objectPlaintextSize(physicalBucket, physicalObject, info.Size())
	if err != nil {
		return err
	}
	previous, err := p.loadArchiveManifest(physicalBucket, physicalObject)
	if err != nil {
		return err
	}
	if previous != nil && previous.StorageClass == action.TargetStorageClass {
		return nil
	}
	archiveSourcePath := sourcePath
	storedSize := info.Size()
	lastModified := info.ModTime().UTC()
	if previous != nil {
		archiveSourcePath, err = p.archiveDataPath(*previous)
		if err != nil {
			return err
		}
		storedSize = previous.StoredSize
		plainSize = previous.PlaintextSize
		lastModified = previous.LastModified
	}
	manifest := archiveManifest{
		Version: 1, Bucket: action.Bucket, Key: action.Key, VersionID: action.VersionID,
		StorageClass: action.TargetStorageClass, PlaintextSize: plainSize, StoredSize: storedSize,
		LastModified: lastModified, TransitionedAt: time.Now().UTC(),
	}
	if manifest.VersionID == "" {
		manifest.VersionID = nullVersionId
	}
	if err := p.populateArchiveRecoveryMetadata(physicalBucket, physicalObject, &manifest); err != nil {
		return err
	}
	destination, err := p.archiveDataPath(manifest)
	if err != nil {
		return err
	}
	manifest.ArchivePath, err = filepath.Rel(p.archiveTiers[manifest.StorageClass], destination)
	if err != nil {
		return fmt.Errorf("derive archive object path: %w", err)
	}
	if err := runLifecycleMutationGuard(guard); err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(destination), 0o750); err != nil {
		return fmt.Errorf("create archive object directory: %w", err)
	}
	if info.IsDir() {
		manifest.SHA256 = fmt.Sprintf("%x", sha256.Sum256(nil))
		if err := os.WriteFile(destination, nil, 0o600); err != nil {
			return fmt.Errorf("write archived directory object: %w", err)
		}
	} else {
		manifest.SHA256, err = p.copyFileToArchive(ctx, archiveSourcePath, destination, info.Mode().Perm())
		if err != nil {
			return err
		}
	}
	if err := writeArchiveManifestFile(destination+".json", manifest); err != nil {
		return err
	}
	currentInfo, statErr := os.Stat(sourcePath)
	currentToken, tokenErr := p.currentLifecycleStateToken(ctx, action)
	if statErr != nil || tokenErr != nil || !os.SameFile(info, currentInfo) || currentToken != action.StateToken {
		_ = os.Remove(destination)
		_ = os.Remove(destination + ".json")
		if statErr != nil {
			return statErr
		}
		if tokenErr != nil {
			return tokenErr
		}
		return lifecycle.ErrConflict
	}
	if err := runLifecycleMutationGuard(guard); err != nil {
		return err
	}
	if err := p.storeArchiveManifest(nil, physicalBucket, physicalObject, manifest); err != nil {
		return err
	}
	if !info.IsDir() {
		if err := runLifecycleMutationGuard(guard); err != nil {
			return err
		}
		if release != nil {
			if err := release(sourcePath); err != nil {
				return fmt.Errorf("release transitioned object data: %w", err)
			}
		} else if err := os.Truncate(sourcePath, 0); err != nil {
			return fmt.Errorf("truncate transitioned object to stub: %w", err)
		}
		if err := runLifecycleMutationGuard(guard); err != nil {
			return err
		}
		if err := os.Chtimes(sourcePath, manifest.LastModified, manifest.LastModified); err != nil {
			return fmt.Errorf("restore transitioned object timestamp: %w", err)
		}
	}
	if previous != nil {
		previousPath, pathErr := p.archiveDataPath(*previous)
		if pathErr == nil && previousPath != destination {
			_ = os.Remove(previousPath)
			_ = os.Remove(previousPath + ".json")
		}
	}
	return nil
}

func (p *Posix) populateArchiveRecoveryMetadata(bucket, object string, manifest *archiveManifest) error {
	etag, err := p.meta.RetrieveAttribute(nil, bucket, object, etagkey)
	if err == nil {
		manifest.ETag = string(etag)
	} else if !errors.Is(err, meta.ErrNoSuchKey) && !errors.Is(err, fs.ErrNotExist) {
		return fmt.Errorf("retrieve archive ETag: %w", err)
	}
	checksums, err := p.meta.RetrieveAttribute(nil, bucket, object, checksumsKey)
	if err == nil {
		manifest.Checksums = append([]byte(nil), checksums...)
	} else if !errors.Is(err, meta.ErrNoSuchKey) && !errors.Is(err, fs.ErrNotExist) {
		return fmt.Errorf("retrieve archive checksums: %w", err)
	}
	encryptionMetadata, err := p.meta.RetrieveAttribute(nil, bucket, object, encryptionResultKey)
	if err == nil {
		var result encryption.Result
		if err := json.Unmarshal(encryptionMetadata, &result); err != nil {
			return fmt.Errorf("decode archive encryption metadata: %w", err)
		}
		manifest.Encryption = &result
	} else if !errors.Is(err, meta.ErrNoSuchKey) && !errors.Is(err, fs.ErrNotExist) {
		return fmt.Errorf("retrieve archive encryption metadata: %w", err)
	}
	return nil
}

func (p *Posix) copyFileToArchive(ctx context.Context, sourcePath, destination string, mode fs.FileMode) (string, error) {
	source, err := os.Open(sourcePath)
	if err != nil {
		return "", fmt.Errorf("open object for transition: %w", err)
	}
	defer source.Close()
	temporary, err := os.CreateTemp(filepath.Dir(destination), ".data-")
	if err != nil {
		return "", fmt.Errorf("create archive temporary object: %w", err)
	}
	temporaryName := temporary.Name()
	defer os.Remove(temporaryName)
	if err := temporary.Chmod(mode); err != nil {
		temporary.Close()
		return "", fmt.Errorf("set archive object permissions: %w", err)
	}
	hash := sha256.New()
	buffer := p.getIOBuffer()
	defer p.putIOBuffer(buffer)
	if _, err := io.CopyBuffer(io.MultiWriter(temporary, hash), &contextReader{ctx: ctx, reader: source}, buffer); err != nil {
		temporary.Close()
		return "", fmt.Errorf("copy object to archive: %w", err)
	}
	if err := temporary.Sync(); err != nil {
		temporary.Close()
		return "", fmt.Errorf("sync archived object: %w", err)
	}
	if err := temporary.Close(); err != nil {
		return "", fmt.Errorf("close archived object: %w", err)
	}
	if err := os.Rename(temporaryName, destination); err != nil {
		return "", fmt.Errorf("publish archived object: %w", err)
	}
	if err := syncDirectory(filepath.Dir(destination)); err != nil {
		return "", err
	}
	return hex.EncodeToString(hash.Sum(nil)), nil
}

func writeArchiveManifestFile(path string, manifest archiveManifest) error {
	body, err := json.Marshal(manifest)
	if err != nil {
		return fmt.Errorf("encode archive manifest file: %w", err)
	}
	temporary, err := os.CreateTemp(filepath.Dir(path), ".manifest-")
	if err != nil {
		return fmt.Errorf("create archive manifest file: %w", err)
	}
	name := temporary.Name()
	defer os.Remove(name)
	if err := temporary.Chmod(0o600); err != nil {
		temporary.Close()
		return err
	}
	if _, err := temporary.Write(body); err != nil {
		temporary.Close()
		return fmt.Errorf("write archive manifest file: %w", err)
	}
	if err := temporary.Sync(); err != nil {
		temporary.Close()
		return fmt.Errorf("sync archive manifest file: %w", err)
	}
	if err := temporary.Close(); err != nil {
		return fmt.Errorf("close archive manifest file: %w", err)
	}
	if err := os.Rename(name, path); err != nil {
		return fmt.Errorf("publish archive manifest file: %w", err)
	}
	return syncDirectory(filepath.Dir(path))
}

func syncDirectory(path string) error {
	directory, err := os.Open(path)
	if err != nil {
		return fmt.Errorf("open directory for sync: %w", err)
	}
	defer directory.Close()
	if err := directory.Sync(); err != nil {
		return fmt.Errorf("sync directory: %w", err)
	}
	return nil
}

type contextReader struct {
	ctx    context.Context
	reader io.Reader
}

func (reader *contextReader) Read(destination []byte) (int, error) {
	select {
	case <-reader.ctx.Done():
		return 0, reader.ctx.Err()
	default:
		return reader.reader.Read(destination)
	}
}

func (p *Posix) resolvePhysicalObject(bucket, key, versionID string) (string, string, error) {
	if versionID == "" {
		return bucket, key, nil
	}
	currentID, err := p.meta.RetrieveAttribute(nil, bucket, key, versionIdKey)
	if errors.Is(err, meta.ErrNoSuchKey) {
		currentID = []byte(nullVersionId)
	} else if err != nil {
		return "", "", err
	}
	if string(currentID) == versionID {
		return bucket, key, nil
	}
	return filepath.Join(p.versioningDir, bucket), filepath.Join(genObjVersionKey(key), versionID), nil
}

func archiveRestoreHeader(manifest *archiveManifest, now time.Time) *string {
	if manifest == nil || manifest.RestoredUntil == nil {
		return nil
	}
	value := `ongoing-request="false", expiry-date="` + manifest.RestoredUntil.UTC().Format(http.TimeFormat) + `"`
	return &value
}

func archiveStorageClass(manifest *archiveManifest) string {
	if manifest == nil {
		return "STANDARD"
	}
	return manifest.StorageClass
}

func archiveRestored(manifest *archiveManifest, now time.Time) bool {
	return manifest != nil && manifest.RestoredUntil != nil && now.Before(*manifest.RestoredUntil)
}

func (p *Posix) ensureArchiveCopySourceAvailable(bucket, object string) error {
	manifest, err := p.loadArchiveManifest(bucket, object)
	if err != nil {
		return err
	}
	if manifest != nil && !archiveRestored(manifest, time.Now().UTC()) {
		return s3err.GetAPIError(s3err.ErrInvalidObjectState)
	}
	return nil
}

// NativeRestore stages archive bytes into an existing filesystem-managed
// offline inode. It returns the number of bytes consumed from source.
type NativeRestore func(path string, source io.Reader, size int64) (int64, error)

func (p *Posix) RestoreObject(ctx context.Context, input *s3.RestoreObjectInput) error {
	return p.RestoreLifecycleObject(ctx, input, nil)
}

// RestoreLifecycleObject restores a gateway-managed archive and optionally
// preserves the existing inode through a filesystem-native staging callback.
func (p *Posix) RestoreLifecycleObject(ctx context.Context, input *s3.RestoreObjectInput, nativeRestore NativeRestore) error {
	release, err := p.acquireActionSlot(ctx)
	if err != nil {
		return err
	}
	defer release()
	if input.Bucket == nil || input.Key == nil || input.RestoreRequest == nil || input.RestoreRequest.Days == nil || *input.RestoreRequest.Days <= 0 || input.RestoreRequest.SelectParameters != nil || input.RestoreRequest.OutputLocation != nil {
		return s3err.GetAPIError(s3err.ErrInvalidRequest)
	}
	mutationRelease, err := p.acquireObjectMutationLock(ctx, *input.Bucket, *input.Key)
	if err != nil {
		return err
	}
	defer mutationRelease()
	ctx = withObjectMutationHeld(ctx)
	if err := p.validateVersionId(stringValue(input.VersionId)); err != nil {
		return err
	}
	physicalBucket, physicalObject, err := p.resolvePhysicalObject(*input.Bucket, *input.Key, stringValue(input.VersionId))
	if err != nil {
		return err
	}
	if _, err := os.Stat(filepath.Join(physicalBucket, physicalObject)); errors.Is(err, fs.ErrNotExist) {
		if input.VersionId != nil && *input.VersionId != "" {
			return s3err.GetNoSuchVersionErr(*input.Key, *input.VersionId)
		}
		return s3err.GetAPIError(s3err.ErrNoSuchKey)
	} else if err != nil {
		return fmt.Errorf("stat object for restore: %w", err)
	}
	manifest, err := p.loadArchiveManifest(physicalBucket, physicalObject)
	if err != nil {
		return err
	}
	if manifest == nil {
		return s3err.GetAPIError(s3err.ErrInvalidObjectState)
	}
	destination, err := p.archiveDataPath(*manifest)
	if err != nil {
		return err
	}
	archiveFile, err := os.Open(destination)
	if errors.Is(err, fs.ErrNotExist) {
		return fmt.Errorf("archived object data is missing")
	}
	if err != nil {
		return fmt.Errorf("open archived object: %w", err)
	}
	defer archiveFile.Close()
	objectPath := filepath.Join(physicalBucket, physicalObject)
	info, err := os.Stat(objectPath)
	if err != nil {
		return err
	}
	expires := time.Now().UTC().Add(time.Duration(*input.RestoreRequest.Days) * 24 * time.Hour)
	manifest.RestoredUntil = &expires
	if info.IsDir() {
		return p.storeArchiveManifest(nil, physicalBucket, physicalObject, *manifest)
	}
	if nativeRestore != nil {
		hash := sha256.New()
		written, err := nativeRestore(objectPath, io.TeeReader(&contextReader{ctx: ctx, reader: archiveFile}, hash), manifest.StoredSize)
		if err != nil {
			return fmt.Errorf("stage archived object: %w", err)
		}
		if written != manifest.StoredSize || hex.EncodeToString(hash.Sum(nil)) != manifest.SHA256 {
			return fmt.Errorf("archived object checksum mismatch")
		}
		if err := p.storeArchiveManifest(nil, physicalBucket, physicalObject, *manifest); err != nil {
			return err
		}
		return os.Chtimes(objectPath, manifest.LastModified, manifest.LastModified)
	}
	temporary, err := os.CreateTemp(filepath.Dir(objectPath), ".restore-")
	if err != nil {
		return fmt.Errorf("create restore temporary object: %w", err)
	}
	temporaryName := temporary.Name()
	defer os.Remove(temporaryName)
	if err := temporary.Chmod(info.Mode().Perm()); err != nil {
		temporary.Close()
		return err
	}
	hash := sha256.New()
	buffer := p.getIOBuffer()
	defer p.putIOBuffer(buffer)
	if _, err := io.CopyBuffer(io.MultiWriter(temporary, hash), &contextReader{ctx: ctx, reader: archiveFile}, buffer); err != nil {
		temporary.Close()
		return fmt.Errorf("restore archived object: %w", err)
	}
	if hex.EncodeToString(hash.Sum(nil)) != manifest.SHA256 {
		temporary.Close()
		return fmt.Errorf("archived object checksum mismatch")
	}
	attributes, err := p.meta.ListAttributes(physicalBucket, physicalObject)
	if err != nil {
		temporary.Close()
		return fmt.Errorf("list object metadata for restore: %w", err)
	}
	for _, attribute := range attributes {
		value, err := p.meta.RetrieveAttribute(nil, physicalBucket, physicalObject, attribute)
		if err != nil {
			temporary.Close()
			return fmt.Errorf("retrieve object metadata for restore: %w", err)
		}
		if err := p.meta.StoreAttribute(temporary, physicalBucket, physicalObject, attribute, value); err != nil {
			temporary.Close()
			return fmt.Errorf("copy object metadata for restore: %w", err)
		}
	}
	if err := p.storeArchiveManifest(temporary, physicalBucket, physicalObject, *manifest); err != nil {
		temporary.Close()
		return err
	}
	if err := temporary.Sync(); err != nil {
		temporary.Close()
		return fmt.Errorf("sync restored object: %w", err)
	}
	if err := temporary.Close(); err != nil {
		return fmt.Errorf("close restored object: %w", err)
	}
	if err := os.Rename(temporaryName, objectPath); err != nil {
		return fmt.Errorf("publish restored object: %w", err)
	}
	if err := os.Chtimes(objectPath, manifest.LastModified, manifest.LastModified); err != nil {
		return fmt.Errorf("restore archived object timestamp: %w", err)
	}
	return syncDirectory(filepath.Dir(objectPath))
}

func (p *Posix) removeArchiveCopy(bucket, object string) error {
	manifest, err := p.loadArchiveManifest(bucket, object)
	if err != nil || manifest == nil {
		return err
	}
	return p.removeArchivedManifest(*manifest)
}

func (p *Posix) removeArchivedManifest(manifest archiveManifest) error {
	dataPath, err := p.archiveDataPath(manifest)
	if err != nil {
		return err
	}
	for _, path := range []string{dataPath, dataPath + ".json"} {
		if err := os.Remove(path); err != nil && !errors.Is(err, fs.ErrNotExist) {
			return fmt.Errorf("remove archived object: %w", err)
		}
	}
	return nil
}

// ListLifecycleReconciliationBuckets derives durable reconciliation work from
// the archive layout itself, so restore expiry remains automatic after the S3
// Lifecycle configuration is deleted.
func (p *Posix) ListLifecycleReconciliationBuckets(ctx context.Context) ([]string, error) {
	buckets := make(map[string]struct{})
	for _, root := range p.archiveTiers {
		entries, err := os.ReadDir(root)
		if err != nil {
			return nil, fmt.Errorf("read archive root %q: %w", root, err)
		}
		for _, entry := range entries {
			if err := ctx.Err(); err != nil {
				return nil, err
			}
			if !entry.IsDir() {
				continue
			}
			decoded, err := hex.DecodeString(entry.Name())
			if err != nil {
				continue
			}
			bucket := string(decoded)
			if !p.isBucketValid(bucket) {
				continue
			}
			info, err := os.Stat(bucket)
			if errors.Is(err, fs.ErrNotExist) {
				continue
			}
			if err != nil {
				return nil, fmt.Errorf("stat archived bucket %q: %w", bucket, err)
			}
			if info.IsDir() {
				buckets[bucket] = struct{}{}
			}
		}
	}
	result := make([]string, 0, len(buckets))
	for bucket := range buckets {
		result = append(result, bucket)
	}
	sort.Strings(result)
	return result, nil
}

// ReconcileLifecycle expires temporary restores and finishes transitions that
// published their manifest before the hot payload was released.
func (p *Posix) ReconcileLifecycle(ctx context.Context, bucket string) error {
	return p.reconcileLifecycleArchives(ctx, bucket, nil, nil, nil)
}

// ReconcileLifecycleWithNativeRelease lets filesystem backends keep their
// native offline inode while reusing the POSIX archive manifest protocol.
func (p *Posix) ReconcileLifecycleWithNativeRelease(ctx context.Context, bucket string, isOffline func(string) (bool, error), release func(string) error) error {
	return p.ReconcileLifecycleWithNativeReleaseGuard(ctx, bucket, isOffline, release, nil)
}

// ReconcileLifecycleWithNativeReleaseGuard revalidates an external leadership
// condition before every reconciliation mutation.
func (p *Posix) ReconcileLifecycleWithNativeReleaseGuard(ctx context.Context, bucket string, isOffline func(string) (bool, error), release func(string) error, guard func() error) error {
	return p.reconcileLifecycleArchives(ctx, bucket, isOffline, release, guard)
}

func (p *Posix) reconcileLifecycleArchives(ctx context.Context, bucket string, isOffline func(string) (bool, error), release func(string) error, guard func() error) error {
	roots := []string{bucket}
	if p.versioningDir != "" {
		roots = append(roots, filepath.Join(p.versioningDir, bucket))
	}
	for _, physicalBucket := range roots {
		if _, err := os.Stat(physicalBucket); errors.Is(err, fs.ErrNotExist) {
			continue
		} else if err != nil {
			return err
		}
		err := filepath.WalkDir(physicalBucket, func(path string, entry fs.DirEntry, walkErr error) error {
			if walkErr != nil {
				return walkErr
			}
			if err := ctx.Err(); err != nil {
				return err
			}
			relative, err := filepath.Rel(physicalBucket, path)
			if err != nil || relative == "." {
				return err
			}
			if entry.IsDir() && (relative == MetaTmpDir || strings.HasPrefix(relative, MetaTmpDir+string(filepath.Separator))) {
				return filepath.SkipDir
			}
			manifest, err := p.loadArchiveManifest(physicalBucket, relative)
			if err != nil {
				return err
			}
			if manifest == nil {
				return nil
			}
			now := time.Now().UTC()
			if manifest.RestoredUntil != nil && now.Before(*manifest.RestoredUntil) {
				return nil
			}
			if entry.IsDir() {
				if manifest.RestoredUntil != nil {
					if err := runLifecycleMutationGuard(guard); err != nil {
						return err
					}
					manifest.RestoredUntil = nil
					return p.storeArchiveManifest(nil, physicalBucket, relative, *manifest)
				}
				return nil
			}
			offline := false
			if isOffline != nil {
				offline, err = isOffline(path)
				if err != nil {
					return err
				}
			} else {
				info, err := entry.Info()
				if err != nil {
					return err
				}
				offline = info.Size() == 0
			}
			if !offline {
				if err := p.verifyArchivedData(ctx, *manifest); err != nil {
					return err
				}
				if err := runLifecycleMutationGuard(guard); err != nil {
					return err
				}
				if release != nil {
					if err := release(path); err != nil {
						return err
					}
				} else if err := os.Truncate(path, 0); err != nil {
					return err
				}
			}
			if err := runLifecycleMutationGuard(guard); err != nil {
				return err
			}
			if err := os.Chtimes(path, manifest.LastModified, manifest.LastModified); err != nil {
				return err
			}
			if manifest.RestoredUntil != nil {
				if err := runLifecycleMutationGuard(guard); err != nil {
					return err
				}
				manifest.RestoredUntil = nil
				return p.storeArchiveManifest(nil, physicalBucket, relative, *manifest)
			}
			return nil
		})
		if err != nil {
			return fmt.Errorf("reconcile archive tree %q: %w", physicalBucket, err)
		}
	}
	return nil
}

func (p *Posix) verifyArchivedData(ctx context.Context, manifest archiveManifest) error {
	path, err := p.archiveDataPath(manifest)
	if err != nil {
		return err
	}
	file, err := os.Open(path)
	if err != nil {
		return fmt.Errorf("open archive data for verification: %w", err)
	}
	defer file.Close()
	hash := sha256.New()
	buffer := p.getIOBuffer()
	defer p.putIOBuffer(buffer)
	written, err := io.CopyBuffer(hash, &contextReader{ctx: ctx, reader: file}, buffer)
	if err != nil {
		return fmt.Errorf("verify archive data: %w", err)
	}
	if written != manifest.StoredSize || hex.EncodeToString(hash.Sum(nil)) != manifest.SHA256 {
		return fmt.Errorf("archive data verification failed")
	}
	return nil
}

func archiveObjectStorageClass(manifest *archiveManifest) types.ObjectStorageClass {
	return types.ObjectStorageClass(archiveStorageClass(manifest))
}

func archiveObjectVersionStorageClass(manifest *archiveManifest) types.ObjectVersionStorageClass {
	return types.ObjectVersionStorageClass(archiveStorageClass(manifest))
}

func archiveRestoreStatus(manifest *archiveManifest) *types.RestoreStatus {
	if manifest == nil || manifest.RestoredUntil == nil {
		return nil
	}
	inProgress := false
	return &types.RestoreStatus{IsRestoreInProgress: &inProgress, RestoreExpiryDate: manifest.RestoredUntil}
}
