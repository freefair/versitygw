// Copyright 2026 Versity Software
// This file is licensed under the Apache License, Version 2.0.

package posix

import (
	"context"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"strconv"

	"github.com/aws/aws-sdk-go-v2/service/s3"
	"github.com/versity/versitygw/backend/meta"
	"github.com/versity/versitygw/internal/encryption"
)

type encryptionObject struct {
	logicalBucket  string
	logicalKey     string
	versionID      string
	uploadID       string
	partNumber     int32
	physicalBucket string
	physicalObject string
}

func (object encryptionObject) identity() encryption.Identity {
	if object.uploadID != "" {
		return multipartPartIdentity(object.logicalBucket, object.logicalKey, object.uploadID, object.partNumber)
	}
	versionID := object.versionID
	if versionID == "" {
		versionID = nullVersionId
	}
	return encryption.Identity{Bucket: object.logicalBucket, Key: object.logicalKey, VersionID: versionID}
}

func (p *Posix) RewrapEncryption(ctx context.Context, dryRun bool) (encryption.MaintenanceResult, error) {
	return p.maintainEncryption(ctx, dryRun, true, p.rewrapEncryptionObject)
}

func (p *Posix) ReencryptLegacy(ctx context.Context, dryRun bool) (encryption.MaintenanceResult, error) {
	if p.managedEncryptionProvider == nil {
		return encryption.MaintenanceResult{}, encryption.ErrUnsupportedEncryption
	}
	return p.maintainEncryption(ctx, dryRun, false, p.reencryptLegacyObject)
}

func (p *Posix) maintainEncryption(ctx context.Context, dryRun, includeMultipart bool, operation func(context.Context, encryptionObject, bool) (bool, error)) (encryption.MaintenanceResult, error) {
	result := encryption.MaintenanceResult{}
	err := p.walkEncryptionObjects(ctx, includeMultipart, func(object encryptionObject) error {
		result.Scanned++
		changed, err := operation(ctx, object, dryRun)
		if err != nil {
			result.Failed++
			return err
		}
		if changed {
			result.Changed++
		} else {
			result.Skipped++
		}
		return nil
	})
	return result, err
}

func (p *Posix) walkEncryptionObjects(ctx context.Context, includeMultipart bool, visit func(encryptionObject) error) error {
	entries, err := os.ReadDir(".")
	if err != nil {
		return fmt.Errorf("read backend root for encryption maintenance: %w", err)
	}
	maxKeys := int32(1000)
	for _, entry := range entries {
		if (!entry.IsDir() && entry.Type()&fs.ModeSymlink == 0) || !p.isBucketValid(entry.Name()) {
			continue
		}
		bucket := entry.Name()
		var keyMarker, versionMarker string
		for {
			if err := ctx.Err(); err != nil {
				return err
			}
			versions, err := p.ListObjectVersions(withCtxNoSlot(ctx), &s3.ListObjectVersionsInput{
				Bucket: &bucket, KeyMarker: &keyMarker, VersionIdMarker: &versionMarker, MaxKeys: &maxKeys,
			})
			if err != nil {
				return fmt.Errorf("list object versions for encryption maintenance: %w", err)
			}
			for _, version := range versions.Versions {
				if version.Key == nil {
					continue
				}
				versionID := stringValue(version.VersionId)
				physicalBucket, physicalObject, err := p.resolvePhysicalObject(bucket, *version.Key, versionID)
				if errors.Is(err, fs.ErrNotExist) {
					continue
				}
				if err != nil {
					return err
				}
				object := encryptionObject{
					logicalBucket: bucket, logicalKey: *version.Key, versionID: versionID,
					physicalBucket: physicalBucket, physicalObject: physicalObject,
				}
				release, err := p.acquireObjectMutationLock(ctx, bucket, *version.Key)
				if err != nil {
					return err
				}
				currentBucket, currentObject, resolveErr := p.resolvePhysicalObject(bucket, *version.Key, versionID)
				if errors.Is(resolveErr, fs.ErrNotExist) || currentBucket != physicalBucket || currentObject != physicalObject {
					release()
					continue
				}
				if resolveErr != nil {
					release()
					return resolveErr
				}
				err = visit(object)
				release()
				if err != nil {
					return fmt.Errorf("maintain encryption for %s version %q: %w", *version.Key, versionID, err)
				}
			}
			if versions.IsTruncated == nil || !*versions.IsTruncated {
				break
			}
			keyMarker = stringValue(versions.NextKeyMarker)
			versionMarker = stringValue(versions.NextVersionIdMarker)
		}
		if includeMultipart {
			if err := p.walkEncryptionMultipartParts(ctx, bucket, visit); err != nil {
				return err
			}
		}
	}
	return nil
}

func (p *Posix) walkEncryptionMultipartParts(ctx context.Context, bucket string, visit func(encryptionObject) error) error {
	maxUploads := int32(1000)
	var keyMarker, uploadIDMarker string
	for {
		result, err := p.ListMultipartUploads(withCtxNoSlot(ctx), &s3.ListMultipartUploadsInput{
			Bucket: &bucket, KeyMarker: &keyMarker, UploadIdMarker: &uploadIDMarker, MaxUploads: &maxUploads,
		})
		if err != nil {
			return fmt.Errorf("list multipart uploads for encryption maintenance: %w", err)
		}
		for _, upload := range result.Uploads {
			digest := sha256.Sum256([]byte(upload.Key))
			uploadPath := filepath.Join(MetaTmpMultipartDir, fmt.Sprintf("%x", digest), upload.UploadID)
			parts, err := os.ReadDir(filepath.Join(bucket, uploadPath))
			if errors.Is(err, fs.ErrNotExist) {
				continue
			}
			if err != nil {
				return fmt.Errorf("read multipart parts for encryption maintenance: %w", err)
			}
			for _, part := range parts {
				if part.IsDir() {
					continue
				}
				partNumber64, err := strconv.ParseInt(part.Name(), 10, 32)
				if err != nil || partNumber64 <= 0 {
					continue
				}
				partNumber := int32(partNumber64)
				object := encryptionObject{
					logicalBucket: bucket, logicalKey: upload.Key, uploadID: upload.UploadID, partNumber: partNumber,
					physicalBucket: bucket, physicalObject: filepath.Join(uploadPath, part.Name()),
				}
				release, err := p.acquireObjectMutationLock(ctx, bucket, upload.Key)
				if err != nil {
					return err
				}
				err = visit(object)
				release()
				if err != nil {
					return fmt.Errorf("maintain encryption for multipart upload %q part %d: %w", upload.UploadID, partNumber, err)
				}
			}
		}
		if !result.IsTruncated {
			return nil
		}
		keyMarker, uploadIDMarker = result.NextKeyMarker, result.NextUploadIDMarker
	}
}

func (p *Posix) rewrapEncryptionObject(ctx context.Context, object encryptionObject, dryRun bool) (bool, error) {
	path, source, info, containerInfo, encrypted, err := p.openMaintenanceObject(object)
	if err != nil {
		return false, err
	}
	if source != nil {
		defer source.Close()
	}
	if !encrypted || containerInfo.Mode == encryption.ModeSSEC {
		return false, nil
	}
	if dryRun {
		return true, nil
	}
	snapshot, err := p.snapshotMaintenanceObject(path, source, object)
	if err != nil {
		return false, err
	}
	err = p.replaceObjectFile(path, source, info, object, func(destination io.Writer) error {
		_, err := encryption.Rewrap(ctx, destination, source, info.Size(), object.identity(), p.encryptionProviderMap())
		return err
	})
	if err != nil {
		return false, err
	}
	if err := p.refreshMaintainedEncryptionMetadata(path, object); err != nil {
		if rollbackErr := p.rollbackMaintenanceObject(path, source, info, object, snapshot); rollbackErr != nil {
			return false, fmt.Errorf("refresh maintained encryption metadata: %w (rollback failed: %v)", err, rollbackErr)
		}
		return false, err
	}
	return true, nil
}

func (p *Posix) reencryptLegacyObject(ctx context.Context, object encryptionObject, dryRun bool) (bool, error) {
	path, source, info, _, encrypted, err := p.openMaintenanceObject(object)
	if err != nil {
		return false, err
	}
	if source != nil {
		defer source.Close()
	}
	if encrypted {
		return false, nil
	}
	if _, metadataErr := p.meta.RetrieveAttribute(source, object.physicalBucket, object.physicalObject, encryptionResultKey); metadataErr == nil {
		return false, nil
	} else if !errors.Is(metadataErr, meta.ErrNoSuchKey) && !errors.Is(metadataErr, fs.ErrNotExist) {
		return false, metadataErr
	}
	if info.IsDir() {
		return false, nil
	}
	if dryRun {
		return true, nil
	}
	snapshot, err := p.snapshotMaintenanceObject(path, source, object)
	if err != nil {
		return false, err
	}
	layers, err := p.encryptionLayers(&encryption.Intent{Mode: encryption.ModeSSES3})
	if err != nil {
		return false, err
	}
	err = p.replaceObjectFile(path, source, info, object, func(destination io.Writer) error {
		writer, err := encryption.NewWriter(ctx, destination, encryption.WriterOptions{
			Identity: object.identity(), Mode: encryption.ModeSSES3, PlaintextSize: info.Size(), Layers: layers,
		})
		if err != nil {
			return err
		}
		if _, err := io.Copy(writer, source); err != nil {
			_ = writer.Close()
			return err
		}
		return writer.Close()
	})
	if err != nil {
		return false, err
	}
	if err := p.refreshMaintainedEncryptionMetadata(path, object); err != nil {
		if rollbackErr := p.rollbackMaintenanceObject(path, source, info, object, snapshot); rollbackErr != nil {
			return false, fmt.Errorf("refresh maintained encryption metadata: %w (rollback failed: %v)", err, rollbackErr)
		}
		return false, err
	}
	return true, nil
}

type maintenanceObjectSnapshot struct {
	attributes       map[string][]byte
	externalManifest *archiveManifest
}

func (p *Posix) snapshotMaintenanceObject(path string, source *os.File, object encryptionObject) (maintenanceObjectSnapshot, error) {
	attributes, err := p.meta.ListAttributes(object.physicalBucket, object.physicalObject)
	if err != nil {
		return maintenanceObjectSnapshot{}, err
	}
	snapshot := maintenanceObjectSnapshot{attributes: make(map[string][]byte, len(attributes))}
	for _, attribute := range attributes {
		value, err := p.meta.RetrieveAttribute(source, object.physicalBucket, object.physicalObject, attribute)
		if err != nil {
			return maintenanceObjectSnapshot{}, err
		}
		snapshot.attributes[attribute] = append([]byte(nil), value...)
	}
	manifestBody, err := os.ReadFile(path + ".json")
	if err == nil {
		var manifest archiveManifest
		if err := json.Unmarshal(manifestBody, &manifest); err != nil {
			return maintenanceObjectSnapshot{}, fmt.Errorf("parse external archive manifest snapshot: %w", err)
		}
		snapshot.externalManifest = &manifest
	} else if !errors.Is(err, fs.ErrNotExist) {
		return maintenanceObjectSnapshot{}, fmt.Errorf("read external archive manifest snapshot: %w", err)
	}
	return snapshot, nil
}

func (p *Posix) rollbackMaintenanceObject(path string, source *os.File, info os.FileInfo, object encryptionObject, snapshot maintenanceObjectSnapshot) error {
	if _, err := source.Seek(0, io.SeekStart); err != nil {
		return fmt.Errorf("rewind previous maintained object: %w", err)
	}
	temporary, err := os.CreateTemp(filepath.Dir(path), ".versitygw-encryption-rollback-")
	if err != nil {
		return err
	}
	temporaryPath := temporary.Name()
	defer func() {
		_ = temporary.Close()
		_ = os.Remove(temporaryPath)
	}()
	if err := temporary.Chmod(info.Mode().Perm()); err != nil {
		return err
	}
	if _, err := io.Copy(temporary, source); err != nil {
		return err
	}
	if err := temporary.Sync(); err != nil {
		return err
	}
	if err := os.Chtimes(temporaryPath, info.ModTime(), info.ModTime()); err != nil {
		return err
	}
	if err := temporary.Close(); err != nil {
		return err
	}
	if err := os.Rename(temporaryPath, path); err != nil {
		return err
	}
	restored, err := os.Open(path)
	if err != nil {
		return err
	}
	defer restored.Close()
	currentAttributes, err := p.meta.ListAttributes(object.physicalBucket, object.physicalObject)
	if err != nil {
		return err
	}
	for _, attribute := range currentAttributes {
		if _, ok := snapshot.attributes[attribute]; !ok {
			if err := p.meta.DeleteAttribute(object.physicalBucket, object.physicalObject, attribute); err != nil && !errors.Is(err, meta.ErrNoSuchKey) {
				return err
			}
		}
	}
	for attribute, value := range snapshot.attributes {
		if err := p.meta.StoreAttribute(restored, object.physicalBucket, object.physicalObject, attribute, value); err != nil {
			return err
		}
	}
	if snapshot.externalManifest != nil {
		if err := writeArchiveManifestFile(path+".json", *snapshot.externalManifest); err != nil {
			return err
		}
	} else if err := os.Remove(path + ".json"); err != nil && !errors.Is(err, fs.ErrNotExist) {
		return err
	}
	directory, err := os.Open(filepath.Dir(path))
	if err != nil {
		return err
	}
	defer directory.Close()
	return directory.Sync()
}

func (p *Posix) refreshMaintainedEncryptionMetadata(path string, object encryptionObject) error {
	file, err := os.Open(path)
	if err != nil {
		return fmt.Errorf("open maintained encrypted object: %w", err)
	}
	defer file.Close()
	info, err := file.Stat()
	if err != nil {
		return fmt.Errorf("stat maintained encrypted object: %w", err)
	}
	containerInfo, err := encryption.Inspect(file, info.Size())
	if err != nil {
		return fmt.Errorf("inspect maintained encrypted object: %w", err)
	}
	result := encryptionResultFromContainerInfo(containerInfo)
	if object.uploadID == "" {
		if err := p.meta.StoreAttribute(nil, object.physicalBucket, object.physicalObject, encryptionPlainSizeKey, []byte(strconv.FormatInt(containerInfo.PlaintextSize, 10))); err != nil {
			return fmt.Errorf("store maintained plaintext size: %w", err)
		}
		if err := p.storeObjectEncryption(nil, object.physicalBucket, object.physicalObject, result); err != nil {
			return err
		}
	}

	manifest, err := p.loadArchiveManifest(object.physicalBucket, object.physicalObject)
	if err != nil || manifest == nil {
		return err
	}
	hash := sha256.New()
	if _, err := io.Copy(hash, file); err != nil {
		return fmt.Errorf("hash maintained archive object: %w", err)
	}
	previous := *manifest
	manifest.StoredSize = info.Size()
	manifest.PlaintextSize = containerInfo.PlaintextSize
	manifest.SHA256 = fmt.Sprintf("%x", hash.Sum(nil))
	manifest.Encryption = result
	if err := writeArchiveManifestFile(path+".json", *manifest); err != nil {
		return err
	}
	if err := p.storeArchiveManifest(nil, object.physicalBucket, object.physicalObject, *manifest); err != nil {
		if rollbackErr := writeArchiveManifestFile(path+".json", previous); rollbackErr != nil {
			return fmt.Errorf("store maintained archive manifest: %w (external manifest rollback failed: %v)", err, rollbackErr)
		}
		return err
	}
	return nil
}

func encryptionResultFromContainerInfo(info encryption.ContainerInfo) *encryption.Result {
	result := &encryption.Result{Mode: info.Mode, BucketKeyEnabled: info.BucketKeyEnabled}
	if (info.Mode == encryption.ModeSSEKMS || info.Mode == encryption.ModeDSSEKMS) && len(info.KeyReferences) != 0 {
		result.KMSKeyID = info.KeyReferences[0].KeyID
	}
	return result
}

func (p *Posix) openMaintenanceObject(object encryptionObject) (string, *os.File, os.FileInfo, encryption.ContainerInfo, bool, error) {
	path := filepath.Join(object.physicalBucket, object.physicalObject)
	manifest, err := p.loadArchiveManifest(object.physicalBucket, object.physicalObject)
	if err != nil {
		return "", nil, nil, encryption.ContainerInfo{}, false, err
	}
	if manifest != nil {
		path, err = p.archiveDataPath(*manifest)
		if err != nil {
			return "", nil, nil, encryption.ContainerInfo{}, false, err
		}
	}
	lstat, err := os.Lstat(path)
	if err != nil {
		return "", nil, nil, encryption.ContainerInfo{}, false, err
	}
	if !lstat.Mode().IsRegular() {
		return path, nil, lstat, encryption.ContainerInfo{}, false, nil
	}
	source, err := os.Open(path)
	if err != nil {
		return "", nil, nil, encryption.ContainerInfo{}, false, err
	}
	info, err := source.Stat()
	if err != nil || !os.SameFile(lstat, info) {
		source.Close()
		if err != nil {
			return "", nil, nil, encryption.ContainerInfo{}, false, err
		}
		return "", nil, nil, encryption.ContainerInfo{}, false, encryption.ErrInvalidContainer
	}
	_, metadataErr := p.meta.RetrieveAttribute(source, object.physicalBucket, object.physicalObject, encryptionResultKey)
	hasEncryptionMetadata := metadataErr == nil
	if metadataErr != nil && !errors.Is(metadataErr, meta.ErrNoSuchKey) && !errors.Is(metadataErr, fs.ErrNotExist) {
		return "", nil, nil, encryption.ContainerInfo{}, false, metadataErr
	}
	isContainer, err := encryption.IsContainer(source)
	if err != nil || !isContainer {
		if !isContainer && hasEncryptionMetadata && err == nil {
			err = encryption.ErrInvalidContainer
		}
		return path, source, info, encryption.ContainerInfo{}, false, err
	}
	containerInfo, err := encryption.Inspect(source, info.Size())
	if errors.Is(err, encryption.ErrInvalidContainer) && !hasEncryptionMetadata {
		return path, source, info, encryption.ContainerInfo{}, false, nil
	}
	return path, source, info, containerInfo, true, err
}

func (p *Posix) replaceObjectFile(path string, source *os.File, info os.FileInfo, object encryptionObject, write func(io.Writer) error) (returnErr error) {
	temporary, err := os.CreateTemp(filepath.Dir(path), ".versitygw-encryption-")
	if err != nil {
		return err
	}
	temporaryPath := temporary.Name()
	defer func() {
		_ = temporary.Close()
		if returnErr != nil {
			_ = os.Remove(temporaryPath)
		}
	}()
	if err := temporary.Chmod(info.Mode().Perm()); err != nil {
		return err
	}
	if err := write(temporary); err != nil {
		return err
	}
	attributes, err := p.meta.ListAttributes(object.physicalBucket, object.physicalObject)
	if err != nil {
		return err
	}
	for _, attribute := range attributes {
		value, err := p.meta.RetrieveAttribute(source, object.physicalBucket, object.physicalObject, attribute)
		if err != nil {
			return err
		}
		if err := p.meta.StoreAttribute(temporary, object.physicalBucket, object.physicalObject, attribute, value); err != nil {
			return err
		}
	}
	if err := temporary.Sync(); err != nil {
		return err
	}
	if err := os.Chtimes(temporaryPath, info.ModTime(), info.ModTime()); err != nil {
		return err
	}
	if err := temporary.Close(); err != nil {
		return err
	}
	currentInfo, err := os.Lstat(path)
	if err != nil || !os.SameFile(info, currentInfo) {
		if err != nil {
			return err
		}
		return encryption.ErrIdentityMismatch
	}
	if err := os.Rename(temporaryPath, path); err != nil {
		return err
	}
	directory, err := os.Open(filepath.Dir(path))
	if err != nil {
		return err
	}
	defer directory.Close()
	return directory.Sync()
}
