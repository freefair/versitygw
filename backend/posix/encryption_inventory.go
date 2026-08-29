// Copyright 2026 Versity Software
// This file is licensed under the Apache License, Version 2.0.

package posix

import (
	"context"
	"crypto/sha256"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"sort"

	"github.com/aws/aws-sdk-go-v2/service/s3"
	"github.com/versity/versitygw/backend/meta"
	"github.com/versity/versitygw/internal/encryption"
)

func (p *Posix) AuditEncryption(ctx context.Context) (encryption.Inventory, error) {
	inventory := encryption.NewInventory()
	providers := p.encryptionProviderMap()
	for name, provider := range providers {
		if referencer, ok := provider.(encryption.ActiveKeyReferencer); ok {
			inventory.ActiveKeyReferences[name] = referencer.ActiveKeyReference()
		}
	}
	entries, err := os.ReadDir(".")
	if err != nil {
		return inventory, fmt.Errorf("read backend root for encryption inventory: %w", err)
	}
	buckets := make([]string, 0, len(entries))
	for _, entry := range entries {
		if (entry.IsDir() || entry.Type()&fs.ModeSymlink != 0) && p.isBucketValid(entry.Name()) {
			buckets = append(buckets, entry.Name())
		}
	}
	sort.Strings(buckets)
	for _, bucket := range buckets {
		if err := ctx.Err(); err != nil {
			return inventory, err
		}
		inventory.Buckets++
		if err := p.auditBucketEncryption(ctx, bucket, providers, &inventory); err != nil {
			return inventory, err
		}
	}
	return inventory, nil
}

func (p *Posix) auditBucketEncryption(ctx context.Context, bucket string, providers encryption.ProviderMap, inventory *encryption.Inventory) error {
	maxKeys := int32(1000)
	var keyMarker, versionMarker string
	for {
		result, err := p.ListObjectVersions(withCtxNoSlot(ctx), &s3.ListObjectVersionsInput{
			Bucket: &bucket, KeyMarker: &keyMarker, VersionIdMarker: &versionMarker, MaxKeys: &maxKeys,
		})
		if err != nil {
			return fmt.Errorf("list object versions for encryption inventory: %w", err)
		}
		for _, version := range result.Versions {
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
			inventory.Objects++
			if err := p.auditEncryptedPath(ctx, physicalBucket, physicalObject, providers, inventory); err != nil {
				return err
			}
		}
		if result.IsTruncated == nil || !*result.IsTruncated {
			break
		}
		keyMarker = stringValue(result.NextKeyMarker)
		versionMarker = stringValue(result.NextVersionIdMarker)
	}

	var uploadKeyMarker, uploadIDMarker string
	for {
		result, err := p.ListMultipartUploads(withCtxNoSlot(ctx), &s3.ListMultipartUploadsInput{
			Bucket: &bucket, KeyMarker: &uploadKeyMarker, UploadIdMarker: &uploadIDMarker, MaxUploads: &maxKeys,
		})
		if err != nil {
			return fmt.Errorf("list multipart uploads for encryption inventory: %w", err)
		}
		for _, upload := range result.Uploads {
			digest := sha256.Sum256([]byte(upload.Key))
			uploadPath := filepath.Join(MetaTmpMultipartDir, fmt.Sprintf("%x", digest), upload.UploadID)
			parts, err := os.ReadDir(filepath.Join(bucket, uploadPath))
			if errors.Is(err, fs.ErrNotExist) {
				continue
			}
			if err != nil {
				return fmt.Errorf("read multipart parts for encryption inventory: %w", err)
			}
			for _, part := range parts {
				if part.IsDir() {
					continue
				}
				inventory.MultipartParts++
				if err := p.auditEncryptedPath(ctx, bucket, filepath.Join(uploadPath, part.Name()), providers, inventory); err != nil {
					return err
				}
			}
		}
		if !result.IsTruncated {
			break
		}
		uploadKeyMarker, uploadIDMarker = result.NextKeyMarker, result.NextUploadIDMarker
	}
	return nil
}

func (p *Posix) auditEncryptedPath(ctx context.Context, physicalBucket, physicalObject string, providers encryption.ProviderMap, inventory *encryption.Inventory) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	path := filepath.Join(physicalBucket, physicalObject)
	manifest, err := p.loadArchiveManifest(physicalBucket, physicalObject)
	if err != nil {
		inventory.InvalidContainers++
		return nil
	}
	if manifest != nil {
		path, err = p.archiveDataPath(*manifest)
		if err != nil {
			inventory.InvalidContainers++
			return nil
		}
	}
	file, err := os.Open(path)
	if errors.Is(err, fs.ErrNotExist) {
		inventory.InvalidContainers++
		return nil
	}
	if err != nil {
		return fmt.Errorf("open object for encryption inventory: %w", err)
	}
	defer file.Close()
	info, err := file.Stat()
	if err != nil {
		return fmt.Errorf("stat object for encryption inventory: %w", err)
	}
	_, metadataErr := p.meta.RetrieveAttribute(nil, physicalBucket, physicalObject, encryptionResultKey)
	hasEncryptionMetadata := metadataErr == nil
	if metadataErr != nil && !errors.Is(metadataErr, meta.ErrNoSuchKey) && !errors.Is(metadataErr, fs.ErrNotExist) {
		return fmt.Errorf("read encryption metadata for inventory: %w", metadataErr)
	}
	isContainer, err := encryption.IsContainer(file)
	if err != nil {
		return fmt.Errorf("inspect object for encryption inventory: %w", err)
	}
	if !isContainer {
		if hasEncryptionMetadata {
			inventory.InvalidContainers++
			return nil
		}
		inventory.PlaintextLegacy++
		return nil
	}
	containerInfo, err := encryption.Inspect(file, info.Size())
	if err != nil {
		if hasEncryptionMetadata {
			inventory.InvalidContainers++
		} else {
			inventory.PlaintextLegacy++
		}
		return nil
	}
	inventory.Encrypted++
	inventory.FormatVersions[containerInfo.FormatVersion]++
	missing := false
	for _, reference := range containerInfo.KeyReferences {
		if reference.Provider == "sse-c" {
			continue
		}
		provider := providers[reference.Provider]
		if provider != nil && provider.ValidateKeyReference(reference.KeyID) == nil {
			continue
		}
		missing = true
		inventory.MissingKeyReferences[reference.Provider+":"+reference.KeyID]++
	}
	if missing {
		inventory.MissingKeyObjects++
	}
	return nil
}

func (p *Posix) encryptionProviderMap() encryption.ProviderMap {
	providers := encryption.ProviderMap{}
	for _, provider := range []encryption.KeyProvider{p.encryptionProvider, p.managedEncryptionProvider, p.dsseEncryptionProvider} {
		if provider != nil {
			providers[provider.Name()] = provider
		}
	}
	return providers
}
