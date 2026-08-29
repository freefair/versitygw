// Copyright 2026 Versity Software
// This file is licensed under the Apache License, Version 2.0.

package posix

import (
	"context"
	"errors"
	"fmt"
	"io/fs"
	"os"

	"github.com/versity/versitygw/backend/meta"
	"github.com/versity/versitygw/internal/lifecycle"
	"github.com/versity/versitygw/s3err"
)

func (p *Posix) LifecycleCapabilities() lifecycle.Capabilities {
	if len(p.archiveTiers) == 0 {
		return lifecycle.Capabilities{}
	}
	transitions := make(map[string]bool, len(p.archiveTiers))
	for storageClass := range p.archiveTiers {
		transitions[storageClass] = true
	}
	return lifecycle.Capabilities{Transitions: transitions}
}

func (p *Posix) PutLifecycleConfiguration(ctx context.Context, bucket string, configuration lifecycle.Configuration) error {
	release, err := p.acquireActionSlot(ctx)
	if err != nil {
		return err
	}
	defer release()

	if err := p.requireLifecycleBucket(bucket); err != nil {
		return err
	}
	body, err := lifecycle.MarshalStored(configuration)
	if err != nil {
		return err
	}
	if err := p.meta.StoreAttribute(nil, bucket, "", lifecyclekey, body); err != nil {
		return fmt.Errorf("store lifecycle configuration: %w", err)
	}
	return nil
}

func (p *Posix) GetLifecycleConfiguration(ctx context.Context, bucket string) (lifecycle.Configuration, error) {
	release, err := p.acquireActionSlot(ctx)
	if err != nil {
		return lifecycle.Configuration{}, err
	}
	defer release()

	if err := p.requireLifecycleBucket(bucket); err != nil {
		return lifecycle.Configuration{}, err
	}
	body, err := p.meta.RetrieveAttribute(nil, bucket, "", lifecyclekey)
	if errors.Is(err, meta.ErrNoSuchKey) {
		return lifecycle.Configuration{}, s3err.GetAPIError(s3err.ErrNoSuchLifecycleConfiguration)
	}
	if err != nil {
		return lifecycle.Configuration{}, fmt.Errorf("retrieve lifecycle configuration: %w", err)
	}
	configuration, err := lifecycle.ParseStored(body, p.LifecycleCapabilities())
	if err != nil {
		return lifecycle.Configuration{}, fmt.Errorf("parse stored lifecycle configuration: %w", err)
	}
	return configuration, nil
}

func (p *Posix) DeleteLifecycleConfiguration(ctx context.Context, bucket string) error {
	release, err := p.acquireActionSlot(ctx)
	if err != nil {
		return err
	}
	defer release()

	if err := p.requireLifecycleBucket(bucket); err != nil {
		return err
	}
	err = p.meta.DeleteAttribute(bucket, "", lifecyclekey)
	if errors.Is(err, meta.ErrNoSuchKey) {
		return nil
	}
	if err != nil {
		return fmt.Errorf("delete lifecycle configuration: %w", err)
	}
	return nil
}

func (p *Posix) requireLifecycleBucket(bucket string) error {
	if !p.isBucketValid(bucket) {
		return s3err.GetBucketErr(s3err.ErrInvalidBucketName, bucket)
	}
	_, err := os.Stat(bucket)
	if errors.Is(err, fs.ErrNotExist) {
		return s3err.GetBucketErr(s3err.ErrNoSuchBucket, bucket)
	}
	if err != nil {
		return fmt.Errorf("stat bucket: %w", err)
	}
	return nil
}
