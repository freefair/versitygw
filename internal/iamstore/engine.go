// Copyright 2026 Versity Software
// This file is licensed under the Apache License, Version 2.0
// (the "License"); you may not use this file except in compliance
// with the License.  You may obtain a copy of the License at
//
//   http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing,
// software distributed under the License is distributed on an
// "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
// KIND, either express or implied.  See the License for the
// specific language governing permissions and limitations
// under the License.

package iamstore

import (
	"context"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"sync"
	"time"
)

const (
	iamMode  = 0600
	backoff  = 100 * time.Millisecond
	maxretry = 300
)

var (
	// ErrPlaintextStore reports a plaintext store file where the operator
	// required encryption.
	ErrPlaintextStore = errors.New("iam store is not encrypted")
	// ErrMissingProtector reports an encrypted store file that cannot be
	// opened because no encryption key is configured.
	ErrMissingProtector = errors.New("iam store is encrypted but no encryption key is configured")
)

// UpdateFunc accepts the current JSON data and returns the new JSON data to store.
type UpdateFunc func([]byte) ([]byte, error)

type NormalizeFunc[T any] func(*T)

// Options selects how the engine represents the store on disk.
type Options struct {
	// Protector encrypts store files the engine creates and opens encrypted
	// ones. Nil keeps the historical plaintext format.
	Protector *Protector
	// RequireEncryption refuses to read a plaintext store file instead of
	// warning about it.
	RequireEncryption bool
}

type Engine[T any] struct {
	dir               string
	iamFile           string
	iamBackupFile     string
	defaultConfig     T
	normalize         NormalizeFunc[T]
	protector         *Protector
	requireEncryption bool

	// cache holds the decrypted store so the authentication path does not
	// decrypt the file per request.
	cache struct {
		sync.RWMutex
		// digest identifies the stored bytes the plaintext came from.
		digest [sha256.Size]byte
		// validated is when the cache was last checked against the file.
		validated time.Time
		plaintext []byte
		valid     bool
	}
}

// cacheValidity bounds how long a request may be served without reading the
// store file. Reads within the window come straight from memory; after it the
// file is read again, but decrypted only when its bytes actually changed. The
// window has to stay short because a shared IAM directory has no other
// coordination between gateways, and because on NFS only an open() forces the
// client to revalidate what a stat() may answer from its attribute cache.
const cacheValidity = time.Second

func New[T any](dir, iamFile, iamBackupFile string, defaultConfig T, normalize NormalizeFunc[T]) (*Engine[T], error) {
	return NewWithOptions(dir, iamFile, iamBackupFile, defaultConfig, normalize, Options{})
}

func NewWithOptions[T any](dir, iamFile, iamBackupFile string, defaultConfig T, normalize NormalizeFunc[T], opts Options) (*Engine[T], error) {
	engine := &Engine[T]{
		dir:               dir,
		iamFile:           iamFile,
		iamBackupFile:     iamBackupFile,
		defaultConfig:     defaultConfig,
		normalize:         normalize,
		protector:         opts.Protector,
		requireEncryption: opts.RequireEncryption,
	}

	if err := engine.InitIAM(); err != nil {
		return nil, err
	}

	return engine, nil
}

func (e *Engine[T]) InitIAM() error {
	fname := filepath.Join(e.dir, e.iamFile)

	raw, err := os.ReadFile(fname)
	if errors.Is(err, fs.ErrNotExist) {
		b, err := json.Marshal(e.defaultConfig)
		if err != nil {
			return fmt.Errorf("marshal default iam: %w", err)
		}
		// A store created here is encrypted from its first byte whenever a
		// key is configured. An existing plaintext store is migrated
		// deliberately with the CLI instead, because the first encrypted
		// write makes the file unreadable for gateways without the key.
		out, err := e.encode(b, e.protector != nil)
		if err != nil {
			return fmt.Errorf("encrypt default iam: %w", err)
		}
		if err := os.WriteFile(fname, out, iamMode); err != nil {
			return fmt.Errorf("write default iam: %w", err)
		}
		return nil
	}
	if err != nil {
		return fmt.Errorf("read iam file: %w", err)
	}

	return e.reportFormat(raw, fname)
}

// reportFormat validates the stored format against the configured encryption
// once at startup, where the operator can still act on it.
func (e *Engine[T]) reportFormat(raw []byte, fname string) error {
	if IsEncrypted(raw) {
		if e.protector == nil {
			return fmt.Errorf("%w: %s", ErrMissingProtector, fname)
		}
		return nil
	}
	if e.requireEncryption {
		return fmt.Errorf("%w: %s", ErrPlaintextStore, fname)
	}
	if e.protector != nil {
		fmt.Fprintf(os.Stderr,
			"WARNING: %s holds credentials in plaintext; encrypt it with \"versitygw utils iam-encryption encrypt\"\n",
			fname)
	}
	return nil
}

func (e *Engine[T]) GetIAM() (T, error) {
	b, err := e.ReadIAMData()
	if err != nil {
		var zero T
		return zero, err
	}

	return e.ParseIAM(b)
}

func (e *Engine[T]) ParseIAM(b []byte) (T, error) {
	return ParseIAM(b, e.normalize)
}

func ParseIAM[T any](b []byte, normalize NormalizeFunc[T]) (T, error) {
	var conf T
	if err := json.Unmarshal(b, &conf); err != nil {
		return conf, fmt.Errorf("failed to parse the config file: %w", err)
	}

	if normalize != nil {
		normalize(&conf)
	}

	return conf, nil
}

func (e *Engine[T]) ReadIAMData() ([]byte, error) {
	// We are going to be racing with other running gateways without any
	// coordination. So we might find the file does not exist at times.
	// For this case we need to retry for a while assuming the other gateway
	// will eventually write the file. If it doesn't after the max retries,
	// then we will return the error.

	fname := filepath.Join(e.dir, e.iamFile)
	retries := 0

	for {
		if plaintext, ok := e.cachedPlaintext(); ok {
			return plaintext, nil
		}

		raw, err := os.ReadFile(fname)
		if errors.Is(err, fs.ErrNotExist) {
			// racing with someone else updating
			// keep retrying after backoff
			retries++
			if retries < maxretry {
				time.Sleep(backoff)
				continue
			}
			return nil, fmt.Errorf("read iam file: %w", err)
		}
		if err != nil {
			return nil, err
		}

		// Unchanged bytes revalidate the cached plaintext instead of
		// decrypting again, so an idle gateway makes no key provider call
		// however often it authenticates.
		digest := sha256.Sum256(raw)
		if plaintext, ok := e.revalidate(digest); ok {
			return plaintext, nil
		}

		plaintext, err := e.decode(raw)
		if err != nil {
			return nil, err
		}
		e.cachePlaintext(digest, plaintext)

		return append([]byte(nil), plaintext...), nil
	}
}

func (e *Engine[T]) StoreIAM(update UpdateFunc) error {
	// We are going to be racing with other running gateways without any
	// coordination. So the strategy here is to read the current file data,
	// update the data, write back out to a temp file, then rename the
	// temp file to the original file. This rename will replace the
	// original file with the new file. This is atomic and should always
	// allow for a consistent view of the data. There is a small
	// window where the file could be read and then updated by
	// another process. In this case any updates the other process did
	// will be lost. This is a limitation of the internal IAM service.
	// This should be rare, and even when it does happen should result
	// in a valid IAM file, just without the other process's updates.

	iamFname := filepath.Join(e.dir, e.iamFile)
	backupFname := filepath.Join(e.dir, e.iamBackupFile)

	raw, err := os.ReadFile(iamFname)
	missing := errors.Is(err, fs.ErrNotExist)
	if err != nil && !missing {
		return fmt.Errorf("read iam file: %w", err)
	}

	// The backup is a byte copy of the previous file, so an encrypted store
	// keeps an encrypted backup and restoring it stays a plain rename.
	if err := e.writeUsingTempFile(raw, backupFname); err != nil {
		return fmt.Errorf("write backup iam file: %w", err)
	}

	// The store keeps the format it already has. Only a store created by
	// this engine, or migrated with the CLI, starts out encrypted.
	encrypt := e.protector != nil
	plaintext := raw
	if !missing {
		encrypt = IsEncrypted(raw)
		plaintext, err = e.decode(raw)
		if err != nil {
			return fmt.Errorf("read iam data: %w", err)
		}
	}

	updated, err := update(plaintext)
	if err != nil {
		return fmt.Errorf("update iam data: %w", err)
	}

	out, err := e.encode(updated, encrypt)
	if err != nil {
		return fmt.Errorf("encrypt iam data: %w", err)
	}

	if err := e.writeUsingTempFile(out, iamFname); err != nil {
		e.invalidateCache()
		return fmt.Errorf("write iam file: %w", err)
	}

	// The bytes just published are known, so the cache starts out warm and
	// the next request neither reads nor decrypts the file.
	e.cachePlaintext(sha256.Sum256(out), updated)

	return nil
}

// decode returns the plaintext behind stored bytes, whichever format they use.
func (e *Engine[T]) decode(raw []byte) ([]byte, error) {
	if !IsEncrypted(raw) {
		if e.requireEncryption {
			return nil, fmt.Errorf("%w: %s", ErrPlaintextStore, filepath.Join(e.dir, e.iamFile))
		}
		return raw, nil
	}
	if e.protector == nil {
		return nil, fmt.Errorf("%w: %s", ErrMissingProtector, filepath.Join(e.dir, e.iamFile))
	}
	// The IAM service interfaces carry no request context; the KMS provider
	// applies its own call timeout.
	return e.protector.Decode(context.Background(), e.iamFile, raw)
}

func (e *Engine[T]) encode(plaintext []byte, encrypt bool) ([]byte, error) {
	if !encrypt {
		return plaintext, nil
	}
	if e.protector == nil {
		return nil, fmt.Errorf("%w: %s", ErrMissingProtector, filepath.Join(e.dir, e.iamFile))
	}
	return e.protector.Encode(context.Background(), e.iamFile, plaintext)
}

// cachedPlaintext serves a request from memory while the cache is inside its
// validity window.
func (e *Engine[T]) cachedPlaintext() ([]byte, bool) {
	e.cache.RLock()
	defer e.cache.RUnlock()

	if !e.cache.valid || time.Since(e.cache.validated) >= cacheValidity {
		return nil, false
	}

	return append([]byte(nil), e.cache.plaintext...), true
}

// revalidate extends the cache when the file still holds the bytes the cached
// plaintext was decrypted from.
func (e *Engine[T]) revalidate(digest [sha256.Size]byte) ([]byte, bool) {
	e.cache.Lock()
	defer e.cache.Unlock()

	if !e.cache.valid || e.cache.digest != digest {
		return nil, false
	}
	e.cache.validated = time.Now()

	return append([]byte(nil), e.cache.plaintext...), true
}

func (e *Engine[T]) cachePlaintext(digest [sha256.Size]byte, plaintext []byte) {
	stored := append([]byte(nil), plaintext...)

	e.cache.Lock()
	defer e.cache.Unlock()

	clear(e.cache.plaintext)
	e.cache.digest = digest
	e.cache.validated = time.Now()
	e.cache.plaintext = stored
	e.cache.valid = true
}

func (e *Engine[T]) invalidateCache() {
	e.cache.Lock()
	defer e.cache.Unlock()

	clear(e.cache.plaintext)
	e.cache.plaintext = nil
	e.cache.digest = [sha256.Size]byte{}
	e.cache.valid = false
}

func (e *Engine[T]) writeUsingTempFile(b []byte, fname string) error {
	f, err := os.CreateTemp(e.dir, e.iamFile)
	if err != nil {
		return fmt.Errorf("create temp file: %w", err)
	}
	defer os.Remove(f.Name())

	_, err = f.Write(b)
	f.Close()
	if err != nil {
		return fmt.Errorf("write temp file: %w", err)
	}

	err = os.Rename(f.Name(), fname)
	if err != nil {
		return fmt.Errorf("rename temp file: %w", err)
	}

	return nil
}
