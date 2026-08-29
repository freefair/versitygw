// Copyright 2026 Versity Software
// This file is licensed under the Apache License, Version 2.0.

package encryption

import (
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/hmac"
	"crypto/md5"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"reflect"
	"regexp"
	"strings"
)

const (
	localProviderName    = "local"
	customerProviderName = "sse-c"
)

var keyIDPattern = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$`)

func ValidateKeyID(id string) error {
	if !keyIDPattern.MatchString(id) {
		return ErrInvalidKey
	}
	return nil
}

type KeyRequest struct {
	KeyID         string
	Context       []byte
	ClientContext []byte
}

type WrappedDataKey struct {
	Provider   string            `json:"provider"`
	KeyID      string            `json:"key_id"`
	Ciphertext []byte            `json:"ciphertext"`
	Metadata   map[string]string `json:"metadata,omitempty"`
}

type KeyProvider interface {
	Name() string
	GenerateDataKey(context.Context, KeyRequest) (SensitiveBytes, WrappedDataKey, error)
	WrapKey(context.Context, KeyRequest, SensitiveBytes) (WrappedDataKey, error)
	UnwrapKey(context.Context, KeyRequest, WrappedDataKey) (SensitiveBytes, error)
	ValidateKeyReference(string) error
}

type ProviderMap map[string]KeyProvider

type ActiveKeyReferencer interface {
	ActiveKeyReference() string
}

type LocalProvider struct {
	active string
	keys   map[string]SensitiveBytes
}

type DerivedLocalProvider struct {
	name  string
	label string
	base  *LocalProvider
}

// ValidateLocalKeyDirectory enforces the ownership, permission, and symlink
// rules shared by key generation and provider startup.
func ValidateLocalKeyDirectory(dir string) error {
	directoryInfo, err := os.Lstat(dir)
	if err != nil {
		return fmt.Errorf("stat local key directory: %w", err)
	}
	if !directoryInfo.IsDir() || directoryInfo.Mode()&os.ModeSymlink != 0 {
		return fmt.Errorf("%w: key directory must not be a symlink", ErrInvalidKey)
	}
	if directoryInfo.Mode().Perm() != 0o700 || !ownedByEffectiveUser(directoryInfo) {
		return ErrInsecureKeyPermissions
	}
	entries, err := os.ReadDir(dir)
	if err != nil {
		return fmt.Errorf("read local key directory: %w", err)
	}
	for _, entry := range entries {
		if entry.Type()&os.ModeSymlink != 0 {
			return fmt.Errorf("%w: key directory must not contain symlinks", ErrInvalidKey)
		}
		if entry.Name() != "active" && filepath.Ext(entry.Name()) != ".key" {
			continue
		}
		info, err := entry.Info()
		if err != nil {
			return fmt.Errorf("stat local key entry: %w", err)
		}
		if !info.Mode().IsRegular() || info.Mode().Perm()&0o077 != 0 || !ownedByEffectiveUser(info) {
			return ErrInsecureKeyPermissions
		}
	}
	return nil
}

func NewLocalProvider(dir, active string) (_ *LocalProvider, returnErr error) {
	if err := ValidateLocalKeyDirectory(dir); err != nil {
		return nil, err
	}
	entries, err := os.ReadDir(dir)
	if err != nil {
		return nil, fmt.Errorf("read local key directory: %w", err)
	}
	keys := make(map[string]SensitiveBytes)
	defer func() {
		if returnErr != nil {
			for id, key := range keys {
				key.Destroy()
				delete(keys, id)
			}
		}
	}()
	for _, entry := range entries {
		name := entry.Name()
		if entry.Type()&os.ModeSymlink != 0 {
			return nil, fmt.Errorf("%w: key directory must not contain symlinks", ErrInvalidKey)
		}
		if filepath.Ext(name) != ".key" {
			continue
		}
		id := strings.TrimSuffix(name, ".key")
		if !keyIDPattern.MatchString(id) {
			return nil, fmt.Errorf("%w: invalid key ID", ErrInvalidKey)
		}
		path := filepath.Join(dir, name)
		info, err := os.Lstat(path)
		if err != nil {
			return nil, fmt.Errorf("stat local key: %w", err)
		}
		if !info.Mode().IsRegular() || info.Mode()&os.ModeSymlink != 0 {
			return nil, fmt.Errorf("%w: key must be a regular file", ErrInvalidKey)
		}
		if info.Mode().Perm()&0o077 != 0 || !ownedByEffectiveUser(info) {
			return nil, ErrInsecureKeyPermissions
		}
		file, err := os.Open(path)
		if err != nil {
			return nil, fmt.Errorf("open local key: %w", err)
		}
		openedInfo, err := file.Stat()
		if err != nil || !os.SameFile(info, openedInfo) {
			_ = file.Close()
			return nil, fmt.Errorf("%w: local key changed while opening", ErrInvalidKey)
		}
		key, err := io.ReadAll(io.LimitReader(file, DataKeySize+1))
		closeErr := file.Close()
		if err != nil {
			return nil, fmt.Errorf("read local key: %w", err)
		}
		if closeErr != nil {
			clear(key)
			return nil, fmt.Errorf("close local key: %w", closeErr)
		}
		if len(key) != DataKeySize {
			return nil, fmt.Errorf("%w: key must contain exactly %d bytes", ErrInvalidKey, DataKeySize)
		}
		keys[id] = append(SensitiveBytes(nil), key...)
		clear(key)
	}
	if active == "" {
		activePath := filepath.Join(dir, "active")
		activeInfo, err := os.Lstat(activePath)
		if err != nil {
			return nil, fmt.Errorf("stat active key ID: %w", err)
		}
		if !activeInfo.Mode().IsRegular() || activeInfo.Mode()&os.ModeSymlink != 0 {
			return nil, fmt.Errorf("%w: active key ID must be a regular file", ErrInvalidKey)
		}
		if activeInfo.Mode().Perm()&0o077 != 0 || !ownedByEffectiveUser(activeInfo) {
			return nil, ErrInsecureKeyPermissions
		}
		activeFile, err := os.Open(activePath)
		if err != nil {
			return nil, fmt.Errorf("open active key ID: %w", err)
		}
		openedInfo, err := activeFile.Stat()
		if err != nil || !os.SameFile(activeInfo, openedInfo) {
			_ = activeFile.Close()
			return nil, fmt.Errorf("%w: active key ID changed while opening", ErrInvalidKey)
		}
		activeBytes, err := io.ReadAll(io.LimitReader(activeFile, 1024))
		closeErr := activeFile.Close()
		if err != nil {
			clear(activeBytes)
			return nil, fmt.Errorf("read active key ID: %w", err)
		}
		if closeErr != nil {
			clear(activeBytes)
			return nil, fmt.Errorf("close active key ID: %w", closeErr)
		}
		active = strings.TrimSpace(string(activeBytes))
		clear(activeBytes)
	}
	if !keyIDPattern.MatchString(active) {
		return nil, fmt.Errorf("%w: invalid active key ID", ErrInvalidKey)
	}
	if _, ok := keys[active]; !ok {
		return nil, fmt.Errorf("%w: active key", ErrKeyNotFound)
	}
	return &LocalProvider{active: active, keys: keys}, nil
}

func ownedByEffectiveUser(info os.FileInfo) bool {
	effectiveUID := os.Geteuid()
	if effectiveUID < 0 {
		return true
	}
	value := reflect.ValueOf(info.Sys())
	if !value.IsValid() {
		return false
	}
	if value.Kind() == reflect.Pointer {
		value = value.Elem()
	}
	if !value.IsValid() || value.Kind() != reflect.Struct {
		return false
	}
	uid := value.FieldByName("Uid")
	return uid.IsValid() && uid.CanUint() && uid.Uint() == uint64(effectiveUID)
}

func (p *LocalProvider) Name() string { return localProviderName }

func (p *LocalProvider) ActiveKeyReference() string { return p.active }

func (p *LocalProvider) Close() {
	for id, key := range p.keys {
		key.Destroy()
		delete(p.keys, id)
	}
}

func (p *LocalProvider) Derived(name, label string) (*DerivedLocalProvider, error) {
	if !keyIDPattern.MatchString(name) || name == p.Name() || label == "" {
		return nil, ErrInvalidKey
	}
	return &DerivedLocalProvider{name: name, label: label, base: p}, nil
}

func (p *LocalProvider) ValidateKeyReference(id string) error {
	if id == "" {
		id = p.active
	}
	if !keyIDPattern.MatchString(id) {
		return ErrInvalidKey
	}
	if _, ok := p.keys[id]; !ok {
		return ErrKeyNotFound
	}
	return nil
}

func (p *LocalProvider) GenerateDataKey(ctx context.Context, req KeyRequest) (SensitiveBytes, WrappedDataKey, error) {
	key := make(SensitiveBytes, DataKeySize)
	if _, err := io.ReadFull(rand.Reader, key); err != nil {
		return nil, WrappedDataKey{}, fmt.Errorf("generate data key: %w", err)
	}
	wrapped, err := p.WrapKey(ctx, req, key)
	if err != nil {
		key.Destroy()
		return nil, WrappedDataKey{}, err
	}
	return key, wrapped, nil
}

func (p *LocalProvider) WrapKey(_ context.Context, req KeyRequest, key SensitiveBytes) (WrappedDataKey, error) {
	id := req.KeyID
	if id == "" {
		id = p.active
	}
	if err := p.ValidateKeyReference(id); err != nil {
		return WrappedDataKey{}, err
	}
	return wrapWithAESGCM(localProviderName, id, p.keys[id], req.Context, key, nil)
}

func (p *LocalProvider) UnwrapKey(_ context.Context, req KeyRequest, wrapped WrappedDataKey) (SensitiveBytes, error) {
	if wrapped.Provider != localProviderName {
		return nil, ErrInvalidKey
	}
	if err := p.ValidateKeyReference(wrapped.KeyID); err != nil {
		return nil, err
	}
	return unwrapWithAESGCM(p.keys[wrapped.KeyID], req.Context, wrapped)
}

func (p *DerivedLocalProvider) Name() string { return p.name }

func (p *DerivedLocalProvider) ActiveKeyReference() string { return p.base.active }

func (p *DerivedLocalProvider) ValidateKeyReference(id string) error {
	return p.base.ValidateKeyReference(id)
}

func (p *DerivedLocalProvider) GenerateDataKey(ctx context.Context, request KeyRequest) (SensitiveBytes, WrappedDataKey, error) {
	key := make(SensitiveBytes, DataKeySize)
	if _, err := io.ReadFull(rand.Reader, key); err != nil {
		return nil, WrappedDataKey{}, fmt.Errorf("generate derived data key: %w", err)
	}
	wrapped, err := p.WrapKey(ctx, request, key)
	if err != nil {
		key.Destroy()
		return nil, WrappedDataKey{}, err
	}
	return key, wrapped, nil
}

func (p *DerivedLocalProvider) WrapKey(_ context.Context, request KeyRequest, key SensitiveBytes) (WrappedDataKey, error) {
	id := request.KeyID
	if id == "" {
		id = p.base.active
	}
	if err := p.ValidateKeyReference(id); err != nil {
		return WrappedDataKey{}, err
	}
	derived := hkdfSHA256(p.base.keys[id], nil, []byte("versitygw/local-provider/"+p.label), DataKeySize)
	defer clear(derived)
	return wrapWithAESGCM(p.name, id, derived, request.Context, key, nil)
}

func (p *DerivedLocalProvider) UnwrapKey(_ context.Context, request KeyRequest, wrapped WrappedDataKey) (SensitiveBytes, error) {
	if wrapped.Provider != p.name {
		return nil, ErrInvalidKey
	}
	if err := p.ValidateKeyReference(wrapped.KeyID); err != nil {
		return nil, err
	}
	derived := hkdfSHA256(p.base.keys[wrapped.KeyID], nil, []byte("versitygw/local-provider/"+p.label), DataKeySize)
	defer clear(derived)
	return unwrapWithAESGCM(derived, request.Context, wrapped)
}

type CustomerKeyProvider struct {
	key    SensitiveBytes
	keyMD5 [md5.Size]byte
}

func NewCustomerKeyProvider(key []byte) (*CustomerKeyProvider, error) {
	if len(key) != DataKeySize {
		return nil, fmt.Errorf("%w: SSE-C key must contain exactly %d bytes", ErrInvalidKey, DataKeySize)
	}
	copyKey := append(SensitiveBytes(nil), key...)
	return &CustomerKeyProvider{key: copyKey, keyMD5: md5.Sum(key)}, nil
}

func (p *CustomerKeyProvider) Name() string { return customerProviderName }

func (p *CustomerKeyProvider) Destroy() { p.key.Destroy() }

func (p *CustomerKeyProvider) ValidateKeyReference(id string) error {
	if subtle.ConstantTimeCompare([]byte(id), []byte(base64.StdEncoding.EncodeToString(p.keyMD5[:]))) != 1 {
		return ErrInvalidKey
	}
	return nil
}

func (p *CustomerKeyProvider) GenerateDataKey(ctx context.Context, req KeyRequest) (SensitiveBytes, WrappedDataKey, error) {
	key := make(SensitiveBytes, DataKeySize)
	if _, err := io.ReadFull(rand.Reader, key); err != nil {
		return nil, WrappedDataKey{}, fmt.Errorf("generate data key: %w", err)
	}
	wrapped, err := p.WrapKey(ctx, req, key)
	if err != nil {
		key.Destroy()
		return nil, WrappedDataKey{}, err
	}
	return key, wrapped, nil
}

func (p *CustomerKeyProvider) WrapKey(_ context.Context, req KeyRequest, key SensitiveBytes) (WrappedDataKey, error) {
	salt := make([]byte, sha256.Size)
	if _, err := io.ReadFull(rand.Reader, salt); err != nil {
		return WrappedDataKey{}, fmt.Errorf("generate SSE-C salt: %w", err)
	}
	wrappingKey := hkdfSHA256(p.key, salt, append([]byte("versitygw/sse-c/"), req.Context...), DataKeySize)
	defer clear(wrappingKey)
	id := base64.StdEncoding.EncodeToString(p.keyMD5[:])
	return wrapWithAESGCM(customerProviderName, id, wrappingKey, req.Context, key, map[string]string{
		"salt": base64.StdEncoding.EncodeToString(salt),
	})
}

func (p *CustomerKeyProvider) UnwrapKey(_ context.Context, req KeyRequest, wrapped WrappedDataKey) (SensitiveBytes, error) {
	if wrapped.Provider != customerProviderName || p.ValidateKeyReference(wrapped.KeyID) != nil {
		return nil, ErrAuthentication
	}
	salt, err := base64.StdEncoding.DecodeString(wrapped.Metadata["salt"])
	if err != nil || len(salt) != sha256.Size {
		return nil, ErrInvalidContainer
	}
	wrappingKey := hkdfSHA256(p.key, salt, append([]byte("versitygw/sse-c/"), req.Context...), DataKeySize)
	defer clear(wrappingKey)
	return unwrapWithAESGCM(wrappingKey, req.Context, wrapped)
}

func wrapWithAESGCM(provider, id string, wrappingKey, context, plaintext []byte, metadata map[string]string) (WrappedDataKey, error) {
	aead, err := newGCM(wrappingKey)
	if err != nil {
		return WrappedDataKey{}, err
	}
	nonce := make([]byte, aead.NonceSize())
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return WrappedDataKey{}, fmt.Errorf("generate wrapping nonce: %w", err)
	}
	aad := wrapAAD(provider, id, context)
	ciphertext := aead.Seal(append([]byte(nil), nonce...), nonce, plaintext, aad)
	return WrappedDataKey{Provider: provider, KeyID: id, Ciphertext: ciphertext, Metadata: metadata}, nil
}

func unwrapWithAESGCM(wrappingKey, context []byte, wrapped WrappedDataKey) (SensitiveBytes, error) {
	aead, err := newGCM(wrappingKey)
	if err != nil {
		return nil, err
	}
	if len(wrapped.Ciphertext) < aead.NonceSize()+aead.Overhead() {
		return nil, ErrInvalidContainer
	}
	nonce := wrapped.Ciphertext[:aead.NonceSize()]
	plaintext, err := aead.Open(nil, nonce, wrapped.Ciphertext[aead.NonceSize():], wrapAAD(wrapped.Provider, wrapped.KeyID, context))
	if err != nil {
		return nil, ErrAuthentication
	}
	if len(plaintext) != DataKeySize {
		clear(plaintext)
		return nil, ErrInvalidContainer
	}
	return SensitiveBytes(plaintext), nil
}

func newGCM(key []byte) (cipher.AEAD, error) {
	if len(key) != DataKeySize {
		return nil, ErrInvalidKey
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, fmt.Errorf("initialize AES: %w", err)
	}
	aead, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("initialize GCM: %w", err)
	}
	return aead, nil
}

func wrapAAD(provider, id string, context []byte) []byte {
	aad := make([]byte, 0, len(provider)+len(id)+len(context)+2)
	aad = append(aad, provider...)
	aad = append(aad, 0)
	aad = append(aad, id...)
	aad = append(aad, 0)
	return append(aad, context...)
}

func hkdfSHA256(secret, salt, info []byte, size int) []byte {
	extract := hmac.New(sha256.New, salt)
	_, _ = extract.Write(secret)
	prk := extract.Sum(nil)
	defer clear(prk)
	result := make([]byte, 0, size)
	var previous []byte
	for counter := byte(1); len(result) < size; counter++ {
		expand := hmac.New(sha256.New, prk)
		_, _ = expand.Write(previous)
		_, _ = expand.Write(info)
		_, _ = expand.Write([]byte{counter})
		previous = expand.Sum(nil)
		result = append(result, previous...)
	}
	clear(previous)
	return result[:size]
}

func IsAuthenticationError(err error) bool {
	return errors.Is(err, ErrAuthentication) || errors.Is(err, ErrIdentityMismatch)
}
