// Copyright 2026 Versity Software
// This file is licensed under the Apache License, Version 2.0.

package posix

import (
	"context"
	"crypto/subtle"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"strconv"

	"github.com/aws/aws-sdk-go-v2/service/s3/types"
	"github.com/versity/versitygw/backend/meta"
	"github.com/versity/versitygw/internal/encryption"
	"github.com/versity/versitygw/s3err"
)

type multipartEncryptionState struct {
	Mode             encryption.Mode `json:"mode"`
	KMSKeyID         string          `json:"kms_key_id,omitempty"`
	KMSContext       []byte          `json:"kms_context,omitempty"`
	BucketKeyEnabled bool            `json:"bucket_key_enabled,omitempty"`
	CustomerKeyMD5   []byte          `json:"customer_key_md5,omitempty"`
}

func multipartStateFromIntent(intent *encryption.Intent) *multipartEncryptionState {
	if intent == nil {
		return nil
	}
	state := &multipartEncryptionState{
		Mode: intent.Mode, KMSKeyID: intent.KMSKeyID, KMSContext: append([]byte(nil), intent.KMSContext...),
		BucketKeyEnabled: intent.BucketKeyEnabled,
	}
	if intent.Mode == encryption.ModeSSEC {
		state.CustomerKeyMD5 = append([]byte(nil), intent.CustomerKeyMD5[:]...)
	}
	return state
}

func (p *Posix) storeMultipartEncryption(bucket, uploadPath string, intent *encryption.Intent) error {
	state := multipartStateFromIntent(intent)
	if state == nil {
		return nil
	}
	body, err := json.Marshal(state)
	if err != nil {
		return fmt.Errorf("marshal multipart encryption state: %w", err)
	}
	if err := p.meta.StoreAttribute(nil, bucket, uploadPath, mpEncryptionKey, body); err != nil {
		return fmt.Errorf("store multipart encryption state: %w", err)
	}
	return nil
}

func (p *Posix) loadMultipartEncryption(bucket, uploadPath string) (*multipartEncryptionState, error) {
	body, err := p.meta.RetrieveAttribute(nil, bucket, uploadPath, mpEncryptionKey)
	if errors.Is(err, meta.ErrNoSuchKey) || errors.Is(err, fs.ErrNotExist) {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("retrieve multipart encryption state: %w", err)
	}
	var state multipartEncryptionState
	if err := json.Unmarshal(body, &state); err != nil {
		return nil, fmt.Errorf("parse multipart encryption state: %w", err)
	}
	if state.Mode != encryption.ModeSSES3 && state.Mode != encryption.ModeSSEC && state.Mode != encryption.ModeSSEKMS && state.Mode != encryption.ModeDSSEKMS {
		return nil, encryption.ErrInvalidContainer
	}
	return &state, nil
}

func multipartIntent(state *multipartEncryptionState, algorithm, key, keyMD5 *string) (*encryption.Intent, error) {
	headers := encryption.RequestHeaders{
		CustomerAlgorithm: encryptionStringValue(algorithm),
		CustomerKey:       encryptionStringValue(key),
		CustomerKeyMD5:    encryptionStringValue(keyMD5),
	}
	hasCustomerHeaders := encryption.HasCustomerKeyHeaders(headers)
	if state == nil {
		if hasCustomerHeaders {
			return nil, s3err.GetAPIError(s3err.ErrInvalidRequest)
		}
		return nil, nil
	}
	if state.Mode != encryption.ModeSSEC {
		if hasCustomerHeaders {
			return nil, s3err.GetAPIError(s3err.ErrInvalidRequest)
		}
		return &encryption.Intent{
			Mode: state.Mode, KMSKeyID: state.KMSKeyID, KMSContext: append([]byte(nil), state.KMSContext...),
			BucketKeyEnabled: state.BucketKeyEnabled,
		}, nil
	}
	intent, err := encryption.ParseCustomerKeyHeaders(headers)
	if err != nil || subtle.ConstantTimeCompare(intent.CustomerKeyMD5[:], state.CustomerKeyMD5) != 1 {
		intent.CustomerKey.Destroy()
		return nil, s3err.GetAPIError(s3err.ErrInvalidRequest)
	}
	return &intent, nil
}

func multipartPartIdentity(bucket, object, uploadID string, part int32) encryption.Identity {
	return encryption.Identity{Bucket: bucket, Key: object, VersionID: fmt.Sprintf("multipart:%s:%d", uploadID, part)}
}

func (p *Posix) multipartPartPlaintextSize(bucket, partPath string, storedSize int64) (int64, error) {
	body, err := p.meta.RetrieveAttribute(nil, bucket, partPath, mpPartPlainSizeKey)
	if errors.Is(err, meta.ErrNoSuchKey) {
		return storedSize, nil
	}
	if err != nil {
		return 0, fmt.Errorf("retrieve multipart part plaintext size: %w", err)
	}
	size, err := strconv.ParseInt(string(body), 10, 64)
	if err != nil || size < 0 {
		return 0, encryption.ErrInvalidContainer
	}
	return size, nil
}

func (p *Posix) objectPlaintextSize(bucket, object string, storedSize int64) (int64, error) {
	body, err := p.meta.RetrieveAttribute(nil, bucket, object, encryptionPlainSizeKey)
	if errors.Is(err, meta.ErrNoSuchKey) {
		return storedSize, nil
	}
	if err != nil {
		return 0, fmt.Errorf("retrieve encrypted object plaintext size: %w", err)
	}
	size, err := strconv.ParseInt(string(body), 10, 64)
	if err != nil || size < 0 {
		return 0, encryption.ErrInvalidContainer
	}
	return size, nil
}

func (p *Posix) storeEmptyObjectEncryption(bucket, object string, intent *encryption.Intent) error {
	return p.storeObjectEncryption(nil, bucket, object, encryptionResult(intent))
}

func (p *Posix) storeObjectEncryption(file *os.File, bucket, object string, result *encryption.Result) error {
	if result == nil {
		return nil
	}
	body, err := json.Marshal(result)
	if err != nil {
		return fmt.Errorf("marshal empty-object encryption result: %w", err)
	}
	if err := p.meta.StoreAttribute(file, bucket, object, encryptionResultKey, body); err != nil {
		return fmt.Errorf("store object encryption result: %w", err)
	}
	return nil
}

func (p *Posix) loadEmptyObjectEncryption(bucket, object string, algorithm, key, keyMD5 *string) (*encryption.Result, error) {
	body, err := p.meta.RetrieveAttribute(nil, bucket, object, encryptionResultKey)
	if errors.Is(err, meta.ErrNoSuchKey) {
		if encryption.HasCustomerKeyHeaders(encryption.RequestHeaders{
			CustomerAlgorithm: encryptionStringValue(algorithm), CustomerKey: encryptionStringValue(key), CustomerKeyMD5: encryptionStringValue(keyMD5),
		}) {
			return nil, s3err.GetAPIError(s3err.ErrInvalidRequest)
		}
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("retrieve empty-object encryption result: %w", err)
	}
	var result encryption.Result
	if err := json.Unmarshal(body, &result); err != nil {
		return nil, encryption.ErrInvalidContainer
	}
	headers := encryption.RequestHeaders{
		CustomerAlgorithm: encryptionStringValue(algorithm), CustomerKey: encryptionStringValue(key), CustomerKeyMD5: encryptionStringValue(keyMD5),
	}
	if result.Mode != encryption.ModeSSEC {
		if encryption.HasCustomerKeyHeaders(headers) {
			return nil, s3err.GetAPIError(s3err.ErrInvalidRequest)
		}
		return &result, nil
	}
	intent, err := encryption.ParseCustomerKeyHeaders(headers)
	if err != nil {
		return nil, s3err.GetAPIError(s3err.ErrInvalidRequest)
	}
	defer intent.CustomerKey.Destroy()
	if subtle.ConstantTimeCompare([]byte(result.CustomerKeyMD5), []byte(base64.StdEncoding.EncodeToString(intent.CustomerKeyMD5[:]))) != 1 {
		return nil, s3err.GetAPIError(s3err.ErrInvalidRequest)
	}
	return &result, nil
}

func (p *Posix) encryptionLayers(intent *encryption.Intent) ([]encryption.LayerRequest, error) {
	if intent == nil {
		return nil, nil
	}
	switch intent.Mode {
	case encryption.ModeSSEC:
		provider, err := encryption.NewCustomerKeyProvider(intent.CustomerKey)
		if err != nil {
			return nil, err
		}
		return []encryption.LayerRequest{{Provider: provider}}, nil
	case encryption.ModeSSES3:
		if p.managedEncryptionProvider == nil {
			return nil, encryption.ErrUnsupportedEncryption
		}
		return []encryption.LayerRequest{{Provider: p.managedEncryptionProvider}}, nil
	case encryption.ModeSSEKMS:
		if p.encryptionProvider == nil {
			return nil, encryption.ErrUnsupportedEncryption
		}
		return []encryption.LayerRequest{{Provider: p.encryptionProvider, KeyID: intent.KMSKeyID, Context: intent.KMSContext}}, nil
	case encryption.ModeDSSEKMS:
		if p.encryptionProvider == nil || p.dsseEncryptionProvider == nil {
			return nil, encryption.ErrUnsupportedEncryption
		}
		return []encryption.LayerRequest{
			{Provider: p.encryptionProvider, KeyID: intent.KMSKeyID, Context: intent.KMSContext},
			{Provider: p.dsseEncryptionProvider, Context: intent.KMSContext},
		}, nil
	default:
		return nil, encryption.ErrUnsupportedEncryption
	}
}

func (p *Posix) resolveEncryptionIntent(intent *encryption.Intent) (*encryption.Intent, error) {
	if intent == nil || intent.KMSKeyID != "" || (intent.Mode != encryption.ModeSSEKMS && intent.Mode != encryption.ModeDSSEKMS) {
		return intent, nil
	}
	referencer, ok := p.encryptionProvider.(encryption.ActiveKeyReferencer)
	if !ok || referencer.ActiveKeyReference() == "" {
		return nil, encryption.ErrInvalidKey
	}
	resolved := *intent
	resolved.KMSContext = append([]byte(nil), intent.KMSContext...)
	resolved.KMSKeyID = referencer.ActiveKeyReference()
	return &resolved, nil
}

func encryptionResult(intent *encryption.Intent) *encryption.Result {
	if intent == nil {
		return nil
	}
	result := &encryption.Result{Mode: intent.Mode, KMSKeyID: intent.KMSKeyID, BucketKeyEnabled: intent.BucketKeyEnabled}
	if intent.Mode == encryption.ModeSSEC {
		result.CustomerKeyMD5 = base64.StdEncoding.EncodeToString(intent.CustomerKeyMD5[:])
	}
	return result
}

func (p *Posix) openEncryptedObject(ctx context.Context, file *os.File, size int64, metadataBucket, metadataObject string, identity encryption.Identity, customerAlgorithm, customerKey, customerKeyMD5 *string) (*encryption.Reader, *encryption.Result, bool, error) {
	headers := encryption.RequestHeaders{
		CustomerAlgorithm: encryptionStringValue(customerAlgorithm),
		CustomerKey:       encryptionStringValue(customerKey),
		CustomerKeyMD5:    encryptionStringValue(customerKeyMD5),
	}
	hasCustomerKey := encryption.HasCustomerKeyHeaders(headers)
	info, err := file.Stat()
	if err != nil {
		return nil, nil, false, fmt.Errorf("stat object before encryption inspection: %w", err)
	}
	if info.IsDir() {
		if hasCustomerKey {
			return nil, nil, false, s3err.GetAPIError(s3err.ErrInvalidRequest)
		}
		return nil, nil, false, nil
	}
	hasEncryptionMetadata, err := p.hasEncryptionMetadata(file, metadataBucket, metadataObject)
	if err != nil {
		return nil, nil, false, err
	}
	isContainer, err := encryption.IsContainer(file)
	if err != nil {
		return nil, nil, false, fmt.Errorf("inspect encrypted object: %w", err)
	}
	if !isContainer {
		if hasEncryptionMetadata {
			return nil, nil, false, encryption.ErrInvalidContainer
		}
		if hasCustomerKey {
			return nil, nil, false, s3err.GetAPIError(s3err.ErrInvalidRequest)
		}
		return nil, nil, false, nil
	}

	providers := p.encryptionProviderMap()
	if hasCustomerKey {
		intent, err := encryption.ParseCustomerKeyHeaders(headers)
		if err != nil {
			return nil, nil, true, s3err.GetAPIError(s3err.ErrInvalidRequest)
		}
		provider, err := encryption.NewCustomerKeyProvider(intent.CustomerKey)
		intent.CustomerKey.Destroy()
		if err != nil {
			return nil, nil, true, s3err.GetAPIError(s3err.ErrInvalidRequest)
		}
		defer provider.Destroy()
		providers[provider.Name()] = provider
	}
	reader, err := encryption.Open(ctx, file, size, identity, providers)
	if err != nil {
		if errors.Is(err, encryption.ErrInvalidContainer) && !hasEncryptionMetadata {
			if hasCustomerKey {
				return nil, nil, false, s3err.GetAPIError(s3err.ErrInvalidRequest)
			}
			return nil, nil, false, nil
		}
		if errors.Is(err, encryption.ErrAuthentication) || errors.Is(err, encryption.ErrKeyNotFound) {
			return nil, nil, true, s3err.GetAPIError(s3err.ErrInvalidRequest)
		}
		return nil, nil, true, fmt.Errorf("open encrypted object: %w", err)
	}
	result := reader.Result()
	if (result.Mode == encryption.ModeSSEC) != hasCustomerKey {
		reader.Close()
		return nil, nil, true, s3err.GetAPIError(s3err.ErrInvalidRequest)
	}
	return reader, &result, true, nil
}

func (p *Posix) hasEncryptionMetadata(file *os.File, bucket, object string) (bool, error) {
	for _, attribute := range []string{encryptionResultKey, encryptionPlainSizeKey, mpPartPlainSizeKey} {
		_, err := p.meta.RetrieveAttribute(file, bucket, object, attribute)
		if err == nil {
			return true, nil
		}
		if errors.Is(err, meta.ErrNoSuchKey) || errors.Is(err, fs.ErrNotExist) {
			continue
		}
		return false, fmt.Errorf("retrieve encryption marker %q: %w", attribute, err)
	}
	return false, nil
}

func encryptionStringValue(value *string) string {
	if value == nil {
		return ""
	}
	return *value
}

func encryptionOutputValues(result *encryption.Result) (types.ServerSideEncryption, *string, *string, *string, *bool) {
	if result == nil {
		return "", nil, nil, nil, nil
	}
	var algorithm types.ServerSideEncryption
	var kmsKeyID, customerAlgorithm, customerKeyMD5 *string
	switch result.Mode {
	case encryption.ModeSSES3:
		algorithm = types.ServerSideEncryptionAes256
	case encryption.ModeSSEKMS:
		algorithm = types.ServerSideEncryptionAwsKms
		kmsKeyID = encryptionOptionalString(result.KMSKeyID)
	case encryption.ModeDSSEKMS:
		algorithm = types.ServerSideEncryptionAwsKmsDsse
		kmsKeyID = encryptionOptionalString(result.KMSKeyID)
	case encryption.ModeSSEC:
		customerAlgorithm = encryptionOptionalString("AES256")
		customerKeyMD5 = encryptionOptionalString(result.CustomerKeyMD5)
	}
	if result.Mode == encryption.ModeSSEKMS {
		bucketKeyEnabled := result.BucketKeyEnabled
		return algorithm, kmsKeyID, customerAlgorithm, customerKeyMD5, &bucketKeyEnabled
	}
	return algorithm, kmsKeyID, customerAlgorithm, customerKeyMD5, nil
}

func encryptionOptionalString(value string) *string {
	if value == "" {
		return nil
	}
	return &value
}

type encryptedObjectBody struct {
	reader io.ReadCloser
	file   *os.File
}

func (b *encryptedObjectBody) Read(destination []byte) (int, error) {
	return b.reader.Read(destination)
}

func (b *encryptedObjectBody) Close() error {
	readerErr := b.reader.Close()
	fileErr := b.file.Close()
	if readerErr != nil {
		return readerErr
	}
	return fileErr
}

func (p *Posix) EncryptionCapabilities() encryption.Capabilities {
	if p.managedEncryptionProvider == nil {
		return encryption.Capabilities{}
	}
	return encryption.Capabilities{
		SSES3: true, SSEC: true,
		SSEKMS:  p.encryptionProvider != nil,
		DSSEKMS: p.encryptionProvider != nil && p.dsseEncryptionProvider != nil,
	}
}

func (p *Posix) EncryptionActive() bool { return p.managedEncryptionProvider != nil }

func (p *Posix) PutEncryptionConfiguration(ctx context.Context, bucket string, configuration encryption.Configuration) error {
	release, err := p.acquireActionSlot(ctx)
	if err != nil {
		return err
	}
	defer release()
	if p.managedEncryptionProvider == nil {
		return s3err.GetAPIError(s3err.ErrNotImplemented)
	}
	if err := p.requireLifecycleBucket(bucket); err != nil {
		return err
	}
	body, err := encryption.MarshalConfiguration(configuration)
	if err != nil {
		return err
	}
	if err := p.meta.StoreAttribute(nil, bucket, "", encryptionkey, body); err != nil {
		return fmt.Errorf("store encryption configuration: %w", err)
	}
	return nil
}

func (p *Posix) GetEncryptionConfiguration(ctx context.Context, bucket string) (encryption.Configuration, error) {
	release, err := p.acquireActionSlot(ctx)
	if err != nil {
		return encryption.Configuration{}, err
	}
	defer release()
	if p.managedEncryptionProvider == nil {
		return encryption.Configuration{}, s3err.GetAPIError(s3err.ErrNotImplemented)
	}
	if err := p.requireLifecycleBucket(bucket); err != nil {
		return encryption.Configuration{}, err
	}
	body, err := p.meta.RetrieveAttribute(nil, bucket, "", encryptionkey)
	if errors.Is(err, meta.ErrNoSuchKey) {
		return encryption.LegacyConfiguration(), nil
	}
	if err != nil {
		return encryption.Configuration{}, fmt.Errorf("retrieve encryption configuration: %w", err)
	}
	configuration, err := encryption.ParseConfiguration(body)
	if err != nil {
		return encryption.Configuration{}, fmt.Errorf("parse stored encryption configuration: %w", err)
	}
	return encryption.ValidateConfiguration(configuration, p.EncryptionCapabilities())
}

func (p *Posix) DeleteEncryptionConfiguration(ctx context.Context, bucket string) error {
	release, err := p.acquireActionSlot(ctx)
	if err != nil {
		return err
	}
	defer release()
	if p.managedEncryptionProvider == nil {
		return s3err.GetAPIError(s3err.ErrNotImplemented)
	}
	if err := p.requireLifecycleBucket(bucket); err != nil {
		return err
	}
	body, err := encryption.MarshalConfiguration(encryption.DefaultConfiguration())
	if err != nil {
		return err
	}
	if err := p.meta.StoreAttribute(nil, bucket, "", encryptionkey, body); err != nil {
		return fmt.Errorf("reset encryption configuration: %w", err)
	}
	return nil
}
