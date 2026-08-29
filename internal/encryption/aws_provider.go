// Copyright 2026 Versity Software
// This file is licensed under the Apache License, Version 2.0.

package encryption

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"strings"
	"time"
	"unicode"

	awskms "github.com/aws/aws-sdk-go-v2/service/kms"
	"github.com/aws/aws-sdk-go-v2/service/kms/types"
)

const (
	awsKMSProviderName         = "aws-kms"
	defaultKMSTimeout          = 10 * time.Second
	kmsObjectBindingContextKey = "versitygw:object-binding"
)

type AWSKMSClient interface {
	GenerateDataKey(context.Context, *awskms.GenerateDataKeyInput, ...func(*awskms.Options)) (*awskms.GenerateDataKeyOutput, error)
	Encrypt(context.Context, *awskms.EncryptInput, ...func(*awskms.Options)) (*awskms.EncryptOutput, error)
	Decrypt(context.Context, *awskms.DecryptInput, ...func(*awskms.Options)) (*awskms.DecryptOutput, error)
}

type AWSKMSProvider struct {
	client     AWSKMSClient
	defaultKey string
	timeout    time.Duration
}

func NewAWSKMSProvider(client AWSKMSClient, defaultKey string, timeout time.Duration) (*AWSKMSProvider, error) {
	if client == nil {
		return nil, fmt.Errorf("%w: AWS KMS client is required", ErrInvalidKey)
	}
	if defaultKey == "" {
		defaultKey = "alias/aws/s3"
	}
	provider := &AWSKMSProvider{client: client, defaultKey: defaultKey, timeout: timeout}
	if provider.timeout <= 0 {
		provider.timeout = defaultKMSTimeout
	}
	if err := provider.ValidateKeyReference(defaultKey); err != nil {
		return nil, err
	}
	return provider, nil
}

func (p *AWSKMSProvider) Name() string { return awsKMSProviderName }

func (p *AWSKMSProvider) ActiveKeyReference() string { return p.defaultKey }

func (p *AWSKMSProvider) ValidateKeyReference(id string) error {
	if id == "" {
		id = p.defaultKey
	}
	if len(id) == 0 || len(id) > 2048 || strings.TrimSpace(id) != id {
		return ErrInvalidKey
	}
	for _, char := range id {
		if unicode.IsControl(char) {
			return ErrInvalidKey
		}
	}
	return nil
}

func (p *AWSKMSProvider) GenerateDataKey(ctx context.Context, request KeyRequest) (SensitiveBytes, WrappedDataKey, error) {
	keyID, err := p.keyID(request.KeyID)
	if err != nil {
		return nil, WrappedDataKey{}, err
	}
	callContext, cancel := context.WithTimeout(ctx, p.timeout)
	defer cancel()
	encryptionContext, err := kmsEncryptionContext(request.ClientContext, request.Context)
	if err != nil {
		return nil, WrappedDataKey{}, err
	}
	output, err := p.client.GenerateDataKey(callContext, &awskms.GenerateDataKeyInput{
		KeyId:             &keyID,
		KeySpec:           types.DataKeySpecAes256,
		EncryptionContext: encryptionContext,
	})
	if err != nil {
		return nil, WrappedDataKey{}, fmt.Errorf("AWS KMS GenerateDataKey: %w", err)
	}
	if output == nil || len(output.Plaintext) != DataKeySize || len(output.CiphertextBlob) == 0 {
		if output != nil {
			clear(output.Plaintext)
		}
		return nil, WrappedDataKey{}, fmt.Errorf("%w: invalid AWS KMS data-key response", ErrInvalidKey)
	}
	plaintext := append(SensitiveBytes(nil), output.Plaintext...)
	clear(output.Plaintext)
	return plaintext, WrappedDataKey{
		Provider:   awsKMSProviderName,
		KeyID:      keyID,
		Ciphertext: append([]byte(nil), output.CiphertextBlob...),
	}, nil
}

func (p *AWSKMSProvider) WrapKey(ctx context.Context, request KeyRequest, plaintext SensitiveBytes) (WrappedDataKey, error) {
	if len(plaintext) != DataKeySize {
		return WrappedDataKey{}, ErrInvalidKey
	}
	keyID, err := p.keyID(request.KeyID)
	if err != nil {
		return WrappedDataKey{}, err
	}
	callContext, cancel := context.WithTimeout(ctx, p.timeout)
	defer cancel()
	encryptionContext, err := kmsEncryptionContext(request.ClientContext, request.Context)
	if err != nil {
		return WrappedDataKey{}, err
	}
	output, err := p.client.Encrypt(callContext, &awskms.EncryptInput{
		KeyId:             &keyID,
		Plaintext:         plaintext,
		EncryptionContext: encryptionContext,
	})
	if err != nil {
		return WrappedDataKey{}, fmt.Errorf("AWS KMS Encrypt: %w", err)
	}
	if output == nil || len(output.CiphertextBlob) == 0 {
		return WrappedDataKey{}, fmt.Errorf("%w: invalid AWS KMS encrypt response", ErrInvalidKey)
	}
	return WrappedDataKey{Provider: awsKMSProviderName, KeyID: keyID, Ciphertext: append([]byte(nil), output.CiphertextBlob...)}, nil
}

func (p *AWSKMSProvider) UnwrapKey(ctx context.Context, request KeyRequest, wrapped WrappedDataKey) (SensitiveBytes, error) {
	if wrapped.Provider != awsKMSProviderName || len(wrapped.Ciphertext) == 0 {
		return nil, ErrInvalidKey
	}
	keyID := wrapped.KeyID
	if request.KeyID != "" && request.KeyID != keyID {
		return nil, ErrAuthentication
	}
	if err := p.ValidateKeyReference(keyID); err != nil {
		return nil, err
	}
	callContext, cancel := context.WithTimeout(ctx, p.timeout)
	defer cancel()
	encryptionContext, err := kmsEncryptionContext(request.ClientContext, request.Context)
	if err != nil {
		return nil, err
	}
	output, err := p.client.Decrypt(callContext, &awskms.DecryptInput{
		CiphertextBlob:    wrapped.Ciphertext,
		KeyId:             &keyID,
		EncryptionContext: encryptionContext,
	})
	if err != nil {
		return nil, fmt.Errorf("AWS KMS Decrypt: %w", err)
	}
	if output == nil || len(output.Plaintext) != DataKeySize {
		if output != nil {
			clear(output.Plaintext)
		}
		return nil, ErrAuthentication
	}
	plaintext := append(SensitiveBytes(nil), output.Plaintext...)
	clear(output.Plaintext)
	return plaintext, nil
}

func (p *AWSKMSProvider) keyID(requested string) (string, error) {
	if requested == "" {
		requested = p.defaultKey
	}
	if err := p.ValidateKeyReference(requested); err != nil {
		return "", err
	}
	return requested, nil
}

func kmsEncryptionContext(clientContext, objectBinding []byte) (map[string]string, error) {
	result := make(map[string]string)
	if len(clientContext) != 0 {
		if err := json.Unmarshal(clientContext, &result); err != nil || result == nil {
			return nil, ErrInvalidEncryptionHeaders
		}
		if _, reserved := result[kmsObjectBindingContextKey]; reserved {
			return nil, ErrInvalidEncryptionHeaders
		}
	}
	result[kmsObjectBindingContextKey] = base64.StdEncoding.EncodeToString(objectBinding)
	return result, nil
}
