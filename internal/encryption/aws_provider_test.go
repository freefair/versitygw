// Copyright 2026 Versity Software
// This file is licensed under the Apache License, Version 2.0.

package encryption

import (
	"bytes"
	"context"
	"errors"
	"testing"
	"time"

	awskms "github.com/aws/aws-sdk-go-v2/service/kms"
)

type kmsClientStub struct {
	generate func(context.Context, *awskms.GenerateDataKeyInput) (*awskms.GenerateDataKeyOutput, error)
	encrypt  func(context.Context, *awskms.EncryptInput) (*awskms.EncryptOutput, error)
	decrypt  func(context.Context, *awskms.DecryptInput) (*awskms.DecryptOutput, error)
}

func (stub kmsClientStub) GenerateDataKey(ctx context.Context, input *awskms.GenerateDataKeyInput, _ ...func(*awskms.Options)) (*awskms.GenerateDataKeyOutput, error) {
	return stub.generate(ctx, input)
}
func (stub kmsClientStub) Encrypt(ctx context.Context, input *awskms.EncryptInput, _ ...func(*awskms.Options)) (*awskms.EncryptOutput, error) {
	return stub.encrypt(ctx, input)
}
func (stub kmsClientStub) Decrypt(ctx context.Context, input *awskms.DecryptInput, _ ...func(*awskms.Options)) (*awskms.DecryptOutput, error) {
	return stub.decrypt(ctx, input)
}

func TestAWSKMSProviderGenerateAndUnwrap(t *testing.T) {
	plaintext := bytes.Repeat([]byte{0x31}, DataKeySize)
	stub := kmsClientStub{
		generate: func(_ context.Context, input *awskms.GenerateDataKeyInput) (*awskms.GenerateDataKeyOutput, error) {
			if input.KeyId == nil || *input.KeyId != "alias/test" || input.EncryptionContext[kmsObjectBindingContextKey] == "" {
				t.Fatalf("GenerateDataKey input = %#v", input)
			}
			return &awskms.GenerateDataKeyOutput{Plaintext: append([]byte(nil), plaintext...), CiphertextBlob: []byte("wrapped")}, nil
		},
		decrypt: func(_ context.Context, input *awskms.DecryptInput) (*awskms.DecryptOutput, error) {
			if input.KeyId == nil || *input.KeyId != "alias/test" || !bytes.Equal(input.CiphertextBlob, []byte("wrapped")) {
				t.Fatalf("Decrypt input = %#v", input)
			}
			return &awskms.DecryptOutput{Plaintext: append([]byte(nil), plaintext...)}, nil
		},
		encrypt: func(context.Context, *awskms.EncryptInput) (*awskms.EncryptOutput, error) {
			return nil, errors.New("unexpected Encrypt call")
		},
	}
	provider, err := NewAWSKMSProvider(stub, "alias/test", time.Second)
	if err != nil {
		t.Fatal(err)
	}
	generated, wrapped, err := provider.GenerateDataKey(context.Background(), KeyRequest{Context: []byte("context")})
	if err != nil {
		t.Fatal(err)
	}
	defer generated.Destroy()
	if !bytes.Equal(generated, plaintext) || wrapped.Provider != awsKMSProviderName || wrapped.KeyID != "alias/test" {
		t.Fatalf("generated/wrapped = %x %#v", generated, wrapped)
	}
	unwrapped, err := provider.UnwrapKey(context.Background(), KeyRequest{Context: []byte("context")}, wrapped)
	if err != nil {
		t.Fatal(err)
	}
	defer unwrapped.Destroy()
	if !bytes.Equal(unwrapped, plaintext) {
		t.Fatalf("unwrapped = %x", unwrapped)
	}
}

func TestAWSKMSProviderPreservesClientEncryptionContext(t *testing.T) {
	stub := kmsClientStub{
		generate: func(_ context.Context, input *awskms.GenerateDataKeyInput) (*awskms.GenerateDataKeyOutput, error) {
			if input.EncryptionContext["tenant"] != "blue" || input.EncryptionContext["purpose"] != "archive" || input.EncryptionContext[kmsObjectBindingContextKey] == "" {
				t.Fatalf("GenerateDataKey encryption context = %#v", input.EncryptionContext)
			}
			return &awskms.GenerateDataKeyOutput{Plaintext: bytes.Repeat([]byte{0x44}, DataKeySize), CiphertextBlob: []byte("wrapped")}, nil
		},
	}
	provider, err := NewAWSKMSProvider(stub, "alias/test", time.Second)
	if err != nil {
		t.Fatal(err)
	}
	key, _, err := provider.GenerateDataKey(context.Background(), KeyRequest{
		Context: []byte("object binding"), ClientContext: []byte(`{"tenant":"blue","purpose":"archive"}`),
	})
	if err != nil {
		t.Fatal(err)
	}
	key.Destroy()
}

func TestAWSKMSProviderBoundsCallsWithTimeout(t *testing.T) {
	stub := kmsClientStub{
		generate: func(ctx context.Context, _ *awskms.GenerateDataKeyInput) (*awskms.GenerateDataKeyOutput, error) {
			<-ctx.Done()
			return nil, ctx.Err()
		},
	}
	provider, err := NewAWSKMSProvider(stub, "alias/test", time.Millisecond)
	if err != nil {
		t.Fatal(err)
	}
	_, _, err = provider.GenerateDataKey(context.Background(), KeyRequest{})
	if !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("GenerateDataKey() error = %v, want deadline exceeded", err)
	}
}

func TestAWSKMSProviderPreservesPermissionAndOutageCauses(t *testing.T) {
	permissionDenied := errors.New("access denied")
	providerUnavailable := errors.New("provider unavailable")
	stub := kmsClientStub{
		generate: func(context.Context, *awskms.GenerateDataKeyInput) (*awskms.GenerateDataKeyOutput, error) {
			return nil, permissionDenied
		},
		encrypt: func(context.Context, *awskms.EncryptInput) (*awskms.EncryptOutput, error) {
			return nil, providerUnavailable
		},
	}
	provider, err := NewAWSKMSProvider(stub, "alias/test", time.Second)
	if err != nil {
		t.Fatal(err)
	}

	_, _, err = provider.GenerateDataKey(context.Background(), KeyRequest{})
	if !errors.Is(err, permissionDenied) {
		t.Fatalf("GenerateDataKey() error = %v, want permission cause", err)
	}
	_, err = provider.WrapKey(context.Background(), KeyRequest{}, bytes.Repeat([]byte{0x21}, DataKeySize))
	if !errors.Is(err, providerUnavailable) {
		t.Fatalf("WrapKey() error = %v, want outage cause", err)
	}
}

func TestAWSKMSProviderAuthenticatesContextAndUsesRecordedKey(t *testing.T) {
	contextMismatch := errors.New("invalid encryption context")
	stub := kmsClientStub{
		decrypt: func(_ context.Context, input *awskms.DecryptInput) (*awskms.DecryptOutput, error) {
			if input.KeyId == nil || *input.KeyId != "alias/historical" {
				t.Fatalf("Decrypt KeyId = %v, want recorded historical key", input.KeyId)
			}
			if input.EncryptionContext[kmsObjectBindingContextKey] != "ZXhwZWN0ZWQ=" {
				return nil, contextMismatch
			}
			return &awskms.DecryptOutput{Plaintext: bytes.Repeat([]byte{0x22}, DataKeySize)}, nil
		},
	}
	provider, err := NewAWSKMSProvider(stub, "alias/current", time.Second)
	if err != nil {
		t.Fatal(err)
	}
	wrapped := WrappedDataKey{Provider: awsKMSProviderName, KeyID: "alias/historical", Ciphertext: []byte("wrapped")}

	_, err = provider.UnwrapKey(context.Background(), KeyRequest{Context: []byte("wrong")}, wrapped)
	if !errors.Is(err, contextMismatch) {
		t.Fatalf("UnwrapKey(wrong context) error = %v, want context mismatch", err)
	}
	plaintext, err := provider.UnwrapKey(context.Background(), KeyRequest{Context: []byte("expected")}, wrapped)
	if err != nil {
		t.Fatal(err)
	}
	defer plaintext.Destroy()
	if len(plaintext) != DataKeySize {
		t.Fatalf("UnwrapKey() length = %d, want %d", len(plaintext), DataKeySize)
	}
}
