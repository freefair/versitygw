// Copyright 2026 Versity Software
// This file is licensed under the Apache License, Version 2.0.

package controllers

import (
	"context"
	"net/http"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/versity/versitygw/internal/encryption"
	"github.com/versity/versitygw/s3err"
)

func TestPutBucketEncryption(t *testing.T) {
	t.Parallel()

	var stored encryption.Configuration
	backendMock := encryptionBackendMock()
	backendMock.PutEncryptionConfigurationFunc = func(_ context.Context, bucket string, configuration encryption.Configuration) error {
		assert.Equal(t, "bucket", bucket)
		stored = configuration
		return nil
	}
	controller := S3ApiController{be: backendMock}
	body := []byte(`<ServerSideEncryptionConfiguration><Rule><ApplyServerSideEncryptionByDefault><SSEAlgorithm>AES256</SSEAlgorithm></ApplyServerSideEncryptionByDefault><BlockedEncryptionTypes><EncryptionType>NONE</EncryptionType></BlockedEncryptionTypes></Rule></ServerSideEncryptionConfiguration>`)
	testController(t, controller.PutBucketEncryption, encryptionResponse("root", http.StatusOK), nil, ctxInputs{locals: defaultLocals, body: body})
	assert.Equal(t, encryption.AlgorithmAES256, stored.Rules[0].Default.Algorithm)
}

func TestPutBucketEncryptionRejectsUnsupportedKMS(t *testing.T) {
	t.Parallel()

	backendMock := encryptionBackendMock()
	controller := S3ApiController{be: backendMock}
	body := []byte(`<ServerSideEncryptionConfiguration><Rule><ApplyServerSideEncryptionByDefault><SSEAlgorithm>aws:kms</SSEAlgorithm></ApplyServerSideEncryptionByDefault></Rule></ServerSideEncryptionConfiguration>`)
	testController(t, controller.PutBucketEncryption, encryptionResponse("root", http.StatusOK), s3err.GetAPIError(s3err.ErrNotImplemented), ctxInputs{locals: defaultLocals, body: body})
	assert.Empty(t, backendMock.PutEncryptionConfigurationCalls())
}

func TestGetBucketEncryption(t *testing.T) {
	t.Parallel()

	backendMock := encryptionBackendMock()
	backendMock.GetEncryptionConfigurationFunc = func(_ context.Context, bucket string) (encryption.Configuration, error) {
		assert.Equal(t, "bucket", bucket)
		return encryption.DefaultConfiguration(), nil
	}
	controller := S3ApiController{be: backendMock}
	expected := encryptionResponse("root", http.StatusOK)
	cfg := encryption.DefaultConfiguration()
	cfg.XMLNS = encryption.Namespace
	expected.Data = cfg
	testController(t, controller.GetBucketEncryption, expected, nil, ctxInputs{locals: defaultLocals})
}

func TestDeleteBucketEncryption(t *testing.T) {
	t.Parallel()

	backendMock := encryptionBackendMock()
	backendMock.DeleteEncryptionConfigurationFunc = func(_ context.Context, bucket string) error {
		assert.Equal(t, "bucket", bucket)
		return nil
	}
	controller := S3ApiController{be: backendMock}
	testController(t, controller.DeleteBucketEncryption, encryptionResponse("root", http.StatusNoContent), nil, ctxInputs{locals: defaultLocals})
}

func encryptionBackendMock() *BackendMock {
	return &BackendMock{
		EncryptionCapabilitiesFunc: func() encryption.Capabilities {
			return encryption.Capabilities{SSES3: true, SSEC: true}
		},
		PutEncryptionConfigurationFunc: func(context.Context, string, encryption.Configuration) error { return nil },
		GetEncryptionConfigurationFunc: func(context.Context, string) (encryption.Configuration, error) {
			return encryption.DefaultConfiguration(), nil
		},
		DeleteEncryptionConfigurationFunc: func(context.Context, string) error { return nil },
		GetBucketPolicyFunc: func(context.Context, string) ([]byte, error) {
			return nil, s3err.GetAPIError(s3err.ErrAccessDenied)
		},
	}
}
