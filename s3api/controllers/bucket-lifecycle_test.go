// Copyright 2026 Versity Software
// This file is licensed under the Apache License, Version 2.0.

package controllers

import (
	"context"
	"net/http"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/versity/versitygw/internal/lifecycle"
	"github.com/versity/versitygw/s3err"
)

func TestPutBucketLifecycleConfiguration(t *testing.T) {
	t.Parallel()

	body := []byte(`<LifecycleConfiguration><Rule><ID>expire</ID><Filter><Prefix>logs/</Prefix></Filter><Status>Enabled</Status><Expiration><Days>30</Days></Expiration></Rule></LifecycleConfiguration>`)
	var stored lifecycle.Configuration
	backendMock := lifecycleBackendMock()
	backendMock.PutLifecycleConfigurationFunc = func(_ context.Context, bucket string, configuration lifecycle.Configuration) error {
		assert.Equal(t, "bucket", bucket)
		stored = configuration
		return nil
	}
	controller := S3ApiController{be: backendMock}

	testController(t, controller.PutBucketLifecycleConfiguration,
		lifecycleResponseWithTransitionMinimum("root", http.StatusOK, lifecycle.TransitionMinimumAllStorageClasses128K), nil,
		ctxInputs{locals: defaultLocals, body: body})

	if len(stored.Rules) != 1 || stored.Rules[0].Expiration == nil || *stored.Rules[0].Expiration.Days != 30 || stored.TransitionDefaultMinimumObjectSize != lifecycle.TransitionMinimumAllStorageClasses128K {
		t.Fatalf("stored configuration = %#v", stored)
	}
}

func TestPutBucketLifecycleConfigurationRejectsMalformedXML(t *testing.T) {
	t.Parallel()

	backendMock := lifecycleBackendMock()
	controller := S3ApiController{be: backendMock}
	testController(t, controller.PutBucketLifecycleConfiguration,
		lifecycleResponse("root", http.StatusOK), s3err.GetAPIError(s3err.ErrMalformedXML),
		ctxInputs{locals: defaultLocals, body: []byte(`<LifecycleConfiguration>`)})
	assert.Empty(t, backendMock.PutLifecycleConfigurationCalls())
}

func TestPutBucketLifecycleConfigurationRejectsUnsupportedTransition(t *testing.T) {
	t.Parallel()

	backendMock := lifecycleBackendMock()
	controller := S3ApiController{be: backendMock}
	body := []byte(`<LifecycleConfiguration><Rule><Filter/><Status>Enabled</Status><Transition><Days>0</Days><StorageClass>GLACIER</StorageClass></Transition></Rule></LifecycleConfiguration>`)
	testController(t, controller.PutBucketLifecycleConfiguration,
		lifecycleResponse("root", http.StatusOK), s3err.GetAPIError(s3err.ErrInvalidRequest),
		ctxInputs{locals: defaultLocals, body: body})
	assert.Empty(t, backendMock.PutLifecycleConfigurationCalls())
}

func TestPutBucketLifecycleConfigurationPreservesInvalidArgumentCode(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name        string
		body        string
		description string
	}{
		{name: "expiration days", body: `<LifecycleConfiguration><Rule><Filter/><Status>Enabled</Status><Expiration><Days>0</Days></Expiration></Rule></LifecycleConfiguration>`, description: "Expiration Days must be positive"},
		{name: "noncurrent days", body: `<LifecycleConfiguration><Rule><Filter/><Status>Enabled</Status><NoncurrentVersionExpiration><NoncurrentDays>0</NoncurrentDays></NoncurrentVersionExpiration></Rule></LifecycleConfiguration>`, description: "NoncurrentDays must be positive"},
		{name: "retention limit", body: `<LifecycleConfiguration><Rule><Filter/><Status>Enabled</Status><NoncurrentVersionExpiration><NoncurrentDays>1</NoncurrentDays><NewerNoncurrentVersions>101</NewerNoncurrentVersions></NoncurrentVersionExpiration></Rule></LifecycleConfiguration>`, description: "NewerNoncurrentVersions must be between 1 and 100"},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			backendMock := lifecycleBackendMock()
			controller := S3ApiController{be: backendMock}
			testController(t, controller.PutBucketLifecycleConfiguration,
				lifecycleResponse("root", http.StatusOK), s3err.InvalidArgumentError{Description: test.description},
				ctxInputs{locals: defaultLocals, body: []byte(test.body)})
			assert.Empty(t, backendMock.PutLifecycleConfigurationCalls())
		})
	}
}

func TestGetBucketLifecycleConfiguration(t *testing.T) {
	t.Parallel()

	days := int32(7)
	backendMock := lifecycleBackendMock()
	backendMock.GetLifecycleConfigurationFunc = func(_ context.Context, bucket string) (lifecycle.Configuration, error) {
		assert.Equal(t, "bucket", bucket)
		return lifecycle.Configuration{TransitionDefaultMinimumObjectSize: lifecycle.TransitionMinimumVariesByStorageClass, Rules: []lifecycle.Rule{{
			Filter: &lifecycle.Filter{}, Status: "Enabled", Expiration: &lifecycle.Expiration{Days: &days},
		}}}, nil
	}
	controller := S3ApiController{be: backendMock}
	expected := lifecycleResponseWithTransitionMinimum("root", http.StatusOK, lifecycle.TransitionMinimumVariesByStorageClass)
	expected.Data = lifecycle.Configuration{XMLNS: lifecycle.Namespace, TransitionDefaultMinimumObjectSize: lifecycle.TransitionMinimumVariesByStorageClass, Rules: []lifecycle.Rule{{
		Filter: &lifecycle.Filter{}, Status: "Enabled", Expiration: &lifecycle.Expiration{Days: &days},
	}}}
	testController(t, controller.GetBucketLifecycleConfiguration, expected, nil, ctxInputs{locals: defaultLocals})
}

func TestPutBucketLifecycleConfigurationRejectsInvalidTransitionMinimum(t *testing.T) {
	t.Parallel()

	backendMock := lifecycleBackendMock()
	controller := S3ApiController{be: backendMock}
	body := []byte(`<LifecycleConfiguration><Rule><Filter/><Status>Enabled</Status><Expiration><Days>1</Days></Expiration></Rule></LifecycleConfiguration>`)
	testController(t, controller.PutBucketLifecycleConfiguration,
		lifecycleResponse("root", http.StatusOK), s3err.InvalidArgumentError{Description: `invalid transition default minimum object size "invalid"`},
		ctxInputs{locals: defaultLocals, body: body, headers: map[string]string{lifecycleTransitionMinimumHeader: "invalid"}})
	assert.Empty(t, backendMock.PutLifecycleConfigurationCalls())
}

func TestDeleteBucketLifecycle(t *testing.T) {
	t.Parallel()

	backendMock := lifecycleBackendMock()
	backendMock.DeleteLifecycleConfigurationFunc = func(_ context.Context, bucket string) error {
		assert.Equal(t, "bucket", bucket)
		return nil
	}
	controller := S3ApiController{be: backendMock}
	testController(t, controller.DeleteBucketLifecycle,
		lifecycleResponse("root", http.StatusNoContent), nil, ctxInputs{locals: defaultLocals})
}

func lifecycleBackendMock() *BackendMock {
	return &BackendMock{
		LifecycleCapabilitiesFunc:     func() lifecycle.Capabilities { return lifecycle.Capabilities{} },
		PutLifecycleConfigurationFunc: func(context.Context, string, lifecycle.Configuration) error { return nil },
		GetLifecycleConfigurationFunc: func(context.Context, string) (lifecycle.Configuration, error) {
			return lifecycle.Configuration{}, nil
		},
		DeleteLifecycleConfigurationFunc: func(context.Context, string) error { return nil },
		GetBucketPolicyFunc: func(context.Context, string) ([]byte, error) {
			return nil, s3err.GetAPIError(s3err.ErrAccessDenied)
		},
	}
}
