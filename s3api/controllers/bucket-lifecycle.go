// Copyright 2026 Versity Software
// This file is licensed under the Apache License, Version 2.0.

package controllers

import (
	"errors"
	"net/http"

	"github.com/gofiber/fiber/v3"
	"github.com/versity/versitygw/auth"
	"github.com/versity/versitygw/internal/lifecycle"
	"github.com/versity/versitygw/s3api/utils"
	"github.com/versity/versitygw/s3err"
)

const lifecycleTransitionMinimumHeader = "x-amz-transition-default-minimum-object-size"

func (c S3ApiController) PutBucketLifecycleConfiguration(ctx fiber.Ctx) (*Response, error) {
	bucket, owner, err := c.authorizeLifecycle(ctx, auth.PutLifecycleConfigurationAction, auth.PermissionWrite)
	if err != nil {
		return lifecycleResponse(owner, http.StatusOK), err
	}
	configuration, err := lifecycle.Parse(ctx.BodyRaw(), c.be.LifecycleCapabilities())
	if err != nil {
		return lifecycleResponse(owner, http.StatusOK), lifecycleS3Error(err)
	}
	minimum, err := lifecycle.NormalizeTransitionMinimum(ctx.Get(lifecycleTransitionMinimumHeader))
	if err != nil {
		return lifecycleResponse(owner, http.StatusOK), lifecycleS3Error(err)
	}
	configuration.TransitionDefaultMinimumObjectSize = minimum
	err = c.be.PutLifecycleConfiguration(ctx.RequestCtx(), bucket, configuration)
	return lifecycleResponseWithTransitionMinimum(owner, http.StatusOK, minimum), err
}

func (c S3ApiController) GetBucketLifecycleConfiguration(ctx fiber.Ctx) (*Response, error) {
	bucket, owner, err := c.authorizeLifecycle(ctx, auth.GetLifecycleConfigurationAction, auth.PermissionRead)
	if err != nil {
		return lifecycleResponse(owner, http.StatusOK), err
	}
	configuration, err := c.be.GetLifecycleConfiguration(ctx.RequestCtx(), bucket)
	if err != nil {
		return lifecycleResponse(owner, http.StatusOK), err
	}
	configuration.XMLNS = lifecycle.Namespace
	minimum, normalizeErr := lifecycle.NormalizeTransitionMinimum(configuration.TransitionDefaultMinimumObjectSize)
	if normalizeErr != nil {
		return lifecycleResponse(owner, http.StatusOK), lifecycleS3Error(normalizeErr)
	}
	configuration.TransitionDefaultMinimumObjectSize = minimum
	response := lifecycleResponseWithTransitionMinimum(owner, http.StatusOK, minimum)
	response.Data = configuration
	return response, nil
}

func (c S3ApiController) DeleteBucketLifecycle(ctx fiber.Ctx) (*Response, error) {
	bucket, owner, err := c.authorizeLifecycle(ctx, auth.PutLifecycleConfigurationAction, auth.PermissionWrite)
	if err != nil {
		return lifecycleResponse(owner, http.StatusNoContent), err
	}
	err = c.be.DeleteLifecycleConfiguration(ctx.RequestCtx(), bucket)
	return lifecycleResponse(owner, http.StatusNoContent), err
}

func (c S3ApiController) authorizeLifecycle(ctx fiber.Ctx, action auth.Action, permission auth.Permission) (string, string, error) {
	bucket := ctx.Params("bucket")
	account := utils.ContextKeyAccount.Get(ctx).(auth.Account)
	isRoot := utils.ContextKeyIsRoot.Get(ctx).(bool)
	isPublic := utils.ContextKeyPublicBucket.IsSet(ctx)
	acl := utils.ContextKeyParsedAcl.Get(ctx).(auth.ACL)
	err := c.verifyAccess(ctx, auth.AccessOptions{
		Acl:             acl,
		AclPermission:   permission,
		IsRoot:          isRoot,
		Acc:             account,
		Bucket:          bucket,
		Actions:         []auth.Action{action},
		IsPublicRequest: isPublic,
	})
	return bucket, acl.Owner, err
}

func lifecycleResponse(owner string, status int) *Response {
	return &Response{MetaOpts: &MetaOptions{BucketOwner: owner, Status: status}}
}

func lifecycleResponseWithTransitionMinimum(owner string, status int, minimum string) *Response {
	return &Response{
		Headers:  map[string]*string{lifecycleTransitionMinimumHeader: &minimum},
		MetaOpts: &MetaOptions{BucketOwner: owner, Status: status},
	}
}

func lifecycleS3Error(err error) error {
	var validationError lifecycle.ValidationError
	if !errors.As(err, &validationError) {
		return err
	}
	switch validationError.Kind {
	case lifecycle.ErrorMalformedXML:
		return s3err.GetAPIError(s3err.ErrMalformedXML)
	case lifecycle.ErrorInvalidArgument:
		return s3err.InvalidArgumentError{Description: validationError.Message}
	default:
		return s3err.GetAPIError(s3err.ErrInvalidRequest)
	}
}
