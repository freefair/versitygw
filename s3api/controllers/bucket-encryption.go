// Copyright 2026 Versity Software
// This file is licensed under the Apache License, Version 2.0.

package controllers

import (
	"errors"
	"net/http"

	"github.com/gofiber/fiber/v3"
	"github.com/versity/versitygw/auth"
	"github.com/versity/versitygw/internal/encryption"
	"github.com/versity/versitygw/s3api/utils"
	"github.com/versity/versitygw/s3err"
)

func (c S3ApiController) PutBucketEncryption(ctx fiber.Ctx) (*Response, error) {
	bucket, owner, err := c.authorizeEncryption(ctx, auth.PutEncryptionConfigurationAction, auth.PermissionWrite)
	if err != nil {
		return encryptionResponse(owner, http.StatusOK), err
	}
	configuration, err := encryption.ParseConfiguration(ctx.BodyRaw())
	if err != nil {
		return encryptionResponse(owner, http.StatusOK), s3err.GetAPIError(s3err.ErrMalformedXML)
	}
	configuration, err = encryption.ValidateConfiguration(configuration, c.be.EncryptionCapabilities())
	if err != nil {
		return encryptionResponse(owner, http.StatusOK), encryptionS3Error(err)
	}
	err = c.be.PutEncryptionConfiguration(ctx.RequestCtx(), bucket, configuration)
	return encryptionResponse(owner, http.StatusOK), err
}

func (c S3ApiController) GetBucketEncryption(ctx fiber.Ctx) (*Response, error) {
	bucket, owner, err := c.authorizeEncryption(ctx, auth.GetEncryptionConfigurationAction, auth.PermissionRead)
	if err != nil {
		return encryptionResponse(owner, http.StatusOK), err
	}
	configuration, err := c.be.GetEncryptionConfiguration(ctx.RequestCtx(), bucket)
	if err != nil {
		return encryptionResponse(owner, http.StatusOK), err
	}
	configuration.XMLNS = encryption.Namespace
	response := encryptionResponse(owner, http.StatusOK)
	response.Data = configuration
	return response, nil
}

func (c S3ApiController) DeleteBucketEncryption(ctx fiber.Ctx) (*Response, error) {
	bucket, owner, err := c.authorizeEncryption(ctx, auth.PutEncryptionConfigurationAction, auth.PermissionWrite)
	if err != nil {
		return encryptionResponse(owner, http.StatusNoContent), err
	}
	err = c.be.DeleteEncryptionConfiguration(ctx.RequestCtx(), bucket)
	return encryptionResponse(owner, http.StatusNoContent), err
}

func (c S3ApiController) authorizeEncryption(ctx fiber.Ctx, action auth.Action, permission auth.Permission) (string, string, error) {
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

func encryptionResponse(owner string, status int) *Response {
	return &Response{MetaOpts: &MetaOptions{BucketOwner: owner, Status: status}}
}

func encryptionS3Error(err error) error {
	if errors.Is(err, encryption.ErrUnsupportedEncryption) {
		return s3err.GetAPIError(s3err.ErrNotImplemented)
	}
	return s3err.GetAPIError(s3err.ErrInvalidRequest)
}
