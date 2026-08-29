// Copyright 2026 Versity Software
// This file is licensed under the Apache License, Version 2.0.

package controllers

import (
	"errors"
	"net"
	"net/netip"

	"github.com/aws/aws-sdk-go-v2/service/s3/types"
	"github.com/gofiber/fiber/v3"
	"github.com/versity/versitygw/internal/encryption"
	"github.com/versity/versitygw/internal/httpctx"
	"github.com/versity/versitygw/s3api/utils"
	"github.com/versity/versitygw/s3err"
)

func encryptionHeaders(ctx fiber.Ctx, source bool) encryption.RequestHeaders {
	prefix := "x-amz-server-side-encryption"
	if source {
		prefix = "x-amz-copy-source-server-side-encryption"
	}
	headers := encryption.RequestHeaders{
		CustomerAlgorithm: ctx.Get(prefix + "-customer-algorithm"),
		CustomerKey:       ctx.Get(prefix + "-customer-key"),
		CustomerKeyMD5:    ctx.Get(prefix + "-customer-key-MD5"),
	}
	if !source {
		headers.Algorithm = ctx.Get("x-amz-server-side-encryption")
		headers.KMSKeyID = ctx.Get("x-amz-server-side-encryption-aws-kms-key-id")
		headers.KMSContext = ctx.Get("x-amz-server-side-encryption-context")
		headers.BucketKeyEnabled = ctx.Get("x-amz-server-side-encryption-bucket-key-enabled")
	}
	return headers
}

func (c S3ApiController) resolveWriteEncryption(ctx fiber.Ctx, bucket string) (*encryption.Intent, error) {
	return c.resolveWriteEncryptionHeaders(ctx, bucket, encryptionHeaders(ctx, false))
}

func (c S3ApiController) resolveWriteEncryptionHeaders(ctx fiber.Ctx, bucket string, headers encryption.RequestHeaders) (*encryption.Intent, error) {
	hasExplicitHeaders := headers.Algorithm != "" || headers.KMSKeyID != "" || headers.KMSContext != "" || headers.BucketKeyEnabled != "" || encryption.HasCustomerKeyHeaders(headers)
	activeBackend, active := c.be.(interface{ EncryptionActive() bool })
	if !active || !activeBackend.EncryptionActive() {
		if hasExplicitHeaders {
			return nil, s3err.GetAPIError(s3err.ErrNotImplemented)
		}
		return nil, nil
	}
	caps := c.be.EncryptionCapabilities()
	if !caps.SSES3 && !caps.SSEC && !caps.SSEKMS && !caps.DSSEKMS {
		if hasExplicitHeaders {
			return nil, s3err.GetAPIError(s3err.ErrNotImplemented)
		}
		return nil, nil
	}
	if encryption.HasCustomerKeyHeaders(headers) && !c.sseCSecureTransport(ctx) {
		return nil, s3err.GetAPIError(s3err.ErrInvalidRequest)
	}
	configuration, err := c.be.GetEncryptionConfiguration(ctx.RequestCtx(), bucket)
	if err != nil {
		return nil, err
	}
	intent, err := encryption.ResolveWriteIntent(headers, configuration, caps)
	if err != nil {
		return nil, encryptionRequestError(err)
	}
	return &intent, nil
}

func (c S3ApiController) parseReadCustomerEncryption(ctx fiber.Ctx, source bool) (*encryption.Intent, error) {
	headers := encryptionHeaders(ctx, source)
	if !encryption.HasCustomerKeyHeaders(headers) {
		return nil, nil
	}
	if !c.sseCSecureTransport(ctx) {
		return nil, s3err.GetAPIError(s3err.ErrInvalidRequest)
	}
	intent, err := encryption.ParseCustomerKeyHeaders(headers)
	if err != nil {
		return nil, encryptionRequestError(err)
	}
	return &intent, nil
}

func (c S3ApiController) sseCSecureTransport(ctx fiber.Ctx) bool {
	if secure, ok := httpctx.ContextKeySecureTransport.Get(ctx).(bool); ok {
		return secure
	}
	directTLS := ctx.RequestCtx().TLSConnectionState() != nil
	peer := immediatePeer(ctx.RequestCtx().RemoteAddr().String())
	return encryption.SecureTransport(directTLS, peer, ctx.Get("X-Forwarded-Proto"), c.trustedProxyPrefixes)
}

func immediatePeer(remote string) netip.Addr {
	host, _, err := net.SplitHostPort(remote)
	if err == nil {
		remote = host
	}
	address, _ := netip.ParseAddr(remote)
	return address.Unmap()
}

func encryptionRequestError(err error) error {
	if errors.Is(err, encryption.ErrSSECBlocked) {
		return s3err.GetAPIError(s3err.ErrAccessDenied)
	}
	if errors.Is(err, encryption.ErrUnsupportedEncryption) {
		return s3err.GetAPIError(s3err.ErrNotImplemented)
	}
	return s3err.GetAPIError(s3err.ErrInvalidRequest)
}

func encryptionResponseHeaders(result *encryption.Result) map[string]*string {
	if result == nil {
		return nil
	}
	headers := make(map[string]*string)
	switch result.Mode {
	case encryption.ModeSSES3:
		headers["x-amz-server-side-encryption"] = stringPtr(string(encryption.AlgorithmAES256))
	case encryption.ModeSSEKMS:
		headers["x-amz-server-side-encryption"] = stringPtr(string(encryption.AlgorithmAWSKMS))
		headers["x-amz-server-side-encryption-aws-kms-key-id"] = stringPtr(result.KMSKeyID)
	case encryption.ModeDSSEKMS:
		headers["x-amz-server-side-encryption"] = stringPtr(string(encryption.AlgorithmDSSEKMS))
		headers["x-amz-server-side-encryption-aws-kms-key-id"] = stringPtr(result.KMSKeyID)
	case encryption.ModeSSEC:
		headers["x-amz-server-side-encryption-customer-algorithm"] = stringPtr("AES256")
		headers["x-amz-server-side-encryption-customer-key-MD5"] = stringPtr(result.CustomerKeyMD5)
	}
	if result.BucketKeyEnabled {
		headers["x-amz-server-side-encryption-bucket-key-enabled"] = stringPtr("true")
	}
	return headers
}

func mergeResponseHeaders(base, additional map[string]*string) map[string]*string {
	if base == nil {
		base = make(map[string]*string, len(additional))
	}
	for key, value := range additional {
		base[key] = value
	}
	return base
}

func addObjectEncryptionHeaders(
	headers map[string]*string,
	algorithm types.ServerSideEncryption,
	kmsKeyID, customerAlgorithm, customerKeyMD5 *string,
	bucketKeyEnabled *bool,
) {
	if algorithm != "" {
		headers["x-amz-server-side-encryption"] = utils.ConvertToStringPtr(algorithm)
	}
	if kmsKeyID != nil {
		headers["x-amz-server-side-encryption-aws-kms-key-id"] = kmsKeyID
	}
	if customerAlgorithm != nil {
		headers["x-amz-server-side-encryption-customer-algorithm"] = customerAlgorithm
	}
	if customerKeyMD5 != nil {
		headers["x-amz-server-side-encryption-customer-key-MD5"] = customerKeyMD5
	}
	if bucketKeyEnabled != nil {
		headers["x-amz-server-side-encryption-bucket-key-enabled"] = utils.ConvertPtrToStringPtr(bucketKeyEnabled)
	}
}

func stringPtr(value string) *string {
	if value == "" {
		return nil
	}
	return &value
}

func boolPtrFromIntent(intent *encryption.Intent) *bool {
	if intent == nil {
		return nil
	}
	value := intent.BucketKeyEnabled
	return &value
}

func explicitBucketKeyPtr(rawHeader string, intent *encryption.Intent) *bool {
	if rawHeader == "" {
		return nil
	}
	return boolPtrFromIntent(intent)
}
