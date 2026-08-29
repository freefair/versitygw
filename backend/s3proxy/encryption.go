// Copyright 2026 Versity Software
// This file is licensed under the Apache License, Version 2.0.

package s3proxy

import (
	"context"

	"github.com/aws/aws-sdk-go-v2/service/s3"
	"github.com/aws/aws-sdk-go-v2/service/s3/types"
	"github.com/versity/versitygw/internal/encryption"
)

func (s *S3Proxy) EncryptionCapabilities() encryption.Capabilities {
	if s.gcsCompatibility {
		return encryption.Capabilities{}
	}
	return encryption.Capabilities{SSES3: true, SSEC: true, SSEKMS: true, DSSEKMS: true, BucketKeys: true, NativePassthrough: true}
}

func (s *S3Proxy) EncryptionActive() bool { return !s.gcsCompatibility }

func (s *S3Proxy) PutEncryptionConfiguration(ctx context.Context, bucket string, configuration encryption.Configuration) error {
	_, err := s.client.PutBucketEncryption(ctx, &s3.PutBucketEncryptionInput{
		Bucket:                            &bucket,
		ServerSideEncryptionConfiguration: toSDKEncryption(configuration),
	})
	return handleError(err)
}

func (s *S3Proxy) GetEncryptionConfiguration(ctx context.Context, bucket string) (encryption.Configuration, error) {
	output, err := s.client.GetBucketEncryption(ctx, &s3.GetBucketEncryptionInput{Bucket: &bucket})
	if err != nil {
		return encryption.Configuration{}, handleError(err)
	}
	if output.ServerSideEncryptionConfiguration == nil {
		return encryption.Configuration{}, encryption.ErrInvalidConfiguration
	}
	return fromSDKEncryption(output.ServerSideEncryptionConfiguration), nil
}

func (s *S3Proxy) DeleteEncryptionConfiguration(ctx context.Context, bucket string) error {
	_, err := s.client.DeleteBucketEncryption(ctx, &s3.DeleteBucketEncryptionInput{Bucket: &bucket})
	return handleError(err)
}

func toSDKEncryption(configuration encryption.Configuration) *types.ServerSideEncryptionConfiguration {
	rules := make([]types.ServerSideEncryptionRule, 0, len(configuration.Rules))
	for _, source := range configuration.Rules {
		rule := types.ServerSideEncryptionRule{BucketKeyEnabled: source.BucketKeyEnabled}
		if source.Default != nil {
			rule.ApplyServerSideEncryptionByDefault = &types.ServerSideEncryptionByDefault{
				SSEAlgorithm:   types.ServerSideEncryption(source.Default.Algorithm),
				KMSMasterKeyID: stringPointer(source.Default.KMSKeyID),
			}
		}
		if source.BlockedEncryptionTypes != nil {
			rule.BlockedEncryptionTypes = &types.BlockedEncryptionTypes{}
			for _, value := range source.BlockedEncryptionTypes.Types {
				rule.BlockedEncryptionTypes.EncryptionType = append(rule.BlockedEncryptionTypes.EncryptionType, types.EncryptionType(value))
			}
		}
		rules = append(rules, rule)
	}
	return &types.ServerSideEncryptionConfiguration{Rules: rules}
}

func fromSDKEncryption(configuration *types.ServerSideEncryptionConfiguration) encryption.Configuration {
	result := encryption.Configuration{Rules: make([]encryption.Rule, 0, len(configuration.Rules))}
	for _, source := range configuration.Rules {
		rule := encryption.Rule{BucketKeyEnabled: source.BucketKeyEnabled}
		if source.ApplyServerSideEncryptionByDefault != nil {
			rule.Default = &encryption.DefaultEncryption{Algorithm: encryption.Algorithm(source.ApplyServerSideEncryptionByDefault.SSEAlgorithm)}
			if source.ApplyServerSideEncryptionByDefault.KMSMasterKeyID != nil {
				rule.Default.KMSKeyID = *source.ApplyServerSideEncryptionByDefault.KMSMasterKeyID
			}
		}
		if source.BlockedEncryptionTypes != nil {
			rule.BlockedEncryptionTypes = &encryption.BlockedEncryptionTypes{}
			for _, value := range source.BlockedEncryptionTypes.EncryptionType {
				rule.BlockedEncryptionTypes.Types = append(rule.BlockedEncryptionTypes.Types, string(value))
			}
		}
		result.Rules = append(result.Rules, rule)
	}
	return result
}

func stringPointer(value string) *string {
	if value == "" {
		return nil
	}
	return &value
}

func encryptionResultFromPut(output *s3.PutObjectOutput) *encryption.Result {
	if output == nil {
		return nil
	}
	result := &encryption.Result{BucketKeyEnabled: output.BucketKeyEnabled != nil && *output.BucketKeyEnabled}
	if output.SSEKMSKeyId != nil {
		result.KMSKeyID = *output.SSEKMSKeyId
	}
	if output.SSECustomerAlgorithm != nil {
		result.Mode = encryption.ModeSSEC
		if output.SSECustomerKeyMD5 != nil {
			result.CustomerKeyMD5 = *output.SSECustomerKeyMD5
		}
		return result
	}
	switch output.ServerSideEncryption {
	case types.ServerSideEncryptionAes256:
		result.Mode = encryption.ModeSSES3
	case types.ServerSideEncryptionAwsKms:
		result.Mode = encryption.ModeSSEKMS
	case types.ServerSideEncryptionAwsKmsDsse:
		result.Mode = encryption.ModeDSSEKMS
	default:
		return nil
	}
	return result
}

func encryptionResultFromValues(algorithm types.ServerSideEncryption, kmsKeyID, customerAlgorithm, customerKeyMD5 *string, bucketKeyEnabled *bool) *encryption.Result {
	result := &encryption.Result{BucketKeyEnabled: bucketKeyEnabled != nil && *bucketKeyEnabled}
	if kmsKeyID != nil {
		result.KMSKeyID = *kmsKeyID
	}
	if customerAlgorithm != nil {
		result.Mode = encryption.ModeSSEC
		if customerKeyMD5 != nil {
			result.CustomerKeyMD5 = *customerKeyMD5
		}
		return result
	}
	switch algorithm {
	case types.ServerSideEncryptionAes256:
		result.Mode = encryption.ModeSSES3
	case types.ServerSideEncryptionAwsKms:
		result.Mode = encryption.ModeSSEKMS
	case types.ServerSideEncryptionAwsKmsDsse:
		result.Mode = encryption.ModeDSSEKMS
	default:
		return nil
	}
	return result
}
