// Copyright 2026 Versity Software
// This file is licensed under the Apache License, Version 2.0.

package integration

import (
	"context"
	"fmt"

	"github.com/aws/aws-sdk-go-v2/service/s3"
	"github.com/aws/aws-sdk-go-v2/service/s3/types"
	"github.com/versity/versitygw/s3err"
)

func PutBucketLifecycleConfiguration_success(s *S3Conf) error {
	return actionHandler(s, "PutBucketLifecycleConfiguration_success", func(client *s3.Client, bucket string) error {
		ctx, cancel := context.WithTimeout(context.Background(), shortTimeout)
		defer cancel()
		output, err := client.PutBucketLifecycleConfiguration(ctx, lifecycleConfigurationInput(bucket))
		if err != nil {
			return err
		}
		if output.TransitionDefaultMinimumObjectSize != types.TransitionDefaultMinimumObjectSizeAllStorageClasses128k {
			return fmt.Errorf("transition default minimum object size = %q", output.TransitionDefaultMinimumObjectSize)
		}
		return nil
	})
}

func GetBucketLifecycleConfiguration_success(s *S3Conf) error {
	return actionHandler(s, "GetBucketLifecycleConfiguration_success", func(client *s3.Client, bucket string) error {
		ctx, cancel := context.WithTimeout(context.Background(), shortTimeout)
		defer cancel()
		if _, err := client.PutBucketLifecycleConfiguration(ctx, lifecycleConfigurationInput(bucket)); err != nil {
			return err
		}
		output, err := client.GetBucketLifecycleConfiguration(ctx, &s3.GetBucketLifecycleConfigurationInput{Bucket: &bucket})
		if err != nil {
			return err
		}
		if len(output.Rules) != 1 || output.Rules[0].ID == nil || *output.Rules[0].ID != "expire-objects" || output.Rules[0].Expiration == nil || output.Rules[0].Expiration.Days == nil || *output.Rules[0].Expiration.Days != 30 {
			return fmt.Errorf("unexpected lifecycle configuration: %#v", output.Rules)
		}
		if output.TransitionDefaultMinimumObjectSize != types.TransitionDefaultMinimumObjectSizeAllStorageClasses128k {
			return fmt.Errorf("transition default minimum object size = %q", output.TransitionDefaultMinimumObjectSize)
		}
		return nil
	})
}

func DeleteBucketLifecycle_success(s *S3Conf) error {
	return actionHandler(s, "DeleteBucketLifecycle_success", func(client *s3.Client, bucket string) error {
		ctx, cancel := context.WithTimeout(context.Background(), shortTimeout)
		defer cancel()
		if _, err := client.PutBucketLifecycleConfiguration(ctx, lifecycleConfigurationInput(bucket)); err != nil {
			return err
		}
		if _, err := client.DeleteBucketLifecycle(ctx, &s3.DeleteBucketLifecycleInput{Bucket: &bucket}); err != nil {
			return err
		}
		_, err := client.GetBucketLifecycleConfiguration(ctx, &s3.GetBucketLifecycleConfigurationInput{Bucket: &bucket})
		return checkApiErr(err, s3err.GetAPIError(s3err.ErrNoSuchLifecycleConfiguration))
	})
}

func lifecycleConfigurationInput(bucket string) *s3.PutBucketLifecycleConfigurationInput {
	days := int32(30)
	prefix := ""
	id := "expire-objects"
	return &s3.PutBucketLifecycleConfigurationInput{
		Bucket: &bucket,
		LifecycleConfiguration: &types.BucketLifecycleConfiguration{Rules: []types.LifecycleRule{{
			ID: &id, Status: types.ExpirationStatusEnabled,
			Filter:     &types.LifecycleRuleFilter{Prefix: &prefix},
			Expiration: &types.LifecycleExpiration{Days: &days},
		}}},
		TransitionDefaultMinimumObjectSize: types.TransitionDefaultMinimumObjectSizeAllStorageClasses128k,
	}
}
