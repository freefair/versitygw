// Copyright 2026 Versity Software
// This file is licensed under the Apache License, Version 2.0.

package s3proxy

import (
	"context"

	"github.com/aws/aws-sdk-go-v2/service/s3"
	"github.com/aws/aws-sdk-go-v2/service/s3/types"
	"github.com/versity/versitygw/internal/lifecycle"
)

func (s *S3Proxy) LifecycleCapabilities() lifecycle.Capabilities {
	return lifecycle.Capabilities{Transitions: map[string]bool{
		"STANDARD_IA": true, "ONEZONE_IA": true, "INTELLIGENT_TIERING": true,
		"GLACIER_IR": true, "GLACIER": true, "DEEP_ARCHIVE": true,
	}}
}

func (s *S3Proxy) PutLifecycleConfiguration(ctx context.Context, bucket string, configuration lifecycle.Configuration) error {
	_, err := s.client.PutBucketLifecycleConfiguration(ctx, &s3.PutBucketLifecycleConfigurationInput{
		Bucket:                             &bucket,
		LifecycleConfiguration:             toSDKLifecycle(configuration),
		TransitionDefaultMinimumObjectSize: types.TransitionDefaultMinimumObjectSize(configuration.TransitionDefaultMinimumObjectSize),
	})
	return handleError(err)
}

func (s *S3Proxy) GetLifecycleConfiguration(ctx context.Context, bucket string) (lifecycle.Configuration, error) {
	output, err := s.client.GetBucketLifecycleConfiguration(ctx, &s3.GetBucketLifecycleConfigurationInput{Bucket: &bucket})
	if err != nil {
		return lifecycle.Configuration{}, handleError(err)
	}
	configuration := fromSDKLifecycle(output.Rules)
	configuration.TransitionDefaultMinimumObjectSize = string(output.TransitionDefaultMinimumObjectSize)
	minimum, err := lifecycle.NormalizeTransitionMinimum(configuration.TransitionDefaultMinimumObjectSize)
	if err != nil {
		return lifecycle.Configuration{}, err
	}
	configuration.TransitionDefaultMinimumObjectSize = minimum
	return configuration, nil
}

func (s *S3Proxy) DeleteLifecycleConfiguration(ctx context.Context, bucket string) error {
	_, err := s.client.DeleteBucketLifecycle(ctx, &s3.DeleteBucketLifecycleInput{Bucket: &bucket})
	return handleError(err)
}

func toSDKLifecycle(configuration lifecycle.Configuration) *types.BucketLifecycleConfiguration {
	rules := make([]types.LifecycleRule, 0, len(configuration.Rules))
	for _, source := range configuration.Rules {
		rule := types.LifecycleRule{
			ID:     source.ID,
			Prefix: source.Prefix,
			Status: types.ExpirationStatus(source.Status),
		}
		if source.Filter != nil {
			rule.Filter = toSDKLifecycleFilter(*source.Filter)
		}
		if source.Expiration != nil {
			rule.Expiration = &types.LifecycleExpiration{Days: source.Expiration.Days, ExpiredObjectDeleteMarker: source.Expiration.ExpiredObjectDeleteMarker}
			if source.Expiration.Date != nil {
				rule.Expiration.Date = &source.Expiration.Date.Time
			}
		}
		for _, sourceTransition := range source.Transitions {
			transition := types.Transition{Days: sourceTransition.Days, StorageClass: types.TransitionStorageClass(sourceTransition.StorageClass)}
			if sourceTransition.Date != nil {
				transition.Date = &sourceTransition.Date.Time
			}
			rule.Transitions = append(rule.Transitions, transition)
		}
		if source.NoncurrentVersionExpiration != nil {
			rule.NoncurrentVersionExpiration = &types.NoncurrentVersionExpiration{
				NoncurrentDays:          source.NoncurrentVersionExpiration.NoncurrentDays,
				NewerNoncurrentVersions: source.NoncurrentVersionExpiration.NewerNoncurrentVersions,
			}
		}
		for _, sourceTransition := range source.NoncurrentVersionTransitions {
			rule.NoncurrentVersionTransitions = append(rule.NoncurrentVersionTransitions, types.NoncurrentVersionTransition{
				NoncurrentDays: sourceTransition.NoncurrentDays, NewerNoncurrentVersions: sourceTransition.NewerNoncurrentVersions,
				StorageClass: types.TransitionStorageClass(sourceTransition.StorageClass),
			})
		}
		if source.AbortIncompleteMultipartUpload != nil {
			rule.AbortIncompleteMultipartUpload = &types.AbortIncompleteMultipartUpload{DaysAfterInitiation: source.AbortIncompleteMultipartUpload.DaysAfterInitiation}
		}
		rules = append(rules, rule)
	}
	return &types.BucketLifecycleConfiguration{Rules: rules}
}

func toSDKLifecycleFilter(source lifecycle.Filter) *types.LifecycleRuleFilter {
	filter := &types.LifecycleRuleFilter{
		Prefix: source.Prefix, ObjectSizeGreaterThan: source.ObjectSizeGreaterThan, ObjectSizeLessThan: source.ObjectSizeLessThan,
	}
	if source.Tag != nil {
		filter.Tag = &types.Tag{Key: &source.Tag.Key, Value: &source.Tag.Value}
	}
	if source.And != nil {
		filter.And = &types.LifecycleRuleAndOperator{
			Prefix: source.And.Prefix, ObjectSizeGreaterThan: source.And.ObjectSizeGreaterThan, ObjectSizeLessThan: source.And.ObjectSizeLessThan,
		}
		for index := range source.And.Tags {
			tag := source.And.Tags[index]
			filter.And.Tags = append(filter.And.Tags, types.Tag{Key: &tag.Key, Value: &tag.Value})
		}
	}
	return filter
}

func fromSDKLifecycle(rules []types.LifecycleRule) lifecycle.Configuration {
	configuration := lifecycle.Configuration{XMLNS: lifecycle.Namespace, Rules: make([]lifecycle.Rule, 0, len(rules))}
	for _, source := range rules {
		rule := lifecycle.Rule{ID: source.ID, Prefix: source.Prefix, Status: string(source.Status)}
		if source.Filter != nil {
			rule.Filter = fromSDKLifecycleFilter(*source.Filter)
		}
		if source.Expiration != nil {
			rule.Expiration = &lifecycle.Expiration{Days: source.Expiration.Days, ExpiredObjectDeleteMarker: source.Expiration.ExpiredObjectDeleteMarker}
			if source.Expiration.Date != nil {
				rule.Expiration.Date = &lifecycle.Date{Time: *source.Expiration.Date}
			}
		}
		for _, sourceTransition := range source.Transitions {
			transition := lifecycle.Transition{Days: sourceTransition.Days, StorageClass: string(sourceTransition.StorageClass)}
			if sourceTransition.Date != nil {
				transition.Date = &lifecycle.Date{Time: *sourceTransition.Date}
			}
			rule.Transitions = append(rule.Transitions, transition)
		}
		if source.NoncurrentVersionExpiration != nil {
			rule.NoncurrentVersionExpiration = &lifecycle.NoncurrentVersionExpiration{
				NoncurrentDays:          source.NoncurrentVersionExpiration.NoncurrentDays,
				NewerNoncurrentVersions: source.NoncurrentVersionExpiration.NewerNoncurrentVersions,
			}
		}
		for _, sourceTransition := range source.NoncurrentVersionTransitions {
			rule.NoncurrentVersionTransitions = append(rule.NoncurrentVersionTransitions, lifecycle.NoncurrentVersionTransition{
				NoncurrentDays: sourceTransition.NoncurrentDays, NewerNoncurrentVersions: sourceTransition.NewerNoncurrentVersions,
				StorageClass: string(sourceTransition.StorageClass),
			})
		}
		if source.AbortIncompleteMultipartUpload != nil {
			rule.AbortIncompleteMultipartUpload = &lifecycle.AbortIncompleteMultipartUpload{DaysAfterInitiation: source.AbortIncompleteMultipartUpload.DaysAfterInitiation}
		}
		configuration.Rules = append(configuration.Rules, rule)
	}
	return configuration
}

func fromSDKLifecycleFilter(source types.LifecycleRuleFilter) *lifecycle.Filter {
	filter := &lifecycle.Filter{Prefix: source.Prefix, ObjectSizeGreaterThan: source.ObjectSizeGreaterThan, ObjectSizeLessThan: source.ObjectSizeLessThan}
	if source.Tag != nil && source.Tag.Key != nil && source.Tag.Value != nil {
		filter.Tag = &lifecycle.Tag{Key: *source.Tag.Key, Value: *source.Tag.Value}
	}
	if source.And != nil {
		filter.And = &lifecycle.AndOperator{Prefix: source.And.Prefix, ObjectSizeGreaterThan: source.And.ObjectSizeGreaterThan, ObjectSizeLessThan: source.And.ObjectSizeLessThan}
		for _, sourceTag := range source.And.Tags {
			if sourceTag.Key != nil && sourceTag.Value != nil {
				filter.And.Tags = append(filter.And.Tags, lifecycle.Tag{Key: *sourceTag.Key, Value: *sourceTag.Value})
			}
		}
	}
	return filter
}
