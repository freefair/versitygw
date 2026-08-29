// Copyright 2026 Versity Software
// This file is licensed under the Apache License, Version 2.0.

package integration

import (
	"bytes"
	"context"
	"crypto/md5"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/s3"
	"github.com/aws/aws-sdk-go-v2/service/s3/types"
)

func ObjectEncryption_round_trip_copy_and_multipart(s *S3Conf) error {
	return actionHandler(s, "ObjectEncryption_round_trip_copy_and_multipart", func(client *s3.Client, bucket string) error {
		ctx, cancel := context.WithTimeout(context.Background(), 4*shortTimeout)
		defer cancel()
		if _, err := client.PutBucketEncryption(ctx, bucketEncryptionInput(bucket)); err != nil {
			return err
		}

		payload := []byte("backend-owned envelope encryption payload")
		key := "encrypted/source"
		put, err := client.PutObject(ctx, &s3.PutObjectInput{Bucket: &bucket, Key: &key, Body: bytes.NewReader(payload), ContentLength: aws.Int64(int64(len(payload))), Tagging: aws.String("keep=yes")})
		if err != nil {
			return err
		}
		if put.ServerSideEncryption != types.ServerSideEncryptionAes256 {
			return fmt.Errorf("PUT encryption = %q, want AES256", put.ServerSideEncryption)
		}
		rangeHeader := "bytes=8-22"
		got, err := client.GetObject(ctx, &s3.GetObjectInput{Bucket: &bucket, Key: &key, Range: &rangeHeader})
		if err != nil {
			return err
		}
		rangeBody, readErr := io.ReadAll(got.Body)
		closeErr := got.Body.Close()
		if readErr != nil {
			return readErr
		}
		if closeErr != nil {
			return closeErr
		}
		if !bytes.Equal(rangeBody, payload[8:23]) || got.ServerSideEncryption != types.ServerSideEncryptionAes256 {
			return fmt.Errorf("encrypted range = %q, encryption=%q", rangeBody, got.ServerSideEncryption)
		}

		copyKey := "encrypted/copy"
		copySource := bucket + "/" + key
		copyOutput, err := client.CopyObject(ctx, &s3.CopyObjectInput{Bucket: &bucket, Key: &copyKey, CopySource: &copySource})
		if err != nil {
			return err
		}
		if copyOutput.ServerSideEncryption != types.ServerSideEncryptionAes256 {
			return fmt.Errorf("COPY encryption = %q, want AES256", copyOutput.ServerSideEncryption)
		}
		if _, err := client.CopyObject(ctx, &s3.CopyObjectInput{
			Bucket: &bucket, Key: &key, CopySource: &copySource,
			MetadataDirective: types.MetadataDirectiveReplace, TaggingDirective: types.TaggingDirectiveCopy,
		}); err != nil {
			return err
		}
		copiedTags, err := client.GetObjectTagging(ctx, &s3.GetObjectTaggingInput{Bucket: &bucket, Key: &key})
		if err != nil {
			return err
		}
		if len(copiedTags.TagSet) != 1 || aws.ToString(copiedTags.TagSet[0].Key) != "keep" || aws.ToString(copiedTags.TagSet[0].Value) != "yes" {
			return fmt.Errorf("encrypted self-copy tags = %#v", copiedTags.TagSet)
		}
		if _, err := client.CopyObject(ctx, &s3.CopyObjectInput{
			Bucket: &bucket, Key: &key, CopySource: &copySource,
			ServerSideEncryption: types.ServerSideEncryptionAwsKms,
		}); err != nil {
			return fmt.Errorf("encryption-only self-copy: %w", err)
		}

		multipartKey := "encrypted/multipart"
		created, err := client.CreateMultipartUpload(ctx, &s3.CreateMultipartUploadInput{Bucket: &bucket, Key: &multipartKey})
		if err != nil {
			return err
		}
		first := bytes.Repeat([]byte("a"), 5*1024*1024)
		part1 := int32(1)
		part2 := int32(2)
		part3 := int32(3)
		uploaded1, err := client.UploadPart(ctx, &s3.UploadPartInput{Bucket: &bucket, Key: &multipartKey, UploadId: created.UploadId, PartNumber: &part1, Body: bytes.NewReader(first), ContentLength: aws.Int64(int64(len(first)))})
		if err != nil {
			return err
		}
		uploaded2, err := client.UploadPartCopy(ctx, &s3.UploadPartCopyInput{
			Bucket: &bucket, Key: &multipartKey, UploadId: created.UploadId, PartNumber: &part2,
			CopySource: &copySource,
		})
		if err != nil {
			return err
		}
		unused := []byte("unused uploaded part")
		unusedFirst, err := client.UploadPart(ctx, &s3.UploadPartInput{
			Bucket: &bucket, Key: &multipartKey, UploadId: created.UploadId, PartNumber: &part3,
			Body: bytes.NewReader(unused), ContentLength: aws.Int64(int64(len(unused))),
		})
		if err != nil {
			return err
		}
		unusedReplacement := []byte("replacement unused part")
		unusedSecond, err := client.UploadPart(ctx, &s3.UploadPartInput{
			Bucket: &bucket, Key: &multipartKey, UploadId: created.UploadId, PartNumber: &part3,
			Body: bytes.NewReader(unusedReplacement), ContentLength: aws.Int64(int64(len(unusedReplacement))),
		})
		if err != nil {
			return err
		}
		if aws.ToString(unusedFirst.ETag) == aws.ToString(unusedSecond.ETag) {
			return fmt.Errorf("reuploaded encrypted part retained stale ETag %q", aws.ToString(unusedFirst.ETag))
		}
		listed, err := client.ListParts(ctx, &s3.ListPartsInput{Bucket: &bucket, Key: &multipartKey, UploadId: created.UploadId})
		if err != nil {
			return err
		}
		if len(listed.Parts) != 3 || listed.Parts[0].Size == nil || *listed.Parts[0].Size != int64(len(first)) || listed.Parts[1].Size == nil || *listed.Parts[1].Size != int64(len(payload)) {
			return fmt.Errorf("encrypted ListParts = %#v", listed.Parts)
		}
		completed, err := client.CompleteMultipartUpload(ctx, &s3.CompleteMultipartUploadInput{
			Bucket: &bucket, Key: &multipartKey, UploadId: created.UploadId,
			MultipartUpload: &types.CompletedMultipartUpload{Parts: []types.CompletedPart{
				{PartNumber: &part1, ETag: uploaded1.ETag}, {PartNumber: &part2, ETag: uploaded2.CopyPartResult.ETag},
			}},
		})
		if err != nil {
			return err
		}
		if completed.ServerSideEncryption != types.ServerSideEncryptionAes256 {
			return fmt.Errorf("multipart encryption = %q, want AES256", completed.ServerSideEncryption)
		}
		multipart, err := client.GetObject(ctx, &s3.GetObjectInput{Bucket: &bucket, Key: &multipartKey})
		if err != nil {
			return err
		}
		multipartBody, readErr := io.ReadAll(multipart.Body)
		_ = multipart.Body.Close()
		if readErr != nil {
			return readErr
		}
		if !bytes.Equal(multipartBody, append(first, payload...)) {
			return fmt.Errorf("multipart plaintext mismatch: got %d bytes", len(multipartBody))
		}

		abortUpload, err := client.CreateMultipartUpload(ctx, &s3.CreateMultipartUploadInput{Bucket: &bucket, Key: &copyKey})
		if err != nil {
			return err
		}
		if _, err := client.UploadPart(ctx, &s3.UploadPartInput{
			Bucket: &bucket, Key: &copyKey, UploadId: abortUpload.UploadId, PartNumber: &part1,
			Body: bytes.NewReader(payload), ContentLength: aws.Int64(int64(len(payload))),
		}); err != nil {
			return err
		}
		if _, err := client.AbortMultipartUpload(ctx, &s3.AbortMultipartUploadInput{Bucket: &bucket, Key: &copyKey, UploadId: abortUpload.UploadId}); err != nil {
			return err
		}
		copyAfterAbort, err := client.GetObject(ctx, &s3.GetObjectInput{Bucket: &bucket, Key: &copyKey})
		if err != nil {
			return fmt.Errorf("read existing object after encrypted multipart abort: %w", err)
		}
		copyBody, readErr := io.ReadAll(copyAfterAbort.Body)
		_ = copyAfterAbort.Body.Close()
		if readErr != nil || !bytes.Equal(copyBody, payload) {
			return fmt.Errorf("encrypted multipart abort changed destination: body=%q err=%v", copyBody, readErr)
		}
		return nil
	})
}

func ObjectEncryption_browser_post(s *S3Conf) error {
	return actionHandler(s, "ObjectEncryption_browser_post", func(client *s3.Client, bucket string) error {
		ctx, cancel := context.WithTimeout(context.Background(), shortTimeout)
		defer cancel()
		if _, err := client.PutBucketEncryption(ctx, bucketEncryptionInput(bucket)); err != nil {
			return err
		}
		key := "encrypted/browser-post"
		payload := bytes.Repeat([]byte("encrypted-browser-post-payload-"), 4096)
		const field = "x-amz-server-side-encryption"
		resp, err := sendPostObject(PostRequestConfig{
			bucket: bucket, key: key, s3Conf: s, fileContent: payload,
			extraFields:      map[string]string{field: string(types.ServerSideEncryptionAes256)},
			policyConditions: []any{map[string]string{field: string(types.ServerSideEncryptionAes256)}},
		})
		if err != nil {
			return err
		}
		defer resp.Body.Close()
		if resp.StatusCode != http.StatusNoContent || resp.Header.Get("x-amz-server-side-encryption") != string(types.ServerSideEncryptionAes256) {
			return fmt.Errorf("encrypted browser POST status=%d encryption=%q", resp.StatusCode, resp.Header.Get("x-amz-server-side-encryption"))
		}
		got, err := client.GetObject(ctx, &s3.GetObjectInput{Bucket: &bucket, Key: &key})
		if err != nil {
			return err
		}
		body, readErr := io.ReadAll(got.Body)
		closeErr := got.Body.Close()
		if readErr != nil || closeErr != nil {
			return errors.Join(readErr, closeErr)
		}
		if !bytes.Equal(body, payload) || got.ServerSideEncryption != types.ServerSideEncryptionAes256 {
			return fmt.Errorf("encrypted browser POST body match=%t encryption=%q", bytes.Equal(body, payload), got.ServerSideEncryption)
		}
		return nil
	})
}

func ObjectEncryption_sse_c_round_trip(s *S3Conf) error {
	if !strings.HasPrefix(s.endpoint, "https://") {
		runF("ObjectEncryption_sse_c_round_trip")
		skipF("ObjectEncryption_sse_c_round_trip: SSE-C requires TLS")
		return nil
	}
	return actionHandler(s, "ObjectEncryption_sse_c_round_trip", func(client *s3.Client, bucket string) error {
		ctx, cancel := context.WithTimeout(context.Background(), shortTimeout)
		defer cancel()
		if _, err := client.PutBucketEncryption(ctx, bucketEncryptionInput(bucket)); err != nil {
			return err
		}
		customerKey := bytes.Repeat([]byte{0x5a}, 32)
		customerKeyBase64 := base64.StdEncoding.EncodeToString(customerKey)
		digest := md5.Sum(customerKey)
		customerKeyMD5 := base64.StdEncoding.EncodeToString(digest[:])
		algorithm := "AES256"
		key := "encrypted/sse-c"
		payload := []byte("customer-provided encryption key")
		_, err := client.PutObject(ctx, &s3.PutObjectInput{
			Bucket: &bucket, Key: &key, Body: bytes.NewReader(payload), ContentLength: aws.Int64(int64(len(payload))),
			SSECustomerAlgorithm: &algorithm, SSECustomerKey: &customerKeyBase64, SSECustomerKeyMD5: &customerKeyMD5,
		})
		if err != nil {
			return err
		}
		if _, err := client.GetObject(ctx, &s3.GetObjectInput{Bucket: &bucket, Key: &key}); err == nil {
			return fmt.Errorf("SSE-C GET without a customer key succeeded")
		}
		got, err := client.GetObject(ctx, &s3.GetObjectInput{
			Bucket: &bucket, Key: &key, SSECustomerAlgorithm: &algorithm,
			SSECustomerKey: &customerKeyBase64, SSECustomerKeyMD5: &customerKeyMD5,
		})
		if err != nil {
			return err
		}
		body, readErr := io.ReadAll(got.Body)
		_ = got.Body.Close()
		if readErr != nil {
			return readErr
		}
		if !bytes.Equal(body, payload) || got.SSECustomerAlgorithm == nil || *got.SSECustomerAlgorithm != algorithm {
			return fmt.Errorf("SSE-C GET payload=%q algorithm=%v", body, got.SSECustomerAlgorithm)
		}
		return nil
	})
}

func ObjectEncryption_local_kms_modes(s *S3Conf) error {
	return actionHandler(s, "ObjectEncryption_local_kms_modes", func(client *s3.Client, bucket string) error {
		ctx, cancel := context.WithTimeout(context.Background(), shortTimeout)
		defer cancel()
		if _, err := client.PutBucketEncryption(ctx, bucketEncryptionInput(bucket)); err != nil {
			return err
		}
		for _, algorithm := range []types.ServerSideEncryption{
			types.ServerSideEncryptionAwsKms,
			types.ServerSideEncryptionAwsKmsDsse,
		} {
			key := "encrypted/" + string(algorithm)
			payload := []byte("local provider " + string(algorithm))
			put, err := client.PutObject(ctx, &s3.PutObjectInput{
				Bucket: &bucket, Key: &key, Body: bytes.NewReader(payload), ContentLength: aws.Int64(int64(len(payload))),
				ServerSideEncryption: algorithm,
			})
			if err != nil {
				return err
			}
			if put.ServerSideEncryption != algorithm || put.SSEKMSKeyId == nil || *put.SSEKMSKeyId == "" {
				return fmt.Errorf("%s PUT encryption=%q key=%v", algorithm, put.ServerSideEncryption, put.SSEKMSKeyId)
			}
			got, err := client.GetObject(ctx, &s3.GetObjectInput{Bucket: &bucket, Key: &key})
			if err != nil {
				return err
			}
			body, readErr := io.ReadAll(got.Body)
			_ = got.Body.Close()
			if readErr != nil || !bytes.Equal(body, payload) || got.ServerSideEncryption != algorithm {
				return fmt.Errorf("%s GET body=%q encryption=%q err=%v", algorithm, body, got.ServerSideEncryption, readErr)
			}
		}
		return nil
	})
}

func PutBucketEncryption_success(s *S3Conf) error {
	return actionHandler(s, "PutBucketEncryption_success", func(client *s3.Client, bucket string) error {
		ctx, cancel := context.WithTimeout(context.Background(), shortTimeout)
		defer cancel()
		_, err := client.PutBucketEncryption(ctx, bucketEncryptionInput(bucket))
		return err
	})
}

func GetBucketEncryption_success(s *S3Conf) error {
	return actionHandler(s, "GetBucketEncryption_success", func(client *s3.Client, bucket string) error {
		ctx, cancel := context.WithTimeout(context.Background(), shortTimeout)
		defer cancel()
		if _, err := client.PutBucketEncryption(ctx, bucketEncryptionInput(bucket)); err != nil {
			return err
		}
		output, err := client.GetBucketEncryption(ctx, &s3.GetBucketEncryptionInput{Bucket: &bucket})
		if err != nil {
			return err
		}
		if output.ServerSideEncryptionConfiguration == nil || len(output.ServerSideEncryptionConfiguration.Rules) != 1 {
			return fmt.Errorf("unexpected encryption configuration: %#v", output.ServerSideEncryptionConfiguration)
		}
		rule := output.ServerSideEncryptionConfiguration.Rules[0]
		if rule.ApplyServerSideEncryptionByDefault == nil || rule.ApplyServerSideEncryptionByDefault.SSEAlgorithm != types.ServerSideEncryptionAes256 || rule.BucketKeyEnabled == nil || !*rule.BucketKeyEnabled || rule.BlockedEncryptionTypes == nil || len(rule.BlockedEncryptionTypes.EncryptionType) != 1 || rule.BlockedEncryptionTypes.EncryptionType[0] != types.EncryptionTypeNone {
			return fmt.Errorf("unexpected encryption rule: %#v", rule)
		}
		return nil
	})
}

func DeleteBucketEncryption_resets_default(s *S3Conf) error {
	return actionHandler(s, "DeleteBucketEncryption_resets_default", func(client *s3.Client, bucket string) error {
		ctx, cancel := context.WithTimeout(context.Background(), shortTimeout)
		defer cancel()
		if _, err := client.PutBucketEncryption(ctx, bucketEncryptionInput(bucket)); err != nil {
			return err
		}
		if _, err := client.DeleteBucketEncryption(ctx, &s3.DeleteBucketEncryptionInput{Bucket: &bucket}); err != nil {
			return err
		}
		output, err := client.GetBucketEncryption(ctx, &s3.GetBucketEncryptionInput{Bucket: &bucket})
		if err != nil {
			return err
		}
		if output.ServerSideEncryptionConfiguration == nil || len(output.ServerSideEncryptionConfiguration.Rules) != 1 {
			return fmt.Errorf("unexpected default encryption configuration: %#v", output.ServerSideEncryptionConfiguration)
		}
		rule := output.ServerSideEncryptionConfiguration.Rules[0]
		if rule.ApplyServerSideEncryptionByDefault == nil || rule.ApplyServerSideEncryptionByDefault.SSEAlgorithm != types.ServerSideEncryptionAes256 || rule.BlockedEncryptionTypes == nil || len(rule.BlockedEncryptionTypes.EncryptionType) != 1 || rule.BlockedEncryptionTypes.EncryptionType[0] != types.EncryptionTypeSseC {
			return fmt.Errorf("unexpected reset encryption rule: %#v", rule)
		}
		return nil
	})
}

func bucketEncryptionInput(bucket string) *s3.PutBucketEncryptionInput {
	enabled := true
	return &s3.PutBucketEncryptionInput{
		Bucket: &bucket,
		ServerSideEncryptionConfiguration: &types.ServerSideEncryptionConfiguration{Rules: []types.ServerSideEncryptionRule{{
			ApplyServerSideEncryptionByDefault: &types.ServerSideEncryptionByDefault{SSEAlgorithm: types.ServerSideEncryptionAes256},
			BucketKeyEnabled:                   &enabled,
			BlockedEncryptionTypes:             &types.BlockedEncryptionTypes{EncryptionType: []types.EncryptionType{types.EncryptionTypeNone}},
		}}},
	}
}
