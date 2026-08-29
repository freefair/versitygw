// Copyright 2026 Versity Software
// This file is licensed under the Apache License, Version 2.0.

package s3proxy

import (
	"bytes"
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/aws/aws-sdk-go-v2/service/s3"
	"github.com/aws/aws-sdk-go-v2/service/s3/types"
	"github.com/versity/versitygw/internal/encryption"
	"github.com/versity/versitygw/s3response"
)

func TestEncryptionConfigurationDelegatesToUpstream(t *testing.T) {
	requests := make(chan *http.Request, 3)
	requestBodies := make(chan string, 3)
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, err := io.ReadAll(r.Body)
		if err != nil {
			t.Errorf("read request: %v", err)
		}
		requests <- r.Clone(context.Background())
		requestBodies <- string(body)
		if r.Method == http.MethodGet {
			w.Header().Set("Content-Type", "application/xml")
			_, _ = io.WriteString(w, `<ServerSideEncryptionConfiguration xmlns="http://s3.amazonaws.com/doc/2006-03-01/"><Rule><ApplyServerSideEncryptionByDefault><SSEAlgorithm>aws:kms:dsse</SSEAlgorithm><KMSMasterKeyID>alias/archive</KMSMasterKeyID></ApplyServerSideEncryptionByDefault><BucketKeyEnabled>false</BucketKeyEnabled><BlockedEncryptionTypes><EncryptionType>SSE-C</EncryptionType></BlockedEncryptionTypes></Rule></ServerSideEncryptionConfiguration>`)
		}
	}))
	t.Cleanup(server.Close)

	proxy := newTestProxy(t, server.URL)
	configuration := encryption.Configuration{Rules: []encryption.Rule{{
		Default:                &encryption.DefaultEncryption{Algorithm: encryption.AlgorithmDSSEKMS, KMSKeyID: "alias/archive"},
		BucketKeyEnabled:       boolPointer(false),
		BlockedEncryptionTypes: &encryption.BlockedEncryptionTypes{Types: []string{"SSE-C"}},
	}}}
	if err := proxy.PutEncryptionConfiguration(context.Background(), "bucket", configuration); err != nil {
		t.Fatalf("PutEncryptionConfiguration() error = %v", err)
	}
	putRequest, putBody := <-requests, <-requestBodies
	if putRequest.Method != http.MethodPut || putRequest.URL.Path != "/bucket" || !putRequest.URL.Query().Has("encryption") {
		t.Fatalf("PUT request = %s %s?%s", putRequest.Method, putRequest.URL.Path, putRequest.URL.RawQuery)
	}
	for _, expected := range []string{"<SSEAlgorithm>aws:kms:dsse</SSEAlgorithm>", "<KMSMasterKeyID>alias/archive</KMSMasterKeyID>", "<EncryptionType>SSE-C</EncryptionType>"} {
		if !strings.Contains(putBody, expected) {
			t.Errorf("PUT body does not contain %q: %s", expected, putBody)
		}
	}

	got, err := proxy.GetEncryptionConfiguration(context.Background(), "bucket")
	if err != nil {
		t.Fatalf("GetEncryptionConfiguration() error = %v", err)
	}
	getRequest := <-requests
	<-requestBodies
	if getRequest.Method != http.MethodGet || !getRequest.URL.Query().Has("encryption") {
		t.Fatalf("GET request = %s %s?%s", getRequest.Method, getRequest.URL.Path, getRequest.URL.RawQuery)
	}
	if len(got.Rules) != 1 || got.Rules[0].Default == nil || got.Rules[0].Default.Algorithm != encryption.AlgorithmDSSEKMS || got.Rules[0].Default.KMSKeyID != "alias/archive" {
		t.Fatalf("configuration = %#v", got)
	}
	if got.Rules[0].BlockedEncryptionTypes == nil || len(got.Rules[0].BlockedEncryptionTypes.Types) != 1 || got.Rules[0].BlockedEncryptionTypes.Types[0] != "SSE-C" {
		t.Fatalf("blocked encryption types = %#v", got.Rules[0].BlockedEncryptionTypes)
	}

	if err := proxy.DeleteEncryptionConfiguration(context.Background(), "bucket"); err != nil {
		t.Fatalf("DeleteEncryptionConfiguration() error = %v", err)
	}
	deleteRequest := <-requests
	<-requestBodies
	if deleteRequest.Method != http.MethodDelete || !deleteRequest.URL.Query().Has("encryption") {
		t.Fatalf("DELETE request = %s %s?%s", deleteRequest.Method, deleteRequest.URL.Path, deleteRequest.URL.RawQuery)
	}
}

func TestPutObjectForwardsKMSAndReturnsEncryptionResult(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPut || r.URL.Path != "/bucket/object" {
			t.Errorf("request = %s %s", r.Method, r.URL.Path)
		}
		assertHeader(t, r, "x-amz-server-side-encryption", "aws:kms")
		assertHeader(t, r, "x-amz-server-side-encryption-aws-kms-key-id", "alias/data")
		assertHeader(t, r, "x-amz-server-side-encryption-context", "context")
		assertHeader(t, r, "x-amz-server-side-encryption-bucket-key-enabled", "true")
		body, err := io.ReadAll(r.Body)
		if err != nil || string(body) != "payload" {
			t.Errorf("body = %q, error = %v", body, err)
		}
		w.Header().Set("ETag", `"etag"`)
		w.Header().Set("x-amz-server-side-encryption", "aws:kms")
		w.Header().Set("x-amz-server-side-encryption-aws-kms-key-id", "alias/data")
		w.Header().Set("x-amz-server-side-encryption-bucket-key-enabled", "true")
	}))
	t.Cleanup(server.Close)

	proxy := newTestProxy(t, server.URL)
	bucket, key, length, contextValue, keyID, enabled := "bucket", "object", int64(7), "context", "alias/data", true
	output, err := proxy.PutObject(context.Background(), s3response.PutObjectInput{
		Bucket: &bucket, Key: &key, ContentLength: &length, Body: bytes.NewReader([]byte("payload")),
		ServerSideEncryption: types.ServerSideEncryptionAwsKms, SSEKMSKeyId: &keyID,
		SSEKMSEncryptionContext: &contextValue, BucketKeyEnabled: &enabled,
	})
	if err != nil {
		t.Fatalf("PutObject() error = %v", err)
	}
	if output.Encryption == nil || output.Encryption.Mode != encryption.ModeSSEKMS || output.Encryption.KMSKeyID != keyID || !output.Encryption.BucketKeyEnabled {
		t.Fatalf("encryption result = %#v", output.Encryption)
	}
}

func TestMultipartForwardsEncryptionHeaders(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.Method == http.MethodPost && r.URL.Query().Has("uploads"):
			assertHeader(t, r, "x-amz-server-side-encryption", "aws:kms:dsse")
			assertHeader(t, r, "x-amz-server-side-encryption-aws-kms-key-id", "alias/dsse")
			w.Header().Set("x-amz-server-side-encryption", "aws:kms:dsse")
			w.Header().Set("x-amz-server-side-encryption-aws-kms-key-id", "alias/dsse")
			_, _ = io.WriteString(w, `<InitiateMultipartUploadResult xmlns="http://s3.amazonaws.com/doc/2006-03-01/"><Bucket>bucket</Bucket><Key>object</Key><UploadId>upload</UploadId></InitiateMultipartUploadResult>`)
		case r.Method == http.MethodPut && r.URL.Query().Get("partNumber") == "1":
			assertHeader(t, r, "x-amz-server-side-encryption-customer-algorithm", "AES256")
			assertHeader(t, r, "x-amz-server-side-encryption-customer-key", "customer-key")
			assertHeader(t, r, "x-amz-server-side-encryption-customer-key-md5", "customer-md5")
			w.Header().Set("ETag", `"part"`)
		case r.Method == http.MethodPost && r.URL.Query().Get("uploadId") == "upload":
			assertHeader(t, r, "x-amz-server-side-encryption-customer-algorithm", "AES256")
			assertHeader(t, r, "x-amz-server-side-encryption-customer-key", "customer-key")
			assertHeader(t, r, "x-amz-server-side-encryption-customer-key-md5", "customer-md5")
			w.Header().Set("x-amz-server-side-encryption-customer-algorithm", "AES256")
			w.Header().Set("x-amz-server-side-encryption-customer-key-md5", "customer-md5")
			_, _ = io.WriteString(w, `<CompleteMultipartUploadResult xmlns="http://s3.amazonaws.com/doc/2006-03-01/"><Bucket>bucket</Bucket><Key>object</Key><ETag>&quot;complete&quot;</ETag></CompleteMultipartUploadResult>`)
		default:
			t.Errorf("unexpected request = %s %s?%s", r.Method, r.URL.Path, r.URL.RawQuery)
			w.WriteHeader(http.StatusBadRequest)
		}
	}))
	t.Cleanup(server.Close)

	proxy := newTestProxy(t, server.URL)
	bucket, key, kmsKeyID := "bucket", "object", "alias/dsse"
	created, err := proxy.CreateMultipartUpload(context.Background(), s3response.CreateMultipartUploadInput{
		Bucket: &bucket, Key: &key, ServerSideEncryption: types.ServerSideEncryptionAwsKmsDsse, SSEKMSKeyId: &kmsKeyID,
	})
	if err != nil {
		t.Fatalf("CreateMultipartUpload() error = %v", err)
	}
	if created.Encryption == nil || created.Encryption.Mode != encryption.ModeDSSEKMS || created.Encryption.KMSKeyID != kmsKeyID {
		t.Fatalf("create encryption result = %#v", created.Encryption)
	}

	uploadID, algorithm, customerKey, customerMD5, partNumber, length := "upload", "AES256", "customer-key", "customer-md5", int32(1), int64(4)
	if _, err := proxy.UploadPart(context.Background(), &s3.UploadPartInput{
		Bucket: &bucket, Key: &key, UploadId: &uploadID, PartNumber: &partNumber, ContentLength: &length, Body: bytes.NewReader([]byte("part")),
		SSECustomerAlgorithm: &algorithm, SSECustomerKey: &customerKey, SSECustomerKeyMD5: &customerMD5,
	}); err != nil {
		t.Fatalf("UploadPart() error = %v", err)
	}

	completed, _, err := proxy.CompleteMultipartUpload(context.Background(), &s3.CompleteMultipartUploadInput{
		Bucket: &bucket, Key: &key, UploadId: &uploadID,
		MultipartUpload:      &types.CompletedMultipartUpload{Parts: []types.CompletedPart{{ETag: stringPointer(`"part"`), PartNumber: &partNumber}}},
		SSECustomerAlgorithm: &algorithm, SSECustomerKey: &customerKey, SSECustomerKeyMD5: &customerMD5,
	})
	if err != nil {
		t.Fatalf("CompleteMultipartUpload() error = %v", err)
	}
	if completed.Encryption == nil || completed.Encryption.Mode != encryption.ModeSSEC || completed.Encryption.CustomerKeyMD5 != customerMD5 {
		t.Fatalf("complete encryption result = %#v", completed.Encryption)
	}
}

func TestCopyObjectForwardsSourceAndDestinationEncryption(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		assertHeader(t, r, "x-amz-copy-source-server-side-encryption-customer-algorithm", "AES256")
		assertHeader(t, r, "x-amz-copy-source-server-side-encryption-customer-key", "source-key")
		assertHeader(t, r, "x-amz-copy-source-server-side-encryption-customer-key-md5", "source-md5")
		assertHeader(t, r, "x-amz-server-side-encryption", "AES256")
		w.Header().Set("x-amz-server-side-encryption", "AES256")
		_, _ = io.WriteString(w, `<CopyObjectResult xmlns="http://s3.amazonaws.com/doc/2006-03-01/"><ETag>&quot;copy&quot;</ETag><LastModified>2026-08-28T12:00:00.000Z</LastModified></CopyObjectResult>`)
	}))
	t.Cleanup(server.Close)

	proxy := newTestProxy(t, server.URL)
	bucket, key, source := "bucket", "copy", "bucket/source"
	algorithm, sourceKey, sourceMD5 := "AES256", "source-key", "source-md5"
	output, err := proxy.CopyObject(context.Background(), s3response.CopyObjectInput{
		Bucket: &bucket, Key: &key, CopySource: &source,
		CopySourceSSECustomerAlgorithm: &algorithm, CopySourceSSECustomerKey: &sourceKey, CopySourceSSECustomerKeyMD5: &sourceMD5,
		ServerSideEncryption: types.ServerSideEncryptionAes256,
	})
	if err != nil {
		t.Fatalf("CopyObject() error = %v", err)
	}
	if output.ServerSideEncryption != types.ServerSideEncryptionAes256 || output.CopyObjectResult == nil || output.CopyObjectResult.ETag == nil || *output.CopyObjectResult.ETag != `"copy"` {
		t.Fatalf("copy output = %#v", output)
	}
}

func newTestProxy(t *testing.T, endpoint string) *S3Proxy {
	t.Helper()
	proxy, err := New(context.Background(), "", "", endpoint, "us-east-1", "", true, true, true, false, true, false, false)
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}
	return proxy
}

func assertHeader(t *testing.T, request *http.Request, name, expected string) {
	t.Helper()
	if got := request.Header.Get(name); got != expected {
		t.Errorf("%s = %q, want %q", name, got, expected)
	}
}

func boolPointer(value bool) *bool { return &value }
