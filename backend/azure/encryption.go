// Copyright 2026 Versity Software
// This file is licensed under the Apache License, Version 2.0.

package azure

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/subtle"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/Azure/azure-sdk-for-go/sdk/storage/azblob/blob"
	"github.com/Azure/azure-sdk-for-go/sdk/storage/azblob/blockblob"
	"github.com/Azure/azure-sdk-for-go/sdk/storage/azblob/container"
	"github.com/aws/aws-sdk-go-v2/service/s3"
	"github.com/aws/aws-sdk-go-v2/service/s3/types"
	"github.com/versity/versitygw/backend"
	"github.com/versity/versitygw/internal/encryption"
	"github.com/versity/versitygw/s3err"
	"github.com/versity/versitygw/s3response"
)

const azureNullVersionID = "null"

type azureMultipartEncryptionState struct {
	Mode             encryption.Mode `json:"mode"`
	KMSKeyID         string          `json:"kms_key_id,omitempty"`
	KMSContext       []byte          `json:"kms_context,omitempty"`
	BucketKeyEnabled bool            `json:"bucket_key_enabled,omitempty"`
	CustomerKeyMD5   []byte          `json:"customer_key_md5,omitempty"`
}

// ConfigureEncryption injects the providers used by the Azure backend. The
// gateway resolves S3 intent; Azure owns the physical envelope format.
func (az *Azure) ConfigureEncryption(primary, managed encryption.KeyProvider) error {
	if managed == nil {
		managed = primary
	}
	var dsse encryption.KeyProvider = managed
	if local, ok := managed.(*encryption.LocalProvider); ok {
		derived, err := local.Derived("local-dsse", "dsse-second-layer")
		if err != nil {
			return fmt.Errorf("initialize Azure DSSE provider: %w", err)
		}
		dsse = derived
	}
	az.encryptionProvider = primary
	az.managedEncryptionProvider = managed
	az.dsseEncryptionProvider = dsse
	return nil
}

func (az *Azure) EncryptionCapabilities() encryption.Capabilities {
	if az.managedEncryptionProvider == nil {
		return encryption.Capabilities{}
	}
	return encryption.Capabilities{
		SSES3:   true,
		SSEC:    true,
		SSEKMS:  az.encryptionProvider != nil,
		DSSEKMS: az.encryptionProvider != nil && az.dsseEncryptionProvider != nil,
	}
}

func (az *Azure) EncryptionActive() bool { return az.managedEncryptionProvider != nil }

func (az *Azure) resolveEncryptionIntent(intent *encryption.Intent) (*encryption.Intent, error) {
	if intent == nil {
		return nil, nil
	}
	resolved := *intent
	resolved.KMSContext = append([]byte(nil), intent.KMSContext...)
	if (resolved.Mode == encryption.ModeSSEKMS || resolved.Mode == encryption.ModeDSSEKMS) && resolved.KMSKeyID == "" {
		referencer, ok := az.encryptionProvider.(encryption.ActiveKeyReferencer)
		if !ok || referencer.ActiveKeyReference() == "" {
			return nil, encryption.ErrInvalidKey
		}
		resolved.KMSKeyID = referencer.ActiveKeyReference()
	}
	return &resolved, nil
}

func (az *Azure) PutEncryptionConfiguration(ctx context.Context, bucket string, configuration encryption.Configuration) error {
	if !az.EncryptionActive() {
		return s3err.GetAPIError(s3err.ErrNotImplemented)
	}
	configuration, err := encryption.ValidateConfiguration(configuration, az.EncryptionCapabilities())
	if err != nil {
		return err
	}
	body, err := encryption.MarshalConfiguration(configuration)
	if err != nil {
		return err
	}
	return az.setContainerMetaData(ctx, bucket, string(keyEncryption), body)
}

func (az *Azure) GetEncryptionConfiguration(ctx context.Context, bucket string) (encryption.Configuration, error) {
	if !az.EncryptionActive() {
		return encryption.Configuration{}, s3err.GetAPIError(s3err.ErrNotImplemented)
	}
	body, err := az.getContainerMetaData(ctx, bucket, string(keyEncryption))
	if err != nil {
		return encryption.Configuration{}, err
	}
	if len(body) == 0 {
		return encryption.LegacyConfiguration(), nil
	}
	configuration, err := encryption.ParseConfiguration(body)
	if err != nil {
		return encryption.Configuration{}, fmt.Errorf("parse stored Azure encryption configuration: %w", err)
	}
	return encryption.ValidateConfiguration(configuration, az.EncryptionCapabilities())
}

func (az *Azure) DeleteEncryptionConfiguration(ctx context.Context, bucket string) error {
	if !az.EncryptionActive() {
		return s3err.GetAPIError(s3err.ErrNotImplemented)
	}
	body, err := encryption.MarshalConfiguration(encryption.DefaultConfiguration())
	if err != nil {
		return err
	}
	return az.setContainerMetaData(ctx, bucket, string(keyEncryption), body)
}

func (az *Azure) encryptionLayers(intent *encryption.Intent) ([]encryption.LayerRequest, error) {
	if intent == nil {
		return nil, nil
	}
	switch intent.Mode {
	case encryption.ModeSSEC:
		provider, err := encryption.NewCustomerKeyProvider(intent.CustomerKey)
		if err != nil {
			return nil, err
		}
		return []encryption.LayerRequest{{Provider: provider}}, nil
	case encryption.ModeSSES3:
		if az.managedEncryptionProvider == nil {
			return nil, encryption.ErrUnsupportedEncryption
		}
		return []encryption.LayerRequest{{Provider: az.managedEncryptionProvider}}, nil
	case encryption.ModeSSEKMS:
		if az.encryptionProvider == nil {
			return nil, encryption.ErrUnsupportedEncryption
		}
		return []encryption.LayerRequest{{Provider: az.encryptionProvider, KeyID: intent.KMSKeyID, Context: intent.KMSContext}}, nil
	case encryption.ModeDSSEKMS:
		if az.encryptionProvider == nil || az.dsseEncryptionProvider == nil {
			return nil, encryption.ErrUnsupportedEncryption
		}
		return []encryption.LayerRequest{
			{Provider: az.encryptionProvider, KeyID: intent.KMSKeyID, Context: intent.KMSContext},
			{Provider: az.dsseEncryptionProvider, Context: intent.KMSContext},
		}, nil
	default:
		return nil, encryption.ErrUnsupportedEncryption
	}
}

func (az *Azure) encryptionProviderMap() encryption.ProviderMap {
	providers := encryption.ProviderMap{}
	for _, provider := range []encryption.KeyProvider{az.encryptionProvider, az.managedEncryptionProvider, az.dsseEncryptionProvider} {
		if provider != nil {
			providers[provider.Name()] = provider
		}
	}
	return providers
}

func azureEncryptionResult(intent *encryption.Intent) encryption.Result {
	if intent == nil {
		return encryption.Result{}
	}
	result := encryption.Result{Mode: intent.Mode, KMSKeyID: intent.KMSKeyID, BucketKeyEnabled: intent.BucketKeyEnabled}
	if intent.Mode == encryption.ModeSSEC {
		result.CustomerKeyMD5 = base64.StdEncoding.EncodeToString(intent.CustomerKeyMD5[:])
	}
	return result
}

func azureEncryptionResultPtr(intent *encryption.Intent) *encryption.Result {
	if intent == nil {
		return nil
	}
	result := azureEncryptionResult(intent)
	return &result
}

func storeAzureEncryptionMetadata(metadata map[string]*string, intent *encryption.Intent, plaintextSize int64) error {
	if intent == nil {
		return nil
	}
	body, err := json.Marshal(azureEncryptionResult(intent))
	if err != nil {
		return fmt.Errorf("marshal Azure encryption metadata: %w", err)
	}
	encoded := base64.StdEncoding.EncodeToString(body)
	size := strconv.FormatInt(plaintextSize, 10)
	metadata[string(keyObjectEncryption)] = &encoded
	metadata[string(keyObjectPlaintextSize)] = &size
	return nil
}

func loadAzureEncryptionMetadata(metadata map[string]*string) (encryption.Result, int64, bool, error) {
	encoded := metadataValue(metadata, string(keyObjectEncryption))
	if encoded == "" {
		return encryption.Result{}, 0, false, nil
	}
	body, err := base64.StdEncoding.DecodeString(encoded)
	if err != nil {
		return encryption.Result{}, 0, true, encryption.ErrInvalidContainer
	}
	var result encryption.Result
	if err := json.Unmarshal(body, &result); err != nil {
		return encryption.Result{}, 0, true, encryption.ErrInvalidContainer
	}
	size, err := strconv.ParseInt(metadataValue(metadata, string(keyObjectPlaintextSize)), 10, 64)
	if err != nil || size < 0 {
		return encryption.Result{}, 0, true, encryption.ErrInvalidContainer
	}
	return result, size, true, nil
}

func azureListedObjectSize(storedSize *int64, metadata map[string]*string) (*int64, error) {
	_, plaintextSize, encrypted, err := loadAzureEncryptionMetadata(metadata)
	if err != nil {
		return nil, err
	}
	if !encrypted {
		return storedSize, nil
	}
	return &plaintextSize, nil
}

func storeAzureMultipartEncryptionMetadata(metadata map[string]*string, intent *encryption.Intent) error {
	if intent == nil {
		return nil
	}
	state := azureMultipartEncryptionState{
		Mode: intent.Mode, KMSKeyID: intent.KMSKeyID, KMSContext: append([]byte(nil), intent.KMSContext...),
		BucketKeyEnabled: intent.BucketKeyEnabled,
	}
	if intent.Mode == encryption.ModeSSEC {
		state.CustomerKeyMD5 = append([]byte(nil), intent.CustomerKeyMD5[:]...)
	}
	body, err := json.Marshal(state)
	if err != nil {
		return fmt.Errorf("marshal Azure multipart encryption state: %w", err)
	}
	encoded := base64.StdEncoding.EncodeToString(body)
	metadata[string(keyMultipartEncryption)] = &encoded
	return nil
}

func loadAzureMultipartEncryptionMetadata(metadata map[string]*string) (*azureMultipartEncryptionState, error) {
	encoded := metadataValue(metadata, string(keyMultipartEncryption))
	if encoded == "" {
		return nil, nil
	}
	body, err := base64.StdEncoding.DecodeString(encoded)
	if err != nil {
		return nil, encryption.ErrInvalidContainer
	}
	var state azureMultipartEncryptionState
	if err := json.Unmarshal(body, &state); err != nil {
		return nil, encryption.ErrInvalidContainer
	}
	if state.Mode != encryption.ModeSSES3 && state.Mode != encryption.ModeSSEC && state.Mode != encryption.ModeSSEKMS && state.Mode != encryption.ModeDSSEKMS {
		return nil, encryption.ErrInvalidContainer
	}
	return &state, nil
}

func azureMultipartIntent(state *azureMultipartEncryptionState, algorithm, key, keyMD5 string) (*encryption.Intent, error) {
	headers := encryption.RequestHeaders{CustomerAlgorithm: algorithm, CustomerKey: key, CustomerKeyMD5: keyMD5}
	hasCustomerHeaders := encryption.HasCustomerKeyHeaders(headers)
	if state == nil {
		if hasCustomerHeaders {
			return nil, s3err.GetAPIError(s3err.ErrInvalidRequest)
		}
		return nil, nil
	}
	if state.Mode != encryption.ModeSSEC {
		if hasCustomerHeaders {
			return nil, s3err.GetAPIError(s3err.ErrInvalidRequest)
		}
		return &encryption.Intent{
			Mode: state.Mode, KMSKeyID: state.KMSKeyID, KMSContext: append([]byte(nil), state.KMSContext...),
			BucketKeyEnabled: state.BucketKeyEnabled,
		}, nil
	}
	intent, err := encryption.ParseCustomerKeyHeaders(headers)
	if err != nil || subtle.ConstantTimeCompare(intent.CustomerKeyMD5[:], state.CustomerKeyMD5) != 1 {
		intent.CustomerKey.Destroy()
		return nil, s3err.GetAPIError(s3err.ErrInvalidRequest)
	}
	return &intent, nil
}

func azureMultipartPartIdentity(bucket, object, uploadID string, partNumber int32) encryption.Identity {
	return encryption.Identity{
		Bucket: bucket, Key: object,
		VersionID: fmt.Sprintf("multipart:%s:%d", uploadID, partNumber),
	}
}

func azureMultipartPartPath(object, uploadID string, partNumber int32) string {
	return fmt.Sprintf("%s/parts/%05d", createMetaTmpPath(object, uploadID), partNumber)
}

func (az *Azure) multipartEncryptionState(ctx context.Context, bucket, object, uploadID string) (*azureMultipartEncryptionState, error) {
	client, err := az.getBlobClient(bucket, createMetaTmpPath(object, uploadID))
	if err != nil {
		return nil, err
	}
	properties, err := client.GetProperties(ctx, nil)
	if err != nil {
		return nil, parseMpError(err)
	}
	return loadAzureMultipartEncryptionMetadata(properties.Metadata)
}

func (az *Azure) uploadEncryptedPart(ctx context.Context, input *s3.UploadPartInput, state *azureMultipartEncryptionState) (*s3.UploadPartOutput, error) {
	intent, err := azureMultipartIntent(state, getString(input.SSECustomerAlgorithm), getString(input.SSECustomerKey), getString(input.SSECustomerKeyMD5))
	if err != nil {
		return nil, err
	}
	defer intent.CustomerKey.Destroy()
	if input.ContentLength == nil || *input.ContentLength < 0 {
		return nil, s3err.GetAPIError(s3err.ErrInvalidRequest)
	}

	etagBytes := make([]byte, 16)
	if _, err := io.ReadFull(rand.Reader, etagBytes); err != nil {
		return nil, fmt.Errorf("generate encrypted multipart part ETag: %w", err)
	}
	etag := base64.RawStdEncoding.EncodeToString(etagBytes)
	quotedETag := quoteETag(etag)
	partNumber := strconv.FormatInt(int64(*input.PartNumber), 10)
	plainSize := strconv.FormatInt(*input.ContentLength, 10)
	metadata := map[string]*string{
		string(keyMultipartPartETag):      &quotedETag,
		string(keyMultipartPartNumber):    &partNumber,
		string(keyMultipartPartPlainSize): &plainSize,
	}
	if err := storeAzureEncryptionMetadata(metadata, intent, *input.ContentLength); err != nil {
		return nil, err
	}
	uploadBody, done := az.encryptedUploadReader(ctx, azureMultipartPartIdentity(*input.Bucket, *input.Key, *input.UploadId, *input.PartNumber), intent, input.Body, *input.ContentLength)
	response, uploadErr := az.client.UploadStream(ctx, *input.Bucket, azureMultipartPartPath(*input.Key, *input.UploadId, *input.PartNumber), uploadBody, &blockblob.UploadStreamOptions{Metadata: metadata})
	_ = uploadBody.Close()
	encryptionErr := <-done
	if uploadErr != nil {
		return nil, parseMpError(uploadErr)
	}
	if encryptionErr != nil {
		return nil, fmt.Errorf("encrypt Azure multipart part: %w", encryptionErr)
	}
	_ = response
	result := &s3.UploadPartOutput{ETag: &quotedETag}
	if intent.Mode == encryption.ModeSSEC {
		result.SSECustomerAlgorithm = backend.GetPtrFromString("AES256")
		result.SSECustomerKeyMD5 = backend.GetPtrFromString(base64.StdEncoding.EncodeToString(intent.CustomerKeyMD5[:]))
	}
	return result, nil
}

func (az *Azure) listEncryptedParts(ctx context.Context, input *s3.ListPartsInput) (s3response.ListPartsResult, error) {
	client, err := az.getContainerClient(*input.Bucket)
	if err != nil {
		return s3response.ListPartsResult{}, err
	}
	prefix := fmt.Sprintf("%s/parts/", createMetaTmpPath(*input.Key, *input.UploadId))
	pager := client.NewListBlobsFlatPager(&container.ListBlobsFlatOptions{
		Include: container.ListBlobsInclude{Metadata: true}, Prefix: &prefix,
	})
	parts := make([]s3response.Part, 0)
	for pager.More() {
		page, err := pager.NextPage(ctx)
		if err != nil {
			return s3response.ListPartsResult{}, azureErrToS3Err(err)
		}
		for _, item := range page.Segment.BlobItems {
			partNumber, err := strconv.Atoi(metadataValue(item.Metadata, string(keyMultipartPartNumber)))
			if err != nil || partNumber < 1 || partNumber > 10000 {
				return s3response.ListPartsResult{}, encryption.ErrInvalidContainer
			}
			if getString(input.PartNumberMarker) != "" {
				marker, err := strconv.Atoi(*input.PartNumberMarker)
				if err != nil {
					return s3response.ListPartsResult{}, s3err.GetInvalidArgMaxLimiter("part-number-marker", *input.PartNumberMarker)
				}
				if partNumber <= marker {
					continue
				}
			}
			size, err := strconv.ParseInt(metadataValue(item.Metadata, string(keyMultipartPartPlainSize)), 10, 64)
			if err != nil || size < 0 {
				return s3response.ListPartsResult{}, encryption.ErrInvalidContainer
			}
			lastModified := time.Time{}
			if item.Properties.LastModified != nil {
				lastModified = *item.Properties.LastModified
			}
			parts = append(parts, s3response.Part{
				PartNumber: partNumber, Size: size,
				ETag: metadataValue(item.Metadata, string(keyMultipartPartETag)), LastModified: lastModified,
			})
		}
	}
	sort.Slice(parts, func(i, j int) bool { return parts[i].PartNumber < parts[j].PartNumber })
	maxParts := int32(1000)
	if input.MaxParts != nil {
		maxParts = *input.MaxParts
	}
	isTruncated := int32(len(parts)) > maxParts
	nextMarker := 0
	if isTruncated {
		parts = parts[:maxParts]
		nextMarker = parts[len(parts)-1].PartNumber
	}
	marker := 0
	if getString(input.PartNumberMarker) != "" {
		marker, _ = strconv.Atoi(*input.PartNumberMarker)
	}
	return s3response.ListPartsResult{
		Bucket: *input.Bucket, Key: *input.Key, UploadID: *input.UploadId, Parts: parts,
		PartNumberMarker: marker, NextPartNumberMarker: nextMarker, MaxParts: int(maxParts),
		IsTruncated: isTruncated, StorageClass: types.StorageClassStandard,
	}, nil
}

func (az *Azure) completeEncryptedMultipart(ctx context.Context, input *s3.CompleteMultipartUploadInput, state *azureMultipartEncryptionState, properties blob.GetPropertiesResponse, tags blob.GetTagsResponse) (s3response.CompleteMultipartUploadResult, string, error) {
	intent, err := azureMultipartIntent(state, getString(input.SSECustomerAlgorithm), getString(input.SSECustomerKey), getString(input.SSECustomerKeyMD5))
	if err != nil {
		return s3response.CompleteMultipartUploadResult{}, "", err
	}
	defer intent.CustomerKey.Destroy()

	maxParts := int32(10000)
	listed, err := az.listEncryptedParts(ctx, &s3.ListPartsInput{
		Bucket: input.Bucket, Key: input.Key, UploadId: input.UploadId,
		MaxParts: &maxParts, PartNumberMarker: backend.GetPtrFromString(""),
	})
	if err != nil {
		return s3response.CompleteMultipartUploadResult{}, "", err
	}
	available := make(map[int]s3response.Part, len(listed.Parts))
	for _, part := range listed.Parts {
		available[part.PartNumber] = part
	}

	selected := make([]s3response.Part, 0, len(input.MultipartUpload.Parts))
	partOffsets := make([]int64, 0, len(input.MultipartUpload.Parts))
	var totalSize int64
	var previous int32
	last := len(input.MultipartUpload.Parts) - 1
	for index, completed := range input.MultipartUpload.Parts {
		if completed.PartNumber == nil || completed.ETag == nil {
			return s3response.CompleteMultipartUploadResult{}, "", s3err.GetAPIError(s3err.ErrMalformedXML)
		}
		if *completed.PartNumber < 1 || *completed.PartNumber <= previous {
			if *completed.PartNumber < 1 {
				return s3response.CompleteMultipartUploadResult{}, "", s3err.GetInvalidArgumentErr(s3err.InvalidArgCompleteMpPartNumber, fmt.Sprint(*completed.PartNumber))
			}
			return s3response.CompleteMultipartUploadResult{}, "", s3err.GetAPIError(s3err.ErrInvalidPartOrder)
		}
		previous = *completed.PartNumber
		part, ok := available[int(*completed.PartNumber)]
		if !ok || getString(backend.TrimEtag(completed.ETag)) != getString(backend.TrimEtag(&part.ETag)) {
			return s3response.CompleteMultipartUploadResult{}, "", s3err.GetInvalidPartErr(*input.UploadId, *completed.PartNumber, part.ETag)
		}
		if index < last && part.Size < backend.MinPartSize {
			return s3response.CompleteMultipartUploadResult{}, "", s3err.GetEntityTooSmallErr(part.Size, backend.MinPartSize)
		}
		totalSize += part.Size
		partOffsets = append(partOffsets, totalSize)
		selected = append(selected, part)
	}
	if input.MpuObjectSize != nil && *input.MpuObjectSize != totalSize {
		return s3response.CompleteMultipartUploadResult{}, "", s3err.GetIncorrectMpObjectSizeErr(totalSize, *input.MpuObjectSize)
	}

	mpMetadata, err := backend.MarshalMpUploadMetadata(backend.MpUploadMetadata{UploadID: *input.UploadId, Parts: partOffsets}, true)
	if err != nil {
		return s3response.CompleteMultipartUploadResult{}, "", fmt.Errorf("marshal encrypted Azure multipart metadata: %w", err)
	}
	delete(properties.Metadata, string(keyMultipartEncryption))
	delete(properties.Metadata, string(keyMpZeroBytesParts))
	mpMetadataString := string(mpMetadata)
	properties.Metadata[string(keyMpMetadata)] = &mpMetadataString
	if err := storeAzureEncryptionMetadata(properties.Metadata, intent, totalSize); err != nil {
		return s3response.CompleteMultipartUploadResult{}, "", err
	}

	plaintextReader, plaintextWriter := io.Pipe()
	producerDone := make(chan error, 1)
	go func() {
		err := az.writeEncryptedAzureParts(ctx, plaintextWriter, *input.Bucket, *input.Key, *input.UploadId, selected, intent)
		if err != nil {
			_ = plaintextWriter.CloseWithError(err)
		} else {
			err = plaintextWriter.Close()
		}
		producerDone <- err
		close(producerDone)
	}()
	uploadBody, encryptionDone := az.encryptedUploadReader(ctx, encryption.Identity{
		Bucket: *input.Bucket, Key: *input.Key, VersionID: azureNullVersionID,
	}, intent, plaintextReader, totalSize)
	uploadResponse, uploadErr := az.client.UploadStream(ctx, *input.Bucket, *input.Key, uploadBody, &blockblob.UploadStreamOptions{
		Metadata: properties.Metadata,
		Tags:     parseAzTags(tags.BlobTagSet),
		HTTPHeaders: &blob.HTTPHeaders{
			BlobContentType: properties.ContentType, BlobContentEncoding: properties.ContentEncoding,
			BlobContentDisposition: properties.ContentDisposition, BlobContentLanguage: properties.ContentLanguage,
			BlobCacheControl: properties.CacheControl,
		},
	})
	_ = uploadBody.Close()
	_ = plaintextReader.Close()
	encryptionErr := <-encryptionDone
	producerErr := <-producerDone
	if uploadErr != nil {
		return s3response.CompleteMultipartUploadResult{}, "", parseMpError(uploadErr)
	}
	if producerErr != nil {
		return s3response.CompleteMultipartUploadResult{}, "", producerErr
	}
	if encryptionErr != nil {
		return s3response.CompleteMultipartUploadResult{}, "", fmt.Errorf("encrypt completed Azure multipart object: %w", encryptionErr)
	}
	if err := az.cleanupEncryptedMultipart(ctx, *input.Bucket, *input.Key, *input.UploadId, listed.Parts); err != nil {
		return s3response.CompleteMultipartUploadResult{}, "", err
	}
	return s3response.CompleteMultipartUploadResult{
		Bucket: input.Bucket, Key: input.Key,
		ETag: backend.GetPtrFromString(convertAzureEtag(uploadResponse.ETag)), Encryption: azureEncryptionResultPtr(intent),
	}, "", nil
}

func (az *Azure) writeEncryptedAzureParts(ctx context.Context, destination io.Writer, bucket, object, uploadID string, parts []s3response.Part, intent *encryption.Intent) error {
	for _, part := range parts {
		partNumber := int32(part.PartNumber)
		client, err := az.getBlobClient(bucket, azureMultipartPartPath(object, uploadID, partNumber))
		if err != nil {
			return err
		}
		properties, err := client.GetProperties(ctx, nil)
		if err != nil {
			return parseMpError(err)
		}
		storedSize := int64(0)
		if properties.ContentLength != nil {
			storedSize = *properties.ContentLength
		}
		customerAlgorithm, customerKey, customerKeyMD5 := customerHeadersForIntent(intent)
		_, _, metadataEncrypted, metadataErr := loadAzureEncryptionMetadata(properties.Metadata)
		if metadataErr != nil {
			return metadataErr
		}
		reader, result, encrypted, err := az.openEncryptedReader(ctx, &azureBlobReaderAt{ctx: ctx, client: client}, storedSize,
			azureMultipartPartIdentity(bucket, object, uploadID, partNumber), metadataEncrypted, customerAlgorithm, customerKey, customerKeyMD5)
		if err != nil {
			return err
		}
		if !encrypted || result.Mode != intent.Mode || reader.PlaintextSize() != part.Size {
			if reader != nil {
				reader.Close()
			}
			return encryption.ErrInvalidContainer
		}
		body, err := reader.RangeReader(0, reader.PlaintextSize())
		if err == nil {
			_, err = io.Copy(destination, body)
		}
		if body != nil {
			_ = body.Close()
		}
		_ = reader.Close()
		if err != nil {
			return fmt.Errorf("read encrypted Azure multipart part %d: %w", partNumber, err)
		}
	}
	return nil
}

func customerHeadersForIntent(intent *encryption.Intent) (string, string, string) {
	if intent == nil || intent.Mode != encryption.ModeSSEC {
		return "", "", ""
	}
	return "AES256", base64.StdEncoding.EncodeToString(intent.CustomerKey), base64.StdEncoding.EncodeToString(intent.CustomerKeyMD5[:])
}

func (az *Azure) cleanupEncryptedMultipart(ctx context.Context, bucket, object, uploadID string, parts []s3response.Part) error {
	for _, path := range encryptedMultipartCleanupPaths(object, uploadID, parts) {
		_, err := az.client.DeleteBlob(ctx, bucket, path, nil)
		if err != nil {
			parsed := parseMpError(err)
			if isS3ErrorCode(parsed, s3err.GetAPIError(s3err.ErrNoSuchUpload).Code) {
				continue
			}
			return parsed
		}
	}
	return nil
}

func encryptedMultipartCleanupPaths(object, uploadID string, parts []s3response.Part) []string {
	paths := make([]string, 0, len(parts)+1)
	for _, part := range parts {
		paths = append(paths, azureMultipartPartPath(object, uploadID, int32(part.PartNumber)))
	}
	// The marker is the retry journal. Remove it only after every hidden part
	// has been removed so a transient failure remains discoverable.
	paths = append(paths, createMetaTmpPath(object, uploadID))
	return paths
}

func isS3ErrorCode(err error, code string) bool {
	var apiErr s3err.S3Error
	return errors.As(err, &apiErr) && apiErr.BaseError().Code == code
}

func completedAzureMultipartUploadID(metadata map[string]*string) (string, bool) {
	encoded := metadataValue(metadata, string(keyMpMetadata))
	if encoded == "" {
		return "", false
	}
	mpMetadata, err := backend.UnmarshalMpUploadMetadata([]byte(encoded), true)
	if err != nil {
		return "", false
	}
	return mpMetadata.UploadID, true
}

func (az *Azure) resumeCompletedEncryptedMultipart(ctx context.Context, input *s3.CompleteMultipartUploadInput, state *azureMultipartEncryptionState) (s3response.CompleteMultipartUploadResult, bool, error) {
	finalClient, err := az.getBlobClient(*input.Bucket, *input.Key)
	if err != nil {
		return s3response.CompleteMultipartUploadResult{}, false, err
	}
	finalProperties, err := finalClient.GetProperties(ctx, nil)
	if err != nil {
		parsed := azureErrToS3Err(err)
		if isS3ErrorCode(parsed, s3err.GetAPIError(s3err.ErrNoSuchKey).Code) {
			return s3response.CompleteMultipartUploadResult{}, false, nil
		}
		return s3response.CompleteMultipartUploadResult{}, false, parsed
	}
	completedUploadID, completed := completedAzureMultipartUploadID(finalProperties.Metadata)
	if !completed || completedUploadID != *input.UploadId {
		return s3response.CompleteMultipartUploadResult{}, false, nil
	}

	intent, err := azureMultipartIntent(state, getString(input.SSECustomerAlgorithm), getString(input.SSECustomerKey), getString(input.SSECustomerKeyMD5))
	if err != nil {
		return s3response.CompleteMultipartUploadResult{}, false, err
	}
	defer intent.CustomerKey.Destroy()
	result, _, encrypted, err := loadAzureEncryptionMetadata(finalProperties.Metadata)
	if err != nil || !encrypted || result.Mode != state.Mode {
		if err != nil {
			return s3response.CompleteMultipartUploadResult{}, false, err
		}
		return s3response.CompleteMultipartUploadResult{}, false, encryption.ErrInvalidContainer
	}

	maxParts := int32(10000)
	remaining, err := az.listEncryptedParts(ctx, &s3.ListPartsInput{
		Bucket: input.Bucket, Key: input.Key, UploadId: input.UploadId,
		MaxParts: &maxParts, PartNumberMarker: backend.GetPtrFromString(""),
	})
	if err != nil {
		return s3response.CompleteMultipartUploadResult{}, false, err
	}
	if err := az.cleanupEncryptedMultipart(ctx, *input.Bucket, *input.Key, *input.UploadId, remaining.Parts); err != nil {
		return s3response.CompleteMultipartUploadResult{}, false, err
	}
	return s3response.CompleteMultipartUploadResult{
		Bucket:     input.Bucket,
		Key:        input.Key,
		ETag:       backend.GetPtrFromString(convertAzureEtag(finalProperties.ETag)),
		Encryption: &result,
	}, true, nil
}

func metadataValue(metadata map[string]*string, name string) string {
	for key, value := range metadata {
		if value != nil && strings.EqualFold(key, name) {
			return *value
		}
	}
	return ""
}

func (az *Azure) encryptBytes(ctx context.Context, identity encryption.Identity, intent *encryption.Intent, plaintext []byte) ([]byte, error) {
	layers, err := az.encryptionLayers(intent)
	if err != nil {
		return nil, err
	}
	defer destroyLayerProviders(layers)
	var destination bytes.Buffer
	writer, err := encryption.NewWriter(ctx, &destination, encryption.WriterOptions{
		Identity: identity, Mode: intent.Mode, PlaintextSize: int64(len(plaintext)), Layers: layers,
		BucketKeyEnabled: intent.BucketKeyEnabled,
	})
	if err != nil {
		return nil, err
	}
	if _, err := writer.Write(plaintext); err != nil {
		return nil, err
	}
	if err := writer.Close(); err != nil {
		return nil, err
	}
	return destination.Bytes(), nil
}

func (az *Azure) encryptedUploadReader(ctx context.Context, identity encryption.Identity, intent *encryption.Intent, plaintext io.Reader, plaintextSize int64) (io.ReadCloser, <-chan error) {
	reader, writer := io.Pipe()
	done := make(chan error, 1)
	go func() {
		layers, err := az.encryptionLayers(intent)
		if err == nil {
			var encryptedWriter *encryption.Writer
			encryptedWriter, err = encryption.NewWriter(ctx, writer, encryption.WriterOptions{
				Identity: identity, Mode: intent.Mode, PlaintextSize: plaintextSize, Layers: layers,
				BucketKeyEnabled: intent.BucketKeyEnabled,
			})
			destroyLayerProviders(layers)
			if err == nil {
				_, err = io.Copy(encryptedWriter, plaintext)
			}
			if closeErr := encryptedWriterClose(encryptedWriter); err == nil {
				err = closeErr
			}
		}
		if err != nil {
			_ = writer.CloseWithError(err)
		} else {
			err = writer.Close()
		}
		done <- err
		close(done)
	}()
	return reader, done
}

func encryptedWriterClose(writer *encryption.Writer) error {
	if writer == nil {
		return nil
	}
	return writer.Close()
}

type azureBlobReaderAt struct {
	ctx    context.Context
	client *blob.Client
}

func (reader *azureBlobReaderAt) ReadAt(destination []byte, offset int64) (int, error) {
	if len(destination) == 0 {
		return 0, nil
	}
	response, err := reader.client.DownloadStream(reader.ctx, &blob.DownloadStreamOptions{
		Range: blob.HTTPRange{Offset: offset, Count: int64(len(destination))},
	})
	if err != nil {
		return 0, azureErrToS3Err(err)
	}
	defer response.Body.Close()
	n, err := io.ReadFull(response.Body, destination)
	if errors.Is(err, io.ErrUnexpectedEOF) {
		err = io.EOF
	}
	return n, err
}

type azureEncryptedBody struct {
	body   io.ReadCloser
	reader *encryption.Reader
}

func (body *azureEncryptedBody) Read(destination []byte) (int, error) {
	return body.body.Read(destination)
}

func (body *azureEncryptedBody) Close() error {
	bodyErr := body.body.Close()
	readerErr := body.reader.Close()
	if bodyErr != nil {
		return bodyErr
	}
	return readerErr
}

func destroyLayerProviders(layers []encryption.LayerRequest) {
	for _, layer := range layers {
		if destroyer, ok := layer.Provider.(interface{ Destroy() }); ok {
			destroyer.Destroy()
		}
	}
}

func (az *Azure) openEncryptedReader(ctx context.Context, source io.ReaderAt, size int64, identity encryption.Identity, expectedEncrypted bool, customerAlgorithm, customerKey, customerKeyMD5 string) (*encryption.Reader, encryption.Result, bool, error) {
	headers := encryption.RequestHeaders{CustomerAlgorithm: customerAlgorithm, CustomerKey: customerKey, CustomerKeyMD5: customerKeyMD5}
	hasCustomerKey := encryption.HasCustomerKeyHeaders(headers)
	if size == 0 {
		if hasCustomerKey {
			return nil, encryption.Result{}, false, s3err.GetAPIError(s3err.ErrInvalidRequest)
		}
		return nil, encryption.Result{}, false, nil
	}
	isContainer, err := encryption.IsContainer(source)
	if err != nil {
		return nil, encryption.Result{}, false, err
	}
	if !isContainer {
		if expectedEncrypted {
			return nil, encryption.Result{}, false, encryption.ErrInvalidContainer
		}
		if hasCustomerKey {
			return nil, encryption.Result{}, false, s3err.GetAPIError(s3err.ErrInvalidRequest)
		}
		return nil, encryption.Result{}, false, nil
	}

	providers := az.encryptionProviderMap()
	if hasCustomerKey {
		intent, err := encryption.ParseCustomerKeyHeaders(headers)
		if err != nil {
			return nil, encryption.Result{}, true, s3err.GetAPIError(s3err.ErrInvalidRequest)
		}
		provider, err := encryption.NewCustomerKeyProvider(intent.CustomerKey)
		intent.CustomerKey.Destroy()
		if err != nil {
			return nil, encryption.Result{}, true, s3err.GetAPIError(s3err.ErrInvalidRequest)
		}
		defer provider.Destroy()
		providers[provider.Name()] = provider
	}
	reader, err := encryption.Open(ctx, source, size, identity, providers)
	if err != nil {
		if errors.Is(err, encryption.ErrInvalidContainer) && !expectedEncrypted {
			if hasCustomerKey {
				return nil, encryption.Result{}, false, s3err.GetAPIError(s3err.ErrInvalidRequest)
			}
			return nil, encryption.Result{}, false, nil
		}
		if errors.Is(err, encryption.ErrAuthentication) || errors.Is(err, encryption.ErrKeyNotFound) {
			return nil, encryption.Result{}, true, s3err.GetAPIError(s3err.ErrInvalidRequest)
		}
		return nil, encryption.Result{}, true, fmt.Errorf("open Azure encrypted object: %w", err)
	}
	result := reader.Result()
	if (result.Mode == encryption.ModeSSEC) != hasCustomerKey {
		reader.Close()
		return nil, encryption.Result{}, true, s3err.GetAPIError(s3err.ErrInvalidRequest)
	}
	return reader, result, true, nil
}

func azureEncryptionOutput(result *encryption.Result) (types.ServerSideEncryption, *string, *string, *string, *bool) {
	if result == nil || result.Mode == "" {
		return "", nil, nil, nil, nil
	}
	var algorithm types.ServerSideEncryption
	var kmsKeyID, customerAlgorithm, customerKeyMD5 *string
	switch result.Mode {
	case encryption.ModeSSES3:
		algorithm = types.ServerSideEncryptionAes256
	case encryption.ModeSSEKMS:
		algorithm = types.ServerSideEncryptionAwsKms
		kmsKeyID = backend.GetPtrFromString(result.KMSKeyID)
	case encryption.ModeDSSEKMS:
		algorithm = types.ServerSideEncryptionAwsKmsDsse
		kmsKeyID = backend.GetPtrFromString(result.KMSKeyID)
	case encryption.ModeSSEC:
		customerAlgorithm = backend.GetPtrFromString("AES256")
		customerKeyMD5 = backend.GetPtrFromString(result.CustomerKeyMD5)
	}
	if result.Mode == encryption.ModeSSEKMS {
		bucketKeyEnabled := result.BucketKeyEnabled
		return algorithm, kmsKeyID, customerAlgorithm, customerKeyMD5, &bucketKeyEnabled
	}
	return algorithm, kmsKeyID, customerAlgorithm, customerKeyMD5, nil
}

func (az *Azure) copyObjectWithEnvelope(ctx context.Context, input s3response.CopyObjectInput, sourceBucket, sourceKey string, sourceHead *s3.HeadObjectOutput) (s3response.CopyObjectOutput, error) {
	if sourceHead.ContentLength != nil && *sourceHead.ContentLength > az.copyObjectThreshold {
		return s3response.CopyObjectOutput{}, s3err.GetCopySourceObjectTooLargeErr(az.copyObjectThreshold)
	}
	source, err := az.GetObject(ctx, azureEnvelopeCopyGetInput(input, sourceBucket, sourceKey))
	if err != nil {
		return s3response.CopyObjectOutput{}, err
	}
	defer source.Body.Close()

	body := io.Reader(source.Body)
	if sourceBucket == *input.Bucket && sourceKey == *input.Key {
		payload, err := io.ReadAll(source.Body)
		if err != nil {
			return s3response.CopyObjectOutput{}, fmt.Errorf("buffer self-copy source: %w", err)
		}
		body = bytes.NewReader(payload)
	}

	put := s3response.PutObjectInput{
		Body:                      body,
		Bucket:                    input.Bucket,
		Key:                       input.Key,
		ContentLength:             source.ContentLength,
		ContentType:               input.ContentType,
		ContentEncoding:           input.ContentEncoding,
		ContentDisposition:        input.ContentDisposition,
		ContentLanguage:           input.ContentLanguage,
		CacheControl:              input.CacheControl,
		Expires:                   input.Expires,
		WebsiteRedirectLocation:   input.WebsiteRedirectLocation,
		Metadata:                  input.Metadata,
		Tagging:                   input.Tagging,
		ObjectLockRetainUntilDate: input.ObjectLockRetainUntilDate,
		ObjectLockMode:            input.ObjectLockMode,
		ObjectLockLegalHoldStatus: input.ObjectLockLegalHoldStatus,
		Encryption:                input.DestinationEncryption,
	}
	if input.MetadataDirective == types.MetadataDirectiveCopy {
		put.CacheControl = source.CacheControl
		put.ContentDisposition = source.ContentDisposition
		put.ContentEncoding = source.ContentEncoding
		put.ContentLanguage = source.ContentLanguage
		put.ContentType = source.ContentType
		put.Expires = source.ExpiresString
		// S3 does not implicitly copy WebsiteRedirectLocation. It is only set
		// when the destination metadata is explicitly replaced with that value.
		put.WebsiteRedirectLocation = nil
		put.Metadata = source.Metadata
	}
	if input.TaggingDirective != types.TaggingDirectiveReplace {
		put.Tagging = nil
	}
	var copiedTags map[string]string
	if input.TaggingDirective == types.TaggingDirectiveCopy {
		sourceClient, err := az.getBlobClient(sourceBucket, sourceKey)
		if err != nil {
			return s3response.CopyObjectOutput{}, err
		}
		tags, err := sourceClient.GetTags(ctx, nil)
		if err != nil {
			return s3response.CopyObjectOutput{}, azureErrToS3Err(err)
		}
		copiedTags = parseAzTags(tags.BlobTagSet)
	}

	created, err := az.PutObject(ctx, put)
	if err != nil {
		return s3response.CopyObjectOutput{}, err
	}
	if input.TaggingDirective == types.TaggingDirectiveCopy {
		destinationClient, err := az.getBlobClient(*input.Bucket, *input.Key)
		if err != nil {
			return s3response.CopyObjectOutput{}, err
		}
		if _, err := destinationClient.SetTags(ctx, copiedTags, nil); err != nil {
			return s3response.CopyObjectOutput{}, azureErrToS3Err(err)
		}
	}

	serverSideEncryption, kmsKeyID, customerAlgorithm, customerKeyMD5, bucketKeyEnabled := azureEncryptionOutput(created.Encryption)
	now := time.Now().UTC()
	return s3response.CopyObjectOutput{
		CopyObjectResult:     &s3response.CopyObjectResult{ETag: &created.ETag, LastModified: &now},
		ServerSideEncryption: serverSideEncryption,
		SSEKMSKeyId:          kmsKeyID,
		SSECustomerAlgorithm: customerAlgorithm,
		SSECustomerKeyMD5:    customerKeyMD5,
		BucketKeyEnabled:     bucketKeyEnabled,
	}, nil
}

func azureEnvelopeCopyGetInput(input s3response.CopyObjectInput, sourceBucket, sourceKey string) *s3.GetObjectInput {
	return &s3.GetObjectInput{
		Bucket:               &sourceBucket,
		Key:                  &sourceKey,
		IfMatch:              input.CopySourceIfMatch,
		IfNoneMatch:          input.CopySourceIfNoneMatch,
		IfModifiedSince:      input.CopySourceIfModifiedSince,
		IfUnmodifiedSince:    input.CopySourceIfUnmodifiedSince,
		SSECustomerAlgorithm: input.CopySourceSSECustomerAlgorithm,
		SSECustomerKey:       input.CopySourceSSECustomerKey,
		SSECustomerKeyMD5:    input.CopySourceSSECustomerKeyMD5,
	}
}
