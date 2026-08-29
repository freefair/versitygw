// Copyright 2026 Versity Software
// This file is licensed under the Apache License, Version 2.0.

// Package encryption contains the backend-neutral S3 encryption contract,
// envelope-key providers, and the authenticated POSIX container format.
package encryption

import (
	"encoding/xml"
	"errors"
	"strings"
)

const DataKeySize = 32

type Algorithm string

const (
	AlgorithmAES256  Algorithm = "AES256"
	AlgorithmAWSKMS  Algorithm = "aws:kms"
	AlgorithmDSSEKMS Algorithm = "aws:kms:dsse"
)

type Mode string

const (
	ModeSSES3   Mode = "SSE-S3"
	ModeSSEC    Mode = "SSE-C"
	ModeSSEKMS  Mode = "SSE-KMS"
	ModeDSSEKMS Mode = "DSSE-KMS"
)

var (
	ErrInvalidConfiguration   = errors.New("invalid encryption configuration")
	ErrUnsupportedEncryption  = errors.New("unsupported encryption")
	ErrInsecureKeyPermissions = errors.New("insecure key permissions")
	ErrInvalidKey             = errors.New("invalid encryption key")
	ErrKeyNotFound            = errors.New("encryption key not found")
	ErrAuthentication         = errors.New("encrypted data authentication failed")
	ErrInvalidContainer       = errors.New("invalid encrypted object container")
	ErrIdentityMismatch       = errors.New("encrypted object identity mismatch")
)

type Capabilities struct {
	SSES3             bool
	SSEC              bool
	SSEKMS            bool
	DSSEKMS           bool
	BucketKeys        bool
	NativePassthrough bool
}

type Configuration struct {
	XMLName xml.Name `xml:"ServerSideEncryptionConfiguration" json:"-"`
	XMLNS   string   `xml:"xmlns,attr,omitempty" json:"-"`
	Rules   []Rule   `xml:"Rule" json:"rules"`
}

type Rule struct {
	Default                *DefaultEncryption      `xml:"ApplyServerSideEncryptionByDefault,omitempty"`
	BucketKeyEnabled       *bool                   `xml:"BucketKeyEnabled,omitempty"`
	BlockedEncryptionTypes *BlockedEncryptionTypes `xml:"BlockedEncryptionTypes,omitempty"`
}

func (r Rule) BlocksSSEC() bool {
	return r.BlockedEncryptionTypes != nil && len(r.BlockedEncryptionTypes.Types) == 1 && r.BlockedEncryptionTypes.Types[0] == "SSE-C"
}

type DefaultEncryption struct {
	Algorithm Algorithm `xml:"SSEAlgorithm"`
	KMSKeyID  string    `xml:"KMSMasterKeyID,omitempty"`
}

type BlockedEncryptionTypes struct {
	Types []string `xml:"EncryptionType"`
}

func DefaultConfiguration() Configuration {
	blocked := &BlockedEncryptionTypes{Types: []string{"SSE-C"}}
	return Configuration{Rules: []Rule{{
		Default:                &DefaultEncryption{Algorithm: AlgorithmAES256},
		BlockedEncryptionTypes: blocked,
	}}}
}

// LegacyConfiguration is the explicit migration state for buckets that
// predate gateway-managed encryption. New writes use SSE-S3 while SSE-C stays
// available until the operator completes inventory and opts into blocking it.
func LegacyConfiguration() Configuration {
	notBlocked := &BlockedEncryptionTypes{Types: []string{"NONE"}}
	return Configuration{Rules: []Rule{{
		Default:                &DefaultEncryption{Algorithm: AlgorithmAES256},
		BlockedEncryptionTypes: notBlocked,
	}}}
}

type Intent struct {
	Mode             Mode
	KMSKeyID         string
	KMSContext       []byte
	BucketKeyEnabled bool
	CustomerKey      SensitiveBytes
	CustomerKeyMD5   [16]byte
}

type Result struct {
	Mode             Mode
	KMSKeyID         string
	CustomerKeyMD5   string
	BucketKeyEnabled bool
}

type SensitiveBytes []byte

func (b *SensitiveBytes) Destroy() {
	if b == nil {
		return
	}
	for i := range *b {
		(*b)[i] = 0
	}
	*b = nil
}

type Identity struct {
	Bucket    string `json:"bucket"`
	Key       string `json:"key"`
	VersionID string `json:"version_id,omitempty"`
}

func (i Identity) valid() bool {
	return strings.TrimSpace(i.Bucket) != "" && i.Key != ""
}
