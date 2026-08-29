// Copyright 2026 Versity Software
// This file is licensed under the Apache License, Version 2.0.

package encryption

import (
	"crypto/md5"
	"crypto/subtle"
	"encoding/base64"
	"encoding/json"
	"errors"
	"net/netip"
	"strings"
)

var (
	ErrInvalidEncryptionHeaders = errors.New("invalid encryption headers")
	ErrSSECBlocked              = errors.New("SSE-C is blocked for this bucket")
	ErrInsecureTransport        = errors.New("SSE-C requires a secure transport")
)

type RequestHeaders struct {
	Algorithm         string
	KMSKeyID          string
	KMSContext        string
	BucketKeyEnabled  string
	CustomerAlgorithm string
	CustomerKey       string
	CustomerKeyMD5    string
}

func ResolveWriteIntent(headers RequestHeaders, configuration Configuration, caps Capabilities) (Intent, error) {
	if len(configuration.Rules) != 1 || configuration.Rules[0].Default == nil {
		return Intent{}, ErrInvalidConfiguration
	}
	rule := configuration.Rules[0]
	hasSSEC := headers.CustomerAlgorithm != "" || headers.CustomerKey != "" || headers.CustomerKeyMD5 != ""
	if hasSSEC {
		if headers.Algorithm != "" || headers.KMSKeyID != "" || headers.KMSContext != "" || headers.BucketKeyEnabled != "" {
			return Intent{}, ErrInvalidEncryptionHeaders
		}
		if !caps.SSEC {
			return Intent{}, ErrUnsupportedEncryption
		}
		if rule.BlocksSSEC() {
			return Intent{}, ErrSSECBlocked
		}
		return ParseCustomerKeyHeaders(headers)
	}

	algorithm := Algorithm(headers.Algorithm)
	keyID := headers.KMSKeyID
	if algorithm == "" {
		algorithm = rule.Default.Algorithm
		keyID = rule.Default.KMSKeyID
	}
	intent := Intent{KMSKeyID: keyID}
	switch algorithm {
	case AlgorithmAES256:
		if !caps.SSES3 || headers.KMSKeyID != "" || headers.KMSContext != "" {
			return Intent{}, ErrUnsupportedEncryption
		}
		intent.Mode = ModeSSES3
	case AlgorithmAWSKMS:
		if !caps.SSEKMS {
			return Intent{}, ErrUnsupportedEncryption
		}
		intent.Mode = ModeSSEKMS
	case AlgorithmDSSEKMS:
		if !caps.DSSEKMS {
			return Intent{}, ErrUnsupportedEncryption
		}
		intent.Mode = ModeDSSEKMS
	default:
		return Intent{}, ErrInvalidEncryptionHeaders
	}

	if headers.KMSContext != "" {
		decoded, err := base64.StdEncoding.DecodeString(headers.KMSContext)
		var contextValues map[string]string
		if err != nil || json.Unmarshal(decoded, &contextValues) != nil || contextValues == nil {
			return Intent{}, ErrInvalidEncryptionHeaders
		}
		if _, reserved := contextValues[kmsObjectBindingContextKey]; reserved {
			return Intent{}, ErrInvalidEncryptionHeaders
		}
		intent.KMSContext = decoded
	}
	if headers.BucketKeyEnabled != "" {
		switch strings.ToLower(headers.BucketKeyEnabled) {
		case "true":
			intent.BucketKeyEnabled = true
		case "false":
		default:
			return Intent{}, ErrInvalidEncryptionHeaders
		}
	}
	if intent.Mode == ModeDSSEKMS && intent.BucketKeyEnabled {
		return Intent{}, ErrInvalidEncryptionHeaders
	}
	if intent.BucketKeyEnabled && !caps.BucketKeys && intent.Mode == ModeSSEKMS {
		return Intent{}, ErrUnsupportedEncryption
	}
	return intent, nil
}

func ParseCustomerKeyHeaders(headers RequestHeaders) (Intent, error) {
	if headers.CustomerAlgorithm != "AES256" || headers.CustomerKey == "" || headers.CustomerKeyMD5 == "" {
		return Intent{}, ErrInvalidEncryptionHeaders
	}
	key, err := base64.StdEncoding.DecodeString(headers.CustomerKey)
	if err != nil || len(key) != DataKeySize {
		clear(key)
		return Intent{}, ErrInvalidEncryptionHeaders
	}
	providedMD5, err := base64.StdEncoding.DecodeString(headers.CustomerKeyMD5)
	if err != nil || len(providedMD5) != md5.Size {
		clear(key)
		return Intent{}, ErrInvalidEncryptionHeaders
	}
	digest := md5.Sum(key)
	if subtle.ConstantTimeCompare(digest[:], providedMD5) != 1 {
		clear(key)
		return Intent{}, ErrInvalidEncryptionHeaders
	}
	intent := Intent{Mode: ModeSSEC, CustomerKey: SensitiveBytes(key), CustomerKeyMD5: digest}
	return intent, nil
}

func SecureTransport(directTLS bool, peer netip.Addr, forwardedProto string, trusted []netip.Prefix) bool {
	if directTLS {
		return true
	}
	if forwardedProto == "" || strings.ContainsAny(forwardedProto, ",;") || !strings.EqualFold(strings.TrimSpace(forwardedProto), "https") {
		return false
	}
	for _, prefix := range trusted {
		if prefix.Contains(peer) {
			return true
		}
	}
	return false
}

func HasCustomerKeyHeaders(headers RequestHeaders) bool {
	return headers.CustomerAlgorithm != "" || headers.CustomerKey != "" || headers.CustomerKeyMD5 != ""
}
