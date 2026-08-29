// Copyright 2026 Versity Software
// This file is licensed under the Apache License, Version 2.0.

package encryption

import "fmt"

func ValidateConfiguration(cfg Configuration, caps Capabilities) (Configuration, error) {
	if len(cfg.Rules) != 1 {
		return Configuration{}, invalidConfig("exactly one Rule is required")
	}

	rule := cfg.Rules[0]
	if rule.Default == nil {
		rule.Default = &DefaultEncryption{Algorithm: AlgorithmAES256}
	}
	if rule.Default.Algorithm == "" {
		return Configuration{}, invalidConfig("SSEAlgorithm is required")
	}

	switch rule.Default.Algorithm {
	case AlgorithmAES256:
		if !caps.SSES3 {
			return Configuration{}, ErrUnsupportedEncryption
		}
		if rule.Default.KMSKeyID != "" {
			return Configuration{}, invalidConfig("KMSMasterKeyID is not valid with AES256")
		}
	case AlgorithmAWSKMS:
		if !caps.SSEKMS {
			return Configuration{}, ErrUnsupportedEncryption
		}
		if rule.BucketKeyEnabled != nil && *rule.BucketKeyEnabled && !caps.BucketKeys {
			return Configuration{}, ErrUnsupportedEncryption
		}
	case AlgorithmDSSEKMS:
		if !caps.DSSEKMS {
			return Configuration{}, ErrUnsupportedEncryption
		}
		if rule.BucketKeyEnabled != nil && *rule.BucketKeyEnabled {
			return Configuration{}, invalidConfig("BucketKeyEnabled is not valid with aws:kms:dsse")
		}
	default:
		return Configuration{}, invalidConfig("unsupported SSEAlgorithm")
	}

	if blocked := rule.BlockedEncryptionTypes; blocked != nil {
		if len(blocked.Types) != 1 {
			return Configuration{}, invalidConfig("BlockedEncryptionTypes requires exactly one EncryptionType")
		}
		switch blocked.Types[0] {
		case "SSE-C":
			// Blocking remains meaningful even if the backend cannot create SSE-C objects.
		case "NONE":
			if !caps.SSEC {
				return Configuration{}, ErrUnsupportedEncryption
			}
		default:
			return Configuration{}, invalidConfig("EncryptionType must be SSE-C or NONE")
		}
	}

	cfg.Rules[0] = rule
	return cfg, nil
}

func invalidConfig(reason string) error {
	return fmt.Errorf("%w: %s", ErrInvalidConfiguration, reason)
}
