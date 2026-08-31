// Copyright 2026 Versity Software
// This file is licensed under the Apache License, Version 2.0
// (the "License"); you may not use this file except in compliance
// with the License.  You may obtain a copy of the License at
//
//   http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing,
// software distributed under the License is distributed on an
// "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
// KIND, either express or implied.  See the License for the
// specific language governing permissions and limitations
// under the License.

package iamstore

import (
	"context"
	"fmt"
	"strings"
	"time"

	awsconfig "github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/service/kms"

	"github.com/versity/versitygw/internal/encryption"
)

const (
	// iamProviderName marks IAM data keys as wrapped by the IAM-specific
	// derivation of the local key, never by the object wrapping key itself.
	iamProviderName = "local-iam"
	// iamDerivationLabel separates the IAM key derivation from every other
	// use of the same local wrapping key.
	iamDerivationLabel = "iam-store"
)

// ProtectorConfig describes the operator's IAM encryption settings, as they
// arrive from command-line flags or an embedding application.
type ProtectorConfig struct {
	// KeyDirectory holds the protected local wrapping keys. Empty disables
	// local wrapping, which is only valid together with AWS KMS.
	KeyDirectory string
	// ActiveKey selects a local key ID; empty uses the directory's active file.
	ActiveKey string
	// KMSProvider selects "local" (default) or "aws".
	KMSProvider string
	// KMSKeyID names the AWS KMS key or alias.
	KMSKeyID string
	// KMSTimeout bounds a single AWS KMS call.
	KMSTimeout time.Duration
	// RequireEncryption refuses to start against a plaintext store.
	RequireEncryption bool
}

// Enabled reports whether the operator asked for IAM store encryption.
func (c ProtectorConfig) Enabled() bool {
	return c.KeyDirectory != "" || c.provider() == "aws"
}

func (c ProtectorConfig) provider() string {
	return strings.ToLower(strings.TrimSpace(c.KMSProvider))
}

// Options turns the configuration into engine options, building the key
// provider when encryption is configured.
func (c ProtectorConfig) Options(ctx context.Context) (Options, error) {
	if !c.Enabled() {
		if c.RequireEncryption {
			return Options{}, fmt.Errorf("iam encryption is required but no key directory or KMS provider is configured")
		}
		if c.ActiveKey != "" || c.KMSKeyID != "" || c.provider() != "" {
			return Options{}, fmt.Errorf("iam encryption settings require an iam encryption key directory or KMS provider")
		}
		return Options{}, nil
	}

	protector, err := NewProtectorFromConfig(ctx, c)
	if err != nil {
		return Options{}, err
	}

	return Options{Protector: protector, RequireEncryption: c.RequireEncryption}, nil
}

// NewProtectorFromConfig builds the IAM store protector for a configuration
// that has encryption enabled.
func NewProtectorFromConfig(ctx context.Context, cfg ProtectorConfig) (*Protector, error) {
	switch cfg.provider() {
	case "", "local":
		if cfg.KeyDirectory == "" {
			return nil, fmt.Errorf("local iam encryption requires an iam encryption key directory")
		}
		if cfg.KMSKeyID != "" {
			return nil, fmt.Errorf("iam encryption KMS key ID requires the aws KMS provider")
		}
		return newLocalProtector(cfg)
	case "aws":
		if cfg.ActiveKey != "" {
			return nil, fmt.Errorf("iam encryption active key applies to the local provider only")
		}
		if cfg.KeyDirectory != "" {
			return nil, fmt.Errorf("iam encryption key directory applies to the local provider only")
		}
		// Without an explicit key the AWS provider falls back to the
		// S3-managed alias, which a non-S3 principal cannot use. Rejecting
		// it here turns a runtime AccessDenied into a startup error.
		if cfg.KMSKeyID == "" {
			return nil, fmt.Errorf("iam encryption KMS key ID is required for the aws KMS provider")
		}
		return newKMSProtector(ctx, cfg)
	default:
		return nil, fmt.Errorf("unsupported iam encryption KMS provider %q", cfg.KMSProvider)
	}
}

func newLocalProtector(cfg ProtectorConfig) (*Protector, error) {
	local, err := encryption.NewLocalProvider(cfg.KeyDirectory, cfg.ActiveKey)
	if err != nil {
		return nil, fmt.Errorf("initialize local iam encryption provider: %w", err)
	}

	// The IAM store never wraps with the object key itself: the derived
	// provider mixes a store-specific label into the wrapping key, so an
	// object container and an IAM container can never open each other.
	derived, err := local.Derived(iamProviderName, iamDerivationLabel)
	if err != nil {
		local.Close()
		return nil, fmt.Errorf("derive iam encryption provider: %w", err)
	}

	protector, err := NewProtector(derived, cfg.ActiveKey)
	if err != nil {
		local.Close()
		return nil, err
	}
	protector.close = local.Close

	return protector, nil
}

func newKMSProtector(ctx context.Context, cfg ProtectorConfig) (*Protector, error) {
	awsConfiguration, err := awsconfig.LoadDefaultConfig(ctx)
	if err != nil {
		return nil, fmt.Errorf("load AWS configuration for iam encryption KMS: %w", err)
	}

	provider, err := encryption.NewAWSKMSProvider(kms.NewFromConfig(awsConfiguration), cfg.KMSKeyID, cfg.KMSTimeout)
	if err != nil {
		return nil, fmt.Errorf("initialize AWS KMS iam encryption provider: %w", err)
	}

	return NewProtector(provider, cfg.KMSKeyID)
}
