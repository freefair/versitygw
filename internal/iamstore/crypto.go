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
	"bytes"
	"context"
	"fmt"

	"github.com/versity/versitygw/internal/encryption"
)

// identityBucket namespaces IAM ciphertext against S3 object ciphertext.
// Bucket names cannot contain underscores, so no object can ever present the
// identity an IAM store file is bound to, and an object container can never be
// opened as an IAM store.
const identityBucket = "__versitygw_iam__"

// Protector encrypts and decrypts IAM store files with the gateway's
// authenticated envelope container. It holds no key material itself: the
// wrapping key never leaves the key provider.
type Protector struct {
	primary   encryption.KeyProvider
	providers encryption.ProviderMap
	keyID     string
	mode      encryption.Mode
	// close releases key material the protector owns. It is set when the
	// protector built the provider itself.
	close func()
}

// NewProtector binds a key provider to the IAM store. keyID selects a specific
// wrapping key; empty means the provider's active key.
func NewProtector(primary encryption.KeyProvider, keyID string) (*Protector, error) {
	if primary == nil {
		return nil, fmt.Errorf("%w: key provider is required", encryption.ErrInvalidKey)
	}
	if err := primary.ValidateKeyReference(keyID); err != nil {
		return nil, fmt.Errorf("validate iam wrapping key: %w", err)
	}

	// The container mode records how the data key is wrapped so an operator
	// reading a header can tell a KMS-wrapped store from a locally wrapped
	// one. AWS KMS is the only provider that reaches outside the host.
	mode := encryption.ModeSSES3
	if _, ok := primary.(*encryption.AWSKMSProvider); ok {
		mode = encryption.ModeSSEKMS
	}

	return &Protector{
		primary:   primary,
		providers: encryption.ProviderMap{primary.Name(): primary},
		keyID:     keyID,
		mode:      mode,
	}, nil
}

// KeyReference reports the wrapping key the protector writes with, for
// operator-facing status output.
func (p *Protector) KeyReference() string {
	if p.keyID != "" {
		return p.keyID
	}
	if referencer, ok := p.primary.(encryption.ActiveKeyReferencer); ok {
		return referencer.ActiveKeyReference()
	}
	return ""
}

// ProviderName reports the key provider backing the protector.
func (p *Protector) ProviderName() string { return p.primary.Name() }

// Close wipes wrapping key material the protector owns. It is a no-op for a
// protector built around a caller-owned provider.
func (p *Protector) Close() {
	if p.close != nil {
		p.close()
		p.close = nil
	}
}

// Encode wraps plaintext in a container bound to the store file's name. The
// backup file carries a byte copy of the primary file, so callers pass the
// primary file's name for both.
func (p *Protector) Encode(ctx context.Context, name string, plaintext []byte) ([]byte, error) {
	buffer := bytes.NewBuffer(nil)
	writer, err := encryption.NewWriter(ctx, buffer, encryption.WriterOptions{
		Identity:      identityFor(name),
		Mode:          p.mode,
		PlaintextSize: int64(len(plaintext)),
		Layers:        []encryption.LayerRequest{{Provider: p.primary, KeyID: p.keyID}},
	})
	if err != nil {
		return nil, fmt.Errorf("initialize iam container: %w", err)
	}
	if _, err := writer.Write(plaintext); err != nil {
		_ = writer.Close()
		return nil, fmt.Errorf("encrypt iam data: %w", err)
	}
	if err := writer.Close(); err != nil {
		return nil, fmt.Errorf("finalize iam container: %w", err)
	}
	return buffer.Bytes(), nil
}

// Decode returns the plaintext of an encrypted store file. It fails on any
// authentication error rather than returning partial data.
func (p *Protector) Decode(ctx context.Context, name string, raw []byte) ([]byte, error) {
	reader, err := encryption.Open(ctx, bytes.NewReader(raw), int64(len(raw)), identityFor(name), p.providers)
	if err != nil {
		return nil, fmt.Errorf("open iam container: %w", err)
	}
	defer reader.Close()

	plaintext, err := reader.ReadRange(0, reader.PlaintextSize())
	if err != nil {
		return nil, fmt.Errorf("decrypt iam data: %w", err)
	}
	return plaintext, nil
}

// Rewrap re-wraps the data key with the protector's current key without
// re-encrypting the payload.
func (p *Protector) Rewrap(ctx context.Context, name string, raw []byte) ([]byte, error) {
	buffer := bytes.NewBuffer(nil)
	if _, err := encryption.Rewrap(ctx, buffer, bytes.NewReader(raw), int64(len(raw)), identityFor(name), p.providers); err != nil {
		return nil, fmt.Errorf("rewrap iam container: %w", err)
	}
	return buffer.Bytes(), nil
}

// Inspect reports the container header without unwrapping the data key, so it
// works without access to the wrapping key.
func Inspect(raw []byte) (encryption.ContainerInfo, error) {
	return encryption.Inspect(bytes.NewReader(raw), int64(len(raw)))
}

// IsEncrypted reports whether stored bytes are an encrypted container rather
// than the historical plaintext JSON.
func IsEncrypted(raw []byte) bool {
	encrypted, err := encryption.IsContainer(bytes.NewReader(raw))
	if err != nil {
		// A source short enough to fail the magic-number read cannot be a
		// container; encryption.IsContainer only reports other errors for
		// readers that fail, which a bytes.Reader does not.
		return false
	}
	return encrypted
}

func identityFor(name string) encryption.Identity {
	return encryption.Identity{Bucket: identityBucket, Key: name}
}
