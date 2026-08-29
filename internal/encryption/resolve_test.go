// Copyright 2026 Versity Software
// This file is licensed under the Apache License, Version 2.0.

package encryption

import (
	"bytes"
	"crypto/md5"
	"encoding/base64"
	"net/netip"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestResolveWriteIntentUsesBucketDefault(t *testing.T) {
	t.Parallel()

	intent, err := ResolveWriteIntent(RequestHeaders{}, Configuration{Rules: []Rule{{Default: &DefaultEncryption{Algorithm: AlgorithmAWSKMS, KMSKeyID: "local-key"}}}}, Capabilities{SSEKMS: true})
	require.NoError(t, err)
	require.Equal(t, ModeSSEKMS, intent.Mode)
	require.Equal(t, "local-key", intent.KMSKeyID)
}

func TestResolveWriteIntentRejectsInvalidKMSContextShapeAndReservedKey(t *testing.T) {
	configuration := Configuration{Rules: []Rule{{Default: &DefaultEncryption{Algorithm: AlgorithmAWSKMS, KMSKeyID: "key"}}}}
	for _, body := range []string{
		`{"tenant":42}`,
		`{"versitygw:object-binding":"caller value"}`,
		`null`,
	} {
		_, err := ResolveWriteIntent(RequestHeaders{KMSContext: base64.StdEncoding.EncodeToString([]byte(body))}, configuration, Capabilities{SSEKMS: true})
		require.ErrorIs(t, err, ErrInvalidEncryptionHeaders)
	}
}

func TestResolveWriteIntentValidatesSSEC(t *testing.T) {
	t.Parallel()

	key := bytes.Repeat([]byte{0x71}, DataKeySize)
	digest := md5.Sum(key)
	headers := RequestHeaders{
		CustomerAlgorithm: "AES256",
		CustomerKey:       base64.StdEncoding.EncodeToString(key),
		CustomerKeyMD5:    base64.StdEncoding.EncodeToString(digest[:]),
	}
	configuration := Configuration{Rules: []Rule{{Default: &DefaultEncryption{Algorithm: AlgorithmAES256}, BlockedEncryptionTypes: &BlockedEncryptionTypes{Types: []string{"NONE"}}}}}
	intent, err := ResolveWriteIntent(headers, configuration, Capabilities{SSES3: true, SSEC: true})
	require.NoError(t, err)
	require.Equal(t, ModeSSEC, intent.Mode)
	require.Equal(t, key, []byte(intent.CustomerKey))
	intent.CustomerKey.Destroy()

	headers.CustomerKeyMD5 = base64.StdEncoding.EncodeToString(bytes.Repeat([]byte{0}, md5.Size))
	_, err = ResolveWriteIntent(headers, configuration, Capabilities{SSES3: true, SSEC: true})
	require.ErrorIs(t, err, ErrInvalidEncryptionHeaders)
}

func TestResolveWriteIntentRejectsBlockedSSEC(t *testing.T) {
	t.Parallel()

	key := bytes.Repeat([]byte{0x72}, DataKeySize)
	digest := md5.Sum(key)
	_, err := ResolveWriteIntent(RequestHeaders{
		CustomerAlgorithm: "AES256",
		CustomerKey:       base64.StdEncoding.EncodeToString(key),
		CustomerKeyMD5:    base64.StdEncoding.EncodeToString(digest[:]),
	}, DefaultConfiguration(), Capabilities{SSES3: true, SSEC: true})
	require.ErrorIs(t, err, ErrSSECBlocked)
}

func TestSecureTransportTrustedProxyRules(t *testing.T) {
	t.Parallel()

	trusted := []netip.Prefix{netip.MustParsePrefix("10.23.0.0/16"), netip.MustParsePrefix("2001:db8::/32")}
	require.True(t, SecureTransport(true, netip.MustParseAddr("192.0.2.1"), "", trusted))
	require.True(t, SecureTransport(false, netip.MustParseAddr("10.23.4.5"), "https", trusted))
	require.True(t, SecureTransport(false, netip.MustParseAddr("2001:db8::5"), "HTTPS", trusted))
	require.False(t, SecureTransport(false, netip.MustParseAddr("192.0.2.1"), "https", trusted))
	require.False(t, SecureTransport(false, netip.MustParseAddr("10.23.4.5"), "https,http", trusted))
	require.False(t, SecureTransport(false, netip.MustParseAddr("10.23.4.5"), "http", trusted))
}
