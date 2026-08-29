// Copyright 2026 Versity Software
// This file is licensed under the Apache License, Version 2.0.

package controllers

import (
	"errors"
	"net/http/httptest"
	"net/netip"
	"testing"

	"github.com/gofiber/fiber/v3"
	"github.com/versity/versitygw/internal/encryption"
	"github.com/versity/versitygw/s3err"
)

func TestEncryptionRequestErrorMapsBlockedSSECToAccessDenied(t *testing.T) {
	err := encryptionRequestError(encryption.ErrSSECBlocked)
	if !errors.Is(err, s3err.GetAPIError(s3err.ErrAccessDenied)) {
		t.Fatalf("encryptionRequestError() = %v, want AccessDenied", err)
	}
}

func TestExplicitBucketKeyPtr(t *testing.T) {
	intent := &encryption.Intent{Mode: encryption.ModeSSES3}
	if got := explicitBucketKeyPtr("", intent); got != nil {
		t.Fatalf("bucket default produced explicit pointer %v", *got)
	}
	if got := explicitBucketKeyPtr("false", intent); got == nil || *got {
		t.Fatalf("explicit false header produced %v", got)
	}

	intent.BucketKeyEnabled = true
	if got := explicitBucketKeyPtr("true", intent); got == nil || !*got {
		t.Fatalf("explicit true header produced %v", got)
	}
}

func TestSSECTrustedProxyTransportAtControllerBoundary(t *testing.T) {
	tests := []struct {
		name      string
		trusted   []netip.Prefix
		forwarded string
		want      int
	}{
		{name: "explicitly trusted proxy", trusted: []netip.Prefix{netip.MustParsePrefix("0.0.0.0/0"), netip.MustParsePrefix("::/0")}, forwarded: "https", want: 204},
		{name: "header untrusted by default", forwarded: "https", want: 400},
		{name: "multiple forwarded values fail closed", trusted: []netip.Prefix{netip.MustParsePrefix("0.0.0.0/0"), netip.MustParsePrefix("::/0")}, forwarded: "https,http", want: 400},
		{name: "trusted plaintext indication fails closed", trusted: []netip.Prefix{netip.MustParsePrefix("0.0.0.0/0"), netip.MustParsePrefix("::/0")}, forwarded: "http", want: 400},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			controller := S3ApiController{trustedProxyPrefixes: test.trusted}
			app := fiber.New()
			app.Get("/", func(ctx fiber.Ctx) error {
				if controller.sseCSecureTransport(ctx) {
					return ctx.SendStatus(204)
				}
				return ctx.SendStatus(400)
			})
			request := httptest.NewRequest("GET", "http://example.test/", nil)
			request.Header.Set("X-Forwarded-Proto", test.forwarded)
			response, err := app.Test(request)
			if err != nil {
				t.Fatal(err)
			}
			if response.StatusCode != test.want {
				t.Fatalf("status = %d, want %d", response.StatusCode, test.want)
			}
		})
	}
}
