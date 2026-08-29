// Copyright 2026 Versity Software
// This file is licensed under the Apache License, Version 2.0.

package middlewares

import (
	"net/http/httptest"
	"net/netip"
	"testing"

	"github.com/gofiber/fiber/v3"
	"github.com/versity/versitygw/internal/httpctx"
)

func TestResolveSecureTransportTrustsForwardedProtoOnlyFromConfiguredPeer(t *testing.T) {
	for _, test := range []struct {
		name    string
		trusted []netip.Prefix
		want    bool
	}{
		{name: "trusted", trusted: []netip.Prefix{netip.MustParsePrefix("0.0.0.0/0"), netip.MustParsePrefix("::/0")}, want: true},
		{name: "untrusted", want: false},
	} {
		t.Run(test.name, func(t *testing.T) {
			app := fiber.New()
			app.Use(ResolveSecureTransport(test.trusted))
			app.Get("/", func(ctx fiber.Ctx) error {
				if got, _ := httpctx.ContextKeySecureTransport.Get(ctx).(bool); got != test.want {
					t.Fatalf("secure transport = %v, want %v", got, test.want)
				}
				return ctx.SendStatus(204)
			})
			request := httptest.NewRequest("GET", "http://example.test/", nil)
			request.Header.Set("X-Forwarded-Proto", "https")
			if _, err := app.Test(request); err != nil {
				t.Fatal(err)
			}
		})
	}
}
