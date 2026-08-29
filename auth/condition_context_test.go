// Copyright 2026 Versity Software
// This file is licensed under the Apache License, Version 2.0.

package auth

import (
	"net/http/httptest"
	"testing"

	"github.com/gofiber/fiber/v3"
	"github.com/versity/versitygw/internal/httpctx"
)

func TestRequestConditionContextUsesResolvedSecureTransport(t *testing.T) {
	app := fiber.New()
	app.Get("/", func(ctx fiber.Ctx) error {
		httpctx.ContextKeySecureTransport.Set(ctx, true)
		conditions := requestConditionContext(ctx)
		if got := conditions["aws:SecureTransport"]; len(got) != 1 || got[0] != "true" {
			t.Fatalf("aws:SecureTransport = %v, want true", got)
		}
		return ctx.SendStatus(204)
	})
	if _, err := app.Test(httptest.NewRequest("GET", "http://example.test/", nil)); err != nil {
		t.Fatal(err)
	}
}
