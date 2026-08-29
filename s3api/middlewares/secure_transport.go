// Copyright 2026 Versity Software
// This file is licensed under the Apache License, Version 2.0.

package middlewares

import (
	"net"
	"net/netip"

	"github.com/gofiber/fiber/v3"
	"github.com/versity/versitygw/internal/encryption"
	"github.com/versity/versitygw/internal/httpctx"
)

// ResolveSecureTransport records the trusted transport decision once so SSE-C
// enforcement and IAM aws:SecureTransport conditions cannot disagree.
func ResolveSecureTransport(trustedProxyPrefixes []netip.Prefix) fiber.Handler {
	trusted := append([]netip.Prefix(nil), trustedProxyPrefixes...)
	return func(ctx fiber.Ctx) error {
		peer := immediatePeerAddress(ctx.RequestCtx().RemoteAddr().String())
		secure := encryption.SecureTransport(
			ctx.RequestCtx().TLSConnectionState() != nil,
			peer,
			ctx.Get("X-Forwarded-Proto"),
			trusted,
		)
		httpctx.ContextKeySecureTransport.Set(ctx, secure)
		return ctx.Next()
	}
}

func immediatePeerAddress(remote string) netip.Addr {
	host, _, err := net.SplitHostPort(remote)
	if err == nil {
		remote = host
	}
	address, _ := netip.ParseAddr(remote)
	return address.Unmap()
}
