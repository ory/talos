// Copyright © 2026 Ory Corp
// SPDX-License-Identifier: Apache-2.0

//go:build !commercial

package http

import (
	"net/http"

	"github.com/grpc-ecosystem/grpc-gateway/v2/runtime"
)

// Metrics is a no-op implementation for OSS builds. All call sites compile
// identically; no Prometheus metrics are registered or exposed.
type Metrics struct{}

//nolint:gochecknoglobals // Match commercial singleton shape.
var defaultMetrics = &Metrics{}

// NewMetrics returns a no-op Metrics instance.
func NewMetrics() *Metrics { return &Metrics{} }

// GetDefaultMetrics returns the singleton no-op Metrics instance.
func GetDefaultMetrics() *Metrics { return defaultMetrics }

// Instrument returns the handler unchanged; no metrics are recorded in OSS builds.
func (m *Metrics) Instrument(next http.Handler, _ string) http.Handler { return next }

// GatewayMiddleware returns a pass-through middleware; no metrics are recorded in OSS builds.
func (m *Metrics) GatewayMiddleware() runtime.Middleware {
	return func(next runtime.HandlerFunc) runtime.HandlerFunc {
		return next
	}
}
