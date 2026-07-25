// Copyright © 2026 Ory Corp
// SPDX-License-Identifier: Apache-2.0

//go:build !commercial

package http

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestOSSMetricsInstrumentIsPassthrough verifies that in OSS builds, wrapping a
// handler with Instrument does not alter its behavior and does not register
// Prometheus metrics.
func TestOSSMetricsInstrumentIsPassthrough(t *testing.T) {
	t.Parallel()

	called := false
	inner := http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		called = true
		w.WriteHeader(http.StatusOK)
	})
	wrapped := GetDefaultMetrics().Instrument(inner, "/test")

	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/test", nil)
	wrapped.ServeHTTP(rec, req)
	assert.True(t, called, "inner handler must be called")
	assert.Equal(t, http.StatusOK, rec.Code)
}

// TestOSSMetricsGatewayMiddlewareIsPassthrough verifies that the gRPC-Gateway
// middleware returned from Metrics.GatewayMiddleware is a no-op in OSS builds.
func TestOSSMetricsGatewayMiddlewareIsPassthrough(t *testing.T) {
	t.Parallel()

	called := false
	mw := GetDefaultMetrics().GatewayMiddleware()
	handler := mw(func(w http.ResponseWriter, _ *http.Request, _ map[string]string) {
		called = true
		w.WriteHeader(http.StatusAccepted)
	})

	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	handler(rec, req, nil)
	assert.True(t, called)
	assert.Equal(t, http.StatusAccepted, rec.Code)
}

// TestOSSNewMetricsReturnsNoop verifies NewMetrics returns a usable Metrics
// instance even in OSS builds (no-op fields).
func TestOSSNewMetricsReturnsNoop(t *testing.T) {
	t.Parallel()

	m := NewMetrics()
	require.NotNil(t, m)

	// Middleware must be callable and pass requests through.
	_ = m.GatewayMiddleware()

	// Instrument must return a usable handler.
	h := m.Instrument(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusNoContent)
	}), "/noop")
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/noop", nil)
	h.ServeHTTP(rec, req)
	assert.Equal(t, http.StatusNoContent, rec.Code)
}
