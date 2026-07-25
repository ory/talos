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

// TestOSSGatewayHasNoMetricsRoute verifies that the gRPC-Gateway HTTP server
// does not expose /metrics in OSS builds. Prometheus scraping is a
// commercial-only feature.
func TestOSSGatewayHasNoMetricsRoute(t *testing.T) {
	t.Parallel()

	srv := newTestGatewayServer(t)
	require.NoError(t, srv.Setup(t.Context()))

	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/metrics", nil)
	srv.ServeHTTP(rec, req)
	assert.Equal(t, http.StatusNotFound, rec.Code, "/metrics must not be exposed in OSS gateway")
}
