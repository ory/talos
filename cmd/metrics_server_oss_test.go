// Copyright © 2026 Ory Corp
// SPDX-License-Identifier: Apache-2.0

//go:build !commercial

package cmd

import (
	"io"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/ory/herodot"

	"github.com/ory/talos/internal/health"
	"github.com/ory/talos/internal/testutil"
)

// TestOSSMetricsServerHasNoMetricsRoute verifies that the metrics HTTP server
// does not expose the Prometheus /metrics endpoint in OSS builds. Scraping is
// a commercial-only feature.
func TestOSSMetricsServerHasNoMetricsRoute(t *testing.T) {
	t.Parallel()

	writer := herodot.NewJSONWriter(nil)
	healthChecker := health.NewChecker(writer)

	srv := createMetricsHTTPServer("unused-addr", healthChecker)
	require.NotNil(t, srv)

	ts := httptest.NewServer(srv.Handler)
	t.Cleanup(ts.Close)

	req, err := http.NewRequestWithContext(t.Context(), http.MethodGet, ts.URL+"/metrics", nil)
	require.NoError(t, err)
	resp, err := testutil.NewTestHTTPClient(t).Do(req)
	require.NoError(t, err)
	t.Cleanup(func() { _ = resp.Body.Close() })
	_, _ = io.Copy(io.Discard, resp.Body)
	assert.Equal(t, http.StatusNotFound, resp.StatusCode, "/metrics must not exist in OSS builds")
}
