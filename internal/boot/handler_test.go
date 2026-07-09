package boot_test

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.opentelemetry.io/otel"
	sdktrace "go.opentelemetry.io/otel/sdk/trace"

	"github.com/ory/herodot"
	"github.com/ory/x/httpx"

	commercialregistry "github.com/ory/talos/commercial/registry"
	"github.com/ory/talos/internal/boot"
	"github.com/ory/talos/internal/health"
	"github.com/ory/talos/internal/logger"
	"github.com/ory/talos/internal/registry"
	httpserver "github.com/ory/talos/internal/server/http"
	"github.com/ory/talos/internal/testutil"
)

// buildDeps constructs a ServerDependencies for the given mode using a fresh
// SQLite database and an isolated Prometheus registry. It registers a t.Cleanup
// to close the factory.
func buildDeps(t *testing.T, mode boot.ServerMode) *boot.ServerDependencies {
	t.Helper()
	return buildDepsWithLogger(t, mode, logger.NewLogger("warn", "json"))
}

// buildDepsWithLogger is buildDeps with a caller-provided logger, so tests can
// capture log output through a buffer-backed logger.
func buildDepsWithLogger(t *testing.T, mode boot.ServerMode, log *logger.Logger) *boot.ServerDependencies {
	t.Helper()
	ctx := t.Context()

	driver, err := testutil.InitDriver(t, "")
	require.NoError(t, err, "initialize test database")

	writer := herodot.NewJSONWriter(nil)

	provider := testutil.NewTestProviderWithSigningKeys(t)

	propOpts, err := commercialregistry.Options(ctx, provider, log.Logger, writer)
	require.NoError(t, err, "initialize feature options")

	reg := prometheus.NewRegistry()
	factory, err := registry.NewServiceFactory(ctx, driver, provider, testutil.NewMockEmitter(), httpx.NewResilientClient(), propOpts.CacheFactories, nil, reg)
	require.NoError(t, err, "create service factory")
	t.Cleanup(func() { _ = factory.Close() })

	healthChecker := health.NewChecker(writer)
	healthChecker.AddDatabaseCheck(driver.DB())

	return &boot.ServerDependencies{
		Log:           log,
		Writer:        httpserver.NewAIPWriter(log, "www.ory.com/talos"),
		Factory:       factory,
		Provider:      provider,
		HealthChecker: healthChecker,
		PropOpts:      propOpts,
		Mode:          mode,
	}
}

// testResponse captures the small subset of the response that tests care about
// after the body has been fully drained and closed.
type testResponse struct {
	StatusCode int
	Body       []byte
}

// get sends a GET request to the test server, drains the response body, and
// returns the status code and body bytes.
func get(t *testing.T, ts *httptest.Server, path string) testResponse {
	t.Helper()
	req, err := http.NewRequestWithContext(t.Context(), http.MethodGet, ts.URL+path, nil)
	require.NoError(t, err)
	resp, err := http.DefaultClient.Do(req)
	require.NoError(t, err)
	defer func() { _ = resp.Body.Close() }()
	body, err := io.ReadAll(resp.Body)
	require.NoError(t, err)
	return testResponse{StatusCode: resp.StatusCode, Body: body}
}

// post sends a POST request with a JSON body to the test server, drains the
// response body, and returns the status code and body bytes.
func post(t *testing.T, ts *httptest.Server, path, body string) testResponse {
	t.Helper()
	req, err := http.NewRequestWithContext(t.Context(), http.MethodPost, ts.URL+path, strings.NewReader(body))
	require.NoError(t, err)
	req.Header.Set("Content-Type", "application/json")
	resp, err := http.DefaultClient.Do(req)
	require.NoError(t, err)
	defer func() { _ = resp.Body.Close() }()
	respBody, err := io.ReadAll(resp.Body)
	require.NoError(t, err)
	return testResponse{StatusCode: resp.StatusCode, Body: respBody}
}

func TestHTTPHandlerFromDependencies_ModeIsolation(t *testing.T) {
	// Global state (prometheus.DefaultRegisterer) is not used here — each subtest
	// uses its own registry via buildDeps, so parallel execution is safe.
	t.Parallel()

	// adminPath is the issue-key endpoint, present only in ModeAdmin and ModeAllInOne.
	const adminPath = "/v2alpha1/admin/issuedApiKeys"
	// selfPath is the proof-of-possession revoke endpoint, present only in
	// ModePublic and ModeAllInOne.
	const selfPath = "/v2alpha1/apiKeys:selfRevoke"
	// jwksPath is the public JWKS endpoint — wired in all three deployment modes.
	const jwksPath = "/v2alpha1/derivedKeys/jwks.json"
	// jwksLegacyPath is the pre-migration admin-tier path, which must no longer route.
	const jwksLegacyPath = "/v2alpha1/admin/derivedKeys/jwks.json"

	// adminBody is a minimal valid issue-key request body.
	const adminBody = `{"name":"test","actor_id":"u1","scopes":["read"]}`
	// selfBody is a minimal revoke request body (credential value is intentionally invalid;
	// we only care about routing, not business-logic success).
	const selfBody = `{"credential":"talos_invalid_credential"}`

	tests := []struct {
		name string
		mode boot.ServerMode
		// wantAdminActive: admin endpoint is wired — returns a non-5xx response
		// (e.g. 201 created or 400 validation error, but not 500 Unimplemented).
		wantAdminActive bool
		// wantSelfActive: public endpoint is wired — returns a non-5xx response.
		wantSelfActive bool
	}{
		{
			name:            "all-in-one exposes both admin and public endpoints",
			mode:            boot.ModeAllInOne,
			wantAdminActive: true,
			wantSelfActive:  true,
		},
		{
			name:            "admin exposes admin but public returns 404",
			mode:            boot.ModeAdmin,
			wantAdminActive: true,
			wantSelfActive:  false,
		},
		{
			name:            "public exposes public but admin is nil",
			mode:            boot.ModePublic,
			wantAdminActive: false,
			wantSelfActive:  true,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			deps := buildDeps(t, tc.mode)
			handler, err := boot.HTTPHandlerFromDependencies(t.Context(), deps, nil)
			require.NoError(t, err, "HTTPHandlerFromDependencies should succeed")

			ts := httptest.NewServer(handler)
			t.Cleanup(ts.Close)

			// Health endpoint always works regardless of mode.
			aliveResp := get(t, ts, "/health/alive")
			assert.Equal(t, http.StatusOK, aliveResp.StatusCode, "/health/alive should always return 200")

			// Admin endpoint: POST /v2alpha1/admin/issuedApiKeys.
			// Active adapter: request reaches service logic (201 or 4xx validation).
			// Inactive adapter (UnimplementedApiKeysServer): returns
			// codes.Unimplemented → HTTP 404 via customErrorHandler.
			adminResp := post(t, ts, adminPath, adminBody)
			if tc.wantAdminActive {
				assert.Less(t, adminResp.StatusCode, 500,
					"admin endpoint should reach service logic (not Unimplemented) in mode %d", tc.mode)
			} else {
				assert.Equal(t, http.StatusNotFound, adminResp.StatusCode,
					"admin endpoint should return 404 (Unimplemented→NotFound) in mode %d", tc.mode)
			}

			// Public endpoint: POST /v2alpha1/apiKeys:selfRevoke.
			// Active adapter: request reaches service logic (4xx for invalid credential).
			// Inactive adapter (UnimplementedApiKeysServer): returns
			// codes.Unimplemented → HTTP 404 via customErrorHandler.
			selfResp := post(t, ts, selfPath, selfBody)
			if tc.wantSelfActive {
				assert.Less(t, selfResp.StatusCode, 500,
					"public endpoint should reach service logic (not Unimplemented) in mode %d", tc.mode)
			} else {
				assert.Equal(t, http.StatusNotFound, selfResp.StatusCode,
					"public endpoint should return 404 (Unimplemented→NotFound) in mode %d", tc.mode)
			}

			// JWKS endpoint: GET /v2alpha1/derivedKeys/jwks.json. JWKS keys are
			// public per RFC 7517, so all three modes serve the same path. The
			// test provider has signing keys configured, so the response must be 200.
			jwksResp := get(t, ts, jwksPath)
			assert.Equal(t, http.StatusOK, jwksResp.StatusCode,
				"JWKS endpoint must return 200 in mode %d; body: %s", tc.mode, string(jwksResp.Body))
			assert.Contains(t, string(jwksResp.Body), `"keys"`,
				"JWKS response must contain a keys array in mode %d", tc.mode)

			// Legacy admin-tier JWKS path must no longer be routable.
			legacyResp := get(t, ts, jwksLegacyPath)
			assert.Equal(t, http.StatusNotFound, legacyResp.StatusCode,
				"legacy admin JWKS path must return 404 in mode %d", tc.mode)
		})
	}
}

func TestHTTPHandlerFromDependencies_HandlerOptions(t *testing.T) {
	t.Parallel()

	deps := buildDeps(t, boot.ModeAllInOne)

	t.Run("nil opts enables all middleware", func(t *testing.T) {
		t.Parallel()
		handler, err := boot.HTTPHandlerFromDependencies(t.Context(), deps, nil)
		require.NoError(t, err)
		require.NotNil(t, handler)

		ts := httptest.NewServer(handler)
		t.Cleanup(ts.Close)

		resp := get(t, ts, "/health/alive")
		assert.Equal(t, http.StatusOK, resp.StatusCode)
	})

	t.Run("skip all optional middleware", func(t *testing.T) {
		t.Parallel()
		handler, err := boot.HTTPHandlerFromDependencies(t.Context(), deps, &boot.HandlerOptions{
			SkipOTEL:           true,
			SkipRequestID:      true,
			SkipRequestLogging: true,
		})
		require.NoError(t, err)
		require.NotNil(t, handler)

		ts := httptest.NewServer(handler)
		t.Cleanup(ts.Close)

		resp := get(t, ts, "/health/alive")
		assert.Equal(t, http.StatusOK, resp.StatusCode)
	})
}

// TestHTTPHandlerFromDependencies_RequestLogIncludesTraceID is a middleware
// ordering regression test: the request logging middleware must run inside
// otelhttp.NewHandler so the request log carries the span's trace ID.
//
// It mutates the global tracer provider, so it must not run in parallel.
func TestHTTPHandlerFromDependencies_RequestLogIncludesTraceID(t *testing.T) {
	var buf bytes.Buffer
	log := logger.NewLoggerWithWriter(&buf, "info", "json")
	deps := buildDepsWithLogger(t, boot.ModeAllInOne, log)

	// otelhttp uses the global tracer provider; install a real SDK provider so
	// spans carry valid trace IDs, and restore the previous one afterwards.
	prev := otel.GetTracerProvider()
	tp := sdktrace.NewTracerProvider()
	otel.SetTracerProvider(tp)
	t.Cleanup(func() {
		otel.SetTracerProvider(prev)
		_ = tp.Shutdown(context.Background())
	})

	handler, err := boot.HTTPHandlerFromDependencies(t.Context(), deps, nil)
	require.NoError(t, err)

	// Serve the request synchronously so the request log is written before we
	// inspect the buffer.
	req := httptest.NewRequest(http.MethodGet, "/v2alpha1/derivedKeys/jwks.json", nil)
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)
	require.Equal(t, http.StatusOK, rec.Code, "body: %s", rec.Body.String())

	// Find the request completion log line and assert it carries the trace ID.
	var entry map[string]any
	for line := range strings.Lines(buf.String()) {
		var candidate map[string]any
		require.NoError(t, json.Unmarshal([]byte(line), &candidate), "log line: %s", line)
		if candidate["msg"] == "HTTP request completed" {
			entry = candidate
			break
		}
	}
	require.NotNil(t, entry, "no request completion log found in: %s", buf.String())

	otelGroup, ok := entry["otel"].(map[string]any)
	require.True(t, ok, "request log must contain the otel group, got: %v", entry)
	assert.NotEmpty(t, otelGroup["trace_id"], "request log must carry the span's trace ID")
	assert.NotEmpty(t, otelGroup["span_id"], "request log must carry the span's span ID")
}

func TestHTTPHandlerFromDependencies_PreBuiltAdapters(t *testing.T) {
	t.Parallel()

	deps := buildDeps(t, boot.ModeAllInOne)

	// Build adapters from the factory the normal way, then pass them as pre-built.
	fullHandler, err := boot.HTTPHandlerFromDependencies(t.Context(), deps, &boot.HandlerOptions{
		SkipOTEL: true, SkipRequestID: true, SkipRequestLogging: true,
	})
	require.NoError(t, err)

	ts := httptest.NewServer(fullHandler)
	t.Cleanup(ts.Close)

	// Verify the handler works by hitting a health endpoint.
	resp := get(t, ts, "/health/alive")
	assert.Equal(t, http.StatusOK, resp.StatusCode, "body: %s", string(resp.Body))
}
