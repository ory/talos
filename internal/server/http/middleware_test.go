package http_test

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.opentelemetry.io/otel/trace"

	talosconfig "github.com/ory/talos/internal/config"
	"github.com/ory/talos/internal/logger"
	httpserver "github.com/ory/talos/internal/server/http"

	"github.com/ory/x/configx"
)

// mockProvider implements talosconfig.ProviderInterface for testing
type mockProvider struct {
	disableForHealth bool
}

func (m *mockProvider) Bool(_ context.Context, key talosconfig.Key) bool {
	if key.String() == talosconfig.KeyServeHTTPRequestLogExcludeHealthEndpoints.String() {
		return m.disableForHealth
	}
	return false
}

func (m *mockProvider) String(_ context.Context, _ talosconfig.Key) string {
	return ""
}

func (m *mockProvider) Strings(_ context.Context, _ talosconfig.Key) []string {
	return []string{}
}

func (m *mockProvider) Int(_ context.Context, _ talosconfig.Key) int {
	return 0
}

func (m *mockProvider) Float64(_ context.Context, _ talosconfig.Key) float64 {
	return 0
}

func (m *mockProvider) Duration(_ context.Context, _ talosconfig.Key) time.Duration {
	return 0
}

func (m *mockProvider) Get(_ context.Context, _ talosconfig.Key) any {
	return nil
}

func (m *mockProvider) Set(_ context.Context, _ talosconfig.Key, _ any) error {
	return nil
}

func (m *mockProvider) Unmarshal(_ context.Context, _ talosconfig.Key, _ any) error {
	return nil
}

func (m *mockProvider) UnderlyingProvider(_ context.Context) *configx.Provider {
	return nil
}

func TestRequestLoggingMiddleware_CapturesStatusCode(t *testing.T) {
	t.Parallel()

	testCases := []struct {
		name           string
		statusCode     int
		expectedStatus int
	}{
		{
			name:           "200 OK",
			statusCode:     http.StatusOK,
			expectedStatus: http.StatusOK,
		},
		{
			name:           "404 Not Found",
			statusCode:     http.StatusNotFound,
			expectedStatus: http.StatusNotFound,
		},
		{
			name:           "500 Internal Server Error",
			statusCode:     http.StatusInternalServerError,
			expectedStatus: http.StatusInternalServerError,
		},
		{
			name:           "201 Created",
			statusCode:     http.StatusCreated,
			expectedStatus: http.StatusCreated,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			// Create test handler that returns specific status code
			handler := http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
				w.WriteHeader(tc.statusCode)
			})

			// Wrap with logging middleware
			provider := &mockProvider{disableForHealth: false}
			log := logger.NewLogger("error", "json") // Use error level to suppress logs in tests
			middleware := httpserver.RequestLoggingMiddleware(provider, log)
			wrappedHandler := middleware(handler)

			// Make request
			req := httptest.NewRequest(http.MethodGet, "/test", nil)
			rec := httptest.NewRecorder()
			wrappedHandler.ServeHTTP(rec, req)

			// Verify status code
			assert.Equal(t, tc.expectedStatus, rec.Code)
		})
	}
}

func TestRequestLoggingMiddleware_CapturesBytesWritten(t *testing.T) {
	t.Parallel()

	testCases := []struct {
		name          string
		responseBody  string
		expectedBytes int64
	}{
		{
			name:          "Empty response",
			responseBody:  "",
			expectedBytes: 0,
		},
		{
			name:          "Small response",
			responseBody:  "Hello, World!",
			expectedBytes: 13,
		},
		{
			name:          "Large response",
			responseBody:  strings.Repeat("A", 1000),
			expectedBytes: 1000,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			// Create test handler that writes response
			handler := http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
				_, _ = w.Write([]byte(tc.responseBody))
			})

			// Wrap with logging middleware
			provider := &mockProvider{disableForHealth: false}
			log := logger.NewLogger("error", "json")
			middleware := httpserver.RequestLoggingMiddleware(provider, log)
			wrappedHandler := middleware(handler)

			// Make request
			req := httptest.NewRequest(http.MethodGet, "/test", nil)
			rec := httptest.NewRecorder()
			wrappedHandler.ServeHTTP(rec, req)

			// Verify bytes written
			assert.Equal(t, tc.expectedBytes, int64(rec.Body.Len()))
		})
	}
}

func TestRequestLoggingMiddleware_HealthEndpointFiltering(t *testing.T) {
	t.Parallel()

	testCases := []struct {
		name             string
		path             string
		disableForHealth bool
		expectLogged     bool
	}{
		{
			name:             "Health alive endpoint with filtering disabled",
			path:             "/health/alive",
			disableForHealth: false,
			expectLogged:     true,
		},
		{
			name:             "Health alive endpoint with filtering enabled",
			path:             "/health/alive",
			disableForHealth: true,
			expectLogged:     false,
		},
		{
			name:             "Health ready endpoint with filtering enabled",
			path:             "/health/ready",
			disableForHealth: true,
			expectLogged:     false,
		},
		{
			name:             "API endpoint with filtering enabled",
			path:             "/v2alpha1/admin/issuedApiKeys",
			disableForHealth: true,
			expectLogged:     true,
		},
		{
			name:             "API endpoint with filtering disabled",
			path:             "/v2alpha1/admin/issuedApiKeys",
			disableForHealth: false,
			expectLogged:     true,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			// Create test handler
			handler := http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
				w.WriteHeader(http.StatusOK)
				_, _ = w.Write([]byte("OK"))
			})

			// Wrap with logging middleware
			provider := &mockProvider{disableForHealth: tc.disableForHealth}
			log := logger.NewLogger("info", "json")
			middleware := httpserver.RequestLoggingMiddleware(provider, log)
			wrappedHandler := middleware(handler)

			// Make request
			req := httptest.NewRequest(http.MethodGet, tc.path, nil)
			rec := httptest.NewRecorder()
			wrappedHandler.ServeHTTP(rec, req)

			// Verify response was successful
			assert.Equal(t, http.StatusOK, rec.Code)
		})
	}
}

func TestRequestLoggingMiddleware_ImplementsFlusher(t *testing.T) {
	t.Parallel()

	// Create test handler that uses Flusher
	handler := http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		flusher, ok := w.(http.Flusher)
		assert.True(t, ok, "ResponseWriter should implement http.Flusher")

		_, _ = w.Write([]byte("chunk1\n"))
		flusher.Flush()

		_, _ = w.Write([]byte("chunk2\n"))
		flusher.Flush()
	})

	// Wrap with logging middleware
	provider := &mockProvider{disableForHealth: false}
	log := logger.NewLogger("error", "json")
	middleware := httpserver.RequestLoggingMiddleware(provider, log)
	wrappedHandler := middleware(handler)

	// Make request
	req := httptest.NewRequest(http.MethodGet, "/test", nil)
	rec := httptest.NewRecorder()
	wrappedHandler.ServeHTTP(rec, req)

	// Verify response
	assert.Equal(t, http.StatusOK, rec.Code)
	assert.Contains(t, rec.Body.String(), "chunk1")
	assert.Contains(t, rec.Body.String(), "chunk2")
}

func TestRequestLoggingMiddleware_PassesContextCorrectly(t *testing.T) {
	t.Parallel()

	// Create test handler that checks context
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		ctx := r.Context()
		assert.NotNil(t, ctx, "Context should not be nil")
		w.WriteHeader(http.StatusOK)
	})

	// Wrap with logging middleware
	provider := &mockProvider{disableForHealth: false}
	log := logger.NewLogger("error", "json")
	middleware := httpserver.RequestLoggingMiddleware(provider, log)
	wrappedHandler := middleware(handler)

	// Make request with context
	ctx := context.Background()
	req := httptest.NewRequest(http.MethodGet, "/test", nil).WithContext(ctx)
	rec := httptest.NewRecorder()
	wrappedHandler.ServeHTTP(rec, req)

	// Verify response
	assert.Equal(t, http.StatusOK, rec.Code)
}

func TestRequestLoggingMiddleware_DefaultStatusCode(t *testing.T) {
	t.Parallel()

	// Create test handler that doesn't call WriteHeader
	handler := http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte("response without explicit status"))
	})

	// Wrap with logging middleware
	provider := &mockProvider{disableForHealth: false}
	log := logger.NewLogger("error", "json")
	middleware := httpserver.RequestLoggingMiddleware(provider, log)
	wrappedHandler := middleware(handler)

	// Make request
	req := httptest.NewRequest(http.MethodGet, "/test", nil)
	rec := httptest.NewRecorder()
	wrappedHandler.ServeHTTP(rec, req)

	// Verify default status code (200)
	assert.Equal(t, http.StatusOK, rec.Code)
}

func TestRequestLoggingMiddleware_LogLevels(t *testing.T) {
	t.Parallel()

	testCases := []struct {
		name         string
		statusCode   int
		responseBody string
		path         string
	}{
		{
			name:         "2xx status",
			statusCode:   http.StatusOK,
			responseBody: "success",
			path:         "/v2alpha1/admin/issuedApiKeys",
		},
		{
			name:         "4xx status",
			statusCode:   http.StatusNotFound,
			responseBody: "not found",
			path:         "/v2alpha1/admin/issuedApiKeys/nonexistent",
		},
		{
			name:         "5xx status",
			statusCode:   http.StatusInternalServerError,
			responseBody: "internal error",
			path:         "/v2alpha1/admin/issuedApiKeys",
		},
		{
			name:         "3xx redirect",
			statusCode:   http.StatusMovedPermanently,
			responseBody: "",
			path:         "/old-path",
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			// Create test handler
			handler := http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
				w.WriteHeader(tc.statusCode)
				_, _ = w.Write([]byte(tc.responseBody))
			})

			// Use error level logger to suppress output during tests
			log := logger.NewLogger("error", "json")

			// Wrap with logging middleware
			provider := &mockProvider{disableForHealth: false}
			middleware := httpserver.RequestLoggingMiddleware(provider, log)
			wrappedHandler := middleware(handler)

			// Make request
			req := httptest.NewRequest(http.MethodGet, tc.path, nil)
			rec := httptest.NewRecorder()
			wrappedHandler.ServeHTTP(rec, req)

			// Verify response (middleware should not affect the response)
			assert.Equal(t, tc.statusCode, rec.Code)
			assert.Equal(t, tc.responseBody, rec.Body.String())
		})
	}
}

func TestRequestIDMiddleware_AcceptsShortID(t *testing.T) {
	t.Parallel()
	const id = "my-request-id"
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.Header.Set("X-Request-ID", id)
	rr := httptest.NewRecorder()
	var captured string
	handler := httpserver.RequestIDMiddleware(http.HandlerFunc(func(_ http.ResponseWriter, r *http.Request) {
		captured = r.Header.Get("X-Request-ID")
	}))
	handler.ServeHTTP(rr, req)
	assert.Equal(t, id, captured, "short IDs should be passed through unchanged")
}

func TestRequestIDMiddleware_DiscardsLongID(t *testing.T) {
	t.Parallel()
	longID := strings.Repeat("a", 129)
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.Header.Set("X-Request-ID", longID)
	rr := httptest.NewRecorder()
	var captured string
	handler := httpserver.RequestIDMiddleware(http.HandlerFunc(func(_ http.ResponseWriter, r *http.Request) {
		captured = r.Header.Get("X-Request-ID")
	}))
	handler.ServeHTTP(rr, req)
	assert.NotEqual(t, longID, captured, "IDs over 128 bytes must be discarded")
	assert.NotEmpty(t, captured, "a new UUID must be generated in place of the discarded ID")
	assert.LessOrEqual(t, len(captured), 128)
}

func TestSecurityHeadersMiddleware_SetsRequiredHeaders(t *testing.T) {
	t.Parallel()

	handler := httpserver.SecurityHeadersMiddleware(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))

	req := httptest.NewRequest(http.MethodGet, "/", nil)
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	assert.Equal(t, http.StatusOK, rec.Code)
	assert.Equal(t, "max-age=31536000; includeSubDomains", rec.Header().Get("Strict-Transport-Security"))
	assert.Equal(t, "DENY", rec.Header().Get("X-Frame-Options"))
	assert.Equal(t, "nosniff", rec.Header().Get("X-Content-Type-Options"))
	assert.Equal(t, "strict-origin-when-cross-origin", rec.Header().Get("Referrer-Policy"))
	assert.NotEmpty(t, rec.Header().Get("Content-Security-Policy"), "Content-Security-Policy must be set")
}

func TestSecurityHeadersMiddleware_PassesThroughToHandler(t *testing.T) {
	t.Parallel()

	const responseBody = "hello"
	handler := httpserver.SecurityHeadersMiddleware(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusCreated)
		_, _ = w.Write([]byte(responseBody))
	}))

	req := httptest.NewRequest(http.MethodPost, "/keys", nil)
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	assert.Equal(t, http.StatusCreated, rec.Code)
	assert.Equal(t, responseBody, rec.Body.String())
}

func TestRequestIDMiddleware_SetsResponseHeader(t *testing.T) {
	t.Parallel()

	const id = "test-id-123"
	handler := httpserver.RequestIDMiddleware(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))

	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.Header.Set("X-Request-ID", id)
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	assert.Equal(t, id, rec.Header().Get("X-Request-ID"), "X-Request-ID must be echoed in the response")
}

func TestRequestIDMiddleware_GeneratesIDWhenMissing(t *testing.T) {
	t.Parallel()

	handler := httpserver.RequestIDMiddleware(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))

	req := httptest.NewRequest(http.MethodGet, "/", nil)
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	assert.NotEmpty(t, rec.Header().Get("X-Request-ID"), "a UUID must be generated when no X-Request-ID is provided")
}

func TestRequestLoggingMiddleware_EmitsTraceAndRequestMetadata(t *testing.T) {
	t.Parallel()

	var buf bytes.Buffer
	log := logger.NewLoggerWithWriter(&buf, "info", "json")

	handler := http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("OK"))
	})

	provider := &mockProvider{disableForHealth: false}
	wrappedHandler := httpserver.RequestLoggingMiddleware(provider, log)(handler)

	// Build a valid span context without the tracer SDK; the middleware must
	// pick it up from the request context.
	traceID, err := trace.TraceIDFromHex("0123456789abcdef0123456789abcdef")
	require.NoError(t, err)
	spanID, err := trace.SpanIDFromHex("0123456789abcdef")
	require.NoError(t, err)
	spanCtx := trace.NewSpanContext(trace.SpanContextConfig{
		TraceID:    traceID,
		SpanID:     spanID,
		TraceFlags: trace.FlagsSampled,
	})

	req := httptest.NewRequest(http.MethodGet, "/test", nil)
	req = req.WithContext(trace.ContextWithSpanContext(req.Context(), spanCtx))
	rec := httptest.NewRecorder()
	wrappedHandler.ServeHTTP(rec, req)

	var entry map[string]any
	require.NoError(t, json.Unmarshal(buf.Bytes(), &entry), "log output: %s", buf.String())

	otelGroup, ok := entry["otel"].(map[string]any)
	require.True(t, ok, "request log must contain the otel group, got: %s", buf.String())
	assert.Equal(t, traceID.String(), otelGroup["trace_id"])
	assert.Equal(t, spanID.String(), otelGroup["span_id"])

	httpReq, ok := entry["http_request"].(map[string]any)
	require.True(t, ok, "request log must contain the http_request group, got: %s", buf.String())
	assert.Equal(t, http.MethodGet, httpReq["method"])
	assert.Equal(t, "/test", httpReq["path"])

	assert.EqualValues(t, http.StatusOK, entry["status"])
	assert.EqualValues(t, 2, entry["bytes"])
	assert.Contains(t, entry, "duration")
}

func TestRequestLoggingMiddleware_IntegrationWithMultipleWrites(t *testing.T) {
	t.Parallel()

	// Create test handler that writes multiple times
	handler := http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("part1"))
		_, _ = w.Write([]byte("part2"))
		_, _ = w.Write([]byte("part3"))
	})

	// Wrap with logging middleware
	provider := &mockProvider{disableForHealth: false}
	log := logger.NewLogger("error", "json")
	middleware := httpserver.RequestLoggingMiddleware(provider, log)
	wrappedHandler := middleware(handler)

	// Make request
	req := httptest.NewRequest(http.MethodGet, "/test", nil)
	rec := httptest.NewRecorder()
	wrappedHandler.ServeHTTP(rec, req)

	// Verify all parts were written
	assert.Equal(t, http.StatusOK, rec.Code)
	body, err := io.ReadAll(rec.Body)
	require.NoError(t, err)
	assert.Equal(t, "part1part2part3", string(body))
	assert.Equal(t, int64(15), int64(len(body)))
}

// reviewed - @aeneasr - 2026-03-26
