package logger

import (
	"bytes"
	"context"
	"encoding/json"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"testing"

	"github.com/cockroachdb/errors"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.opentelemetry.io/otel/trace"
)

// TestNewLogger_Levels tests logger creation with various log levels
func TestNewLogger_Levels(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name          string
		level         string
		expectedLevel slog.Level
	}{
		{
			name:          "debug level",
			level:         "debug",
			expectedLevel: slog.LevelDebug,
		},
		{
			name:          "info level",
			level:         "info",
			expectedLevel: slog.LevelInfo,
		},
		{
			name:          "warn level",
			level:         "warn",
			expectedLevel: slog.LevelWarn,
		},
		{
			name:          "error level",
			level:         "error",
			expectedLevel: slog.LevelError,
		},
		{
			name:          "invalid level defaults to info",
			level:         "invalid",
			expectedLevel: slog.LevelInfo,
		},
		{
			name:          "empty level defaults to info",
			level:         "",
			expectedLevel: slog.LevelInfo,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			logger := NewLogger(tt.level, "text")
			require.NotNil(t, logger)
			require.NotNil(t, logger.Logger)

			// Logger should be enabled for the configured level
			assert.True(t, logger.Enabled(t.Context(), tt.expectedLevel))

			// Logger should not be enabled for levels below configured level
			if tt.expectedLevel > slog.LevelDebug {
				assert.False(t, logger.Enabled(t.Context(), tt.expectedLevel-1))
			}
		})
	}
}

// TestNewLogger_Formats tests logger creation with various formats
func TestNewLogger_Formats(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name   string
		format string
	}{
		{
			name:   "json format",
			format: "json",
		},
		{
			name:   "text format",
			format: "text",
		},
		{
			name:   "empty format defaults to text",
			format: "",
		},
		{
			name:   "invalid format defaults to text",
			format: "invalid",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			logger := NewLogger("info", tt.format)
			require.NotNil(t, logger)
			require.NotNil(t, logger.Logger)

			// Logger should be created successfully regardless of format
			assert.NotNil(t, logger.Handler())
		})
	}
}

// TestNewLogger_Integration tests the actual NewLogger function
func TestNewLogger_Integration(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name   string
		level  string
		format string
	}{
		{
			name:   "debug + json",
			level:  "debug",
			format: "json",
		},
		{
			name:   "info + text",
			level:  "info",
			format: "text",
		},
		{
			name:   "warn + json",
			level:  "warn",
			format: "json",
		},
		{
			name:   "error + text",
			level:  "error",
			format: "text",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			logger := NewLogger(tt.level, tt.format)
			require.NotNil(t, logger)
			require.NotNil(t, logger.Logger)

			// Logger should be usable
			logger.Info("test message", slog.String("test", "value"))
			logger.Debug("debug message")
			logger.Warn("warning message")
			logger.Error("error message")

			// No assertions on output since it goes to stdout
			// But the test verifies no panics occur
		})
	}
}

// TestNewLogger_StackTraceToggle ensures warn-level configs disable stack traces.
func TestNewLogger_StackTraceToggle(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name              string
		level             string
		expectStackTraces bool
	}{
		{
			name:              "debug keeps stack traces",
			level:             "debug",
			expectStackTraces: true,
		},
		{
			name:              "info keeps stack traces",
			level:             "info",
			expectStackTraces: true,
		},
		{
			name:              "warn disables stack traces",
			level:             "warn",
			expectStackTraces: false,
		},
		{
			name:              "error keeps stack traces",
			level:             "error",
			expectStackTraces: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			logger := NewLogger(tt.level, "json")
			require.NotNil(t, logger)
			assert.Equal(t, tt.expectStackTraces, logger.includeStackTraces)
		})
	}
}

// TestLogger_WithErrorRespectsStackTraceFlag verifies stack trace emission honors the toggle.
func TestLogger_WithErrorRespectsStackTraceFlag(t *testing.T) {
	t.Parallel()

	makeLogger := func(includeStacks bool) (*Logger, *bytes.Buffer) {
		var buf bytes.Buffer
		handler := slog.NewJSONHandler(&buf, &slog.HandlerOptions{
			Level: slog.LevelInfo,
		})

		base := slog.New(handler).With(
			slog.String("service", "talos-server"),
			slog.Int("pid", os.Getpid()),
		)

		return &Logger{
			Logger:             base,
			includeStackTraces: includeStacks,
		}, &buf
	}

	errWithStack := errors.New("boom")

	t.Run("stack traces included", func(t *testing.T) {
		t.Parallel()

		logger, buf := makeLogger(true)
		logger.WithError(errWithStack).Log(context.Background(), slog.LevelError, "test")
		assert.Contains(t, buf.String(), "stacktrace")
	})

	t.Run("stack traces suppressed", func(t *testing.T) {
		t.Parallel()

		logger, buf := makeLogger(false)
		logger.WithError(errWithStack).Log(context.Background(), slog.LevelError, "test")
		assert.NotContains(t, buf.String(), "stacktrace")
	})
}

func TestLogger_WithRequest_CorrelationHeaders(t *testing.T) {
	t.Parallel()

	t.Run("extracts CF-Ray and X-Request-Id as top-level fields", func(t *testing.T) {
		t.Parallel()

		var buf bytes.Buffer
		handler := slog.NewJSONHandler(&buf, &slog.HandlerOptions{Level: slog.LevelInfo})
		logger := &Logger{Logger: slog.New(handler)}

		req := &http.Request{
			Method:     http.MethodGet,
			RemoteAddr: "127.0.0.1:1234",
			Host:       "example.com",
			URL:        &url.URL{Path: "/test"},
			Header: http.Header{
				"Cf-Ray":       []string{"abc123-LAX"},
				"X-Request-Id": []string{"req-456"},
			},
		}

		logger.WithRequest(req).Log(context.Background(), slog.LevelInfo, "test")

		var entry map[string]any
		require.NoError(t, json.Unmarshal(buf.Bytes(), &entry))

		httpReq, ok := entry["http_request"].(map[string]any)
		require.True(t, ok)
		assert.Equal(t, "abc123-LAX", httpReq["cf_ray_id"])
		assert.Equal(t, "req-456", httpReq["request_id"])
	})

	t.Run("omits absent correlation headers", func(t *testing.T) {
		t.Parallel()

		var buf bytes.Buffer
		handler := slog.NewJSONHandler(&buf, &slog.HandlerOptions{Level: slog.LevelInfo})
		logger := &Logger{Logger: slog.New(handler)}

		req := &http.Request{
			Method:     http.MethodGet,
			RemoteAddr: "127.0.0.1:1234",
			Host:       "example.com",
			URL:        &url.URL{Path: "/test"},
			Header:     http.Header{},
		}

		logger.WithRequest(req).Log(context.Background(), slog.LevelInfo, "test")

		var entry map[string]any
		require.NoError(t, json.Unmarshal(buf.Bytes(), &entry))

		httpReq, ok := entry["http_request"].(map[string]any)
		require.True(t, ok)
		assert.NotContains(t, httpReq, "cf_ray_id")
		assert.NotContains(t, httpReq, "request_id")
	})
}

// testSpanContext returns a context carrying a valid, deterministic span context.
// No tracer SDK is needed: trace.ContextWithSpanContext is enough for
// trace.SpanContextFromContext to return a valid span context.
func testSpanContext(t *testing.T) (context.Context, trace.SpanContext) {
	t.Helper()

	traceID, err := trace.TraceIDFromHex("0123456789abcdef0123456789abcdef")
	require.NoError(t, err)
	spanID, err := trace.SpanIDFromHex("0123456789abcdef")
	require.NoError(t, err)
	spanCtx := trace.NewSpanContext(trace.SpanContextConfig{
		TraceID:    traceID,
		SpanID:     spanID,
		TraceFlags: trace.FlagsSampled,
	})
	return trace.ContextWithSpanContext(t.Context(), spanCtx), spanCtx
}

// TestLogger_WithContext_AttrsSurviveEmbeddedLogMethods verifies that attrs
// accumulated via WithContext are emitted by the embedded slog log methods
// (InfoContext etc.), not only by ReportError.
func TestLogger_WithContext_AttrsSurviveEmbeddedLogMethods(t *testing.T) {
	t.Parallel()

	var buf bytes.Buffer
	log := NewLoggerWithWriter(&buf, "info", "json")
	ctx, spanCtx := testSpanContext(t)

	log.WithContext(ctx).InfoContext(ctx, "test")

	var entry map[string]any
	require.NoError(t, json.Unmarshal(buf.Bytes(), &entry))

	otelGroup, ok := entry["otel"].(map[string]any)
	require.True(t, ok, "log entry must contain the otel group, got: %s", buf.String())
	assert.Equal(t, spanCtx.TraceID().String(), otelGroup["trace_id"])
	assert.Equal(t, spanCtx.SpanID().String(), otelGroup["span_id"])
}

// TestLogger_WithRequest_With_AttrsSurviveEmbeddedLogMethods verifies the
// exact chain used by RequestLoggingMiddleware: WithRequest(r).With(...) +
// InfoContext must emit http_request, otel, and the With attrs together.
func TestLogger_WithRequest_With_AttrsSurviveEmbeddedLogMethods(t *testing.T) {
	t.Parallel()

	var buf bytes.Buffer
	log := NewLoggerWithWriter(&buf, "info", "json")
	ctx, spanCtx := testSpanContext(t)

	req := httptest.NewRequest(http.MethodGet, "/test", nil).WithContext(ctx)
	log.WithRequest(req).With(slog.Int("status", 200)).InfoContext(ctx, "HTTP request completed")

	var entry map[string]any
	require.NoError(t, json.Unmarshal(buf.Bytes(), &entry))

	httpReq, ok := entry["http_request"].(map[string]any)
	require.True(t, ok, "log entry must contain the http_request group, got: %s", buf.String())
	assert.Equal(t, http.MethodGet, httpReq["method"])
	assert.Equal(t, "/test", httpReq["path"])

	otelGroup, ok := entry["otel"].(map[string]any)
	require.True(t, ok, "log entry must contain the otel group, got: %s", buf.String())
	assert.Equal(t, spanCtx.TraceID().String(), otelGroup["trace_id"])
	assert.Equal(t, spanCtx.SpanID().String(), otelGroup["span_id"])

	assert.EqualValues(t, 200, entry["status"])
}

func TestRedactHeaders(t *testing.T) {
	t.Parallel()

	headers := http.Header{
		"Authorization":   []string{"Bearer secret"},
		"Cookie":          []string{"session=abc"},
		"Content-Type":    []string{"application/json"},
		"X-Session-Token": []string{"tok-123"},
		"X-Custom":        []string{"visible"},
	}

	result := redactHeaders(headers)

	assert.Equal(t, redactionText, result["authorization"])
	assert.Equal(t, redactionText, result["cookie"])
	assert.Equal(t, redactionText, result["x-session-token"])
	assert.Equal(t, "application/json", result["content-type"])
	assert.Equal(t, "visible", result["x-custom"])
}

// reviewed - @aeneasr - 2026-03-26
