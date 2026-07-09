// Package logger provides structured logging utilities using slog.
package logger

import (
	"context"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"os"
	"strings"

	"github.com/cockroachdb/errors"
	"go.opentelemetry.io/otel/trace"

	"github.com/ory/herodot"
)

// Logger wraps slog.Logger for structured logging (used only by serve command)
type Logger struct {
	*slog.Logger

	includeStackTraces bool
}

// NewLogger creates a new structured logger with the specified level and format
func NewLogger(level string, format string) *Logger {
	return NewLoggerWithWriter(os.Stderr, level, format)
}

// NewLoggerWithWriter creates a new structured logger that writes to w.
// Used by tests to capture log output; production code uses NewLogger.
func NewLoggerWithWriter(w io.Writer, level string, format string) *Logger {
	// Parse log level
	var (
		handler            slog.Handler
		logLevel           slog.Level
		includeStackTraces = true
	)

	switch level {
	case "debug":
		logLevel = slog.LevelDebug
	case "info":
		logLevel = slog.LevelInfo
	case "warn":
		logLevel = slog.LevelWarn
		includeStackTraces = false
	case "error":
		logLevel = slog.LevelError
		includeStackTraces = false
	default:
		logLevel = slog.LevelInfo
	}

	opts := &slog.HandlerOptions{
		Level:     logLevel,
		AddSource: false,
	}

	// Create handler based on format
	switch format {
	case "json":
		handler = slog.NewJSONHandler(w, opts)
	case "text", "":
		handler = slog.NewTextHandler(w, opts)
	default:
		handler = slog.NewTextHandler(w, opts)
	}

	// Create logger with common fields
	logger := slog.New(handler)
	logger = logger.With(
		slog.String("service", "talos-server"),
		slog.Int("pid", os.Getpid()),
	)

	return &Logger{Logger: logger, includeStackTraces: includeStackTraces}
}

// ReportError implements the herodot.ErrorReporter interface.
// It logs HTTP errors with appropriate severity based on status code.
func (l *Logger) ReportError(r *http.Request, code int, err error, args ...any) {
	logger := l.WithError(err).WithRequest(r).withAttr(slog.Group(
		"http_response",
		slog.Int("status_code", code),
	))

	msg := ""
	if len(args) > 0 {
		msg = fmt.Sprint(args...)
	}

	if code < 500 {
		logger.Log(r.Context(), slog.LevelInfo, msg)
	} else {
		logger.Log(r.Context(), slog.LevelError, msg)
	}
}

// WithError returns a new Logger with error context attached.
func (l *Logger) WithError(err error) *Logger {
	if err == nil {
		return l
	}

	errorAttrs := []slog.Attr{
		slog.String("message", err.Error()),
	}

	var herodotErr *herodot.DefaultError
	stackRecorded := false
	if errors.As(err, &herodotErr) {
		errorAttrs = append(
			errorAttrs,
			slog.String("id", herodotErr.ID()),
			slog.Int("code", herodotErr.StatusCode()),
			slog.String("status", herodotErr.Status()),
		)
		if reason := herodotErr.Reason(); reason != "" {
			errorAttrs = append(errorAttrs, slog.String("reason", reason))
		}
		if rid := herodotErr.RequestID(); rid != "" {
			errorAttrs = append(errorAttrs, slog.String("request_id", rid))
		}
		if debug := herodotErr.Debug(); debug != "" {
			errorAttrs = append(errorAttrs, slog.String("debug", debug))
		}
		if l.includeStackTraces {
			if stack := herodotStack(herodotErr); len(stack) > 0 {
				errorAttrs = append(errorAttrs, slog.Any("stacktrace", stack))
				stackRecorded = true
			}
		}
		if details := herodotErr.Details(); len(details) > 0 {
			errorAttrs = append(errorAttrs, slog.Any("details", details))
		}
	}

	if l.includeStackTraces && !stackRecorded {
		if stack := verboseStack(err); stack != "" {
			errorAttrs = append(errorAttrs, slog.String("stacktrace", stack))
		}
	}

	return l.withAttr(groupFromAttrs("error", errorAttrs))
}

// WithRequest returns a new Logger with HTTP request context attached.
func (l *Logger) WithRequest(r *http.Request) *Logger {
	if r == nil {
		return l
	}

	scheme := "https"
	if r.TLS == nil {
		scheme = "http"
	}

	// Build request attributes
	reqAttrs := []any{
		slog.String("remote", r.RemoteAddr),
		slog.String("method", r.Method),
		slog.String("path", r.URL.EscapedPath()),
		slog.String("scheme", scheme),
		slog.String("host", r.Host),
	}

	// Promote correlation headers to top-level fields for easy filtering
	if cfRay := r.Header.Get("Cf-Ray"); cfRay != "" {
		reqAttrs = append(reqAttrs, slog.String("cf_ray_id", cfRay))
	}
	if reqID := r.Header.Get("X-Request-Id"); reqID != "" {
		reqAttrs = append(reqAttrs, slog.String("request_id", reqID))
	}

	// Redact sensitive headers
	headers := redactHeaders(r.Header)
	if len(headers) > 0 {
		headerAttrs := make([]any, 0, len(headers))
		for k, v := range headers {
			headerAttrs = append(headerAttrs, slog.String(k, v))
		}
		reqAttrs = append(reqAttrs, slog.Group("headers", headerAttrs...))
	}

	ll := l.withAttr(slog.Group("http_request", reqAttrs...))
	return ll.withOTELAttrs(r.Context())
}

// WithContext returns a new Logger with OTEL trace context from context.Context.
func (l *Logger) WithContext(ctx context.Context) *Logger {
	return l.withOTELAttrs(ctx)
}

// withOTELAttrs appends trace_id and span_id from the context when available.
func (l *Logger) withOTELAttrs(ctx context.Context) *Logger {
	spanCtx := trace.SpanContextFromContext(ctx)
	if !spanCtx.IsValid() {
		return l
	}

	var traceAttrs []any
	if spanCtx.HasTraceID() {
		traceAttrs = append(traceAttrs, slog.String("trace_id", spanCtx.TraceID().String()))
	}
	if spanCtx.HasSpanID() {
		traceAttrs = append(traceAttrs, slog.String("span_id", spanCtx.SpanID().String()))
	}
	if len(traceAttrs) > 0 {
		return l.withAttr(slog.Group("otel", traceAttrs...))
	}
	return l
}

// WithField returns a new Logger with an additional field.
func (l *Logger) WithField(key string, value slog.Value) *Logger {
	return l.withAttr(slog.Attr{Key: key, Value: value})
}

// withAttr returns a new Logger with an additional attribute. The attribute
// is stored in the embedded slog.Logger so that every log method — including
// the promoted slog methods like InfoContext — emits it.
func (l *Logger) withAttr(attr slog.Attr) *Logger {
	return &Logger{
		Logger:             l.With(attr),
		includeStackTraces: l.includeStackTraces,
	}
}

const redactionText = "[REDACTED]"

// redactHeaders returns a map of headers with sensitive values redacted.
func redactHeaders(h http.Header) map[string]string {
	sensitiveHeaders := map[string]struct{}{
		"authorization":   {},
		"cookie":          {},
		"set-cookie":      {},
		"x-session-token": {},
	}

	headers := make(map[string]string)
	for key := range h {
		keyLower := strings.ToLower(key)
		if _, sensitive := sensitiveHeaders[keyLower]; sensitive {
			headers[keyLower] = redactionText
		} else {
			headers[keyLower] = h.Get(key)
		}
	}
	return headers
}

func herodotStack(err *herodot.DefaultError) []string {
	if err == nil {
		return nil
	}
	stackTrace := err.StackTrace()
	if stackTrace == nil {
		return nil
	}

	lines := make([]string, len(stackTrace))
	for i, frame := range stackTrace {
		lines[i] = fmt.Sprintf("%+v", frame)
	}
	return lines
}

func verboseStack(err error) string {
	if err == nil {
		return ""
	}
	verbose := fmt.Sprintf("%+v", err)
	if verbose == err.Error() {
		return ""
	}
	return verbose
}

func groupFromAttrs(key string, attrs []slog.Attr) slog.Attr {
	args := make([]any, len(attrs))
	for i := range attrs {
		args[i] = attrs[i]
	}
	return slog.Group(key, args...)
}

// reviewed - @aeneasr - 2026-03-26
