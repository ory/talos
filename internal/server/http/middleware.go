package http

import (
	"log/slog"
	"net/http"
	"time"

	"github.com/gofrs/uuid"
	"github.com/rs/cors"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/trace"

	talosconfig "github.com/ory/talos/internal/config"
	"github.com/ory/talos/internal/logger"
	"github.com/ory/talos/internal/tracing"

	"github.com/ory/x/corsx"
	"github.com/ory/x/otelx"
)

// RequestIDMiddleware ensures every request has an X-Request-ID header and adds it
// as a span attribute so it is visible in the talos.http.server trace.
// Must run inside the otelhttp handler so the span already exists.
func RequestIDMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		reqID := r.Header.Get("X-Request-ID")
		if reqID == "" || len(reqID) > 128 {
			// Entropy exhaustion is effectively impossible, but we prefer an
			// empty X-Request-ID over a 500 panic inside the request handler.
			generated, err := uuid.NewV4()
			if err != nil {
				slog.ErrorContext(r.Context(), "generate request ID",
					slog.Any("error", err))
				reqID = ""
			} else {
				reqID = generated.String()
			}
			// r.Header is a map (reference type): Set is safe without cloning.
			r.Header.Set("X-Request-ID", reqID)
		}

		// Attach the ID to the active span (created by otelhttp.NewHandler).
		span := trace.SpanFromContext(r.Context())
		span.SetAttributes(attribute.String("http.request_id", reqID))

		// Echo it back to the caller.
		w.Header().Set("X-Request-ID", reqID)

		next.ServeHTTP(w, r)
	})
}

// CORSMiddleware creates a CORS middleware that reads configuration on each request.
// This keeps CORS settings hot-reloadable.
func CORSMiddleware(provider talosconfig.ProviderInterface) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			ctx, span := tracing.Start(r.Context(), "http.middleware.cors")
			var err error
			defer otelx.End(span, &err)

			if !provider.Bool(ctx, talosconfig.KeyServeHTTPCORSEnabled) {
				next.ServeHTTP(w, r.WithContext(ctx))
				return
			}

			allowedOrigins := provider.Strings(ctx, talosconfig.KeyServeHTTPCORSAllowedOrigins)
			c := cors.New(cors.Options{
				AllowedOrigins:   allowedOrigins,
				AllowedMethods:   provider.Strings(ctx, talosconfig.KeyServeHTTPCORSAllowedMethods),
				AllowedHeaders:   provider.Strings(ctx, talosconfig.KeyServeHTTPCORSAllowedHeaders),
				ExposedHeaders:   provider.Strings(ctx, talosconfig.KeyServeHTTPCORSExposedHeaders),
				AllowCredentials: provider.Bool(ctx, talosconfig.KeyServeHTTPCORSAllowCreds),
				MaxAge:           provider.Int(ctx, talosconfig.KeyServeHTTPCORSMaxAge),
				Debug:            provider.Bool(ctx, talosconfig.KeyServeHTTPCORSDebug),
				// Enforce a DNS-label boundary on wildcard origins: rs/cors' raw
				// matcher would let "https://*foo.com" match "https://evilfoo.com".
				AllowOriginVaryRequestFunc: func(_ *http.Request, origin string) (bool, []string) {
					return corsx.CheckOrigin(allowedOrigins, origin, false), nil
				},
			})

			c.Handler(next).ServeHTTP(w, r.WithContext(ctx))
		})
	}
}

// SecurityHeadersMiddleware adds security headers to all HTTP responses.
func SecurityHeadersMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Strict-Transport-Security", "max-age=31536000; includeSubDomains")
		w.Header().Set("Content-Security-Policy", "default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline'; img-src 'self' data:; font-src 'self'; connect-src 'self'; frame-ancestors 'none'")
		w.Header().Set("X-Frame-Options", "DENY")
		w.Header().Set("X-Content-Type-Options", "nosniff")
		w.Header().Set("Referrer-Policy", "strict-origin-when-cross-origin")
		w.Header().Set("Permissions-Policy", "geolocation=(), microphone=(), camera=()")
		next.ServeHTTP(w, r)
	})
}

// responseWriter wraps http.ResponseWriter to capture response metadata
type responseWriter struct {
	http.ResponseWriter

	statusCode   int
	bytesWritten int64
}

func (rw *responseWriter) WriteHeader(statusCode int) {
	rw.statusCode = statusCode
	rw.ResponseWriter.WriteHeader(statusCode)
}

func (rw *responseWriter) Write(b []byte) (int, error) {
	n, err := rw.ResponseWriter.Write(b)
	rw.bytesWritten += int64(n)
	return n, err
}

// Flush implements http.Flusher for streaming responses
func (rw *responseWriter) Flush() {
	if f, ok := rw.ResponseWriter.(http.Flusher); ok {
		f.Flush()
	}
}

// RequestLoggingMiddleware logs HTTP requests at completion.
// Respects serve.http.request_log.exclude_health_endpoints config to optionally exclude health endpoints.
func RequestLoggingMiddleware(provider talosconfig.ProviderInterface, log *logger.Logger) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			ctx := r.Context()
			// Check if health endpoint logging is disabled
			disableForHealth := provider.Bool(ctx, talosconfig.KeyServeHTTPRequestLogExcludeHealthEndpoints)
			if disableForHealth && (r.URL.Path == "/health/alive" || r.URL.Path == "/health/ready") {
				next.ServeHTTP(w, r.WithContext(ctx))
				return
			}

			// Wrap response writer to capture metadata
			wrapped := &responseWriter{
				ResponseWriter: w,
				statusCode:     200, // Default if WriteHeader not called
				bytesWritten:   0,
			}

			start := time.Now()

			// Process request
			next.ServeHTTP(wrapped, r.WithContext(ctx))

			// Log after completion
			duration := time.Since(start)

			// WithRequest also attaches the otel trace/span IDs from r.Context().
			lg := log.WithRequest(r).With(
				slog.Int("status", wrapped.statusCode),
				slog.Int64("bytes", wrapped.bytesWritten),
				slog.Duration("duration", duration),
			)

			msg := "HTTP request completed"

			switch {
			case wrapped.statusCode >= 500:
				lg.ErrorContext(ctx, msg)
			case wrapped.statusCode >= 400:
				lg.WarnContext(ctx, msg)
			default:
				lg.InfoContext(ctx, msg)
			}
		})
	}
}

// reviewed - @aeneasr - 2026-03-26
