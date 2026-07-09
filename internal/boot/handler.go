// Package boot wires HTTP handler construction for the Talos server modes.
package boot

import (
	"context"
	"net/http"
	"time"

	"github.com/cockroachdb/errors"
	"go.opentelemetry.io/contrib/instrumentation/net/http/otelhttp"

	"github.com/ory/talos/internal/registrytypes"

	"github.com/ory/herodot"

	talosconfig "github.com/ory/talos/internal/config"
	"github.com/ory/talos/internal/health"
	"github.com/ory/talos/internal/logger"
	"github.com/ory/talos/internal/registry"
	httpserver "github.com/ory/talos/internal/server/http"
	"github.com/ory/talos/internal/service"
	talosv2alpha1 "github.com/ory/talos/pkg/api/talos/v2alpha1"
)

// ServerMode defines the operational mode of the server.
type ServerMode int

// Server modes select which adapters the boot handler wires up.
const (
	// ModeAllInOne serves both the admin and public APIs.
	ModeAllInOne ServerMode = iota
	// ModeAdmin serves only the admin API keys API.
	ModeAdmin
	// ModePublic serves only the public API.
	ModePublic
)

// ServerDependencies holds initialized infrastructure for handler construction.
// Does NOT store context — context must be passed explicitly to all methods.
// Does NOT cache config values — only infrastructure instances.
type ServerDependencies struct {
	Log           *logger.Logger
	Writer        herodot.Writer
	Factory       *registry.ServiceFactory
	Provider      talosconfig.ProviderInterface
	HealthChecker *health.Checker
	PropOpts      *registrytypes.FeatureOptions
	Mode          ServerMode

	// PreBuiltAdmin overrides factory-based admin creation.
	// When set, HTTPHandlerFromDependencies uses this adapter directly
	// instead of calling Factory.CreateAdmin. Used by commercial test
	// servers that construct services with custom providers.
	PreBuiltAdmin talosv2alpha1.ApiKeysServer
}

// HandlerOptions controls optional middleware layers.
// A nil HandlerOptions means all middleware is enabled (production behavior).
type HandlerOptions struct {
	// SkipOTEL disables the otelhttp.NewHandler wrapper.
	SkipOTEL bool
	// SkipRequestID disables RequestIDMiddleware.
	SkipRequestID bool
	// SkipRequestLogging disables RequestLoggingMiddleware.
	SkipRequestLogging bool
}

// HTTPHandlerFromDependencies creates the fully-wrapped HTTP handler from server dependencies.
// Pass nil for opts to enable all middleware (production behavior).
func HTTPHandlerFromDependencies(ctx context.Context, deps *ServerDependencies, opts *HandlerOptions) (http.Handler, error) {
	if opts == nil {
		opts = &HandlerOptions{}
	}

	adminAdapter, err := buildAdapters(ctx, deps)
	if err != nil {
		return nil, err
	}

	// Create HTTP gateway
	gateway := httpserver.NewGatewayServer(deps.HealthChecker, adminAdapter, deps.Writer, deps.Provider)

	setupCtx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()

	if err := gateway.Setup(setupCtx); err != nil {
		return nil, errors.Wrap(err, "setup gateway")
	}

	handler := http.Handler(gateway)

	// Apply proprietary middleware if available
	if deps.PropOpts != nil && deps.PropOpts.HTTPMiddleware != nil {
		middlewareFunc := deps.PropOpts.HTTPMiddleware()
		handler = middlewareFunc(handler)
	}

	// Wrap with CORS middleware (reads config dynamically per-request for hot-reload)
	handler = httpserver.CORSMiddleware(deps.Provider)(handler)

	// Wrap with security headers middleware
	handler = httpserver.SecurityHeadersMiddleware(handler)

	if !opts.SkipRequestID {
		// Assign / propagate X-Request-ID inside the span so it appears in traces.
		// Must run INSIDE otelhttp so the span already exists when we call trace.SpanFromContext.
		handler = httpserver.RequestIDMiddleware(handler)
	}

	if !opts.SkipRequestLogging {
		// Log each request on completion. Must run inside otelhttp so the
		// request context already carries the span and logs get trace IDs.
		handler = httpserver.RequestLoggingMiddleware(deps.Provider, deps.Log)(handler)
	}

	if !opts.SkipOTEL {
		// Start a server span for each HTTP request. Must be the outermost
		// wrapper so every inner middleware (request logging, RequestIDMiddleware)
		// sees the span context.
		handler = otelhttp.NewHandler(handler, "talos.http.server")
	}

	return handler, nil
}

// buildAdapters creates or returns the single APIKeys adapter based
// on mode and pre-built overrides. In all modes a single adapter is returned;
// per-mode constructors use UnimplementedApiKeysServer to fail
// closed on methods that are not wired for the current mode.
func buildAdapters(ctx context.Context, deps *ServerDependencies) (talosv2alpha1.ApiKeysServer, error) {
	// If a pre-built adapter is provided, use it directly.
	if deps.PreBuiltAdmin != nil {
		return deps.PreBuiltAdmin, nil
	}

	// Public is shared: it handles public revocation and delegates
	// verify calls from the admin adapter.
	verifier, err := deps.Factory.CreateVerifier(ctx)
	if err != nil {
		return nil, errors.Wrap(err, "create verifier")
	}
	rateLimiter, err := deps.Factory.GetOrCreateRateLimiter(ctx)
	if err != nil {
		return nil, errors.Wrap(err, "create rate limiter")
	}
	publicSvc := service.NewPublic(verifier, deps.Factory.ProtoValidator(), rateLimiter)

	switch deps.Mode {
	case ModeAllInOne:
		admin, err := deps.Factory.CreateAdmin(ctx)
		if err != nil {
			return nil, errors.Wrap(err, "create API keys service")
		}
		return httpserver.NewAllInOneAdapter(admin, publicSvc), nil
	case ModeAdmin:
		admin, err := deps.Factory.CreateAdmin(ctx)
		if err != nil {
			return nil, errors.Wrap(err, "create API keys service")
		}
		return httpserver.NewAdminOnlyAdapter(admin, publicSvc), nil
	case ModePublic:
		return httpserver.NewPublicOnlyAdapter(publicSvc), nil
	default:
		return nil, errors.Newf("unknown server mode: %d", deps.Mode)
	}
}
