package cmd

import (
	"context"
	"fmt"
	"log/slog"
	"net/http"
	"slices"
	"strings"
	"time"

	"github.com/cockroachdb/errors"
	"github.com/prometheus/client_golang/prometheus"
	"golang.org/x/sync/errgroup"

	commercialregistry "github.com/ory/talos/commercial/registry"

	"github.com/ory/x/httpx"

	"github.com/ory/talos/internal/boot"
	talosconfig "github.com/ory/talos/internal/config"
	"github.com/ory/talos/internal/events"
	"github.com/ory/talos/internal/health"
	"github.com/ory/talos/internal/logger"
	"github.com/ory/talos/internal/persistence"
	"github.com/ory/talos/internal/registry"
	httpserver "github.com/ory/talos/internal/server/http"
	"github.com/ory/talos/internal/tracing"
	"github.com/ory/talos/internal/version"
)

// formatAddr formats host and port into an address string suitable for http.Server.Addr
func formatAddr(host string, port int) string {
	return fmt.Sprintf("%s:%d", host, port)
}

// initializeServerDependencies sets up infrastructure dependencies.
// CRITICAL: Does NOT cache config values - only infrastructure instances.
// Context is passed as first parameter, never stored in struct.
func initializeServerDependencies(ctx context.Context, provider talosconfig.ProviderInterface, mode boot.ServerMode) (*boot.ServerDependencies, func(), error) {
	// Read log config dynamically (not cached in struct)
	logLevel := provider.String(ctx, talosconfig.KeyLogLevel)
	logFormat := provider.String(ctx, talosconfig.KeyLogFormat)
	log := logger.NewLogger(logLevel, logFormat)

	log.Info(
		"Starting Ory Talos",
		slog.String("version", version.Version),
		slog.String("commit", version.Commit),
		slog.String("build_time", version.BuildTime),
		slog.String("log_level", logLevel),
		slog.String("log_format", logFormat),
	)

	// Warn once at startup if any JWT signing-key source is fetched over
	// plaintext HTTP, before any other subsystem starts.
	warnInsecureSigningKeyURLs(log, provider.Strings(ctx, talosconfig.KeyCredentialsDerivedTokensJWTSigningKeysURLs))

	// Track cleanup functions
	var cleanups []func()
	cleanup := func() {
		for _, cleanup := range slices.Backward(cleanups) {
			cleanup()
		}
	}

	// Set up tracing - we use a global trace provider instead of injecting it.
	if tp, err := tracing.InitTracer(ctx, provider); err != nil {
		log.Error("Failed to initialize tracer; tracing is disabled and audit events will be dropped", slog.String("error", err.Error()))
	} else if tp != nil {
		cleanups = append(cleanups, func() {
			log.Info("Stopping tracer")
			// Use context.WithoutCancel to inherit values but allow independent timeout
			shutdownCtx, cancel := context.WithTimeout(context.WithoutCancel(ctx), 5*time.Second)

			defer cancel()
			_ = tp.Shutdown(shutdownCtx)
		})

		log.Info(
			"Tracing initialized",
			slog.String("exporter", provider.String(ctx, talosconfig.KeyTracingExporter)),
			slog.String("endpoint", provider.String(ctx, talosconfig.KeyTracingEndpoint)),
		)
	}

	// Wire the analytics-wrapped tracer (commercial only; no-op in OSS).
	commercialregistry.ConfigureAnalyticsTracer(ctx)

	// Get database driver factories (lightweight, no initialization)
	driverFactories := commercialregistry.DatabaseDriverFactories()

	// Initialize database using factories
	dbDriver, err := initDatabaseFromProvider(ctx, provider, log, driverFactories)
	if err != nil {
		return nil, cleanup, errors.Wrap(err, "initialize database")
	}
	cleanups = append(cleanups, func() {
		if err := dbDriver.Close(); err != nil {
			log.Error("Database close error", slog.String("error", err.Error()))
		} else {
			log.Info("Database connection closed")
		}
	})

	// All drivers seed the single-tenant uuid.Nil network row required for
	// FK constraints. Commercial deployments with multitenancy enabled
	// additionally create per-tenant network rows on demand via
	// InitializeNetwork during tenant onboarding.
	if err := dbDriver.Initialize(ctx); err != nil {
		return nil, cleanup, errors.Wrap(err, "initialize database")
	}

	// Create AIP-193 compliant error writer
	writer := httpserver.NewAIPWriter(log, "www.ory.com/talos")

	// Initialize full options with database (called once)
	propOpts, err := commercialregistry.Options(ctx, provider, log.Logger, writer)
	if err != nil {
		return nil, cleanup, errors.Wrap(err, "initialize proprietary features")
	}

	commercialregistry.ConfigureCloudContextualizer(ctx, propOpts, provider)

	// Register database metrics collectors
	if propOpts.RegisterDatabaseMetrics != nil {
		propOpts.RegisterDatabaseMetrics(dbDriver, log)
	}

	// Validate required config (but don't cache the values!).
	// The HMAC secret is the single source of truth for both API key
	// checksums and the derived pagination cursor encryption key.
	hmacSecret := provider.String(ctx, talosconfig.KeySecretsHMACCurrent)
	if hmacSecret == "" {
		return nil, cleanup, errors.Newf("%q is required but not set in configuration", talosconfig.KeySecretsHMACCurrent)
	}

	log.Info("Configuration validated")

	// Create health checker and add database check
	healthChecker := health.NewChecker(writer)
	healthChecker.AddDatabaseCheck(dbDriver.DB())

	// Create emitter
	emitter := events.NewOTELEmitter()

	// Create SSRF-protected HTTP client for outbound requests (JWKS fetching, etc.).
	// Must be created after tracing initialization so OTEL transport is active.
	httpClient := httpx.NewResilientClient(
		httpx.ResilientClientDisallowInternalIPs(),
	)

	// Create service factory (stores provider, not config values!)
	backendFactories := propOpts.CacheFactories
	factory, err := registry.NewServiceFactory(ctx, dbDriver, provider, emitter, httpClient, backendFactories, propOpts.RateLimiterFactory, prometheus.DefaultRegisterer)
	if err != nil {
		return nil, cleanup, errors.Wrap(err, "create service factory")
	}
	cleanups = append(cleanups, func() {
		if err := factory.Close(); err != nil {
			log.Error("Factory close error", slog.String("error", err.Error()))
		}
	})

	return &boot.ServerDependencies{
		Log:           log,
		Writer:        writer,
		Factory:       factory,
		Provider:      provider,
		HealthChecker: healthChecker,
		PropOpts:      propOpts,
		Mode:          mode,
	}, cleanup, nil
}

// warnInsecureSigningKeyURLs emits a single startup warning when any configured
// JWT signing-key source uses a plaintext http:// scheme. Such sources are
// vulnerable to man-in-the-middle tampering of the JWKS used to sign derived
// tokens, so HTTPS, file, or base64 sources are strongly preferred. Only the URL
// scheme is inspected; URL values, credentials, query strings, and key material
// are never logged.
func warnInsecureSigningKeyURLs(log *logger.Logger, urls []string) {
	var insecure []int
	for i, u := range urls {
		if strings.HasPrefix(strings.ToLower(strings.TrimSpace(u)), "http://") {
			insecure = append(insecure, i)
		}
	}
	if len(insecure) == 0 {
		return
	}

	log.Warn(
		"Insecure JWT signing-key source: one or more configured URLs use a plaintext http:// scheme, which is vulnerable to man-in-the-middle tampering of the JWKS used to sign derived tokens. Use an https://, file://, or base64:// source instead.",
		slog.String("config_key", talosconfig.KeyCredentialsDerivedTokensJWTSigningKeysURLs.String()),
		slog.Int("insecure_count", len(insecure)),
		slog.Any("insecure_indexes", insecure),
	)
}

// initDatabaseFromProvider initializes database using driver factories
func initDatabaseFromProvider(ctx context.Context, provider talosconfig.ProviderInterface, log *logger.Logger, driverFactories map[string]persistence.Factory) (persistence.Persister, error) {
	// Read DSN dynamically from provider (not cached)
	dsn := provider.String(ctx, talosconfig.KeyDBDSN)
	if dsn == "" {
		return nil, errors.Errorf("database DSN is required but config key %q is not set", talosconfig.KeyDBDSN)
	}

	// Parse DSN to determine driver type (from scheme: sqlite://, postgres://, cockroach://)
	driverType, connOpts, err := persistence.ParseDSN(dsn)
	if err != nil {
		return nil, errors.Wrap(err, "parse database DSN")
	}

	// NewDriver creates the driver instance (individual drivers handle connection retry)
	driver, err := persistence.NewDriver(ctx, dsn, driverFactories)
	if err != nil {
		return nil, errors.Wrap(err, "initialize database")
	}

	log.Info(
		"Database connected",
		slog.String("driver", driverType),
		slog.Int("max_conns", connOpts.MaxConns),
		slog.Int("max_idle_conns", connOpts.MaxIdleConns),
		slog.Duration("max_conn_lifetime", connOpts.MaxConnLifetime),
		slog.Duration("max_conn_idle_time", connOpts.MaxIdleConnTime),
	)

	return driver, nil
}

// createHTTPServerWithMiddleware creates an HTTP server with gateway and middleware
func createHTTPServerWithMiddleware(ctx context.Context, addr string, deps *boot.ServerDependencies) (*http.Server, error) {
	handler, err := boot.HTTPHandlerFromDependencies(ctx, deps, nil)
	if err != nil {
		return nil, err
	}

	return &http.Server{
		Addr:              addr,
		Handler:           handler,
		ReadTimeout:       15 * time.Second,
		ReadHeaderTimeout: 5 * time.Second,
		WriteTimeout:      15 * time.Second,
		IdleTimeout:       60 * time.Second,
	}, nil
}

// createMetricsHTTPServer creates the metrics HTTP server
func createMetricsHTTPServer(addr string, healthChecker *health.Checker) *http.Server {
	mux := http.NewServeMux()
	registerMetricsRoute(mux)

	healthxHandler := healthChecker.Handler()
	mux.Handle("/health/alive", healthxHandler.Alive())
	mux.Handle("/health/ready", healthxHandler.Ready(false))

	return &http.Server{
		Addr:              addr,
		Handler:           mux,
		ReadTimeout:       15 * time.Second,
		ReadHeaderTimeout: 5 * time.Second,
		WriteTimeout:      15 * time.Second,
		IdleTimeout:       60 * time.Second,
	}
}

// runServersWithErrGroup starts all servers using errgroup for lifecycle management
func runServersWithErrGroup(
	ctx context.Context,
	deps *boot.ServerDependencies,
	httpServer *http.Server,
	metricsServer *http.Server,
) error {
	g, ctx := errgroup.WithContext(ctx)

	// Start HTTP server
	g.Go(func() error {
		deps.Log.Info("HTTP server started", slog.String("addr", httpServer.Addr))
		if err := httpServer.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
			return errors.Wrap(err, "HTTP server error")
		}
		return nil
	})

	// Start metrics server
	g.Go(func() error {
		deps.Log.Info("Metrics server started", slog.String("addr", metricsServer.Addr))
		if err := metricsServer.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
			return errors.Wrap(err, "Metrics server error")
		}
		return nil
	})

	// Handle shutdown signal
	g.Go(func() error {
		<-ctx.Done()
		deps.Log.Info("Shutdown signal received, starting graceful shutdown")

		shutdownCtx, cancel := context.WithTimeout(context.WithoutCancel(ctx), 30*time.Second)
		defer cancel()

		// Shutdown HTTP servers
		if err := httpServer.Shutdown(shutdownCtx); err != nil {
			deps.Log.Error("HTTP server shutdown error", slog.String("error", err.Error()))
		} else {
			deps.Log.Info("HTTP server stopped")
		}

		if err := metricsServer.Shutdown(shutdownCtx); err != nil {
			deps.Log.Error("Metrics server shutdown error", slog.String("error", err.Error()))
		} else {
			deps.Log.Info("Metrics server stopped")
		}

		return nil
	})

	return g.Wait()
}

// reviewed - @aeneasr - 2026-03-25
