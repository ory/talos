// Package registry provides service factory for dependency injection.
package registry

import (
	"context"
	"sync"

	"buf.build/go/protovalidate"
	"github.com/cockroachdb/errors"
	"github.com/hashicorp/go-retryablehttp"
	"github.com/prometheus/client_golang/prometheus"

	"github.com/ory/talos/internal/cache"
	talosconfig "github.com/ory/talos/internal/config"
	"github.com/ory/talos/internal/crypto"
	"github.com/ory/talos/internal/errdef"
	"github.com/ory/talos/internal/events"
	"github.com/ory/talos/internal/lastused"
	"github.com/ory/talos/internal/metrics"
	"github.com/ory/talos/internal/persistence"
	db "github.com/ory/talos/internal/persistence/sqlc/generated"
	"github.com/ory/talos/internal/ratelimit"
	"github.com/ory/talos/internal/registrytypes"
	"github.com/ory/talos/internal/service"
	"github.com/ory/talos/internal/verifier"
	talosv2alpha1 "github.com/ory/talos/pkg/api/talos/v2alpha1"

	"github.com/ory/x/stringsx"
)

const (
	// cacheNamespace is the namespace used for API key caching
	cacheNamespace = "talos"
)

// ServiceFactory creates services with shared infrastructure dependencies.
// CRITICAL: Only infrastructure instances are stored, NOT configuration values.
// Configuration must always be read dynamically from provider with context.
type ServiceFactory struct {
	// Infrastructure instances (can be cached)
	driver         persistence.Persister
	provider       talosconfig.ProviderInterface // Store provider, not config values!
	emitter        events.Emitter
	protoValidator protovalidate.Validator
	httpClient     *retryablehttp.Client // SSRF-protected, OTEL-instrumented

	// Cache (initialized lazily on first use, protected by sync.Once)
	apiKeyCache    cache.Cache[db.IssuedApiKey]
	cacheOnce      sync.Once
	cacheErr       error
	cacheFactories map[string]registrytypes.CacheFactory

	// Rate limiter (initialized lazily on first use, protected by sync.Once)
	rateLimiter        ratelimit.Limiter
	rateLimiterOnce    sync.Once
	rateLimiterErr     error
	rateLimiterFactory registrytypes.RateLimiterFactory

	// Metrics (created once at factory construction time)
	metrics *metrics.Metrics

	// Last-used tracker (batched async last_used_at updates)
	tracker *lastused.Tracker

	// DO NOT store config values here!
	// Config must always be read dynamically from provider with context.
}

// NewServiceFactory creates a factory with core infrastructure dependencies.
// CRITICAL: All dependencies must be non-nil (will panic on use if nil).
func NewServiceFactory(
	ctx context.Context,
	driver persistence.Persister,
	provider talosconfig.ProviderInterface,
	emitter events.Emitter,
	httpClient *retryablehttp.Client,
	cacheFactories map[string]registrytypes.CacheFactory,
	rateLimiterFactory registrytypes.RateLimiterFactory,
	reg prometheus.Registerer,
) (*ServiceFactory, error) {
	pv, err := NewWarmValidator()
	if err != nil {
		return nil, err
	}

	tracker := lastused.New(ctx, driver, lastused.Config{
		QueueSize:     provider.Int(ctx, talosconfig.KeyLastUsedQueueSize),
		FlushSize:     provider.Int(ctx, talosconfig.KeyLastUsedFlushSize),
		FlushInterval: provider.Duration(ctx, talosconfig.KeyLastUsedFlushInterval),
		NumWorkers:    provider.Int(ctx, talosconfig.KeyLastUsedNumWorkers),
	})

	return &ServiceFactory{
		driver:             driver,
		provider:           provider,
		emitter:            emitter,
		httpClient:         httpClient,
		cacheFactories:     cacheFactories,
		rateLimiterFactory: rateLimiterFactory,
		protoValidator:     pv,
		metrics:            metrics.New(reg),
		tracker:            tracker,
	}, nil
}

// keyServiceMetrics returns the adapter bridging metrics.Metrics to crypto.KeyServiceMetrics.
func (f *ServiceFactory) keyServiceMetrics() crypto.KeyServiceMetrics {
	return metrics.NewKeyServiceMetricsAdapter(f.metrics)
}

// CreateAdmin creates a admin service.
// Config is read dynamically on each call - no caching!
// Note: Runtime config (prefix, secrets, TTL) is read per-request via the provider.
func (f *ServiceFactory) CreateAdmin(ctx context.Context) (*service.Admin, error) {
	keyService, err := crypto.NewKeyService(ctx, f.provider, f.httpClient, f.keyServiceMetrics())
	if err != nil {
		return nil, err
	}

	apiKeyCache, err := f.getOrCreateCache(ctx)
	if err != nil {
		return nil, err
	}

	return service.NewAdminFromProvider(
		f.driver,
		f.provider, // Provider handles context-specific config in commercial builds
		f.emitter,
		keyService,
		apiKeyCache,
		f.protoValidator,
		f.metrics,
		f.tracker,
	), nil
}

// CreateVerifier creates a verifier.
// Cache config is built from provider dynamically - no caching!
// Note: Runtime config is read per-request via the provider.
func (f *ServiceFactory) CreateVerifier(ctx context.Context) (*verifier.Verifier, error) {
	apiKeyCache, err := f.getOrCreateCache(ctx)
	if err != nil {
		return nil, err
	}

	keyService, err := crypto.NewKeyService(ctx, f.provider, f.httpClient, f.keyServiceMetrics())
	if err != nil {
		return nil, err
	}

	return verifier.NewFromProvider(
		f.driver,
		f.provider, // Provider handles context-specific config in commercial builds
		apiKeyCache,
		f.emitter,
		keyService,
		f.metrics,
		f.tracker,
	), nil
}

// getOrCreateCache returns the API key cache, creating it if needed. The
// backend is created once and reused (backend type is immutable at runtime).
// The backend is a plain store: whether caching is active is decided per
// request by the verifier, which reads cache.enabled and cache.ttl from the
// provider before it ever reads or writes the cache. Disabled caching is
// therefore handled at the call site, not in the cache layer.
// Uses sync.Once for safe concurrent initialization.
func (f *ServiceFactory) getOrCreateCache(ctx context.Context) (cache.Cache[db.IssuedApiKey], error) {
	f.cacheOnce.Do(func() {
		f.apiKeyCache, f.cacheErr = f.createCache(ctx, f.buildCacheConfig(ctx))
	})
	return f.apiKeyCache, f.cacheErr
}

// createCache creates a typed cache using the registered factories.
func (f *ServiceFactory) createCache(ctx context.Context, config *cache.Config) (cache.Cache[db.IssuedApiKey], error) {
	if factory, ok := f.cacheFactories[config.Type]; ok {
		return factory(ctx, config, cacheNamespace)
	}

	// Fall back to built-in types
	switch fn := stringsx.SwitchExact(config.Type); {
	case fn.AddCase("noop"):
		return cache.NewNoopCache[db.IssuedApiKey](), nil
	case fn.AddCase("memory"):
		return nil, errdef.ErrPaymentRequired().WithReasonf("Memory cache requires license.")
	case fn.AddCase("redis"):
		return nil, errdef.ErrPaymentRequired().WithReasonf("Redis cache requires license.")
	default:
		return nil, errdef.ErrPaymentRequired().WithReasonf("unknown cache type: %s", config.Type)
	}
}

// buildCacheConfig reads cache configuration dynamically.
// Note: Cache config is immutable at runtime (requires restart to change).
func (f *ServiceFactory) buildCacheConfig(ctx context.Context) *cache.Config {
	return &cache.Config{
		Type:                 f.provider.String(ctx, talosconfig.KeyCacheType),
		TTL:                  f.provider.Duration(ctx, talosconfig.KeyCacheTTL),
		MemoryMaxSize:        int64(f.provider.Int(ctx, talosconfig.KeyCacheMemoryMaxSize)),
		MemoryNumCounters:    int64(f.provider.Int(ctx, talosconfig.KeyCacheMemoryNumCounters)),
		RedisAddrs:           f.provider.Strings(ctx, talosconfig.KeyCacheRedisAddrs),
		RedisPassword:        f.provider.String(ctx, talosconfig.KeyCacheRedisPassword),
		RedisDB:              f.provider.Int(ctx, talosconfig.KeyCacheRedisDB),
		RedisPoolSize:        f.provider.Int(ctx, talosconfig.KeyCacheRedisPoolSize),
		RedisMinIdleConns:    f.provider.Int(ctx, talosconfig.KeyCacheRedisMinIdleConns),
		RedisConnMaxIdleTime: f.provider.Duration(ctx, talosconfig.KeyCacheRedisConnMaxIdleTime),
		RedisConnMaxLifetime: f.provider.Duration(ctx, talosconfig.KeyCacheRedisConnMaxLifetime),
		RedisTimeout:         f.provider.Duration(ctx, talosconfig.KeyCacheRedisTimeout),
		RedisTLSEnabled:      f.provider.Bool(ctx, talosconfig.KeyCacheRedisTLSEnabled),
	}
}

// TODO move this to commercial/registry and into rate limiter.

// enableCheckLimiter wraps a real Limiter and checks rate_limit.enabled per-request,
// making the enabled flag hot-reloadable without restarting the server.
type enableCheckLimiter struct {
	delegate ratelimit.Limiter
	provider talosconfig.ProviderInterface
}

// Allow checks rate_limit.enabled per-request. If disabled, returns allowed
// without delegating. If enabled, delegates to the underlying limiter.
func (l *enableCheckLimiter) Allow(ctx context.Context, keyID string, policy *talosv2alpha1.RateLimitPolicy) (*ratelimit.Result, error) {
	if !l.provider.Bool(ctx, talosconfig.KeyRateLimitEnabled) {
		return &ratelimit.Result{Allowed: true}, nil
	}
	return l.delegate.Allow(ctx, keyID, policy)
}

// Enabled reports whether the underlying limiter enforces quotas. It reflects
// the backend (real vs no-op), not the hot-reloadable rate_limit.enabled flag:
// callers use this to decide cache safety, and keeping responses non-storable
// whenever an enforcing backend is configured is the conservative, safe choice.
func (l *enableCheckLimiter) Enabled() bool {
	return l.delegate.Enabled()
}

// Close releases resources held by the underlying limiter.
func (l *enableCheckLimiter) Close() error {
	return l.delegate.Close()
}

// getOrCreateRateLimiter returns the rate limiter, creating it if needed.
// If no factory is set (OSS), returns NoopLimiter. Otherwise creates the real
// backend limiter (immutable) and wraps it with an enabled check (hot-reloadable).
// Uses sync.Once for safe concurrent initialization.
func (f *ServiceFactory) getOrCreateRateLimiter(ctx context.Context) (ratelimit.Limiter, error) {
	f.rateLimiterOnce.Do(func() {
		// If no factory is set (OSS builds), return noop limiter
		if f.rateLimiterFactory == nil {
			f.rateLimiter = &ratelimit.NoopLimiter{}
			return
		}

		// Always create the real backend limiter (backend choice is immutable).
		// The enabled flag is checked per-request by the wrapper.
		backend := f.provider.String(ctx, talosconfig.KeyRateLimitBackend)
		cacheConfig := f.buildCacheConfig(ctx)

		var delegate ratelimit.Limiter
		delegate, f.rateLimiterErr = f.rateLimiterFactory(ctx, backend, cacheConfig)
		if f.rateLimiterErr != nil {
			f.rateLimiterErr = errors.Wrap(f.rateLimiterErr, "create rate limiter")
			return
		}

		f.rateLimiter = &enableCheckLimiter{delegate: delegate, provider: f.provider}
	})
	return f.rateLimiter, f.rateLimiterErr
}

// GetOrCreateRateLimiter returns the rate limiter, creating it if needed.
func (f *ServiceFactory) GetOrCreateRateLimiter(ctx context.Context) (ratelimit.Limiter, error) {
	return f.getOrCreateRateLimiter(ctx)
}

// ProtoValidator returns the shared proto validator instance.
func (f *ServiceFactory) ProtoValidator() protovalidate.Validator {
	return f.protoValidator
}

// HTTPClient returns the shared SSRF-protected HTTP client.
func (f *ServiceFactory) HTTPClient() *retryablehttp.Client {
	return f.httpClient
}

// Provider returns the config provider (for cases where direct access is needed).
func (f *ServiceFactory) Provider() talosconfig.ProviderInterface {
	return f.provider
}

// Driver returns the persistence driver (for cases where direct access is needed).
func (f *ServiceFactory) Driver() persistence.Persister {
	return f.driver
}

// Metrics returns the metrics instance (for cases where direct access is needed).
func (f *ServiceFactory) Metrics() *metrics.Metrics {
	return f.metrics
}

// Close closes all resources managed by the factory.
// Tracker is closed before driver to allow final flush before DB closes.
func (f *ServiceFactory) Close() error {
	var errs []error
	if f.rateLimiter != nil {
		errs = append(errs, f.rateLimiter.Close())
	}
	if f.apiKeyCache != nil {
		errs = append(errs, f.apiKeyCache.Close())
	}
	if f.tracker != nil {
		f.tracker.Close()
	}
	if f.driver != nil {
		errs = append(errs, f.driver.Close())
	}
	return errors.Join(errs...)
}

// reviewed - @aeneasr - 2026-03-26
