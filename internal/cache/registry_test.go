// Copyright © 2026 Ory Corp
// SPDX-License-Identifier: Apache-2.0

//go:build !commercial

package cache_test

import (
	"log/slog"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/prometheus/client_golang/prometheus"

	"github.com/ory/herodot"
	"github.com/ory/x/configx"
	"github.com/ory/x/httpx"

	commercialregistry "github.com/ory/talos/commercial/registry"
	"github.com/ory/talos/internal/config"
	"github.com/ory/talos/internal/errdef"
	"github.com/ory/talos/internal/registry"
	"github.com/ory/talos/internal/testutil"
)

// TODO simplify this code

// TestEditionBehavior tests OSS cache availability through the production ServiceFactory.
// This verifies that commercial cache types properly return ErrPaymentRequired in OSS builds.
func TestEditionBehavior(t *testing.T) {
	t.Parallel()
	ctx := t.Context()

	t.Run("Redis cache availability", func(t *testing.T) {
		t.Parallel()
		// Setup: Create real driver and provider configured for Redis cache
		driver, err := testutil.InitDriver(t, "")
		require.NoError(t, err)
		t.Cleanup(func() { _ = driver.Close() })

		// Create provider with test defaults and Redis cache configuration
		provider := testutil.NewTestProvider(t, configx.WithValues(map[string]any{
			config.KeyCacheType.String():       "redis",
			config.KeyCacheRedisAddrs.String(): []string{"localhost:6379"},
		}))

		emitter := testutil.NewMockEmitter()
		logger := slog.Default()

		// Get OSS registry options (no commercial cache factories)
		propOpts, err := commercialregistry.Options(ctx, provider, logger, herodot.NewJSONWriter(nil))
		require.NoError(t, err)

		// Create ServiceFactory with production code
		factory, err := registry.NewServiceFactory(ctx, driver, provider, emitter, httpx.NewResilientClient(), propOpts.CacheFactories, nil, prometheus.NewRegistry())
		require.NoError(t, err)
		t.Cleanup(func() { _ = factory.Close() })

		// Test: Try to create a verifier (which creates cache internally)
		// In OSS, this should fail with ErrPaymentRequired for Redis cache
		_, err = factory.CreateVerifier(ctx)
		require.Error(t, err)
		require.ErrorIs(t, err, errdef.ErrPaymentRequired())
	})

	t.Run("Memory cache availability", func(t *testing.T) {
		t.Parallel()
		// Setup: Create real driver and provider configured for memory cache
		driver, err := testutil.InitDriver(t, "")
		require.NoError(t, err)
		t.Cleanup(func() { _ = driver.Close() })

		// Create provider with test defaults and memory cache configuration
		provider := testutil.NewTestProvider(t, configx.WithValues(map[string]any{
			config.KeyCacheType.String():              "memory",
			config.KeyCacheMemoryMaxSize.String():     100 * 1024 * 1024,
			config.KeyCacheMemoryNumCounters.String(): 10000,
		}))

		// OSS tests don't need contextualizer dependencies
		propOpts, err := commercialregistry.Options(ctx, nil, slog.Default(), herodot.NewJSONWriter(nil))
		require.NoError(t, err)

		emitter := testutil.NewMockEmitter()

		// Create ServiceFactory with production code
		factory, err := registry.NewServiceFactory(ctx, driver, provider, emitter, httpx.NewResilientClient(), propOpts.CacheFactories, nil, prometheus.NewRegistry())
		require.NoError(t, err)
		t.Cleanup(func() { _ = factory.Close() })

		// Test: Try to create a admin (which creates cache internally)
		// In OSS, this should fail with ErrPaymentRequired for memory cache
		_, err = factory.CreateAdmin(ctx)
		require.Error(t, err)
		require.ErrorIs(t, err, errdef.ErrPaymentRequired())
	})

	t.Run("Noop cache availability", func(t *testing.T) {
		t.Parallel()
		// Setup: Create real driver and provider configured for noop cache
		driver, err := testutil.InitDriver(t, "")
		require.NoError(t, err)
		t.Cleanup(func() { _ = driver.Close() })

		// Create provider with test defaults (noop cache is the default, set explicitly for clarity)
		provider := testutil.NewTestProvider(t, configx.WithValues(map[string]any{
			config.KeyCacheType.String(): "noop",
		}))

		emitter := testutil.NewMockEmitter()
		logger := slog.Default()

		// Get OSS registry options
		propOpts, err := commercialregistry.Options(ctx, provider, logger, herodot.NewJSONWriter(nil))
		require.NoError(t, err)

		// Create ServiceFactory with production code
		factory, err := registry.NewServiceFactory(ctx, driver, provider, emitter, httpx.NewResilientClient(), propOpts.CacheFactories, nil, prometheus.NewRegistry())
		require.NoError(t, err)
		t.Cleanup(func() { _ = factory.Close() })

		// Test: Noop cache should work in OSS
		verifier, err := factory.CreateVerifier(ctx)
		require.NoError(t, err)
		require.NotNil(t, verifier)

		// Also test admin
		admin, err := factory.CreateAdmin(ctx)
		require.NoError(t, err)
		require.NotNil(t, admin)

		// Note: We can't easily inspect the internal cache type from outside,
		// but the fact that creation succeeded proves noop cache works in OSS
	})

	// Note: We don't test "unknown cache type" because config schema validation
	// rejects invalid cache types before they reach our production code.
	// Config validation is tested separately in config package tests.
}

// reviewed - @aeneasr - 2026-03-25
