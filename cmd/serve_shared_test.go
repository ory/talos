package cmd

import (
	"context"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"testing"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/ory/herodot"
	"github.com/ory/x/configx"
	"github.com/ory/x/httpx"

	commercialregistry "github.com/ory/talos/commercial/registry"
	"github.com/ory/talos/internal/boot"
	talosconfig "github.com/ory/talos/internal/config"
	"github.com/ory/talos/internal/health"
	"github.com/ory/talos/internal/logger"
	"github.com/ory/talos/internal/registry"
	httpserver "github.com/ory/talos/internal/server/http"
	"github.com/ory/talos/internal/testutil"
)

func TestCreateMetricsHTTPServer(t *testing.T) {
	// This test does not use prometheus.DefaultRegisterer — promhttp.Handler()
	// reads the default registry but only for reads, which is safe for parallel
	// execution as long as no other test registers metrics concurrently.
	// Marked sequential to match the conservative guidance in AGENTS.md.

	writer := herodot.NewJSONWriter(nil)
	healthChecker := health.NewChecker(writer)

	srv := createMetricsHTTPServer("unused-addr", healthChecker)
	require.NotNil(t, srv)

	// Wrap the handler directly — no need to bind a port.
	ts := httptest.NewServer(srv.Handler)
	t.Cleanup(ts.Close)

	hc := testutil.NewTestHTTPClient(t)

	// get sends a GET request, reads the body fully, closes it, and returns the
	// status code along with the body bytes.
	get := func(t *testing.T, path string) (int, []byte) {
		t.Helper()
		req, err := http.NewRequestWithContext(t.Context(), http.MethodGet, ts.URL+path, nil)
		require.NoError(t, err)
		resp, err := hc.Do(req)
		require.NoError(t, err)
		defer func() { _ = resp.Body.Close() }()
		body, err := io.ReadAll(resp.Body)
		require.NoError(t, err)
		return resp.StatusCode, body
	}

	t.Run("health alive returns 200", func(t *testing.T) {
		status, _ := get(t, "/health/alive")
		assert.Equal(t, http.StatusOK, status)
	})

	t.Run("health ready returns 200", func(t *testing.T) {
		status, _ := get(t, "/health/ready")
		assert.Equal(t, http.StatusOK, status)
	})
}

func TestInitDatabaseFromProvider(t *testing.T) {
	t.Parallel()

	log := logger.NewLogger("error", "json")

	t.Run("unsupported driver scheme returns error", func(t *testing.T) {
		t.Parallel()
		provider := testutil.NewTestProvider(t, configx.WithValues(map[string]any{
			talosconfig.KeyDBDSN.String(): "unsupported://localhost/db",
		}))

		_, err := initDatabaseFromProvider(t.Context(), provider, log, nil)
		require.Error(t, err)
	})

	t.Run("valid SQLite DSN creates driver", func(t *testing.T) {
		t.Parallel()
		dbPath := filepath.Join(t.TempDir(), "test.db")
		provider := testutil.NewTestProvider(t, configx.WithValues(map[string]any{
			talosconfig.KeyDBDSN.String(): "sqlite3://" + dbPath + "?_journal=WAL&_timeout=5000",
		}))

		driver, err := initDatabaseFromProvider(t.Context(), provider, log, nil)
		require.NoError(t, err)
		require.NotNil(t, driver)
		t.Cleanup(func() { _ = driver.Close() })
	})
}

func TestRunServersWithErrGroup(t *testing.T) {
	t.Parallel()

	t.Run("context cancellation triggers graceful shutdown", func(t *testing.T) {
		t.Parallel()

		log := logger.NewLogger("error", "json")
		writer := herodot.NewJSONWriter(nil)
		healthChecker := health.NewChecker(writer)

		deps := &boot.ServerDependencies{
			Log: log,
		}

		// Bind to random free ports.
		lc := &net.ListenConfig{}
		ctx, cancel := context.WithCancel(t.Context())
		httpLn, err := lc.Listen(ctx, "tcp", "127.0.0.1:0")
		require.NoError(t, err)
		metricsLn, err := lc.Listen(ctx, "tcp", "127.0.0.1:0")
		require.NoError(t, err)

		httpServer := &http.Server{
			Addr:    httpLn.Addr().String(),
			Handler: http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusOK) }),
		}
		metricsServer := createMetricsHTTPServer(metricsLn.Addr().String(), healthChecker)

		// Close listeners so ListenAndServe can rebind the same ports.
		require.NoError(t, httpLn.Close())
		require.NoError(t, metricsLn.Close())

		errCh := make(chan error, 1)
		go func() { errCh <- runServersWithErrGroup(ctx, deps, httpServer, metricsServer) }()

		hc := testutil.NewTestHTTPClient(t)

		// probe issues a GET and returns true if the server responded 200.
		probe := func(url string) bool {
			req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
			if err != nil {
				return false
			}
			resp, err := hc.Do(req)
			if err != nil {
				return false
			}
			_ = resp.Body.Close()
			return resp.StatusCode == http.StatusOK
		}

		// Wait for servers to become reachable.
		require.Eventually(t, func() bool {
			return probe("http://" + httpServer.Addr + "/")
		}, 3*time.Second, 50*time.Millisecond, "HTTP server did not start")

		require.Eventually(t, func() bool {
			return probe("http://" + metricsServer.Addr + "/health/alive")
		}, 3*time.Second, 50*time.Millisecond, "metrics server did not start")

		// Cancel triggers shutdown.
		cancel()

		select {
		case err := <-errCh:
			require.NoError(t, err, "graceful shutdown should not return an error")
		case <-time.After(10 * time.Second):
			t.Fatal("runServersWithErrGroup did not return after context cancellation")
		}
	})
}

// newTestDeps constructs a *boot.ServerDependencies for use in cmd-package
// tests. It mirrors the buildDeps helper in internal/boot/handler_test.go but
// lives here so that serve_shared_test.go (package cmd) can call it directly.
// It uses an isolated Prometheus registry so tests are safe to run in parallel.
func newTestDeps(t *testing.T, mode boot.ServerMode) *boot.ServerDependencies {
	t.Helper()
	ctx := t.Context()

	driver, err := testutil.InitDriver(t, "")
	require.NoError(t, err, "initialize test database")

	writer := herodot.NewJSONWriter(nil)

	provider := testutil.NewTestProviderWithSigningKeys(t)

	log := logger.NewLogger("warn", "json")

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

func TestInitializeServerDependencies(t *testing.T) {
	// initializeServerDependencies writes to prometheus.DefaultRegisterer, so
	// the success sub-test cannot run in parallel with other tests that touch
	// the default registry. The error sub-tests fail before reaching
	// registration, so they are safe to parallelize.

	t.Run("unsupported DB scheme returns error", func(t *testing.T) {
		// Use a non-empty but unsupported DSN scheme. An empty DSN fails config
		// schema validation (minLength >= 1) before reaching initializeServerDependencies,
		// so we test the driver-init error path instead.
		t.Parallel()
		provider := testutil.NewTestProvider(t, configx.WithValues(map[string]any{
			talosconfig.KeyDBDSN.String(): "unsupported://localhost/db",
		}))

		deps, cleanup, err := initializeServerDependencies(t.Context(), provider, boot.ModeAllInOne)
		t.Cleanup(cleanup)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "initialize database")
		assert.Nil(t, deps)
	})

	t.Run("valid config returns non-nil deps and working cleanup", func(t *testing.T) {
		// Uses prometheus.DefaultRegisterer — not safe to run in parallel with
		// other tests that register to the default registry.
		//
		// initializeServerDependencies calls dbDriver.Initialize() which requires
		// the migrations to have already run (it needs the networks table). We
		// pre-migrate the database by passing an explicit DSN to InitDriver, then
		// close that driver and hand the same path to initializeServerDependencies
		// via the config provider.
		dbPath := filepath.Join(t.TempDir(), "talos.db")
		dsn := "sqlite://" + dbPath + "?mode=rwc"

		preDriver, err := testutil.InitDriver(t, dsn)
		require.NoError(t, err, "pre-migrate database")
		// Close so initializeServerDependencies can open its own connection.
		require.NoError(t, preDriver.Close())

		provider := testutil.NewTestProvider(t, configx.WithValues(map[string]any{
			talosconfig.KeyDBDSN.String(): dsn,
		}))

		deps, cleanup, err := initializeServerDependencies(t.Context(), provider, boot.ModeAllInOne)
		require.NoError(t, err)
		require.NotNil(t, deps)
		// cleanup must not panic.
		t.Cleanup(cleanup)

		assert.NotNil(t, deps.Log, "Log must be set")
		assert.NotNil(t, deps.Writer, "Writer must be set")
		assert.NotNil(t, deps.Factory, "Factory must be set")
		assert.NotNil(t, deps.HealthChecker, "HealthChecker must be set")
	})
}

func TestCreateHTTPServerWithMiddleware(t *testing.T) {
	t.Parallel()

	// deps is read-only: createHTTPServerWithMiddleware reads it but never mutates it,
	// so sharing across parallel subtests is safe.
	deps := newTestDeps(t, boot.ModeAllInOne)

	t.Run("creates server with correct timeouts", func(t *testing.T) {
		t.Parallel()
		srv, err := createHTTPServerWithMiddleware(t.Context(), "127.0.0.1:0", deps)
		require.NoError(t, err)
		require.NotNil(t, srv)

		assert.Equal(t, 15*time.Second, srv.ReadTimeout)
		assert.Equal(t, 5*time.Second, srv.ReadHeaderTimeout)
		assert.Equal(t, 15*time.Second, srv.WriteTimeout)
		assert.Equal(t, 60*time.Second, srv.IdleTimeout)
	})

	t.Run("sets non-nil handler", func(t *testing.T) {
		t.Parallel()
		srv, err := createHTTPServerWithMiddleware(t.Context(), "127.0.0.1:0", deps)
		require.NoError(t, err)
		require.NotNil(t, srv)

		assert.NotNil(t, srv.Handler, "Handler must be set")
	})

	t.Run("sets addr to provided value", func(t *testing.T) {
		t.Parallel()
		const addr = "127.0.0.1:0"
		srv, err := createHTTPServerWithMiddleware(t.Context(), addr, deps)
		require.NoError(t, err)
		require.NotNil(t, srv)

		assert.Equal(t, addr, srv.Addr)
	})

	t.Run("handler serves health endpoint", func(t *testing.T) {
		t.Parallel()
		srv, err := createHTTPServerWithMiddleware(t.Context(), "127.0.0.1:0", deps)
		require.NoError(t, err)
		require.NotNil(t, srv)

		ts := httptest.NewServer(srv.Handler)
		t.Cleanup(ts.Close)

		req, err := http.NewRequestWithContext(t.Context(), http.MethodGet, ts.URL+"/health/alive", nil)
		require.NoError(t, err)
		resp, err := testutil.NewTestHTTPClient(t).Do(req)
		require.NoError(t, err)
		t.Cleanup(func() { _ = resp.Body.Close() })
		assert.Equal(t, http.StatusOK, resp.StatusCode)
	})
}
