package verifier

import (
	"context"
	"crypto/ed25519"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/cockroachdb/errors"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/ory/herodot"
	"github.com/ory/x/configx"
	"github.com/ory/x/httpx"

	"github.com/ory/talos/internal/cache"
	"github.com/ory/talos/internal/cachecontrol"
	"github.com/ory/talos/internal/clientip"
	"github.com/ory/talos/internal/config"
	"github.com/ory/talos/internal/contextx"
	"github.com/ory/talos/internal/crypto"
	"github.com/ory/talos/internal/crypto/token"

	"github.com/prometheus/client_golang/prometheus"
	promtestutil "github.com/prometheus/client_golang/prometheus/testutil"

	"github.com/ory/talos/internal/errdef"
	"github.com/ory/talos/internal/lastused"
	db "github.com/ory/talos/internal/persistence/sqlc/generated"
	"github.com/ory/talos/internal/persistence/sqlite"

	"github.com/ory/talos/internal/metrics"
	"github.com/ory/talos/internal/persistence/sqlutil"
	persistencetypes "github.com/ory/talos/internal/persistence/types"
	"github.com/ory/talos/internal/testutil"
	talosv2alpha1 "github.com/ory/talos/pkg/api/talos/v2alpha1"
)

// scopesToJSON is a helper that converts []string to json.RawMessage for tests
func scopesToJSON(scopes []string) json.RawMessage {
	// sqlutil.MarshalScopes works on persistence types; this helper works on raw []string for tests.
	if len(scopes) == 0 {
		return json.RawMessage(`[]`)
	}
	scopesJSON, _ := json.Marshal(scopes) //nolint:errchkjson // test helper, error impossible for string slices
	return scopesJSON
}

// newNoopCache creates a no-op cache for testing
func newNoopCache() cache.Cache[db.IssuedApiKey] {
	return cache.NewNoopCache[db.IssuedApiKey]()
}

// testVerifierEnv bundles all dependencies needed for verifier tests.
type testVerifierEnv struct {
	driver   *sqlite.Driver
	provider *config.Provider
	verifier *Verifier
}

// newTestVerifier creates a driver, provider, key service, and verifier with a noop cache.
// It registers cleanup automatically.
func newTestVerifier(ctx context.Context, t *testing.T) testVerifierEnv {
	t.Helper()
	return newTestVerifierWithCache(ctx, t, newNoopCache())
}

// newTestVerifierWithCache creates a full verifier test environment with the given cache.
// Caching is enabled (cache.enabled defaults to false) so cache-dependent tests
// exercise the cache paths.
func newTestVerifierWithCache(ctx context.Context, t *testing.T, c cache.Cache[db.IssuedApiKey]) testVerifierEnv {
	t.Helper()

	driver, err := testutil.InitDriver(t, "")
	require.NoError(t, err)
	t.Cleanup(func() { _ = driver.Close() })

	provider := testutil.NewTestProvider(t)
	require.NoError(t, provider.Set(ctx, config.KeyCacheEnabled, true))

	keyService, err := crypto.NewKeyService(ctx, provider, httpx.NewResilientClient(), crypto.NoopKeyServiceMetrics())
	require.NoError(t, err)

	tracker := lastused.New(ctx, driver, lastused.Config{
		QueueSize: 100, FlushSize: 100, FlushInterval: time.Hour, NumWorkers: 1,
	})
	t.Cleanup(tracker.Close)

	verifier := NewFromProvider(driver, provider, c, testutil.NewMockEmitter(), keyService, metrics.New(prometheus.NewRegistry()), tracker)

	return testVerifierEnv{
		driver:   driver,
		provider: provider,
		verifier: verifier,
	}
}

// configureProviderForAPIKeys sets the prefix and HMAC secret on the provider.
func configureProviderForAPIKeys(ctx context.Context, t *testing.T, provider *config.Provider, hmacSecret string) {
	t.Helper()
	require.NoError(t, provider.Set(ctx, config.KeyCredentialsAPIKeysPrefixCurrent, "talos"))
	require.NoError(t, provider.Set(ctx, config.KeySecretsHMACCurrent, hmacSecret))
}

// mustGenerateAndCreateAPIKey generates an API key, creates it in the DB, and returns the full key and key ID.
func mustGenerateAndCreateAPIKey(ctx context.Context, t *testing.T, driver *sqlite.Driver, hmacSecret, name, actorID string, scopes []string) (fullKey, keyID string) {
	t.Helper()

	const prefix = "talos"
	fullKey, keyID, err := crypto.GenerateAPIKey(ctx, prefix, []byte(hmacSecret))
	require.NoError(t, err)

	_, err = driver.CreateIssuedAPIKey(ctx, persistencetypes.CreateIssuedAPIKeyParams{
		KeyID:       keyID,
		Name:        name,
		TokenPrefix: prefix,
		ActorID:     actorID,
		Scopes:      scopesToJSON(scopes),
		Metadata:    json.RawMessage(`{}`),
	})
	require.NoError(t, err)

	return fullKey, keyID
}

// mustCreateImportedKey creates an imported API key in the DB and returns its key ID.
func mustCreateImportedKey(ctx context.Context, t *testing.T, driver *sqlite.Driver, credential, name string, scopes json.RawMessage) string {
	t.Helper()

	importedKeyID := crypto.HashImportedAPIKey(credential, contextx.NetworkIDFromContext(ctx).String())

	_, err := driver.CreateImportedAPIKey(ctx, persistencetypes.CreateImportedKeyParams{
		KeyID:    importedKeyID,
		Name:     name,
		ActorID:  "owner-imported",
		Scopes:   scopes,
		Metadata: json.RawMessage(`{}`),
		Status:   int32(talosv2alpha1.KeyStatus_KEY_STATUS_ACTIVE),
	})
	require.NoError(t, err)

	return importedKeyID
}

// testCache is a simple in-memory cache for testing. It keys values by key_id
// with NID-based isolation, mirroring the production memory/redis backends.
type testCache struct {
	data map[string]db.IssuedApiKey
}

func newTestCache() *testCache {
	return &testCache{
		data: make(map[string]db.IssuedApiKey),
	}
}

func (c *testCache) Get(ctx context.Context, key string) (db.IssuedApiKey, bool, error) {
	// Build full key with NID prefix (simulating real cache behavior)
	val, ok := c.data[c.buildKey(ctx, key)]
	return val, ok, nil
}

func (c *testCache) Set(ctx context.Context, key string, value db.IssuedApiKey, _ time.Duration) error {
	c.data[c.buildKey(ctx, key)] = value
	return nil
}

func (c *testCache) Delete(ctx context.Context, key string) error {
	delete(c.data, c.buildKey(ctx, key))
	return nil
}

func (c *testCache) Clear(_ context.Context) error {
	c.data = make(map[string]db.IssuedApiKey)
	return nil
}

func (c *testCache) Close() error {
	return nil
}

func (c *testCache) Metrics() cache.Metrics {
	return nil
}

func (c *testCache) Wait() {}

// buildKey simulates the real cache's NID-based key isolation
func (c *testCache) buildKey(ctx context.Context, key string) string {
	return contextx.NetworkIDFromContext(ctx).String() + ":" + key
}

func newVerifierTestProvider(t *testing.T, secret string) *config.Provider {
	t.Helper()
	return testutil.NewTestProvider(t, configx.WithValues(map[string]any{
		config.KeySecretsHMACCurrent.String():                            secret,
		config.KeyCredentialsAPIKeysPrefixCurrent.String():               "talos",
		config.KeyCredentialsIssuer.String():                             "talos-service",
		config.KeyCredentialsDerivedTokensMacaroonPrefixCurrent.String(): "mc",
		config.KeyCacheTTL.String():                                      "5m",
	}))
}

func newDeterministicEdDSAKeyService(t *testing.T) (*crypto.KeyService, ed25519.PrivateKey, string) {
	t.Helper()

	seed := [32]byte{
		1, 2, 3, 4, 5, 6, 7, 8,
		9, 10, 11, 12, 13, 14, 15, 16,
		17, 18, 19, 20, 21, 22, 23, 24,
		25, 26, 27, 28, 29, 30, 31, 32,
	}
	privateKey := ed25519.NewKeyFromSeed(seed[:])
	keyID := "test-signing-key-1"

	jwksURL := testutil.TestSigningKeyJWKSURLWithKey(t, privateKey, keyID)
	provider := testutil.NewTestProvider(t, configx.WithValues(map[string]any{
		config.KeySecretsHMACCurrent.String():                            "test-secret-123-must-be-32chars!",
		config.KeyCredentialsAPIKeysPrefixCurrent.String():               "talos",
		config.KeyCredentialsIssuer.String():                             "talos-service",
		config.KeyCredentialsDerivedTokensMacaroonPrefixCurrent.String(): "mc",
		config.KeyCacheTTL.String():                                      "5m",
		config.KeyCredentialsDerivedTokensJWTSigningKeysURLs.String():    []string{jwksURL},
	}))

	keyService, err := crypto.NewKeyService(t.Context(), provider, httpx.NewResilientClient(), crypto.NoopKeyServiceMetrics())
	require.NoError(t, err)

	return keyService, privateKey, keyID
}

// TestValidateKeyStatusAndExpiration tests the validateKeyStatusAndExpiration helper
func TestValidateKeyStatusAndExpiration(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name      string
		status    int32
		expiresAt *time.Time
		wantErr   error
	}{
		{
			name:      "active and not expired",
			status:    int32(talosv2alpha1.KeyStatus_KEY_STATUS_ACTIVE),
			expiresAt: new(time.Now().Add(1 * time.Hour)),
			wantErr:   nil,
		},
		{
			name:      "active with nil expiry",
			status:    int32(talosv2alpha1.KeyStatus_KEY_STATUS_ACTIVE),
			expiresAt: nil,
			wantErr:   nil,
		},
		{
			name:      "revoked key",
			status:    int32(talosv2alpha1.KeyStatus_KEY_STATUS_REVOKED),
			expiresAt: new(time.Now().Add(1 * time.Hour)),
			wantErr:   errdef.ErrAPIKeyRevoked(),
		},
		{
			name:      "active but expired",
			status:    int32(talosv2alpha1.KeyStatus_KEY_STATUS_ACTIVE),
			expiresAt: new(time.Now().Add(-1 * time.Hour)),
			wantErr:   errdef.ErrAPIKeyExpired(),
		},
		{
			name:      "unknown status code",
			status:    99,
			expiresAt: nil,
			wantErr:   errdef.ErrAPIKeyNotFound(),
		},
		{
			name:      "revoked and expired",
			status:    int32(talosv2alpha1.KeyStatus_KEY_STATUS_REVOKED),
			expiresAt: new(time.Now().Add(-1 * time.Hour)),
			wantErr:   errdef.ErrAPIKeyRevoked(), // Status checked first
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			err := validateKeyStatusAndExpiration(tt.status, tt.expiresAt)
			if tt.wantErr == nil {
				assert.NoError(t, err)
			} else {
				require.Error(t, err)
				assert.True(t, errors.Is(err, tt.wantErr), "expected %v, got %v", tt.wantErr, err)
			}
		})
	}
}

// TestGetHMACSecret tests HMAC secret retrieval
func TestGetHMACSecret(t *testing.T) {
	t.Parallel()

	ctx := t.Context()

	t.Run("returns hmac secrets when configured", func(t *testing.T) {
		t.Parallel()

		provider := newVerifierTestProvider(t, "test-secret-123-must-be-32chars!")
		verifier := &Verifier{
			provider: provider,
		}

		secrets, err := verifier.getHMACSecrets(ctx)
		require.NoError(t, err)
		assert.Equal(t, [][]byte{[]byte("test-secret-123-must-be-32chars!")}, secrets)
	})
}

// TestGetCacheTTL tests cache TTL calculation logic
func TestGetCacheTTL(t *testing.T) {
	t.Parallel()

	ctx := t.Context()

	t.Run("returns config TTL when key has no expiry", func(t *testing.T) {
		t.Parallel()

		verifier := &Verifier{
			provider: newVerifierTestProvider(t, "test-secret-for-test-must-32chars!!"),
		}

		ttl, cacheable := verifier.getCacheTTL(ctx, nil)
		assert.True(t, cacheable)
		assert.Equal(t, 5*time.Minute, ttl)
	})

	t.Run("marks already expired key as not cacheable", func(t *testing.T) {
		t.Parallel()

		verifier := &Verifier{
			provider: newVerifierTestProvider(t, "test-secret-for-test-must-32chars!!"),
		}

		expired := time.Now().Add(-1 * time.Hour)
		ttl, cacheable := verifier.getCacheTTL(ctx, &expired)
		assert.False(t, cacheable)
		assert.Equal(t, time.Duration(0), ttl)
	})

	t.Run("marks key expiring very soon as not cacheable", func(t *testing.T) {
		t.Parallel()

		verifier := &Verifier{
			provider: newVerifierTestProvider(t, "test-secret-for-test-must-32chars!!"),
		}

		expiresSoon := time.Now().Add(500 * time.Millisecond)
		ttl, cacheable := verifier.getCacheTTL(ctx, &expiresSoon)
		assert.False(t, cacheable)
		assert.Equal(t, time.Duration(0), ttl)
	})

	t.Run("returns time until expiry when less than config TTL", func(t *testing.T) {
		t.Parallel()

		verifier := &Verifier{
			provider: newVerifierTestProvider(t, "test-secret-for-test-must-32chars!!"),
		}

		expiresIn2Min := time.Now().Add(2 * time.Minute)
		ttl, cacheable := verifier.getCacheTTL(ctx, &expiresIn2Min)
		assert.True(t, cacheable)
		// Should be close to 2 minutes (within a few seconds tolerance)
		assert.Greater(t, ttl, 1*time.Minute+50*time.Second)
		assert.Less(t, ttl, 2*time.Minute+10*time.Second)
	})

	t.Run("returns config TTL when expiry is far in future", func(t *testing.T) {
		t.Parallel()

		verifier := &Verifier{
			provider: newVerifierTestProvider(t, "test-secret-for-test-must-32chars!!"),
		}

		expiresIn1Hour := time.Now().Add(1 * time.Hour)
		ttl, cacheable := verifier.getCacheTTL(ctx, &expiresIn1Hour)
		assert.True(t, cacheable)
		assert.Equal(t, 5*time.Minute, ttl)
	})
}

// TestNewVerifierFromProvider tests verifier construction
func TestNewVerifierFromProvider(t *testing.T) {
	t.Parallel()

	ctx := t.Context()

	t.Run("creates verifier with all dependencies", func(t *testing.T) {
		t.Parallel()

		driver, err := testutil.InitDriver(t, "")
		require.NoError(t, err)
		t.Cleanup(func() { _ = driver.Close() })

		provider := testutil.NewTestProvider(t)

		emitter := testutil.NewMockEmitter()
		keyService, err := crypto.NewKeyService(ctx, provider, httpx.NewResilientClient(), crypto.NoopKeyServiceMetrics())
		require.NoError(t, err)

		tracker := lastused.New(ctx, driver, lastused.Config{
			QueueSize: 100, FlushSize: 100, FlushInterval: time.Hour, NumWorkers: 1,
		})
		t.Cleanup(tracker.Close)

		verifier := NewFromProvider(driver, provider, newNoopCache(), emitter, keyService, metrics.New(prometheus.NewRegistry()), tracker)
		require.NotNil(t, verifier)
		assert.NotNil(t, verifier.driver)
		assert.NotNil(t, verifier.provider)
		assert.NotNil(t, verifier.cache)
		assert.NotNil(t, verifier.keyService)
		assert.NotNil(t, verifier.emitter)
	})

	t.Run("creates verifier for test mode", func(t *testing.T) {
		t.Parallel()

		driver, err := testutil.InitDriver(t, "")
		require.NoError(t, err)
		t.Cleanup(func() { _ = driver.Close() })

		baseProvider := testutil.NewTestProvider(t)

		keyService, err := crypto.NewKeyService(ctx, baseProvider, httpx.NewResilientClient(), crypto.NoopKeyServiceMetrics())
		require.NoError(t, err)

		emitter := testutil.NewMockEmitter()

		testProvider := newVerifierTestProvider(t, "test-hmac-secret-for-testing-32c")

		tracker := lastused.New(ctx, driver, lastused.Config{
			QueueSize: 100, FlushSize: 100, FlushInterval: time.Hour, NumWorkers: 1,
		})
		t.Cleanup(tracker.Close)

		verifier := NewFromProvider(driver, testProvider, newNoopCache(), emitter, keyService, metrics.New(prometheus.NewRegistry()), tracker)
		require.NotNil(t, verifier)
		assert.NotNil(t, verifier.provider)
	})
}

// TestVerifyAPIKey_EmptyCredential tests empty credential handling
func TestVerifyAPIKey_EmptyCredential(t *testing.T) {
	t.Parallel()

	ctx := t.Context()
	env := newTestVerifier(ctx, t)

	_, _, verifyErr := env.verifier.VerifyAPIKey(ctx, "")
	require.Error(t, verifyErr)
	assert.True(t, errors.Is(verifyErr, errdef.ErrCredentialRequired()))
}

// TestVerifyAPIKey_ValidKey tests verification of a valid active API key
func TestVerifyAPIKey_ValidKey(t *testing.T) {
	t.Parallel()

	ctx := t.Context()
	const hmacSecret = "test-hmac-secret-for-api-key-checksum-validation-32chars"
	env := newTestVerifier(ctx, t)
	configureProviderForAPIKeys(ctx, t, env.provider, hmacSecret)

	fullKey, keyID := mustGenerateAndCreateAPIKey(ctx, t, env.driver, hmacSecret, "valid-key", "owner-1", []string{"read"})

	result, _, err := env.verifier.VerifyAPIKey(ctx, fullKey)
	require.NoError(t, err)
	require.NotNil(t, result)
	assert.Equal(t, keyID, result.KeyID)
	assert.Equal(t, "owner-1", sqlutil.Deref(result.ActorID))
}

// TestVerifyAPIKey_InvalidFormat tests malformed credential
func TestVerifyAPIKey_InvalidFormat(t *testing.T) {
	t.Parallel()

	ctx := t.Context()
	env := newTestVerifier(ctx, t)

	tests := []struct {
		name       string
		credential string
	}{
		{
			name:       "random string",
			credential: "not-a-valid-key",
		},
		{
			name:       "too short",
			credential: "short",
		},
		{
			name:       "invalid characters",
			credential: "ory_at1_!!!invalid!!!",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Do NOT call t.Parallel() here - parent test has deferred driver.Close()
			// which would be called before subtests complete, causing "database is closed" errors

			_, _, verifyErr := env.verifier.VerifyAPIKey(ctx, tt.credential)
			require.Error(t, verifyErr)
			// Should fail at parse, checksum, or lookup stage
			assert.True(t,
				errors.Is(verifyErr, errdef.ErrInvalidAPIKeyFormat()) ||
					errors.Is(verifyErr, errdef.ErrAPIKeyNotFound()) ||
					errors.Is(verifyErr, errdef.ErrUnknownCredential()),
				"unexpected error: %v", verifyErr)
		})
	}
}

// TestVerifyJWT tests JWT token verification
// Note: Full end-to-end JWT tests are in test/api/
func TestVerifyJWT(t *testing.T) {
	t.Parallel()

	ctx := t.Context()

	t.Run("validates JWT format - invalid format", func(t *testing.T) {
		t.Parallel()

		env := newTestVerifier(ctx, t)

		// Invalid JWT format
		_, _, verifyErr := env.verifier.VerifyAPIKey(ctx, "invalid.jwt")
		require.Error(t, verifyErr)
	})

	// Note: Minting and verifying JWT tokens end-to-end is covered in test/api/
}

func reasonFromHerodotError(t *testing.T, err error) string {
	t.Helper()

	var herodotErr *herodot.DefaultError
	require.ErrorAs(t, err, &herodotErr)
	return herodotErr.ReasonField
}

// TestVerifyAPIKey_CacheDisabled verifies that cache.enabled=false bypasses the
// cache entirely: no reads, no writes, and the SKIP status is reported. The
// flag is read per request, so toggling it takes effect immediately.
func TestVerifyAPIKey_CacheDisabled(t *testing.T) {
	t.Parallel()

	ctx := t.Context()
	const hmacSecret = "test-hmac-secret-for-disabled-test-32chars"
	testCacheInst := newTestCache()
	env := newTestVerifierWithCache(ctx, t, testCacheInst)
	configureProviderForAPIKeys(ctx, t, env.provider, hmacSecret)
	require.NoError(t, env.provider.Set(ctx, config.KeyCacheEnabled, false))

	fullKey, keyID := mustGenerateAndCreateAPIKey(ctx, t, env.driver, hmacSecret, "test-key", "owner-1", []string{"read"})

	// First verification: DB lookup succeeds, nothing is written to the cache,
	// and the SKIP status is reported.
	result1, status1, err := env.verifier.VerifyAPIKey(ctx, fullKey)
	require.NoError(t, err)
	require.NotNil(t, result1)
	assert.Equal(t, keyID, result1.KeyID)
	assert.Equal(t, cachecontrol.CacheSkip, status1)
	assert.Empty(t, testCacheInst.data, "disabled cache must not be written to")

	// Seed a tampered cache entry under the key_id (the production cache key):
	// a disabled cache must never be read, so the verification result must
	// come from the DB.
	tampered := *result1
	tampered.Name = "from-cache"
	require.NoError(t, testCacheInst.Set(ctx, keyID, tampered, 5*time.Minute))

	result2, status2, err := env.verifier.VerifyAPIKey(ctx, fullKey)
	require.NoError(t, err)
	assert.Equal(t, cachecontrol.CacheSkip, status2)
	assert.NotEqual(t, "from-cache", result2.Name, "disabled cache must not be read")

	// Revocation takes effect immediately: no stale cached entry can answer.
	require.NoError(t, env.driver.RevokeIssuedAPIKey(ctx, persistencetypes.RevokeIssuedAPIKeyParams{
		KeyID:  keyID,
		Reason: int32(talosv2alpha1.RevocationReason_REVOCATION_REASON_KEY_COMPROMISE),
	}))
	_, status3, err := env.verifier.VerifyAPIKey(ctx, fullKey)
	require.Error(t, err)
	assert.True(t, errors.Is(err, errdef.ErrAPIKeyRevoked()))
	assert.Equal(t, cachecontrol.CacheSkip, status3)

	// Re-enabling restores normal cache behavior on the next request: the
	// seeded (still-active) entry is served again, demonstrating the
	// eventual-consistency trade-off of enabled caching.
	require.NoError(t, env.provider.Set(ctx, config.KeyCacheEnabled, true))
	result4, status4, err := env.verifier.VerifyAPIKey(ctx, fullKey)
	require.NoError(t, err)
	assert.Equal(t, cachecontrol.CacheHit, status4)
	assert.Equal(t, "from-cache", result4.Name, "seeded entry is read once caching is enabled again")
}

// TestVerifyAPIKey_CacheStatusEnabled verifies MISS then HIT statuses when
// caching is enabled.
func TestVerifyAPIKey_CacheStatusEnabled(t *testing.T) {
	t.Parallel()

	ctx := t.Context()
	const hmacSecret = "test-hmac-secret-for-status-test-32chars1"
	env := newTestVerifierWithCache(ctx, t, newTestCache())
	configureProviderForAPIKeys(ctx, t, env.provider, hmacSecret)

	fullKey, _ := mustGenerateAndCreateAPIKey(ctx, t, env.driver, hmacSecret, "test-key", "owner-1", []string{"read"})

	_, status1, err := env.verifier.VerifyAPIKey(ctx, fullKey)
	require.NoError(t, err)
	assert.Equal(t, cachecontrol.CacheMiss, status1)

	_, status2, err := env.verifier.VerifyAPIKey(ctx, fullKey)
	require.NoError(t, err)
	assert.Equal(t, cachecontrol.CacheHit, status2)
}

// TestVerifyAPIKey_CacheKeyCollisionPrevention verifies that different credentials
// are cached separately and don't collide.
// Note: Multi-tenant NID-based isolation is tested in commercial edition.
func TestVerifyAPIKey_CacheKeyCollisionPrevention(t *testing.T) {
	t.Parallel()

	ctx := t.Context()
	const hmacSecret = "test-hmac-secret-for-collision-test-32chars"
	env := newTestVerifierWithCache(ctx, t, newTestCache())
	configureProviderForAPIKeys(ctx, t, env.provider, hmacSecret)

	fullKey1, keyID1 := mustGenerateAndCreateAPIKey(ctx, t, env.driver, hmacSecret, "key-1", "owner-1", []string{"read"})
	fullKey2, keyID2 := mustGenerateAndCreateAPIKey(ctx, t, env.driver, hmacSecret, "key-2", "owner-2", []string{"write"})

	// Verify key1 (cache miss)
	result1, _, err := env.verifier.VerifyAPIKey(ctx, fullKey1)
	require.NoError(t, err)
	require.NotNil(t, result1)
	assert.Equal(t, "owner-1", sqlutil.Deref(result1.ActorID))
	assert.Equal(t, keyID1, result1.KeyID)

	// Verify key1 again (cache hit)
	result1Again, _, err := env.verifier.VerifyAPIKey(ctx, fullKey1)
	require.NoError(t, err)
	require.NotNil(t, result1Again)
	assert.Equal(t, "owner-1", sqlutil.Deref(result1Again.ActorID))

	// Verify key2 (separate cache entry - different credential)
	result2, _, err := env.verifier.VerifyAPIKey(ctx, fullKey2)
	require.NoError(t, err)
	require.NotNil(t, result2)
	assert.Equal(t, "owner-2", sqlutil.Deref(result2.ActorID))
	assert.Equal(t, keyID2, result2.KeyID)

	// Verify the cache returns correct results for each credential
	assert.Equal(t, "owner-1", sqlutil.Deref(result1.ActorID), "key1 should return owner-1")
	assert.Equal(t, "owner-2", sqlutil.Deref(result2.ActorID), "key2 should return owner-2")
}

// TestVerifyAPIKey_CacheInvalidationRevoked verifies that revoked cached keys
// are properly invalidated and refreshed from DB.
func TestVerifyAPIKey_CacheInvalidationRevoked(t *testing.T) {
	t.Parallel()

	ctx := t.Context()
	const hmacSecret = "test-hmac-secret-for-revoked-test-32chars"
	testCacheInst := newTestCache()
	env := newTestVerifierWithCache(ctx, t, testCacheInst)
	configureProviderForAPIKeys(ctx, t, env.provider, hmacSecret)

	fullKey, keyID := mustGenerateAndCreateAPIKey(ctx, t, env.driver, hmacSecret, "test-key", "owner-1", []string{"read"})

	// First verification - cache miss, DB lookup, stores in cache
	result1, _, err := env.verifier.VerifyAPIKey(ctx, fullKey)
	require.NoError(t, err)
	require.NotNil(t, result1)
	assert.Equal(t, int32(talosv2alpha1.KeyStatus_KEY_STATUS_ACTIVE), result1.Status)

	// Second verification - cache hit
	result2, _, err := env.verifier.VerifyAPIKey(ctx, fullKey)
	require.NoError(t, err)
	require.NotNil(t, result2)
	assert.Equal(t, int32(talosv2alpha1.KeyStatus_KEY_STATUS_ACTIVE), result2.Status)

	// Revoke the key in DB
	err = env.driver.RevokeIssuedAPIKey(ctx, persistencetypes.RevokeIssuedAPIKeyParams{
		KeyID:  keyID,
		Reason: int32(talosv2alpha1.RevocationReason_REVOCATION_REASON_KEY_COMPROMISE),
	})
	require.NoError(t, err)

	// Manually invalidate cache to simulate cache expiry
	err = testCacheInst.Delete(ctx, keyID)
	require.NoError(t, err)

	// Third verification - cache miss, DB lookup returns revoked key
	_, _, err = env.verifier.VerifyAPIKey(ctx, fullKey)
	require.Error(t, err)
	assert.True(t, errors.Is(err, errdef.ErrAPIKeyRevoked()))
}

// TestVerifyAPIKey_CacheHitRequiresValidChecksum verifies that an issued key's
// key_id (the public part of the credential) is not enough to be served from
// the cache: a credential with a valid key_id but a wrong HMAC checksum must
// fall through to the DB path and fail, even after the real key was cached.
// This is the invariant that makes keying the cache by key_id safe.
func TestVerifyAPIKey_CacheHitRequiresValidChecksum(t *testing.T) {
	t.Parallel()

	ctx := t.Context()
	const hmacSecret = "test-hmac-secret-for-checksum-gate-32char"
	testCacheInst := newTestCache()
	env := newTestVerifierWithCache(ctx, t, testCacheInst)
	configureProviderForAPIKeys(ctx, t, env.provider, hmacSecret)

	fullKey, keyID := mustGenerateAndCreateAPIKey(ctx, t, env.driver, hmacSecret, "checksum-gate", "owner-1", []string{"read"})

	// Verify the real key to populate the cache, keyed by key_id.
	_, _, err := env.verifier.VerifyAPIKey(ctx, fullKey)
	require.NoError(t, err)

	_, found, err := testCacheInst.Get(ctx, keyID)
	require.NoError(t, err)
	require.True(t, found, "real key must be cached under its key_id")

	// Forge a credential with the same identifier (hence the same key_id and
	// cache key) but a different checksum by flipping the last character.
	repl := byte('A')
	if fullKey[len(fullKey)-1] == 'A' {
		repl = 'B'
	}
	forged := fullKey[:len(fullKey)-1] + string(repl)
	require.NotEqual(t, fullKey, forged)

	// The forged credential must not be served from cache: the checksum gate
	// fails, so it falls through to the DB path and returns NOT_FOUND.
	_, _, err = env.verifier.VerifyAPIKey(ctx, forged)
	require.Error(t, err)
	assert.True(t, errors.Is(err, errdef.ErrAPIKeyNotFound()), "forged checksum must not be served from cache")
}

// TestVerifyAPIKey_LookupUsesChecksumVerifiedKeyID checks if the
// UUID used for the DB and cache lookup of an issued key must be
// the checksum-verified key_id
// (crypto.VerifyAPIKeyChecksum) — the same value the key is authenticated
// against — not an independently routing-decoded UUID.
func TestVerifyAPIKey_LookupUsesChecksumVerifiedKeyID(t *testing.T) {
	t.Parallel()

	ctx := t.Context()
	const hmacSecret = "test-hmac-secret-for-lookup-uuid-32chars1"
	testCacheInst := newTestCache()
	env := newTestVerifierWithCache(ctx, t, testCacheInst)
	configureProviderForAPIKeys(ctx, t, env.provider, hmacSecret)

	fullKey, keyID := mustGenerateAndCreateAPIKey(ctx, t, env.driver, hmacSecret, "lookup-uuid", "owner-1", []string{"read"})

	// The checksum-verified key_id is the authenticated lookup key.
	components, err := crypto.VerifyAPIKeyChecksum(fullKey, [][]byte{[]byte(hmacSecret)})
	require.NoError(t, err)
	require.Equal(t, keyID, components.KeyID)

	// A valid key resolves and returns the checksum-verified key_id.
	result, _, err := env.verifier.VerifyAPIKey(ctx, fullKey)
	require.NoError(t, err)
	require.NotNil(t, result)
	assert.Equal(t, components.KeyID, result.KeyID)

	// The key is cached under exactly that checksum-verified key_id, so a
	// self-revoke or admin invalidation keyed by key_id hits the same entry.
	cached, found, err := testCacheInst.Get(ctx, components.KeyID)
	require.NoError(t, err)
	require.True(t, found, "issued key must be cached under its checksum-verified key_id")
	assert.Equal(t, components.KeyID, cached.KeyID)
}

// Cache hit/miss verification: tests below use a real cache and verify behavior
// indirectly (e.g., revoking a cached key and re-verifying). Direct hit/miss counting
// is done via the dedicated prometheus.NewRegistry() approach in metrics unit tests.

// TestVerifyAPIKey_CacheInvalidationExpired verifies that expired cached keys
// are properly handled and refreshed from DB.
func TestVerifyAPIKey_CacheInvalidationExpired(t *testing.T) {
	t.Parallel()

	ctx := t.Context()
	const (
		prefix     = "talos"
		hmacSecret = "test-hmac-secret-for-expired-test-32chars"
	)
	testCacheInst := newTestCache()
	env := newTestVerifierWithCache(ctx, t, testCacheInst)
	configureProviderForAPIKeys(ctx, t, env.provider, hmacSecret)

	// Generate and create a key with short expiration
	fullKey, keyID, err := crypto.GenerateAPIKey(ctx, prefix, []byte(hmacSecret))
	require.NoError(t, err)

	expiresAt := time.Now().UTC().Add(10 * time.Second)
	_, err = env.driver.CreateIssuedAPIKey(ctx, persistencetypes.CreateIssuedAPIKeyParams{
		KeyID:       keyID,
		Name:        "test-key",
		TokenPrefix: prefix,
		ActorID:     "owner-1",
		Scopes:      scopesToJSON([]string{"read"}),
		Metadata:    json.RawMessage(`{}`),
		ExpiresAt:   &expiresAt,
	})
	require.NoError(t, err)

	// First verification - cache miss, DB lookup, stores in cache
	result1, _, err := env.verifier.VerifyAPIKey(ctx, fullKey)
	require.NoError(t, err)
	require.NotNil(t, result1)

	// Manually create an expired cached entry
	expiredKey := *result1
	pastTime := time.Now().UTC().Add(-1 * time.Hour)
	expiredKey.ExpiresAt = &pastTime

	// Set the expired key in cache
	err = testCacheInst.Set(ctx, expiredKey.KeyID, expiredKey, 5*time.Minute)
	require.NoError(t, err)

	// Verification with expired cached key - isActiveAndNotExpired check should fail
	// causing cache to be treated as miss and DB lookup
	_, _, err = env.verifier.VerifyAPIKey(ctx, fullKey)
	// Should succeed because DB still has active key
	require.NoError(t, err)
}

// TestVerifyAPIKey_DynamicTTL verifies cache TTL calculation respects min(config_ttl, expiration_time).
func TestVerifyAPIKey_DynamicTTL(t *testing.T) {
	t.Parallel()

	ctx := t.Context()

	t.Run("key expires before config TTL", func(t *testing.T) {
		t.Parallel()

		provider := testutil.NewTestProvider(t, configx.WithValues(map[string]any{
			config.KeyCacheTTL.String(): "5m",
		}))

		verifier := &Verifier{provider: provider}

		expiresIn1Min := time.Now().UTC().Add(1 * time.Minute)
		ttl, cacheable := verifier.getCacheTTL(ctx, &expiresIn1Min)
		assert.True(t, cacheable)

		// Should be close to 1 minute
		assert.Greater(t, ttl, 50*time.Second)
		assert.Less(t, ttl, 70*time.Second)
	})

	t.Run("key expires after config TTL", func(t *testing.T) {
		t.Parallel()

		provider := testutil.NewTestProvider(t, configx.WithValues(map[string]any{
			config.KeyCacheTTL.String(): "5m",
		}))

		verifier := &Verifier{provider: provider}

		expiresIn10Min := time.Now().UTC().Add(10 * time.Minute)
		ttl, cacheable := verifier.getCacheTTL(ctx, &expiresIn10Min)
		assert.True(t, cacheable)

		// Should be config TTL (5 minutes)
		assert.Equal(t, 5*time.Minute, ttl)
	})

	t.Run("key has no expiration", func(t *testing.T) {
		t.Parallel()

		provider := testutil.NewTestProvider(t, configx.WithValues(map[string]any{
			config.KeyCacheTTL.String(): "5m",
		}))

		verifier := &Verifier{provider: provider}

		ttl, cacheable := verifier.getCacheTTL(ctx, nil)
		assert.True(t, cacheable)

		// Should be config TTL
		assert.Equal(t, 5*time.Minute, ttl)
	})

	t.Run("expired key is not cacheable", func(t *testing.T) {
		t.Parallel()

		provider := testutil.NewTestProvider(t, configx.WithValues(map[string]any{
			config.KeyCacheTTL.String(): "5m",
		}))

		verifier := &Verifier{provider: provider}

		expired := time.Now().UTC().Add(-1 * time.Hour)
		ttl, cacheable := verifier.getCacheTTL(ctx, &expired)
		assert.False(t, cacheable)

		// Should be 0 and skipped by the caller.
		assert.Equal(t, time.Duration(0), ttl)
	})
}

// TestVerifyAPIKey_AllCredentialTypesUseCaching verifies that all credential types
// (API keys, imported keys, JWT, macaroon) benefit from the unified caching.
func TestVerifyAPIKey_AllCredentialTypesUseCaching(t *testing.T) {
	t.Parallel()

	ctx := t.Context()
	driver, err := testutil.InitDriver(t, "")
	require.NoError(t, err)
	t.Cleanup(func() { _ = driver.Close() })

	provider := testutil.NewTestProvider(t)
	const (
		prefix     = "talos"
		hmacSecret = "test-hmac-secret-for-caching-test-32chars"
	)
	configureProviderForAPIKeys(ctx, t, provider, hmacSecret)
	require.NoError(t, provider.Set(ctx, config.KeyCacheEnabled, true))
	require.NoError(t, provider.Set(ctx, config.KeyCredentialsIssuer, "talos-service"))
	require.NoError(t, provider.Set(ctx, config.KeyCredentialsDerivedTokensMacaroonPrefixCurrent, "mc"))

	keyService, privateKey, signingKeyID := newDeterministicEdDSAKeyService(t)
	testCacheInst := newTestCache()

	tracker := lastused.New(ctx, driver, lastused.Config{
		QueueSize: 100, FlushSize: 100, FlushInterval: time.Hour, NumWorkers: 1,
	})
	t.Cleanup(tracker.Close)

	verifier := NewFromProvider(driver, provider, testCacheInst, testutil.NewMockEmitter(), keyService, metrics.New(prometheus.NewRegistry()), tracker)

	t.Run("native API key uses caching", func(t *testing.T) {
		// Do NOT use t.Parallel() - shares driver with other subtests

		fullKey, keyID := mustGenerateAndCreateAPIKey(ctx, t, driver, hmacSecret, "native-key", "owner-native", []string{"read"})

		// First call - cache miss
		result1, _, err := verifier.VerifyAPIKey(ctx, fullKey)
		require.NoError(t, err)
		assert.Equal(t, keyID, result1.KeyID)

		// Second call - cache hit (same result, faster)
		result2, _, err := verifier.VerifyAPIKey(ctx, fullKey)
		require.NoError(t, err)
		assert.Equal(t, keyID, result2.KeyID)
	})

	t.Run("imported API key uses caching", func(t *testing.T) {
		// Do NOT use t.Parallel() - shares driver with other subtests

		importedCred := "imported-credential-value-12345"
		importedKeyID := mustCreateImportedKey(ctx, t, driver, importedCred, "imported-key", json.RawMessage(`["write"]`))

		// First call - cache miss
		result1, _, err := verifier.VerifyAPIKey(ctx, importedCred)
		require.NoError(t, err)
		assert.Equal(t, importedKeyID, result1.KeyID)

		// Second call — same credential, cache populated from first call.
		result2, _, err := verifier.VerifyAPIKey(ctx, importedCred)
		require.NoError(t, err)
		assert.Equal(t, importedKeyID, result2.KeyID)
	})

	t.Run("session JWT uses caching", func(t *testing.T) {
		// Do NOT use t.Parallel() - shares driver with other subtests

		// Derived JWTs are verified statelessly (signature + claims), but the parent
		// key lookup can be cached. This test exercises the full verification path.

		parentKeyID := "44444444-4444-4444-4444-444444444444"
		_, err := driver.CreateIssuedAPIKey(ctx, persistencetypes.CreateIssuedAPIKeyParams{
			KeyID:       parentKeyID,
			Name:        "jwt-parent",
			TokenPrefix: prefix,
			ActorID:     "owner-jwt",
			Scopes:      scopesToJSON([]string{"read", "write"}),
			Metadata:    json.RawMessage(`{}`),
		})
		require.NoError(t, err)

		// Create JWT derived token
		now := time.Now().UTC()
		claims := token.NewClaims()
		claims.SetTokenID("jwt-session-token")
		claims.SetSubject(parentKeyID)
		claims.SetIssuer("talos-service")
		claims.SetIssuedAt(now)
		claims.SetExpiration(now.Add(time.Hour))
		claims.SetNotBefore(now)
		claims.SetTokenType(token.TokenTypeDerived)
		claims.SetKeyID(parentKeyID)
		claims.SetParentID(parentKeyID)
		claims.SetActorID("owner-jwt")
		claims.SetNetworkID(contextx.NetworkIDFromContext(ctx).String())
		claims.SetScopes([]string{"read"})
		claims.SetMetadata(map[string]any{})

		signer, err := token.NewJWTSigner(privateKey, signingKeyID)
		require.NoError(t, err)

		jwtToken, err := signer.Sign(ctx, claims)
		require.NoError(t, err)

		// First call - cache miss
		result1, _, err := verifier.VerifyAPIKey(ctx, jwtToken)
		require.NoError(t, err)
		assert.Equal(t, parentKeyID, result1.KeyID)

		// Second call - cache hit
		result2, _, err := verifier.VerifyAPIKey(ctx, jwtToken)
		require.NoError(t, err)
		assert.Equal(t, parentKeyID, result2.KeyID)
	})

	t.Run("session macaroon uses caching", func(t *testing.T) {
		// Do NOT use t.Parallel() - shares driver with other subtests

		// Derived macaroons are verified statelessly (signature + caveats), but the parent
		// key lookup can be cached. This test exercises the full verification path.

		parentKeyID := "55555555-5555-5555-5555-555555555555"
		_, err := driver.CreateIssuedAPIKey(ctx, persistencetypes.CreateIssuedAPIKeyParams{
			KeyID:       parentKeyID,
			Name:        "macaroon-parent",
			TokenPrefix: prefix,
			ActorID:     "owner-macaroon",
			Scopes:      scopesToJSON([]string{"admin"}),
			Metadata:    json.RawMessage(`{}`),
		})
		require.NoError(t, err)

		// Create macaroon derived token
		now := time.Now().UTC()
		claims := token.NewClaims()
		claims.SetTokenID("macaroon-session-token")
		claims.SetSubject(parentKeyID)
		claims.SetIssuer("talos-service")
		claims.SetIssuedAt(now)
		claims.SetExpiration(now.Add(time.Hour))
		claims.SetNotBefore(now)
		claims.SetTokenType(token.TokenTypeDerived)
		claims.SetKeyID(parentKeyID)
		claims.SetParentID(parentKeyID)
		claims.SetActorID("owner-macaroon")
		claims.SetNetworkID(contextx.NetworkIDFromContext(ctx).String())
		claims.SetScopes([]string{"admin"})
		claims.SetMetadata(map[string]any{})

		signer, err := token.NewMacaroonSigner([]byte(hmacSecret), "talos-service", "mc")
		require.NoError(t, err)

		macaroonToken, err := signer.Sign(ctx, claims)
		require.NoError(t, err)

		// First call - cache miss
		result1, _, err := verifier.VerifyAPIKey(ctx, macaroonToken)
		require.NoError(t, err)
		assert.Equal(t, parentKeyID, result1.KeyID)

		// Second call - cache hit
		result2, _, err := verifier.VerifyAPIKey(ctx, macaroonToken)
		require.NoError(t, err)
		assert.Equal(t, parentKeyID, result2.KeyID)
	})
}

// TestAuthenticateIssuedKey tests the authenticateIssuedKey helper function
func TestAuthenticateIssuedKey(t *testing.T) {
	t.Parallel()

	ctx := t.Context()

	t.Run("valid active key succeeds", func(t *testing.T) {
		t.Parallel()

		const hmacSecret = "test-hmac-secret-for-authenticate-test-32chars"
		env := newTestVerifier(ctx, t)
		configureProviderForAPIKeys(ctx, t, env.provider, hmacSecret)

		fullKey, keyID := mustGenerateAndCreateAPIKey(ctx, t, env.driver, hmacSecret, "test-key", "owner-1", []string{"read"})

		result, err := env.verifier.authenticateIssuedKey(ctx, fullKey)
		require.NoError(t, err)
		require.NotNil(t, result)
		assert.Equal(t, keyID, result.KeyID)
		assert.Equal(t, int32(talosv2alpha1.KeyStatus_KEY_STATUS_ACTIVE), result.Status)
	})

	t.Run("invalid format returns error", func(t *testing.T) {
		t.Parallel()

		env := newTestVerifier(ctx, t)

		_, err := env.verifier.authenticateIssuedKey(ctx, "invalid-format")
		require.Error(t, err)
		// Checksum failures are normalized to ErrAPIKeyNotFound to prevent callers
		// from distinguishing a malformed key from a non-existent one.
		assert.True(t, errors.Is(err, errdef.ErrAPIKeyNotFound()))
	})

	t.Run("invalid checksum returns error", func(t *testing.T) {
		t.Parallel()

		const (
			prefix     = "talos"
			hmacSecret = "test-hmac-secret-for-checksum-test-32chars"
		)
		env := newTestVerifier(ctx, t)
		configureProviderForAPIKeys(ctx, t, env.provider, hmacSecret)

		// Generate a key with one secret
		fullKey, _, err := crypto.GenerateAPIKey(ctx, prefix, []byte(hmacSecret))
		require.NoError(t, err)

		// But verify with a different secret (checksum mismatch)
		require.NoError(t, env.provider.Set(ctx, config.KeySecretsHMACCurrent, "different-secret-32chars-long-12"))

		_, err = env.verifier.authenticateIssuedKey(ctx, fullKey)
		require.Error(t, err)
		// Checksum failures are normalized to ErrAPIKeyNotFound to prevent callers
		// from distinguishing a wrong-project key (bad HMAC) from a non-existent one.
		assert.True(t, errors.Is(err, errdef.ErrAPIKeyNotFound()))
		assert.Contains(t, reasonFromHerodotError(t, err), "invalid API key checksum")
	})

	t.Run("revoked key returns error", func(t *testing.T) {
		t.Parallel()

		const hmacSecret = "test-hmac-secret-for-revoked-test-32chars"
		env := newTestVerifier(ctx, t)
		configureProviderForAPIKeys(ctx, t, env.provider, hmacSecret)

		fullKey, keyID := mustGenerateAndCreateAPIKey(ctx, t, env.driver, hmacSecret, "revoked-key", "owner-1", []string{"read"})

		// Revoke the key
		err := env.driver.RevokeIssuedAPIKey(ctx, persistencetypes.RevokeIssuedAPIKeyParams{
			KeyID:  keyID,
			Reason: int32(talosv2alpha1.RevocationReason_REVOCATION_REASON_KEY_COMPROMISE),
		})
		require.NoError(t, err)

		_, err = env.verifier.authenticateIssuedKey(ctx, fullKey)
		require.Error(t, err)
		assert.True(t, errors.Is(err, errdef.ErrAPIKeyRevoked()))
	})

	t.Run("expired key returns error", func(t *testing.T) {
		t.Parallel()

		const (
			prefix     = "talos"
			hmacSecret = "test-hmac-secret-for-expired-test-32chars"
		)
		env := newTestVerifier(ctx, t)
		configureProviderForAPIKeys(ctx, t, env.provider, hmacSecret)

		fullKey, keyID, err := crypto.GenerateAPIKey(ctx, prefix, []byte(hmacSecret))
		require.NoError(t, err)

		expiresAt := time.Now().UTC().Add(-1 * time.Hour)
		_, err = env.driver.CreateIssuedAPIKey(ctx, persistencetypes.CreateIssuedAPIKeyParams{
			KeyID:       keyID,
			Name:        "expired-key",
			TokenPrefix: prefix,
			ActorID:     "owner-1",
			Scopes:      scopesToJSON([]string{"read"}),
			Metadata:    json.RawMessage(`{}`),
			ExpiresAt:   &expiresAt,
		})
		require.NoError(t, err)

		_, err = env.verifier.authenticateIssuedKey(ctx, fullKey)
		require.Error(t, err)
		assert.True(t, errors.Is(err, errdef.ErrAPIKeyExpired()))
	})

	t.Run("key not found returns error", func(t *testing.T) {
		t.Parallel()

		const (
			prefix     = "talos"
			hmacSecret = "test-hmac-secret-for-notfound-test-32chars"
		)
		env := newTestVerifier(ctx, t)
		configureProviderForAPIKeys(ctx, t, env.provider, hmacSecret)

		// Generate a key but don't create it in DB
		fullKey, _, err := crypto.GenerateAPIKey(ctx, prefix, []byte(hmacSecret))
		require.NoError(t, err)

		_, err = env.verifier.authenticateIssuedKey(ctx, fullKey)
		require.Error(t, err)
		assert.True(t, errors.Is(err, errdef.ErrAPIKeyNotFound()))
	})
}

// TestAuthenticateImportedKey tests the authenticateImportedKey helper function
func TestAuthenticateImportedKey(t *testing.T) {
	t.Parallel()

	ctx := t.Context()

	t.Run("valid active imported key succeeds", func(t *testing.T) {
		t.Parallel()

		env := newTestVerifier(ctx, t)

		importedCred := "imported-credential-value-12345"
		importedKeyID := mustCreateImportedKey(ctx, t, env.driver, importedCred, "imported-test-key", json.RawMessage(`["read"]`))

		result, err := env.verifier.authenticateImportedKey(ctx, importedCred)
		require.NoError(t, err)
		require.NotNil(t, result)
		assert.Equal(t, importedKeyID, result.KeyID)
		assert.Equal(t, int32(talosv2alpha1.KeyStatus_KEY_STATUS_ACTIVE), result.Status)
	})

	t.Run("key not found returns error", func(t *testing.T) {
		t.Parallel()

		env := newTestVerifier(ctx, t)

		// Non-existent credential
		_, err := env.verifier.authenticateImportedKey(ctx, "non-existent-credential")
		require.Error(t, err)
		assert.True(t, errors.Is(err, errdef.ErrAPIKeyNotFound()))
	})

	t.Run("revoked imported key returns error", func(t *testing.T) {
		t.Parallel()

		env := newTestVerifier(ctx, t)

		importedCred := "revoked-imported-credential"
		importedKeyID := mustCreateImportedKey(ctx, t, env.driver, importedCred, "revoked-imported-key", json.RawMessage(`["read"]`))

		// Revoke the imported key
		_, err := env.driver.RevokeImportedAPIKey(ctx, persistencetypes.RevokeImportedKeyParams{
			KeyID:  importedKeyID,
			Reason: int32(talosv2alpha1.RevocationReason_REVOCATION_REASON_KEY_COMPROMISE),
		})
		require.NoError(t, err)

		_, err = env.verifier.authenticateImportedKey(ctx, importedCred)
		require.Error(t, err)
		assert.True(t, errors.Is(err, errdef.ErrAPIKeyRevoked()))
	})

	t.Run("expired imported key returns error", func(t *testing.T) {
		t.Parallel()

		env := newTestVerifier(ctx, t)

		importedCred := "expired-imported-credential"
		importedKeyID := crypto.HashImportedAPIKey(importedCred, contextx.NetworkIDFromContext(ctx).String())

		expiresAt := time.Now().UTC().Add(-1 * time.Hour)
		_, err := env.driver.CreateImportedAPIKey(ctx, persistencetypes.CreateImportedKeyParams{
			KeyID:     importedKeyID,
			Name:      "expired-imported-key",
			ActorID:   "owner-imported",
			Scopes:    json.RawMessage(`["read"]`),
			Metadata:  json.RawMessage(`{}`),
			Status:    int32(talosv2alpha1.KeyStatus_KEY_STATUS_ACTIVE),
			ExpiresAt: &expiresAt,
		})
		require.NoError(t, err)

		_, err = env.verifier.authenticateImportedKey(ctx, importedCred)
		require.Error(t, err)
		assert.True(t, errors.Is(err, errdef.ErrAPIKeyExpired()))
	})
}

// TestVerifier_PrefixMismatch asserts that a key whose prefix is not in the
// allowed set returns ErrAPIKeyNotFound (HTTP 404), not ErrInvalidAPIKeyFormat (HTTP 400).
// This prevents callers from distinguishing "wrong project" from "key does not exist".
func TestVerifier_PrefixMismatch(t *testing.T) {
	t.Parallel()

	ctx := t.Context()
	const hmacSecret = "test-hmac-secret-for-prefix-mismatch-32chars"

	// Verifier is configured to allow only the "talos" prefix.
	env := newTestVerifier(ctx, t)
	configureProviderForAPIKeys(ctx, t, env.provider, hmacSecret)

	// Generate a structurally valid key with a different prefix ("other").
	// RouteCredential will classify it as CredentialTypeIssued (v1 format),
	// so it reaches authenticateIssuedKey and the isAllowedPrefix check.
	fullKey, _, err := crypto.GenerateAPIKey(ctx, "other", []byte(hmacSecret))
	require.NoError(t, err)

	_, _, verifyErr := env.verifier.VerifyAPIKey(ctx, fullKey)
	require.Error(t, verifyErr)

	// Must be 404 NOT_FOUND — not 400 INVALID_FORMAT — to prevent information leakage.
	assert.True(t, errors.Is(verifyErr, errdef.ErrAPIKeyNotFound()),
		"prefix mismatch must return ErrAPIKeyNotFound, got: %v", verifyErr)
	assert.False(t, errors.Is(verifyErr, errdef.ErrInvalidAPIKeyFormat()),
		"prefix mismatch must NOT return ErrInvalidAPIKeyFormat, got: %v", verifyErr)

	var herodotErr *herodot.DefaultError
	require.ErrorAs(t, verifyErr, &herodotErr)
	assert.Equal(t, 404, herodotErr.CodeField,
		"HTTP status must be 404, got: %d", herodotErr.CodeField)
}

// TestSelfRevokeAPIKey_UnitTests tests self-revocation with authentication failures
func TestSelfRevokeAPIKey_UnitTests(t *testing.T) {
	t.Parallel()

	ctx := t.Context()

	t.Run("issued key with invalid checksum fails authentication", func(t *testing.T) {
		t.Parallel()

		const hmacSecret = "test-hmac-secret-for-revoke-test-32chars"
		env := newTestVerifier(ctx, t)
		configureProviderForAPIKeys(ctx, t, env.provider, hmacSecret)

		fullKey, _ := mustGenerateAndCreateAPIKey(ctx, t, env.driver, hmacSecret, "test-key", "owner-1", []string{"read"})

		// Change the HMAC secret to cause checksum failure
		require.NoError(t, env.provider.Set(ctx, config.KeySecretsHMACCurrent, "different-secret-32chars-long-12"))

		err := env.verifier.SelfRevokeAPIKey(ctx, fullKey, int32(talosv2alpha1.RevocationReason_REVOCATION_REASON_KEY_COMPROMISE))
		require.Error(t, err)
		// Checksum failures are normalized to ErrAPIKeyNotFound to prevent callers
		// from distinguishing a wrong-project key (bad HMAC) from a non-existent one.
		assert.True(t, errors.Is(err, errdef.ErrAPIKeyNotFound()))
		assert.Contains(t, reasonFromHerodotError(t, err), "invalid API key checksum")
	})

	// Coverage: issued key (valid, revoked, HMAC-mismatch), imported key (wrong credential),
	// cache invalidation on revocation. Additional adversarial paths are covered
	// by TestVerifyAPIKey_AdversarialCredentialInputs and TestVerifyAPIKey_CrossTenantTokenReplay.

	t.Run("imported key with wrong credential fails authentication", func(t *testing.T) {
		t.Parallel()

		env := newTestVerifier(ctx, t)

		importedCred := "correct-imported-credential"
		mustCreateImportedKey(ctx, t, env.driver, importedCred, "imported-key", json.RawMessage(`["read"]`))

		// Try to revoke with wrong credential
		err := env.verifier.SelfRevokeAPIKey(ctx, "wrong-imported-credential", int32(talosv2alpha1.RevocationReason_REVOCATION_REASON_KEY_COMPROMISE))
		require.Error(t, err)
		assert.True(t, errors.Is(err, errdef.ErrAPIKeyNotFound()))
	})

	t.Run("issued key cache invalidated on revocation", func(t *testing.T) {
		t.Parallel()

		const hmacSecret = "test-hmac-secret-for-cache-test-32chars"
		testCacheInst := newTestCache()
		env := newTestVerifierWithCache(ctx, t, testCacheInst)
		configureProviderForAPIKeys(ctx, t, env.provider, hmacSecret)

		fullKey, keyID := mustGenerateAndCreateAPIKey(ctx, t, env.driver, hmacSecret, "test-key", "owner-1", []string{"read"})

		// First verify - should cache the key
		result, _, err := env.verifier.VerifyAPIKey(ctx, fullKey)
		require.NoError(t, err)
		assert.Equal(t, int32(talosv2alpha1.KeyStatus_KEY_STATUS_ACTIVE), result.Status)

		// Verify it's in cache (keyed by key_id)
		cachedKey, found, err := testCacheInst.Get(ctx, keyID)
		require.NoError(t, err)
		assert.True(t, found)
		assert.Equal(t, keyID, cachedKey.KeyID)

		// Self-revoke the key
		err = env.verifier.SelfRevokeAPIKey(ctx, fullKey, int32(talosv2alpha1.RevocationReason_REVOCATION_REASON_KEY_COMPROMISE))
		require.NoError(t, err)

		// Verify cache was invalidated
		_, found, err = testCacheInst.Get(ctx, keyID)
		require.NoError(t, err)
		assert.False(t, found, "cache should be invalidated after revocation")
	})
}

// ctxWithRemoteAddr returns a context that carries the given remote IP address
// as the client request info, matching the format set by clientip.WithRequestInfo.
func ctxWithRemoteAddr(ctx context.Context, remoteAddr string) context.Context {
	r := httptest.NewRequest(http.MethodGet, "/", nil)
	r.RemoteAddr = remoteAddr + ":12345"
	return clientip.WithRequestInfo(ctx, r)
}

// TestValidateIPRestriction tests the validateIPRestriction method directly.
func TestValidateIPRestriction(t *testing.T) {
	t.Parallel()

	ctx := t.Context()
	provider := newVerifierTestProvider(t, "test-hmac-secret-for-ip-test-32ch!")
	v := &Verifier{provider: provider}

	tests := []struct {
		name         string
		allowedCIDRs json.RawMessage
		remoteAddr   string
		wantErr      error
	}{
		{
			name:         "no restriction — any IP is allowed",
			allowedCIDRs: json.RawMessage(`[]`),
			remoteAddr:   "10.0.0.1",
			wantErr:      nil,
		},
		{
			name:         "no restriction (null) — any IP is allowed",
			allowedCIDRs: json.RawMessage(`null`),
			remoteAddr:   "203.0.113.5",
			wantErr:      nil,
		},
		{
			name:         "IP within allowed CIDR — allowed",
			allowedCIDRs: json.RawMessage(`["192.168.1.0/24"]`),
			remoteAddr:   "192.168.1.42",
			wantErr:      nil,
		},
		{
			name:         "IP in second of multiple allowed CIDRs — allowed",
			allowedCIDRs: json.RawMessage(`["10.0.0.0/8","192.168.1.0/24"]`),
			remoteAddr:   "192.168.1.10",
			wantErr:      nil,
		},
		{
			name:         "IP outside all allowed CIDRs — denied",
			allowedCIDRs: json.RawMessage(`["192.168.1.0/24"]`),
			remoteAddr:   "10.0.0.1",
			wantErr:      errdef.ErrIPNotAllowed(),
		},
		{
			name:         "IP outside multiple allowed CIDRs — denied",
			allowedCIDRs: json.RawMessage(`["10.0.0.0/8","192.168.1.0/24"]`),
			remoteAddr:   "203.0.113.1",
			wantErr:      errdef.ErrIPNotAllowed(),
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			reqCtx := ctxWithRemoteAddr(ctx, tt.remoteAddr)
			key := &db.IssuedApiKey{
				AllowedCidrs: tt.allowedCIDRs,
			}

			err := v.validateIPRestriction(reqCtx, key)
			if tt.wantErr == nil {
				assert.NoError(t, err)
			} else {
				require.Error(t, err)
				assert.True(t, errors.Is(err, tt.wantErr), "expected %v, got %v", tt.wantErr, err)
			}
		})
	}
}

// TestValidateIPRestriction_NoRequestInfo tests the case where the context carries
// no request info but the key has CIDR restrictions. The verifier must deny the
// request because it cannot determine the client IP.
func TestValidateIPRestriction_NoRequestInfo(t *testing.T) {
	t.Parallel()

	ctx := t.Context()
	provider := newVerifierTestProvider(t, "test-hmac-secret-for-ip-test-32ch!")
	v := &Verifier{provider: provider}

	key := &db.IssuedApiKey{
		AllowedCidrs: json.RawMessage(`["192.168.1.0/24"]`),
	}

	// Context has no RequestInfo — client IP cannot be resolved.
	err := v.validateIPRestriction(ctx, key)
	require.Error(t, err)
	assert.True(t, errors.Is(err, errdef.ErrIPNotAllowed()), "expected ErrIPNotAllowed, got %v", err)
}

// TestVerifyAPIKey_IPRejected_RecordedAsFailure asserts that a key which
// authenticates against the database but is then rejected by its IP restriction
// is counted as a failed verification, not a success. The DB path previously
// recorded the metric before the IP check, inflating the success counter.
func TestVerifyAPIKey_IPRejected_RecordedAsFailure(t *testing.T) {
	t.Parallel()

	ctx := t.Context()
	keyService, _, _ := newDeterministicEdDSAKeyService(t)

	driver, err := testutil.InitDriver(t, "")
	require.NoError(t, err)
	t.Cleanup(func() { _ = driver.Close() })

	const hmacSecret = "test-hmac-secret-for-ip-fail-metric-3"
	provider := newVerifierTestProvider(t, hmacSecret)

	tracker := lastused.New(ctx, driver, lastused.Config{
		QueueSize: 100, FlushSize: 100, FlushInterval: time.Hour, NumWorkers: 1,
	})
	t.Cleanup(tracker.Close)

	m := metrics.New(prometheus.NewRegistry())
	v := NewFromProvider(driver, provider, newNoopCache(), testutil.NewMockEmitter(), keyService, m, tracker)

	fullKey, keyID, err := crypto.GenerateAPIKey(ctx, "talos", []byte(hmacSecret))
	require.NoError(t, err)
	_, err = driver.CreateIssuedAPIKey(ctx, persistencetypes.CreateIssuedAPIKeyParams{
		KeyID:        keyID,
		Name:         "ip-fail-metric",
		TokenPrefix:  "talos",
		ActorID:      "owner-ip",
		Scopes:       scopesToJSON([]string{"read"}),
		Metadata:     json.RawMessage(`{}`),
		AllowedCIDRs: json.RawMessage(`["192.168.1.0/24"]`),
	})
	require.NoError(t, err)

	// The key authenticates against the DB, but the caller IP is outside the
	// allowed CIDR — so verification must fail and be recorded as a failure.
	reqCtx := ctxWithRemoteAddr(ctx, "10.0.0.1")
	_, _, err = v.VerifyAPIKey(reqCtx, fullKey)
	require.Error(t, err)
	assert.True(t, errors.Is(err, errdef.ErrIPNotAllowed()), "got: %v", err)

	label := string(crypto.CredentialTypeIssued)
	assert.Equal(t, 0, int(promtestutil.ToFloat64(m.VerificationAttempts.WithLabelValues(label, "success"))),
		"IP-rejected verification must not count as success")
	assert.Equal(t, 1, int(promtestutil.ToFloat64(m.VerificationAttempts.WithLabelValues(label, "failure"))),
		"IP-rejected verification must count as failure")
}

// TestVerifyAPIKey_AdversarialCredentialInputs tests that malformed, oversized, and
// specially crafted credential strings are rejected without panics or data leaks.
func TestVerifyAPIKey_AdversarialCredentialInputs(t *testing.T) {
	t.Parallel()

	ctx := t.Context()
	env := newTestVerifier(ctx, t)

	tests := []struct {
		name       string
		credential string
	}{
		{name: "null byte injection", credential: "talos_\x00_secret"},
		{name: "64KB string", credential: string(make([]byte, 65536))},
		{name: "unicode snowman", credential: "\u2603\u2603\u2603"},
		{name: "newline injection", credential: "valid\nX-Injected-Header: evil"},
		{name: "carriage return injection", credential: "valid\r\nX-Injected: evil"},
		{name: "whitespace only", credential: "   \t\n  "},
		{name: "prefix only issued", credential: "talos_"},
		{name: "prefix only macaroon", credential: "mc_v1_"},
		{name: "JWT garbage three parts", credential: "not.a.jwt"},
		{name: "JWT garbage valid-looking", credential: "eyJhbGciOiJFZERTQSJ9.eyJzdWIiOiJ0ZXN0In0.fakesig"},
		{name: "BOM prefix", credential: "\xef\xbb\xbfsome-key"},
		{name: "RTL override", credential: "\u202eevil-key"},
		{name: "only dots", credential: "..."},
		{name: "extremely long macaroon prefix", credential: "mc_v1_" + string(make([]byte, 65536))},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, _, err := env.verifier.VerifyAPIKey(ctx, tt.credential)
			require.Error(t, err, "credential %q must be rejected", tt.name)
			// Must not panic and must return a proper error — that's the key assertion.
			// The specific error type depends on how RouteCredential classifies the input.
		})
	}
}

// TestVerifyAPIKey_CrossTenantTokenReplay verifies that a JWT derived token minted for
// one network (NID-A) is rejected when verified in the context of another network (NID-B).
func TestVerifyAPIKey_CrossTenantTokenReplay(t *testing.T) {
	t.Parallel()

	ctx := t.Context()

	// Create a deterministic key service and driver.
	keyService, privateKey, signingKeyID := newDeterministicEdDSAKeyService(t)

	driver, err := testutil.InitDriver(t, "")
	require.NoError(t, err)
	t.Cleanup(func() { _ = driver.Close() })

	provider := newVerifierTestProvider(t, "test-secret-123-must-be-32chars!")
	require.NoError(t, provider.Set(ctx, config.KeyCredentialsDerivedTokensJWTSigningKeysURLs, []string{
		testutil.TestSigningKeyJWKSURLWithKey(t, privateKey, signingKeyID),
	}))

	tracker := lastused.New(ctx, driver, lastused.Config{
		QueueSize: 100, FlushSize: 100, FlushInterval: time.Hour, NumWorkers: 1,
	})
	t.Cleanup(tracker.Close)

	verifier := NewFromProvider(driver, provider, newNoopCache(), testutil.NewMockEmitter(), keyService, metrics.New(prometheus.NewRegistry()), tracker)

	// Create a parent key in the DB under the default NID (uuid.Nil).
	const (
		hmacSecret  = "test-secret-123-must-be-32chars!"
		parentKeyID = "aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa"
	)
	_, err = driver.CreateIssuedAPIKey(ctx, persistencetypes.CreateIssuedAPIKeyParams{
		KeyID:       parentKeyID,
		Name:        "cross-tenant-parent",
		TokenPrefix: "talos",
		ActorID:     "owner-a",
		Scopes:      scopesToJSON([]string{"read"}),
		Metadata:    json.RawMessage(`{}`),
	})
	require.NoError(t, err)

	// Mint a JWT token claiming a *different* NID than the context NID.
	differentNID := "bbbbbbbb-bbbb-bbbb-bbbb-bbbbbbbbbbbb"
	now := time.Now().UTC()
	claims := token.NewClaims()
	claims.SetTokenID("jwt-cross-tenant")
	claims.SetSubject(parentKeyID)
	claims.SetIssuer("talos-service")
	claims.SetIssuedAt(now)
	claims.SetExpiration(now.Add(time.Hour))
	claims.SetNotBefore(now)
	claims.SetTokenType(token.TokenTypeDerived)
	claims.SetKeyID(parentKeyID)
	claims.SetParentID(parentKeyID)
	claims.SetActorID("owner-a")
	claims.SetNetworkID(differentNID) // NID-B, but context will be NID-A (uuid.Nil)
	claims.SetScopes([]string{"read"})
	claims.SetMetadata(map[string]any{})

	signer, err := token.NewJWTSigner(privateKey, signingKeyID)
	require.NoError(t, err)

	jwtToken, err := signer.Sign(ctx, claims)
	require.NoError(t, err)

	// Verify in context with NID-A (uuid.Nil) — the token claims NID-B, so it must fail.
	_, _, verifyErr := verifier.VerifyAPIKey(ctx, jwtToken)
	require.Error(t, verifyErr, "cross-tenant token replay must be rejected")
}

// TestVerifyAPIKey_SignatureManipulation verifies that modifying even a single character
// of a signed JWT causes verification to fail.
func TestVerifyAPIKey_SignatureManipulation(t *testing.T) {
	t.Parallel()

	ctx := t.Context()

	keyService, privateKey, signingKeyID := newDeterministicEdDSAKeyService(t)

	driver, err := testutil.InitDriver(t, "")
	require.NoError(t, err)
	t.Cleanup(func() { _ = driver.Close() })

	provider := newVerifierTestProvider(t, "test-secret-123-must-be-32chars!")
	require.NoError(t, provider.Set(ctx, config.KeyCredentialsDerivedTokensJWTSigningKeysURLs, []string{
		testutil.TestSigningKeyJWKSURLWithKey(t, privateKey, signingKeyID),
	}))

	tracker := lastused.New(ctx, driver, lastused.Config{
		QueueSize: 100, FlushSize: 100, FlushInterval: time.Hour, NumWorkers: 1,
	})
	t.Cleanup(tracker.Close)

	verifier := NewFromProvider(driver, provider, newNoopCache(), testutil.NewMockEmitter(), keyService, metrics.New(prometheus.NewRegistry()), tracker)

	parentKeyID := "cccccccc-cccc-cccc-cccc-cccccccccccc"
	_, err = driver.CreateIssuedAPIKey(ctx, persistencetypes.CreateIssuedAPIKeyParams{
		KeyID:       parentKeyID,
		Name:        "sig-test-parent",
		TokenPrefix: "talos",
		ActorID:     "owner-sig",
		Scopes:      scopesToJSON([]string{"read"}),
		Metadata:    json.RawMessage(`{}`),
	})
	require.NoError(t, err)

	// Mint a valid JWT token.
	now := time.Now().UTC()
	claims := token.NewClaims()
	claims.SetTokenID("jwt-sig-test")
	claims.SetSubject(parentKeyID)
	claims.SetIssuer("talos-service")
	claims.SetIssuedAt(now)
	claims.SetExpiration(now.Add(time.Hour))
	claims.SetNotBefore(now)
	claims.SetTokenType(token.TokenTypeDerived)
	claims.SetKeyID(parentKeyID)
	claims.SetParentID(parentKeyID)
	claims.SetActorID("owner-sig")
	claims.SetNetworkID(contextx.NetworkIDFromContext(ctx).String())
	claims.SetScopes([]string{"read"})
	claims.SetMetadata(map[string]any{})

	signer, err := token.NewJWTSigner(privateKey, signingKeyID)
	require.NoError(t, err)

	jwtToken, err := signer.Sign(ctx, claims)
	require.NoError(t, err)

	// Sanity: the valid token verifies.
	result, _, err := verifier.VerifyAPIKey(ctx, jwtToken)
	require.NoError(t, err)
	assert.Equal(t, parentKeyID, result.KeyID)

	// Flip the last byte of the signature — must fail.
	tampered := []byte(jwtToken)
	tampered[len(tampered)-1] ^= 0xFF
	_, _, err = verifier.VerifyAPIKey(ctx, string(tampered))
	require.Error(t, err, "tampered JWT signature must be rejected by verifier")
}

// TestVerifyAPIKey_IPRestriction_AllCredentialTypes verifies that IP restrictions are
// enforced for all four credential types: issued, imported, JWT, and macaroon.
func TestVerifyAPIKey_IPRestriction_AllCredentialTypes(t *testing.T) {
	t.Parallel()

	ctx := t.Context()
	keyService, privateKey, signingKeyID := newDeterministicEdDSAKeyService(t)

	driver, err := testutil.InitDriver(t, "")
	require.NoError(t, err)
	t.Cleanup(func() { _ = driver.Close() })

	const hmacSecret = "test-hmac-secret-for-ip-all-types-32c"
	provider := newVerifierTestProvider(t, hmacSecret)
	require.NoError(t, provider.Set(ctx, config.KeyCredentialsDerivedTokensJWTSigningKeysURLs, []string{
		testutil.TestSigningKeyJWKSURLWithKey(t, privateKey, signingKeyID),
	}))

	tracker := lastused.New(ctx, driver, lastused.Config{
		QueueSize: 100, FlushSize: 100, FlushInterval: time.Hour, NumWorkers: 1,
	})
	t.Cleanup(tracker.Close)

	v := NewFromProvider(driver, provider, newNoopCache(), testutil.NewMockEmitter(), keyService, metrics.New(prometheus.NewRegistry()), tracker)

	allowedCIDR := json.RawMessage(`["192.168.1.0/24"]`)
	allowedAddr := "192.168.1.10"
	deniedAddr := "10.0.0.1"
	// Subtests share driver and verifier; they cannot run in parallel without restructuring.

	parentKeyID := "dddddddd-dddd-dddd-dddd-dddddddddddd"
	now := time.Now().UTC()

	buildDerivedClaims := func(nid string) *token.Claims {
		c := token.NewClaims()
		c.SetTokenID("ip-test-token")
		c.SetSubject(parentKeyID)
		c.SetIssuer("talos-service")
		c.SetIssuedAt(now)
		c.SetExpiration(now.Add(time.Hour))
		c.SetNotBefore(now)
		c.SetTokenType(token.TokenTypeDerived)
		c.SetKeyID(parentKeyID)
		c.SetParentID(parentKeyID)
		c.SetActorID("owner-ip-test")
		c.SetNetworkID(nid)
		c.SetScopes([]string{"read"})
		c.SetMetadata(map[string]any{})
		c.SetAllowedCidrs([]string{"192.168.1.0/24"})
		return c
	}

	t.Run("issued key — allowed IP passes", func(t *testing.T) {
		fullKey, keyID, err := crypto.GenerateAPIKey(ctx, "talos", []byte(hmacSecret))
		require.NoError(t, err)
		_, err = driver.CreateIssuedAPIKey(ctx, persistencetypes.CreateIssuedAPIKeyParams{
			KeyID:        keyID,
			Name:         "ip-issued-allow",
			TokenPrefix:  "talos",
			ActorID:      "owner-ip",
			Scopes:       scopesToJSON([]string{"read"}),
			Metadata:     json.RawMessage(`{}`),
			AllowedCIDRs: allowedCIDR,
		})
		require.NoError(t, err)

		reqCtx := ctxWithRemoteAddr(ctx, allowedAddr)
		result, _, err := v.VerifyAPIKey(reqCtx, fullKey)
		require.NoError(t, err)
		assert.Equal(t, keyID, result.KeyID)
	})

	t.Run("issued key — denied IP rejected", func(t *testing.T) {
		fullKey, keyID, err := crypto.GenerateAPIKey(ctx, "talos", []byte(hmacSecret))
		require.NoError(t, err)
		_, err = driver.CreateIssuedAPIKey(ctx, persistencetypes.CreateIssuedAPIKeyParams{
			KeyID:        keyID,
			Name:         "ip-issued-deny",
			TokenPrefix:  "talos",
			ActorID:      "owner-ip",
			Scopes:       scopesToJSON([]string{"read"}),
			Metadata:     json.RawMessage(`{}`),
			AllowedCIDRs: allowedCIDR,
		})
		require.NoError(t, err)

		reqCtx := ctxWithRemoteAddr(ctx, deniedAddr)
		_, _, err = v.VerifyAPIKey(reqCtx, fullKey)
		require.Error(t, err)
		assert.True(t, errors.Is(err, errdef.ErrIPNotAllowed()), "got: %v", err)
	})

	t.Run("imported key — allowed IP passes", func(t *testing.T) {
		cred := "imported-ip-allowed-cred"
		keyID := crypto.HashImportedAPIKey(cred, contextx.NetworkIDFromContext(ctx).String())
		_, err := driver.CreateImportedAPIKey(ctx, persistencetypes.CreateImportedKeyParams{
			KeyID:        keyID,
			Name:         "ip-imported-allow",
			ActorID:      "owner-ip",
			Scopes:       json.RawMessage(`["read"]`),
			Metadata:     json.RawMessage(`{}`),
			Status:       int32(talosv2alpha1.KeyStatus_KEY_STATUS_ACTIVE),
			AllowedCIDRs: allowedCIDR,
		})
		require.NoError(t, err)

		reqCtx := ctxWithRemoteAddr(ctx, allowedAddr)
		result, _, err := v.VerifyAPIKey(reqCtx, cred)
		require.NoError(t, err)
		assert.Equal(t, keyID, result.KeyID)
	})

	t.Run("imported key — denied IP rejected", func(t *testing.T) {
		cred := "imported-ip-denied-cred"
		keyID := crypto.HashImportedAPIKey(cred, contextx.NetworkIDFromContext(ctx).String())
		_, err := driver.CreateImportedAPIKey(ctx, persistencetypes.CreateImportedKeyParams{
			KeyID:        keyID,
			Name:         "ip-imported-deny",
			ActorID:      "owner-ip",
			Scopes:       json.RawMessage(`["read"]`),
			Metadata:     json.RawMessage(`{}`),
			Status:       int32(talosv2alpha1.KeyStatus_KEY_STATUS_ACTIVE),
			AllowedCIDRs: allowedCIDR,
		})
		require.NoError(t, err)

		reqCtx := ctxWithRemoteAddr(ctx, deniedAddr)
		_, _, err = v.VerifyAPIKey(reqCtx, cred)
		require.Error(t, err)
		assert.True(t, errors.Is(err, errdef.ErrIPNotAllowed()), "got: %v", err)
	})

	t.Run("JWT derived token — allowed IP passes", func(t *testing.T) {
		signer, err := token.NewJWTSigner(privateKey, signingKeyID)
		require.NoError(t, err)

		claims := buildDerivedClaims(contextx.NetworkIDFromContext(ctx).String())
		claims.SetTokenID("jwt-ip-allow")
		jwtTok, err := signer.Sign(ctx, claims)
		require.NoError(t, err)

		reqCtx := ctxWithRemoteAddr(ctx, allowedAddr)
		result, _, err := v.VerifyAPIKey(reqCtx, jwtTok)
		require.NoError(t, err)
		assert.Equal(t, parentKeyID, result.KeyID)
	})

	t.Run("JWT derived token — denied IP rejected", func(t *testing.T) {
		signer, err := token.NewJWTSigner(privateKey, signingKeyID)
		require.NoError(t, err)

		claims := buildDerivedClaims(contextx.NetworkIDFromContext(ctx).String())
		claims.SetTokenID("jwt-ip-deny")
		jwtTok, err := signer.Sign(ctx, claims)
		require.NoError(t, err)

		reqCtx := ctxWithRemoteAddr(ctx, deniedAddr)
		_, _, err = v.VerifyAPIKey(reqCtx, jwtTok)
		require.Error(t, err)
		assert.True(t, errors.Is(err, errdef.ErrIPNotAllowed()), "got: %v", err)
	})

	t.Run("macaroon derived token — allowed IP passes", func(t *testing.T) {
		macSigner, err := token.NewMacaroonSigner([]byte(hmacSecret), "talos-service", "mc")
		require.NoError(t, err)

		claims := buildDerivedClaims(contextx.NetworkIDFromContext(ctx).String())
		claims.SetTokenID("mac-ip-allow")
		macTok, err := macSigner.Sign(ctx, claims)
		require.NoError(t, err)

		reqCtx := ctxWithRemoteAddr(ctx, allowedAddr)
		result, _, err := v.VerifyAPIKey(reqCtx, macTok)
		require.NoError(t, err)
		assert.Equal(t, parentKeyID, result.KeyID)
	})

	t.Run("macaroon derived token — denied IP rejected", func(t *testing.T) {
		macSigner, err := token.NewMacaroonSigner([]byte(hmacSecret), "talos-service", "mc")
		require.NoError(t, err)

		claims := buildDerivedClaims(contextx.NetworkIDFromContext(ctx).String())
		claims.SetTokenID("mac-ip-deny")
		macTok, err := macSigner.Sign(ctx, claims)
		require.NoError(t, err)

		reqCtx := ctxWithRemoteAddr(ctx, deniedAddr)
		_, _, err = v.VerifyAPIKey(reqCtx, macTok)
		require.Error(t, err)
		assert.True(t, errors.Is(err, errdef.ErrIPNotAllowed()), "got: %v", err)
	})
}

// TestVerifyAPIKey_HMACRotation verifies that a key signed with a retired HMAC secret
// still verifies when the retired secret is listed in the configuration.
func TestVerifyAPIKey_HMACRotation(t *testing.T) {
	t.Parallel()

	ctx := t.Context()
	const (
		oldSecret = "old-hmac-secret-must-be-32-chars!!"
		newSecret = "new-hmac-secret-must-be-32-chars!!"
	)

	env := newTestVerifier(ctx, t)

	// Generate key with the OLD secret.
	fullKey, keyID, err := crypto.GenerateAPIKey(ctx, "talos", []byte(oldSecret))
	require.NoError(t, err)
	_, err = env.driver.CreateIssuedAPIKey(ctx, persistencetypes.CreateIssuedAPIKeyParams{
		KeyID:       keyID,
		Name:        "rotation-test-key",
		TokenPrefix: "talos",
		ActorID:     "owner-rotation",
		Scopes:      scopesToJSON([]string{"read"}),
		Metadata:    json.RawMessage(`{}`),
	})
	require.NoError(t, err)

	// Configure verifier: new secret is current, old secret is retired.
	require.NoError(t, env.provider.Set(ctx, config.KeyCredentialsAPIKeysPrefixCurrent, "talos"))
	require.NoError(t, env.provider.Set(ctx, config.KeySecretsHMACCurrent, newSecret))
	require.NoError(t, env.provider.Set(ctx, config.KeySecretsHMACRetired, []map[string]any{{"value": oldSecret}}))

	// Key signed with the old secret must still verify.
	result, _, err := env.verifier.VerifyAPIKey(ctx, fullKey)
	require.NoError(t, err, "key signed with retired HMAC secret must still verify")
	assert.Equal(t, keyID, result.KeyID)
}

// TestVerifyAPIKey_HMACRotation_LegacyBareString mirrors TestVerifyAPIKey_HMACRotation
// but stores the retired HMAC secret in the legacy bare-string form persisted before
// retired values gained expiry (issue 12213). Contrast the object shape
// []map[string]any{{"value": oldSecret}} used above. A key signed with a secret that
// now lives on disk as a bare string must still verify through the full chain,
// proving the verification path — not just the parser — honors pre-expiry data.
func TestVerifyAPIKey_HMACRotation_LegacyBareString(t *testing.T) {
	t.Parallel()

	ctx := t.Context()
	const (
		oldSecret = "old-hmac-secret-must-be-32-chars!!"
		newSecret = "new-hmac-secret-must-be-32-chars!!"
	)

	env := newTestVerifier(ctx, t)

	// Generate key with the OLD secret.
	fullKey, keyID, err := crypto.GenerateAPIKey(ctx, "talos", []byte(oldSecret))
	require.NoError(t, err)
	_, err = env.driver.CreateIssuedAPIKey(ctx, persistencetypes.CreateIssuedAPIKeyParams{
		KeyID:       keyID,
		Name:        "rotation-legacy-barestring-key",
		TokenPrefix: "talos",
		ActorID:     "owner-rotation",
		Scopes:      scopesToJSON([]string{"read"}),
		Metadata:    json.RawMessage(`{}`),
	})
	require.NoError(t, err)

	require.NoError(t, env.provider.Set(ctx, config.KeyCredentialsAPIKeysPrefixCurrent, "talos"))
	require.NoError(t, env.provider.Set(ctx, config.KeySecretsHMACCurrent, newSecret))
	// Legacy bare-string retired secret (no {"value": ...} wrapper).
	require.NoError(t, env.provider.Set(ctx, config.KeySecretsHMACRetired, []any{oldSecret}))

	result, _, err := env.verifier.VerifyAPIKey(ctx, fullKey)
	require.NoError(t, err, "key signed with a legacy bare-string retired HMAC secret must still verify")
	assert.Equal(t, keyID, result.KeyID)
}

// TestVerifyDerivedJWT_RetiredIssuerLegacyBareString mirrors the retired-issuer JWT
// path (see TestVerifyDerivedJWT_RetiredIssuerExpiry) but configures the retired
// issuer in the legacy bare-string form. A JWT minted under an issuer that now lives
// on disk as a bare string must still verify, proving getTokenIssuers honors
// pre-expiry retired-issuer data (issue 12213 backward compat).
func TestVerifyDerivedJWT_RetiredIssuerLegacyBareString(t *testing.T) {
	t.Parallel()

	const (
		retiredIssuer = "https://retired-issuer.example.com"
		parentKeyID   = "d4d4d4d4-d4d4-d4d4-d4d4-d4d4d4d4d4d4"
	)

	ctx := t.Context()
	v, driver, privateKey, signingKeyID := newRetiredIssuerVerifierWithRetired(ctx, t, []any{retiredIssuer})
	mustCreateDerivedParentKey(ctx, t, driver, parentKeyID, "owner-retired-jwt-legacy")

	now := time.Now().UTC()
	claims := token.NewClaims()
	claims.SetTokenID("jwt-retired-issuer-legacy")
	claims.SetSubject(parentKeyID)
	claims.SetIssuer(retiredIssuer)
	claims.SetIssuedAt(now)
	claims.SetExpiration(now.Add(time.Hour))
	claims.SetNotBefore(now)
	claims.SetTokenType(token.TokenTypeDerived)
	claims.SetKeyID(parentKeyID)
	claims.SetParentID(parentKeyID)
	claims.SetActorID("owner-retired-jwt-legacy")
	claims.SetNetworkID(contextx.NetworkIDFromContext(ctx).String())
	claims.SetScopes([]string{"read"})
	claims.SetMetadata(map[string]any{})

	signer, err := token.NewJWTSigner(privateKey, signingKeyID)
	require.NoError(t, err)
	jwtToken, err := signer.Sign(ctx, claims)
	require.NoError(t, err)

	result, _, err := v.VerifyAPIKey(ctx, jwtToken)
	require.NoError(t, err, "JWT under a legacy bare-string retired issuer must verify")
	assert.Equal(t, parentKeyID, result.KeyID)
}

// TestVerifyAPIKey_HMACRetiredExpiry verifies that a retired HMAC secret is honored
// only while its expiry is unset or still in the future. Once the expiry passes, a
// key signed with the retired secret no longer verifies.
func TestVerifyAPIKey_HMACRetiredExpiry(t *testing.T) {
	t.Parallel()

	const (
		oldSecret = "old-hmac-secret-must-be-32-chars!!"
		newSecret = "new-hmac-secret-must-be-32-chars!!"
	)

	for _, tc := range []struct {
		name       string
		expiresAt  string // RFC3339, empty means no expires_at field
		wantVerify bool
	}{
		{name: "future expiry retained", expiresAt: time.Now().UTC().Add(time.Hour).Format(time.RFC3339), wantVerify: true},
		{name: "past expiry dropped", expiresAt: time.Now().UTC().Add(-time.Hour).Format(time.RFC3339), wantVerify: false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			ctx := t.Context()
			env := newTestVerifier(ctx, t)

			fullKey, keyID, err := crypto.GenerateAPIKey(ctx, "talos", []byte(oldSecret))
			require.NoError(t, err)
			_, err = env.driver.CreateIssuedAPIKey(ctx, persistencetypes.CreateIssuedAPIKeyParams{
				KeyID:       keyID,
				Name:        "rotation-expiry-test-key",
				TokenPrefix: "talos",
				ActorID:     "owner-rotation",
				Scopes:      scopesToJSON([]string{"read"}),
				Metadata:    json.RawMessage(`{}`),
			})
			require.NoError(t, err)

			require.NoError(t, env.provider.Set(ctx, config.KeyCredentialsAPIKeysPrefixCurrent, "talos"))
			require.NoError(t, env.provider.Set(ctx, config.KeySecretsHMACCurrent, newSecret))
			require.NoError(t, env.provider.Set(ctx, config.KeySecretsHMACRetired, []map[string]any{
				{"value": oldSecret, "expires_at": tc.expiresAt},
			}))

			result, _, err := env.verifier.VerifyAPIKey(ctx, fullKey)
			if tc.wantVerify {
				require.NoError(t, err, "key signed with unexpired retired secret must verify")
				assert.Equal(t, keyID, result.KeyID)
			} else {
				require.Error(t, err, "key signed with expired retired secret must not verify")
			}
		})
	}
}

// mustCreateDerivedParentKey creates the parent API key a derived token points at.
func mustCreateDerivedParentKey(ctx context.Context, t *testing.T, driver *sqlite.Driver, keyID, actorID string) {
	t.Helper()
	_, err := driver.CreateIssuedAPIKey(ctx, persistencetypes.CreateIssuedAPIKeyParams{
		KeyID:       keyID,
		Name:        "retired-issuer-parent",
		TokenPrefix: "talos",
		ActorID:     actorID,
		Scopes:      scopesToJSON([]string{"read"}),
		Metadata:    json.RawMessage(`{}`),
	})
	require.NoError(t, err)
}

// newRetiredIssuerJWTVerifier builds a verifier whose current issuer is
// "talos-service" and whose retired-issuer list contains retiredIssuer with the
// given expiry. It returns the verifier and the signing material so the caller
// can mint a JWT under the retired issuer.
func newRetiredIssuerVerifier(ctx context.Context, t *testing.T, retiredIssuer, expiresAt string) (*Verifier, *sqlite.Driver, ed25519.PrivateKey, string) {
	t.Helper()
	return newRetiredIssuerVerifierWithRetired(ctx, t, []map[string]any{
		{"value": retiredIssuer, "expires_at": expiresAt},
	})
}

// newRetiredIssuerVerifierWithRetired builds the same verifier as
// newRetiredIssuerVerifier but takes the raw retired-issuer config payload, so a
// caller can supply either the object shape ([]map[string]any{{"value": ...}}) or
// the legacy bare-string shape ([]any{"issuer"}). The current issuer stays
// "talos-service"; tokens are minted under a different, retired issuer so
// verification depends entirely on the retired-issuer list.
func newRetiredIssuerVerifierWithRetired(ctx context.Context, t *testing.T, retired any) (*Verifier, *sqlite.Driver, ed25519.PrivateKey, string) {
	t.Helper()

	keyService, privateKey, signingKeyID := newDeterministicEdDSAKeyService(t)

	driver, err := testutil.InitDriver(t, "")
	require.NoError(t, err)
	t.Cleanup(func() { _ = driver.Close() })

	provider := newVerifierTestProvider(t, "test-secret-123-must-be-32chars!")
	require.NoError(t, provider.Set(ctx, config.KeyCredentialsDerivedTokensJWTSigningKeysURLs, []string{
		testutil.TestSigningKeyJWKSURLWithKey(t, privateKey, signingKeyID),
	}))
	require.NoError(t, provider.Set(ctx, config.KeyCredentialsIssuerRetired, retired))

	tracker := lastused.New(ctx, driver, lastused.Config{
		QueueSize: 100, FlushSize: 100, FlushInterval: time.Hour, NumWorkers: 1,
	})
	t.Cleanup(tracker.Close)

	v := NewFromProvider(driver, provider, newNoopCache(), testutil.NewMockEmitter(), keyService, metrics.New(prometheus.NewRegistry()), tracker)
	return v, driver, privateKey, signingKeyID
}

// TestVerifyDerivedJWT_RetiredIssuerExpiry verifies that a JWT signed under a
// retired issuer is honored only while that issuer's expiry is unset or still in
// the future. This is the derived-token mirror of TestVerifyAPIKey_HMACRetiredExpiry
// for the retired-issuer half of getTokenIssuers.
func TestVerifyDerivedJWT_RetiredIssuerExpiry(t *testing.T) {
	t.Parallel()

	const (
		retiredIssuer = "https://retired-issuer.example.com"
		parentKeyID   = "a1a1a1a1-a1a1-a1a1-a1a1-a1a1a1a1a1a1"
	)

	for _, tc := range []struct {
		name       string
		expiresAt  string
		wantVerify bool
	}{
		{name: "future expiry retained", expiresAt: time.Now().UTC().Add(time.Hour).Format(time.RFC3339), wantVerify: true},
		{name: "past expiry dropped", expiresAt: time.Now().UTC().Add(-time.Hour).Format(time.RFC3339), wantVerify: false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			ctx := t.Context()
			v, driver, privateKey, signingKeyID := newRetiredIssuerVerifier(ctx, t, retiredIssuer, tc.expiresAt)
			mustCreateDerivedParentKey(ctx, t, driver, parentKeyID, "owner-retired-jwt")

			now := time.Now().UTC()
			claims := token.NewClaims()
			claims.SetTokenID("jwt-retired-issuer")
			claims.SetSubject(parentKeyID)
			claims.SetIssuer(retiredIssuer)
			claims.SetIssuedAt(now)
			claims.SetExpiration(now.Add(time.Hour))
			claims.SetNotBefore(now)
			claims.SetTokenType(token.TokenTypeDerived)
			claims.SetKeyID(parentKeyID)
			claims.SetParentID(parentKeyID)
			claims.SetActorID("owner-retired-jwt")
			claims.SetNetworkID(contextx.NetworkIDFromContext(ctx).String())
			claims.SetScopes([]string{"read"})
			claims.SetMetadata(map[string]any{})

			signer, err := token.NewJWTSigner(privateKey, signingKeyID)
			require.NoError(t, err)
			jwtToken, err := signer.Sign(ctx, claims)
			require.NoError(t, err)

			result, _, err := v.VerifyAPIKey(ctx, jwtToken)
			if tc.wantVerify {
				require.NoError(t, err, "JWT under an unexpired retired issuer must verify")
				assert.Equal(t, parentKeyID, result.KeyID)
			} else {
				require.Error(t, err, "JWT under an expired retired issuer must not verify")
			}
		})
	}
}

// TestVerifyDerivedMacaroon_RetiredIssuerExpiry mirrors the JWT case on the
// macaroon derived-token path.
func TestVerifyDerivedMacaroon_RetiredIssuerExpiry(t *testing.T) {
	t.Parallel()

	const (
		retiredIssuer = "https://retired-issuer.example.com"
		hmacSecret    = "test-secret-123-must-be-32chars!"
		parentKeyID   = "b2b2b2b2-b2b2-b2b2-b2b2-b2b2b2b2b2b2"
	)

	for _, tc := range []struct {
		name       string
		expiresAt  string
		wantVerify bool
	}{
		{name: "future expiry retained", expiresAt: time.Now().UTC().Add(time.Hour).Format(time.RFC3339), wantVerify: true},
		{name: "past expiry dropped", expiresAt: time.Now().UTC().Add(-time.Hour).Format(time.RFC3339), wantVerify: false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			ctx := t.Context()
			v, driver, _, _ := newRetiredIssuerVerifier(ctx, t, retiredIssuer, tc.expiresAt)
			mustCreateDerivedParentKey(ctx, t, driver, parentKeyID, "owner-retired-mac")

			macSigner, err := token.NewMacaroonSigner([]byte(hmacSecret), retiredIssuer, "mc")
			require.NoError(t, err)

			now := time.Now().UTC()
			claims := token.NewClaims()
			claims.SetTokenID("mac-retired-issuer")
			claims.SetSubject(parentKeyID)
			claims.SetIssuer(retiredIssuer)
			claims.SetIssuedAt(now)
			claims.SetExpiration(now.Add(time.Hour))
			claims.SetNotBefore(now)
			claims.SetTokenType(token.TokenTypeDerived)
			claims.SetKeyID(parentKeyID)
			claims.SetParentID(parentKeyID)
			claims.SetActorID("owner-retired-mac")
			claims.SetNetworkID(contextx.NetworkIDFromContext(ctx).String())
			claims.SetScopes([]string{"read"})
			claims.SetMetadata(map[string]any{})

			macTok, err := macSigner.Sign(ctx, claims)
			require.NoError(t, err)

			result, _, err := v.VerifyAPIKey(ctx, macTok)
			if tc.wantVerify {
				require.NoError(t, err, "macaroon under an unexpired retired issuer must verify")
				assert.Equal(t, parentKeyID, result.KeyID)
			} else {
				require.Error(t, err, "macaroon under an expired retired issuer must not verify")
			}
		})
	}
}

// issuerLookupErrProvider embeds a real provider but forces ActiveRetiredValues to
// fail, simulating the whole-key config unmarshal failure that
// FilterActiveRetiredValues surfaces (see config.TestFilterActiveRetiredValues_WholeKeyUnmarshalFails).
// The schema's oneOf constraint makes that failure unreachable from a validated
// config, so the embedded provider supplies every other real value while this one
// failure mode is injected.
type issuerLookupErrProvider struct {
	*config.Provider
}

func (issuerLookupErrProvider) ActiveRetiredValues(context.Context, config.Key) ([]string, error) {
	return nil, errors.New("simulated retired-issuer unmarshal failure")
}

// TestVerifyDerivedJWT_IssuerLookupFailsClosed verifies that when the retired-issuer
// lookup fails, the derived-token path maps it to ErrServiceUnavailable rather than
// silently accepting or generically rejecting the token.
func TestVerifyDerivedJWT_IssuerLookupFailsClosed(t *testing.T) {
	t.Parallel()

	ctx := t.Context()

	keyService, privateKey, signingKeyID := newDeterministicEdDSAKeyService(t)

	driver, err := testutil.InitDriver(t, "")
	require.NoError(t, err)
	t.Cleanup(func() { _ = driver.Close() })

	base := newVerifierTestProvider(t, "test-secret-123-must-be-32chars!")
	require.NoError(t, base.Set(ctx, config.KeyCredentialsDerivedTokensJWTSigningKeysURLs, []string{
		testutil.TestSigningKeyJWKSURLWithKey(t, privateKey, signingKeyID),
	}))

	tracker := lastused.New(ctx, driver, lastused.Config{
		QueueSize: 100, FlushSize: 100, FlushInterval: time.Hour, NumWorkers: 1,
	})
	t.Cleanup(tracker.Close)

	v := NewFromProvider(driver, issuerLookupErrProvider{Provider: base}, newNoopCache(), testutil.NewMockEmitter(), keyService, metrics.New(prometheus.NewRegistry()), tracker)

	const parentKeyID = "c3c3c3c3-c3c3-c3c3-c3c3-c3c3c3c3c3c3"
	mustCreateDerivedParentKey(ctx, t, driver, parentKeyID, "owner-fail-closed")

	now := time.Now().UTC()
	claims := token.NewClaims()
	claims.SetTokenID("jwt-issuer-lookup-fail")
	claims.SetSubject(parentKeyID)
	claims.SetIssuer("talos-service")
	claims.SetIssuedAt(now)
	claims.SetExpiration(now.Add(time.Hour))
	claims.SetNotBefore(now)
	claims.SetTokenType(token.TokenTypeDerived)
	claims.SetKeyID(parentKeyID)
	claims.SetParentID(parentKeyID)
	claims.SetActorID("owner-fail-closed")
	claims.SetNetworkID(contextx.NetworkIDFromContext(ctx).String())
	claims.SetScopes([]string{"read"})
	claims.SetMetadata(map[string]any{})

	signer, err := token.NewJWTSigner(privateKey, signingKeyID)
	require.NoError(t, err)
	jwtToken, err := signer.Sign(ctx, claims)
	require.NoError(t, err)

	_, _, err = v.VerifyAPIKey(ctx, jwtToken)
	require.Error(t, err)
	assert.True(t, errors.Is(err, errdef.ErrServiceUnavailable()), "issuer lookup failure must map to ErrServiceUnavailable, got %v", err)
}

// TestVerifyAPIKey_PrefixRotation verifies that a key with a retired prefix still verifies
// when the retired prefix is listed in the configuration.
func TestVerifyAPIKey_PrefixRotation(t *testing.T) {
	t.Parallel()

	ctx := t.Context()
	const hmacSecret = "test-hmac-secret-prefix-rotation-32c"

	env := newTestVerifier(ctx, t)

	// Generate key with the old prefix "legacy".
	fullKey, keyID, err := crypto.GenerateAPIKey(ctx, "legacy", []byte(hmacSecret))
	require.NoError(t, err)
	_, err = env.driver.CreateIssuedAPIKey(ctx, persistencetypes.CreateIssuedAPIKeyParams{
		KeyID:       keyID,
		Name:        "prefix-rotation-key",
		TokenPrefix: "legacy",
		ActorID:     "owner-prefix-rotation",
		Scopes:      scopesToJSON([]string{"read"}),
		Metadata:    json.RawMessage(`{}`),
	})
	require.NoError(t, err)

	// Configure verifier: current prefix is "talos", "legacy" is retired.
	require.NoError(t, env.provider.Set(ctx, config.KeyCredentialsAPIKeysPrefixCurrent, "talos"))
	require.NoError(t, env.provider.Set(ctx, config.KeySecretsHMACCurrent, hmacSecret))
	require.NoError(t, env.provider.Set(ctx, config.KeyCredentialsAPIKeysPrefixRetired, []string{"legacy"}))

	// Key with retired prefix must still verify.
	result, _, err := env.verifier.VerifyAPIKey(ctx, fullKey)
	require.NoError(t, err, "key with retired prefix must still verify")
	assert.Equal(t, keyID, result.KeyID)
}

// TestVerifyAPIKey_AdversarialEyJCredential verifies that a credential starting with "eyJ"
// (the base64url prefix for a JSON object header, as used by JWTs) but containing an
// invalid or unsigned token is rejected without panics or data leaks.
func TestVerifyAPIKey_AdversarialEyJCredential(t *testing.T) {
	t.Parallel()

	ctx := t.Context()
	env := newTestVerifier(ctx, t)

	tests := []struct {
		name       string
		credential string
	}{
		// A well-formed three-part JWT that is NOT signed by any known key.
		{name: "unsigned JWT-shaped token", credential: "eyJhbGciOiJFZERTQSIsInR5cCI6IkpXVCJ9.eyJzdWIiOiJhdHRhY2tlciIsImlzcyI6InRhbG9zLXNlcnZpY2UiLCJleHAiOjk5OTk5OTk5OTl9.invalidsignatureXXXXXXXXXXXXXXXX"},
		// Base64url-encoded JSON with no signature part.
		{name: "eyJ prefix with no dot separators", credential: "eyJhbGciOiJub25lIn0"},
		// Looks like a JWT header but payload and sig are garbage.
		{name: "eyJ prefix truncated", credential: "eyJhbGciOiJFZERTQSJ9.garbage"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			_, _, err := env.verifier.VerifyAPIKey(ctx, tt.credential)
			require.Error(t, err, "adversarial eyJ credential must be rejected")
		})
	}
}

// TestVerifyAPIKey_MacaroonNIDMismatch verifies that a macaroon derived token minted for
// one network (NID-A) is rejected when verified in the context of another network (NID-B).
func TestVerifyAPIKey_MacaroonNIDMismatch(t *testing.T) {
	t.Parallel()

	ctx := t.Context()

	keyService, privateKey, signingKeyID := newDeterministicEdDSAKeyService(t)

	driver, err := testutil.InitDriver(t, "")
	require.NoError(t, err)
	t.Cleanup(func() { _ = driver.Close() })

	provider := newVerifierTestProvider(t, "test-secret-123-must-be-32chars!")
	require.NoError(t, provider.Set(ctx, config.KeyCredentialsDerivedTokensJWTSigningKeysURLs, []string{
		testutil.TestSigningKeyJWKSURLWithKey(t, privateKey, signingKeyID),
	}))

	tracker := lastused.New(ctx, driver, lastused.Config{
		QueueSize: 100, FlushSize: 100, FlushInterval: time.Hour, NumWorkers: 1,
	})
	t.Cleanup(tracker.Close)

	v := NewFromProvider(driver, provider, newNoopCache(), testutil.NewMockEmitter(), keyService, metrics.New(prometheus.NewRegistry()), tracker)

	// Mint a macaroon token claiming a *different* NID than the context NID.
	differentNID := "eeeeeeee-eeee-eeee-eeee-eeeeeeeeeeee"
	now := time.Now().UTC()

	macSigner, err := token.NewMacaroonSigner([]byte("test-secret-123-must-be-32chars!"), "talos-service", "mc")
	require.NoError(t, err)

	claims := token.NewClaims()
	claims.SetTokenID("mac-cross-tenant")
	claims.SetSubject("ffffffff-ffff-ffff-ffff-ffffffffffff")
	claims.SetIssuer("talos-service")
	claims.SetIssuedAt(now)
	claims.SetExpiration(now.Add(time.Hour))
	claims.SetNotBefore(now)
	claims.SetTokenType(token.TokenTypeDerived)
	claims.SetKeyID("ffffffff-ffff-ffff-ffff-ffffffffffff")
	claims.SetActorID("owner-mac-cross")
	claims.SetNetworkID(differentNID) // NID-B, but context will be NID-A (uuid.Nil)
	claims.SetScopes([]string{"read"})
	claims.SetMetadata(map[string]any{})

	macTok, err := macSigner.Sign(ctx, claims)
	require.NoError(t, err)

	// Verify in context with NID-A (uuid.Nil) — must fail.
	_, _, verifyErr := v.VerifyAPIKey(ctx, macTok)
	require.Error(t, verifyErr, "cross-tenant macaroon replay must be rejected")
}

func TestFailureEventLimiter_AllowsUpToLimit(t *testing.T) {
	t.Parallel()

	var lim failureEventLimiter
	for i := range failureEventRateLimit {
		assert.True(t, lim.allow("nid-1"), "call %d should be allowed", i+1)
	}
	assert.False(t, lim.allow("nid-1"), "call beyond the rate limit should be rejected")
}

func TestFailureEventLimiter_IndependentNIDs(t *testing.T) {
	t.Parallel()

	var lim failureEventLimiter

	// Exhaust limit for nid-a.
	for range failureEventRateLimit {
		lim.allow("nid-a")
	}
	assert.False(t, lim.allow("nid-a"), "nid-a should be exhausted")

	// nid-b must still have its full budget.
	for i := range failureEventRateLimit {
		assert.True(t, lim.allow("nid-b"), "nid-b call %d should be allowed", i+1)
	}
	assert.False(t, lim.allow("nid-b"), "nid-b should now be exhausted")
}

func TestFailureEventLimiter_WindowReset(t *testing.T) {
	t.Parallel()

	var lim failureEventLimiter

	// Exhaust the limit.
	for range failureEventRateLimit {
		lim.allow("nid-reset")
	}
	assert.False(t, lim.allow("nid-reset"), "should be exhausted before window reset")

	// Manually move the window start into the past so the next call sees an expired window.
	val, ok := lim.buckets.Load("nid-reset")
	require.True(t, ok)
	bucket, ok := val.(*failureEventBucket)
	require.True(t, ok, "bucket must be *failureEventBucket")
	bucket.mu.Lock()
	bucket.windowNs = time.Now().Add(-2 * failureEventWindow).UnixNano()
	bucket.mu.Unlock()

	// After the window resets, calls should be allowed again.
	assert.True(t, lim.allow("nid-reset"), "should be allowed after window reset")
}

func TestFailureEventLimiter_ConcurrentAccess(t *testing.T) {
	t.Parallel()

	var lim failureEventLimiter
	var allowed atomic.Int64
	var wg sync.WaitGroup

	const goroutines = 100
	wg.Add(goroutines)
	for range goroutines {
		go func() {
			defer wg.Done()
			if lim.allow("shared-nid") {
				allowed.Add(1)
			}
		}()
	}
	wg.Wait()

	assert.Equal(t, failureEventRateLimit, allowed.Load(),
		"exactly %d calls should be allowed across concurrent goroutines", failureEventRateLimit)
}

// TestBatchVerifyAPIKeys_ChecksumFailureMidBatch verifies that when one credential in a
// batch has an invalid checksum, the other credentials still verify successfully.
func TestBatchVerifyAPIKeys_ChecksumFailureMidBatch(t *testing.T) {
	t.Parallel()

	ctx := t.Context()
	const hmacSecret = "test-hmac-batch-checksum-fail-32chars"

	env := newTestVerifier(ctx, t)
	configureProviderForAPIKeys(ctx, t, env.provider, hmacSecret)

	// Create 3 valid keys.
	fullKey1, keyID1 := mustGenerateAndCreateAPIKey(ctx, t, env.driver, hmacSecret, "batch-key-1", "owner-1", []string{"read"})
	fullKey3, keyID3 := mustGenerateAndCreateAPIKey(ctx, t, env.driver, hmacSecret, "batch-key-3", "owner-3", []string{"write"})

	// Generate a key with a different HMAC secret so its checksum won't validate.
	badKey, _, err := crypto.GenerateAPIKey(ctx, "talos", []byte("wrong-hmac-secret-must-be-32char!"))
	require.NoError(t, err)

	results, err := env.verifier.BatchVerifyAPIKeys(ctx, []string{fullKey1, badKey, fullKey3})
	require.NoError(t, err)
	require.Len(t, results, 3)

	// First credential succeeds.
	require.NoError(t, results[0].Err)
	require.NotNil(t, results[0].Key)
	assert.Equal(t, keyID1, results[0].Key.KeyID)

	// Second credential fails with checksum error, normalized to ErrAPIKeyNotFound
	// to prevent enumeration of valid project keys via HMAC mismatch.
	require.Error(t, results[1].Err)
	assert.True(t, errors.Is(results[1].Err, errdef.ErrAPIKeyNotFound()),
		"expected ErrAPIKeyNotFound, got: %v", results[1].Err)
	assert.Nil(t, results[1].Key)

	// Third credential succeeds.
	require.NoError(t, results[2].Err)
	require.NotNil(t, results[2].Key)
	assert.Equal(t, keyID3, results[2].Key.KeyID)
}

// TestBatchVerifyAPIKeys_PartialDBMiss verifies that credentials whose keys exist in the
// DB return success while missing keys return not-found errors.
func TestBatchVerifyAPIKeys_PartialDBMiss(t *testing.T) {
	t.Parallel()

	ctx := t.Context()
	const hmacSecret = "test-hmac-batch-partial-miss-32chars!"

	env := newTestVerifier(ctx, t)
	configureProviderForAPIKeys(ctx, t, env.provider, hmacSecret)

	// Create only the first key in the DB.
	fullKey1, keyID1 := mustGenerateAndCreateAPIKey(ctx, t, env.driver, hmacSecret, "exists-key", "owner-exists", []string{"read"})

	// Generate a second key but do NOT create it in the DB.
	missingKey, _, err := crypto.GenerateAPIKey(ctx, "talos", []byte(hmacSecret))
	require.NoError(t, err)

	results, err := env.verifier.BatchVerifyAPIKeys(ctx, []string{fullKey1, missingKey})
	require.NoError(t, err)
	require.Len(t, results, 2)

	// First credential is found.
	require.NoError(t, results[0].Err)
	require.NotNil(t, results[0].Key)
	assert.Equal(t, keyID1, results[0].Key.KeyID)

	// Second credential is not found.
	require.Error(t, results[1].Err)
	assert.True(t, errors.Is(results[1].Err, errdef.ErrAPIKeyNotFound()),
		"expected ErrAPIKeyNotFound, got: %v", results[1].Err)
	assert.Nil(t, results[1].Key)
}

// TestBatchVerifyAPIKeys_MixIssuedAndImported verifies that a batch containing both an
// issued API key and an imported API key routes each to the correct verification path.
func TestBatchVerifyAPIKeys_MixIssuedAndImported(t *testing.T) {
	t.Parallel()

	ctx := t.Context()
	const hmacSecret = "test-hmac-batch-mix-types-32chars!!"

	env := newTestVerifier(ctx, t)
	configureProviderForAPIKeys(ctx, t, env.provider, hmacSecret)

	// Create an issued key.
	fullIssuedKey, issuedKeyID := mustGenerateAndCreateAPIKey(ctx, t, env.driver, hmacSecret, "issued-batch", "owner-issued", []string{"read"})

	// Create an imported key.
	importedCred := "imported-batch-credential-value"
	importedKeyID := mustCreateImportedKey(ctx, t, env.driver, importedCred, "imported-batch", json.RawMessage(`["write"]`))

	results, err := env.verifier.BatchVerifyAPIKeys(ctx, []string{fullIssuedKey, importedCred})
	require.NoError(t, err)
	require.Len(t, results, 2)

	// Issued key succeeds.
	require.NoError(t, results[0].Err)
	require.NotNil(t, results[0].Key)
	assert.Equal(t, issuedKeyID, results[0].Key.KeyID)

	// Imported key succeeds.
	require.NoError(t, results[1].Err)
	require.NotNil(t, results[1].Key)
	assert.Equal(t, importedKeyID, results[1].Key.KeyID)
}

// TestBatchVerifyAPIKeys_RevokedKey verifies that a revoked key in a batch returns an
// error while other keys in the same batch still succeed.
func TestBatchVerifyAPIKeys_RevokedKey(t *testing.T) {
	t.Parallel()

	ctx := t.Context()
	const hmacSecret = "test-hmac-batch-revoked-key-32chars!"

	env := newTestVerifier(ctx, t)
	configureProviderForAPIKeys(ctx, t, env.provider, hmacSecret)

	// Create two keys.
	activeKey, activeKeyID := mustGenerateAndCreateAPIKey(ctx, t, env.driver, hmacSecret, "active-batch", "owner-active", []string{"read"})
	revokedKey, revokedKeyID := mustGenerateAndCreateAPIKey(ctx, t, env.driver, hmacSecret, "revoked-batch", "owner-revoked", []string{"write"})

	// Revoke the second key.
	err := env.driver.RevokeIssuedAPIKey(ctx, persistencetypes.RevokeIssuedAPIKeyParams{
		KeyID:  revokedKeyID,
		Reason: int32(talosv2alpha1.RevocationReason_REVOCATION_REASON_KEY_COMPROMISE),
	})
	require.NoError(t, err)

	results, err := env.verifier.BatchVerifyAPIKeys(ctx, []string{activeKey, revokedKey})
	require.NoError(t, err)
	require.Len(t, results, 2)

	// Active key succeeds.
	require.NoError(t, results[0].Err)
	require.NotNil(t, results[0].Key)
	assert.Equal(t, activeKeyID, results[0].Key.KeyID)

	// Revoked key fails.
	require.Error(t, results[1].Err)
	assert.True(t, errors.Is(results[1].Err, errdef.ErrAPIKeyRevoked()),
		"expected ErrAPIKeyRevoked, got: %v", results[1].Err)
	assert.Nil(t, results[1].Key)
}

// reviewed - @aeneasr - 2026-03-27
