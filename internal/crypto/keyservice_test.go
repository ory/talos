package crypto

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"testing"
	"time"

	"github.com/gofrs/uuid"
	"github.com/lestrrat-go/jwx/v3/jwk"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/ory/herodot"

	"github.com/ory/talos/internal/contextx"

	talosconfig "github.com/ory/talos/internal/config"
	"github.com/ory/talos/internal/testutil"

	"github.com/ory/x/configx"
	"github.com/ory/x/httpx"
)

// newTestKeyServiceWithURL creates a KeyService backed by a provider with signing key URLs.
func newTestKeyServiceWithURL(t *testing.T, jwksURL string) *KeyService {
	t.Helper()
	provider := &tenantSigningURLProvider{
		urlsByNID: map[string][]string{
			// Default NID (uuid.Nil) gets the URL
			uuid.Nil.String(): {jwksURL},
		},
	}
	ks, err := NewKeyService(t.Context(), provider, httpx.NewResilientClient(), NoopKeyServiceMetrics())
	require.NoError(t, err)
	return ks
}

func TestKeyService_LoadSigningKeys(t *testing.T) {
	t.Parallel()

	ctx := context.WithValue(t.Context(), contextx.NIDKey{}, uuid.Nil)

	// Generate test Ed25519 key
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	require.NoError(t, err)

	jwksURL := testutil.TestSigningKeyJWKSURLWithKey(t, priv, "test-key-1")
	ks := newTestKeyServiceWithURL(t, jwksURL)

	t.Run("LoadSigningKeys returns keys", func(t *testing.T) {
		loaded, err := ks.LoadSigningKeys(ctx)
		require.NoError(t, err)
		assert.Equal(t, 1, loaded.Len())
	})

	t.Run("ListActiveSigningKeys returns keys", func(t *testing.T) {
		loaded, err := ks.ListActiveSigningKeys(ctx)
		require.NoError(t, err)
		assert.Equal(t, 1, loaded.Len())
	})

	t.Run("GetActiveSigningKey returns first key", func(t *testing.T) {
		activeKey, err := ks.GetActiveSigningKey(ctx)
		require.NoError(t, err)
		kid, _ := activeKey.KeyID()
		assert.Equal(t, "test-key-1", kid)
	})

	t.Run("GetActiveSigningKey returns key with public component", func(t *testing.T) {
		activeKey, err := ks.GetActiveSigningKey(ctx)
		require.NoError(t, err)

		// Verify we can extract the public key
		var rawKey any
		err = jwk.Export(activeKey, &rawKey)
		require.NoError(t, err)

		// For Ed25519, rawKey should be ed25519.PrivateKey
		privKey, ok := rawKey.(ed25519.PrivateKey)
		require.True(t, ok, "expected ed25519.PrivateKey")

		// Extract public key
		pubKey := privKey.Public()
		assert.NotNil(t, pubKey)
		assert.Equal(t, pub, pubKey)
	})
}

func TestKeyServiceMultipleKeys(t *testing.T) {
	t.Parallel()

	ctx := context.WithValue(t.Context(), contextx.NIDKey{}, uuid.Nil)

	// Create key set with multiple keys
	keySet := jwk.NewSet()

	// Add first key (no usage specified)
	_, priv1, err := ed25519.GenerateKey(rand.Reader)
	require.NoError(t, err)
	key1, err := jwk.Import(priv1)
	require.NoError(t, err)
	err = key1.Set(jwk.KeyIDKey, "key-1")
	require.NoError(t, err)
	err = keySet.AddKey(key1)
	require.NoError(t, err)

	// Add second key (with "sig" usage)
	_, priv2, err := ed25519.GenerateKey(rand.Reader)
	require.NoError(t, err)
	key2, err := jwk.Import(priv2)
	require.NoError(t, err)
	err = key2.Set(jwk.KeyIDKey, "key-2")
	require.NoError(t, err)
	err = key2.Set(jwk.KeyUsageKey, "sig")
	require.NoError(t, err)
	err = keySet.AddKey(key2)
	require.NoError(t, err)

	// Serialize to base64:// URL
	data, err := json.Marshal(keySet)
	require.NoError(t, err)
	jwksURL := "base64://" + base64.StdEncoding.EncodeToString(data)

	ks := newTestKeyServiceWithURL(t, jwksURL)

	t.Run("GetActiveSigningKey prefers key with sig usage", func(t *testing.T) {
		activeKey, err := ks.GetActiveSigningKey(ctx)
		require.NoError(t, err)
		// Should return key-2 because it has "use": "sig"
		kid, _ := activeKey.KeyID()
		assert.Equal(t, "key-2", kid)
	})

	t.Run("ListActiveSigningKeys returns all keys", func(t *testing.T) {
		loaded, err := ks.ListActiveSigningKeys(ctx)
		require.NoError(t, err)
		assert.Equal(t, 2, loaded.Len())
	})
}

// twoKeyJWKSURL is a local convenience wrapper that builds a base64:// JWKS
// URL with kid="key-1" and kid="key-2" via testutil.TestTwoKeyJWKSURL.
func twoKeyJWKSURL(t *testing.T, useSigOnSecond bool) string {
	t.Helper()
	return testutil.TestTwoKeyJWKSURL(t, "key-1", "key-2", useSigOnSecond)
}

func TestKeyService_GetActiveSigningKey_KIDHint(t *testing.T) {
	t.Parallel()

	ctx := context.WithValue(t.Context(), contextx.NIDKey{}, uuid.Nil)
	nilNID := uuid.Nil.String()

	t.Run("kid hint matches selects that key", func(t *testing.T) {
		t.Parallel()

		provider := &tenantSigningURLProvider{
			urlsByNID:         map[string][]string{nilNID: {twoKeyJWKSURL(t, true)}},
			signingKeyIDByNID: map[string]string{nilNID: "key-1"},
		}
		ks, err := NewKeyService(ctx, provider, httpx.NewResilientClient(), NoopKeyServiceMetrics())
		require.NoError(t, err)

		active, err := ks.GetActiveSigningKey(ctx)
		require.NoError(t, err)
		kid, _ := active.KeyID()
		assert.Equal(t, "key-1", kid, "kid hint must override use:sig preference")
	})

	t.Run("kid hint missing returns InternalError", func(t *testing.T) {
		t.Parallel()

		provider := &tenantSigningURLProvider{
			urlsByNID:         map[string][]string{nilNID: {twoKeyJWKSURL(t, true)}},
			signingKeyIDByNID: map[string]string{nilNID: "key-unknown"},
		}
		ks, err := NewKeyService(ctx, provider, httpx.NewResilientClient(), NoopKeyServiceMetrics())
		require.NoError(t, err)

		_, err = ks.GetActiveSigningKey(ctx)
		require.Error(t, err)

		var herr *herodot.DefaultError
		require.ErrorAs(t, err, &herr)
		assert.Equal(t, http.StatusInternalServerError, herr.StatusCode())
		assert.Equal(t, "key-unknown", herr.Details()["signing_key_id"])
	})

	t.Run("no kid hint prefers use:sig", func(t *testing.T) {
		t.Parallel()

		provider := &tenantSigningURLProvider{
			urlsByNID: map[string][]string{nilNID: {twoKeyJWKSURL(t, true)}},
		}
		ks, err := NewKeyService(ctx, provider, httpx.NewResilientClient(), NoopKeyServiceMetrics())
		require.NoError(t, err)

		active, err := ks.GetActiveSigningKey(ctx)
		require.NoError(t, err)
		kid, _ := active.KeyID()
		assert.Equal(t, "key-2", kid)
	})

	t.Run("no kid hint and no use:sig returns first key", func(t *testing.T) {
		t.Parallel()

		provider := &tenantSigningURLProvider{
			urlsByNID: map[string][]string{nilNID: {twoKeyJWKSURL(t, false)}},
		}
		ks, err := NewKeyService(ctx, provider, httpx.NewResilientClient(), NoopKeyServiceMetrics())
		require.NoError(t, err)

		active, err := ks.GetActiveSigningKey(ctx)
		require.NoError(t, err)
		kid, _ := active.KeyID()
		assert.Equal(t, "key-1", kid)
	})

	t.Run("empty kid hint falls back to default selection", func(t *testing.T) {
		t.Parallel()

		provider := &tenantSigningURLProvider{
			urlsByNID:         map[string][]string{nilNID: {twoKeyJWKSURL(t, true)}},
			signingKeyIDByNID: map[string]string{nilNID: ""},
		}
		ks, err := NewKeyService(ctx, provider, httpx.NewResilientClient(), NoopKeyServiceMetrics())
		require.NoError(t, err)

		active, err := ks.GetActiveSigningKey(ctx)
		require.NoError(t, err)
		kid, _ := active.KeyID()
		assert.Equal(t, "key-2", kid, "empty kid hint should not override use:sig selection")
	})
}

func TestKeyService_NoURLsConfigured(t *testing.T) {
	t.Parallel()

	ctx := context.WithValue(t.Context(), contextx.NIDKey{}, uuid.Nil)

	// Provider with no signing key URLs
	provider := &tenantSigningURLProvider{
		urlsByNID: map[string][]string{},
	}
	ks, err := NewKeyService(t.Context(), provider, httpx.NewResilientClient(), NoopKeyServiceMetrics())
	require.NoError(t, err)

	t.Run("GetActiveSigningKey returns error when no URLs configured", func(t *testing.T) {
		_, err := ks.GetActiveSigningKey(ctx)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "no signing key URLs configured")
	})

	t.Run("LoadSigningKeys returns error when no URLs configured", func(t *testing.T) {
		_, err := ks.LoadSigningKeys(ctx)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "no signing key URLs configured")
	})
}

func TestKeyService_ErrorsDoNotLeakKeyMaterial(t *testing.T) {
	t.Parallel()

	ctx := context.WithValue(t.Context(), contextx.NIDKey{}, uuid.Nil)

	t.Run("fetch failure does not leak the base64 payload", func(t *testing.T) {
		t.Parallel()

		// An invalid base64 payload with a recognizable marker stands in for a private JWKS.
		const secretPayload = "SECRETMARKER!!!not-base64"
		ks := newTestKeyServiceWithURL(t, "base64://"+secretPayload)

		_, err := ks.LoadSigningKeys(ctx)
		require.Error(t, err)
		assert.NotContains(t, err.Error(), secretPayload)
		assert.NotContains(t, err.Error(), "SECRETMARKER")
		assert.Contains(t, err.Error(), "urls[0]")
	})

	t.Run("parse failure does not leak decoded key material", func(t *testing.T) {
		t.Parallel()

		// Valid base64 but invalid JWKS so jwk.Parse fails after a successful fetch.
		const secretJWKS = `{"keys":[{"kty":"oct","k":"SECRETKEYMATERIALAAAA"`
		encoded := base64.StdEncoding.EncodeToString([]byte(secretJWKS))
		ks := newTestKeyServiceWithURL(t, "base64://"+encoded)

		_, err := ks.LoadSigningKeys(ctx)
		require.Error(t, err)
		assert.NotContains(t, err.Error(), "SECRETKEYMATERIAL")
		assert.NotContains(t, err.Error(), encoded)
		assert.Contains(t, err.Error(), "urls[0]")
	})
}

type tenantSigningURLProvider struct {
	urlsByNID         map[string][]string
	signingKeyIDByNID map[string]string
}

func (p *tenantSigningURLProvider) String(ctx context.Context, key talosconfig.Key) string {
	if key != talosconfig.KeyCredentialsDerivedTokensJWTSigningKeyID {
		return ""
	}
	return p.signingKeyIDByNID[contextx.NetworkIDFromContext(ctx).String()]
}

func (p *tenantSigningURLProvider) Strings(ctx context.Context, key talosconfig.Key) []string {
	if key != talosconfig.KeyCredentialsDerivedTokensJWTSigningKeysURLs {
		return nil
	}

	return p.urlsByNID[contextx.NetworkIDFromContext(ctx).String()]
}
func (p *tenantSigningURLProvider) Bool(_ context.Context, _ talosconfig.Key) bool { return false }
func (p *tenantSigningURLProvider) Int(_ context.Context, _ talosconfig.Key) int   { return 0 }
func (p *tenantSigningURLProvider) Float64(_ context.Context, _ talosconfig.Key) float64 {
	return 0
}

func (p *tenantSigningURLProvider) Duration(_ context.Context, _ talosconfig.Key) time.Duration {
	return 0
}
func (p *tenantSigningURLProvider) Get(_ context.Context, _ talosconfig.Key) any { return nil }
func (p *tenantSigningURLProvider) Set(_ context.Context, _ talosconfig.Key, _ any) error {
	return nil
}

func (p *tenantSigningURLProvider) Unmarshal(_ context.Context, _ talosconfig.Key, _ any) error {
	return nil
}

func (p *tenantSigningURLProvider) ActiveRetiredValues(_ context.Context, _ talosconfig.Key) ([]string, error) {
	return nil, nil
}

func (p *tenantSigningURLProvider) UnderlyingProvider(_ context.Context) *configx.Provider {
	return nil
}

func encodeJWKSURL(jwks string) string {
	return "base64://" + base64.StdEncoding.EncodeToString([]byte(jwks))
}

func firstKeyID(t *testing.T, set jwk.Set) string {
	t.Helper()

	key, ok := set.Key(0)
	require.True(t, ok)
	kid, _ := key.KeyID()
	return kid
}

func TestKeyService_LoadSigningKeysIsTenantScoped(t *testing.T) {
	t.Parallel()

	const tenant1JWKS = `{"keys":[{"kty":"oct","k":"GawgguFyGrWKav7AX4VKUg","kid":"tenant1-key","use":"sig","alg":"HS256"}]}`
	const tenant2JWKS = `{"keys":[{"kty":"oct","k":"hJtXIZ2uSN5kbQfbtTNWbg","kid":"tenant2-key","use":"sig","alg":"HS256"}]}`

	tenant1ID := uuid.Must(uuid.FromString("11111111-1111-1111-1111-111111111111"))
	tenant2ID := uuid.Must(uuid.FromString("22222222-2222-2222-2222-222222222222"))

	provider := &tenantSigningURLProvider{
		urlsByNID: map[string][]string{
			tenant1ID.String(): {encodeJWKSURL(tenant1JWKS)},
			tenant2ID.String(): {encodeJWKSURL(tenant2JWKS)},
		},
	}

	ks, err := NewKeyService(t.Context(), provider, httpx.NewResilientClient(), NoopKeyServiceMetrics())
	require.NoError(t, err)

	tenant1Ctx := context.WithValue(t.Context(), contextx.NIDKey{}, tenant1ID)
	tenant2Ctx := context.WithValue(t.Context(), contextx.NIDKey{}, tenant2ID)

	keysTenant1, err := ks.LoadSigningKeys(tenant1Ctx)
	require.NoError(t, err)
	assert.Equal(t, "tenant1-key", firstKeyID(t, keysTenant1))

	keysTenant2, err := ks.LoadSigningKeys(tenant2Ctx)
	require.NoError(t, err)
	assert.Equal(t, "tenant2-key", firstKeyID(t, keysTenant2))

	cachedTenant1, err := ks.LoadSigningKeys(tenant1Ctx)
	require.NoError(t, err)
	assert.Equal(t, "tenant1-key", firstKeyID(t, cachedTenant1))
}

// NOT reviewed - @aeneasr - 2026-03-26 - needs re-review once keyservice is changed.
