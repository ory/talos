package config

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/cockroachdb/errors"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// createTestProvider creates a provider with minimal test config including required secrets and issuer
func createTestProvider(t *testing.T) (*Provider, error) {
	t.Helper()
	ctx := t.Context()

	// Create minimal config file with required secrets and credentials issuer
	configContent := `
secrets:
  hmac:
    current: "test-hmac-secret-for-config-provider-32chars"
    retired: []
credentials:
  issuer: "https://test.talos.local"
`
	configFile := filepath.Join(t.TempDir(), "config.yaml")
	err := os.WriteFile(configFile, []byte(configContent), 0o600)
	require.NoError(t, err)

	return NewProvider(ctx, configFile)
}

func setupProviderWithConfig(t *testing.T, configContent string) (*Provider, context.Context) {
	t.Helper()
	ctx := t.Context()

	// Add required secrets to config content if not present
	if configContent != "" && !strings.Contains(configContent, "secrets:") {
		configContent = `secrets:
  hmac:
    current: "test-hmac-secret-for-config-provider-32chars"
    retired: []
` + configContent
	}

	// Add required credentials.issuer if not present
	// Check if there's already an issuer field, or if there's no credentials section at all
	if configContent != "" && !strings.Contains(configContent, "issuer:") {
		if strings.Contains(configContent, "credentials:") {
			// Credentials section exists but no issuer - add issuer to the credentials section
			// Find the credentials section and append issuer after it
			configContent = strings.Replace(configContent, "credentials:", "credentials:\n  issuer: \"https://test.talos.local\"", 1)
		} else {
			// No credentials section at all - add complete credentials section
			configContent += `
credentials:
  issuer: "https://test.talos.local"
`
		}
	}

	configFile := filepath.Join(t.TempDir(), "config.yaml")
	err := os.WriteFile(configFile, []byte(configContent), 0o600)
	require.NoError(t, err)

	provider, err := NewProvider(ctx, configFile)
	require.NoError(t, err)

	return provider, ctx
}

func TestNewProvider(t *testing.T) {
	t.Parallel()
	ctx := t.Context()

	t.Run("creates provider with no config files", func(t *testing.T) {
		t.Parallel()

		provider, err := createTestProvider(t)
		require.NoError(t, err)
		require.NotNil(t, provider)
		assert.Equal(t, "0.0.0.0", provider.String(ctx, KeyServeHTTPHost))
		assert.Equal(t, 4420, provider.Int(ctx, KeyServeHTTPPort))
	})

	t.Run("creates provider with config file", func(t *testing.T) {
		t.Parallel()

		provider, cfgCtx := setupProviderWithConfig(t, `
serve:
  http:
    host: "127.0.0.1"
    port: 9999
    cors:
      max_age: 3600
log:
  level: "debug"
tracing:
  enabled: false
  sample_rate: 0.75
credentials:
  derived_tokens:
    default_ttl: "2h"
`)

		assert.Equal(t, "127.0.0.1", provider.String(cfgCtx, KeyServeHTTPHost))
		assert.Equal(t, 9999, provider.Int(cfgCtx, KeyServeHTTPPort))
		assert.Equal(t, "debug", provider.String(cfgCtx, KeyLogLevel))
		assert.False(t, provider.Bool(cfgCtx, KeyTracingEnabled))
		assert.Equal(t, 3600, provider.Int(cfgCtx, KeyServeHTTPCORSMaxAge))
		assert.Equal(t, 2*time.Hour, provider.Duration(cfgCtx, KeyCredentialsDerivedTokensDefaultTTL))
		assert.InDelta(t, 0.75, provider.Float64(cfgCtx, KeyTracingSampleRate), 0.0001)
	})
}

// TestImmutableKeysAreRealConfigKeys guards against the phantom-key regression:
// the hot-reload immutability guard previously watched "tls.key" (no such key)
// and "redis.password" (the real key is "cache.redis.password"), so rotating the
// Redis password at runtime was silently accepted while the live connection kept
// the old value. The immutables are now the typed key constants; this test
// asserts they resolve to the real, addressable schema paths.
func TestImmutableKeysAreRealConfigKeys(t *testing.T) {
	t.Parallel()

	// Lock the immutable set's key paths so a rename can't reintroduce a phantom.
	assert.Equal(t, "db.dsn", KeyDBDSN.String())
	assert.Equal(t, "cache.redis.password", KeyCacheRedisPassword.String())

	// Prove cache.redis.password is a real, readable key (not phantom) by setting
	// it via config and reading it back through the typed constant.
	provider, ctx := setupProviderWithConfig(t, `
cache:
  redis:
    password: "s3cret-rotation-value"
`)
	assert.Equal(t, "s3cret-rotation-value", provider.String(ctx, KeyCacheRedisPassword))
}

func TestProvider_String(t *testing.T) {
	t.Parallel()
	ctx := t.Context()

	provider, err := createTestProvider(t)
	require.NoError(t, err)
	require.NoError(t, provider.Set(ctx, KeyServeHTTPHost, "localhost"))
	require.NoError(t, provider.Set(ctx, KeyLogLevel, "debug"))

	assert.Equal(t, "localhost", provider.String(ctx, KeyServeHTTPHost))
	assert.Equal(t, "debug", provider.String(ctx, KeyLogLevel))
}

func TestProvider_Bool(t *testing.T) {
	t.Parallel()
	ctx := t.Context()

	provider, err := createTestProvider(t)
	require.NoError(t, err)
	require.NoError(t, provider.Set(ctx, KeyTracingEnabled, false))

	assert.False(t, provider.Bool(ctx, KeyTracingEnabled))
}

func TestProvider_Int(t *testing.T) {
	t.Parallel()
	ctx := t.Context()

	provider, err := createTestProvider(t)
	require.NoError(t, err)
	require.NoError(t, provider.Set(ctx, KeyServeHTTPCORSMaxAge, 3600))

	assert.Equal(t, 3600, provider.Int(ctx, KeyServeHTTPCORSMaxAge))
}

func TestProvider_Duration(t *testing.T) {
	t.Parallel()
	ctx := t.Context()

	provider, err := createTestProvider(t)
	require.NoError(t, err)
	require.NoError(t, provider.Set(ctx, KeyCredentialsDerivedTokensDefaultTTL, "2h"))

	assert.Equal(t, 2*time.Hour, provider.Duration(ctx, KeyCredentialsDerivedTokensDefaultTTL))
}

func TestProvider_ActiveRetiredValues(t *testing.T) {
	t.Parallel()

	future := time.Now().UTC().Add(time.Hour).Format(time.RFC3339)
	past := time.Now().UTC().Add(-time.Hour).Format(time.RFC3339)

	// A YAML config carrying retired issuers in the new object shape: one without
	// expiry (never expires), one with a future expiry (still active), and one
	// already expired (dropped). Uses issuer_retired because its value has no
	// 32-char minimum, keeping the fixture readable.
	provider, ctx := setupProviderWithConfig(t, `
credentials:
  issuer: "https://test.talos.local"
  issuer_retired:
    - value: "https://never.example.com"
    - value: "https://future.example.com"
      expires_at: "`+future+`"
    - value: "https://past.example.com"
      expires_at: "`+past+`"
`)

	active, err := provider.ActiveRetiredValues(ctx, KeyCredentialsIssuerRetired)
	require.NoError(t, err)
	assert.Equal(t, []string{
		"https://never.example.com",
		"https://future.example.com",
	}, active, "unset and future expiry are kept, past expiry is dropped")
}

func TestProvider_ActiveRetiredValues_Empty(t *testing.T) {
	t.Parallel()

	provider, err := createTestProvider(t)
	require.NoError(t, err)

	active, err := provider.ActiveRetiredValues(t.Context(), KeyCredentialsIssuerRetired)
	require.NoError(t, err)
	assert.Empty(t, active)
}

func TestProvider_ActiveRetiredValues_LegacyAndMixedShapes(t *testing.T) {
	t.Parallel()

	future := time.Now().UTC().Add(time.Hour).Format(time.RFC3339)
	past := time.Now().UTC().Add(-time.Hour).Format(time.RFC3339)

	// Config written before retired values gained expiry stored bare strings.
	// They must still validate and be treated as never-expiring, including when
	// mixed with the new object shape in the same array.
	provider, ctx := setupProviderWithConfig(t, `
credentials:
  issuer: "https://test.talos.local"
  issuer_retired:
    - "https://legacy.example.com"
    - value: "https://future.example.com"
      expires_at: "`+future+`"
    - value: "https://past.example.com"
      expires_at: "`+past+`"
`)

	active, err := provider.ActiveRetiredValues(ctx, KeyCredentialsIssuerRetired)
	require.NoError(t, err)
	assert.Equal(t, []string{
		"https://legacy.example.com",
		"https://future.example.com",
	}, active, "legacy bare string never expires; object entries still filter on expiry")
}

func TestProvider_ActiveRetiredValues_LegacyHMACString(t *testing.T) {
	t.Parallel()

	// A retired HMAC secret persisted in the legacy bare-string form must still
	// validate against the 32-char minimum and be accepted for verification.
	provider, ctx := setupProviderWithConfig(t, `
secrets:
  hmac:
    current: "test-hmac-secret-for-config-provider-32chars"
    retired:
      - "legacy-retired-hmac-secret-32-characters-long"
`)

	active, err := provider.ActiveRetiredValues(ctx, KeySecretsHMACRetired)
	require.NoError(t, err)
	assert.Equal(t, []string{"legacy-retired-hmac-secret-32-characters-long"}, active)
}

// fixedRetiredUnmarshaler feeds a controlled raw slice into
// FilterActiveRetiredValues. The schema's oneOf(string, object) constraint makes
// the real provider reject malformed retired entries at load and on Set, so a
// malformed entry can only reach the filter from a source that skips schema
// validation. This seam supplies exactly that input to prove the filter degrades
// gracefully instead of failing the whole call.
type fixedRetiredUnmarshaler []any

func (f fixedRetiredUnmarshaler) Unmarshal(_ context.Context, _ Key, value any) error {
	out, ok := value.(*[]any)
	if !ok {
		return errors.Errorf("unexpected unmarshal target %T", value)
	}
	*out = []any(f)
	return nil
}

func TestFilterActiveRetiredValues_SkipsMalformed(t *testing.T) {
	t.Parallel()

	future := time.Now().UTC().Add(time.Hour).Format(time.RFC3339)
	past := time.Now().UTC().Add(-time.Hour).Format(time.RFC3339)

	raw := fixedRetiredUnmarshaler{
		"https://legacy.example.com", // bare string, never expires
		map[string]any{"value": "https://future.example.com", "expires_at": future},   // active
		map[string]any{"value": "https://past.example.com", "expires_at": past},       // expired, dropped
		map[string]any{"value": "https://bad-date.example.com", "expires_at": "nope"}, // malformed, skipped
		42, // wrong element type, skipped
		map[string]any{"value": "https://bad-bool.example.com", "expires_at": true}, // wrong expires_at type, skipped
		map[string]any{"value": "https://trailing.example.com"},                     // never expires
	}

	active, err := FilterActiveRetiredValues(t.Context(), raw, KeyCredentialsIssuerRetired)
	require.NoError(t, err, "a malformed entry must be skipped, not fail the whole key")
	assert.Equal(t, []string{
		"https://legacy.example.com",
		"https://future.example.com",
		"https://trailing.example.com",
	}, active, "valid entries survive around the skipped and expired ones")
}

// errRetiredUnmarshaler simulates a whole-key unmarshal failure (e.g. the value
// is not an array at all), which must still fail closed.
type errRetiredUnmarshaler struct{}

func (errRetiredUnmarshaler) Unmarshal(_ context.Context, _ Key, _ any) error {
	return errors.New("boom")
}

func TestFilterActiveRetiredValues_WholeKeyUnmarshalFails(t *testing.T) {
	t.Parallel()

	active, err := FilterActiveRetiredValues(t.Context(), errRetiredUnmarshaler{}, KeySecretsHMACRetired)
	require.Error(t, err, "a whole-key unmarshal failure must fail closed")
	assert.Nil(t, active)
}

func TestIsActiveAt(t *testing.T) {
	t.Parallel()

	now := time.Now().UTC()

	assert.True(t, isActiveAt(now, time.Time{}), "zero expiry never expires")
	assert.True(t, isActiveAt(now, now.Add(time.Nanosecond)), "expiry just after now is still active")
	assert.False(t, isActiveAt(now, now), "expiry exactly at now is expired (exclusive boundary)")
	assert.False(t, isActiveAt(now, now.Add(-time.Nanosecond)), "expiry just before now is expired")
}

func TestParseRetiredValue(t *testing.T) {
	t.Parallel()

	when := time.Date(2030, 1, 2, 3, 4, 5, 0, time.UTC)

	t.Run("bare string never expires", func(t *testing.T) {
		t.Parallel()
		value, expiresAt, err := parseRetiredValue("https://legacy.example.com")
		require.NoError(t, err)
		assert.Equal(t, "https://legacy.example.com", value)
		assert.True(t, expiresAt.IsZero())
	})

	t.Run("object with expiry", func(t *testing.T) {
		t.Parallel()
		value, expiresAt, err := parseRetiredValue(map[string]any{
			"value":      "https://future.example.com",
			"expires_at": when.Format(time.RFC3339),
		})
		require.NoError(t, err)
		assert.Equal(t, "https://future.example.com", value)
		assert.Equal(t, when, expiresAt)
	})

	t.Run("object without expiry", func(t *testing.T) {
		t.Parallel()
		value, expiresAt, err := parseRetiredValue(map[string]any{"value": "https://x.example.com"})
		require.NoError(t, err)
		assert.Equal(t, "https://x.example.com", value)
		assert.True(t, expiresAt.IsZero())
	})

	t.Run("malformed expires_at errors", func(t *testing.T) {
		t.Parallel()
		_, _, err := parseRetiredValue(map[string]any{"value": "https://x.example.com", "expires_at": "not-a-date"})
		require.Error(t, err)
	})

	t.Run("wrong element type errors", func(t *testing.T) {
		t.Parallel()
		_, _, err := parseRetiredValue(42)
		require.Error(t, err)
	})
}

func TestParseExpiresAt(t *testing.T) {
	t.Parallel()

	when := time.Date(2030, 1, 2, 3, 4, 5, 0, time.UTC)

	t.Run("nil never expires", func(t *testing.T) {
		t.Parallel()
		got, err := parseExpiresAt(nil)
		require.NoError(t, err)
		assert.True(t, got.IsZero())
	})

	t.Run("empty string never expires", func(t *testing.T) {
		t.Parallel()
		got, err := parseExpiresAt("")
		require.NoError(t, err)
		assert.True(t, got.IsZero())
	})

	t.Run("time.Time is normalized to UTC", func(t *testing.T) {
		t.Parallel()
		got, err := parseExpiresAt(when.In(time.FixedZone("x", 3600)))
		require.NoError(t, err)
		assert.Equal(t, when, got)
	})

	t.Run("RFC3339 string", func(t *testing.T) {
		t.Parallel()
		got, err := parseExpiresAt(when.Format(time.RFC3339))
		require.NoError(t, err)
		assert.Equal(t, when, got)
	})

	t.Run("non-RFC3339 string errors", func(t *testing.T) {
		t.Parallel()
		_, err := parseExpiresAt("not-a-date")
		require.Error(t, err)
	})

	t.Run("wrong type errors", func(t *testing.T) {
		t.Parallel()
		_, err := parseExpiresAt(true)
		require.Error(t, err)
	})
}

func TestProvider_Float64(t *testing.T) {
	t.Parallel()
	ctx := t.Context()

	provider, err := createTestProvider(t)
	require.NoError(t, err)
	require.NoError(t, provider.Set(ctx, KeyTracingSampleRate, 0.5))

	assert.InDelta(t, 0.5, provider.Float64(ctx, KeyTracingSampleRate), 0.0001)
}

func TestNewProvider_RequiresSecretsAtSchemaLevel(t *testing.T) {
	t.Parallel()
	ctx := t.Context()

	tests := []struct {
		name   string
		config string
	}{
		{
			name: "missing secrets",
			config: `
credentials:
  issuer: "https://test.talos.local"
`,
		},
		{
			name: "empty secrets.hmac.current",
			config: `
secrets:
  hmac:
    current: ""
credentials:
  issuer: "https://test.talos.local"
`,
		},
		{
			name: "missing secrets.hmac.current",
			config: `
secrets:
  hmac:
    retired: []
credentials:
  issuer: "https://test.talos.local"
`,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			configFile := filepath.Join(t.TempDir(), "config.yaml")
			require.NoError(t, os.WriteFile(configFile, []byte(tt.config), 0o600))

			_, err := NewProvider(ctx, configFile)
			require.Error(t, err, "schema must reject config without required secrets")
		})
	}
}

// reviewed - @aeneasr - 2026-03-25
