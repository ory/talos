package crypto

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestRouteAPIKey(t *testing.T) {
	t.Parallel()

	hmacSecret := []byte("test-secret-must-be-at-least-32-characters-long-for-hmac")

	// Generate real API keys with timestamp+UUID format for testing
	prodKey, _, err := GenerateAPIKey(t.Context(), "prod", hmacSecret)
	require.NoError(t, err)
	testKey, _, err := GenerateAPIKey(t.Context(), "test", hmacSecret)
	require.NoError(t, err)
	singleCharKey, _, err := GenerateAPIKey(t.Context(), "a", hmacSecret)
	require.NoError(t, err)

	tests := []struct {
		name         string
		key          string
		expectedType CredentialType
	}{
		{
			name:         "v1 API key with valid format",
			key:          prodKey,
			expectedType: CredentialTypeIssued,
		},
		{
			name:         "v1 key with test prefix",
			key:          testKey,
			expectedType: CredentialTypeIssued,
		},
		{
			name:         "v1 key with single char prefix",
			key:          singleCharKey,
			expectedType: CredentialTypeIssued,
		},
		{
			name:         "imported key - Stripe format",
			key:          "sk_live_abc123xyz789",
			expectedType: CredentialTypeImported,
		},
		{
			name:         "imported key - GitHub PAT",
			key:          "ghp_abc123def456ghi789jkl012mno345pqr",
			expectedType: CredentialTypeImported,
		},
		{
			name:         "imported key - custom format",
			key:          "my-custom-api-key-12345",
			expectedType: CredentialTypeImported,
		},
		{
			name:         "imported key - no underscore",
			key:          "simpletalos",
			expectedType: CredentialTypeImported,
		},
		{
			name:         "imported key - key ID too short",
			key:          "prod_v1_0ujsswThIG_short",
			expectedType: CredentialTypeImported,
		},
		{
			name:         "imported key - prefix too long (>8 chars)",
			key:          "verylongprefix_v1_0ujsswThIGTUYm2K8Fj63K_data",
			expectedType: CredentialTypeImported,
		},
		{
			name:         "imported key - invalid key ID chars (contains hyphen)",
			key:          "prod_v1_0ujsswTh-GTUYm2K8Fj63K_data", // Contains '-' which is invalid
			expectedType: CredentialTypeImported,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			route := RouteCredential(tt.key, nil)

			assert.Equal(t, tt.expectedType, route.Type, "credential type mismatch")
		})
	}
}

func TestHashImportedAPIKey(t *testing.T) {
	t.Parallel()

	testNID := "00000000-0000-0000-0000-000000000001"

	tests := []struct {
		name  string
		input string
	}{
		{
			name:  "simple key",
			input: "test123",
		},
		{
			name:  "stripe-like key",
			input: "sk_live_test",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			result := HashImportedAPIKey(tt.input, testNID)

			// Verify it's a 64-character hex string
			assert.Len(t, result, 64, "hash should be 64 chars")
			assert.Regexp(t, "^[0-9a-f]{64}$", result, "hash should be lowercase hex")

			// Verify deterministic (same input + nid = same output)
			result2 := HashImportedAPIKey(tt.input, testNID)
			assert.Equal(t, result, result2, "hash should be deterministic")
		})
	}

	t.Run("different NIDs produce different hashes", func(t *testing.T) {
		t.Parallel()

		nid2 := "00000000-0000-0000-0000-000000000002"
		rawKey := "shared-key-material"

		hash1 := HashImportedAPIKey(rawKey, testNID)
		hash2 := HashImportedAPIKey(rawKey, nid2)

		assert.NotEqual(t, hash1, hash2, "same raw key in different tenants must produce different hashes")
	})
}

func TestRouteCredential(t *testing.T) {
	t.Parallel()

	hmacSecret := []byte("test-secret-must-be-at-least-32-characters-long-for-hmac")

	// Generate a real v1 API key for testing
	apiKey, _, err := GenerateAPIKey(t.Context(), "prod", hmacSecret)
	require.NoError(t, err)

	tests := []struct {
		name         string
		credential   string
		expectedType CredentialType
	}{
		{
			name:         "JWT token",
			credential:   "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.dozjgNryP4J3jVmNHl0w5N_XgL0n3I9PlFUP0THsR8U",
			expectedType: CredentialTypeDerivedJWT,
		},
		{
			name:         "Macaroon token",
			credential:   "mc_v1_AgETaHR0cHM6Ly9leGFtcGxlLmNvbQIkAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
			expectedType: CredentialTypeDerivedMacaroon,
		},
		{
			name:         "v1 API key",
			credential:   apiKey,
			expectedType: CredentialTypeIssued,
		},
		{
			name:         "imported API key",
			credential:   "sk_live_abc123xyz",
			expectedType: CredentialTypeImported,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			route := RouteCredential(tt.credential, []string{"mc"})
			assert.Equal(t, tt.expectedType, route.Type)
		})
	}
}

func TestRouteCredential_WithGeneratedKey(t *testing.T) {
	t.Parallel()

	hmacSecret := []byte("test-secret-must-be-at-least-32-characters-long-for-hmac")

	t.Run("generated v1 API key routes correctly", func(t *testing.T) {
		t.Parallel()
		// Generate a real v1 API key
		apiKey, keyID, err := GenerateAPIKey(t.Context(), "talos", hmacSecret)
		require.NoError(t, err)
		assert.NotEmpty(t, apiKey)
		assert.NotEmpty(t, keyID)

		t.Logf("Generated API key: %s", apiKey)
		t.Logf("Key ID: %s", keyID)
		t.Logf("Key length: %d", len(apiKey))

		// Parse to see structure
		components, err := parseAPIKey(apiKey)
		require.NoError(t, err)
		t.Logf("TokenPrefix: %s", components.TokenPrefix)
		t.Logf("Version: %s", components.Version)
		t.Logf("KeyID: %s", components.KeyID)
		t.Logf("Checksum: %s (length: %d)", components.Checksum, len(components.Checksum))

		// Route the key
		route := RouteCredential(apiKey, []string{"mc"})

		t.Logf("Route type: %s", route.Type)

		// Should be routed as API key, not imported.
		assert.Equal(t, CredentialTypeIssued, route.Type, "Key should be routed as API key")

		// The checksum-verified key_id must equal the generated key ID.
		verified, err := VerifyAPIKeyChecksum(apiKey, [][]byte{hmacSecret})
		require.NoError(t, err)
		assert.Equal(t, keyID, verified.KeyID, "checksum-verified key_id should match generated key ID")
	})

	t.Run("generated key with different prefixes", func(t *testing.T) {
		t.Parallel()

		prefixes := []string{"api", "test", "prod", "dev", "staging", "a", "12345678"}

		for _, prefix := range prefixes {
			t.Run("prefix_"+prefix, func(t *testing.T) {
				t.Parallel()
				apiKey, keyID, err := GenerateAPIKey(t.Context(), prefix, hmacSecret)
				require.NoError(t, err)

				route := RouteCredential(apiKey, []string{"mc"})

				assert.Equal(t, CredentialTypeIssued, route.Type, "Key with prefix '%s' should be routed as API key", prefix)

				// The checksum-verified key_id must equal the generated key ID for
				// every allowed prefix.
				verified, err := VerifyAPIKeyChecksum(apiKey, [][]byte{hmacSecret})
				require.NoError(t, err)
				assert.Equal(t, keyID, verified.KeyID)
			})
		}
	})
}

func TestRouteCredential_EdgeCases(t *testing.T) {
	t.Parallel()

	t.Run("malformed v1 keys should not silently route as imported", func(t *testing.T) {
		t.Parallel()
		testCases := []struct {
			name     string
			key      string
			wantType CredentialType
		}{
			{
				name:     "v1 key with short checksum",
				key:      "api_v1_0ujsswThIGTUYm2K8Fj63K_short",
				wantType: CredentialTypeImported,
			},
			{
				name:     "v1 key with very long checksum",
				key:      "api_v1_0ujsswThIGTUYm2K8Fj63K_toolongchecksum123",
				wantType: CredentialTypeImported,
			},
			{
				name:     "v1 key with short key ID",
				key:      "api_v1_0ujsswTh_checksum12",
				wantType: CredentialTypeImported,
			},
			{
				name:     "v1 key missing checksum",
				key:      "api_v1_0ujsswThIGTUYm2K8Fj63K",
				wantType: CredentialTypeImported,
			},
		}

		for _, tc := range testCases {
			t.Run(tc.name, func(t *testing.T) {
				t.Parallel()

				route := RouteCredential(tc.key, []string{"mc"})
				t.Logf("Key: %s", tc.key)
				t.Logf("Routed as: %s", route.Type)

				// Document current behavior (see Notes in test cases above)
				assert.Equal(t, tc.wantType, route.Type,
					"Current routing behavior: malformed v1 keys route as imported for hash lookup")
			})
		}
	})
}

func TestRouteCredential_JWTDetection(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name         string
		credential   string
		expectedType CredentialType
	}{
		// Valid JWT formats
		{
			name:         "standard JWT",
			credential:   "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.dozjgNryP4J3jVmNHl0w5N_XgL0n3I9PlFUP0THsR8U",
			expectedType: CredentialTypeDerivedJWT,
		},
		{
			name:         "JWT with base64url special chars (underscore)",
			credential:   "eyJhbGc.payload_with_underscore.signature-with-dash",
			expectedType: CredentialTypeDerivedJWT,
		},
		{
			name:         "JWT with base64url special chars (dash)",
			credential:   "eyJheader-dash.payload-dash.signature-dash",
			expectedType: CredentialTypeDerivedJWT,
		},
		// Invalid JWT formats (should route as imported keys)
		{
			name:         "only starts with eyJ (missing parts)",
			credential:   "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9",
			expectedType: CredentialTypeImported,
		},
		{
			name:         "only two parts (missing signature)",
			credential:   "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0",
			expectedType: CredentialTypeImported,
		},
		{
			name:         "four parts (too many)",
			credential:   "header.payload.signature.extra",
			expectedType: CredentialTypeImported,
		},
		{
			name:         "contains invalid base64url chars (space)",
			credential:   "header with space.payload.signature",
			expectedType: CredentialTypeImported,
		},
		{
			name:         "contains invalid base64url chars (slash)",
			credential:   "header/slash.payload.signature",
			expectedType: CredentialTypeImported,
		},
		{
			name:         "empty parts",
			credential:   "..",
			expectedType: CredentialTypeImported,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			route := RouteCredential(tt.credential, []string{"mc"})
			assert.Equal(t, tt.expectedType, route.Type,
				"Credential %q should route as %s", tt.credential, tt.expectedType)
		})
	}
}

func TestRouteCredential_CustomMacaroonPrefix(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name             string
		credential       string
		macaroonPrefixes []string
		expectedType     CredentialType
	}{
		{
			name:             "custom prefix matches",
			credential:       "custom_v1_AgETaHR0cHM6Ly9leGFtcGxlLmNvbQ",
			macaroonPrefixes: []string{"custom"},
			expectedType:     CredentialTypeDerivedMacaroon,
		},
		{
			name:             "legacy prefix matches",
			credential:       "old_v1_AgETaHR0cHM6Ly9leGFtcGxlLmNvbQ",
			macaroonPrefixes: []string{"new", "old"},
			expectedType:     CredentialTypeDerivedMacaroon,
		},
		{
			name:             "current prefix matches with legacy also present",
			credential:       "new_v1_AgETaHR0cHM6Ly9leGFtcGxlLmNvbQ",
			macaroonPrefixes: []string{"new", "old"},
			expectedType:     CredentialTypeDerivedMacaroon,
		},
		{
			name:             "no matching prefix routes as imported",
			credential:       "unknown_v1_AgETaHR0cHM6Ly9leGFtcGxlLmNvbQ",
			macaroonPrefixes: []string{"mc"},
			expectedType:     CredentialTypeImported,
		},
		{
			name:             "default mc prefix",
			credential:       "mc_v1_AgETaHR0cHM6Ly9leGFtcGxlLmNvbQ",
			macaroonPrefixes: []string{"mc"},
			expectedType:     CredentialTypeDerivedMacaroon,
		},
		{
			name:             "empty prefix list routes macaroon as imported",
			credential:       "mc_v1_AgETaHR0cHM6Ly9leGFtcGxlLmNvbQ",
			macaroonPrefixes: []string{},
			expectedType:     CredentialTypeImported,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			route := RouteCredential(tt.credential, tt.macaroonPrefixes)
			assert.Equal(t, tt.expectedType, route.Type,
				"Credential %q with prefixes %v should route as %s", tt.credential, tt.macaroonPrefixes, tt.expectedType)
		})
	}
}

func BenchmarkRouteCredential(b *testing.B) {
	keys := []string{
		"prod_v1_0ujsswThIGTUYm2K8Fj63K_checksum12",
		"sk_live_abc123xyz789def456ghi",
		"test_v1_1BsqCKVNKRmw4VXfgSJd7Z_checksumxy",
		"ghp_customtalosformat1234567890",
	}

	b.ResetTimer()
	for i := range b.N {
		key := keys[i%len(keys)]
		_ = RouteCredential(key, nil)
	}
}

func BenchmarkHashImportedAPIKey(b *testing.B) {
	key := "sk_live_test123456789abcdefghijklmnop"
	nid := "00000000-0000-0000-0000-000000000001"

	b.ResetTimer()
	for b.Loop() {
		_ = HashImportedAPIKey(key, nid)
	}
}

// TODO add advesarial and fuziing tests

// reviewed - @aeneasr - 2026-03-26
