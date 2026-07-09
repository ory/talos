package token

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// forgeMacaroonForTest builds a macaroon token using the provided root key
// directly — bypassing domain-separated derivation. It is used only to verify
// that domain separation is actually enforced by VerifyMacaroonWithSecrets.
func forgeMacaroonForTest(rootKey []byte, location string, identifier []byte, claims *Claims) (string, error) {
	m, err := claimsToMacaroon(rootKey, location, string(identifier), claims)
	if err != nil {
		return "", err
	}
	binary, err := m.MarshalBinary()
	if err != nil {
		return "", err
	}
	return "mc_v1_" + base64.RawURLEncoding.EncodeToString(binary), nil
}

// testClockSkew is the default clock skew used in tests (matches crypto.DefaultClockSkew).
const testClockSkew = 5 * time.Minute

// testIssuer is the default issuer used in test macaroons.
const testIssuer = "https://test.example.com"

// testHMACSecretString is the default shared HMAC secret used in tests.
const testHMACSecretString = "test-hmac-secret-must-be-at-least-32-bytes-long!"

func testHMACSecret() []byte { return []byte(testHMACSecretString) }

func verifyMacaroonWithSecret(t *testing.T, ctx context.Context, secret []byte, prefix, tokenString string) (*Claims, error) {
	t.Helper()
	return VerifyMacaroonWithSecrets(ctx, tokenString, [][]byte{secret}, []string{testIssuer}, []string{prefix}, testClockSkew)
}

func TestNewMacaroonSigner(t *testing.T) {
	t.Parallel()

	signer, err := NewMacaroonSigner(testHMACSecret(), "https://test.example.com", "mc")
	require.NoError(t, err)
	assert.NotNil(t, signer)
	assert.NotNil(t, signer.rootKey)
	assert.Equal(t, "https://test.example.com", signer.location)
	assert.Empty(t, signer.KeyID(), "macaroon signer KeyID must be empty (single shared secret)")
}

func TestNewMacaroonSigner_EmptySecret(t *testing.T) {
	t.Parallel()

	_, err := NewMacaroonSigner(nil, "https://test.example.com", "mc")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "hmac secret is empty")

	_, err = NewMacaroonSigner([]byte{}, "https://test.example.com", "mc")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "hmac secret is empty")
}

func TestMacaroonSigner_SignAndVerify(t *testing.T) {
	t.Parallel()

	signer, err := NewMacaroonSigner(testHMACSecret(), "https://test.example.com", "mc")
	require.NoError(t, err)

	// Create test claims
	now := time.Now()
	claims := &Claims{
		tokenID:   "token123",
		subject:   "parent-key-id",
		issuer:    "https://test.example.com",
		issuedAt:  now,
		expiresAt: now.Add(1 * time.Hour),
		notBefore: now,
		tokenType: TokenTypeDerived,
		keyID:     "parent-key-id",
		parentID:  "parent-key-id",
		actorID:   "user123",
		scopes:    []string{"read", "write"},
		metadata: map[string]any{
			"app": "test-app",
			"env": "staging",
		},
	}

	ctx := t.Context()

	token, err := signer.Sign(ctx, claims)
	require.NoError(t, err)
	assert.NotEmpty(t, token)
	assert.Contains(t, token, "mc_v1_")

	verifiedClaims, err := verifyMacaroonWithSecret(t, ctx, testHMACSecret(), "mc", token)
	require.NoError(t, err)
	assert.Equal(t, claims.subject, verifiedClaims.subject)
	assert.Equal(t, claims.issuer, verifiedClaims.issuer)
	assert.Equal(t, claims.actorID, verifiedClaims.actorID)
	assert.Equal(t, claims.subject, verifiedClaims.GetKeyID())
	assert.Equal(t, claims.subject, verifiedClaims.GetParentID())
	assert.Equal(t, claims.scopes, verifiedClaims.scopes)
	assert.Equal(t, claims.metadata["app"], verifiedClaims.metadata["app"])
	assert.Equal(t, claims.metadata["env"], verifiedClaims.metadata["env"])
	assert.WithinDuration(t, claims.expiresAt, verifiedClaims.expiresAt, time.Second)
	assert.WithinDuration(t, claims.notBefore, verifiedClaims.notBefore, time.Second)
}

func TestMacaroonSigner_SessionToken(t *testing.T) {
	t.Parallel()

	signer, err := NewMacaroonSigner(testHMACSecret(), "https://test.example.com", "mc")
	require.NoError(t, err)

	now := time.Now()
	claims := &Claims{
		tokenID:   "session123",
		subject:   "root-key-id",
		issuer:    "https://test.example.com",
		issuedAt:  now,
		expiresAt: now.Add(30 * time.Minute),
		tokenType: TokenTypeDerived,
		keyID:     "root-key-id",
		parentID:  "root-key-id",
		actorID:   "user456",
		scopes:    []string{"read"},
	}

	ctx := t.Context()

	token, err := signer.Sign(ctx, claims)
	require.NoError(t, err)

	verifiedClaims, err := verifyMacaroonWithSecret(t, ctx, testHMACSecret(), "mc", token)
	require.NoError(t, err)
	assert.Equal(t, "root-key-id", verifiedClaims.GetKeyID())
	assert.Equal(t, "root-key-id", verifiedClaims.GetParentID())
}

func TestMacaroonSigner_ExpiredToken(t *testing.T) {
	t.Parallel()

	signer, err := NewMacaroonSigner(testHMACSecret(), "https://test.example.com", "mc")
	require.NoError(t, err)

	// Create expired token
	now := time.Now()
	claims := &Claims{
		tokenID:   "expired123",
		subject:   "user789",
		issuer:    "https://test.example.com",
		issuedAt:  now.Add(-2 * time.Hour),
		expiresAt: now.Add(-1 * time.Hour), // Expired 1 hour ago
		tokenType: TokenTypeDerived,
		keyID:     "key-id",
		actorID:   "user789",
	}

	ctx := t.Context()

	token, err := signer.Sign(ctx, claims)
	require.NoError(t, err)

	_, err = verifyMacaroonWithSecret(t, ctx, testHMACSecret(), "mc", token)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "expired")
}

func TestMacaroonSigner_NotYetValid(t *testing.T) {
	t.Parallel()

	signer, err := NewMacaroonSigner(testHMACSecret(), "https://test.example.com", "mc")
	require.NoError(t, err)

	now := time.Now()
	claims := &Claims{
		tokenID:   "future123",
		subject:   "user999",
		issuer:    "https://test.example.com",
		issuedAt:  now,
		notBefore: now.Add(1 * time.Hour),
		expiresAt: now.Add(2 * time.Hour),
		tokenType: TokenTypeDerived,
		keyID:     "key-id",
		actorID:   "user999",
	}

	ctx := t.Context()

	token, err := signer.Sign(ctx, claims)
	require.NoError(t, err)

	_, err = verifyMacaroonWithSecret(t, ctx, testHMACSecret(), "mc", token)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "not yet valid")
}

func TestMacaroonSigner_InvalidToken(t *testing.T) {
	t.Parallel()

	ctx := t.Context()

	// Invalid encoding.
	_, err := verifyMacaroonWithSecret(t, ctx, testHMACSecret(), "mc", "mc_v1_invalid!!!base64")
	require.Error(t, err)

	// Token signed with a different secret.
	otherSecret := []byte("different-hmac-secret-must-be-32-bytes!!")
	otherSigner, err := NewMacaroonSigner(otherSecret, "https://test.example.com", "mc")
	require.NoError(t, err)

	claims := &Claims{
		tokenID:   "token123",
		subject:   "user123",
		issuer:    "https://test.example.com",
		expiresAt: time.Now().Add(1 * time.Hour),
		tokenType: TokenTypeDerived,
		keyID:     "key-id",
		actorID:   "user123",
	}

	otherToken, err := otherSigner.Sign(ctx, claims)
	require.NoError(t, err)

	_, err = verifyMacaroonWithSecret(t, ctx, testHMACSecret(), "mc", otherToken)
	assert.Error(t, err)
}

func TestVerifyMacaroonWithSecrets_MultipleSecrets(t *testing.T) {
	t.Parallel()

	secretA := []byte("hmac-secret-alpha-must-be-32-bytes-long!")
	secretB := []byte("hmac-secret-bravo-must-be-32-bytes-long!")

	signerA, err := NewMacaroonSigner(secretA, "https://test.example.com", "mc")
	require.NoError(t, err)
	signerB, err := NewMacaroonSigner(secretB, "https://test.example.com", "mc")
	require.NoError(t, err)

	ctx := t.Context()

	now := time.Now()
	claimsA := &Claims{
		tokenID: "tokenA", subject: "userA", issuer: "https://test.example.com",
		expiresAt: now.Add(1 * time.Hour), tokenType: TokenTypeDerived,
		keyID: "keyA", actorID: "userA",
	}
	claimsB := &Claims{
		tokenID: "tokenB", subject: "userB", issuer: "https://test.example.com",
		expiresAt: now.Add(1 * time.Hour), tokenType: TokenTypeDerived,
		keyID: "keyB", actorID: "userB",
	}

	tokenA, err := signerA.Sign(ctx, claimsA)
	require.NoError(t, err)
	tokenB, err := signerB.Sign(ctx, claimsB)
	require.NoError(t, err)

	bothSecrets := [][]byte{secretA, secretB}

	verifiedA, err := VerifyMacaroonWithSecrets(ctx, tokenA, bothSecrets, []string{testIssuer}, []string{"mc"}, testClockSkew)
	require.NoError(t, err)
	assert.Equal(t, "userA", verifiedA.subject)

	verifiedB, err := VerifyMacaroonWithSecrets(ctx, tokenB, bothSecrets, []string{testIssuer}, []string{"mc"}, testClockSkew)
	require.NoError(t, err)
	assert.Equal(t, "userB", verifiedB.subject)
}

func TestVerifyMacaroonWithSecrets_SecretRotation(t *testing.T) {
	t.Parallel()

	oldSecret := []byte("old-hmac-secret-must-be-32-bytes-long!!!")
	newSecret := []byte("new-hmac-secret-must-be-32-bytes-long!!!")

	oldSigner, err := NewMacaroonSigner(oldSecret, "https://test.example.com", "mc")
	require.NoError(t, err)
	newSigner, err := NewMacaroonSigner(newSecret, "https://test.example.com", "mc")
	require.NoError(t, err)

	ctx := t.Context()
	now := time.Now()

	oldToken, err := oldSigner.Sign(ctx, &Claims{
		tokenID: "old-token", subject: "user", issuer: "https://test.example.com",
		expiresAt: now.Add(1 * time.Hour), tokenType: TokenTypeDerived,
		keyID: "k", actorID: "user",
	})
	require.NoError(t, err)

	newToken, err := newSigner.Sign(ctx, &Claims{
		tokenID: "new-token", subject: "user", issuer: "https://test.example.com",
		expiresAt: now.Add(1 * time.Hour), tokenType: TokenTypeDerived,
		keyID: "k", actorID: "user",
	})
	require.NoError(t, err)

	// Rotation state: current=new, retired=[old].
	duringRotation := [][]byte{newSecret, oldSecret}

	_, err = VerifyMacaroonWithSecrets(ctx, oldToken, duringRotation, []string{testIssuer}, []string{"mc"}, testClockSkew)
	require.NoError(t, err, "token signed with retired secret must still verify during rotation")
	_, err = VerifyMacaroonWithSecrets(ctx, newToken, duringRotation, []string{testIssuer}, []string{"mc"}, testClockSkew)
	require.NoError(t, err)

	// After rotation: only new secret is active.
	newOnly := [][]byte{newSecret}

	_, err = VerifyMacaroonWithSecrets(ctx, oldToken, newOnly, []string{testIssuer}, []string{"mc"}, testClockSkew)
	require.Error(t, err, "token signed with old secret must fail once the old secret is retired")

	_, err = VerifyMacaroonWithSecrets(ctx, newToken, newOnly, []string{testIssuer}, []string{"mc"}, testClockSkew)
	require.NoError(t, err)
}

func TestVerifyMacaroonWithSecrets_EmptySecrets(t *testing.T) {
	t.Parallel()

	signer, err := NewMacaroonSigner(testHMACSecret(), "https://test.example.com", "mc")
	require.NoError(t, err)

	ctx := t.Context()
	token, err := signer.Sign(ctx, &Claims{
		tokenID: "tok1", subject: "user1", issuer: "https://test.example.com",
		expiresAt: time.Now().Add(1 * time.Hour), tokenType: TokenTypeDerived,
		keyID: "k", actorID: "user1",
	})
	require.NoError(t, err)

	_, err = VerifyMacaroonWithSecrets(ctx, token, nil, []string{testIssuer}, []string{"mc"}, testClockSkew)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "HMAC secrets")

	_, err = VerifyMacaroonWithSecrets(ctx, token, [][]byte{}, []string{testIssuer}, []string{"mc"}, testClockSkew)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "HMAC secrets")
}

// TestVerifyMacaroonWithSecrets_AllEmptyEntries covers the misconfiguration
// where the slice is non-empty but every entry is empty. The function must
// return a real error, never (nil, nil).
func TestVerifyMacaroonWithSecrets_AllEmptyEntries(t *testing.T) {
	t.Parallel()

	signer, err := NewMacaroonSigner(testHMACSecret(), "https://test.example.com", "mc")
	require.NoError(t, err)

	ctx := t.Context()
	token, err := signer.Sign(ctx, &Claims{
		tokenID: "tok1", subject: "user1", issuer: "https://test.example.com",
		expiresAt: time.Now().Add(1 * time.Hour), tokenType: TokenTypeDerived,
		keyID: "k", actorID: "user1",
	})
	require.NoError(t, err)

	claims, err := VerifyMacaroonWithSecrets(ctx, token, [][]byte{nil, {}}, []string{testIssuer}, []string{"mc"}, testClockSkew)
	require.Error(t, err)
	assert.Nil(t, claims)
	assert.Contains(t, err.Error(), "no usable HMAC secrets")
}

func TestMacaroonSigner_ScopeCaveats(t *testing.T) {
	t.Parallel()

	signer, err := NewMacaroonSigner(testHMACSecret(), "https://test.example.com", "mc")
	require.NoError(t, err)

	claims := &Claims{
		tokenID:   "token123",
		subject:   "user",
		issuer:    "https://test.example.com",
		expiresAt: time.Now().Add(1 * time.Hour),
		tokenType: TokenTypeDerived,
		keyID:     "key-id",
		actorID:   "user",
		scopes:    []string{"read:api", "write:api", "admin:users"},
	}

	ctx := t.Context()

	token, err := signer.Sign(ctx, claims)
	require.NoError(t, err)

	verified, err := verifyMacaroonWithSecret(t, ctx, testHMACSecret(), "mc", token)
	require.NoError(t, err)
	assert.ElementsMatch(t, claims.scopes, verified.scopes)
}

func TestMacaroonSigner_MetadataCaveats(t *testing.T) {
	t.Parallel()

	signer, err := NewMacaroonSigner(testHMACSecret(), "https://test.example.com", "mc")
	require.NoError(t, err)

	claims := &Claims{
		tokenID:   "token123",
		subject:   "user",
		issuer:    "https://test.example.com",
		expiresAt: time.Now().Add(1 * time.Hour),
		tokenType: TokenTypeDerived,
		keyID:     "key-id",
		actorID:   "user",
		metadata: map[string]any{
			"user_ip":    "192.168.1.1",
			"request_id": "abc123",
			"session_id": "xyz789",
		},
	}

	ctx := t.Context()

	token, err := signer.Sign(ctx, claims)
	require.NoError(t, err)

	verified, err := verifyMacaroonWithSecret(t, ctx, testHMACSecret(), "mc", token)
	require.NoError(t, err)
	assert.Equal(t, claims.metadata["user_ip"], verified.metadata["user_ip"])
	assert.Equal(t, claims.metadata["request_id"], verified.metadata["request_id"])
	assert.Equal(t, claims.metadata["session_id"], verified.metadata["session_id"])
}

func TestMacaroonSigner_CustomPrefix(t *testing.T) {
	t.Parallel()

	signer, err := NewMacaroonSigner(testHMACSecret(), "https://test.example.com", "custom")
	require.NoError(t, err)

	now := time.Now()
	claims := &Claims{
		tokenID:   "token123",
		subject:   "user123",
		issuer:    "https://test.example.com",
		expiresAt: now.Add(1 * time.Hour),
		tokenType: TokenTypeDerived,
		keyID:     "key-id",
		actorID:   "user123",
	}

	ctx := t.Context()

	token, err := signer.Sign(ctx, claims)
	require.NoError(t, err)
	assert.True(t, strings.HasPrefix(token, "custom_v1_"), "token should have custom prefix, got: %s", token)
	assert.False(t, strings.HasPrefix(token, "mc_v1_"), "token should not have default mc prefix")

	verified, err := verifyMacaroonWithSecret(t, ctx, testHMACSecret(), "custom", token)
	require.NoError(t, err)
	assert.Equal(t, "user123", verified.subject)
}

func TestVerifyMacaroonWithSecrets_LegacyPrefixRotation(t *testing.T) {
	t.Parallel()

	ctx := t.Context()
	now := time.Now()
	claims := &Claims{
		tokenID:   "token123",
		subject:   "user123",
		issuer:    "https://test.example.com",
		expiresAt: now.Add(1 * time.Hour),
		tokenType: TokenTypeDerived,
		keyID:     "test-key",
		actorID:   "user123",
	}

	secrets := [][]byte{testHMACSecret()}

	oldSigner, err := NewMacaroonSigner(testHMACSecret(), "https://test.example.com", "old")
	require.NoError(t, err)
	oldToken, err := oldSigner.Sign(ctx, claims)
	require.NoError(t, err)
	assert.True(t, strings.HasPrefix(oldToken, "old_v1_"))

	newSigner, err := NewMacaroonSigner(testHMACSecret(), "https://test.example.com", "new")
	require.NoError(t, err)
	newToken, err := newSigner.Sign(ctx, claims)
	require.NoError(t, err)
	assert.True(t, strings.HasPrefix(newToken, "new_v1_"))

	allowedPrefixes := []string{"new", "old"}

	verified1, err := VerifyMacaroonWithSecrets(ctx, oldToken, secrets, []string{testIssuer}, allowedPrefixes, testClockSkew)
	require.NoError(t, err)
	assert.Equal(t, "user123", verified1.subject)

	verified2, err := VerifyMacaroonWithSecrets(ctx, newToken, secrets, []string{testIssuer}, allowedPrefixes, testClockSkew)
	require.NoError(t, err)
	assert.Equal(t, "user123", verified2.subject)

	_, err = VerifyMacaroonWithSecrets(ctx, oldToken, secrets, []string{testIssuer}, []string{"new"}, testClockSkew)
	require.Error(t, err, "token with old prefix should fail when only new prefix is allowed")
}

func TestDeriveMacaroonRootKey(t *testing.T) {
	t.Parallel()

	// Deterministic: same secret yields same key.
	rootKey1 := deriveMacaroonRootKey(testHMACSecret())
	rootKey2 := deriveMacaroonRootKey(testHMACSecret())
	assert.Len(t, rootKey1, 32)
	assert.Equal(t, rootKey1, rootKey2)

	// Different secret yields different key.
	other := deriveMacaroonRootKey([]byte("different-hmac-secret-must-be-32-bytes!!"))
	assert.NotEqual(t, rootKey1, other)
}

func TestDeriveMacaroonRootKey_DomainSeparation(t *testing.T) {
	t.Parallel()

	// The domain-separated derivation must match HMAC-SHA256(secret, domain).
	h := hmac.New(sha256.New, testHMACSecret())
	h.Write([]byte(macaroonRootKeyDomain))
	expected := h.Sum(nil)
	assert.Equal(t, expected, deriveMacaroonRootKey(testHMACSecret()))

	// Derivation must not reduce to the raw secret or to a plain SHA-256 of it.
	rawHash := sha256.Sum256(testHMACSecret())
	assert.NotEqual(t, rawHash[:], deriveMacaroonRootKey(testHMACSecret()),
		"domain-separated key must differ from sha256(secret)")
	assert.NotEqual(t, testHMACSecret(), deriveMacaroonRootKey(testHMACSecret()))
}

func TestParseMacaroonIdentifier(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name       string
		identifier string
		wantJti    string
		wantErr    bool
	}{
		{
			name:       "valid identifier",
			identifier: `{"jti":"token123"}`,
			wantJti:    "token123",
			wantErr:    false,
		},
		{
			name:       "identifier with ignored kid field still valid",
			identifier: `{"kid":"legacy","jti":"token123"}`,
			wantJti:    "token123",
			wantErr:    false,
		},
		{
			name:       "missing jti",
			identifier: `{}`,
			wantErr:    true,
		},
		{
			name:       "invalid json",
			identifier: "not-json",
			wantErr:    true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			jti, err := parseMacaroonIdentifier(tt.identifier)
			if tt.wantErr {
				require.Error(t, err)
			} else {
				require.NoError(t, err)
				assert.Equal(t, tt.wantJti, jti)
			}
		})
	}
}

func TestMacaroonVerify_ValidatesIssuer(t *testing.T) {
	t.Parallel()

	ctx := t.Context()

	issuer := "https://trusted.issuer.com"
	signer, err := NewMacaroonSigner(testHMACSecret(), issuer, "mc")
	require.NoError(t, err)

	claims := NewClaims()
	claims.SetTokenID("test-token-id")
	claims.SetIssuer(issuer)
	claims.SetSubject("test-subject")
	claims.SetIssuedAt(time.Now().UTC())
	claims.SetExpiration(time.Now().UTC().Add(1 * time.Hour))

	tokenString, err := signer.Sign(ctx, claims)
	require.NoError(t, err)

	secrets := [][]byte{testHMACSecret()}

	// Correct issuer verifies.
	verifiedClaims, err := VerifyMacaroonWithSecrets(ctx, tokenString, secrets, []string{issuer}, []string{"mc"}, testClockSkew)
	require.NoError(t, err)
	require.NotNil(t, verifiedClaims)
	claimsIssuer, ok := verifiedClaims.Issuer()
	require.True(t, ok)
	require.Equal(t, issuer, claimsIssuer)

	// Wrong expected issuer fails.
	_, err = VerifyMacaroonWithSecrets(ctx, tokenString, secrets, []string{"https://wrong.issuer.com"}, []string{"mc"}, testClockSkew)
	require.Error(t, err)
	require.Contains(t, err.Error(), "issuer")

	// Retired issuer still in the allow list succeeds.
	verifiedClaims2, err := VerifyMacaroonWithSecrets(ctx, tokenString, secrets, []string{"https://new.issuer.com", issuer}, []string{"mc"}, testClockSkew)
	require.NoError(t, err)
	claimsIssuer2, ok := verifiedClaims2.Issuer()
	require.True(t, ok)
	require.Equal(t, issuer, claimsIssuer2)
}

func TestMacaroonVerify_SignAlwaysEmbedsIssuer(t *testing.T) {
	t.Parallel()

	ctx := t.Context()

	issuer := "https://trusted.issuer.com"
	signer, err := NewMacaroonSigner(testHMACSecret(), issuer, "mc")
	require.NoError(t, err)

	// Claims without explicitly setting issuer — Sign must embed the signer's location.
	claims := NewClaims()
	claims.SetTokenID("test-token-id")
	claims.SetSubject("test-subject")
	claims.SetIssuedAt(time.Now().UTC())
	claims.SetExpiration(time.Now().UTC().Add(1 * time.Hour))

	tokenString, err := signer.Sign(ctx, claims)
	require.NoError(t, err)

	secrets := [][]byte{testHMACSecret()}

	verified, err := VerifyMacaroonWithSecrets(ctx, tokenString, secrets, []string{issuer}, []string{"mc"}, testClockSkew)
	require.NoError(t, err)
	claimsIssuer, ok := verified.Issuer()
	require.True(t, ok)
	require.Equal(t, issuer, claimsIssuer)

	_, err = VerifyMacaroonWithSecrets(ctx, tokenString, secrets, []string{"https://wrong.issuer.com"}, []string{"mc"}, testClockSkew)
	require.Error(t, err)
	require.Contains(t, err.Error(), "issuer")
}

func TestMacaroonSigner_AdversarialInputs(t *testing.T) {
	t.Parallel()

	signer, err := NewMacaroonSigner(testHMACSecret(), "https://test.example.com", "mc")
	require.NoError(t, err)

	ctx := t.Context()

	validClaims := &Claims{
		tokenID:   "tok_valid",
		subject:   "user_123",
		issuer:    "https://test.example.com",
		issuedAt:  time.Now(),
		expiresAt: time.Now().Add(1 * time.Hour),
		tokenType: TokenTypeDerived,
		keyID:     "key-id",
		actorID:   "user_123",
	}
	validToken, err := signer.Sign(ctx, validClaims)
	require.NoError(t, err)

	tests := []struct {
		name  string
		token string
	}{
		{name: "invalid base64 after prefix", token: "mc_v1_!!!not-base64!!!"},
		{name: "valid base64 random bytes", token: "mc_v1_" + "dGhpcyBpcyBub3QgYSBtYWNhcm9vbg"},
		{name: "empty after prefix", token: "mc_v1_"},

		{name: "wrong version mc_v2", token: strings.Replace(validToken, "mc_v1_", "mc_v2_", 1)},

		{name: "null byte after prefix", token: "mc_v1_\x00"},
		{name: "null byte in body", token: "mc_v1_AAA\x00AAA"},

		{name: "flipped last byte", token: validToken[:len(validToken)-1] + string([]byte{validToken[len(validToken)-1] ^ 0xFF})},
		{name: "truncated to prefix plus 4 bytes", token: validToken[:len("mc_v1_")+4]},

		{name: "64KB garbage after prefix", token: "mc_v1_" + string(make([]byte, 65536))},

		{name: "empty string", token: ""},
		{name: "whitespace only", token: "   "},
		{name: "JWT-format string", token: "eyJhbGciOiJFZERTQSJ9.eyJzdWIiOiJ0ZXN0In0.fakesig"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			_, err := verifyMacaroonWithSecret(t, ctx, testHMACSecret(), "mc", tt.token)
			assert.Error(t, err, "adversarial token %q must be rejected", tt.name)
		})
	}
}

func TestMacaroonSigner_CrossSecretVerification(t *testing.T) {
	t.Parallel()

	ctx := t.Context()

	secretA := []byte("secret-alpha-must-be-at-least-32-bytes!!")
	secretB := []byte("secret-bravo-must-be-at-least-32-bytes!!")

	signerA, err := NewMacaroonSigner(secretA, "https://test.example.com", "mc")
	require.NoError(t, err)

	claims := &Claims{
		tokenID:   "tok_cross",
		subject:   "user_123",
		issuer:    "https://test.example.com",
		expiresAt: time.Now().Add(1 * time.Hour),
		tokenType: TokenTypeDerived,
		keyID:     "key-id",
		actorID:   "user_123",
	}

	tokenA, err := signerA.Sign(ctx, claims)
	require.NoError(t, err)

	_, err = VerifyMacaroonWithSecrets(ctx, tokenA, [][]byte{secretB}, []string{testIssuer}, []string{"mc"}, testClockSkew)
	require.Error(t, err, "token signed by secret-a must not verify with secret-b")
}

func TestMacaroon_Verify_PrefixMismatch(t *testing.T) {
	t.Parallel()

	ctx := t.Context()
	claims := &Claims{
		tokenID:   "token1",
		subject:   "user1",
		issuer:    "https://test.example.com",
		expiresAt: time.Now().Add(1 * time.Hour),
		tokenType: TokenTypeDerived,
		keyID:     "key1",
		actorID:   "user1",
	}

	oldSigner, err := NewMacaroonSigner(testHMACSecret(), "https://test.example.com", "old")
	require.NoError(t, err)
	token, err := oldSigner.Sign(ctx, claims)
	require.NoError(t, err)

	_, err = VerifyMacaroonWithSecrets(ctx, token, [][]byte{testHMACSecret()}, []string{testIssuer}, []string{"new"}, testClockSkew)
	require.Error(t, err, "token with 'old' prefix should fail when only 'new' prefix is allowed")
}

func TestVerifyMacaroonWithSecrets_MultipleRetiredPrefixes(t *testing.T) {
	t.Parallel()

	ctx := t.Context()
	secrets := [][]byte{testHMACSecret()}

	baseClaims := func(jti string) *Claims {
		return &Claims{
			tokenID:   jti,
			subject:   "user1",
			issuer:    "https://test.example.com",
			expiresAt: time.Now().Add(1 * time.Hour),
			tokenType: TokenTypeDerived,
			keyID:     "key1",
			actorID:   "user1",
		}
	}

	signerV1, err := NewMacaroonSigner(testHMACSecret(), "https://test.example.com", "v1")
	require.NoError(t, err)
	tokenV1, err := signerV1.Sign(ctx, baseClaims("tok-v1"))
	require.NoError(t, err)

	signerV2, err := NewMacaroonSigner(testHMACSecret(), "https://test.example.com", "v2")
	require.NoError(t, err)
	tokenV2, err := signerV2.Sign(ctx, baseClaims("tok-v2"))
	require.NoError(t, err)

	signerV3, err := NewMacaroonSigner(testHMACSecret(), "https://test.example.com", "v3")
	require.NoError(t, err)
	tokenV3, err := signerV3.Sign(ctx, baseClaims("tok-v3"))
	require.NoError(t, err)

	allPrefixes := []string{"v3", "v2", "v1"}
	for _, tok := range []string{tokenV1, tokenV2, tokenV3} {
		_, err := VerifyMacaroonWithSecrets(ctx, tok, secrets, []string{testIssuer}, allPrefixes, testClockSkew)
		require.NoError(t, err)
	}

	_, err = VerifyMacaroonWithSecrets(ctx, tokenV1, secrets, []string{testIssuer}, []string{"v3", "v2"}, testClockSkew)
	require.Error(t, err, "v1 token should fail when v1 prefix is retired")

	_, err = VerifyMacaroonWithSecrets(ctx, tokenV2, secrets, []string{testIssuer}, []string{"v3", "v2"}, testClockSkew)
	require.NoError(t, err)
	_, err = VerifyMacaroonWithSecrets(ctx, tokenV3, secrets, []string{testIssuer}, []string{"v3", "v2"}, testClockSkew)
	require.NoError(t, err)
}

func TestVerifyMacaroonWithSecrets_CrossPrefixCrossSecret(t *testing.T) {
	t.Parallel()

	secretA := []byte("secret-alpha-must-be-at-least-32-bytes!!")
	secretB := []byte("secret-bravo-must-be-at-least-32-bytes!!")

	ctx := t.Context()

	signerAOld, err := NewMacaroonSigner(secretA, "https://test.example.com", "old")
	require.NoError(t, err)
	tokenAOld, err := signerAOld.Sign(ctx, &Claims{
		tokenID: "tok-a-old", subject: "user1", issuer: "https://test.example.com",
		expiresAt: time.Now().Add(1 * time.Hour),
		tokenType: TokenTypeDerived, keyID: "keyA", actorID: "user1",
	})
	require.NoError(t, err)

	signerBNew, err := NewMacaroonSigner(secretB, "https://test.example.com", "new")
	require.NoError(t, err)
	tokenBNew, err := signerBNew.Sign(ctx, &Claims{
		tokenID: "tok-b-new", subject: "user1", issuer: "https://test.example.com",
		expiresAt: time.Now().Add(1 * time.Hour),
		tokenType: TokenTypeDerived, keyID: "keyB", actorID: "user1",
	})
	require.NoError(t, err)

	bothSecrets := [][]byte{secretA, secretB}
	bothPrefixes := []string{"new", "old"}

	v1, err := VerifyMacaroonWithSecrets(ctx, tokenAOld, bothSecrets, []string{testIssuer}, bothPrefixes, testClockSkew)
	require.NoError(t, err)
	assert.Equal(t, "user1", v1.subject)

	v2, err := VerifyMacaroonWithSecrets(ctx, tokenBNew, bothSecrets, []string{testIssuer}, bothPrefixes, testClockSkew)
	require.NoError(t, err)
	assert.Equal(t, "user1", v2.subject)

	// Token signed with secretA fails if only secretB is in the set.
	_, err = VerifyMacaroonWithSecrets(ctx, tokenAOld, [][]byte{secretB}, []string{testIssuer}, bothPrefixes, testClockSkew)
	require.Error(t, err)

	// Token signed with prefix "old" fails if only "new" prefix is allowed.
	_, err = VerifyMacaroonWithSecrets(ctx, tokenAOld, bothSecrets, []string{testIssuer}, []string{"new"}, testClockSkew)
	require.Error(t, err, "old-prefix token should fail with only new prefix allowed")
}

func TestVerifyMacaroonWithSecrets_EmptyAllowedPrefixes(t *testing.T) {
	t.Parallel()

	ctx := t.Context()
	signer, err := NewMacaroonSigner(testHMACSecret(), "https://test.example.com", "mc")
	require.NoError(t, err)
	token, err := signer.Sign(ctx, &Claims{
		tokenID: "tok1", subject: "user1", issuer: "https://test.example.com",
		expiresAt: time.Now().Add(1 * time.Hour),
		tokenType: TokenTypeDerived, keyID: "key1", actorID: "user1",
	})
	require.NoError(t, err)

	secrets := [][]byte{testHMACSecret()}

	// Empty allowedPrefixes means no prefix is stripped, so the base64 decode
	// includes the "mc_v1_" text and fails.
	_, err = VerifyMacaroonWithSecrets(ctx, token, secrets, []string{testIssuer}, []string{}, testClockSkew)
	require.Error(t, err, "empty allowedPrefixes should reject all prefixed tokens")

	_, err = VerifyMacaroonWithSecrets(ctx, token, secrets, []string{testIssuer}, nil, testClockSkew)
	require.Error(t, err, "nil allowedPrefixes should reject all prefixed tokens")
}

func TestVerifyMacaroonWithSecrets_PrefixSubstringAttack(t *testing.T) {
	t.Parallel()

	ctx := t.Context()
	signer, err := NewMacaroonSigner(testHMACSecret(), "https://test.example.com", "mc")
	require.NoError(t, err)
	token, err := signer.Sign(ctx, &Claims{
		tokenID: "tok1", subject: "user1", issuer: "https://test.example.com",
		expiresAt: time.Now().Add(1 * time.Hour),
		tokenType: TokenTypeDerived, keyID: "key1", actorID: "user1",
	})
	require.NoError(t, err)

	secrets := [][]byte{testHMACSecret()}

	// "m" is a substring of "mc" but should NOT match as a prefix.
	_, err = VerifyMacaroonWithSecrets(ctx, token, secrets, []string{testIssuer}, []string{"m"}, testClockSkew)
	require.Error(t, err, "substring prefix 'm' must not match 'mc' prefix")

	_, err = VerifyMacaroonWithSecrets(ctx, token, secrets, []string{testIssuer}, []string{"mc"}, testClockSkew)
	require.NoError(t, err)
}

// TestVerifyMacaroonWithSecrets_MissingPrefixRejected asserts that a token
// carrying no allowed prefix is rejected explicitly by the allow-list check,
// rather than leaning on the downstream base64 decode to fail.
func TestVerifyMacaroonWithSecrets_MissingPrefixRejected(t *testing.T) {
	t.Parallel()

	ctx := t.Context()
	signer, err := NewMacaroonSigner(testHMACSecret(), "https://test.example.com", "mc")
	require.NoError(t, err)
	token, err := signer.Sign(ctx, &Claims{
		tokenID: "tok1", subject: "user1", issuer: "https://test.example.com",
		expiresAt: time.Now().Add(1 * time.Hour),
		tokenType: TokenTypeDerived, keyID: "key1", actorID: "user1",
	})
	require.NoError(t, err)

	secrets := [][]byte{testHMACSecret()}

	// Baseline: the token verifies with its own prefix.
	verified, err := VerifyMacaroonWithSecrets(ctx, token, secrets, []string{testIssuer}, []string{"mc"}, testClockSkew)
	require.NoError(t, err)
	assert.Equal(t, "user1", verified.subject)

	// Strip the prefix so the raw string carries no allowed prefix. It must be
	// rejected by the explicit allow-list check, not the base64 decode.
	stripped := strings.TrimPrefix(token, "mc_v1_")
	require.NotEqual(t, token, stripped, "prefix must have been present to strip")

	_, err = VerifyMacaroonWithSecrets(ctx, stripped, secrets, []string{testIssuer}, []string{"mc"}, testClockSkew)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "allowed prefix")
}

// TestVerifyMacaroonWithSecrets_NoJWTKeyMaterial documents the core invariant
// of this design: macaroon verification uses only the shared HMAC secret.
// A verifier that lacks access to any JWT signing key can still verify a
// macaroon as long as it holds the HMAC secret the signer used.
func TestVerifyMacaroonWithSecrets_NoJWTKeyMaterial(t *testing.T) {
	t.Parallel()

	ctx := t.Context()

	sharedSecret := []byte("shared-hmac-secret-min-32-bytes-long!!!")

	// Signer node has the HMAC secret (and would have a JWT key in prod, but it's
	// irrelevant to this test). Verifier node has only the HMAC secret.
	signer, err := NewMacaroonSigner(sharedSecret, "https://test.example.com", "mc")
	require.NoError(t, err)

	claims := &Claims{
		tokenID:   "iso_test",
		subject:   "user_iso",
		issuer:    "https://test.example.com",
		expiresAt: time.Now().Add(1 * time.Hour),
		tokenType: TokenTypeDerived,
		keyID:     "key-iso",
		actorID:   "user_iso",
	}

	tokenString, err := signer.Sign(ctx, claims)
	require.NoError(t, err)

	// Verifier only holds the HMAC secret. No JWT key involved.
	verified, err := VerifyMacaroonWithSecrets(ctx, tokenString, [][]byte{sharedSecret}, []string{testIssuer}, []string{"mc"}, testClockSkew)
	require.NoError(t, err)
	assert.Equal(t, "user_iso", verified.subject)
}

// TestVerifyMacaroonWithSecrets_DomainSeparation ensures that tokens built with
// the raw HMAC secret used directly as the root key do NOT verify. This
// enforces the HMAC-SHA256(secret, domain) derivation required by the design.
func TestVerifyMacaroonWithSecrets_DomainSeparation(t *testing.T) {
	t.Parallel()

	ctx := t.Context()

	// Build a macaroon using the raw secret as the root key (not the
	// domain-separated derivation). Such a token MUST NOT verify with
	// VerifyMacaroonWithSecrets.
	rawRootKey := testHMACSecret()
	identifier := []byte(`{"jti":"raw-root"}`)

	m, err := forgeMacaroonForTest(rawRootKey, "https://test.example.com", identifier, &Claims{
		tokenID:   "raw-root",
		subject:   "attacker",
		issuer:    "https://test.example.com",
		expiresAt: time.Now().Add(1 * time.Hour),
		tokenType: TokenTypeDerived,
		keyID:     "k",
		actorID:   "attacker",
	})
	require.NoError(t, err)

	_, err = VerifyMacaroonWithSecrets(ctx, m, [][]byte{testHMACSecret()}, []string{testIssuer}, []string{"mc"}, testClockSkew)
	require.Error(t, err, "token minted with raw secret as root key must not verify")
}
