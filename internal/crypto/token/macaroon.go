package token

import (
	"context"
	"crypto"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"strings"
	"time"

	"github.com/cockroachdb/errors"
	"go.opentelemetry.io/otel/attribute"
	"gopkg.in/macaroon.v2"

	"github.com/ory/talos/internal/tracing"

	"github.com/ory/x/otelx"
)

// Macaroons encode claims as first-party caveats with JSON payloads. This is a
// simplified usage — full caveat delegation is not implemented.

// macaroonRootKeyDomain is the HKDF-style domain separator for deriving the
// macaroon root key from the shared HMAC secret. It must never be reused for
// other key derivations.
const macaroonRootKeyDomain = "talos/macaroon/v1/root-key"

// macaroonIdentifier is the JSON-encoded macaroon identifier containing the
// unique token ID. Root-key derivation is based on a single shared HMAC
// secret, so no per-key identifier is required.
type macaroonIdentifier struct {
	JTI string `json:"jti"`
}

// MacaroonSigner signs tokens using macaroon format.
// Root-key derivation is decoupled from the JWT signing key: the signer
// derives its root key from a dedicated HMAC secret, so verifier nodes only
// need the shared HMAC secret and never the JWT private key.
type MacaroonSigner struct {
	rootKey  []byte
	location string // Issuer URL
	prefix   string // Token prefix (e.g. "mc" produces "mc_v1_<base64>")
}

// NewMacaroonSigner creates a new macaroon signer.
// The prefix parameter controls the token prefix (e.g. "mc" produces "mc_v1_<base64>").
// The root key is derived deterministically from the provided HMAC secret.
func NewMacaroonSigner(hmacSecret []byte, location, prefix string) (*MacaroonSigner, error) {
	if len(hmacSecret) == 0 {
		return nil, errors.New("talos/macaroon: hmac secret is empty")
	}

	return &MacaroonSigner{
		rootKey:  deriveMacaroonRootKey(hmacSecret),
		location: location,
		prefix:   prefix,
	}, nil
}

// Algorithm returns the algorithm identifier for macaroons.
func (s *MacaroonSigner) Algorithm() Algorithm {
	return AlgorithmMacaroon
}

// KeyID returns the empty string: macaroon verification uses a single shared
// HMAC secret, so there is no per-key identifier to surface.
func (s *MacaroonSigner) KeyID() string {
	return ""
}

// PublicKey returns nil for macaroons (HMAC-based, no public key).
func (s *MacaroonSigner) PublicKey() (crypto.PublicKey, error) {
	return nil, errors.New("macaroons are HMAC-based and do not have public keys")
}

// Sign creates a signed macaroon token from claims.
func (s *MacaroonSigner) Sign(ctx context.Context, claims *Claims) (token string, err error) {
	_, span := tracing.StartWithoutNID(
		ctx, "macaroon.Sign",
		attribute.String("algorithm", string(AlgorithmMacaroon)),
		attribute.String("token_type", string(claims.GetTokenType())),
	)
	defer otelx.End(span, &err)

	identifier, err := json.Marshal(macaroonIdentifier{JTI: claims.tokenID})
	if err != nil {
		return "", errors.Wrap(err, "marshal macaroon identifier")
	}

	// Inject the signer's location as the issuer claim so verifyCaveat can validate it.
	// Use a shallow copy to avoid mutating the caller's claims.
	claimsWithIssuer := *claims
	claimsWithIssuer.issuer = s.location

	m, err := claimsToMacaroon(s.rootKey, s.location, string(identifier), &claimsWithIssuer)
	if err != nil {
		return "", errors.Wrap(err, "create macaroon")
	}

	binary, err := m.MarshalBinary()
	if err != nil {
		return "", errors.Wrap(err, "marshal macaroon")
	}

	token = s.prefix + "_v1_" + base64.RawURLEncoding.EncodeToString(binary)

	return token, nil
}

// VerifyMacaroonWithSecrets verifies a macaroon token against the provided
// HMAC secrets and validates issuer, prefix, and time claims.
//
// hmacSecrets must list the current secret first followed by any retired
// secrets; verification stops at the first match. Because the secrets come
// from trusted configuration, the iteration is not constant-time.
func VerifyMacaroonWithSecrets(ctx context.Context, tokenString string, hmacSecrets [][]byte, allowedIssuers []string, allowedPrefixes []string, clockSkew time.Duration) (claims *Claims, err error) {
	_, span := tracing.StartWithoutNID(ctx, "macaroon.VerifyWithSecrets")
	defer otelx.End(span, &err)

	if len(hmacSecrets) == 0 {
		return nil, errors.New("no HMAC secrets configured for macaroon verification")
	}

	// Strip the first matching prefix. Reject tokens that match no allowed
	// prefix explicitly, rather than relying on the downstream base64 decode
	// to fail.
	matched := false
	for _, p := range allowedPrefixes {
		pfx := p + "_v1_"
		if after, ok := strings.CutPrefix(tokenString, pfx); ok {
			tokenString = after
			matched = true
			break
		}
	}
	if !matched {
		return nil, errors.New("macaroon token does not carry an allowed prefix")
	}

	decoded, err := base64.RawURLEncoding.DecodeString(tokenString)
	if err != nil {
		return nil, errors.Wrap(err, "invalid macaroon encoding")
	}

	m := &macaroon.Macaroon{}
	if err = m.UnmarshalBinary(decoded); err != nil {
		return nil, errors.Wrap(err, "invalid macaroon format")
	}

	jti, err := parseMacaroonIdentifier(string(m.Id()))
	if err != nil {
		return nil, errors.Wrap(err, "invalid macaroon identifier")
	}

	var lastErr error
	for _, secret := range hmacSecrets {
		if len(secret) == 0 {
			continue
		}
		rootKey := deriveMacaroonRootKey(secret)
		if verr := m.Verify(rootKey, func(caveat string) error {
			return verifyCaveat(ctx, caveat, allowedIssuers, clockSkew)
		}, nil); verr != nil {
			lastErr = verr
			continue
		}

		verified, verr := macaroonToClaims(m)
		if verr != nil {
			return nil, verr
		}
		verified.tokenID = jti

		if verr := matchIssuer(verified, allowedIssuers, span); verr != nil {
			return nil, verr
		}

		return verified, nil
	}

	if lastErr == nil {
		return nil, errors.New("no usable HMAC secrets configured for macaroon verification")
	}
	return nil, errors.Wrap(lastErr, "macaroon verification failed")
}

// deriveMacaroonRootKey derives the macaroon root key from the shared HMAC
// secret using a fixed domain-separated HMAC-SHA256. The domain separator
// prevents the derived key from colliding with other uses of the same secret.
func deriveMacaroonRootKey(hmacSecret []byte) []byte {
	h := hmac.New(sha256.New, hmacSecret)
	h.Write([]byte(macaroonRootKeyDomain))
	return h.Sum(nil)
}

// parseMacaroonIdentifier extracts the jti from a JSON-encoded identifier.
func parseMacaroonIdentifier(identifier string) (string, error) {
	var id macaroonIdentifier
	if err := json.Unmarshal([]byte(identifier), &id); err != nil {
		return "", errors.Wrap(err, "invalid macaroon identifier JSON")
	}

	if id.JTI == "" {
		return "", errors.New("missing jti in identifier")
	}

	return id.JTI, nil
}

// claimsToMacaroon converts Claims to a macaroon with a single JSON caveat.
// Claims is directly JSON-serializable via its struct tags.
func claimsToMacaroon(rootKey []byte, location, identifier string, claims *Claims) (*macaroon.Macaroon, error) {
	m, err := macaroon.New(rootKey, []byte(identifier), location, macaroon.V2)
	if err != nil {
		return nil, err
	}

	caveat, err := json.Marshal(claims)
	if err != nil {
		return nil, errors.Wrap(err, "marshal claims")
	}

	if err = m.AddFirstPartyCaveat(caveat); err != nil {
		return nil, err
	}

	return m, nil
}

// macaroonToClaims extracts Claims from the single JSON caveat in a macaroon.
func macaroonToClaims(m *macaroon.Macaroon) (*Claims, error) {
	caveats := m.Caveats()
	if len(caveats) == 0 {
		return nil, errors.New("macaroon has no caveats")
	}

	var claims Claims
	if err := json.Unmarshal(caveats[0].Id, &claims); err != nil {
		return nil, errors.Wrap(err, "unmarshal claims")
	}

	if claims.metadata == nil {
		claims.metadata = make(map[string]any)
	}

	return &claims, nil
}

// verifyCaveat validates a single JSON-encoded caveat. It checks time
// constraints (exp, nbf) and issuer (iss) as defense-in-depth.
// allowedIssuers is the list of accepted issuer URLs (current + retired).
// clockSkew is the tolerance applied to nbf checks only. exp is checked strictly
// because adding clock skew to expiry would extend short-lived tokens by minutes,
// defeating their purpose. The JWT path (verifyJWTWithKeySet) applies the same
// skew semantics: leeway on nbf, strict exp.
func verifyCaveat(_ context.Context, caveat string, allowedIssuers []string, clockSkew time.Duration) error {
	if len(allowedIssuers) == 0 {
		return errors.New("allowed issuers must not be empty")
	}
	var claims Claims
	if err := json.Unmarshal([]byte(caveat), &claims); err != nil {
		return errors.Wrap(err, "invalid caveat JSON")
	}

	now := time.Now().UTC()
	if !claims.expiresAt.IsZero() && now.After(claims.expiresAt) {
		return errors.New("token expired")
	}
	if !claims.notBefore.IsZero() && now.Before(claims.notBefore.Add(-clockSkew)) {
		return errors.New("token not yet valid")
	}

	// Defense-in-depth: validate issuer matches one of the allowed issuers.
	// Reject caveats that omit iss entirely — otherwise an attacker could
	// craft a caveat without iss to bypass this check.
	if err := matchIssuerString(claims.issuer, allowedIssuers); err != nil {
		return err
	}

	return nil
}
