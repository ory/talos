package crypto

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"slices"

	"github.com/cockroachdb/errors"

	talosconfig "github.com/ory/talos/internal/config"
)

// paginationKeyDomain is the domain separator that turns the shared HMAC
// secret into the pagination cursor encryption key. It must never be reused
// for other key derivations.
const paginationKeyDomain = "talos/pagination/v1/cursor-key"

// ConfigProvider defines configuration methods used by crypto helpers.
type ConfigProvider interface {
	String(ctx context.Context, key talosconfig.Key) string
	Strings(ctx context.Context, key talosconfig.Key) []string
	ActiveRetiredValues(ctx context.Context, key talosconfig.Key) ([]string, error)
}

// HMACSecretsForVerification returns all HMAC secrets (current + retired) for verification.
// Returns an error if the project has no HMAC key configured.
// Returns: [current, ...retired] so that keys signed with a retired secret still verify.
// Retired secrets whose expiry has passed are dropped so a forgotten retired secret
// cannot be used forever.
func HMACSecretsForVerification(ctx context.Context, provider ConfigProvider) ([]string, error) {
	current := provider.String(ctx, talosconfig.KeySecretsHMACCurrent)
	if current == "" {
		return nil, errors.New("project has no HMAC key configured")
	}

	retired, err := provider.ActiveRetiredValues(ctx, talosconfig.KeySecretsHMACRetired)
	if err != nil {
		return nil, err
	}
	return slices.Concat([]string{current}, retired), nil
}

// HMACSecretForSigning returns the current HMAC secret for signing new keys.
// Returns an error if the project has no HMAC key configured.
func HMACSecretForSigning(ctx context.Context, provider ConfigProvider) (string, error) {
	current := provider.String(ctx, talosconfig.KeySecretsHMACCurrent)
	if current == "" {
		return "", errors.New("project has no HMAC key configured")
	}
	return current, nil
}

// DerivePaginationKey derives the 32-byte pagination cursor encryption key
// from the shared HMAC secret using domain-separated HMAC-SHA256. Mirrors the
// macaroon root key derivation so a single HMAC secret feeds both purposes
// without collision.
func DerivePaginationKey(hmacSecret string) [32]byte {
	h := hmac.New(sha256.New, []byte(hmacSecret))
	h.Write([]byte(paginationKeyDomain))
	var out [32]byte
	copy(out[:], h.Sum(nil))
	return out
}

// PaginationKeysForVerification returns the pagination cursor keys derived
// from the configured HMAC secrets, in [current, ...retired] order so tokens
// signed with a retired secret still decode during rotation.
func PaginationKeysForVerification(ctx context.Context, provider ConfigProvider) ([][32]byte, error) {
	secrets, err := HMACSecretsForVerification(ctx, provider)
	if err != nil {
		return nil, err
	}
	keys := make([][32]byte, len(secrets))
	for i, s := range secrets {
		keys[i] = DerivePaginationKey(s)
	}
	return keys, nil
}

// reviewed - @aeneasr - 2026-03-26
