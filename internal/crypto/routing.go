package crypto

import (
	"crypto/sha512"
	"encoding/hex"
	"regexp"
	"strings"
)

// jwtRegex validates JWT format: header.payload.signature (3 base64url segments)
// Each segment is base64url: A-Za-z0-9_-
var jwtRegex = regexp.MustCompile(`^eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+$`)

// CredentialType identifies the type of credential
type CredentialType string

// Credential type constants
const (
	CredentialTypeIssued          CredentialType = "issued"           // Our generated keys
	CredentialTypeImported        CredentialType = "imported"         // External keys (Stripe, GitHub, etc.)
	CredentialTypeDerivedJWT      CredentialType = "derived_jwt"      // JWT derived token
	CredentialTypeDerivedMacaroon CredentialType = "derived_macaroon" // Macaroon derived token
)

// CredentialRoute contains routing information for a credential
type CredentialRoute struct {
	Type CredentialType
}

// RouteCredential determines how to route a credential for verification.
//
// macaroonPrefixes lists the allowed macaroon token prefixes (e.g. ["mc", "auth"]).
// A token matching any prefix+"_v1_" is routed as a derived macaroon token.
//
// It classifies the credential type only; it does not surface a lookup key.
// Callers derive the lookup key from the authenticated credential — the
// checksum-verified key_id via crypto.VerifyAPIKeyChecksum for issued keys, or
// crypto.HashImportedAPIKey for imported keys — so the authenticated UUID and the
// looked-up UUID always come from the same parse.
func RouteCredential(credential string, macaroonPrefixes []string) CredentialRoute {
	// Derived tokens (short-lived, derived from API keys)

	// Check for JWT format: <base64>.<base64>.<base64>
	if jwtRegex.MatchString(credential) {
		// JWT token - key_id is extracted from claims during verification.
		return CredentialRoute{Type: CredentialTypeDerivedJWT}
	}

	// Check for macaroon prefix (any configured prefix + "_v1_")
	for _, p := range macaroonPrefixes {
		if strings.HasPrefix(credential, p+"_v1_") {
			// Macaroon token - key_id is extracted from the identifier during verification.
			return CredentialRoute{Type: CredentialTypeDerivedMacaroon}
		}
	}

	// API keys (long-lived)
	// Try to parse as v1 API key format: prefix_v1_identifier_checksum
	// Uses the same regex as parseAPIKey for consistency
	matches := apiKeyRegex.FindStringSubmatch(credential)
	if matches != nil {
		// Valid v1 API key format - classify by whether the base58 identifier
		// (capture group [2]) decodes. A decode error means the key is not one we
		// issued, so route it as imported. Routing only classifies the type, so
		// the decoded UUID is discarded.
		identifier := matches[2]
		if _, _, err := DecodeIdentifier(identifier); err != nil {
			return CredentialRoute{Type: CredentialTypeImported}
		}
		return CredentialRoute{Type: CredentialTypeIssued}
	}

	// Not a valid v1 format - treat as imported key. The verifier computes a
	// tenant-scoped hash via HashImportedAPIKey using the NID from context.
	return CredentialRoute{Type: CredentialTypeImported}
}

// HashImportedAPIKey generates a deterministic, tenant-scoped key ID for an imported key.
// The NID is included in the hash input so that the same raw key produces different
// key IDs in different tenants, preventing cross-tenant key ID collisions.
// Uses SHA512/256 for better performance on 64-bit systems.
func HashImportedAPIKey(rawKey string, nid string) string {
	h := sha512.New512_256()
	h.Write([]byte(nid))
	h.Write([]byte{0}) // separator to prevent nid+rawKey ambiguity
	h.Write([]byte(rawKey))

	return hex.EncodeToString(h.Sum(nil))
}

// reviewed - @aeneasr - 2026-03-26
