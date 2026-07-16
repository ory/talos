// Package service implements the business logic layer for API key management.
// It provides Admin for management operations (issue, import, revoke, rotate,
// list, derive, verify) and Public for proof-of-possession self-revocation
// available to credential holders.
package service

import (
	"cmp"
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"log/slog"
	"maps"
	"slices"
	"time"

	"buf.build/go/protovalidate"
	"github.com/cockroachdb/errors"
	"github.com/lestrrat-go/jwx/v3/jwk"
	"google.golang.org/grpc/codes"
	"google.golang.org/protobuf/types/known/emptypb"
	"google.golang.org/protobuf/types/known/structpb"
	"google.golang.org/protobuf/types/known/timestamppb"

	"github.com/ory/talos/internal/cachecontrol"

	"github.com/ory/herodot"

	"go.opentelemetry.io/otel/attribute"

	"github.com/ory/talos/internal/cache"
	"github.com/ory/talos/internal/clientip"
	talosconfig "github.com/ory/talos/internal/config"
	"github.com/ory/talos/internal/crypto"
	"github.com/ory/talos/internal/crypto/token"
	cryptoverifier "github.com/ory/talos/internal/crypto/verifier"
	"github.com/ory/talos/internal/errdef"
	"github.com/ory/talos/internal/eventcontext"
	"github.com/ory/talos/internal/events"
	"github.com/ory/talos/internal/metrics"

	"github.com/ory/talos/internal/contextx"

	"github.com/ory/talos/internal/lastused"
	"github.com/ory/talos/internal/persistence"
	"github.com/ory/talos/internal/persistence/persistmodel"
	db "github.com/ory/talos/internal/persistence/sqlc/generated"
	"github.com/ory/talos/internal/persistence/sqlutil"
	persistencetypes "github.com/ory/talos/internal/persistence/types"
	"github.com/ory/talos/internal/service/validation"
	"github.com/ory/talos/internal/tracing"
	"github.com/ory/talos/internal/verifier"
	talosv2alpha1 "github.com/ory/talos/pkg/api/talos/v2alpha1"

	"github.com/ory/x/otelx"
)

// reservedTokenClaims lists JWT claim names that Talos manages and rejects
// from caller-provided custom claims in DeriveToken.
var reservedTokenClaims = map[string]struct{}{
	"jti": {}, "sub": {}, "iss": {}, "aud": {},
	"iat": {}, "exp": {}, "nbf": {},
	"nid": {}, "akid": {}, "pid": {},
	"tty": {}, "oid": {}, "scp": {}, "scope": {},
	"meta": {}, "vis": {}, "acl": {},
}

// ConfigProvider defines the interface for configuration access
type ConfigProvider interface {
	String(ctx context.Context, key talosconfig.Key) string
	Strings(ctx context.Context, key talosconfig.Key) []string
	ActiveRetiredValues(ctx context.Context, key talosconfig.Key) ([]string, error)
	Duration(ctx context.Context, key talosconfig.Key) time.Duration
	Int(ctx context.Context, key talosconfig.Key) int
	Bool(ctx context.Context, key talosconfig.Key) bool
}

// Admin implements a simplified admin service
type Admin struct {
	driver         persistence.Persister
	provider       ConfigProvider
	emitter        events.Emitter
	keyService     *crypto.KeyService
	cache          cache.Cache[db.IssuedApiKey]
	pagination     *paginationHelper
	cryptoVerifier *cryptoverifier.Verifier
	apiKeyVerifier *verifier.Verifier
	protoValidator protovalidate.Validator
	metrics        *metrics.Metrics
}

// apiKeyKind selects the not-found message used by handleDBError.
type apiKeyKind int

const (
	apiKeyKindIssued apiKeyKind = iota
	apiKeyKindImported
)

// allowedIssuedKeyMaskPaths is the set of update_mask paths accepted by
// AdminUpdateIssuedApiKey. Any path outside this set is rejected with
// InvalidArgument (AIP-134: unknown fields must not be silently ignored).
var allowedIssuedKeyMaskPaths = []string{
	"name",
	"scopes",
	"metadata",
	"rate_limit_policy",
	"ip_restriction",
}

// allowedImportedKeyMaskPaths is the set of update_mask paths accepted by
// AdminUpdateImportedApiKey. Mirrors allowedIssuedKeyMaskPaths because the
// two resources share the same mutable surface today.
var allowedImportedKeyMaskPaths = []string{
	"name",
	"scopes",
	"metadata",
	"rate_limit_policy",
	"ip_restriction",
}

// handleDBError maps persistence errors to appropriate API errors.
// It centralizes error handling logic for database operations.
// The kind parameter selects the not-found message; the operation parameter
// is used as the InternalError message for unrecognized errors.
func handleDBError(err error, kind apiKeyKind, operation string) error {
	switch {
	case errors.Is(err, sql.ErrNoRows):
		if kind == apiKeyKindImported {
			return errdef.ErrAPIKeyNotFound().WithReasonf("imported key not found").WithWrap(errors.WithStack(err))
		}
		return errdef.ErrAPIKeyNotFound().WithReasonf("API key not found").WithWrap(errors.WithStack(err))
	case errors.Is(err, context.DeadlineExceeded):
		return errdef.ErrGatewayTimeout().WithReasonf("database operation timed out").WithWrap(errors.WithStack(err))
	case persistence.IsConnectionError(err):
		return errdef.ErrServiceUnavailable().WithReasonf("database connection failed").WithWrap(errors.WithStack(err))
	default:
		return errdef.InternalError(operation).WithWrap(errors.WithStack(err))
	}
}

// NewAdminFromProvider creates a new admin service from a config provider.
// CRITICAL: All dependencies must be non-nil (will panic on use if nil).
func NewAdminFromProvider(driver persistence.Persister, provider ConfigProvider, emitter events.Emitter, keyService *crypto.KeyService, apiKeyCache cache.Cache[db.IssuedApiKey], pv protovalidate.Validator, m *metrics.Metrics, tracker *lastused.Tracker) *Admin {
	cryptoVer := cryptoverifier.NewVerifier(keyService)
	ver := verifier.NewFromProvider(driver, provider, apiKeyCache, emitter, keyService, m, tracker)

	return &Admin{
		driver:         driver,
		provider:       provider,
		emitter:        emitter,
		keyService:     keyService,
		cache:          apiKeyCache,
		pagination:     &paginationHelper{provider: provider},
		cryptoVerifier: cryptoVer,
		apiKeyVerifier: ver,
		protoValidator: pv,
		metrics:        m,
	}
}

// Verifier returns the internal Verifier for testing.
// This verifier shares the same KeyService as the Admin, ensuring
// that tokens signed by this Admin can be verified by this verifier.
func (s *Admin) Verifier() *verifier.Verifier {
	return s.apiKeyVerifier
}

// getMacaroonPrefixes returns all allowed macaroon prefixes (current + retired).
func (s *Admin) getMacaroonPrefixes(ctx context.Context) []string {
	return append(
		[]string{cmp.Or(s.provider.String(ctx, talosconfig.KeyCredentialsDerivedTokensMacaroonPrefixCurrent), "mc")},
		s.provider.Strings(ctx, talosconfig.KeyCredentialsDerivedTokensMacaroonPrefixRetired)...,
	)
}

// getAPIKeyPrefix returns the appropriate prefix based on key visibility.
// For PUBLIC keys, it uses the public prefix config.
// For SECRET or UNSPECIFIED, it uses the standard prefix config.
func (s *Admin) getAPIKeyPrefix(ctx context.Context, visibility talosv2alpha1.KeyVisibility) (string, error) {
	if visibility == talosv2alpha1.KeyVisibility_KEY_VISIBILITY_PUBLIC {
		prefix := s.provider.String(ctx, talosconfig.KeyCredentialsAPIKeysPrefixPublicCurrent)
		if prefix == "" {
			return "", errdef.BadRequest("public key prefix not configured: set credentials.api_keys.prefix.public_current")
		}
		return prefix, nil
	}
	return s.provider.String(ctx, talosconfig.KeyCredentialsAPIKeysPrefixCurrent), nil
}

// normalizeVisibility converts UNSPECIFIED to SECRET.
func normalizeVisibility(v talosv2alpha1.KeyVisibility) int32 {
	if v == talosv2alpha1.KeyVisibility_KEY_VISIBILITY_PUBLIC {
		return int32(talosv2alpha1.KeyVisibility_KEY_VISIBILITY_PUBLIC)
	}
	return int32(talosv2alpha1.KeyVisibility_KEY_VISIBILITY_SECRET)
}

// enforceAPIKeyQuota rejects a request when creating extra new keys would push
// the tenant past the plan-allotted maximum. A cap of 0 (or absent) means no
// enforcement: paid tiers leave the key unset and metered usage handles
// overages.
//
// Enforcement is best-effort: the count query runs outside the insert
// transaction, so under concurrent issuance the live key count may briefly
// exceed the cap by up to N-1 keys, where N is the burst concurrency. The
// next request that observes the over-cap state is rejected, so the breach
// is transient. For hard limits use metered billing instead of this quota.
func (s *Admin) enforceAPIKeyQuota(ctx context.Context, extra int64) error {
	quotaCap := int64(s.provider.Int(ctx, talosconfig.KeyQuotaAPIKeysMax))
	if quotaCap <= 0 {
		return nil
	}
	if extra <= 0 {
		extra = 1
	}
	// CountActiveAPIKeysUpTo stops scanning once the cap is reached, so the
	// query never returns more than `quotaCap` rows even on very large tables.
	count, err := s.driver.CountActiveAPIKeysUpTo(ctx, quotaCap)
	if err != nil {
		return handleDBError(err, apiKeyKindIssued, "count active API keys")
	}
	if count+extra > quotaCap {
		return errdef.ErrAPIKeyQuotaExceeded().
			WithReasonf("the API key quota for this plan permits up to %d active API keys", quotaCap).
			WithDetail("limit", quotaCap).
			WithDetail("current_usage", count)
	}
	return nil
}

func visibilityLabel(v talosv2alpha1.KeyVisibility) string {
	if v == talosv2alpha1.KeyVisibility_KEY_VISIBILITY_PUBLIC {
		return "public"
	}
	return "secret"
}

// IssueApiKey creates a new API key
func (s *Admin) IssueApiKey(ctx context.Context, req *talosv2alpha1.IssueApiKeyRequest) (_ *talosv2alpha1.IssueApiKeyResponse, err error) {
	ctx, span := tracing.Start(ctx, "service.IssueApiKey")
	defer otelx.End(span, &err)

	if err := s.protoValidator.Validate(req); err != nil {
		return nil, errdef.BadRequest(err.Error())
	}

	// Validate and normalize request using validation package
	normalized, err := validation.ValidateAndNormalizeIssueRequest(req, s.provider.Duration(ctx, talosconfig.KeyCredentialsAPIKeysDefaultTTL), s.provider.Duration(ctx, talosconfig.KeyCredentialsAPIKeysMaxTTL))
	if err != nil {
		return nil, err
	}

	if err := s.enforceAPIKeyQuota(ctx, 1); err != nil {
		return nil, err
	}

	// Generate v1 API key format with HMAC-SHA256
	// Get current prefix from configuration (visibility-aware)
	prefix, err := s.getAPIKeyPrefix(ctx, req.GetVisibility())
	if err != nil {
		return nil, err
	}

	// Generate v1 key: prefix_v1_UUID_checksum
	hmacSecret, err := crypto.HMACSecretForSigning(ctx, s.provider)
	if err != nil {
		return nil, errdef.InternalError("get HMAC secret").WithWrap(errors.WithStack(err))
	}
	apiKeyToken, keyID, err := crypto.GenerateAPIKey(ctx, prefix, []byte(hmacSecret))
	if err != nil {
		return nil, errdef.InternalError("generate v1 API key").WithWrap(errors.WithStack(err))
	}

	// Insert-first: attempt to create the key directly. On unique constraint violation
	// from request_id, recover by returning the existing key (idempotent replay, AIP-155).
	// This avoids an extra DB round-trip on every request that carries a request_id.
	dbKey, err := s.driver.CreateIssuedAPIKey(ctx, persistencetypes.CreateIssuedAPIKeyParams{
		KeyID:           keyID,
		Name:            normalized.Name,
		TokenPrefix:     prefix,
		ActorID:         normalized.ActorID,
		Scopes:          normalized.Fields.Scopes,
		Metadata:        normalized.Fields.Metadata,
		ExpiresAt:       normalized.ExpiresAt,
		RateLimitQuota:  normalized.Fields.RateLimitQuota,
		RateLimitWindow: normalized.Fields.RateLimitWindow,
		AllowedCIDRs:    normalized.Fields.AllowedCIDRs,
		RequestID:       req.RequestId,
		Visibility:      normalizeVisibility(req.GetVisibility()),
	})
	if err != nil && !persistence.IsUniqueViolation(err) {
		return nil, handleDBError(err, apiKeyKindIssued, "create API key")
	}
	// If request_id was provided, the violation is likely from the idempotency index.
	// Fetch the existing key and return it (idempotent replay).
	if err != nil && req.RequestId != "" {
		existing, idErr := s.driver.GetIssuedAPIKeyByRequestID(ctx, req.RequestId)
		if idErr == nil {
			issuedAPIKey, convErr := dbIssuedKeyToProto(existing)
			if convErr != nil {
				return nil, wrapDecodePersistedScopesError(convErr)
			}
			return &talosv2alpha1.IssueApiKeyResponse{
				IssuedApiKey: issuedAPIKey,
			}, nil
		}
		if !errors.Is(idErr, sql.ErrNoRows) {
			return nil, handleDBError(idErr, apiKeyKindIssued, "idempotency lookup")
		}
	}
	if err != nil {
		return nil, errdef.ErrAPIKeyExists().WithReasonf("API key with ID %s already exists", keyID).WithWrap(errors.WithStack(err))
	}

	// Record metrics
	s.metrics.APIKeysCreated.Inc()

	// Emit audit event
	eventcontext.NewFromContext(ctx, events.EventIssuedAPIKeyCreated).
		WithKeyID(keyID).
		WithPrefix(prefix).
		WithActor(normalized.ActorID).
		WithExpiry(normalized.ExpiresAt).
		WithVisibility(visibilityLabel(req.GetVisibility())).
		Emit(ctx, s.emitter)

	issuedAPIKey, err := dbIssuedKeyToProto(dbKey)
	if err != nil {
		return nil, wrapDecodePersistedScopesError(err)
	}
	return &talosv2alpha1.IssueApiKeyResponse{
		IssuedApiKey: issuedAPIKey,
		Secret:       apiKeyToken, // Only returned on creation
	}, nil
}

// GetIssuedAPIKey retrieves an API key by ID
func (s *Admin) GetIssuedAPIKey(ctx context.Context, req *talosv2alpha1.GetIssuedApiKeyRequest) (resp *talosv2alpha1.IssuedApiKey, err error) {
	if err := s.protoValidator.Validate(req); err != nil {
		return nil, errdef.BadRequest(err.Error())
	}

	ctx, span := tracing.Start(
		ctx, "service.GetIssuedAPIKey",
		attribute.String("key_id", req.KeyId),
	)
	defer otelx.End(span, &err)

	// NID is extracted from context internally by the driver
	key, err := s.driver.GetIssuedAPIKey(ctx, req.KeyId)
	if err != nil {
		return nil, handleDBError(err, apiKeyKindIssued, "get API key")
	}

	issuedAPIKey, err := dbIssuedKeyToProto(key)
	if err != nil {
		return nil, wrapDecodePersistedScopesError(err)
	}
	return issuedAPIKey, nil
}

// RotateIssuedApiKey generates a new secret for an API key by creating a new key with a new key_id.
// The old key is always immediately revoked to prevent security issues from forgotten active keys.
//
// The old key is read and its status verified inside the same transaction that creates the
// replacement key, eliminating TOCTOU race conditions between concurrent rotations.
func (s *Admin) RotateIssuedApiKey(ctx context.Context, req *talosv2alpha1.RotateIssuedApiKeyRequest) (_ *talosv2alpha1.RotateIssuedApiKeyResponse, err error) {
	if err := s.protoValidator.Validate(req); err != nil {
		return nil, errdef.BadRequest(err.Error())
	}

	ctx, span := tracing.Start(
		ctx, "service.RotateIssuedApiKey",
		attribute.String("old_key_id", req.GetKeyId()),
	)
	defer otelx.End(span, &err)

	// Validate metadata format before starting the transaction.
	if req.Metadata != nil {
		fields, fErr := validation.NormalizeCreateFields(nil, req.GetMetadata(), nil, nil)
		if fErr != nil {
			return nil, fErr
		}
		if fErr := validation.ValidateMetadataSize(fields.Metadata); fErr != nil {
			return nil, fErr
		}
	}

	hmacSecret, err := crypto.HMACSecretForSigning(ctx, s.provider)
	if err != nil {
		return nil, errdef.InternalError("get HMAC secret").WithWrap(errors.WithStack(err))
	}

	// Generate a new API key and atomically rotate in the database.
	// The old key is read inside the transaction; mergeRotationParams produces the new key's
	// parameters from the just-read old key. This eliminates the TOCTOU gap.
	var apiKeyToken, newKeyID, prefix string

	rotateResult, err := s.driver.RotateIssuedAPIKeyAtomic(ctx, req.KeyId, func(oldKey db.IssuedApiKey) (persistencetypes.RotateIssuedAPIKeyParams, error) {
		// Determine prefix based on merged visibility (request wins, else inherit from old key).
		mergedVisibility := oldKey.Visibility
		if req.GetVisibility() != talosv2alpha1.KeyVisibility_KEY_VISIBILITY_UNSPECIFIED {
			mergedVisibility = normalizeVisibility(req.GetVisibility())
		}

		var pfxErr error
		prefix, pfxErr = s.getAPIKeyPrefix(ctx, talosv2alpha1.KeyVisibility(mergedVisibility))
		if pfxErr != nil {
			return persistencetypes.RotateIssuedAPIKeyParams{}, pfxErr
		}

		var genErr error
		apiKeyToken, newKeyID, genErr = crypto.GenerateAPIKey(ctx, prefix, []byte(hmacSecret))
		if genErr != nil {
			return persistencetypes.RotateIssuedAPIKeyParams{}, errdef.InternalError("generate new API key").WithWrap(errors.WithStack(genErr))
		}

		return mergeRotationParams(req, newKeyID, prefix, oldKey)
	})
	if err != nil {
		if persistence.IsUniqueViolation(err) {
			return nil, errdef.ErrAPIKeyExists().WithReasonf("API key with ID %s already exists", newKeyID).WithWrap(errors.WithStack(err))
		}
		if errors.Is(err, persistencetypes.ErrKeyNotActive) {
			return nil, errdef.FailedPrecondition("cannot rotate a non-active key")
		}
		return nil, handleDBError(err, apiKeyKindIssued, "rotate API key")
	}

	// Use the old key as read inside the transaction (authoritative post-revoke state).
	rotateResult.OldKey.Status = int32(talosv2alpha1.KeyStatus_KEY_STATUS_REVOKED)

	// Invalidate the rotated-out key's cache entry. The new key has not been
	// cached yet, so only the old key_id needs eviction.
	s.invalidateVerifierCache(ctx, req.KeyId)

	// Emit audit events — use the new key returned from the transaction as the source of truth.
	rotateEvent := eventcontext.NewFromContext(ctx, events.EventIssuedAPIKeyRotated).
		WithKeyID(newKeyID).
		WithPrefix(prefix).
		WithOperation("rotate").
		WithActor(sqlutil.Deref(rotateResult.NewKey.ActorID)).
		WithExpiry(rotateResult.NewKey.ExpiresAt).
		WithVisibility(visibilityLabel(talosv2alpha1.KeyVisibility(rotateResult.NewKey.Visibility))).
		WithMetadata("old_key_id", req.KeyId)
	if rotateResult.OldKey.ExpiresAt != nil {
		rotateEvent = rotateEvent.WithMetadata("old_expires_at", rotateResult.OldKey.ExpiresAt.UTC().Format(time.RFC3339))
	}
	rotateEvent.Emit(ctx, s.emitter)

	// Record metrics
	s.metrics.APIKeysCreated.Inc()
	s.metrics.APIKeysRevoked.WithLabelValues("rotation").Inc()
	s.metrics.APIKeysRotated.Inc()

	newIssuedAPIKey, err := dbIssuedKeyToProto(rotateResult.NewKey)
	if err != nil {
		return nil, wrapDecodePersistedScopesError(err)
	}
	oldIssuedAPIKey, err := dbIssuedKeyToProto(rotateResult.OldKey)
	if err != nil {
		return nil, wrapDecodePersistedScopesError(err)
	}
	return &talosv2alpha1.RotateIssuedApiKeyResponse{
		IssuedApiKey:    newIssuedAPIKey,
		Secret:          apiKeyToken,
		OldIssuedApiKey: oldIssuedAPIKey,
	}, nil
}

// mergeRotationParams merges old key fields with request overrides to produce the
// RotateIssuedAPIKeyParams for the transaction. It is called inside the transaction
// with the just-read old key, so no TOCTOU gap exists.
func mergeRotationParams(req *talosv2alpha1.RotateIssuedApiKeyRequest, newKeyID, prefix string, oldKey db.IssuedApiKey) (persistencetypes.RotateIssuedAPIKeyParams, error) {
	var p persistencetypes.RotateIssuedAPIKeyParams
	p.OldKeyID = oldKey.KeyID
	p.NewKeyID = newKeyID
	p.TokenPrefix = prefix

	// Normalize request metadata if provided
	overrideMetadata := req.Metadata != nil
	var reqMetadata json.RawMessage
	if overrideMetadata {
		fields, err := validation.NormalizeCreateFields(nil, req.GetMetadata(), nil, nil)
		if err != nil {
			return p, err
		}
		reqMetadata = fields.Metadata
	}

	// Name: presence-based override. The optional proto field gives us a
	// non-nil pointer when the caller sent the field (even with an empty
	// string), letting us distinguish "absent" from "explicit empty".
	if req.Name != nil {
		p.Name = *req.Name
	} else {
		p.Name = oldKey.Name
	}

	// Scopes: request wins, then old key
	if req.Scopes != nil {
		p.Scopes = sqlutil.NonNilSlice(req.GetScopes())
	} else {
		scopes, err := sqlutil.UnmarshalScopes(oldKey.Scopes)
		if err != nil {
			return p, wrapDecodePersistedScopesError(err)
		}
		p.Scopes = scopes
	}

	// Metadata: explicit override, old key value, or empty object
	switch {
	case overrideMetadata:
		p.Metadata = reqMetadata
	case len(oldKey.Metadata) > 0:
		p.Metadata = oldKey.Metadata
	default:
		p.Metadata = json.RawMessage(`{}`)
	}

	// Expiration: inherit from old key. Safe to share pointer; oldKey is read-only after this point.
	p.ExpiresAt = oldKey.ExpiresAt

	// Owner ID
	p.ActorID = sqlutil.Deref(oldKey.ActorID)

	// Rate limit policy: request wins, then old key.
	//
	// Not extracted into a shared helper: the Update methods use useMask/pathSet branching
	// with clear-to-nil semantics, while rotation uses simple "request wins, else inherit"
	// logic. A shared helper would need to handle both patterns, adding complexity without
	// reducing total code. The three sites (mergeRotationParams, UpdateIssuedAPIKey,
	// UpdateImportedAPIKey) each have ~8 lines of rate-limit logic — below the threshold
	// where extraction pays for the indirection cost.
	if req.RateLimitPolicy != nil {
		q := req.RateLimitPolicy.Quota
		p.RateLimitQuota = &q
		if req.RateLimitPolicy.Window != nil {
			w := int64(req.RateLimitPolicy.Window.AsDuration().Seconds())
			p.RateLimitWindow = &w
		}
	} else {
		p.RateLimitQuota = oldKey.RateLimitQuota
		p.RateLimitWindow = oldKey.RateLimitWindow
	}

	// IP restriction: request wins, then old key.
	// Same rationale as rate-limit above: Update methods have mask-based clear semantics
	// that differ from rotation's simple "request wins" pattern.
	if req.GetIpRestriction() != nil {
		cidrs, err := validation.NormalizeIPRestriction(req.GetIpRestriction())
		if err != nil {
			return p, err
		}
		p.AllowedCIDRs = cidrs
	} else {
		p.AllowedCIDRs = oldKey.AllowedCidrs
	}

	// Visibility: request wins (if not UNSPECIFIED), then inherit from old key
	if req.GetVisibility() != talosv2alpha1.KeyVisibility_KEY_VISIBILITY_UNSPECIFIED {
		p.Visibility = normalizeVisibility(req.GetVisibility())
	} else {
		p.Visibility = oldKey.Visibility
	}

	return p, nil
}

// RevokeIssuedApiKey revokes an existing issued API key.
func (s *Admin) RevokeIssuedApiKey(ctx context.Context, req *talosv2alpha1.RevokeIssuedApiKeyRequest) (resp *emptypb.Empty, err error) {
	if err := s.protoValidator.Validate(req); err != nil {
		return nil, errdef.BadRequest(err.Error())
	}

	ctx, span := tracing.Start(
		ctx, "service.RevokeIssuedAPIKey",
		attribute.String("key_id", req.KeyId),
		attribute.Int("revocation_reason", int(req.Reason)),
	)
	defer otelx.End(span, &err)

	// Description is only permitted with PRIVILEGE_WITHDRAWN to document the justification.
	if req.Description != "" && req.Reason != talosv2alpha1.RevocationReason_REVOCATION_REASON_PRIVILEGE_WITHDRAWN {
		return nil, errdef.BadRequest("description is only allowed when reason is PRIVILEGE_WITHDRAWN")
	}

	currentKey, err := s.driver.GetIssuedAPIKey(ctx, req.KeyId)
	if err != nil {
		return nil, handleDBError(err, apiKeyKindIssued, "get key for revocation")
	}

	if currentKey.Status == int32(talosv2alpha1.KeyStatus_KEY_STATUS_REVOKED) {
		return nil, errdef.Conflict("key is already revoked")
	}

	now := sqlutil.UTCNow()
	newExpiresAt := sqlutil.CalculateRevocationExpiry(now, currentKey.ExpiresAt)

	err = s.driver.RevokeIssuedAPIKey(ctx, persistencetypes.RevokeIssuedAPIKeyParams{
		KeyID:       req.KeyId,
		Reason:      int32(req.Reason),
		Description: req.Description,
		ExpiresAt:   newExpiresAt,
	})
	if err != nil {
		return nil, handleDBError(err, apiKeyKindIssued, "revoke API key")
	}

	s.invalidateVerifierCache(ctx, req.KeyId)

	s.emitRevocationEvent(ctx, req.KeyId, req.Reason, revocationEventContext{
		eventType:  events.EventIssuedAPIKeyRevoked,
		actorID:    sqlutil.Deref(currentKey.ActorID),
		expiresAt:  currentKey.ExpiresAt,
		visibility: visibilityLabel(talosv2alpha1.KeyVisibility(currentKey.Visibility)),
	})

	return &emptypb.Empty{}, nil
}

// RevokeImportedApiKey revokes an existing imported API key.
func (s *Admin) RevokeImportedApiKey(ctx context.Context, req *talosv2alpha1.RevokeImportedApiKeyRequest) (resp *emptypb.Empty, err error) {
	if err := s.protoValidator.Validate(req); err != nil {
		return nil, errdef.BadRequest(err.Error())
	}

	ctx, span := tracing.Start(
		ctx, "service.RevokeImportedAPIKey",
		attribute.String("key_id", req.KeyId),
		attribute.Int("revocation_reason", int(req.Reason)),
	)
	defer otelx.End(span, &err)

	// Description is only permitted with PRIVILEGE_WITHDRAWN to document the justification.
	if req.Description != "" && req.Reason != talosv2alpha1.RevocationReason_REVOCATION_REASON_PRIVILEGE_WITHDRAWN {
		return nil, errdef.BadRequest("description is only allowed when reason is PRIVILEGE_WITHDRAWN")
	}

	importedKey, err := s.driver.GetImportedAPIKeyByHash(ctx, req.KeyId)
	if err != nil {
		return nil, handleDBError(err, apiKeyKindImported, "get key for revocation")
	}

	if importedKey.Status == int32(talosv2alpha1.KeyStatus_KEY_STATUS_REVOKED) {
		return nil, errdef.Conflict("key is already revoked")
	}

	now := sqlutil.UTCNow()
	newExpiresAt := sqlutil.CalculateRevocationExpiry(now, importedKey.ExpiresAt)

	_, err = s.driver.RevokeImportedAPIKey(ctx, persistencetypes.RevokeImportedKeyParams{
		KeyID:       req.KeyId,
		Reason:      int32(req.Reason),
		Description: req.Description,
		ExpiresAt:   newExpiresAt,
	})
	if err != nil {
		return nil, handleDBError(err, apiKeyKindImported, "revoke imported API key")
	}

	// req.KeyId is the imported key's hash, which is also its key_id and the id
	// the verifier registered the cache entry under.
	s.invalidateVerifierCache(ctx, req.KeyId)

	s.emitRevocationEvent(ctx, req.KeyId, req.Reason, revocationEventContext{
		eventType:  events.EventImportedAPIKeyRevoked,
		actorID:    sqlutil.Deref(importedKey.ActorID),
		expiresAt:  importedKey.ExpiresAt,
		visibility: visibilityLabel(talosv2alpha1.KeyVisibility(importedKey.Visibility)),
	})

	return &emptypb.Empty{}, nil
}

// revocationEventContext holds the key details needed to enrich a revocation audit event.
type revocationEventContext struct {
	eventType  events.EventType
	actorID    string
	expiresAt  *time.Time
	visibility string
}

func (s *Admin) emitRevocationEvent(ctx context.Context, keyID string, reason talosv2alpha1.RevocationReason, keyCtx revocationEventContext) {
	reasonLabel := reason.String()
	s.metrics.APIKeysRevoked.WithLabelValues(reasonLabel).Inc()

	builder := eventcontext.NewFromContext(ctx, keyCtx.eventType).
		WithKeyID(keyID).
		WithActor(keyCtx.actorID).
		WithExpiry(keyCtx.expiresAt).
		WithVisibility(keyCtx.visibility)

	if reason != talosv2alpha1.RevocationReason_REVOCATION_REASON_UNSPECIFIED {
		builder.WithReason(reasonLabel)
	}

	builder.Emit(ctx, s.emitter)
}

// invalidateVerifierCache evicts the verifier cache entry for keyID after an
// admin mutation changes the key's validity or policy (revoke, update, rotate,
// delete). The verifier cache is keyed by key_id, so admin handlers can evict
// the entry without the raw secret they never see.
//
// The database is already authoritative, so an eviction failure is logged but
// not fatal — the stale entry expires on its own at cache.ttl. Invalidation is
// immediate on a shared cache (redis) and on the local replica for an in-memory
// cache; cross-replica in-memory eviction is bounded by cache.ttl.
func (s *Admin) invalidateVerifierCache(ctx context.Context, keyID string) {
	if err := s.cache.Delete(ctx, keyID); err != nil {
		slog.WarnContext(ctx, "invalidate verifier cache after admin mutation",
			slog.String("key_id", keyID),
			slog.Any("error", err))
	}
}

// extractRateLimitPolicy returns the final quota and window to write to the DB,
// applying AIP-134 field-mask semantics.
//
// The SQL UPDATE uses direct assignment (not COALESCE) for these columns, so
// passing nil would clear them. Callers must pass existing values so that an
// unmasked or absent field is preserved, not zeroed.
//
//   - useMask=false, policy=nil   → return existing (no-op)
//   - useMask=true,  !inMask      → return existing (field not requested)
//   - useMask=true,  inMask, nil  → return nil, nil (explicit clear)
//   - policy != nil               → extract and return new values
func extractRateLimitPolicy(policy *talosv2alpha1.RateLimitPolicy, useMask, inMask bool, existingQuota, existingWindow *int64) (*int64, *int64) {
	if useMask {
		if !inMask {
			return existingQuota, existingWindow
		}
	} else if policy == nil {
		return existingQuota, existingWindow
	}
	if policy == nil {
		return nil, nil // in-mask nil = clear
	}
	quota := policy.Quota
	var window *int64
	if policy.Window != nil {
		w := int64(policy.Window.AsDuration().Seconds())
		window = &w
	}
	return &quota, window
}

// extractIPRestriction returns the final allowed_cidrs JSON to write to the DB,
// applying AIP-134 field-mask semantics.
//
// The SQL UPDATE uses COALESCE for allowed_cidrs, so nil means "keep existing".
// An explicit empty array signals "clear".
//
//   - useMask=false, restriction=nil → nil (no-op via COALESCE)
//   - useMask=true,  !inMask         → nil (no-op via COALESCE)
//   - useMask=true,  inMask, nil     → [] (clear via non-nil empty array)
//   - restriction != nil             → normalize and return CIDRs
func extractIPRestriction(restriction *talosv2alpha1.IPRestriction, useMask, inMask bool) (json.RawMessage, error) {
	if useMask && !inMask {
		return nil, nil
	}
	if restriction == nil {
		if useMask {
			// In-mask nil means "clear the restriction".
			return json.RawMessage("[]"), nil
		}
		return nil, nil
	}
	return validation.NormalizeIPRestriction(restriction)
}

// UpdateIssuedAPIKey updates mutable fields of an issued API key (AIP-134)
func (s *Admin) UpdateIssuedAPIKey(ctx context.Context, req *talosv2alpha1.UpdateIssuedApiKeyRequest) (_ *talosv2alpha1.IssuedApiKey, err error) {
	if err := s.protoValidator.Validate(req); err != nil {
		return nil, errdef.BadRequest(err.Error())
	}

	patch := req.GetIssuedApiKey()
	keyID := patch.GetKeyId()

	ctx, span := tracing.Start(
		ctx, "service.UpdateIssuedAPIKey",
		attribute.String("key_id", keyID),
	)
	defer otelx.End(span, &err)

	// Apply AIP-134 field mask semantics (or legacy presence-based fallback).
	// Validate mask paths before the DB read so a typo fails fast with
	// InvalidArgument rather than performing a no-op update.
	mask, err := newFieldMaskValidated(req.GetUpdateMask().GetPaths(), allowedIssuedKeyMaskPaths)
	if err != nil {
		return nil, err
	}

	// Get the existing key first to preserve unmodified fields
	existingKey, err := s.driver.GetIssuedAPIKey(ctx, keyID)
	if err != nil {
		return nil, handleDBError(err, apiKeyKindIssued, "get API key for update")
	}

	// Start with existing values
	name := existingKey.Name
	scopes, err := sqlutil.UnmarshalScopes(existingKey.Scopes)
	if err != nil {
		return nil, wrapDecodePersistedScopesError(err)
	}
	metadataJSON := existingKey.Metadata

	name = mask.applyString("name", patch.GetName(), name)
	scopes = applySlice(mask, "scopes", patch.GetScopes(), scopes)

	metadataJSON, err = mask.applyMetadata(patch.GetMetadata(), metadataJSON)
	if err != nil {
		return nil, err
	}

	rateLimitQuota, rateLimitWindow := extractRateLimitPolicy(patch.GetRateLimitPolicy(), mask.useMask, mask.has("rate_limit_policy"), existingKey.RateLimitQuota, existingKey.RateLimitWindow)

	allowedCIDRs, err := extractIPRestriction(patch.GetIpRestriction(), mask.useMask, mask.has("ip_restriction"))
	if err != nil {
		return nil, err
	}

	// Update via persistence layer
	updatedKey, err := s.driver.UpdateIssuedAPIKeyMetadata(ctx, persistencetypes.UpdateIssuedAPIKeyParams{
		KeyID:           keyID,
		Name:            name,
		Scopes:          scopes,
		Metadata:        metadataJSON,
		RateLimitQuota:  rateLimitQuota,
		RateLimitWindow: rateLimitWindow,
		AllowedCIDRs:    allowedCIDRs,
	})
	if err != nil {
		return nil, handleDBError(err, apiKeyKindIssued, "update issued API key")
	}

	s.invalidateVerifierCache(ctx, keyID)

	eventcontext.NewFromContext(ctx, events.EventIssuedAPIKeyUpdated).
		WithKeyID(keyID).
		WithActor(sqlutil.Deref(updatedKey.ActorID)).
		WithExpiry(updatedKey.ExpiresAt).
		WithVisibility(visibilityLabel(talosv2alpha1.KeyVisibility(updatedKey.Visibility))).
		Emit(ctx, s.emitter)

	issuedAPIKey, err := dbIssuedKeyToProto(updatedKey)
	if err != nil {
		return nil, wrapDecodePersistedScopesError(err)
	}
	return issuedAPIKey, nil
}

// ListIssuedAPIKeys lists API keys for a network with cursor-based pagination
func (s *Admin) ListIssuedAPIKeys(ctx context.Context, req *talosv2alpha1.ListIssuedApiKeysRequest) (resp *talosv2alpha1.ListIssuedApiKeysResponse, err error) {
	ctx, span := tracing.Start(
		ctx, "service.ListIssuedAPIKeys",
		attribute.Int("page_size", int(req.PageSize)),
	)
	defer otelx.End(span, &err)

	if err := s.protoValidator.Validate(req); err != nil {
		return nil, errdef.BadRequest(err.Error())
	}

	// Shared pagination setup: filter parsing, page size, cursor decoding
	q, err := s.pagination.prepareListQuery(ctx, req.Filter, req.PageSize, req.PageToken)
	if err != nil {
		return nil, err
	}

	// Fetch keys (one extra for hasMore detection) - NID is extracted from context internally by the driver
	keys, err := s.driver.ListIssuedAPIKeysByNetwork(ctx, q.filter.ActorID, int32(q.filter.Status), q.cursorKey, q.limit)
	if err != nil {
		return nil, handleDBError(err, apiKeyKindIssued, "list API keys")
	}

	// Trim results and generate next page token if needed
	originalCount := len(keys)
	keys = trimResults(keys, q.pageSize)
	var nextPageToken string
	if len(keys) > 0 {
		nextPageToken, err = s.pagination.nextPageToken(ctx, originalCount, q.pageSize, keys[len(keys)-1].KeyID)
		if err != nil {
			return nil, err
		}
	}

	// Convert to protobuf
	protoKeys := make([]*talosv2alpha1.IssuedApiKey, 0, len(keys))
	for _, key := range keys {
		protoKey, err := dbIssuedKeyToProto(key)
		if err != nil {
			return nil, wrapDecodePersistedScopesError(err)
		}
		protoKeys = append(protoKeys, protoKey)
	}

	return &talosv2alpha1.ListIssuedApiKeysResponse{
		IssuedApiKeys: protoKeys,
		NextPageToken: nextPageToken,
	}, nil
}

// DeriveToken creates a short-lived JWT or Macaroon session token from a parent API key.
//
// Security Model: Stateless Capability Tokens
// Derived tokens are "capability tokens" that remain valid until expiration regardless
// of parent key status changes. All security constraints are enforced at creation time:
//   - Parent key must be ACTIVE (not revoked, not expired)
//   - Derived scopes must be subset of parent scopes (can be equal or fewer)
//   - Derived TTL cannot exceed parent's remaining lifetime
//   - Subject and owner are inherited from parent (cannot be changed)
//
// After creation, derived tokens are verified statelessly using only cryptographic
// signature and expiration checks. This provides:
//   - Low latency verification
//   - Reduced database load on hot verification path
//   - Better scalability for high-volume verification workloads
//
// Best Practices:
//   - Use short TTLs (15 minutes to 1 hour) to limit exposure
//   - Rotate parent keys periodically
//   - Monitor for unusual derivation patterns
//
// Revocation Model:
//   - Revoking parent key prevents NEW derived tokens from being created
//   - Existing derived tokens remain valid until expiration
//   - For immediate revocation, use short TTLs or implement token deny lists
//
// Parameters:
//   - algorithm: "jwt" or "macaroon" for the derived token (empty defaults to "jwt")
//   - customClaims: additional claims to merge into the token metadata (cannot override reserved claims)
func (s *Admin) DeriveToken(ctx context.Context, req *talosv2alpha1.DeriveTokenRequest) (_ *talosv2alpha1.DeriveTokenResponse, err error) {
	if err := s.protoValidator.Validate(req); err != nil {
		return nil, errdef.BadRequest(err.Error())
	}

	// Normalize request fields
	algorithm := string(token.AlgorithmJWT)
	if req.GetAlgorithm() == talosv2alpha1.TokenAlgorithm_TOKEN_ALGORITHM_MACAROON {
		algorithm = string(token.AlgorithmMacaroon)
	}

	var customClaims map[string]any
	if req.GetCustomClaims() != nil {
		customClaims = req.GetCustomClaims().AsMap()
	}

	ttl := validation.ConvertTTL(req.GetTtl(), s.provider.Duration(ctx, talosconfig.KeyCredentialsDerivedTokensDefaultTTL))

	// Reject (not clamp) because derived tokens are programmatic — callers
	// depend on exact TTL for caching and retry logic.
	if maxTTL := s.provider.Duration(ctx, talosconfig.KeyCredentialsAPIKeysMaxTTL); maxTTL > 0 && ttl > maxTTL {
		return nil, errdef.BadRequest("ttl exceeds the configured maximum of " + maxTTL.String())
	}

	scopes := req.GetScopes()

	ctx, span := tracing.Start(
		ctx, "service.DeriveToken",
		attribute.String("algorithm", algorithm),
	)
	defer otelx.End(span, &err)

	// Verify the API key token (works with JWT or opaque v1)
	key, _, err := s.apiKeyVerifier.VerifyAPIKey(cachecontrol.WithCacheControl(ctx, cachecontrol.CacheControl{NoCache: true}), req.Credential)
	if err != nil {
		if errors.Is(err, errdef.ErrAPIKeyRevoked()) {
			return nil, errdef.ErrForbidden().WithReasonf("key is revoked").WithWrap(errors.WithStack(err))
		}
		return nil, errdef.ErrUnauthorized().WithReasonf("verify API key").WithWrap(errors.WithStack(err))
	}

	ctxNID := contextx.NetworkIDFromContext(ctx).String()
	span.SetAttributes(
		attribute.String("nid", ctxNID),
		attribute.String("key_id", key.KeyID),
	)

	// Capture now once so expiry validation and the token's IssuedAt/NotBefore
	// use the same instant — avoids microsecond drift between the two.
	now := time.Now().UTC()

	// Validate derived TTL against parent expiry
	if key.ExpiresAt != nil {
		remaining := key.ExpiresAt.Sub(now)
		if remaining <= 0 {
			return nil, errors.WithStack(errdef.FailedPrecondition("cannot derive token from expired parent key"))
		}
		if ttl > remaining {
			return nil, errors.WithStack(errdef.ErrBadRequest().WithReasonf(
				"derived token ttl (%s) exceeds parent key remaining lifetime (%s)", ttl, remaining,
			))
		}
	}

	// Key material selection depends on the target algorithm:
	//   - JWT: extract the active asymmetric signing key from KeyService.
	//   - Macaroon: fetch the shared HMAC secret. The JWT private key must
	//     never flow into the macaroon path so verifier nodes can stay
	//     decoupled from admin key material.
	var (
		privateKey any
		kid        string
		hmacSecret []byte
	)
	if algorithm == string(token.AlgorithmMacaroon) {
		secret, err := crypto.HMACSecretForSigning(ctx, s.provider)
		if err != nil {
			return nil, errdef.InternalError("get HMAC secret").WithWrap(errors.WithStack(err))
		}
		hmacSecret = []byte(secret)
	} else {
		jwkKey, err := s.keyService.GetActiveSigningKey(ctx)
		if err != nil {
			return nil, errdef.InternalError("get signing key").WithWrap(errors.WithStack(err))
		}
		if err := jwk.Export(jwkKey, &privateKey); err != nil {
			return nil, errdef.InternalError("extract private key from JWK").WithWrap(errors.WithStack(err))
		}
		kid, _ = jwkKey.KeyID()
	}

	parentScopes, err := sqlutil.UnmarshalScopes(key.Scopes)
	if err != nil {
		return nil, wrapDecodePersistedScopesError(err)
	}

	// Use requested scopes if provided (scope restriction), otherwise use parent scopes
	if len(scopes) == 0 {
		scopes = parentScopes
	} else {
		// Validate that requested scopes are a subset of parent scopes
		for _, s := range scopes {
			if !slices.Contains(parentScopes, s) {
				return nil, errors.WithStack(errdef.ErrForbidden().WithReasonf(
					"requested scope '%s' not available in parent key", s,
				))
			}
		}
	}

	// Parse key metadata and apply user-defined custom claims as top-level JWT fields.
	metadataMap := make(map[string]any)
	if len(key.Metadata) > 0 && string(key.Metadata) != "{}" {
		var rawMap map[string]any
		if err := json.Unmarshal(key.Metadata, &rawMap); err != nil {
			slog.Error("unmarshal API key metadata",
				slog.String("metadata_prefix", string(key.Metadata[:min(len(key.Metadata), 32)])),
				slog.Any("error", err))
		} else {
			metadataMap = rawMap
		}
	}
	var filteredCustomClaims map[string]any
	if len(customClaims) > 0 {
		filtered := make(map[string]any, len(customClaims))
		for k, v := range customClaims {
			if _, reserved := reservedTokenClaims[k]; !reserved {
				filtered[k] = v
			}
		}
		if len(filtered) > 0 {
			filteredCustomClaims = filtered
		}
	}
	issuer := cmp.Or(s.provider.String(ctx, talosconfig.KeyCredentialsIssuer), "http://localhost/ory/talos")

	// Create token claims (reuses `now` captured before expiry validation above).
	claims := token.NewClaims()
	claims.SetTokenID(crypto.GenerateKeyID())
	claims.SetSubject(key.KeyID)
	claims.SetIssuer(issuer)
	claims.SetIssuedAt(now)
	claims.SetExpiration(now.Add(ttl))
	claims.SetNotBefore(now)
	claims.SetTokenType(token.TokenTypeDerived)
	claims.SetKeyID(key.KeyID)
	claims.SetParentID(key.KeyID)
	claims.SetActorID(sqlutil.Deref(key.ActorID))
	claims.SetScopes(scopes)
	claims.SetMetadata(metadataMap)
	claims.SetCustomClaims(filteredCustomClaims)
	claims.SetNetworkID(ctxNID)

	// Propagate IP restrictions from parent key to derived token so
	// session tokens enforce the same CIDR allowlist.
	if cidrs := clientip.UnmarshalCIDRs(key.AllowedCidrs); len(cidrs) > 0 {
		claims.SetAllowedCidrs(cidrs)
	}

	if key.Visibility == int32(talosv2alpha1.KeyVisibility_KEY_VISIBILITY_PUBLIC) {
		claims.SetVisibility("public")
	} else {
		claims.SetVisibility("secret")
	}

	// Sign token based on algorithm
	tokenString, err := token.SignDerivedToken(ctx, token.SignDerivedTokenParams{
		Algorithm:      algorithm,
		Claims:         claims,
		KID:            kid,
		PrivateKey:     privateKey,
		HMACSecret:     hmacSecret,
		Issuer:         issuer,
		MacaroonPrefix: cmp.Or(s.provider.String(ctx, talosconfig.KeyCredentialsDerivedTokensMacaroonPrefixCurrent), "mc"),
	})
	if err != nil {
		return nil, err
	}

	// Build response claims: merge parent metadata with user-defined custom claims
	responseClaims := metadataMap
	if len(filteredCustomClaims) > 0 {
		merged := make(map[string]any, len(metadataMap)+len(filteredCustomClaims))
		maps.Copy(merged, metadataMap)
		maps.Copy(merged, filteredCustomClaims)
		responseClaims = merged
	}
	claimsStruct, err := structpb.NewStruct(responseClaims)
	if err != nil {
		return nil, errdef.InternalError("convert metadata to struct").WithWrap(errors.WithStack(err))
	}

	// Record metrics
	s.metrics.TokensMinted.Inc()

	// Emit audit event
	eventcontext.NewFromContext(ctx, events.EventAPIKeyDerivedToken).
		WithKeyID(key.KeyID).
		WithMetadata("algorithm", algorithm).
		WithMetadata("ttl", fmt.Sprint(ttl)).
		Emit(ctx, s.emitter)

	tokenExp, _ := claims.Expiration()
	return &talosv2alpha1.DeriveTokenResponse{
		Token: &talosv2alpha1.Token{
			Token:      tokenString,
			ExpireTime: timestamppb.New(tokenExp),
			Scopes:     scopes,
			Claims:     claimsStruct,
		},
	}, nil
}

// Imported Key Management

// ImportAPIKey imports an external HMAC-based API key
func (s *Admin) ImportAPIKey(ctx context.Context, req *talosv2alpha1.ImportApiKeyRequest) (_ *talosv2alpha1.ImportedApiKey, err error) {
	if err := s.protoValidator.Validate(req); err != nil {
		return nil, errdef.BadRequest(err.Error())
	}

	ctx, span := tracing.Start(
		ctx, "service.ImportAPIKey",
		attribute.String("actor_id", req.GetActorId()),
	)
	defer otelx.End(span, &err)

	// Validate and normalize (apply default and max TTL policy)
	normalized, err := validation.ValidateAndNormalizeImportRequest(req, s.provider.Duration(ctx, talosconfig.KeyCredentialsAPIKeysDefaultTTL), s.provider.Duration(ctx, talosconfig.KeyCredentialsAPIKeysMaxTTL))
	if err != nil {
		return nil, err
	}

	// Format conflict detection
	route := crypto.RouteCredential(normalized.RawKey, s.getMacaroonPrefixes(ctx))
	if route.Type == crypto.CredentialTypeIssued {
		return nil, errdef.Conflict("cannot import key: format conflicts with issued api key pattern")
	}
	if route.Type == crypto.CredentialTypeDerivedJWT || route.Type == crypto.CredentialTypeDerivedMacaroon {
		return nil, errdef.FailedPrecondition("cannot import key: format conflicts with derived token pattern")
	}

	if err := s.enforceAPIKeyQuota(ctx, 1); err != nil {
		return nil, err
	}

	// Generate deterministic key ID
	nid := contextx.NetworkIDFromContext(ctx).String()
	keyID := crypto.HashImportedAPIKey(normalized.RawKey, nid)

	// Insert-first: attempt the insert directly and handle unique violations.
	// This avoids two extra DB round-trips (idempotency check + duplicate check) on the happy path.
	// The unique index on (nid, key_id) catches duplicate raw keys; the unique index on
	// (nid, request_id) catches idempotent replays.
	dbKey, err := s.driver.CreateImportedAPIKey(ctx, persistencetypes.CreateImportedKeyParams{
		KeyID:           keyID,
		ActorID:         normalized.ActorID,
		Name:            normalized.Name,
		Scopes:          normalized.Fields.Scopes,
		Metadata:        normalized.Fields.Metadata,
		Status:          int32(talosv2alpha1.KeyStatus_KEY_STATUS_ACTIVE),
		ExpiresAt:       normalized.ExpiresAt,
		RateLimitQuota:  normalized.Fields.RateLimitQuota,
		RateLimitWindow: normalized.Fields.RateLimitWindow,
		AllowedCIDRs:    normalized.Fields.AllowedCIDRs,
		RequestID:       req.RequestId,
		Visibility:      normalizeVisibility(req.GetVisibility()),
	})
	if err != nil && !persistence.IsUniqueViolation(err) {
		return nil, handleDBError(err, apiKeyKindImported, "import key")
	}
	// If request_id was provided, the violation may be from the idempotency index.
	// Fetch the existing key and return it (idempotent replay, AIP-155).
	if err != nil && req.RequestId != "" {
		existing, idErr := s.driver.GetImportedAPIKeyByRequestID(ctx, req.RequestId)
		if idErr == nil {
			importedAPIKey, convErr := dbImportedKeyToProto(persistencetypes.ImportedAPIKeyToIssuedAPIKey(ctx, existing))
			if convErr != nil {
				return nil, wrapDecodePersistedScopesError(convErr)
			}
			return importedAPIKey, nil
		}
		if !errors.Is(idErr, sql.ErrNoRows) {
			return nil, handleDBError(idErr, apiKeyKindImported, "idempotency lookup")
		}
	}
	if err != nil {
		// Not an idempotency replay — the raw key was already imported (hash collision on primary key).
		return nil, errdef.ErrAPIKeyExists().WithReasonf("key already imported (duplicate detected)").WithWrap(errors.WithStack(err))
	}

	importedAPIKey, err := dbImportedKeyToProto(persistencetypes.ImportedAPIKeyToIssuedAPIKey(ctx, dbKey))
	if err != nil {
		return nil, wrapDecodePersistedScopesError(err)
	}
	span.SetAttributes(attribute.String("key_id", importedAPIKey.GetKeyId()))

	// Record metrics (imported keys count as created keys)
	s.metrics.APIKeysCreated.Inc()

	// Emit audit event
	eventcontext.NewFromContext(ctx, events.EventImportedAPIKeyCreated).
		WithKeyID(importedAPIKey.GetKeyId()).
		WithActor(importedAPIKey.GetActorId()).
		WithExpiry(normalized.ExpiresAt).
		WithVisibility(visibilityLabel(req.GetVisibility())).
		Emit(ctx, s.emitter)

	return importedAPIKey, nil
}

// batchCandidate pairs a validated batch item with its original index in the request.
type batchCandidate struct {
	index int
	item  persistmodel.BatchCreateImportedAPIKeyInput
}

// BatchImportAPIKeys imports multiple external API keys.
//
// The handler intentionally does not run protoValidator.Validate(req) on the
// whole request because the per-item ImportApiKeyRequest rules would
// short-circuit the entire batch on a single bad item, contradicting
// AIP-231's per-item success/failure contract. The min_items/max_items
// constraint on requests is enforced below by the explicit length checks.
// Instead, the same proto rules that guard single ImportAPIKey run per item
// inside the loop (protoValidator.Validate on each ImportApiKeyRequest),
// followed by validation.ValidateAndNormalizeImportRequest, so a violating
// item fails individually while its siblings proceed.
func (s *Admin) BatchImportAPIKeys(ctx context.Context, req *talosv2alpha1.BatchCreateImportedApiKeysRequest) (_ *talosv2alpha1.BatchCreateImportedApiKeysResponse, err error) {
	nid := contextx.NetworkIDFromContext(ctx).String()
	keys := req.GetRequests()
	batchSize := len(keys)

	ctx, span := tracing.Start(
		ctx, "service.BatchImportAPIKeys",
		attribute.Int("batch_size", batchSize),
	)
	defer otelx.End(span, &err)

	if batchSize == 0 {
		return nil, errdef.BadRequest("keys must contain at least one item")
	}
	if batchSize > MaxBatchImportSize {
		return nil, errdef.BadRequest("maximum 1000 keys per batch")
	}

	s.metrics.BatchImportRequests.Inc()
	s.metrics.BatchImportKeyCount.Observe(float64(batchSize))

	// --- Phase 1: Validate each item and build candidates for DB insert ---
	results := make([]*talosv2alpha1.BatchCreateImportedApiKeysResult, batchSize)
	candidates := make([]batchCandidate, 0, batchSize)
	firstIndexByKeyID := make(map[string]int, batchSize)

	for i, keyReq := range keys {
		if keyReq == nil {
			results[i] = batchImportErrorResult(i, talosv2alpha1.BatchCreateImportedApiKeysErrorCode_BATCH_CREATE_IMPORTED_API_KEYS_ERROR_INVALID_ARGUMENT, "batch item is required")
			continue
		}

		// Enforce the same buf.validate rules as single ImportAPIKey (raw_key,
		// name, actor_id, scopes, request_id constraints) per item so the batch
		// path cannot bypass proto validation. A violation fails only this item.
		if validateErr := s.protoValidator.Validate(keyReq); validateErr != nil {
			results[i] = batchImportErrorResult(i, talosv2alpha1.BatchCreateImportedApiKeysErrorCode_BATCH_CREATE_IMPORTED_API_KEYS_ERROR_INVALID_ARGUMENT, validateErr.Error())
			continue
		}

		normalized, normErr := validation.ValidateAndNormalizeImportRequest(keyReq, s.provider.Duration(ctx, talosconfig.KeyCredentialsAPIKeysDefaultTTL), s.provider.Duration(ctx, talosconfig.KeyCredentialsAPIKeysMaxTTL))
		if normErr != nil {
			errorCode := talosv2alpha1.BatchCreateImportedApiKeysErrorCode_BATCH_CREATE_IMPORTED_API_KEYS_ERROR_INTERNAL
			errorMessage := normErr.Error()
			var herodotErr *herodot.DefaultError
			if errors.As(normErr, &herodotErr) {
				if m := herodotErr.ReasonField; m != "" {
					errorMessage = m
				} else if m := herodotErr.ErrorField; m != "" {
					errorMessage = m
				}
				switch herodotErr.GRPCCodeField {
				case codes.OK,
					codes.Canceled,
					codes.Unknown,
					codes.DeadlineExceeded,
					codes.NotFound,
					codes.PermissionDenied,
					codes.ResourceExhausted,
					codes.Aborted,
					codes.OutOfRange,
					codes.Unimplemented,
					codes.Internal,
					codes.Unavailable,
					codes.DataLoss,
					codes.Unauthenticated:
					errorCode = talosv2alpha1.BatchCreateImportedApiKeysErrorCode_BATCH_CREATE_IMPORTED_API_KEYS_ERROR_INTERNAL
				case codes.InvalidArgument:
					errorCode = talosv2alpha1.BatchCreateImportedApiKeysErrorCode_BATCH_CREATE_IMPORTED_API_KEYS_ERROR_INVALID_ARGUMENT
				case codes.AlreadyExists:
					errorCode = talosv2alpha1.BatchCreateImportedApiKeysErrorCode_BATCH_CREATE_IMPORTED_API_KEYS_ERROR_ALREADY_EXISTS
				case codes.FailedPrecondition:
					errorCode = talosv2alpha1.BatchCreateImportedApiKeysErrorCode_BATCH_CREATE_IMPORTED_API_KEYS_ERROR_FAILED_PRECONDITION
				}
			}
			results[i] = batchImportErrorResult(i, errorCode, errorMessage)
			continue
		}

		route := crypto.RouteCredential(normalized.RawKey, s.getMacaroonPrefixes(ctx))
		if route.Type == crypto.CredentialTypeIssued {
			results[i] = batchImportErrorResult(i, talosv2alpha1.BatchCreateImportedApiKeysErrorCode_BATCH_CREATE_IMPORTED_API_KEYS_ERROR_FAILED_PRECONDITION, "cannot import key: format conflicts with issued api key pattern")
			continue
		}
		if route.Type == crypto.CredentialTypeDerivedJWT || route.Type == crypto.CredentialTypeDerivedMacaroon {
			results[i] = batchImportErrorResult(i, talosv2alpha1.BatchCreateImportedApiKeysErrorCode_BATCH_CREATE_IMPORTED_API_KEYS_ERROR_FAILED_PRECONDITION, "cannot import key: format conflicts with derived token pattern")
			continue
		}

		keyID := crypto.HashImportedAPIKey(normalized.RawKey, nid)
		if firstIndex, exists := firstIndexByKeyID[keyID]; exists {
			results[i] = batchImportErrorResult(i, talosv2alpha1.BatchCreateImportedApiKeysErrorCode_BATCH_CREATE_IMPORTED_API_KEYS_ERROR_ALREADY_EXISTS, fmt.Sprintf("key already imported (duplicate detected at index %d)", firstIndex))
			continue
		}

		firstIndexByKeyID[keyID] = i
		candidates = append(candidates, batchCandidate{
			index: i,
			item: persistmodel.BatchCreateImportedAPIKeyInput{
				KeyID:           keyID,
				ActorID:         normalized.ActorID,
				Name:            normalized.Name,
				Scopes:          normalized.Fields.Scopes,
				Metadata:        normalized.Fields.Metadata,
				ExpiresAt:       normalized.ExpiresAt,
				RateLimitQuota:  normalized.Fields.RateLimitQuota,
				RateLimitWindow: normalized.Fields.RateLimitWindow,
				AllowedCIDRs:    normalized.Fields.AllowedCIDRs,
				Visibility:      normalizeVisibility(keyReq.GetVisibility()),
			},
		})
	}

	// Cap enforcement: trim candidates that would exceed the plan-allotted
	// maximum. The first headroom candidates proceed; the rest are reported as
	// per-item quota errors so the AIP-231 batch contract is preserved.
	if quotaCap := int64(s.provider.Int(ctx, talosconfig.KeyQuotaAPIKeysMax)); quotaCap > 0 && len(candidates) > 0 {
		current, countErr := s.driver.CountActiveAPIKeysUpTo(ctx, quotaCap)
		if countErr != nil {
			return nil, handleDBError(countErr, apiKeyKindImported, "count active API keys")
		}
		headroom := max(quotaCap-current, 0)
		if int64(len(candidates)) > headroom {
			rejected := candidates[headroom:]
			reason := fmt.Sprintf("the API key quota for this plan permits up to %d active API keys", quotaCap)
			for _, c := range rejected {
				results[c.index] = batchImportErrorResult(c.index, talosv2alpha1.BatchCreateImportedApiKeysErrorCode_BATCH_CREATE_IMPORTED_API_KEYS_ERROR_RESOURCE_EXHAUSTED, reason)
			}
			candidates = candidates[:headroom]
		}
	}

	// --- Phase 2: Execute the batch insert for all valid candidates ---
	if len(candidates) > 0 {
		inputs := make([]persistmodel.BatchCreateImportedAPIKeyInput, len(candidates))
		for i, c := range candidates {
			inputs[i] = c.item
		}

		batchResult, insertErr := s.driver.CreateImportedAPIKeysBatch(ctx, inputs)
		if insertErr != nil {
			return nil, handleDBError(insertErr, apiKeyKindImported, "import keys in batch")
		}

		for _, c := range candidates {
			if inserted, ok := batchResult.Inserted[c.item.KeyID]; ok {
				importedAPIKey, convErr := dbImportedKeyToProto(persistencetypes.ImportedAPIKeyToIssuedAPIKey(ctx, inserted))
				if convErr != nil {
					return nil, wrapDecodePersistedScopesError(convErr)
				}
				results[c.index] = &talosv2alpha1.BatchCreateImportedApiKeysResult{
					Index:          safeBatchIndex(c.index),
					ImportedApiKey: importedAPIKey,
				}
			} else if _, exists := batchResult.Existing[c.item.KeyID]; exists {
				results[c.index] = batchImportErrorResult(c.index, talosv2alpha1.BatchCreateImportedApiKeysErrorCode_BATCH_CREATE_IMPORTED_API_KEYS_ERROR_ALREADY_EXISTS, "key already imported (duplicate detected)")
			} else {
				results[c.index] = batchImportErrorResult(c.index, talosv2alpha1.BatchCreateImportedApiKeysErrorCode_BATCH_CREATE_IMPORTED_API_KEYS_ERROR_INTERNAL, "batch insert returned no row for key")
			}
		}
	}

	// --- Phase 3: Fill nil result slots, emit events, record metrics ---
	var successCount, failureCount int32
	for i, result := range results {
		if result == nil {
			code := talosv2alpha1.BatchCreateImportedApiKeysErrorCode_BATCH_CREATE_IMPORTED_API_KEYS_ERROR_INTERNAL
			message := "batch item failed with no result"
			results[i] = &talosv2alpha1.BatchCreateImportedApiKeysResult{
				Index:        safeBatchIndex(i),
				ErrorCode:    &code,
				ErrorMessage: &message,
			}
			result = results[i]
		}

		if result.GetImportedApiKey() != nil {
			successCount++
			var expiry *time.Time
			if et := result.GetImportedApiKey().GetExpireTime(); et != nil {
				t := et.AsTime()
				expiry = &t
			}
			eventcontext.NewFromContext(ctx, events.EventImportedAPIKeyCreated).
				WithKeyID(result.GetImportedApiKey().GetKeyId()).
				WithActor(result.GetImportedApiKey().GetActorId()).
				WithExpiry(expiry).
				WithVisibility(visibilityLabel(result.GetImportedApiKey().GetVisibility())).
				Emit(ctx, s.emitter)
			continue
		}

		failureCount++
		failureEvent := eventcontext.NewFromContext(ctx, events.EventAPIKeyImportFailed).
			WithKeyType("imported").
			WithReason(cmp.Or(result.GetErrorMessage(), "batch import failed")).
			WithMetadata("index", fmt.Sprintf("%d", result.GetIndex())).
			WithMetadata("error_code", result.GetErrorCode().String())
		if keyReq := keys[i]; keyReq != nil {
			failureEvent = failureEvent.WithActor(keyReq.GetActorId())
		}
		failureEvent.Emit(ctx, s.emitter)
	}

	if successCount > 0 {
		s.metrics.APIKeysCreated.Add(float64(successCount))
	}
	if successCount > 0 && failureCount > 0 {
		s.metrics.BatchImportPartialFailures.Inc()
	}

	// Record per-key outcome metrics.
	failedByCode := make(map[string]int)
	for _, result := range results {
		if result != nil && result.ErrorCode != nil {
			failedByCode[batchImportErrorCodeLabel(result.GetErrorCode())]++
		}
	}
	s.metrics.RecordBatchImportOutcome(int(successCount), failedByCode)

	if successCount == 0 {
		counts := make(map[talosv2alpha1.BatchCreateImportedApiKeysErrorCode]int)
		for _, result := range results {
			if result != nil && result.ErrorCode != nil {
				counts[result.GetErrorCode()]++
			}
		}
		dominantCode := talosv2alpha1.BatchCreateImportedApiKeysErrorCode_BATCH_CREATE_IMPORTED_API_KEYS_ERROR_INTERNAL
		for _, code := range []talosv2alpha1.BatchCreateImportedApiKeysErrorCode{
			talosv2alpha1.BatchCreateImportedApiKeysErrorCode_BATCH_CREATE_IMPORTED_API_KEYS_ERROR_ALREADY_EXISTS,
			talosv2alpha1.BatchCreateImportedApiKeysErrorCode_BATCH_CREATE_IMPORTED_API_KEYS_ERROR_INVALID_ARGUMENT,
			talosv2alpha1.BatchCreateImportedApiKeysErrorCode_BATCH_CREATE_IMPORTED_API_KEYS_ERROR_FAILED_PRECONDITION,
			talosv2alpha1.BatchCreateImportedApiKeysErrorCode_BATCH_CREATE_IMPORTED_API_KEYS_ERROR_RESOURCE_EXHAUSTED,
		} {
			if counts[code] > counts[dominantCode] {
				dominantCode = code
			}
		}
		switch dominantCode {
		case talosv2alpha1.BatchCreateImportedApiKeysErrorCode_BATCH_CREATE_IMPORTED_API_KEYS_ERROR_UNSPECIFIED,
			talosv2alpha1.BatchCreateImportedApiKeysErrorCode_BATCH_CREATE_IMPORTED_API_KEYS_ERROR_INTERNAL:
			return nil, errors.WithStack(errdef.InternalError("all keys in batch import failed"))
		case talosv2alpha1.BatchCreateImportedApiKeysErrorCode_BATCH_CREATE_IMPORTED_API_KEYS_ERROR_ALREADY_EXISTS:
			return nil, errors.WithStack(errdef.ErrAPIKeyExists().WithReasonf("all keys in batch already exist"))
		case talosv2alpha1.BatchCreateImportedApiKeysErrorCode_BATCH_CREATE_IMPORTED_API_KEYS_ERROR_INVALID_ARGUMENT:
			return nil, errors.WithStack(errdef.BadRequest("all keys in batch failed validation"))
		case talosv2alpha1.BatchCreateImportedApiKeysErrorCode_BATCH_CREATE_IMPORTED_API_KEYS_ERROR_FAILED_PRECONDITION:
			return nil, errors.WithStack(errdef.FailedPrecondition("all keys in batch failed precondition checks"))
		case talosv2alpha1.BatchCreateImportedApiKeysErrorCode_BATCH_CREATE_IMPORTED_API_KEYS_ERROR_RESOURCE_EXHAUSTED:
			return nil, errors.WithStack(errdef.ErrAPIKeyQuotaExceeded().WithReasonf("all keys in batch exceeded the tenant quota"))
		}

		return nil, errors.WithStack(errdef.InternalError("all keys in batch import failed"))
	}

	return &talosv2alpha1.BatchCreateImportedApiKeysResponse{
		Results:      results,
		SuccessCount: successCount,
		FailureCount: failureCount,
	}, nil
}

func batchImportErrorResult(index int, code talosv2alpha1.BatchCreateImportedApiKeysErrorCode, message string) *talosv2alpha1.BatchCreateImportedApiKeysResult {
	return &talosv2alpha1.BatchCreateImportedApiKeysResult{
		Index:        safeBatchIndex(index),
		ErrorCode:    &code,
		ErrorMessage: &message,
	}
}

func safeBatchIndex(index int) int32 {
	if index < 0 {
		return 0
	}
	if index >= MaxBatchImportSize {
		return MaxBatchImportSize - 1
	}

	return int32(index)
}

// batchImportErrorCodeLabel maps a BatchCreateImportedApiKeysErrorCode to a short, bounded
// Prometheus label value. Using raw proto enum strings would risk unbounded
// cardinality if the enum grows.
func batchImportErrorCodeLabel(code talosv2alpha1.BatchCreateImportedApiKeysErrorCode) string {
	switch code {
	case talosv2alpha1.BatchCreateImportedApiKeysErrorCode_BATCH_CREATE_IMPORTED_API_KEYS_ERROR_UNSPECIFIED,
		talosv2alpha1.BatchCreateImportedApiKeysErrorCode_BATCH_CREATE_IMPORTED_API_KEYS_ERROR_INTERNAL:
		return "INTERNAL"
	case talosv2alpha1.BatchCreateImportedApiKeysErrorCode_BATCH_CREATE_IMPORTED_API_KEYS_ERROR_ALREADY_EXISTS:
		return "ALREADY_EXISTS"
	case talosv2alpha1.BatchCreateImportedApiKeysErrorCode_BATCH_CREATE_IMPORTED_API_KEYS_ERROR_INVALID_ARGUMENT:
		return "INVALID_ARGUMENT"
	case talosv2alpha1.BatchCreateImportedApiKeysErrorCode_BATCH_CREATE_IMPORTED_API_KEYS_ERROR_FAILED_PRECONDITION:
		return "FAILED_PRECONDITION"
	case talosv2alpha1.BatchCreateImportedApiKeysErrorCode_BATCH_CREATE_IMPORTED_API_KEYS_ERROR_RESOURCE_EXHAUSTED:
		return "RESOURCE_EXHAUSTED"
	}

	return "INTERNAL"
}

// ListImportedAPIKeys lists imported keys with cursor-based pagination
func (s *Admin) ListImportedAPIKeys(ctx context.Context, req *talosv2alpha1.ListImportedApiKeysRequest) (_ *talosv2alpha1.ListImportedApiKeysResponse, err error) {
	if err := s.protoValidator.Validate(req); err != nil {
		return nil, errdef.BadRequest(err.Error())
	}

	ctx, span := tracing.Start(ctx, "service.ListImportedAPIKeys")
	defer otelx.End(span, &err)

	// Shared pagination setup: filter parsing, page size, cursor decoding
	q, err := s.pagination.prepareListQuery(ctx, req.Filter, req.PageSize, req.PageToken)
	if err != nil {
		return nil, err
	}

	// Fetch keys (one extra for hasMore detection) - NID is extracted from context internally by the driver
	keys, err := s.driver.ListImportedAPIKeys(ctx, int32(q.filter.Status), q.filter.ActorID, q.cursorKey, q.limit)
	if err != nil {
		return nil, handleDBError(err, apiKeyKindImported, "list imported keys")
	}

	// Trim results and generate next page token if needed
	originalCount := len(keys)
	keys = trimResults(keys, q.pageSize)
	var nextPageToken string
	if len(keys) > 0 {
		nextPageToken, err = s.pagination.nextPageToken(ctx, originalCount, q.pageSize, keys[len(keys)-1].KeyID)
		if err != nil {
			return nil, err
		}
	}

	// Convert ImportedApiKey slice to protobuf
	protoKeys := make([]*talosv2alpha1.ImportedApiKey, len(keys))
	for i, key := range keys {
		apiKey := persistencetypes.ImportedAPIKeyToIssuedAPIKey(ctx, key)
		protoKey, err := dbImportedKeyToProto(apiKey)
		if err != nil {
			return nil, wrapDecodePersistedScopesError(err)
		}
		protoKeys[i] = protoKey
	}

	return &talosv2alpha1.ListImportedApiKeysResponse{
		ImportedApiKeys: protoKeys,
		NextPageToken:   nextPageToken,
	}, nil
}

// GetImportedAPIKey retrieves an imported key by its hash ID
func (s *Admin) GetImportedAPIKey(ctx context.Context, req *talosv2alpha1.GetImportedApiKeyRequest) (_ *talosv2alpha1.ImportedApiKey, err error) {
	if err := s.protoValidator.Validate(req); err != nil {
		return nil, errdef.BadRequest(err.Error())
	}

	ctx, span := tracing.Start(
		ctx, "service.GetImportedAPIKey",
		attribute.String("key_id", req.KeyId),
	)
	defer otelx.End(span, &err)

	// Get imported key by hash
	key, err := s.driver.GetImportedAPIKeyByHash(ctx, req.KeyId)
	if err != nil {
		return nil, handleDBError(err, apiKeyKindImported, "get imported key")
	}
	// Convert ImportedApiKey to protobuf
	apiKey := persistencetypes.ImportedAPIKeyToIssuedAPIKey(ctx, key)

	importedAPIKey, err := dbImportedKeyToProto(apiKey)
	if err != nil {
		return nil, wrapDecodePersistedScopesError(err)
	}
	return importedAPIKey, nil
}

// UpdateImportedAPIKey updates mutable fields of an imported API key (AIP-134)
func (s *Admin) UpdateImportedAPIKey(ctx context.Context, req *talosv2alpha1.UpdateImportedApiKeyRequest) (_ *talosv2alpha1.ImportedApiKey, err error) {
	if err := s.protoValidator.Validate(req); err != nil {
		return nil, errdef.BadRequest(err.Error())
	}

	patch := req.GetImportedApiKey()
	keyID := patch.GetKeyId()

	ctx, span := tracing.Start(
		ctx, "service.UpdateImportedAPIKey",
		attribute.String("key_id", keyID),
	)
	defer otelx.End(span, &err)

	// Apply AIP-134 field mask semantics (or legacy presence-based fallback).
	// Validate mask paths before the DB read so a typo fails fast with
	// InvalidArgument rather than performing a no-op update.
	mask, err := newFieldMaskValidated(req.GetUpdateMask().GetPaths(), allowedImportedKeyMaskPaths)
	if err != nil {
		return nil, err
	}

	// Get the existing key first to preserve unmodified fields
	existingKey, err := s.driver.GetImportedAPIKeyByHash(ctx, keyID)
	if err != nil {
		return nil, handleDBError(err, apiKeyKindImported, "get imported key for update")
	}

	// Start with existing values (via the common db.IssuedApiKey representation)
	existing := persistencetypes.ImportedAPIKeyToIssuedAPIKey(ctx, existingKey)
	name := existing.Name
	scopes, err := sqlutil.UnmarshalScopes(existing.Scopes)
	if err != nil {
		return nil, wrapDecodePersistedScopesError(err)
	}
	metadataJSON := existing.Metadata

	name = mask.applyString("name", patch.GetName(), name)
	scopes = applySlice(mask, "scopes", patch.GetScopes(), scopes)

	metadataJSON, err = mask.applyMetadata(patch.GetMetadata(), metadataJSON)
	if err != nil {
		return nil, err
	}

	rateLimitQuota, rateLimitWindow := extractRateLimitPolicy(patch.GetRateLimitPolicy(), mask.useMask, mask.has("rate_limit_policy"), existing.RateLimitQuota, existing.RateLimitWindow)

	allowedCIDRs, err := extractIPRestriction(patch.GetIpRestriction(), mask.useMask, mask.has("ip_restriction"))
	if err != nil {
		return nil, err
	}

	updatedKey, err := s.driver.UpdateImportedAPIKeyMetadata(ctx, persistencetypes.UpdateImportedKeyParams{
		KeyID:           keyID,
		Name:            name,
		Scopes:          scopes,
		Metadata:        metadataJSON,
		RateLimitQuota:  rateLimitQuota,
		RateLimitWindow: rateLimitWindow,
		AllowedCIDRs:    allowedCIDRs,
	})
	if err != nil {
		return nil, handleDBError(err, apiKeyKindImported, "update imported API key")
	}

	s.invalidateVerifierCache(ctx, keyID)

	eventcontext.NewFromContext(ctx, events.EventImportedAPIKeyUpdated).
		WithKeyID(keyID).
		WithActor(sqlutil.Deref(updatedKey.ActorID)).
		WithExpiry(updatedKey.ExpiresAt).
		WithVisibility(visibilityLabel(talosv2alpha1.KeyVisibility(updatedKey.Visibility))).
		Emit(ctx, s.emitter)

	importedAPIKey, err := dbImportedKeyToProto(persistencetypes.ImportedAPIKeyToIssuedAPIKey(ctx, updatedKey))
	if err != nil {
		return nil, wrapDecodePersistedScopesError(err)
	}
	return importedAPIKey, nil
}

// DeleteImportedAPIKey permanently deletes an imported key
func (s *Admin) DeleteImportedAPIKey(ctx context.Context, req *talosv2alpha1.DeleteImportedApiKeyRequest) (_ *emptypb.Empty, err error) {
	if err := s.protoValidator.Validate(req); err != nil {
		return nil, errdef.BadRequest(err.Error())
	}

	ctx, span := tracing.Start(
		ctx, "service.DeleteImportedAPIKey",
		attribute.String("key_id", req.KeyId),
	)
	defer otelx.End(span, &err)

	// Verify key exists and is imported before deletion
	importedKey, err := s.driver.GetImportedAPIKeyByHash(ctx, req.KeyId)
	if err != nil {
		return nil, handleDBError(err, apiKeyKindImported, "get imported key")
	}

	// Delete the key permanently
	err = s.driver.DeleteImportedAPIKey(ctx, req.KeyId)
	if err != nil {
		return nil, handleDBError(err, apiKeyKindImported, "delete imported key")
	}

	s.invalidateVerifierCache(ctx, req.KeyId)

	eventcontext.NewFromContext(ctx, events.EventImportedAPIKeyDeleted).
		WithKeyID(req.KeyId).
		WithActor(sqlutil.Deref(importedKey.ActorID)).
		WithExpiry(importedKey.ExpiresAt).
		WithVisibility(visibilityLabel(talosv2alpha1.KeyVisibility(importedKey.Visibility))).
		Emit(ctx, s.emitter)

	return &emptypb.Empty{}, nil
}

// reviewed - @aeneasr - 2026-03-26
