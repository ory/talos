// Package verifier provides API key and token verification functionality.
package verifier

import (
	"cmp"
	"context"
	"database/sql"
	"encoding/json"
	stderrors "errors"
	"log/slog"
	"maps"
	"slices"
	"sync"
	"sync/atomic"
	"time"

	"github.com/cockroachdb/errors"
	"github.com/lestrrat-go/jwx/v3/jwk"

	"github.com/ory/herodot"

	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/trace"

	"github.com/ory/talos/internal/cache"
	"github.com/ory/talos/internal/cachecontrol"
	"github.com/ory/talos/internal/clientip"
	talosconfig "github.com/ory/talos/internal/config"
	"github.com/ory/talos/internal/crypto"
	"github.com/ory/talos/internal/crypto/token"
	"github.com/ory/talos/internal/crypto/verifier"
	"github.com/ory/talos/internal/errdef"
	"github.com/ory/talos/internal/eventcontext"
	"github.com/ory/talos/internal/events"
	"github.com/ory/talos/internal/lastused"
	"github.com/ory/talos/internal/metrics"
	"github.com/ory/talos/internal/persistence"
	db "github.com/ory/talos/internal/persistence/sqlc/generated"
	"github.com/ory/talos/internal/persistence/sqlutil"
	persistencetypes "github.com/ory/talos/internal/persistence/types"
	"github.com/ory/talos/internal/tracing"
	talosv2alpha1 "github.com/ory/talos/pkg/api/talos/v2alpha1"

	"github.com/ory/talos/internal/contextx"
	"github.com/ory/x/otelx"
)

// clientIPSourceFromString parses a ClientIPSource enum name to its int32 value.
// Returns 0 (UNSPECIFIED = remote addr) for unknown strings, logging a warning
// so misconfigured values don't silently fall back to the wrong IP source.
func clientIPSourceFromString(s string) int32 {
	switch s {
	case "", "CLIENT_IP_SOURCE_UNSPECIFIED":
		return 0
	case "CLIENT_IP_SOURCE_REMOTE_ADDR":
		return 1
	case "CLIENT_IP_SOURCE_CF_CONNECTING_IP":
		return 2
	case "CLIENT_IP_SOURCE_X_FORWARDED_FOR":
		return 3
	case "CLIENT_IP_SOURCE_X_REAL_IP":
		return 4
	case "CLIENT_IP_SOURCE_TRUE_CLIENT_IP":
		return 5
	default:
		slog.Warn("unknown client IP source, falling back to remote address",
			slog.String("configured_value", s))
		return 0
	}
}

// ConfigProvider defines configuration methods used by the verifier.
type ConfigProvider interface {
	String(ctx context.Context, key talosconfig.Key) string
	Strings(ctx context.Context, key talosconfig.Key) []string
	ActiveRetiredValues(ctx context.Context, key talosconfig.Key) ([]string, error)
	Duration(ctx context.Context, key talosconfig.Key) time.Duration
	Bool(ctx context.Context, key talosconfig.Key) bool
}

const (
	// failureEventRateLimit is the maximum number of verification failure events
	// emitted per NID per rate limit window. Under adversarial load, unlimited
	// event emission would DDoS the event pipeline.
	failureEventRateLimit int64 = 10

	// failureEventWindow is the time window for the per-NID failure event rate limit.
	failureEventWindow = time.Minute
)

// failureEventBucket tracks per-NID rate limiting for verification failure events.
// Each bucket allows failureEventRateLimit events per failureEventWindow.
// mu serializes all reads and writes to count and windowNs so no goroutine can
// observe a partially-reset bucket (e.g. window updated but count not yet zeroed).
type failureEventBucket struct {
	mu       sync.Mutex
	count    int64 // protected by mu
	windowNs int64 // unix nano of the current window start; protected by mu
}

// failureEventLimiter provides per-NID rate limiting for verification failure events.
// Uses sync.Map for lock-free concurrent access across verification goroutines.
// Stale buckets are evicted periodically to prevent unbounded memory growth.
type failureEventLimiter struct {
	buckets     sync.Map     // map[string]*failureEventBucket (keyed by NID string)
	lastCleanup atomic.Int64 // unix nano of last cleanup sweep
}

const failureEventCleanupInterval = 5 * time.Minute

// allow returns true if a failure event may be emitted for the given NID.
// When the rate limit is exceeded, returns false.
func (l *failureEventLimiter) allow(nid string) bool {
	now := time.Now().UnixNano()

	// Periodically evict stale buckets to bound memory growth.
	lastClean := l.lastCleanup.Load()
	if now-lastClean > failureEventCleanupInterval.Nanoseconds() {
		if l.lastCleanup.CompareAndSwap(lastClean, now) {
			windowNs := failureEventWindow.Nanoseconds()
			l.buckets.Range(func(key, value any) bool {
				bucket, ok := value.(*failureEventBucket)
				if !ok {
					// The sync.Map is private and only ever stores *failureEventBucket;
					// skip any unexpected value defensively rather than panicking.
					return true
				}
				bucket.mu.Lock()
				stale := now-bucket.windowNs > 2*windowNs
				bucket.mu.Unlock()
				if stale {
					l.buckets.Delete(key)
				}
				return true
			})
		}
	}

	// Fast path: check if bucket exists before allocating.
	val, ok := l.buckets.Load(nid)
	if !ok {
		val, _ = l.buckets.LoadOrStore(nid, &failureEventBucket{})
	}
	bucket, ok := val.(*failureEventBucket)
	if !ok {
		// Private sync.Map only stores *failureEventBucket; treat as allowed if
		// the invariant is ever violated rather than panicking in hot paths.
		return true
	}

	bucket.mu.Lock()
	defer bucket.mu.Unlock()

	if now >= bucket.windowNs+failureEventWindow.Nanoseconds() {
		bucket.windowNs = now
		bucket.count = 0
	}
	bucket.count++
	return bucket.count <= failureEventRateLimit
}

// Reset clears all per-NID rate limit buckets. Intended for use in tests only.
func (l *failureEventLimiter) reset() {
	l.buckets.Range(func(key, _ any) bool {
		l.buckets.Delete(key)
		return true
	})
}

// Verifier provides high-performance key and token verification
type Verifier struct {
	driver     persistence.Persister
	provider   ConfigProvider               // Config provider for dynamic config reading
	cache      cache.Cache[db.IssuedApiKey] // Type-safe cache with automatic network ID extraction
	keyService *crypto.KeyService           // KeyService for loading signing keys from config
	emitter    events.Emitter               // Audit event emitter
	verifier   *verifier.Verifier           // Shared token verifier
	metrics    *metrics.Metrics
	tracker    *lastused.Tracker // Batched async last_used_at updates

	failureEventLimiter failureEventLimiter // Per-NID rate limiter for failure events
}

// validateKeyStatusAndExpiration validates key status and expiration.
// Returns nil if key is active and not expired, or an appropriate errdef error otherwise.
func validateKeyStatusAndExpiration(status int32, expiresAt *time.Time) error {
	if status != int32(talosv2alpha1.KeyStatus_KEY_STATUS_ACTIVE) {
		if status == int32(talosv2alpha1.KeyStatus_KEY_STATUS_REVOKED) {
			return errors.WithStack(errdef.ErrAPIKeyRevoked())
		}
		return errors.WithStack(errdef.ErrAPIKeyNotFound().WithReasonf("key status %d", status))
	}

	if expiresAt != nil && time.Now().UTC().After(*expiresAt) {
		return errors.WithStack(errdef.ErrAPIKeyExpired())
	}

	return nil
}

// authenticateIssuedKey validates an issued API key and returns the DB record.
// Performs: parse, timestamp validation, prefix validation, checksum verification, DB lookup, status validation.
// Does NOT: update last_used, cache operations, emit events, record metrics.
func (v *Verifier) authenticateIssuedKey(ctx context.Context, fullKey string) (_ *db.IssuedApiKey, err error) {
	ctx, span := tracing.Start(ctx, "verifier.authenticateIssuedKey")
	defer otelx.End(span, &err)

	// Verify checksum (also parses the key into components, eliminating double parsing)
	hmacSecrets, err := v.getHMACSecrets(ctx)
	if err != nil {
		return nil, errdef.InternalError("get HMAC secrets").WithWrap(errors.WithStack(err))
	}
	components, err := crypto.VerifyAPIKeyChecksum(fullKey, hmacSecrets)
	if err != nil {
		span.SetAttributes(attribute.Bool("checksum_valid", false))
		// Return NOT_FOUND (not INVALID_FORMAT) so callers cannot distinguish
		// a cross-project key (wrong HMAC) from a non-existent key — prevents
		// information leakage about project membership.
		return nil, errors.WithStack(errdef.ErrAPIKeyNotFound().WithReason("invalid API key checksum").WithWrap(err))
	}
	span.SetAttributes(
		attribute.String("key_id", components.KeyID),
		attribute.Bool("checksum_valid", true),
		attribute.String("prefix", components.TokenPrefix),
		attribute.Int64("timestamp", components.Timestamp),
	)

	// Validate timestamp age
	maxAge := v.provider.Duration(ctx, talosconfig.KeyCredentialsAPIKeysMaxTTL)
	if err := crypto.ValidateKeyTimestamp(components.Timestamp, maxAge, v.clockSkew(ctx)); err != nil {
		span.SetAttributes(attribute.Bool("timestamp_valid", false))
		// Return NOT_FOUND so callers cannot distinguish an expired key from a
		// non-existent one — prevents information leakage about key existence.
		return nil, errors.WithStack(errdef.ErrAPIKeyNotFound().WithReason("timestamp out of range").WithWrap(err))
	}
	span.SetAttributes(attribute.Bool("timestamp_valid", true))

	// Validate prefix is allowed.
	// Return NOT_FOUND (not INVALID_FORMAT) so callers cannot distinguish
	// "wrong project" from "key does not exist" — prevents information leakage.
	if !v.isAllowedPrefix(ctx, components.TokenPrefix) {
		span.SetAttributes(attribute.Bool("prefix_allowed", false))
		return nil, errors.WithStack(errdef.ErrAPIKeyNotFound().WithReason("prefix not allowed"))
	}
	span.SetAttributes(attribute.Bool("prefix_allowed", true))

	// DB lookup using the checksum-verified key_id.
	dbKey, err := v.driver.GetIssuedAPIKey(ctx, components.KeyID)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			span.SetAttributes(attribute.Bool("found_in_db", false))
			return nil, errors.WithStack(errdef.ErrAPIKeyNotFound())
		}
		return nil, errdef.InternalError("database error").WithWrap(errors.WithStack(err))
	}
	span.SetAttributes(attribute.Bool("found_in_db", true))

	// Key validation stays in verifier because moving to persistence/types would
	// introduce a proto dependency, violating the dependency graph.
	if err := validateKeyStatusAndExpiration(dbKey.Status, dbKey.ExpiresAt); err != nil {
		return nil, err
	}

	return &dbKey, nil
}

// authenticateImportedKey validates an imported API key and returns the DB record.
// Performs: hash computation, DB lookup, status validation.
// Does NOT: convert to ApiKey, cache operations, emit events, record metrics.
func (v *Verifier) authenticateImportedKey(ctx context.Context, credential string) (_ *db.ImportedApiKey, err error) {
	ctx, span := tracing.Start(ctx, "verifier.authenticateImportedKey")
	defer otelx.End(span, &err)

	// Compute tenant-scoped hash using NID from context.
	// IP validation order is correct: hash computation is CPU-only and precedes DB lookup.
	keyHash := crypto.HashImportedAPIKey(credential, contextx.NetworkIDFromContext(ctx).String())

	importedKey, err := v.driver.GetImportedAPIKeyByHash(ctx, keyHash)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			span.SetAttributes(attribute.Bool("found_in_db", false))
			return nil, errors.WithStack(errdef.ErrAPIKeyNotFound())
		}
		return nil, errdef.InternalError("database error").WithWrap(errors.WithStack(err))
	}
	span.SetAttributes(attribute.Bool("found_in_db", true), attribute.String("key_id", importedKey.KeyID))

	// Key validation stays in verifier (same rationale as authenticateIssuedKey).
	if err := validateKeyStatusAndExpiration(importedKey.Status, importedKey.ExpiresAt); err != nil {
		return nil, err
	}

	return &importedKey, nil
}

// getHMACSecrets returns all HMAC secrets for verification (current + retired).
func (v *Verifier) getHMACSecrets(ctx context.Context) ([][]byte, error) {
	secrets, err := crypto.HMACSecretsForVerification(ctx, v.provider)
	if err != nil {
		return nil, err
	}
	result := make([][]byte, len(secrets))
	for i, s := range secrets {
		result[i] = []byte(s)
	}
	return result, nil
}

// defaultTokenIssuer is the default issuer URL for tokens
const defaultTokenIssuer = "http://localhost/ory/talos"

// GetTokenIssuer reads the current token issuer from config, with a default fallback.
// Used for signing (single issuer stamped into new tokens).
func (v *Verifier) GetTokenIssuer(ctx context.Context) string {
	return cmp.Or(v.provider.String(ctx, talosconfig.KeyCredentialsIssuer), defaultTokenIssuer) // Set the defaults in the JSON schema instead and remove them from here.
}

// getTokenIssuers returns all allowed issuers for verification: [current, ...retired].
// Retired issuers whose expiry has passed are dropped so a forgotten retired issuer
// cannot be used forever.
func (v *Verifier) getTokenIssuers(ctx context.Context) ([]string, error) {
	retired, err := v.provider.ActiveRetiredValues(ctx, talosconfig.KeyCredentialsIssuerRetired)
	if err != nil {
		return nil, err
	}
	return append([]string{v.GetTokenIssuer(ctx)}, retired...), nil
}

// getMacaroonPrefixes returns all allowed macaroon prefixes (current + retired).
func (v *Verifier) getMacaroonPrefixes(ctx context.Context) []string {
	return append(
		[]string{
			cmp.Or(v.provider.String(ctx, talosconfig.KeyCredentialsDerivedTokensMacaroonPrefixCurrent), "mc"), // Set the defaults in the JSON schema instead and remove them from here.
		},
		v.provider.Strings(ctx, talosconfig.KeyCredentialsDerivedTokensMacaroonPrefixRetired)...,
	)
}

// clockSkew returns the configured clock skew tolerance, falling back to DefaultClockSkew.
func (v *Verifier) clockSkew(ctx context.Context) time.Duration {
	return cmp.Or(v.provider.Duration(ctx, talosconfig.KeyCredentialsClockSkew), crypto.DefaultClockSkew)
}

// getCacheTTL calculates the cache TTL as min(config_ttl, time_until_key_expires).
// Returns the TTL and whether the key should be cached at all.
// Delegates to cachecontrol.ComputeCacheTTL to keep the logic in one place.
func (v *Verifier) getCacheTTL(ctx context.Context, expiresAt *time.Time) (time.Duration, bool) {
	configTTL := v.provider.Duration(ctx, talosconfig.KeyCacheTTL)
	return cachecontrol.ComputeCacheTTL(configTTL, expiresAt)
}

// ListActiveSigningKeys returns the JWK set of all active signing keys
// configured for the service. The set is sourced from the underlying
// KeyService and is suitable for publishing via a JWKS endpoint after
// stripping any private key material at the caller.
func (v *Verifier) ListActiveSigningKeys(ctx context.Context) (jwk.Set, error) {
	return v.keyService.ListActiveSigningKeys(ctx)
}

// NewFromProvider creates a new verifier instance directly from a config provider.
// CRITICAL: All dependencies must be non-nil (will panic on use if nil).
// The tracker lifecycle is owned by the caller (typically ServiceFactory).
func NewFromProvider(driver persistence.Persister, provider ConfigProvider, c cache.Cache[db.IssuedApiKey], emitter events.Emitter, keyService *crypto.KeyService, m *metrics.Metrics, tracker *lastused.Tracker) *Verifier {
	return &Verifier{
		driver:     driver,
		provider:   provider,
		cache:      c,
		keyService: keyService,
		emitter:    emitter,
		verifier:   verifier.NewVerifier(keyService),
		metrics:    m,
		tracker:    tracker,
	}
}

// validateIPRestriction checks whether the requesting client IP falls within
// the key's allowed CIDR ranges. Returns nil if no restriction is configured
// (empty or "[]") or if the IP is allowed.
func (v *Verifier) validateIPRestriction(ctx context.Context, key *db.IssuedApiKey) error {
	if !clientip.HasRestriction(key.AllowedCidrs) {
		return nil
	}
	ip := clientip.ResolveClientIP(ctx, clientIPSourceFromString(
		v.provider.String(ctx, talosconfig.KeyServeHTTPClientIPSource),
	))
	if ip == nil {
		return errors.WithStack(errdef.ErrIPNotAllowed().WithReason("unable to determine client IP"))
	}
	cidrs := clientip.UnmarshalCIDRs(key.AllowedCidrs)
	allowed, err := clientip.CheckIP(ip, cidrs)
	if err != nil {
		return errdef.InternalError("invalid CIDR configuration").WithWrap(err)
	}
	if !allowed {
		return errors.WithStack(errdef.ErrIPNotAllowed())
	}
	return nil
}

// cacheLookupKey authenticates the raw credential and returns the cache key
// (its key_id) to look up. ok is false when the credential must not be served
// from cache: derived tokens (verified statelessly, never cached) or a failed
// secret proof. Authenticating here — checksum-verifying an issued key, hashing
// an imported key — means a cache hit already proves possession of the secret,
// so the hit site needs no second check. The cache is keyed by key_id, which is
// public for issued keys; for imported keys the key_id is a tenant-scoped hash
// of the whole secret, so computing it proves possession.
func (v *Verifier) cacheLookupKey(ctx context.Context, route crypto.CredentialRoute, credential string) (lookupID string, ok bool) {
	switch route.Type {
	case crypto.CredentialTypeIssued:
		hmacSecrets, err := v.getHMACSecrets(ctx)
		if err != nil {
			return "", false
		}
		components, err := crypto.VerifyAPIKeyChecksum(credential, hmacSecrets)
		if err != nil {
			return "", false
		}
		return components.KeyID, true // Checksum-verified key_id, matching cache.Set(dbKey.KeyID).
	case crypto.CredentialTypeImported:
		return crypto.HashImportedAPIKey(credential, contextx.NetworkIDFromContext(ctx).String()), true
	case crypto.CredentialTypeDerivedJWT, crypto.CredentialTypeDerivedMacaroon:
		// Derived tokens are verified statelessly and are never cached by key_id.
		return "", false
	default:
		return "", false
	}
}

// VerifyAPIKey verifies any credential type (API key v1, imported key, JWT, or macaroon).
// Returns the verified key and the cache outcome. The caller is responsible for
// propagating the CacheStatus to any response layer (e.g. HTTP headers).
func (v *Verifier) VerifyAPIKey(ctx context.Context, credential string) (_ *db.IssuedApiKey, _ cachecontrol.CacheStatus, err error) {
	ctx, span := tracing.Start(ctx, "verifier.VerifyAPIKey")
	defer otelx.End(span, &err)

	startTime := time.Now()
	if credential == "" {
		err = errdef.ErrCredentialRequired()
		v.metrics.RecordVerification("unknown", false, false, time.Since(startTime).Seconds())
		v.emitVerificationFailureEvent(ctx, "unknown", err)
		return nil, "", err
	}

	// Route credential to appropriate verifier
	route := crypto.RouteCredential(credential, v.getMacaroonPrefixes(ctx))
	span.SetAttributes(attribute.String("credential_type", string(route.Type)))

	// Derived tokens (JWT, Macaroon) are verified statelessly — signature check
	// and claims validation only, no database lookup. Caching their results would
	// provide no performance benefit and creates a correctness issue: JWK signing
	// key rotation with revoke would not invalidate cached results, causing
	// revoked tokens to appear valid until the cache entry expires.
	isDerived := route.Type == crypto.CredentialTypeDerivedJWT || route.Type == crypto.CredentialTypeDerivedMacaroon

	// cache.enabled is read per request so the flag is hot-reloadable and
	// tenant-configurable. Disabled caching reports SKIP and never reads or
	// writes the cache, so revocations take effect immediately.
	cacheEnabled := v.provider.Bool(ctx, talosconfig.KeyCacheEnabled)

	dbCacheStatus := cachecontrol.CacheMiss
	switch {
	case isDerived:
		dbCacheStatus = cachecontrol.CacheSkip
		span.SetAttributes(attribute.String("cache_bypass", "derived-token"))
	case !cacheEnabled:
		dbCacheStatus = cachecontrol.CacheSkip
		span.SetAttributes(attribute.String("cache_bypass", "disabled"))
	case cachecontrol.ShouldBypassCache(ctx):
		dbCacheStatus = cachecontrol.CacheSkip
		span.SetAttributes(attribute.String("cache_bypass", "no-cache"))
	default:
		// Only now is the cache actually consulted, so authenticate the raw
		// credential to derive its lookup key (the key_id, not the raw secret)
		// — this work is skipped on every bypass path above. cacheable is false
		// for credential types that are not cached or whose secret proof failed.
		lookupID, cacheable := v.cacheLookupKey(ctx, route, credential)
		if !cacheable {
			dbCacheStatus = cachecontrol.CacheSkip
			span.SetAttributes(attribute.String("cache_bypass", "no-cache"))
			break
		}
		// cacheLookupKey already proved possession of the secret (checksum for
		// issued keys, whole-key hash for imported keys), so a hit can be served
		// without a second check.
		cachedKey, found, cacheErr := v.cache.Get(ctx, lookupID)
		switch {
		case cacheErr != nil:
			span.SetAttributes(attribute.Bool("cache_read_error", true))
			v.metrics.CacheErrors.WithLabelValues("read").Inc()
			slog.WarnContext(ctx, "cache read failed, falling through to DB",
				slog.Any("error", cacheErr))
		case found && validateKeyStatusAndExpiration(cachedKey.Status, cachedKey.ExpiresAt) == nil:
			// Enforce IP restrictions on cached keys
			if ipErr := v.validateIPRestriction(ctx, &cachedKey); ipErr != nil {
				span.SetAttributes(attribute.Bool("cache_hit", true), attribute.Bool("ip_rejected", true))
				v.metrics.RecordVerification(string(route.Type), false, true, time.Since(startTime).Seconds())
				v.emitVerificationFailureEvent(ctx, string(route.Type), ipErr)
				return nil, cachecontrol.CacheHit, ipErr
			}
			span.SetAttributes(attribute.Bool("cache_hit", true))
			v.metrics.RecordVerification(string(route.Type), true, true, time.Since(startTime).Seconds())
			return &cachedKey, cachecontrol.CacheHit, nil
		}
	}
	span.SetAttributes(attribute.Bool("cache_hit", false))

	var dbKey *db.IssuedApiKey

	switch route.Type {
	case crypto.CredentialTypeIssued:
		dbKey, err = v.verifyAPIKey(ctx, credential)

	case crypto.CredentialTypeImported:
		dbKey, err = v.verifyImportedAPIKey(ctx, credential)

	case crypto.CredentialTypeDerivedJWT:
		dbKey, err = v.verifyDerivedJWT(ctx, credential)

	case crypto.CredentialTypeDerivedMacaroon:
		dbKey, err = v.verifyDerivedMacaroon(ctx, credential)

	default:
		err = errdef.ErrUnknownCredential()
	}

	// Enforce IP restrictions after successful DB authentication. Fold the
	// rejection into err before recording metrics so an IP-rejected key counts
	// as a failed verification, not a success.
	if err == nil && dbKey != nil {
		if ipErr := v.validateIPRestriction(ctx, dbKey); ipErr != nil {
			span.SetAttributes(attribute.Bool("ip_rejected", true))
			err = ipErr
		}
	}

	v.metrics.RecordVerification(string(route.Type), err == nil, false, time.Since(startTime).Seconds())

	if err != nil {
		v.emitVerificationFailureEvent(ctx, string(route.Type), err)
		return nil, dbCacheStatus, err
	}
	if dbKey == nil {
		return nil, dbCacheStatus, errors.WithStack(errdef.InternalError("verification succeeded but dbKey is nil"))
	}

	if !isDerived && cacheEnabled {
		cacheTTL, cacheable := v.getCacheTTL(ctx, dbKey.ExpiresAt)
		cc := cachecontrol.FromContext(ctx)
		if cacheable && !cc.NoStore {
			if cacheErr := v.cache.Set(ctx, dbKey.KeyID, *dbKey, cacheTTL); cacheErr != nil {
				span.SetAttributes(attribute.Bool("cache_write_error", true))
				v.metrics.CacheErrors.WithLabelValues("write").Inc()
				slog.WarnContext(ctx, "write verification result to cache",
					slog.String("key_id", dbKey.KeyID),
					slog.Any("error", cacheErr))
			}
		}
	}

	return dbKey, dbCacheStatus, nil
}

// verifyAPIKey verifies a generated API key using allowlist approach.
// Returns the db.IssuedApiKey and any error.
func (v *Verifier) verifyAPIKey(ctx context.Context, fullKey string) (_ *db.IssuedApiKey, err error) {
	ctx, span := tracing.Start(ctx, "verifier.verifyAPIKey")
	defer otelx.End(span, &err)

	// Authenticate and validate the key
	dbKey, err := v.authenticateIssuedKey(ctx, fullKey)
	if err != nil {
		return nil, err
	}

	// Update last_used (async, don't block)
	// Only update if last_used_at is nil or from a previous day to avoid excessive writes
	if persistence.ShouldUpdateLastUsed(dbKey.LastUsedAt, time.Now().UTC()) {
		v.tracker.Publish(dbKey.KeyID, contextx.NetworkIDFromContext(ctx), false)
	}

	return dbKey, nil
}

// verifyImportedAPIKey verifies an imported API key using hash lookup.
// Returns the db.IssuedApiKey and any error.
func (v *Verifier) verifyImportedAPIKey(ctx context.Context, credential string) (_ *db.IssuedApiKey, err error) {
	ctx, span := tracing.Start(ctx, "verifier.verifyImportedAPIKey")
	defer otelx.End(span, &err)

	// Authenticate and validate the key
	importedKey, err := v.authenticateImportedKey(ctx, credential)
	if err != nil {
		return nil, err
	}

	// Update last_used (async, don't block) — same debounce as issued keys
	if persistence.ShouldUpdateLastUsed(importedKey.LastUsedAt, time.Now().UTC()) {
		v.tracker.Publish(importedKey.KeyID, contextx.NetworkIDFromContext(ctx), true)
	}

	// Convert imported key to db.IssuedApiKey
	apiKey := persistencetypes.ImportedAPIKeyToIssuedAPIKey(ctx, *importedKey)

	return &apiKey, nil
}

// claimsToAPIKey builds a synthetic db.IssuedApiKey from token claims for stateless verification.
func claimsToAPIKey(ctx context.Context, claims *token.Claims) db.IssuedApiKey {
	metadata := json.RawMessage(`{}`)
	metaMap := claims.GetMetadata()
	customClaims := claims.GetCustomClaims()
	// Custom claims are copied first so internal metadata takes precedence
	// on key collision — metadata is authoritative.
	merged := make(map[string]any, len(metaMap)+len(customClaims))
	maps.Copy(merged, customClaims)
	maps.Copy(merged, metaMap)
	if len(merged) > 0 {
		b, err := json.Marshal(merged)
		if err != nil {
			slog.WarnContext(ctx, "marshal token claim metadata", slog.Any("error", err))
		} else {
			metadata = b
		}
	}
	scopes := json.RawMessage(`[]`)
	if s := claims.GetScopes(); len(s) > 0 {
		b, err := json.Marshal(s)
		if err != nil {
			slog.WarnContext(ctx, "marshal token claim scopes", slog.Any("error", err))
		} else {
			scopes = b
		}
	}

	// Use the boolean to distinguish "no expiration" (nil) from an actual timestamp.
	// Without this, a zero time.Time{} (year 1) would make the key appear expired
	// and prevent caching entirely.
	var expiresAt *time.Time
	if exp, ok := claims.Expiration(); ok {
		expiresAt = &exp
	}

	var visibility int32
	if claims.GetVisibility() == "public" {
		visibility = int32(talosv2alpha1.KeyVisibility_KEY_VISIBILITY_PUBLIC)
	} else {
		visibility = int32(talosv2alpha1.KeyVisibility_KEY_VISIBILITY_SECRET)
	}

	// Propagate IP restrictions from token claims so session tokens
	// inherit the parent key's CIDR allowlist.
	allowedCidrs := json.RawMessage("[]")
	if cidrs := claims.GetAllowedCidrs(); len(cidrs) > 0 {
		if b, err := json.Marshal(cidrs); err != nil {
			slog.WarnContext(ctx, "marshal token claim allowed_cidrs", slog.Any("error", err))
		} else {
			allowedCidrs = b
		}
	}

	return db.IssuedApiKey{
		NID:          contextx.NetworkIDFromContext(ctx),
		KeyID:        claims.GetKeyID(),
		ActorID:      sqlutil.PtrOrNil(claims.GetActorID()),
		Scopes:       scopes,
		Status:       int32(talosv2alpha1.KeyStatus_KEY_STATUS_ACTIVE),
		Metadata:     metadata,
		AllowedCidrs: allowedCidrs,
		ExpiresAt:    expiresAt,
		Visibility:   visibility,
	}
}

// validateDerivedTokenClaims validates token type and network ID for derived tokens.
// It checks that the token type is a derived token (or unset for newer tokens)
// and that the NID claim matches the context NID (defense-in-depth).
func validateDerivedTokenClaims(ctx context.Context, claims *token.Claims, span trace.Span) error {
	// Validate token type (if present; omitted in newer tokens)
	if tt := claims.GetTokenType(); tt != "" && tt != token.TokenTypeDerived {
		return errors.WithStack(errdef.ErrInvalidTokenType())
	}

	// Validate NID matches context (defense-in-depth)
	ctxNID := contextx.NetworkIDFromContext(ctx).String()
	claimNID := claims.GetNetworkID()
	if claimNID != ctxNID {
		span.SetAttributes(
			attribute.String("nid_expected", ctxNID),
			attribute.String("nid_claim", claimNID),
			attribute.Bool("nid_mismatch", true),
		)
		return errors.WithStack(errdef.ErrAPIKeyNotFound().WithReason("token not valid for this network"))
	}

	return nil
}

// verifyDerivedJWT verifies a JWT derived token
//
// Derived tokens are stateless capability tokens. All constraints (scopes, TTL, subject)
// are enforced at derivation time. Once issued, tokens remain valid until expiration
// regardless of parent key status changes. This enables stateless verification with
// minimal latency.
func (v *Verifier) verifyDerivedJWT(ctx context.Context, tokenString string) (_ *db.IssuedApiKey, err error) {
	ctx, span := tracing.Start(ctx, "verifier.verifyDerivedJWT")
	defer otelx.End(span, &err)

	// Issuer: validated by VerifyJWT → VerifyJWTWithKeySetAndIssuer → matchIssuer
	// (token/issuer.go). Returns an error if the iss claim is missing or doesn't match
	// any of the allowed issuers from getTokenIssuers (current + retired).
	//
	// Expiry: validated by jwt.Parse with jwt.WithValidate(true) inside verifyJWTWithKeySet
	// (token/jwt.go). The lestrrat-go/jwx library checks exp and nbf, applying the
	// configured clock skew as acceptable leeway so minor clock drift between nodes
	// does not cause spurious "not yet valid" rejections.

	issuers, err := v.getTokenIssuers(ctx)
	if err != nil {
		return nil, errdef.ErrServiceUnavailable().WithReasonf("get token issuers").WithWrap(errors.WithStack(err))
	}

	// Verify the token signature and claims using shared verifier
	claims, err := v.verifier.VerifyJWT(ctx, tokenString, issuers, v.clockSkew(ctx))
	if err != nil {
		return nil, errdef.ErrSignatureInvalid().WithWrap(err)
	}

	if err := validateDerivedTokenClaims(ctx, claims, span); err != nil {
		return nil, err
	}

	apiKey := claimsToAPIKey(ctx, claims)
	return &apiKey, nil
}

// verifyDerivedMacaroon verifies a macaroon derived token
//
// Derived tokens are stateless capability tokens. All constraints (scopes, TTL, subject)
// are enforced at derivation time. Once issued, tokens remain valid until expiration
// regardless of parent key status changes. This enables stateless verification with
// minimal latency.
func (v *Verifier) verifyDerivedMacaroon(ctx context.Context, tokenString string) (_ *db.IssuedApiKey, err error) {
	ctx, span := tracing.Start(ctx, "verifier.verifyDerivedMacaroon")
	defer otelx.End(span, &err)

	// Issuer: checked twice as defense-in-depth.
	// 1. verifyCaveat (token/macaroon.go) checks iss inside each caveat during m.Verify.
	// 2. matchIssuer (token/issuer.go) re-checks iss on the parsed Claims after
	//    signature verification in VerifyMacaroonWithKeySetAndIssuer.
	// Both accept the full list of allowed issuers (current + retired).
	//
	// Expiry: verifyCaveat checks exp and nbf inside each caveat during m.Verify.
	// This is the only expiry check — macaroons don't go through jwt.Parse.

	hmacSecrets, err := v.getHMACSecrets(ctx)
	if err != nil {
		return nil, errdef.ErrServiceUnavailable().WithReasonf("get HMAC secrets").WithWrap(errors.WithStack(err))
	}

	issuers, err := v.getTokenIssuers(ctx)
	if err != nil {
		return nil, errdef.ErrServiceUnavailable().WithReasonf("get token issuers").WithWrap(errors.WithStack(err))
	}

	// Verify the token signature and claims using shared verifier
	claims, err := v.verifier.VerifyMacaroon(ctx, tokenString, hmacSecrets, issuers, v.getMacaroonPrefixes(ctx), v.clockSkew(ctx))
	if err != nil {
		return nil, errdef.ErrSignatureInvalid().WithWrap(err)
	}
	if claims == nil {
		return nil, errdef.ErrSignatureInvalid().WithReason("macaroon verification returned nil claims")
	}

	if err := validateDerivedTokenClaims(ctx, claims, span); err != nil {
		return nil, err
	}

	apiKey := claimsToAPIKey(ctx, claims)
	return &apiKey, nil
}

// emitVerificationFailureEvent emits an audit event for a failed verification.
// Events are rate-limited to failureEventRateLimit per NID per failureEventWindow
// to prevent adversarial load from overwhelming the event pipeline.
func (v *Verifier) emitVerificationFailureEvent(ctx context.Context, credentialType string, verifyErr error) {
	if !v.emitter.Enabled() {
		return
	}

	nid := contextx.NetworkIDFromContext(ctx).String()
	if !v.failureEventLimiter.allow(nid) {
		slog.DebugContext(ctx, "verification failure event throttled",
			slog.String("nid", nid),
			slog.String("credential_type", credentialType))
		return
	}

	// Use the most specific reason for audit events.
	reason := verifyErr.Error()
	if herodotErr, ok := stderrors.AsType[*herodot.DefaultError](verifyErr); ok && herodotErr.ReasonField != "" {
		reason = herodotErr.ReasonField
	}

	builder := eventcontext.NewFromContext(ctx, events.EventAPIKeyVerificationFailed).
		WithMetadata("credential_type", credentialType).
		WithReason(reason)

	builder.Emit(ctx, v.emitter)
}

// SelfRevokeAPIKey allows a key holder to revoke their own key by providing the full secret.
// Supports both issued API keys and imported keys. JWT/macaroon tokens cannot be revoked.
// Returns nil on success, or an error for invalid credentials or internal failures.
func (v *Verifier) SelfRevokeAPIKey(ctx context.Context, credential string, reason int32) (err error) {
	ctx, span := tracing.Start(ctx, "verifier.SelfRevokeAPIKey")
	defer otelx.End(span, &err)

	if credential == "" {
		return errdef.ErrCredentialRequired()
	}

	route := crypto.RouteCredential(credential, v.getMacaroonPrefixes(ctx))
	span.SetAttributes(attribute.String("credential_type", string(route.Type)))

	switch route.Type {
	case crypto.CredentialTypeIssued:
		return v.selfRevokeIssuedKey(ctx, credential, reason)
	case crypto.CredentialTypeImported:
		return v.selfRevokeImportedKey(ctx, credential, reason)
	case crypto.CredentialTypeDerivedJWT, crypto.CredentialTypeDerivedMacaroon:
		return errdef.ErrDerivedTokenNotRevocable()
	default:
		return errdef.ErrUnknownCredential()
	}
}

// completeSelfRevocation performs post-revocation housekeeping: cache invalidation,
// metrics recording, and audit event emission. keyID is the key identifier,
// eventType is the revocation event to emit (issued vs. imported), and eventPrefix
// is "" for native keys or "imported" for imported keys.
func (v *Verifier) completeSelfRevocation(ctx context.Context, span trace.Span, keyID string, eventType events.EventType, eventPrefix string, reason int32) {
	// Invalidate the cached verification result by key_id; the cache is keyed
	// by key_id, so the raw credential is not needed.
	if cacheErr := v.cache.Delete(ctx, keyID); cacheErr != nil {
		span.SetAttributes(attribute.Bool("cache_delete_error", true))
		slog.WarnContext(ctx, "invalidate cache entry",
			slog.String("key_id", keyID),
			slog.Any("error", cacheErr))
	}

	// Record metrics
	metricReason := talosv2alpha1.RevocationReason(reason).String()
	v.metrics.APIKeysRevoked.WithLabelValues(metricReason).Inc()

	// Emit audit event
	builder := eventcontext.NewFromContext(ctx, eventType).
		WithKeyID(keyID).
		WithMetadata("initiated_by", "self")
	if eventPrefix != "" {
		builder.WithPrefix(eventPrefix)
	}
	if reason != 0 {
		builder.WithReason(metricReason)
	}
	builder.Emit(ctx, v.emitter)
}

// selfRevokeIssuedKey handles self-revocation for issued API keys.
func (v *Verifier) selfRevokeIssuedKey(ctx context.Context, fullKey string, reason int32) (err error) {
	ctx, span := tracing.Start(
		ctx, "verifier.selfRevokeIssuedKey",
		attribute.Int("revocation_reason", int(reason)),
	)
	defer otelx.End(span, &err)

	// Authenticate and validate the key
	apiKey, err := v.authenticateIssuedKey(ctx, fullKey)
	if err != nil {
		if errors.Is(err, errdef.ErrAPIKeyRevoked()) {
			// Idempotent: already revoked is success
			return nil
		}
		return err
	}

	// Use the DB-confirmed key_id for the revocation and cache invalidation.
	keyID := apiKey.KeyID
	span.SetAttributes(attribute.String("key_id", keyID))

	// Calculate new expiration: max(now + 30 days, original_expires_at)
	now := sqlutil.UTCNow()
	newExpiresAt := sqlutil.CalculateRevocationExpiry(now, apiKey.ExpiresAt)

	// Revoke the key
	if err = v.driver.RevokeIssuedAPIKey(ctx, persistencetypes.RevokeIssuedAPIKeyParams{
		KeyID:     keyID,
		Reason:    reason,
		ExpiresAt: newExpiresAt,
	}); err != nil {
		return errdef.InternalError("revoke key").WithWrap(errors.WithStack(err))
	}

	v.completeSelfRevocation(ctx, span, keyID, events.EventIssuedAPIKeyRevoked, "", reason)
	return nil
}

// selfRevokeImportedKey handles self-revocation for imported API keys.
// credential is the raw imported key; the tenant-scoped hash is computed here
// (matching the import and verify paths).
func (v *Verifier) selfRevokeImportedKey(ctx context.Context, credential string, reason int32) (err error) {
	ctx, span := tracing.Start(
		ctx, "verifier.selfRevokeImportedKey",
		attribute.Int("revocation_reason", int(reason)),
	)
	defer otelx.End(span, &err)

	// Authenticate and validate the key
	importedKey, err := v.authenticateImportedKey(ctx, credential)
	if err != nil {
		if errors.Is(err, errdef.ErrAPIKeyRevoked()) {
			// Idempotent: already revoked is success
			return nil
		}
		return err
	}

	// Calculate new expiration: max(now + 30 days, original_expires_at)
	now := sqlutil.UTCNow()
	newExpiresAt := sqlutil.CalculateRevocationExpiry(now, importedKey.ExpiresAt)

	// Revoke the key
	if _, err := v.driver.RevokeImportedAPIKey(ctx, persistencetypes.RevokeImportedKeyParams{
		KeyID:     importedKey.KeyID,
		Reason:    reason,
		ExpiresAt: newExpiresAt,
	}); err != nil {
		return errdef.InternalError("revoke imported key").WithWrap(errors.WithStack(err))
	}

	v.completeSelfRevocation(ctx, span, importedKey.KeyID, events.EventImportedAPIKeyRevoked, "imported", reason)
	return nil
}

// BatchVerifyResult holds the outcome of verifying one credential in a batch.
type BatchVerifyResult struct {
	// Key is the verified key; non-nil only on success.
	Key *db.IssuedApiKey
	// Err is the verification error; non-nil only on failure.
	Err error
}

// BatchVerifyAPIKeys verifies multiple API key credentials with a single DB round-trip
// for issued keys. Issued-key credentials are pre-validated (parse, timestamp, prefix,
// checksum) in CPU-only passes, then all valid key IDs are fetched in one
// WHERE key_id IN (...) query. Non-issued credentials (imported, derived JWT/macaroon)
// fall through to individual VerifyAPIKey.
//
// TODO: integrate with cache.GetMulti for cache-aware batch verification.
func (v *Verifier) BatchVerifyAPIKeys(ctx context.Context, credentials []string) (_ []BatchVerifyResult, err error) {
	ctx, span := tracing.Start(
		ctx, "verifier.BatchVerifyAPIKeys",
		attribute.Int("batch_size", len(credentials)),
	)
	defer otelx.End(span, &err)

	results := make([]BatchVerifyResult, len(credentials))

	// Pass 1: route and pre-validate issued/imported credentials (CPU-only, no DB).
	type issuedEntry struct {
		idx   int
		keyID string
	}
	type importedEntry struct {
		idx  int
		hash string
	}

	hmacSecrets, err := v.getHMACSecrets(ctx)
	if err != nil {
		return nil, errdef.InternalError("get HMAC secrets").WithWrap(errors.WithStack(err))
	}
	macaroonPrefixes := v.getMacaroonPrefixes(ctx)
	maxAge := v.provider.Duration(ctx, talosconfig.KeyCredentialsAPIKeysMaxTTL)
	clockSkew := v.clockSkew(ctx)
	cacheEnabled := v.provider.Bool(ctx, talosconfig.KeyCacheEnabled)
	nid := contextx.NetworkIDFromContext(ctx)
	nidStr := nid.String()

	routes := make([]crypto.CredentialRoute, len(credentials))
	var issuedEntries []issuedEntry
	var importedEntries []importedEntry

	for i, cred := range credentials {
		route := crypto.RouteCredential(cred, macaroonPrefixes)
		routes[i] = route

		switch route.Type {
		case crypto.CredentialTypeDerivedJWT, crypto.CredentialTypeDerivedMacaroon:
			continue
		case crypto.CredentialTypeImported:
			hash := crypto.HashImportedAPIKey(cred, nidStr)
			importedEntries = append(importedEntries, importedEntry{idx: i, hash: hash})

		case crypto.CredentialTypeIssued:
			components, checksumErr := crypto.VerifyAPIKeyChecksum(cred, hmacSecrets)
			if checksumErr != nil {
				// Return NOT_FOUND (not INVALID_FORMAT) to match single-key behavior
				// and prevent callers from distinguishing a cross-project key from
				// a non-existent one.
				results[i] = BatchVerifyResult{Err: errors.WithStack(errdef.ErrAPIKeyNotFound().WithReason("invalid API key checksum").WithWrap(checksumErr))}
				continue
			}

			if tsErr := crypto.ValidateKeyTimestamp(components.Timestamp, maxAge, clockSkew); tsErr != nil {
				results[i] = BatchVerifyResult{Err: errors.WithStack(errdef.ErrAPIKeyNotFound().WithReason("timestamp out of range").WithWrap(tsErr))}
				continue
			}

			if !v.isAllowedPrefix(ctx, components.TokenPrefix) {
				results[i] = BatchVerifyResult{Err: errors.WithStack(errdef.ErrAPIKeyNotFound().WithReason("prefix not allowed"))}
				continue
			}

			issuedEntries = append(issuedEntries, issuedEntry{idx: i, keyID: components.KeyID})
		}
	}

	// Pass 2a: single batch DB fetch for all valid issued keys.
	if len(issuedEntries) > 0 {
		keyIDs := make([]string, len(issuedEntries))
		for j, e := range issuedEntries {
			keyIDs[j] = e.keyID
		}

		dbKeys, dbErr := v.driver.GetIssuedAPIKeysBatch(ctx, keyIDs)
		if dbErr != nil {
			return nil, errdef.InternalError("batch fetch issued keys").WithWrap(errors.WithStack(dbErr))
		}

		keyMap := make(map[string]db.IssuedApiKey, len(dbKeys))
		for _, k := range dbKeys {
			keyMap[k.KeyID] = k
		}

		for _, e := range issuedEntries {
			dbKey, found := keyMap[e.keyID]
			if !found {
				results[e.idx] = BatchVerifyResult{Err: errors.WithStack(errdef.ErrAPIKeyNotFound())}
				v.emitVerificationFailureEvent(ctx, string(crypto.CredentialTypeIssued), errdef.ErrAPIKeyNotFound())
				continue
			}

			if statusErr := validateKeyStatusAndExpiration(dbKey.Status, dbKey.ExpiresAt); statusErr != nil {
				results[e.idx] = BatchVerifyResult{Err: statusErr}
				v.emitVerificationFailureEvent(ctx, string(crypto.CredentialTypeIssued), statusErr)
				continue
			}

			if ipErr := v.validateIPRestriction(ctx, &dbKey); ipErr != nil {
				results[e.idx] = BatchVerifyResult{Err: ipErr}
				v.emitVerificationFailureEvent(ctx, string(crypto.CredentialTypeIssued), ipErr)
				continue
			}

			cacheTTL, cacheable := v.getCacheTTL(ctx, dbKey.ExpiresAt)
			cc := cachecontrol.FromContext(ctx)
			if cacheEnabled && cacheable && !cc.NoStore {
				if cacheErr := v.cache.Set(ctx, dbKey.KeyID, dbKey, cacheTTL); cacheErr != nil {
					slog.WarnContext(ctx, "write batch verification result to cache",
						slog.String("key_id", dbKey.KeyID),
						slog.Any("error", cacheErr))
				}
			}

			if persistence.ShouldUpdateLastUsed(dbKey.LastUsedAt, time.Now().UTC()) {
				v.tracker.Publish(dbKey.KeyID, nid, false)
			}

			keyCopy := dbKey
			results[e.idx] = BatchVerifyResult{Key: &keyCopy}
		}
	}

	// Pass 2b: single batch DB fetch for all imported keys.
	if len(importedEntries) > 0 {
		hashes := make([]string, len(importedEntries))
		for j, e := range importedEntries {
			hashes[j] = e.hash
		}

		importedKeys, dbErr := v.driver.GetImportedAPIKeysBatch(ctx, hashes)
		if dbErr != nil {
			return nil, errdef.InternalError("batch fetch imported keys").WithWrap(errors.WithStack(dbErr))
		}

		keyMap := make(map[string]db.ImportedApiKey, len(importedKeys))
		for _, k := range importedKeys {
			keyMap[k.KeyID] = k
		}

		for _, e := range importedEntries {
			importedKey, found := keyMap[e.hash]
			if !found {
				results[e.idx] = BatchVerifyResult{Err: errors.WithStack(errdef.ErrAPIKeyNotFound())}
				v.emitVerificationFailureEvent(ctx, string(crypto.CredentialTypeImported), errdef.ErrAPIKeyNotFound())
				continue
			}

			if statusErr := validateKeyStatusAndExpiration(importedKey.Status, importedKey.ExpiresAt); statusErr != nil {
				results[e.idx] = BatchVerifyResult{Err: statusErr}
				v.emitVerificationFailureEvent(ctx, string(crypto.CredentialTypeImported), statusErr)
				continue
			}

			apiKey := persistencetypes.ImportedAPIKeyToIssuedAPIKey(ctx, importedKey)

			if ipErr := v.validateIPRestriction(ctx, &apiKey); ipErr != nil {
				results[e.idx] = BatchVerifyResult{Err: ipErr}
				v.emitVerificationFailureEvent(ctx, string(crypto.CredentialTypeImported), ipErr)
				continue
			}

			cacheTTL, cacheable := v.getCacheTTL(ctx, apiKey.ExpiresAt)
			cc := cachecontrol.FromContext(ctx)
			if cacheEnabled && cacheable && !cc.NoStore {
				if cacheErr := v.cache.Set(ctx, apiKey.KeyID, apiKey, cacheTTL); cacheErr != nil {
					slog.WarnContext(ctx, "write batch verification result to cache",
						slog.String("key_id", apiKey.KeyID),
						slog.Any("error", cacheErr))
				}
			}

			keyCopy := apiKey
			results[e.idx] = BatchVerifyResult{Key: &keyCopy}
		}
	}

	// Pass 3: individual verify for remaining types (derived JWT/macaroon).
	for i, cred := range credentials {
		if results[i].Key != nil || results[i].Err != nil {
			continue // handled in pass 1, 2a, or 2b
		}
		dbKey, _, verifyErr := v.VerifyAPIKey(ctx, cred)
		if verifyErr != nil {
			results[i] = BatchVerifyResult{Err: verifyErr}
		} else {
			results[i] = BatchVerifyResult{Key: dbKey}
		}
	}

	return results, nil
}

// isAllowedPrefix checks if the given prefix is allowed by configuration.
// Returns true if prefix matches current, public, or any retired prefix.
func (v *Verifier) isAllowedPrefix(ctx context.Context, prefix string) bool {
	// Check current prefix
	current := v.provider.String(ctx, talosconfig.KeyCredentialsAPIKeysPrefixCurrent)
	if prefix == current {
		return true
	}

	// Check public current prefix
	publicCurrent := v.provider.String(ctx, talosconfig.KeyCredentialsAPIKeysPrefixPublicCurrent)
	if publicCurrent != "" && prefix == publicCurrent {
		return true
	}

	// Check retired prefixes (standard and public)
	retired := v.provider.Strings(ctx, talosconfig.KeyCredentialsAPIKeysPrefixRetired)
	if slices.Contains(retired, prefix) {
		return true
	}
	publicRetired := v.provider.Strings(ctx, talosconfig.KeyCredentialsAPIKeysPrefixPublicRetired)
	return slices.Contains(publicRetired, prefix)
}

// ResetFailureEventLimiter clears all per-NID rate limit buckets for the
// failure event limiter. Intended for use in tests only, so that subtests
// that emit failure events are not affected by the rate limits of earlier tests.
func (v *Verifier) ResetFailureEventLimiter() {
	v.failureEventLimiter.reset()
}

// reviewed - @aeneasr - 2026-03-27
