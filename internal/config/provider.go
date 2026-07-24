// Package config provides a context-aware configuration provider built on top of
// github.com/ory/x/configx. It enables hot reloading of configuration values.
//
// Configuration sources are loaded in the following priority order (lowest to highest):
//  1. Default values (defined in this package)
//  2. Configuration files (YAML)
//  3. Environment variables (DB_DSN, SERVE_HTTP_PORT, etc.)
//
// Environment variables are unprefixed; their underscores are converted to dot
// notation and matched against config schema paths:
//
//	DB_DSN → db.dsn
//	SERVE_HTTP_PORT → serve.http.port
package config

import (
	"context"
	"log/slog"
	"sync/atomic"
	"time"

	"github.com/cockroachdb/errors"

	"github.com/ory/talos/internal/configschema"
	"github.com/ory/talos/internal/logger"

	"github.com/ory/x/configx"
	"github.com/ory/x/watcherx"
)

// ProviderInterface defines the interface for configuration providers.
// Both OSS and commercial implementations must implement this interface.
type ProviderInterface interface {
	String(ctx context.Context, key Key) string
	Strings(ctx context.Context, key Key) []string
	Bool(ctx context.Context, key Key) bool
	Int(ctx context.Context, key Key) int
	Float64(ctx context.Context, key Key) float64
	Duration(ctx context.Context, key Key) time.Duration
	Get(ctx context.Context, key Key) any
	Set(ctx context.Context, key Key, value any) error
	Unmarshal(ctx context.Context, key Key, value any) error
	ActiveRetiredValues(ctx context.Context, key Key) ([]string, error)
	UnderlyingProvider(ctx context.Context) *configx.Provider
}

// retiredUnmarshaler is the minimal capability FilterActiveRetiredValues needs.
// Both the OSS Provider and the commercial provider satisfy it.
type retiredUnmarshaler interface {
	Unmarshal(ctx context.Context, key Key, value any) error
}

// FilterActiveRetiredValues unmarshals the retired-value array at key and returns
// the values whose expiry is unset or still in the future, dropping any entry
// whose expires_at has already passed. It keeps the expiry filter in one place so
// the OSS and commercial providers behave identically.
//
// Each element may be either the current object form ({value, expires_at}) or
// the legacy bare-string form (shorthand for an entry that never expires). The
// array is decoded into []any because configx unmarshals through
// koanf/mapstructure, which cannot decode a bare string into a struct; the loose
// decode normalizes both shapes per element.
//
// A malformed individual entry is logged and skipped rather than failing the
// whole call: one bad retired value must not break verification for the valid
// current credential. Only a whole-key unmarshal failure returns an error.
func FilterActiveRetiredValues(ctx context.Context, p retiredUnmarshaler, key Key) ([]string, error) {
	var raw []any
	if err := p.Unmarshal(ctx, key, &raw); err != nil {
		return nil, errors.Wrapf(err, "unmarshal retired values for key %q", key.String())
	}

	now := time.Now().UTC()
	active := make([]string, 0, len(raw))
	for i, entry := range raw {
		value, expiresAt, err := parseRetiredValue(entry)
		if err != nil {
			// A single malformed entry must not take down verification for the
			// valid current credential and its well-formed siblings. Skipping a
			// malformed retired entry is fail-safe: the stale credential it would
			// have described is simply not honored. The whole-key unmarshal
			// failure above still fails closed.
			slog.Default().WarnContext(
				ctx, "skipping malformed retired value",
				slog.String("key", key.String()),
				slog.Int("index", i),
				slog.String("error", err.Error()),
			)
			continue
		}
		if value == "" {
			continue
		}
		if isActiveAt(now, expiresAt) {
			active = append(active, value)
		}
	}
	return active, nil
}

// isActiveAt reports whether a retired value with the given expiry is still
// active at now. A zero expiry never expires. The boundary is exclusive: an
// entry whose expires_at equals now is already expired.
func isActiveAt(now, expiresAt time.Time) bool {
	return expiresAt.IsZero() || now.Before(expiresAt)
}

// parseRetiredValue normalizes one retired-value entry from its loosely-typed
// config representation. It accepts a bare string (never expires) or an object
// carrying "value" and an optional RFC 3339 "expires_at".
func parseRetiredValue(entry any) (value string, expiresAt time.Time, err error) {
	switch e := entry.(type) {
	case string:
		return e, time.Time{}, nil
	case map[string]any:
		v, _ := e["value"].(string)
		expiresAt, err = parseExpiresAt(e["expires_at"])
		return v, expiresAt, err
	default:
		return "", time.Time{}, errors.Errorf("unexpected retired value type %T", entry)
	}
}

// parseExpiresAt reads an optional expires_at from a config value. A missing or
// empty value means the entry never expires.
func parseExpiresAt(v any) (time.Time, error) {
	switch t := v.(type) {
	case nil:
		return time.Time{}, nil
	case time.Time:
		return t.UTC(), nil
	case string:
		if t == "" {
			return time.Time{}, nil
		}
		parsed, err := time.Parse(time.RFC3339, t)
		if err != nil {
			return time.Time{}, errors.Wrapf(err, "parse expires_at %q", t)
		}
		return parsed.UTC(), nil
	default:
		return time.Time{}, errors.Errorf("unexpected expires_at type %T", v)
	}
}

// Provider wraps the ory/x/configx provider for configuration access with hot reloading.
// Network-specific configuration overrides are handled by the contextualizer at the
// middleware level, not within this provider.
//
// In OSS builds, this embeds configx.Provider directly, making all methods available.
// In commercial builds, a separate provider implementation extracts config from context.
type Provider struct {
	*configx.Provider
}

// NewProviderWithOptions creates a Provider with custom configx options.
// Used for creating network-specific config providers with overrides.
func NewProviderWithOptions(ctx context.Context, opts ...configx.OptionModifier) (*Provider, error) {
	p, err := configx.New(ctx, configschema.SchemaJSON, append(
		[]configx.OptionModifier{
			configx.WithContext(ctx),
			configx.WithImmutables(KeyDBDSN.String(), KeyCacheRedisPassword.String()),
			configx.WithStderrValidationReporter(),
		},
		opts...,
	)...)
	if err != nil {
		return nil, errors.Wrap(err, "create config provider")
	}

	return &Provider{
		Provider: p,
	}, nil
}

// NewProvider creates a new config provider with hot reload support.
//
// Configuration sources are loaded in priority order:
//  1. Schema defaults (defined in config.schema.json)
//  2. Configuration file (if provided)
//  3. Environment variables (unprefixed, e.g. DB_DSN — highest priority)
//
// The provider supports hot reloading when configuration files change.
//
// Note: Network-specific configuration overrides are handled by the contextualizer
// at the middleware level, not within this provider.
func NewProvider(ctx context.Context, configFile string) (*Provider, error) {
	// The watcher logger is published after the provider is built, because its
	// level and format come from the config we are about to load. Reload events
	// only fire on later file changes, long after construction returns, so the
	// pointer is always set by the time the callback runs. atomic.Pointer keeps
	// the publish race-free against configx's watcher goroutine.
	var watchLog atomic.Pointer[slog.Logger]

	opts := []configx.OptionModifier{
		configx.WithContext(ctx),
		configx.WithImmutables("db.dsn", "tls.key", "redis.password"),
		configx.WithStderrValidationReporter(),
		configx.AttachWatcher(func(e watcherx.Event, err error) {
			if l := watchLog.Load(); l != nil {
				logConfigChange(l, e, err)
			}
		}),
	}

	if len(configFile) > 0 {
		opts = append(opts, configx.WithConfigFiles(configFile))
	}

	p, err := configx.New(ctx, configschema.SchemaJSON, opts...)
	if err != nil {
		return nil, errors.Wrap(err, "create config provider")
	}

	// Build the watcher logger from the now-loaded config and publish it so the
	// callback above can use it on the next reload.
	watchLog.Store(logger.NewLogger(
		p.String(KeyLogLevel.String()),
		p.String(KeyLogFormat.String()),
	).Logger)

	return &Provider{
		Provider: p,
	}, nil
}

// String returns the string value for the given config key.
func (p *Provider) String(_ context.Context, key Key) string {
	return p.Provider.String(key.String())
}

// Strings returns the string slice value for the given config key.
func (p *Provider) Strings(_ context.Context, key Key) []string {
	return p.Provider.Strings(key.String())
}

// Bool returns the boolean value for the given config key.
func (p *Provider) Bool(_ context.Context, key Key) bool {
	return p.Provider.Bool(key.String())
}

// Int returns the integer value for the given config key.
func (p *Provider) Int(_ context.Context, key Key) int {
	return p.Provider.Int(key.String())
}

// Float64 returns the float64 value for the given config key.
func (p *Provider) Float64(_ context.Context, key Key) float64 {
	return p.Provider.Float64(key.String())
}

// Duration returns the duration value for the given config key.
func (p *Provider) Duration(_ context.Context, key Key) time.Duration {
	return p.Provider.Duration(key.String())
}

// Get returns the raw value for the given config key.
func (p *Provider) Get(_ context.Context, key Key) any {
	return p.Provider.Get(key.String())
}

// Set updates the value for the given config key.
func (p *Provider) Set(_ context.Context, key Key, value any) error {
	return p.Provider.Set(key.String(), value)
}

// Unmarshal decodes the config value into the provided struct.
func (p *Provider) Unmarshal(_ context.Context, key Key, value any) error {
	return p.Provider.Unmarshal(key.String(), value)
}

// ActiveRetiredValues returns the retired values at key whose expiry is unset or
// still in the future. See FilterActiveRetiredValues.
func (p *Provider) ActiveRetiredValues(ctx context.Context, key Key) ([]string, error) {
	return FilterActiveRetiredValues(ctx, p, key)
}

// UnderlyingProvider returns the wrapped configx.Provider for direct access.
func (p *Provider) UnderlyingProvider(_ context.Context) *configx.Provider {
	return p.Provider
}

// reviewed - @aeneasr - 2026-03-25
