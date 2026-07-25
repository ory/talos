// Copyright © 2026 Ory Corp
// SPDX-License-Identifier: Apache-2.0

//go:build !commercial

package registry

import (
	"context"
	"log/slog"
	"net/http"

	"github.com/ory/talos/internal/config"
	"github.com/ory/talos/internal/logger"
	"github.com/ory/talos/internal/persistence"
	"github.com/ory/x/contextx"

	"github.com/ory/herodot"
)

// Options returns feature options for the OSS edition.
// OSS ignores contextualizer dependencies and returns no-op middleware.
func Options(_ context.Context, _ config.ProviderInterface, _ *slog.Logger, _ herodot.Writer) (*FeatureOptions, error) {
	return &FeatureOptions{
		Contextualizer:          &contextx.Default{},
		CacheFactories:          make(map[string]CacheFactory),
		DriverFactories:         make(map[string]persistence.Factory),
		RegisterDatabaseMetrics: func(_ persistence.Persister, _ *logger.Logger) {},
		// OSS doesn't support multi-tenancy, so middleware returns no-op
		HTTPMiddleware: func() func(http.Handler) http.Handler {
			return func(next http.Handler) http.Handler { return next }
		},
	}, nil
}

// reviewed - @aeneasr - 2026-03-25
