// Copyright © 2026 Ory Corp
// SPDX-License-Identifier: Apache-2.0

//go:build !commercial

package registry

import (
	"context"

	talosconfig "github.com/ory/talos/internal/config"
)

// ConfigureCloudContextualizer is a no-op in OSS builds; the commercial edition wires up
// the multi-tenant hostname-to-network-ID contextualizer.
func ConfigureCloudContextualizer(_ context.Context, _ *FeatureOptions, _ talosconfig.ProviderInterface) {
}

// ConfigureAnalyticsTracer is a no-op in OSS builds; the commercial edition wires up
// the analytics exporter for tenant activity tracing.
func ConfigureAnalyticsTracer(_ context.Context) {}

// reviewed - @aeneasr - 2026-03-25
