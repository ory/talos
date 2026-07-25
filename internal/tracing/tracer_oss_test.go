// Copyright © 2026 Ory Corp
// SPDX-License-Identifier: Apache-2.0

//go:build !commercial

package tracing_test

import (
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/ory/talos/internal/config"
	"github.com/ory/talos/internal/testutil"
	"github.com/ory/talos/internal/tracing"
)

// TestInitTracerOSSIsNoop verifies that InitTracer is a no-op in OSS builds
// even when tracing is enabled in the configuration. Tracing exporters are a
// commercial-only feature.
func TestInitTracerOSSIsNoop(t *testing.T) {
	t.Parallel()

	ctx := t.Context()
	provider := testutil.NewTestProvider(t)
	require.NoError(t, provider.Set(ctx, config.KeyTracingEnabled, true))
	require.NoError(t, provider.Set(ctx, config.KeyTracingExporter, "otlp"))
	require.NoError(t, provider.Set(ctx, config.KeyTracingEndpoint, "localhost:4317"))

	tp, err := tracing.InitTracer(ctx, provider)
	require.NoError(t, err)
	require.Nil(t, tp, "OSS InitTracer must return nil even when tracing is enabled")
}
