// Copyright © 2026 Ory Corp
// SPDX-License-Identifier: Apache-2.0

//go:build !commercial

package tracing

import (
	"context"

	sdktrace "go.opentelemetry.io/otel/sdk/trace"

	"github.com/ory/talos/internal/config"
)

// InitTracer is a no-op in OSS builds; tracing requires the commercial edition.
func InitTracer(_ context.Context, _ config.ProviderInterface) (*sdktrace.TracerProvider, error) {
	return nil, nil
}
