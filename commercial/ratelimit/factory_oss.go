// Copyright © 2026 Ory Corp
// SPDX-License-Identifier: Apache-2.0

//go:build !commercial

package ratelimit

import (
	"context"

	"github.com/ory/talos/internal/cache"
)

// NewLimiter returns a no-op limiter in OSS builds.
func NewLimiter(_ context.Context, _ string, _ *cache.Config) (Limiter, error) {
	return &NoopLimiter{}, nil
}

// reviewed - @aeneasr - 2026-03-25
