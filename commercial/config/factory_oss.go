// Copyright © 2026 Ory Corp
// SPDX-License-Identifier: Apache-2.0

//go:build !commercial

// Package config provides build-specific factory functions for config providers.
package config

import (
	"context"

	"github.com/ory/talos/internal/config"
)

// NewProvider creates a config provider for the OSS edition.
func NewProvider(ctx context.Context, configFile string) (config.ProviderInterface, error) {
	return config.NewProvider(ctx, configFile)
}

// reviewed - @aeneasr - 2026-03-25
