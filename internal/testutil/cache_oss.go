// Copyright © 2026 Ory Corp
// SPDX-License-Identifier: Apache-2.0

//go:build !commercial

// Package testutil provides test utilities for OSS builds.
package testutil

import (
	"github.com/ory/talos/internal/cache"
	db "github.com/ory/talos/internal/persistence/sqlc/generated"
)

// GetCacheForTests returns a noop cache for OSS tests
func GetCacheForTests() cache.Cache[db.IssuedApiKey] {
	return cache.NewNoopCache[db.IssuedApiKey]()
}

// reviewed - @aeneasr - 2026-03-25
