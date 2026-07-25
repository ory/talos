// Copyright © 2026 Ory Corp
// SPDX-License-Identifier: Apache-2.0

//go:build !commercial

// Package migrations provides database migration filesystem selection for OSS edition.
// In OSS builds, this simply delegates to the internal migrations package.
package migrations

import (
	"io/fs"

	"github.com/ory/talos/internal/persistence/migrations"
)

// GetMigrationsFS returns the appropriate migrations filesystem for the given database URL.
// OSS edition only supports SQLite - delegates to internal package.
func GetMigrationsFS(databaseURL string) (fs.FS, string, error) {
	// Delegate to internal package which handles OSS validation
	return migrations.GetMigrationsFS(databaseURL)
}

// reviewed - @aeneasr - 2026-03-25
