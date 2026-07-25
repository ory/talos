// Copyright © 2026 Ory Corp
// SPDX-License-Identifier: Apache-2.0

//go:build !commercial

package registry

import (
	"github.com/ory/talos/internal/persistence"
)

// DatabaseDriverFactories returns database driver factories for initialization.
// OSS version returns empty map (SQLite is initialized differently).
func DatabaseDriverFactories() map[string]persistence.Factory {
	return make(map[string]persistence.Factory)
}

// reviewed - @aeneasr - 2026-03-25
