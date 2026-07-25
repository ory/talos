// Copyright © 2026 Ory Corp
// SPDX-License-Identifier: Apache-2.0

//go:build !commercial

package cmd

import (
	"github.com/ory/talos/internal/persistence/migrations"
)

var getMigrationsFS = migrations.GetMigrationsFS

// reviewed - @aeneasr - 2026-03-25
