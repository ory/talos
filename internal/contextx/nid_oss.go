// Copyright © 2026 Ory Corp
// SPDX-License-Identifier: Apache-2.0

//go:build !commercial

package contextx

import (
	"context"

	"github.com/gofrs/uuid"
)

// RequiredNetworkIDFromContext returns the network ID. OSS builds are
// single-tenant, so the network ID is always uuid.Nil regardless of context.
// The error return exists so commercial (multi-tenant) builds can fail loud on
// a missing NID; see nid_commercial.go.
func RequiredNetworkIDFromContext(context.Context) (uuid.UUID, error) {
	return uuid.Nil, nil
}
