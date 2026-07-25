// Copyright © 2026 Ory Corp
// SPDX-License-Identifier: Apache-2.0

//go:build !commercial

package contextx

import (
	"context"
	"testing"

	"github.com/gofrs/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestRequiredNetworkIDFromContext_IgnoresContextValue(t *testing.T) {
	t.Parallel()

	// OSS is single-tenant: the network ID is always uuid.Nil, even when a
	// value is present in context.
	customNID := uuid.Must(uuid.FromString("12345678-1234-1234-1234-123456789012"))
	ctx := context.WithValue(t.Context(), NIDKey{}, customNID)

	nid, err := RequiredNetworkIDFromContext(ctx)
	require.NoError(t, err)
	assert.Equal(t, uuid.Nil, nid)
}

func TestRequiredNetworkIDFromContext_Missing(t *testing.T) {
	t.Parallel()

	// OSS is single-tenant: a missing NID resolves to uuid.Nil without error.
	nid, err := RequiredNetworkIDFromContext(t.Context())
	require.NoError(t, err)
	assert.Equal(t, uuid.Nil, nid)
}

func TestRequiredNetworkIDFromContext_WrongType(t *testing.T) {
	t.Parallel()

	// OSS is single-tenant: a wrong-type value resolves to uuid.Nil without error.
	ctx := context.WithValue(t.Context(), NIDKey{}, "not-a-uuid")
	nid, err := RequiredNetworkIDFromContext(ctx)
	require.NoError(t, err)
	assert.Equal(t, uuid.Nil, nid)
}
