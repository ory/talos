package service

import (
	"context"
	"testing"
	"time"

	"github.com/cockroachdb/errors"
	"github.com/gofrs/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/ory/herodot"

	"github.com/ory/talos/internal/contextx"
	"github.com/ory/talos/internal/crypto"

	"github.com/ory/talos/internal/config"
	"github.com/ory/talos/internal/pagination"
	"github.com/ory/talos/internal/testutil"

	"github.com/ory/x/configx"
)

// fakeConfigProvider is a minimal ConfigProvider stub for unit tests of helpers
// that only need a small slice of configuration. It avoids the schema validation
// performed by the real provider, which prevents constructing fixtures with
// intentionally missing or empty secrets.
type fakeConfigProvider struct {
	strings map[config.Key]string
	lists   map[config.Key][]string
}

func (f *fakeConfigProvider) String(_ context.Context, key config.Key) string {
	return f.strings[key]
}

func (f *fakeConfigProvider) Strings(_ context.Context, key config.Key) []string {
	return f.lists[key]
}

func (f *fakeConfigProvider) ActiveRetiredValues(_ context.Context, key config.Key) ([]string, error) {
	return f.lists[key], nil
}

func (f *fakeConfigProvider) Duration(_ context.Context, _ config.Key) time.Duration {
	return 0
}

func (f *fakeConfigProvider) Int(_ context.Context, _ config.Key) int {
	return 0
}

func (f *fakeConfigProvider) Bool(_ context.Context, _ config.Key) bool {
	return false
}

func TestPaginationKeys_RequireHMACSecret(t *testing.T) {
	t.Parallel()

	// With no HMAC secret configured, decoding any token must fail with an
	// internal-error wrap of the "no HMAC key configured" message. This
	// guards against a regression where a missing secret silently degrades
	// to an unsigned cursor.
	provider := &fakeConfigProvider{}
	helper := &paginationHelper{provider: provider}

	_, err := helper.prepareListQuery(t.Context(), "", 10, "some-non-empty-token")
	require.Error(t, err)
	herodotErr := new(herodot.DefaultError)
	require.True(t, errors.As(err, &herodotErr), "error should be a herodot DefaultError")
	assert.Contains(t, errors.Unwrap(herodotErr).Error(), "no HMAC key configured")
}

func TestPaginationHelper_PrepareListQuery(t *testing.T) {
	t.Parallel()

	const testSecret = "test-secret-at-least-32-bytes-long"
	mockProvider := testutil.NewTestProvider(t, configx.WithValues(map[string]any{
		config.KeySecretsHMACCurrent.String(): testSecret,
	}))
	helper := &paginationHelper{provider: mockProvider}
	// Required because prepareListQuery uses the strict RequiredNetworkIDFromContext,
	// which errors in commercial builds when the context has no NID.
	ctx := context.WithValue(t.Context(), contextx.NIDKey{}, uuid.Nil)
	testKey := crypto.DerivePaginationKey(testSecret)

	t.Run("empty token returns empty cursor key", func(t *testing.T) {
		params, err := helper.prepareListQuery(ctx, "", 10, "")
		require.NoError(t, err)
		assert.Empty(t, params.cursorKey)
		assert.Equal(t, int64(11), params.limit)
	})

	t.Run("valid token decodes cursor key", func(t *testing.T) {
		token, err := pagination.EncodeCursor(testKey, "item-123", contextx.NetworkIDFromContext(ctx).String())
		require.NoError(t, err)

		params, err := helper.prepareListQuery(ctx, "", 10, token)
		require.NoError(t, err)
		assert.Equal(t, "item-123", params.cursorKey)
	})

	// Cross-tenant token rejection is a multi-tenant (commercial) concern: in OSS
	// the network ID is always uuid.Nil, so there is no cross-tenant boundary to
	// enforce. See pagination_helper_commercial_test.go for that coverage.

	t.Run("invalid token returns bad request", func(t *testing.T) {
		_, err := helper.prepareListQuery(ctx, "", 10, "invalid-token")
		require.Error(t, err)
	})
}

func TestPaginationHelper_OSSMode(t *testing.T) {
	t.Parallel()

	// In OSS mode no NID is set on the context, so NetworkIDStringFromContext
	// returns the nil UUID string "00000000-0000-0000-0000-000000000000".
	// This test verifies the full encode -> decode roundtrip works with that value.
	mockProvider := testutil.NewTestProvider(t, configx.WithValues(map[string]any{
		config.KeySecretsHMACCurrent.String(): "test-secret-at-least-32-bytes-long",
	}))
	helper := &paginationHelper{provider: mockProvider}
	ctx := context.WithValue(t.Context(), contextx.NIDKey{}, uuid.Nil)

	// nextPageToken encodes a cursor using the nil UUID NID from context.
	nextToken, err := helper.nextPageToken(ctx, 11, 10, "last-item-id")
	require.NoError(t, err)
	require.NotEmpty(t, nextToken)

	// prepareListQuery must decode the token back correctly.
	params, err := helper.prepareListQuery(ctx, "", 10, nextToken)
	require.NoError(t, err)
	assert.Equal(t, "last-item-id", params.cursorKey)
}

func TestPaginationHelper_HMACRotation(t *testing.T) {
	t.Parallel()

	// Tokens encrypted with a retired HMAC secret must still decode after
	// rotation, because the pagination key set tracks the HMAC key set 1:1.
	const oldSecret = "old-hmac-secret-at-least-32-bytes-long"
	const newSecret = "new-hmac-secret-at-least-32-bytes-long"

	mockProvider := testutil.NewTestProvider(t, configx.WithValues(map[string]any{
		config.KeySecretsHMACCurrent.String(): newSecret,
		config.KeySecretsHMACRetired.String(): []map[string]any{{"value": oldSecret}},
	}))
	helper := &paginationHelper{provider: mockProvider}
	ctx := context.WithValue(t.Context(), contextx.NIDKey{}, uuid.Nil)

	// Encode a token using the OLD key (simulating a token issued before rotation).
	oldKey := crypto.DerivePaginationKey(oldSecret)
	tokenFromOldKey, err := pagination.EncodeCursor(oldKey, "item-from-before-rotation", contextx.NetworkIDFromContext(ctx).String())
	require.NoError(t, err)

	// The helper, configured with the new secret as current, must still decode
	// the old token via the retired secret.
	params, err := helper.prepareListQuery(ctx, "", 10, tokenFromOldKey)
	require.NoError(t, err)
	assert.Equal(t, "item-from-before-rotation", params.cursorKey)
}

func Test_trimResults(t *testing.T) {
	t.Parallel()

	t.Run("trims extra result", func(t *testing.T) {
		results := []int{1, 2, 3, 4} // Fetched 4
		pageSize := int32(3)
		trimmed := trimResults(results, pageSize)
		assert.Len(t, trimmed, 3)
		assert.Equal(t, []int{1, 2, 3}, trimmed)
	})

	t.Run("returns all results if count <= pageSize", func(t *testing.T) {
		results := []int{1, 2, 3}
		pageSize := int32(3)
		trimmed := trimResults(results, pageSize)
		assert.Len(t, trimmed, 3)
		assert.Equal(t, results, trimmed)
	})

	t.Run("returns empty slice when input is empty", func(t *testing.T) {
		trimmed := trimResults([]int{}, 10)
		assert.Empty(t, trimmed)
	})

	t.Run("returns nil slice when input is nil", func(t *testing.T) {
		trimmed := trimResults[int](nil, 10)
		assert.Nil(t, trimmed)
	})

	t.Run("returns single element when pageSize is 1 and has extra", func(t *testing.T) {
		trimmed := trimResults([]int{1, 2}, 1)
		assert.Equal(t, []int{1}, trimmed)
	})
}

func TestPaginationHelper_PrepareListQuery_Adversarial(t *testing.T) {
	t.Parallel()

	const testSecret = "test-secret-at-least-32-bytes-long"
	mockProvider := testutil.NewTestProvider(t, configx.WithValues(map[string]any{
		config.KeySecretsHMACCurrent.String(): testSecret,
	}))
	helper := &paginationHelper{provider: mockProvider}
	ctx := context.WithValue(t.Context(), contextx.NIDKey{}, uuid.Nil)
	testKey := crypto.DerivePaginationKey(testSecret)

	t.Run("page size boundaries", func(t *testing.T) {
		tests := []struct {
			name             string
			pageSize         int32
			expectedPageSize int32
		}{
			{"zero defaults to 50", 0, 50},
			{"negative defaults to 50", -1, 50},
			{"min int32 defaults to 50", -2147483648, 50},
			{"one is valid", 1, 1},
			{"max page size 1000", 1000, 1000},
			{"over max clamped to 1000", 1001, 1000},
			{"max int32 clamped to 1000", 2147483647, 1000},
		}

		for _, tt := range tests {
			t.Run(tt.name, func(t *testing.T) {
				params, err := helper.prepareListQuery(ctx, "", tt.pageSize, "")
				require.NoError(t, err)
				assert.Equal(t, tt.expectedPageSize, params.pageSize)
				assert.Equal(t, int64(tt.expectedPageSize+1), params.limit, "limit should be pageSize+1")
			})
		}
	})

	t.Run("filter injection attempts", func(t *testing.T) {
		tests := []struct {
			name   string
			filter string
		}{
			// Note: SQL injection via quoted values is safe because values are
			// always parameterized, never interpolated into SQL. The regex
			// [^"]+ allows semicolons and quotes-within-quotes are impossible.
			// These tests verify structural rejection only.
			{"SQL comment injection", `actor_id="test" /* comment */`},
			{"SQL UNION injection", `actor_id="x" UNION SELECT * FROM keys`},
			{"newline injection", "actor_id=\"test\nAND 1=1\""},
			{"unknown field", `admin=true`},
			{"unknown field with SQL", `1=1; DROP TABLE keys`},
			{"empty clause from double AND", `actor_id="test" AND AND status=KEY_STATUS_ACTIVE`}, //nolint:dupword // intentional adversarial filter input
			{"bare AND keyword", `AND`},
			{"OR not supported", `actor_id="a" OR actor_id="b"`},
		}

		for _, tt := range tests {
			t.Run(tt.name, func(t *testing.T) {
				_, err := helper.prepareListQuery(ctx, tt.filter, 10, "")
				require.Error(t, err, "filter %q should be rejected", tt.filter)
			})
		}
	})

	t.Run("SQL injection in quoted values is safely parameterized", func(t *testing.T) {
		// Values inside quotes are accepted by the parser because they are
		// always passed as parameterized query arguments, never interpolated.
		// Verify the value arrives intact (not that it's rejected).
		params, err := helper.prepareListQuery(ctx, `actor_id="'; DROP TABLE keys; --"`, 10, "")
		require.NoError(t, err)
		assert.Equal(t, "'; DROP TABLE keys; --", params.filter.ActorID,
			"dangerous value should be captured verbatim for parameterized use")

		params, err = helper.prepareListQuery(ctx, `actor_id="test;DROP TABLE keys"`, 10, "")
		require.NoError(t, err)
		assert.Equal(t, "test;DROP TABLE keys", params.filter.ActorID)
	})

	t.Run("status filter without actor_id returns bad request", func(t *testing.T) {
		_, err := helper.prepareListQuery(ctx, `status=KEY_STATUS_ACTIVE`, 10, "")
		require.Error(t, err)
		var herodotErr *herodot.DefaultError
		require.True(t, errors.As(err, &herodotErr))
		assert.Equal(t, 400, herodotErr.StatusCode())
		assert.Contains(t, herodotErr.Reason(), "status filter must be combined with actor_id")
	})

	t.Run("valid combined filter", func(t *testing.T) {
		params, err := helper.prepareListQuery(ctx, `actor_id="user-123" AND status=KEY_STATUS_ACTIVE`, 10, "")
		require.NoError(t, err)
		assert.Equal(t, "user-123", params.filter.ActorID)
	})

	t.Run("duplicate filter fields rejected", func(t *testing.T) {
		_, err := helper.prepareListQuery(ctx, `actor_id="a" AND actor_id="b"`, 10, "")
		require.Error(t, err)
	})

	t.Run("tampered token bytes returns bad request", func(t *testing.T) {
		// Encode a valid token then corrupt it
		token, err := pagination.EncodeCursor(testKey, "item-1", contextx.NetworkIDFromContext(ctx).String())
		require.NoError(t, err)

		corrupted := token[:len(token)-3] + "XXX"
		_, err = helper.prepareListQuery(ctx, "", 10, corrupted)
		require.Error(t, err)
	})

	t.Run("wrong-key token returns bad request", func(t *testing.T) {
		wrongKey := crypto.DerivePaginationKey("another-secret-at-least-32-bytes!!")
		token, err := pagination.EncodeCursor(wrongKey, "item-1", contextx.NetworkIDFromContext(ctx).String())
		require.NoError(t, err)

		_, err = helper.prepareListQuery(ctx, "", 10, token)
		require.Error(t, err)
	})
}

func TestPaginationHelper_NextPageToken(t *testing.T) {
	t.Parallel()

	const testSecret = "test-secret-at-least-32-bytes-long"
	mockProvider := testutil.NewTestProvider(t, configx.WithValues(map[string]any{
		config.KeySecretsHMACCurrent.String(): testSecret,
	}))
	helper := &paginationHelper{provider: mockProvider}
	ctx := context.WithValue(t.Context(), contextx.NIDKey{}, uuid.Nil)

	t.Run("no next page when count equals page size", func(t *testing.T) {
		token, err := helper.nextPageToken(ctx, 10, 10, "last-id")
		require.NoError(t, err)
		assert.Empty(t, token)
	})

	t.Run("no next page when count less than page size", func(t *testing.T) {
		token, err := helper.nextPageToken(ctx, 5, 10, "last-id")
		require.NoError(t, err)
		assert.Empty(t, token)
	})

	t.Run("has next page when count exceeds page size", func(t *testing.T) {
		token, err := helper.nextPageToken(ctx, 11, 10, "last-id")
		require.NoError(t, err)
		assert.NotEmpty(t, token)

		// Verify round-trip
		params, err := helper.prepareListQuery(ctx, "", 10, token)
		require.NoError(t, err)
		assert.Equal(t, "last-id", params.cursorKey)
	})

	t.Run("zero count returns no next page", func(t *testing.T) {
		token, err := helper.nextPageToken(ctx, 0, 10, "last-id")
		require.NoError(t, err)
		assert.Empty(t, token)
	})
}

// reviewed - @aeneasr - 2026-03-26
