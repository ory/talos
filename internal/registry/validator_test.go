package registry_test

import (
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/ory/talos/internal/registry"
	talosv2alpha1 "github.com/ory/talos/pkg/api/talos/v2alpha1"
)

func TestNewWarmValidator(t *testing.T) {
	t.Parallel()

	validator, err := registry.NewWarmValidator()
	require.NoError(t, err)

	t.Run("accepts a valid request", func(t *testing.T) {
		t.Parallel()
		require.NoError(t, validator.Validate(&talosv2alpha1.IssueApiKeyRequest{
			Name:    "warm-validator-test",
			ActorId: "actor-1",
		}))
	})

	t.Run("rejects an invalid request", func(t *testing.T) {
		t.Parallel()
		// name violates min_len: 1, proving the pre-compiled rules are enforced.
		require.Error(t, validator.Validate(&talosv2alpha1.IssueApiKeyRequest{
			Name:    "",
			ActorId: "actor-1",
		}))
	})
}
