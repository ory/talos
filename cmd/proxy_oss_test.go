// Copyright © 2026 Ory Corp
// SPDX-License-Identifier: Apache-2.0

//go:build !commercial

package cmd

import (
	"bytes"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestProxyCommand_OSS_ReturnsCommercialRequired(t *testing.T) {
	t.Parallel()

	root := NewRoot()
	root.SetArgs([]string{"proxy"})

	var stderr bytes.Buffer
	root.SetErr(&stderr)

	err := root.Execute()
	require.Error(t, err)
	assert.Contains(t, err.Error(), "commercial edition")
}

func TestProxyCommand_OSS_Help(t *testing.T) {
	t.Parallel()

	root := NewRoot()
	root.SetArgs([]string{"proxy", "--help"})

	var stdout bytes.Buffer
	root.SetOut(&stdout)

	err := root.Execute()
	require.NoError(t, err)

	output := stdout.String()
	// The Long description contains the commercial edition message
	assert.Contains(t, output, "commercial edition")
}

// reviewed - @aeneasr - 2026-03-25
