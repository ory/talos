// Copyright © 2026 Ory Corp
// SPDX-License-Identifier: Apache-2.0

//go:build !commercial

package cmd

import (
	"github.com/cockroachdb/errors"
	"github.com/spf13/cobra"
)

func newProxyCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "proxy",
		Short: "Start the edge proxy (commercial edition only)",
		Long:  `The proxy command is only available in the commercial edition.`,
		RunE: func(_ *cobra.Command, _ []string) error {
			return errors.New("proxy command requires commercial edition")
		},
	}
}

// reviewed - @aeneasr - 2026-03-25
