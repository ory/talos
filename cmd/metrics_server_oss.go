// Copyright © 2026 Ory Corp
// SPDX-License-Identifier: Apache-2.0

//go:build !commercial

package cmd

import "net/http"

// registerMetricsRoute is a no-op in OSS builds; Prometheus metrics scraping
// requires the commercial edition.
func registerMetricsRoute(_ *http.ServeMux) {}
