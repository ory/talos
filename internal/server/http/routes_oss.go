// Copyright © 2026 Ory Corp
// SPDX-License-Identifier: Apache-2.0

//go:build !commercial

package http

import "github.com/grpc-ecosystem/grpc-gateway/v2/runtime"

// registerEditionRoutes is a no-op in OSS builds.
// The /revisions/talos endpoint requires per-tenant config (commercial contextualizer)
// and is not available in single-tenant OSS deployments.
func (s *GatewayServer) registerEditionRoutes(_ *Metrics, _ *runtime.ServeMux) {}

// setupMetricsRoute is a no-op in OSS builds; Prometheus scraping requires the commercial edition.
func (s *GatewayServer) setupMetricsRoute() {}
