// Package cmd implements CLI commands for Talos.
package cmd

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/phayes/freeport"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/stretchr/testify/require"

	"github.com/ory/x/cmdx"

	client "github.com/ory/talos/internal/client/generated"
	"github.com/ory/talos/internal/testutil"
)

// testContext provides access to a running test server and CLI execution helpers.
type testContext struct {
	endpoint string
}

// setupTestServer starts a real Talos server via the serve command with SQLite,
// runs migrations, waits for the server to be healthy, and returns a testContext
// configured to execute CLI commands against it.
//
// This function resets prometheus.DefaultRegisterer and prometheus.DefaultGatherer
// to a fresh registry before starting the server. The production serve command uses
// prometheus.DefaultRegisterer, so sequential tests that each start a server would
// panic with "duplicate metrics collector registration" without this reset.
// Tests calling setupTestServer must NOT call t.Parallel() at the top level.
func setupTestServer(t *testing.T) *testContext {
	t.Helper()

	// Reset the default Prometheus registry so the next in-process server invocation
	// can register its metrics without a duplicate-registration panic. Capture the
	// originals so Cleanup can restore them — overwriting with a fresh empty registry
	// would drop process-global collectors that other tests rely on.
	origRegisterer := prometheus.DefaultRegisterer
	origGatherer := prometheus.DefaultGatherer
	fresh := prometheus.NewRegistry()
	prometheus.DefaultRegisterer = fresh
	prometheus.DefaultGatherer = fresh
	t.Cleanup(func() {
		prometheus.DefaultRegisterer = origRegisterer
		prometheus.DefaultGatherer = origGatherer
	})

	tmpDir := t.TempDir()

	// Generate test JWKS file for token signing via CLI, then encode as base64:// literal
	// (the config schema only accepts base64:// URLs for signing keys).
	jwksFile := filepath.Join(tmpDir, "test-jwks.json")
	_, _, err := cmdx.ExecCtx(t.Context(), NewRoot(), nil, "jwk", "generate", "eddsa", "--jwks", "--output", jwksFile)
	require.NoError(t, err, "generate JWKS file")
	jwksData, err := os.ReadFile(jwksFile)
	require.NoError(t, err, "read JWKS file")
	jwksURL := "base64://" + base64.StdEncoding.EncodeToString(jwksData)

	// Find free ports for HTTP and metrics servers
	ports, err := freeport.GetFreePorts(2)
	require.NoError(t, err)
	httpAddr := fmt.Sprintf("127.0.0.1:%d", ports[0])
	metricsAddr := fmt.Sprintf("127.0.0.1:%d", ports[1])

	// SQLite database path
	dbFile := filepath.Join(tmpDir, "test.db")
	dsn := "sqlite3://" + dbFile

	// Write config file
	configFile := filepath.Join(tmpDir, "config.yaml")
	writeTestConfig(t, configFile, dsn, jwksURL, httpAddr, metricsAddr)

	// Run migrations via CLI
	migrateRoot := NewRoot()
	_, migrateStderr, err := cmdx.ExecCtx(t.Context(), migrateRoot, nil,
		"migrate", "up", "--database", dsn)
	require.NoError(t, err, "migration failed: %s", migrateStderr)

	// Start server in background
	serverCtx, serverCancel := context.WithCancel(t.Context())

	var serverOut, serverErr bytes.Buffer
	serveRoot := NewRoot()
	eg := cmdx.ExecBackgroundCtx(serverCtx, serveRoot, nil, &serverOut, &serverErr,
		"serve", "--config", configFile)

	endpoint := "http://" + httpAddr

	// Wait for server to be ready
	waitForServer(t, endpoint)

	t.Cleanup(func() {
		serverCancel()
		_ = eg.Wait()
		t.Logf("server stdout: %s", serverOut.String())
		t.Logf("server stderr: %s", serverErr.String())
	})

	return &testContext{
		endpoint: endpoint,
	}
}

// exec runs a CLI command against the test server using a fresh NewRoot() command tree.
// The --endpoint flag is automatically set to point to the test server.
func (tc *testContext) exec(t *testing.T, args ...string) (stdout, stderr string, err error) {
	t.Helper()
	root := NewRoot()
	return cmdx.ExecCtx(t.Context(), root, nil,
		append([]string{"--endpoint", tc.endpoint}, args...)...)
}

// execWithInput runs a CLI command with stdin content.
func (tc *testContext) execWithInput(t *testing.T, input string, args ...string) (stdout, stderr string, err error) {
	t.Helper()
	root := NewRoot()
	return cmdx.ExecCtx(t.Context(), root, strings.NewReader(input),
		append([]string{"--endpoint", tc.endpoint}, args...)...)
}

// execNoErr runs a CLI command and requires it to succeed (error must be nil).
// Stderr output is allowed (commands print status messages there).
func (tc *testContext) execNoErr(t *testing.T, args ...string) (stdout, stderr string) {
	t.Helper()
	stdout, stderr, err := tc.exec(t, args...)
	require.NoError(t, err,
		"command %v failed\nstdout: %s\nstderr: %s", args, stdout, stderr)
	return stdout, stderr
}

// createAPIKey creates an API key via the CLI and returns the key ID and secret.
func (tc *testContext) createAPIKey(t *testing.T, name string) (keyID, secret string) {
	t.Helper()
	stdout, _ := tc.execNoErr(t, "keys", "issue", name,
		"--actor", "test-user",
		"--scopes", "read,write",
		"--format", "json")

	var output client.IssueApiKeyResponse
	require.NoError(t, json.Unmarshal([]byte(stdout), &output),
		"parse create output: %s", stdout)
	apiKey := output.GetIssuedApiKey()
	require.NotEmpty(t, apiKey.GetKeyId(), "key ID should not be empty")
	require.NotEmpty(t, output.GetSecret(), "secret should not be empty")

	return apiKey.GetKeyId(), output.GetSecret()
}

// revokeAPIKey revokes an API key via the CLI.
func (tc *testContext) revokeAPIKey(t *testing.T, keyID string) {
	t.Helper()
	tc.execNoErr(t, "keys", "issued", "revoke", keyID, "--reason", "superseded")
}

// assertAPIKeyRevoked checks that an API key has been revoked by attempting
// to validate its secret (which should fail).
func (tc *testContext) assertAPIKeyRevoked(t *testing.T, keyID string) {
	t.Helper()

	resp, httpResp, err := tc.sdkClient().ApiKeysAPI.
		AdminGetIssuedApiKey(t.Context(), keyID).
		Execute()
	if httpResp != nil {
		defer httpResp.Body.Close()
	}
	require.NoError(t, err, "should be able to get API key %s", keyID)
	require.Equal(t, "KEY_STATUS_REVOKED", string(resp.GetStatus()),
		"API key should be revoked")
}

// importAPIKey imports an external API key via the CLI and returns the key ID.
func (tc *testContext) importAPIKey(t *testing.T, name, rawKey string) string {
	t.Helper()
	stdout, _ := tc.execNoErr(t, "keys", "imported", "import", name,
		"--raw-key", rawKey,
		"--actor", "test-user",
		"--scopes", "read,write",
		"--format", "json")

	var output client.ImportedApiKey
	require.NoError(t, json.Unmarshal([]byte(stdout), &output),
		"parse import output: %s", stdout)
	require.NotEmpty(t, output.GetKeyId(), "key ID should not be empty")

	return output.GetKeyId()
}

// revokeImportedAPIKey revokes an imported API key via the CLI.
func (tc *testContext) revokeImportedAPIKey(t *testing.T, keyID string) {
	t.Helper()
	tc.execNoErr(t, "keys", "imported", "revoke", keyID, "--reason", "key_compromise")
}

// getIssuedRateLimitPolicy fetches an issued key via the SDK and returns its
// rate limit policy, or nil if none is set.
func (tc *testContext) getIssuedRateLimitPolicy(t *testing.T, keyID string) *client.RateLimitPolicy {
	t.Helper()

	resp, httpResp, err := tc.sdkClient().ApiKeysAPI.
		AdminGetIssuedApiKey(t.Context(), keyID).
		Execute()
	if httpResp != nil {
		defer httpResp.Body.Close()
	}
	require.NoError(t, err, "get issued key %s", keyID)

	policy, _ := resp.GetRateLimitPolicyOk()
	return policy
}

// getImportedRateLimitPolicy fetches an imported key via the SDK and returns its
// rate limit policy, or nil if none is set.
func (tc *testContext) getImportedRateLimitPolicy(t *testing.T, keyID string) *client.RateLimitPolicy {
	t.Helper()

	resp, httpResp, err := tc.sdkClient().ApiKeysAPI.
		AdminGetImportedApiKey(t.Context(), keyID).
		Execute()
	if httpResp != nil {
		defer httpResp.Body.Close()
	}
	require.NoError(t, err, "get imported key %s", keyID)

	policy, _ := resp.GetRateLimitPolicyOk()
	return policy
}

// sdkClient returns an OpenAPI SDK client pointing at the test server.
// Use this for verification assertions that cannot be done through CLI commands.
func (tc *testContext) sdkClient() *client.APIClient {
	return newSDKClient(tc.endpoint)
}

// writeTestConfig writes a minimal YAML config file for the test server.
// jwksURL must be a base64:// literal accepted by the config schema.
func writeTestConfig(t *testing.T, path, dsn, jwksURL, httpAddr, metricsAddr string) {
	t.Helper()

	httpHost, httpPort, err := net.SplitHostPort(httpAddr)
	require.NoError(t, err, "invalid http address")
	metricsHost, metricsPort, err := net.SplitHostPort(metricsAddr)
	require.NoError(t, err, "invalid metrics address")

	config := fmt.Sprintf(`db:
  dsn: %q

serve:
  http:
    host: %q
    port: %s
  metrics:
    host: %q
    port: %s

secrets:
  hmac:
    current: "test-hmac-secret-32-characters-long-for-hmac-sha256"
    retired: []

credentials:
  issuer: "test-issuer"
  api_keys:
    default_ttl: "24h"
    max_ttl: "8760h"
    prefix:
      current: "test"
      retired: []
  derived_tokens:
    default_ttl: "1h"
    jwt:
      signing_keys:
        urls:
          - "%s"
    macaroon:
      prefix:
        current: "mc"
        retired: []

cache:
  type: "noop"

log:
  level: "warn"
  format: "json"
`, dsn, httpHost, httpPort, metricsHost, metricsPort, jwksURL)

	require.NoError(t, os.WriteFile(path, []byte(config), 0o600))
}

// waitForServer polls the health endpoint until the server is ready or timeout.
func waitForServer(t *testing.T, endpoint string) {
	t.Helper()

	httpClient := &http.Client{Timeout: 500 * time.Millisecond, Transport: testutil.NewTestTransport(t)}
	deadline := time.Now().Add(15 * time.Second)

	for time.Now().Before(deadline) {
		req, err := http.NewRequestWithContext(t.Context(), http.MethodGet, endpoint+"/health/alive", nil)
		require.NoError(t, err)

		resp, err := httpClient.Do(req)
		if err == nil {
			_ = resp.Body.Close()
			if resp.StatusCode == http.StatusOK {
				return
			}
		}
		time.Sleep(100 * time.Millisecond)
	}

	t.Fatalf("server at %s failed to start within 15s", endpoint)
}

// reviewed - @aeneasr - 2026-03-25
