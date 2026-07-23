package cmd

import (
	"bytes"
	"encoding/json"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/ory/talos/internal/logger"
)

// secretMarker is embedded in test URLs to prove that no part of a configured
// URL (host, credentials, or query string) ever reaches the log output.
const secretMarker = "super-secret-do-not-log"

func newBufferLogger(t *testing.T) (*logger.Logger, *bytes.Buffer) {
	t.Helper()
	buf := &bytes.Buffer{}
	return logger.NewLoggerWithWriter(buf, "warn", "json"), buf
}

// warnRecords parses the JSON log buffer and returns only the WARN records
// emitted by warnInsecureSigningKeyURLs (identified by the config_key field).
func warnRecords(t *testing.T, buf *bytes.Buffer) []map[string]any {
	t.Helper()
	var records []map[string]any
	for line := range strings.SplitSeq(strings.TrimSpace(buf.String()), "\n") {
		if line == "" {
			continue
		}
		var rec map[string]any
		require.NoError(t, json.Unmarshal([]byte(line), &rec))
		if rec["level"] == "WARN" {
			records = append(records, rec)
		}
	}
	return records
}

func TestWarnInsecureSigningKeyURLs(t *testing.T) {
	t.Parallel()

	t.Run("safe sources produce no warning", func(t *testing.T) {
		t.Parallel()

		log, buf := newBufferLogger(t)
		warnInsecureSigningKeyURLs(log, []string{
			"https://" + secretMarker + ".example.com/jwks.json",
			"file:///etc/talos/" + secretMarker + ".json",
			"base64://" + secretMarker,
		})

		assert.Empty(t, warnRecords(t, buf))
	})

	t.Run("no sources produce no warning", func(t *testing.T) {
		t.Parallel()

		log, buf := newBufferLogger(t)
		warnInsecureSigningKeyURLs(log, nil)

		assert.Empty(t, warnRecords(t, buf))
	})

	t.Run("single insecure source produces one warning", func(t *testing.T) {
		t.Parallel()

		log, buf := newBufferLogger(t)
		warnInsecureSigningKeyURLs(log, []string{
			"http://" + secretMarker + ".example.com/jwks.json?token=" + secretMarker,
		})

		records := warnRecords(t, buf)
		require.Len(t, records, 1)
		rec := records[0]
		assert.Equal(t, "credentials.derived_tokens.jwt.signing_keys.urls", rec["config_key"])
		assert.EqualValues(t, 1, rec["insecure_count"])
		assert.Equal(t, []any{float64(0)}, rec["insecure_indexes"])
	})

	t.Run("multiple insecure sources report count and indexes", func(t *testing.T) {
		t.Parallel()

		log, buf := newBufferLogger(t)
		warnInsecureSigningKeyURLs(log, []string{
			"https://safe.example.com/jwks.json",
			"http://insecure-one.example.com/jwks.json",
			"HTTP://insecure-two.example.com/jwks.json",
		})

		records := warnRecords(t, buf)
		require.Len(t, records, 1)
		rec := records[0]
		assert.EqualValues(t, 2, rec["insecure_count"])
		assert.Equal(t, []any{float64(1), float64(2)}, rec["insecure_indexes"])
	})

	t.Run("never logs URL values or secrets", func(t *testing.T) {
		t.Parallel()

		log, buf := newBufferLogger(t)
		warnInsecureSigningKeyURLs(log, []string{
			"http://" + secretMarker + ".example.com/jwks.json?token=" + secretMarker,
		})

		require.Len(t, warnRecords(t, buf), 1)
		assert.NotContains(t, buf.String(), secretMarker)
		assert.NotContains(t, buf.String(), "example.com")
	})
}
