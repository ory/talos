// Package main provides a documentation drift checker that validates markdown docs
// against the project's proto, swagger, and config schema sources of truth.
package main

import (
	"bufio"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
)

var errProjectRootNotFound = errors.New("could not find project root (no go.mod)")

type violation struct {
	File    string
	Line    int
	Kind    string
	Literal string
	Message string
}

func main() {
	if len(os.Args) < 2 {
		fmt.Fprintf(os.Stderr, "Usage: %s <docs-dir>\n", os.Args[0])
		os.Exit(1)
	}

	docsDir := os.Args[1]

	root, err := findProjectRoot()
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error finding project root: %v\n", err)
		os.Exit(1)
	}

	endpoints, err := loadSwaggerEndpoints(filepath.Join(root, "api", "talos.openapi-v2.json"))
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error loading swagger: %v\n", err)
		os.Exit(1)
	}

	enums, err := loadProtoEnums(filepath.Join(root, "api", "talos", "v2alpha1", "talos.proto"))
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error loading proto: %v\n", err)
		os.Exit(1)
	}

	configKeys, validEnvVars, err := loadConfigKeys(filepath.Join(root, "spec", "config.schema.json"))
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error loading config schema: %v\n", err)
		os.Exit(1)
	}

	envVarRes := buildEnvVarRegexps(configKeys)

	var violations []violation

	err = filepath.Walk(docsDir, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}
		if info.IsDir() || !strings.HasSuffix(path, ".md") {
			return nil
		}
		// Skip confidential notes/plans (internal dev docs, not published)
		if strings.Contains(path, ".confidential") {
			return nil
		}

		fileViolations, scanErr := checkFile(path, endpoints, enums, validEnvVars, envVarRes)
		if scanErr != nil {
			fmt.Fprintf(os.Stderr, "Warning: error scanning %s: %v\n", path, scanErr)
			return nil
		}
		violations = append(violations, fileViolations...)
		return nil
	})
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error walking docs: %v\n", err)
		os.Exit(1)
	}

	if len(violations) == 0 {
		fmt.Println("No drift detected.")
		return
	}

	fmt.Printf("Found %d potential drift issue(s):\n\n", len(violations))
	for _, v := range violations {
		fmt.Printf("  %s:%d [%s] %q — %s\n", v.File, v.Line, v.Kind, v.Literal, v.Message)
	}
	os.Exit(1)
}

// loadSwaggerEndpoints extracts all path templates from the swagger spec.
// It also stores normalized forms (with generic {id} params) for flexible matching.
func loadSwaggerEndpoints(path string) (map[string]bool, error) {
	// #nosec G304 - Reading project source files is the intended functionality
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}

	var spec struct {
		Paths map[string]any `json:"paths"`
	}
	if err := json.Unmarshal(data, &spec); err != nil {
		return nil, err
	}

	endpoints := make(map[string]bool, len(spec.Paths)*2)
	paramRe := regexp.MustCompile(`\{[^}]+\}`)
	for p := range spec.Paths {
		endpoints[p] = true
		// Also store version with generic {id} for flexible matching
		normalized := paramRe.ReplaceAllString(p, "{id}")
		endpoints[normalized] = true
	}
	return endpoints, nil
}

// loadProtoEnums extracts all enum value names from the proto file.
func loadProtoEnums(path string) (map[string]bool, error) {
	// #nosec G304 - Reading project source files is the intended functionality
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}

	enums := make(map[string]bool)
	re := regexp.MustCompile(`^\s+((?:VERIFICATION_ERROR|BATCH_IMPORT_ERROR|REVOCATION_REASON|KEY_STATUS|TOKEN_ALGORITHM)\w+)\s*=`)
	for line := range strings.SplitSeq(string(data), "\n") {
		if m := re.FindStringSubmatch(line); m != nil {
			enums[m[1]] = true
		}
	}
	return enums, nil
}

// loadConfigKeys recursively extracts all dotted property paths from the JSON Schema
// and builds a set of valid environment variable names from those paths.
func loadConfigKeys(path string) (map[string]bool, map[string]bool, error) {
	// #nosec G304 - Reading project source files is the intended functionality
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, nil, err
	}

	var schema map[string]any
	if err := json.Unmarshal(data, &schema); err != nil {
		return nil, nil, err
	}

	keys := make(map[string]bool)
	extractConfigKeys(schema, "", keys)

	// Build valid env vars from config keys using the unambiguous forward mapping.
	// Include all path prefixes so docs can reference parent sections (e.g. DB).
	validEnvVars := make(map[string]bool)
	for key := range keys {
		parts := strings.Split(key, ".")
		for i := 1; i <= len(parts); i++ {
			prefix := strings.Join(parts[:i], ".")
			validEnvVars[configKeyToEnvVar(prefix)] = true
		}
	}

	return keys, validEnvVars, nil
}

func extractConfigKeys(obj map[string]any, prefix string, keys map[string]bool) {
	props, ok := obj["properties"].(map[string]any)
	if !ok {
		return
	}
	for k, v := range props {
		full := k
		if prefix != "" {
			full = prefix + "." + k
		}
		keys[full] = true
		if sub, ok := v.(map[string]any); ok {
			extractConfigKeys(sub, full, keys)
		}
	}
}

// envVarRegexps holds the scan patterns for config env vars in docs prose.
type envVarRegexps struct {
	// unprefixed matches candidate config env vars (e.g. SERVE_HTTP_PORT), anchored
	// on the schema's top-level sections so unrelated ALL_CAPS identifiers don't match.
	unprefixed *regexp.Regexp
	// stalePrefix matches config env vars still carrying the legacy TALOS_ prefix,
	// which the server never reads.
	stalePrefix *regexp.Regexp
}

// buildEnvVarRegexps derives the scan patterns from the schema's top-level config
// sections (e.g. SECRETS, SERVE, DB). Anchoring on real sections keeps the
// unprefixed pattern from matching arbitrary uppercase identifiers like enum values.
func buildEnvVarRegexps(configKeys map[string]bool) envVarRegexps {
	var sections []string
	for key := range configKeys {
		if !strings.Contains(key, ".") {
			sections = append(sections, regexp.QuoteMeta(strings.ToUpper(key)))
		}
	}
	// Longest-first so alternation can't stop at a shorter section that prefixes a longer one.
	sort.Slice(sections, func(i, j int) bool { return len(sections[i]) > len(sections[j]) })
	alternation := strings.Join(sections, "|")

	return envVarRegexps{
		// Require at least 2 segments (e.g. SERVE_HTTP_PORT) and end on an alphanumeric
		// to avoid matching partial env vars like FOO_ from FOO_0.
		unprefixed:  regexp.MustCompile(`\b(?:` + alternation + `)(?:_[A-Z][A-Z0-9]*)+`),
		stalePrefix: regexp.MustCompile(`TALOS_(?:` + alternation + `)(?:_[A-Z][A-Z0-9]*)*`),
	}
}

func checkFile(path string, endpoints map[string]bool, enums map[string]bool, validEnvVars map[string]bool, envVarRes envVarRegexps) ([]violation, error) {
	// #nosec G304 - Reading user-specified markdown files is the intended functionality
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()

	var violations []violation
	scanner := bufio.NewScanner(f)
	lineNum := 0
	inCodeBlock := false

	// Endpoint regex captures shell variables and path params in URL paths
	endpointRe := regexp.MustCompile(`/v2alpha1/(?:admin/|api[Kk]eys)[$$\w/.{}\-:]+`)
	enumRe := regexp.MustCompile(`\b(VERIFICATION_ERROR_\w+|BATCH_IMPORT_ERROR_\w+|REVOCATION_REASON_\w+|KEY_STATUS_\w+|TOKEN_ALGORITHM_\w+)\b`)

	for scanner.Scan() {
		lineNum++
		line := scanner.Text()

		// Track fenced code blocks — skip checks inside code examples
		if strings.HasPrefix(strings.TrimSpace(line), "```") {
			inCodeBlock = !inCodeBlock
			continue
		}
		if inCodeBlock {
			continue
		}

		// Skip frontmatter
		if lineNum <= 7 && (line == "---" || strings.HasPrefix(line, "title:") || strings.HasPrefix(line, "tags:") || strings.HasPrefix(line, "description:") || strings.HasPrefix(line, "sidebar_custom_props:") || strings.HasPrefix(line, "  badge:")) {
			continue
		}

		// Check endpoint paths
		for _, m := range endpointRe.FindAllString(line, -1) {
			normalized := normalizeEndpoint(m)
			if normalized == "" {
				continue
			}
			if !endpoints[normalized] {
				violations = append(violations, violation{
					File:    path,
					Line:    lineNum,
					Kind:    "endpoint",
					Literal: m,
					Message: "endpoint not found in swagger spec",
				})
			}
		}

		// Check enum literals
		for _, m := range enumRe.FindAllStringSubmatch(line, -1) {
			if !enums[m[1]] {
				violations = append(violations, violation{
					File:    path,
					Line:    lineNum,
					Kind:    "enum",
					Literal: m[1],
					Message: "enum value not found in proto",
				})
			}
		}

		// Config env vars still carrying the legacy TALOS_ prefix are never read by the server.
		for _, m := range envVarRes.stalePrefix.FindAllString(line, -1) {
			violations = append(violations, violation{
				File:    path,
				Line:    lineNum,
				Kind:    "config",
				Literal: m,
				Message: "Talos reads unprefixed env vars; drop the TALOS_ prefix",
			})
		}

		// Check config env vars (at least 2 segments, e.g. SERVE_HTTP_PORT)
		for _, m := range envVarRes.unprefixed.FindAllString(line, -1) {
			if !validEnvVars[m] {
				violations = append(violations, violation{
					File:    path,
					Line:    lineNum,
					Kind:    "config",
					Literal: m,
					Message: fmt.Sprintf("env var %q does not match any config key", m),
				})
			}
		}
	}
	return violations, scanner.Err()
}

// normalizeEndpoint cleans up endpoint paths for matching against swagger.
func normalizeEndpoint(ep string) string {
	// Trim trailing whitespace, quotes, backticks
	ep = strings.TrimRight(ep, "` \t\n\r\"')")

	// Skip ellipsis/wildcard patterns (descriptive, not real endpoints)
	if strings.Contains(ep, "...") {
		return ""
	}

	// Replace shell variables: $KEY_ID, ${KEY_ID}, $key_id
	shellVarRe := regexp.MustCompile(`\$\{?\w+\}?`)
	ep = shellVarRe.ReplaceAllString(ep, "{id}")

	// Normalize all path params to {id} for matching
	paramRe := regexp.MustCompile(`\{[^}]+\}`)
	ep = paramRe.ReplaceAllString(ep, "{id}")

	// Normalize literal resource IDs in path segments (UUIDs, ULIDs, hex strings ≥16 chars)
	literalIDRe := regexp.MustCompile(`/[0-9a-fA-F]{16,}|/[0-9A-Z]{20,}`)
	ep = literalIDRe.ReplaceAllString(ep, "/{id}")

	// Remove trailing slash if it's not the entire path
	ep = strings.TrimRight(ep, "/")

	return ep
}

// configKeyToEnvVar converts a dotted config key to its env var form.
// Example: credentials.api_keys.default_ttl -> CREDENTIALS_API_KEYS_DEFAULT_TTL
func configKeyToEnvVar(key string) string {
	return strings.ToUpper(strings.ReplaceAll(key, ".", "_"))
}

func findProjectRoot() (string, error) {
	dir, err := os.Getwd()
	if err != nil {
		return "", err
	}
	for {
		if _, err := os.Stat(filepath.Join(dir, "go.mod")); err == nil {
			return dir, nil
		}
		parent := filepath.Dir(dir)
		if parent == dir {
			return "", errProjectRootNotFound
		}
		dir = parent
	}
}
