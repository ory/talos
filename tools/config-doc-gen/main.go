// Package main generates Markdown documentation from the Talos configuration JSON Schema.
//
// Usage:
//
//	go run ./tools/config-doc-gen > docs/reference/config.md
package main

import (
	"encoding/json"
	"fmt"
	"maps"
	"os"
	"slices"
	"strings"
)

const typeObject = "object"

type Schema struct {
	Title       string            `json:"title"`
	Description string            `json:"description"`
	Type        string            `json:"type"`
	Properties  map[string]Schema `json:"properties"`
	Items       *Schema           `json:"items"`
	Default     any               `json:"default"`
	Enum        []any             `json:"enum"`
	OneOf       []Schema          `json:"oneOf"`
	Minimum     *float64          `json:"minimum"`
	Maximum     *float64          `json:"maximum"`
	MinLength   *int              `json:"minLength"`
	Pattern     string            `json:"pattern"`
	Required    []string          `json:"required"`

	// Custom extensions
	Immutable       bool `json:"x-immutable"`
	LicenseRequired bool `json:"x-license-required"`

	// Additional properties
	AdditionalProperties any `json:"additionalProperties"`
}

func main() {
	data, err := os.ReadFile("spec/config.schema.json")
	if err != nil {
		_, _ = fmt.Fprintf(os.Stderr, "Error reading schema: %v\n", err)
		os.Exit(1)
	}

	var schema Schema
	if err := json.Unmarshal(data, &schema); err != nil {
		_, _ = fmt.Fprintf(os.Stderr, "Error parsing schema: %v\n", err)
		os.Exit(1)
	}

	fmt.Println("---")
	fmt.Println("title: Configuration reference")
	fmt.Println("description: Auto-generated configuration reference from JSON Schema")
	fmt.Println("---")
	fmt.Println()
	fmt.Println("# Configuration reference")
	fmt.Println()
	fmt.Println("This page is auto-generated from the [configuration schema](https://github.com/ory/talos/blob/main/spec/config.schema.json).")
	fmt.Println()
	fmt.Printf("Required top-level keys: %s\n", formatRequired(schema.Required))
	fmt.Println()
	printEnvVarSection()
	fmt.Println()

	// Sort top-level keys for deterministic output
	keys := sortedKeys(schema.Properties)
	for _, key := range keys {
		prop := schema.Properties[key]
		printSection(key, prop, 2)
	}
}

func printEnvVarSection() {
	fmt.Println(`## Environment variables

Every configuration key can be set via an environment variable. Talos uses the ` + "`TALOS_`" + ` prefix and
converts dot-separated config paths to uppercase with underscores:

` + "```" + `
TALOS_<SECTION>_<KEY>
` + "```" + `

Replace dots (` + "`.`" + `) with underscores (` + "`_`" + `) and convert to uppercase. For example, ` + "`serve.http.port`" + `
becomes ` + "`TALOS_SERVE_HTTP_PORT`" + `.

### Array values

For array-typed config keys (like ` + "`secrets.hmac.retired`" + `), use comma separation or indexed
variables:

` + "```bash" + `
# Comma-separated
export TALOS_SECRETS_HMAC_RETIRED="old-secret-1,old-secret-2"

# Or indexed
export TALOS_SECRETS_HMAC_RETIRED_0="old-secret-1"
export TALOS_SECRETS_HMAC_RETIRED_1="old-secret-2"
` + "```" + `

### Precedence

Configuration sources are applied in this order (highest priority first):

1. Environment variables
2. Configuration file (` + "`--config`" + ` flag)
3. Default values

Environment variables always override file-based configuration.

### Required variables

At minimum, these must be set (via env var or config file):

| Variable                         | Description                                       |
| -------------------------------- | ------------------------------------------------- |
| ` + "`TALOS_SECRETS_HMAC_CURRENT`" + `       | HMAC secret (also derives the pagination cursor key). Minimum 32 characters. |
| ` + "`TALOS_CREDENTIALS_ISSUER`" + `        | Token issuer (` + "`iss`" + ` claim) for derived tokens.                              |`)
}

func printSection(prefix string, s Schema, depth int) {
	heading := strings.Repeat("#", depth)
	badges := sectionBadges(s)

	fmt.Printf("%s `%s`%s\n\n", heading, prefix, badges)

	if s.Description != "" {
		desc, _, _ := strings.Cut(s.Description, ". ")
		fmt.Printf("%s.\n\n", strings.TrimSuffix(desc, "."))
	}

	if s.Type == typeObject && len(s.Properties) > 0 {
		fmt.Println("| Key | Type | Default | Env Var | Description |")
		fmt.Println("|-----|------|---------|---------|-------------|")

		printRows(prefix, s, "", s.LicenseRequired)

		fmt.Println()
	}
}

func printRows(prefix string, s Schema, parentPath string, parentLicenseRequired bool) {
	keys := sortedKeys(s.Properties)
	for _, key := range keys {
		prop := s.Properties[key]
		path := prefix + "." + key
		if parentPath != "" {
			path = parentPath + "." + key
		}

		// Inherit commercial flag from parent section
		if parentLicenseRequired {
			prop.LicenseRequired = true
		}

		if prop.Type == typeObject && len(prop.Properties) > 0 && !isLeafObject(prop) {
			// Recurse into nested objects
			printRows(path, prop, "", prop.LicenseRequired)
			continue
		}

		typStr := formatType(prop)
		defStr := formatDefault(prop.Default)
		envVar := configKeyToEnvVar(path)
		desc := formatDescription(prop)

		fmt.Printf("| `%s` | %s | %s | `%s` | %s |\n", path, typStr, defStr, envVar, desc)
	}
}

func isLeafObject(s Schema) bool {
	// An object with additionalProperties (like a map) or with simple nested properties
	// is treated as a leaf if all children are primitives
	if m, ok := s.AdditionalProperties.(map[string]any); ok && m["type"] != nil {
		return true
	}
	for _, prop := range s.Properties {
		if prop.Type == typeObject && len(prop.Properties) > 0 {
			return false
		}
	}
	return false
}

func formatType(s Schema) string {
	t := s.Type
	if t == "" {
		t = "any"
	}
	if s.Enum != nil {
		vals := make([]string, len(s.Enum))
		for i, v := range s.Enum {
			vals[i] = fmt.Sprintf("`%v`", v)
		}
		return strings.Join(vals, ", ")
	}
	if t == "array" && s.Items != nil {
		return itemType(*s.Items) + "[]"
	}
	return t
}

// itemType names an array's element type. When the element is a oneOf (e.g. a
// bare string or an object form), it reports the most descriptive object variant
// so the reference reads "object[]" rather than an empty "[]".
func itemType(item Schema) string {
	if item.Type != "" {
		return item.Type
	}
	for _, variant := range item.OneOf {
		if variant.Type == typeObject {
			return typeObject
		}
	}
	if len(item.OneOf) > 0 {
		return item.OneOf[0].Type
	}
	return ""
}

func formatDefault(def any) string {
	if def == nil {
		return "—"
	}
	switch v := def.(type) {
	case string:
		if v == "" {
			return `""`
		}
		return "`" + v + "`"
	case bool:
		return fmt.Sprintf("`%v`", v)
	case float64:
		if v == float64(int64(v)) {
			return fmt.Sprintf("`%d`", int64(v))
		}
		return fmt.Sprintf("`%g`", v)
	case []any:
		if len(v) == 0 {
			return "`[]`"
		}
		b, err := json.Marshal(v)
		if err != nil {
			return fmt.Sprintf("`%v`", v)
		}
		return "`" + string(b) + "`"
	default:
		b, err := json.Marshal(v)
		if err != nil {
			return fmt.Sprintf("`%v`", v)
		}
		return "`" + string(b) + "`"
	}
}

func formatDescription(s Schema) string {
	desc := s.Description
	if s.Title != "" && desc == "" {
		desc = s.Title
	}
	// Truncate at first sentence for table readability
	if idx := strings.Index(desc, ". "); idx > 0 && idx < 100 {
		desc = desc[:idx+1]
	}
	// Add annotations
	var annotations []string
	if s.Immutable {
		annotations = append(annotations, "restart required")
	}
	if s.LicenseRequired {
		annotations = append(annotations, "Commercial")
	}
	if s.MinLength != nil && *s.MinLength > 0 {
		annotations = append(annotations, fmt.Sprintf("min %d chars", *s.MinLength))
	}
	if len(annotations) > 0 {
		desc += " (" + strings.Join(annotations, ", ") + ")"
	}
	return desc
}

func sectionBadges(s Schema) string {
	var badges []string
	if s.LicenseRequired {
		badges = append(badges, " Commercial")
	}
	if s.Immutable {
		badges = append(badges, " (restart required)")
	}
	return strings.Join(badges, "")
}

func formatRequired(reqs []string) string {
	if len(reqs) == 0 {
		return "none"
	}
	parts := make([]string, len(reqs))
	for i, r := range reqs {
		parts[i] = "`" + r + "`"
	}
	return strings.Join(parts, ", ")
}

func configKeyToEnvVar(key string) string {
	return "TALOS_" + strings.ToUpper(strings.NewReplacer(".", "_").Replace(key))
}

func sortedKeys(m map[string]Schema) []string {
	return slices.Sorted(maps.Keys(m))
}
