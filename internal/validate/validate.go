// Package validate implements NockGuard Phase 2 input validation: regex rules
// applied to the arguments of an MCP tools/call, blocking injection attempts
// and outbound sensitive-data patterns before they reach the upstream tool.
//
// Validation is opt-in per agent (via policy categories / custom patterns), so
// a Phase 1 allowlist-only config is unaffected.
package validate

import (
	"encoding/json"
	"fmt"
	"regexp"
)

// Category names for the built-in rule sets.
const (
	CategorySQLi          = "sqli"
	CategoryPathTraversal = "path_traversal"
	CategorySecrets       = "secrets"
)

type rule struct {
	name string
	re   *regexp.Regexp
}

// builtin maps a category to its compiled rules. Patterns are intentionally
// conservative (high-signal) to limit false positives on legitimate calls.
var builtin = map[string][]rule{
	CategorySQLi: {
		{"sql-tautology", regexp.MustCompile(`(?i)('|")?\s*or\s+('|")?\d+('|")?\s*=\s*('|")?\d+`)},
		{"sql-union-select", regexp.MustCompile(`(?i)\bunion\b\s+(all\s+)?\bselect\b`)},
		{"sql-stacked-drop", regexp.MustCompile(`(?i);\s*(drop|delete|truncate|alter)\s+(table|database)\b`)},
		{"sql-comment", regexp.MustCompile(`(?:--|#|/\*)\s*$`)},
	},
	CategoryPathTraversal: {
		{"dotdot-slash", regexp.MustCompile(`\.\.[\\/]`)},
		{"url-encoded-dotdot", regexp.MustCompile(`(?i)%2e%2e[\\/%]`)},
		{"sensitive-unix-path", regexp.MustCompile(`(?i)/(etc/(passwd|shadow)|root/\.ssh|\.aws/credentials)`)},
	},
	CategorySecrets: {
		{"ssn", regexp.MustCompile(`\b\d{3}-\d{2}-\d{4}\b`)},
		{"credit-card", regexp.MustCompile(`\b(?:\d[ -]?){13,16}\b`)},
		{"openai-key", regexp.MustCompile(`\bsk-[A-Za-z0-9]{20,}\b`)},
		{"aws-access-key", regexp.MustCompile(`\bAKIA[0-9A-Z]{16}\b`)},
		{"generic-bearer", regexp.MustCompile(`(?i)\b(api[_-]?key|secret|token|bearer)\b["':=\s]{1,4}[A-Za-z0-9_\-]{16,}`)},
	},
}

// Validator checks tool-call argument text against enabled categories and any
// custom regex patterns from policy.
type Validator struct {
	rules []rule
}

// New builds a Validator for the given built-in categories plus custom regex
// patterns. Unknown categories are ignored; an invalid custom pattern returns
// an error so misconfiguration fails loud at load time.
func New(categories, customPatterns []string) (*Validator, error) {
	v := &Validator{}
	for _, c := range categories {
		v.rules = append(v.rules, builtin[c]...)
	}
	for i, p := range customPatterns {
		re, err := regexp.Compile(p)
		if err != nil {
			return nil, fmt.Errorf("custom validation pattern %d (%q): %w", i, p, err)
		}
		v.rules = append(v.rules, rule{name: fmt.Sprintf("custom-%d", i), re: re})
	}
	return v, nil
}

// Enabled reports whether any rule is active (no rules = validation off).
func (v *Validator) Enabled() bool { return v != nil && len(v.rules) > 0 }

// CheckParams scans the JSON-RPC params of a tools/call. It flattens every
// string value (argument names + values, recursively) and matches each rule.
// Returns the first violating rule name, or "" if clean.
func (v *Validator) CheckParams(params json.RawMessage) string {
	if !v.Enabled() || len(params) == 0 {
		return ""
	}
	var decoded any
	if err := json.Unmarshal(params, &decoded); err != nil {
		// Unparseable params: scan the raw bytes as a fail-safe.
		return v.scan(string(params))
	}
	return v.walk(decoded)
}

func (v *Validator) walk(node any) string {
	switch n := node.(type) {
	case string:
		return v.scan(n)
	case []any:
		for _, item := range n {
			if hit := v.walk(item); hit != "" {
				return hit
			}
		}
	case map[string]any:
		for k, val := range n {
			if hit := v.scan(k); hit != "" {
				return hit
			}
			if hit := v.walk(val); hit != "" {
				return hit
			}
		}
	}
	return ""
}

func (v *Validator) scan(s string) string {
	for _, r := range v.rules {
		if r.re.MatchString(s) {
			return r.name
		}
	}
	return ""
}
