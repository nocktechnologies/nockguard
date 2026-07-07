// Package validate implements NockGuard Phase 2 input validation: regex rules
// applied to the arguments of an MCP tools/call, blocking injection attempts
// and outbound sensitive-data patterns before they reach the upstream tool.
//
// Validation is opt-in per agent (via policy categories / custom patterns), so
// a Phase 1 allowlist-only config is unaffected.
package validate

import (
	"bytes"
	"encoding/json"
	"fmt"
	"regexp"
	"strconv"
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
		{"credit-card", regexp.MustCompile(`(?:^|[^\w-])(?:\d[ -]?){13,16}(?:$|[^\w-])`)},
		{"openai-key", regexp.MustCompile(`\bsk-[A-Za-z0-9]{20,}\b`)},
		{"aws-access-key", regexp.MustCompile(`\bAKIA[0-9A-Z]{16}\b`)},
		{"github-token", regexp.MustCompile(`\bgh[opusr]_[A-Za-z0-9]{36}\b`)},
		{"github-fine-grained-pat", regexp.MustCompile(`\bgithub_pat_[A-Za-z0-9]{22}_[A-Za-z0-9]{59}\b`)},
		{"slack-token", regexp.MustCompile(`(?:^|[^A-Za-z0-9_-])xox[bpars]-[0-9]{12}-[0-9]{12,13}-[A-Za-z0-9]{24}(?:$|[^A-Za-z0-9_-])`)},
		{"stripe-live-key", regexp.MustCompile(`\b[rs]k_live_[A-Za-z0-9]{24}\b`)},
		{"gcp-service-account-key", regexp.MustCompile(`(?is)"type"\s*:\s*"service_account".*"private_key"\s*:\s*"-----BEGIN PRIVATE KEY-----`)},
		{"azure-storage-connection-string", regexp.MustCompile(`(?i)\bDefaultEndpointsProtocol=https;AccountName=[A-Za-z0-9-]{3,24};AccountKey=[A-Za-z0-9+/]{80,}={0,2};EndpointSuffix=core\.windows\.net\b`)},
		{"npm-token", regexp.MustCompile(`\bnpm_[A-Za-z0-9]{36}\b`)},
		{"generic-bearer", regexp.MustCompile(`(?i)\b(api[_-]?key|secret|token|bearer)\b["':=\s]{1,4}[A-Za-z0-9_\-]{16,}`)},
	},
}

// LooksLikeSecret reports whether s contains a value matching any built-in
// CategorySecrets detector (API keys, tokens, SSNs, credit cards, etc.). It
// lets other packages redact secret-shaped strings using the SAME high-signal
// patterns as validation, so "what counts as a secret" stays defined in one
// place. Unlike a Validator it needs no configuration — the secret detectors
// are always-on for callers that must never forward a credential (e.g. the
// human approval prompt, N8613).
func LooksLikeSecret(s string) bool {
	for _, r := range builtin[CategorySecrets] {
		if r.re.MatchString(s) {
			return true
		}
	}
	return false
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
	// Decode with UseNumber so JSON numbers arrive as json.Number (their exact
	// source text) instead of float64 — a 16-digit card number would otherwise
	// lose precision / switch to scientific notation and slip past the secret
	// detectors. See the numeric branch in walk (N8654).
	dec := json.NewDecoder(bytes.NewReader(params))
	dec.UseNumber()
	var decoded any
	if err := dec.Decode(&decoded); err != nil {
		// Unparseable params: scan the raw bytes as a fail-safe.
		return v.scan(string(params))
	}
	return v.walk(decoded)
}

func (v *Validator) walk(node any) string {
	switch n := node.(type) {
	case string:
		return v.scan(n)
	case json.Number:
		// A secret sent as a NUMERIC literal — e.g. {"card": 4111111111111111}
		// — must be caught exactly as its string form is. json.Number.String()
		// preserves the original digits with no float rounding (N8654).
		return v.scan(n.String())
	case float64:
		// Fallback: if a number ever reaches walk as float64 (e.g. a caller
		// that decoded without UseNumber), format it without scientific
		// notation and with full precision so digits aren't lost.
		return v.scan(strconv.FormatFloat(n, 'f', -1, 64))
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
