package validate

import (
	"encoding/json"
	"strings"
	"testing"
)

func mustNew(t *testing.T, cats, custom []string) *Validator {
	t.Helper()
	v, err := New(cats, custom)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	return v
}

func params(t *testing.T, v any) json.RawMessage {
	t.Helper()
	b, err := json.Marshal(v)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	return b
}

func TestDisabledWhenNoRules(t *testing.T) {
	v := mustNew(t, nil, nil)
	if v.Enabled() {
		t.Fatal("expected validator with no rules to be disabled")
	}
	var nilV *Validator
	if nilV.Enabled() {
		t.Fatal("nil validator must report disabled")
	}
}

func TestSQLi(t *testing.T) {
	v := mustNew(t, []string{CategorySQLi}, nil)
	bad := []string{
		"' OR '1'='1",
		"1 UNION SELECT password FROM users",
		"x'; DROP TABLE accounts;",
	}
	for _, s := range bad {
		p := params(t, map[string]any{"name": "query", "arguments": map[string]any{"q": s}})
		if hit := v.CheckParams(p); hit == "" {
			t.Errorf("expected SQLi block for %q", s)
		}
	}
	clean := params(t, map[string]any{"name": "query", "arguments": map[string]any{"q": "select the blue option"}})
	if hit := v.CheckParams(clean); hit != "" {
		t.Errorf("clean query flagged as %q", hit)
	}
}

func TestPathTraversal(t *testing.T) {
	v := mustNew(t, []string{CategoryPathTraversal}, nil)
	bad := []string{"../../etc/passwd", "..\\..\\secret", "/etc/shadow", "%2e%2e/"}
	for _, s := range bad {
		p := params(t, map[string]any{"arguments": map[string]any{"path": s}})
		if hit := v.CheckParams(p); hit == "" {
			t.Errorf("expected path-traversal block for %q", s)
		}
	}
	clean := params(t, map[string]any{"arguments": map[string]any{"path": "reports/2026/may.csv"}})
	if hit := v.CheckParams(clean); hit != "" {
		t.Errorf("clean path flagged as %q", hit)
	}
}

func TestSecrets(t *testing.T) {
	v := mustNew(t, []string{CategorySecrets}, nil)
	bad := []string{
		"my ssn is 123-45-6789",
		"sk-abcdefghijklmnopqrstuvwx",
		"AKIAIOSFODNN7EXAMPLE",
	}
	for _, s := range bad {
		p := params(t, map[string]any{"arguments": map[string]any{"body": s}})
		if hit := v.CheckParams(p); hit == "" {
			t.Errorf("expected secret block for %q", s)
		}
	}
}

func TestGitHubSecrets(t *testing.T) {
	v := mustNew(t, []string{CategorySecrets}, nil)
	cases := []struct {
		name  string
		token string
	}{
		{"classic-pat", "ghp_0123456789abcdefABCDEF0123456789abcd"},
		{"oauth-token", "gho_0123456789abcdefABCDEF0123456789abcd"},
		{"user-to-server-token", "ghu_0123456789abcdefABCDEF0123456789abcd"},
		{"server-to-server-token", "ghs_0123456789abcdefABCDEF0123456789abcd"},
		{"refresh-token", "ghr_0123456789abcdefABCDEF0123456789abcd"},
		{"fine-grained-pat", "github_pat_0123456789abcdefABCDEF_0123456789abcdefABCDEF0123456789abcdefABCDEF0123456789abcde"},
	}
	for _, tc := range cases {
		t.Run(tc.name+"/value", func(t *testing.T) {
			p := params(t, map[string]any{"arguments": map[string]any{"body": tc.token}})
			if hit := v.CheckParams(p); hit == "" {
				t.Fatalf("expected GitHub secret block for value %q", tc.token)
			}
		})
		t.Run(tc.name+"/key", func(t *testing.T) {
			p := params(t, map[string]any{"arguments": map[string]any{tc.token: "value"}})
			if hit := v.CheckParams(p); hit == "" {
				t.Fatalf("expected GitHub secret block for key %q", tc.token)
			}
		})
		for _, s := range []string{"x" + tc.token, tc.token + "A"} {
			t.Run(tc.name+"/embedded/"+s, func(t *testing.T) {
				p := params(t, map[string]any{"arguments": map[string]any{"body": s}})
				if hit := v.CheckParams(p); hit != "" {
					t.Fatalf("embedded token-shaped string flagged as %q", hit)
				}
			})
		}
	}

	clean := []string{
		"prose mentioning ghp_ without a token body",
		"ghp_0123456789abcdefABCDEF0123456789abc",
		"gho_0123456789abcdefABCDEF0123456789abc!",
		"ghu_0123456789abcdefABCDEF0123456789abc_",
		"ghs_0123456789abcdefABCDEF0123456789abc/",
		"ghr_0123456789abcdefABCDEF0123456789abc-",
		"github_pat_0123456789abcdefABCDE_0123456789abcdefABCDEF0123456789abcdefABCDEF0123456789abcde",
		"github_pat_0123456789abcdefABCDEF_0123456789abcdefABCDEF0123456789abcdefABCDEF0123456789abcd!",
		"nothing secret here",
	}
	for _, s := range clean {
		t.Run("clean/"+s, func(t *testing.T) {
			p := params(t, map[string]any{"arguments": map[string]any{"body": s}})
			if hit := v.CheckParams(p); hit != "" {
				t.Fatalf("clean string flagged as %q", hit)
			}
		})
	}
}

func TestVendorSecrets(t *testing.T) {
	v := mustNew(t, []string{CategorySecrets}, nil)
	slack := func(prefix string) string {
		return prefix + "-123456789012-" + "1234567890123-" + "AbCdEfGhIjKlMnOpQrStUvWx"
	}
	stripe := func(prefix string) string {
		return prefix + "_live_" + "0123456789abcdefABCDEF01"
	}
	npm := func(body string) string {
		return "npm" + "_" + body
	}
	gcpServiceAccount := `"type":"service_account","private_key":"-----BEGIN ` + `PRIVATE KEY-----\nabc\n-----END PRIVATE KEY-----\n"`
	azureConnectionString := "DefaultEndpointsProtocol=https;" +
		"AccountName=acct01;" +
		"AccountKey=" + "YWJjZGVmZ2hpamtsbW5vcHFyc3R1dnd4eXowMTIzNDU2Nzg5" + "QUJDREVGR0hJSktMTU5PUFFSU1RVVldYWVo=;" +
		"EndpointSuffix=core.windows.net"
	cases := []struct {
		name  string
		token string
	}{
		{"slack-bot-token", slack("xox" + "b")},
		{"slack-app-token", slack("xox" + "a")},
		{"slack-refresh-token", slack("xox" + "r")},
		{"slack-user-token", slack("xox" + "p")},
		{"slack-workspace-token", slack("xox" + "s")},
		{"stripe-secret-key", stripe("s" + "k")},
		{"stripe-restricted-key", stripe("r" + "k")},
		{"gcp-service-account-json", gcpServiceAccount},
		{"azure-storage-connection-string", azureConnectionString},
		{"npm-token", npm("0123456789abcdefABCDEF0123456789abcd")},
	}
	for _, tc := range cases {
		t.Run(tc.name+"/value", func(t *testing.T) {
			p := params(t, map[string]any{"arguments": map[string]any{"body": tc.token}})
			if hit := v.CheckParams(p); hit == "" {
				t.Fatalf("expected vendor secret block for value %q", tc.token)
			}
		})
		t.Run(tc.name+"/key", func(t *testing.T) {
			p := params(t, map[string]any{"arguments": map[string]any{tc.token: "value"}})
			if hit := v.CheckParams(p); hit == "" {
				t.Fatalf("expected vendor secret block for key %q", tc.token)
			}
		})
	}

	clean := []string{
		"slack docs mention " + "xox" + "b- without a token body",
		"x" + slack("xox"+"b"),
		slack("xox"+"b") + "y",
		"s" + "k_test_" + "0123456789abcdefABCDEF01",
		"s" + "k_live_" + "0123456789abcdefABCDEF0",
		"s" + "k_live_" + "0123456789abcdefABCDEF012",
		"r" + "k_test_" + "0123456789abcdefABCDEF01",
		"r" + "k_live_" + "0123456789abcdefABCDEF0",
		"r" + "k_live_" + "0123456789abcdefABCDEF012",
		`"type":"service_account"`,
		`"private_key":"-----BEGIN ` + `PRIVATE KEY-----"`,
		"DefaultEndpointsProtocol=https;AccountName=acct01;EndpointSuffix=core.windows.net",
		"DefaultEndpointsProtocol=https;AccountName=acct01;Account" + "Key=not-base64;EndpointSuffix=core.windows.net",
		npm("0123456789abcdefABCDEF0123456789abc"),
		npm("0123456789abcdefABCDEF0123456789abcde"),
		"x" + npm("0123456789abcdefABCDEF0123456789abcd"),
	}
	for _, s := range clean {
		t.Run("clean/"+s, func(t *testing.T) {
			p := params(t, map[string]any{"arguments": map[string]any{"body": s}})
			if hit := v.CheckParams(p); hit != "" {
				t.Fatalf("clean vendor string flagged as %q", hit)
			}
		})
	}
}

func TestCustomPattern(t *testing.T) {
	v := mustNew(t, nil, []string{`(?i)rm\s+-rf\s+/`})
	p := params(t, map[string]any{"arguments": map[string]any{"cmd": "rm -rf /"}})
	if hit := v.CheckParams(p); hit != "custom-0" {
		t.Errorf("expected custom-0, got %q", hit)
	}
}

func TestInvalidCustomPatternErrors(t *testing.T) {
	if _, err := New(nil, []string{"("}); err == nil {
		t.Fatal("expected error for invalid custom regex")
	}
}

func TestNestedAndArrayParams(t *testing.T) {
	v := mustNew(t, []string{CategoryPathTraversal}, nil)
	p := params(t, map[string]any{
		"arguments": map[string]any{
			"files": []any{"ok.txt", map[string]any{"src": "../../etc/passwd"}},
		},
	})
	if hit := v.CheckParams(p); hit == "" {
		t.Error("expected block on nested/array param")
	}
}

func TestEmptyParamsClean(t *testing.T) {
	v := mustNew(t, []string{CategorySQLi}, nil)
	if hit := v.CheckParams(nil); hit != "" {
		t.Errorf("nil params should be clean, got %q", hit)
	}
}

// TestNumericSecretParams guards N8654: a secret sent as a NUMERIC literal (e.g.
// a 16-digit card number under a neutral key) must be caught exactly as its
// string form is, while a harmless number still passes. The raw JSON literals
// exercise the json.Number path — the digits must survive with no float
// rounding / scientific-notation loss.
func TestNumericSecretParams(t *testing.T) {
	v := mustNew(t, []string{CategorySecrets}, nil)

	// Card number as a bare JSON integer under a neutral key — no quotes.
	badLiterals := []json.RawMessage{
		json.RawMessage(`{"arguments":{"card":4111111111111111}}`),
		json.RawMessage(`{"arguments":{"id":4111111111111111}}`),
	}
	for _, p := range badLiterals {
		if hit := v.CheckParams(p); hit == "" {
			t.Errorf("expected numeric secret block for %s", p)
		}
	}

	// A test SSN sent as a numeric-looking value still gets caught in string
	// form; a harmless number must pass clean.
	harmless := []json.RawMessage{
		json.RawMessage(`{"arguments":{"quantity":42}}`),
		json.RawMessage(`{"arguments":{"total":1234.56}}`),
		json.RawMessage(`{"arguments":{"year":2026}}`),
	}
	for _, p := range harmless {
		if hit := v.CheckParams(p); hit != "" {
			t.Errorf("harmless number %s flagged as %q", p, hit)
		}
	}
}

// N8695 regression — an unknown validate_input category (a typo like "secret"
// for "secrets", or "sql" for "sqli") was silently ignored, so New returned a
// validator with zero built-in rules and Phase 2 filtering was OFF while the
// operator believed it on. New must now fail LOUD.
func TestUnknownCategoryRejected(t *testing.T) {
	for _, bad := range []string{"secret", "sql", "path-traversal", "SQLi", ""} {
		v, err := New([]string{bad}, nil)
		if err == nil {
			t.Errorf("New(%q) must reject an unknown category, got nil error (validator would silently have no rules)", bad)
		}
		if v != nil {
			t.Errorf("New(%q) must return a nil validator on error, got %+v", bad, v)
		}
	}
	// The error should name the offending category and list the valid set so the
	// operator can fix the typo.
	_, err := New([]string{"secret"}, nil)
	if err == nil {
		t.Fatal("expected error for unknown category")
	}
	for _, want := range []string{"secret", CategorySQLi, CategoryPathTraversal, CategorySecrets} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("error %q should mention %q", err.Error(), want)
		}
	}
}

// The supported categories must still build a working validator, and mixing a
// known category with custom patterns must be unaffected by the new guard.
func TestKnownCategoriesStillBuild(t *testing.T) {
	v, err := New([]string{CategorySQLi, CategoryPathTraversal, CategorySecrets}, []string{`foo\d+`})
	if err != nil {
		t.Fatalf("New with all known categories must succeed: %v", err)
	}
	if !v.Enabled() {
		t.Fatal("validator built from known categories must be enabled")
	}
}

// KnownCategory / Categories are the shared source of truth used by policy.Load
// to reject typos; guard their contract.
func TestKnownCategoryAndCategories(t *testing.T) {
	for _, c := range []string{CategorySQLi, CategoryPathTraversal, CategorySecrets} {
		if !KnownCategory(c) {
			t.Errorf("KnownCategory(%q) must be true", c)
		}
	}
	for _, c := range []string{"secret", "sql", ""} {
		if KnownCategory(c) {
			t.Errorf("KnownCategory(%q) must be false", c)
		}
	}
	if got := len(Categories()); got != 3 {
		t.Errorf("Categories() must return the 3 built-in categories, got %d: %v", got, Categories())
	}
}
