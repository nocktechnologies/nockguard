package validate

import (
	"encoding/json"
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
