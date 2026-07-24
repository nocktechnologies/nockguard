package policy

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/nocktechnologies/nockguard/internal/audit"
)

// TestExpandTilde covers the leading-~ expansion used for portable audit paths.
func TestExpandTilde(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)

	cases := []struct {
		in   string
		want string
	}{
		{"~", home},
		{"~/.nockguard/logs/x.jsonl", filepath.Join(home, ".nockguard/logs/x.jsonl")},
		{"/abs/path/audit.jsonl", "/abs/path/audit.jsonl"},     // absolute untouched
		{"relative/audit.jsonl", "relative/audit.jsonl"},       // relative untouched
		{"~notation/without/slash", "~notation/without/slash"}, // only ~ and ~/ expand
		{"", ""},
	}
	for _, c := range cases {
		got, err := expandTilde(c.in)
		if err != nil {
			t.Fatalf("expandTilde(%q): %v", c.in, err)
		}
		if got != c.want {
			t.Errorf("expandTilde(%q) = %q, want %q", c.in, got, c.want)
		}
	}
}

// TestAuditorTildePathPortable proves a committed policy with a ~-prefixed audit
// path resolves under the current machine's home — the fix for the hardcoded
// /Users/kevin path that made livedemo/policy.yaml non-portable off the author's
// Mac (broke the flagship VPS dogfood dry-run).
func TestAuditorTildePathPortable(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)

	path := writePolicy(t, `
audit:
  enabled: true
  path: ~/.nockguard/logs/live-demo.jsonl
agents:
  kit:
    allow: ["*"]
`)
	eng, err := Load(path)
	if err != nil {
		t.Fatal(err)
	}
	a, err := eng.Auditor()
	if err != nil {
		t.Fatalf("Auditor: %v", err)
	}
	if err := a.Record(audit.Event{Agent: "kit", Tool: "Read", Decision: "allow"}); err != nil {
		t.Fatal(err)
	}
	a.Close()

	want := filepath.Join(home, ".nockguard/logs/live-demo.jsonl")
	if _, err := os.Stat(want); err != nil {
		t.Fatalf("expected audit file at expanded home path %s: %v", want, err)
	}
}
