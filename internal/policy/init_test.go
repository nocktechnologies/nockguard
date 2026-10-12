package policy

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// The scaffold's most important property: it must itself be a valid policy. A
// starter that doesn't load is worse than no starter at all.
func TestStarterPolicyLoadsAndIsDefaultDeny(t *testing.T) {
	path := filepath.Join(t.TempDir(), "policy.yaml")
	written, err := WriteStarter(path, false)
	if err != nil || !written {
		t.Fatalf("WriteStarter: written=%v err=%v", written, err)
	}

	eng, err := Load(path)
	if err != nil {
		t.Fatalf("generated starter policy must Load cleanly: %v", err)
	}

	// allow matches a read-only tool; deny-precedence kills a destructive one;
	// an unknown agent falls back to default (empty allow = deny everything).
	cases := []struct {
		agent, tool string
		want        bool
	}{
		{"coder", "read_file", true},
		{"coder", "read_text_file", true},
		{"coder", "write_file", false},
		{"coder", "unknown_tool", false},
		{"nobody-knows-me", "read_file", false},
	}
	for _, c := range cases {
		if got := eng.Check(c.agent, c.tool); got != c.want {
			t.Errorf("Check(%q,%q)=%v want %v", c.agent, c.tool, got, c.want)
		}
	}

	if eng.config.Audit == nil || !eng.config.Audit.Enabled {
		t.Fatal("starter must enable auditing for the signed quickstart trail")
	}
}

func TestStarterDoesNotClobberWithoutForce(t *testing.T) {
	path := filepath.Join(t.TempDir(), "policy.yaml")
	original := "agents:\n  me:\n    allow: ['*']\n"
	if err := os.WriteFile(path, []byte(original), 0644); err != nil {
		t.Fatal(err)
	}

	// Without --force: refuse, and leave the existing policy untouched.
	if written, err := WriteStarter(path, false); err == nil || written {
		t.Errorf("must refuse to overwrite without force (written=%v err=%v)", written, err)
	}
	if data, _ := os.ReadFile(path); string(data) != original {
		t.Error("existing policy must be left byte-for-byte intact")
	}

	// With --force: overwrite.
	if written, err := WriteStarter(path, true); err != nil || !written {
		t.Fatalf("WriteStarter --force: written=%v err=%v", written, err)
	}
	if data, _ := os.ReadFile(path); strings.Contains(string(data), "me:") {
		t.Error("force should have replaced the old policy")
	}
}

func TestStarterCreatesParentDirs(t *testing.T) {
	path := filepath.Join(t.TempDir(), "nested", "deep", "policy.yaml")
	if written, err := WriteStarter(path, false); err != nil || !written {
		t.Fatalf("WriteStarter into nested dir: written=%v err=%v", written, err)
	}
	if _, err := os.Stat(path); err != nil {
		t.Errorf("expected the file to be created: %v", err)
	}
}
