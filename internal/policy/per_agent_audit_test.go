package policy

import (
	"crypto/ed25519"
	"encoding/hex"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/nocktechnologies/nockguard/internal/audit"
)

// TestAgentKeyEnvName verifies the canonical env-var naming convention for
// per-agent Ed25519 keys: hyphen→underscore, uppercase, wrapped in
// NOCKGUARD_AGENT_..._ED25519_KEY / _PUB.
func TestAgentKeyEnvName(t *testing.T) {
	cases := []struct {
		agent   string
		wantKey string
		wantPub string
	}{
		{"kit", "NOCKGUARD_AGENT_KIT_ED25519_KEY", "NOCKGUARD_AGENT_KIT_ED25519_PUB"},
		{"mira-nockos", "NOCKGUARD_AGENT_MIRA_NOCKOS_ED25519_KEY", "NOCKGUARD_AGENT_MIRA_NOCKOS_ED25519_PUB"},
		{"mar-nockos", "NOCKGUARD_AGENT_MAR_NOCKOS_ED25519_KEY", "NOCKGUARD_AGENT_MAR_NOCKOS_ED25519_PUB"},
		{"UPPER", "NOCKGUARD_AGENT_UPPER_ED25519_KEY", "NOCKGUARD_AGENT_UPPER_ED25519_PUB"},
	}
	for _, tc := range cases {
		if got := AgentKeyEnvName(tc.agent); got != tc.wantKey {
			t.Errorf("AgentKeyEnvName(%q) = %q, want %q", tc.agent, got, tc.wantKey)
		}
		if got := AgentPubKeyEnvName(tc.agent); got != tc.wantPub {
			t.Errorf("AgentPubKeyEnvName(%q) = %q, want %q", tc.agent, got, tc.wantPub)
		}
	}
}

// TestAgentAuditPath verifies that the per-agent audit file is derived from the
// base audit path by inserting the agent name as a path-segment prefix:
// ~/.nockguard/logs/audit.jsonl → ~/.nockguard/logs/mira-nockos.audit.jsonl
func TestAgentAuditPath(t *testing.T) {
	cases := []struct {
		base  string
		agent string
		want  string
	}{
		{"/home/user/.nockguard/logs/audit.jsonl", "kit", "/home/user/.nockguard/logs/kit.audit.jsonl"},
		{"/home/user/.nockguard/logs/audit.jsonl", "mira-nockos", "/home/user/.nockguard/logs/mira-nockos.audit.jsonl"},
		{"/tmp/test.jsonl", "wren", "/tmp/wren.test.jsonl"},
	}
	for _, tc := range cases {
		if got := AgentAuditPath(tc.base, tc.agent); got != tc.want {
			t.Errorf("AgentAuditPath(%q, %q) = %q, want %q", tc.base, tc.agent, got, tc.want)
		}
	}
}

// TestAuditorForFallsBackToGlobal verifies that AuditorFor returns the same
// (global policy) auditor when no per-agent key env var is set.
func TestAuditorForFallsBackToGlobal(t *testing.T) {
	auditPath := filepath.Join(t.TempDir(), "audit.jsonl")
	path := writePolicy(t, `
audit:
  enabled: true
  path: `+auditPath+`
agents:
  kit:
    allow: ["*"]
`)
	eng, err := Load(path)
	if err != nil {
		t.Fatal(err)
	}
	// No per-agent env set — AuditorFor should behave like Auditor.
	a, err := eng.AuditorFor("kit")
	if err != nil {
		t.Fatalf("AuditorFor: %v", err)
	}
	defer a.Close()
	if !a.Enabled() {
		t.Error("expected auditor to be enabled (fallback to global)")
	}
}

// TestAuditorForUsesAgentKey verifies that AuditorFor returns an auditor
// configured with the agent-specific Ed25519 key when the env var is set, and
// that the resulting trail verifies under the corresponding public key.
func TestAuditorForUsesAgentKey(t *testing.T) {
	pub, priv, _ := ed25519.GenerateKey(nil)
	envName := AgentKeyEnvName("kit")
	t.Setenv(envName, hex.EncodeToString(priv.Seed()))

	auditPath := filepath.Join(t.TempDir(), "audit.jsonl")
	path := writePolicy(t, `
audit:
  enabled: true
  path: `+auditPath+`
agents:
  kit:
    allow: ["*"]
`)
	eng, err := Load(path)
	if err != nil {
		t.Fatal(err)
	}
	a, err := eng.AuditorFor("kit")
	if err != nil {
		t.Fatalf("AuditorFor: %v", err)
	}
	if err := a.Record(audit.Event{Agent: "kit", Tool: "Read", Decision: "allow"}); err != nil {
		t.Fatal(err)
	}
	a.Close()

	// Trail should be written to the agent-specific path, not the base path.
	agentPath := AgentAuditPath(auditPath, "kit")
	if _, err := os.Stat(agentPath); err != nil {
		t.Fatalf("expected agent audit file at %s: %v", agentPath, err)
	}
	if _, err := os.Stat(auditPath); err == nil {
		t.Error("base audit path should NOT be written when per-agent key is active")
	}

	// The agent trail must verify with the agent's public key.
	n, err := audit.VerifyEd25519(agentPath, pub)
	if err != nil {
		t.Fatalf("VerifyEd25519: %v", err)
	}
	if n != 1 {
		t.Errorf("expected 1 entry, got %d", n)
	}
}

// TestAuditorForBadKeyFails verifies that a malformed per-agent key env var
// causes AuditorFor to return an error.
func TestAuditorForBadKeyFails(t *testing.T) {
	t.Setenv(AgentKeyEnvName("kit"), "not-valid-hex")
	auditPath := filepath.Join(t.TempDir(), "audit.jsonl")
	path := writePolicy(t, `
audit:
  enabled: true
  path: `+auditPath+`
agents:
  kit:
    allow: ["*"]
`)
	eng, err := Load(path)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := eng.AuditorFor("kit"); err == nil {
		t.Error("expected error for malformed per-agent key, got nil")
	}
}

// TestSigningKeyEnvNamesForIncludesAgentKey verifies that SigningKeyEnvNamesFor
// returns both the global configured signing key name(s) AND the per-agent key
// env var name when the per-agent env var is set, so the proxy can strip both
// from the child process environment.
func TestSigningKeyEnvNamesForIncludesAgentKey(t *testing.T) {
	_, priv, _ := ed25519.GenerateKey(nil)
	t.Setenv(AgentKeyEnvName("kit"), hex.EncodeToString(priv.Seed()))

	path := writePolicy(t, `
audit:
  enabled: true
  sign_ed25519_key_env: GLOBAL_SEED_VAR
agents:
  kit:
    allow: ["*"]
`)
	eng, err := Load(path)
	if err != nil {
		t.Fatal(err)
	}
	names := eng.SigningKeyEnvNamesFor("kit")

	if !contains(names, "GLOBAL_SEED_VAR") {
		t.Errorf("expected global key name GLOBAL_SEED_VAR in %v", names)
	}
	if !contains(names, AgentKeyEnvName("kit")) {
		t.Errorf("expected agent key name %s in %v", AgentKeyEnvName("kit"), names)
	}
}

// TestSigningKeyEnvNamesForNoAgentKeyUnchanged verifies that
// SigningKeyEnvNamesFor returns the same set as SigningKeyEnvNames when no
// per-agent key env var is set.
func TestSigningKeyEnvNamesForNoAgentKeyUnchanged(t *testing.T) {
	path := writePolicy(t, `
audit:
  enabled: true
  sign_ed25519_key_env: GLOBAL_SEED_VAR
agents:
  kit:
    allow: ["*"]
`)
	eng, err := Load(path)
	if err != nil {
		t.Fatal(err)
	}
	base := eng.SigningKeyEnvNames()
	extended := eng.SigningKeyEnvNamesFor("kit") // no agent key set in env

	if len(base) != len(extended) {
		t.Errorf("without agent key set, SigningKeyEnvNamesFor should equal SigningKeyEnvNames: base=%v extended=%v", base, extended)
	}
	for i := range base {
		if base[i] != extended[i] {
			t.Errorf("mismatch at %d: base=%q extended=%q", i, base[i], extended[i])
		}
	}
}

func contains(ss []string, s string) bool {
	for _, v := range ss {
		if v == s {
			return true
		}
	}
	return false
}

// TestAgentKeyEnvNameNormalization verifies dots are also converted to underscores.
func TestAgentKeyEnvNameNormalization(t *testing.T) {
	got := AgentKeyEnvName("my.agent-name")
	if strings.Contains(got, ".") || strings.Contains(got, "-") {
		t.Errorf("env name contains illegal characters: %q", got)
	}
	if strings.ToUpper(got) != got {
		t.Errorf("env name is not uppercase: %q", got)
	}
}

// TestValidAgentName verifies the name allowlist: alphanumerics, hyphens, dots
// accepted; slashes, dots-only traversal, empty, and control characters rejected.
func TestValidAgentName(t *testing.T) {
	valid := []string{"kit", "mira-nockos", "mar-nockos", "my.agent", "Agent1"}
	for _, name := range valid {
		if !ValidAgentName(name) {
			t.Errorf("ValidAgentName(%q) = false, want true", name)
		}
	}
	invalid := []string{"", "../etc", "../../foo", "kit/bar", "a b", "kit\x00", "foo\\bar"}
	for _, name := range invalid {
		if ValidAgentName(name) {
			t.Errorf("ValidAgentName(%q) = true, want false", name)
		}
	}
}

// TestAuditorForInvalidAgentName verifies AuditorFor rejects a path-traversal agent name.
func TestAuditorForInvalidAgentName(t *testing.T) {
	auditPath := filepath.Join(t.TempDir(), "audit.jsonl")
	path := writePolicy(t, `
audit:
  enabled: true
  path: `+auditPath+`
agents:
  kit:
    allow: ["*"]
`)
	eng, err := Load(path)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := eng.AuditorFor("../../../etc/passwd"); err == nil {
		t.Error("AuditorFor with path-traversal agent name should return error")
	}
}
