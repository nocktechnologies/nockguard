package policy

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/hex"
	"strings"
	"testing"
)

func TestToolPinsRequireValidSignedStaticPolicy(t *testing.T) {
	valid := `audit:
  enabled: true
  action_pairing: true
  sign_key_env: TEST_PIN_KEY
agents:
  demo:
    mode: allow
    tool_pins:
      local-fs:
        read:
          hash_version: jcs-rfc8785-v1
          sha256: ` + strings.Repeat("a", 64) + "\n"
	engine, err := LoadBytes([]byte(valid))
	if err != nil {
		t.Fatal(err)
	}
	if pin, ok := engine.ToolPin("demo", "local-fs", "read"); !ok || pin.SHA256 != strings.Repeat("a", 64) {
		t.Fatalf("pin lookup: %+v %t", pin, ok)
	}
	if _, ok := engine.ToolPin("demo", "other-fs", "read"); ok {
		t.Fatal("pin crossed upstream scope")
	}
	if err := engine.ValidateToolPinScope("demo", "other-fs"); err == nil {
		t.Fatal("unconfigured upstream scope accepted")
	}
	if err := engine.ValidateToolPinScope("demo", "local-fs"); err != nil {
		t.Fatal(err)
	}
	// Signing may come from the existing per-agent environment or protected key
	// file; the runtime auditor must verify that a key was actually resolved.
	perAgent := strings.Replace(valid, "  sign_key_env: TEST_PIN_KEY\n", "  path: "+t.TempDir()+"/audit.jsonl\n", 1)
	perAgentEngine, err := LoadBytes([]byte(perAgent))
	if err != nil {
		t.Fatalf("per-agent signing policy rejected at load: %v", err)
	}
	_, key, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	t.Setenv(AgentKeyEnvName("demo"), hex.EncodeToString(key.Seed()))
	perAgentAuditor, err := perAgentEngine.AuditorFor("demo")
	if err != nil {
		t.Fatal(err)
	}
	defer perAgentAuditor.Close()
	if !perAgentAuditor.SigningEnabled() {
		t.Fatal("per-agent seed did not produce a signed auditor")
	}
	for _, bad := range []string{
		strings.Replace(valid, "  action_pairing: true\n", "", 1),
		strings.Replace(valid, strings.Repeat("a", 64), strings.Repeat("A", 64), 1),
		strings.Replace(valid, "jcs-rfc8785-v1", "other", 1),
		strings.Replace(valid, "local-fs:", `"":`, 1),
	} {
		if _, err := LoadBytes([]byte(bad)); err == nil {
			t.Fatalf("invalid pin policy accepted: %s", bad)
		}
	}
}

func TestToolPinUpstreamKeysUseUpstreamIDRule(t *testing.T) {
	pinPolicy := func(upstream string) string {
		return `audit:
  enabled: true
  action_pairing: true
  sign_key_env: TEST_PIN_KEY
agents:
  demo:
    mode: allow
    tool_pins:
      "` + upstream + `":
        read:
          hash_version: jcs-rfc8785-v1
          sha256: ` + strings.Repeat("a", 64) + "\n"
	}
	for _, bad := range []string{"local fs", "local\\tfs", "local\\nfs", strings.Repeat("u", 129)} {
		if _, err := LoadBytes([]byte(pinPolicy(bad))); err == nil {
			t.Errorf("tool_pins upstream key %q accepted; --upstream-id rejects it", bad)
		}
	}
	upstream := strings.Repeat("u", 128)
	engine, err := LoadBytes([]byte(pinPolicy(upstream)))
	if err != nil {
		t.Fatal(err)
	}
	if err := engine.ValidateToolPinScope("demo", upstream); err != nil {
		t.Fatalf("valid upstream ID rejected: %v", err)
	}
}
