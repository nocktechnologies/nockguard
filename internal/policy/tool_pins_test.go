package policy

import (
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
	for _, bad := range []string{
		strings.Replace(valid, "  sign_key_env: TEST_PIN_KEY\n", "", 1),
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
