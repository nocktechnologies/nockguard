package pool

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func writeConfig(t *testing.T, body string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "pool.yaml")
	if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}

const validConfig = `
pool:
  listen: "127.0.0.1:4141"
  upstreams:
    - label: sub-1
      codex_home: ~/.codex
    - label: sub-2
      codex_home: ~/.codex-sub2
  routing:
    strategy: headroom
    cooldown_seconds: 60
`

func TestLoadValidConfig(t *testing.T) {
	cfg, err := Load(writeConfig(t, validConfig))
	if err != nil {
		t.Fatalf("valid config rejected: %v", err)
	}
	cfg.Normalize()
	if got := len(cfg.Pool.Upstreams); got != 2 {
		t.Fatalf("upstreams = %d, want 2", got)
	}
	if cfg.Pool.Upstreams[0].Provider != "codex" {
		t.Errorf("provider default = %q, want codex", cfg.Pool.Upstreams[0].Provider)
	}
	if cfg.Pool.Routing.Cooldown() != 60*time.Second {
		t.Errorf("cooldown = %v, want 60s", cfg.Pool.Routing.Cooldown())
	}
}

func TestCooldownDefaultsTo60s(t *testing.T) {
	r := RoutingConfig{}
	if r.Cooldown() != 60*time.Second {
		t.Errorf("zero-value cooldown = %v, want documented default 60s", r.Cooldown())
	}
}

func TestNonLoopbackListenRefusedByDefault(t *testing.T) {
	body := strings.Replace(validConfig, "127.0.0.1:4141", "0.0.0.0:4141", 1)
	_, err := Load(writeConfig(t, body))
	if err == nil || !strings.Contains(err.Error(), "not loopback") {
		t.Fatalf("non-loopback bind must fail loud, got: %v", err)
	}
}

func TestNonLoopbackAllowedWhenExplicit(t *testing.T) {
	body := strings.Replace(validConfig, "listen: \"127.0.0.1:4141\"",
		"listen: \"0.0.0.0:4141\"\n  allow_non_local: true", 1)
	if _, err := Load(writeConfig(t, body)); err != nil {
		t.Fatalf("explicit allow_non_local must pass: %v", err)
	}
}

func TestDuplicateLabelRejected(t *testing.T) {
	body := strings.Replace(validConfig, "label: sub-2", "label: sub-1", 1)
	_, err := Load(writeConfig(t, body))
	if err == nil || !strings.Contains(err.Error(), "duplicate label") {
		t.Fatalf("duplicate label must fail loud, got: %v", err)
	}
}

func TestDuplicateCodexHomeRejected(t *testing.T) {
	body := strings.Replace(validConfig, "codex_home: ~/.codex-sub2", "codex_home: ~/.codex", 1)
	_, err := Load(writeConfig(t, body))
	if err == nil || !strings.Contains(err.Error(), "duplicate codex_home") {
		t.Fatalf("duplicate codex_home must fail loud, got: %v", err)
	}
}

func TestClaudeProviderReservedInV1(t *testing.T) {
	body := strings.Replace(validConfig, "label: sub-2", "label: sub-2\n      provider: claude", 1)
	_, err := Load(writeConfig(t, body))
	if err == nil || !strings.Contains(err.Error(), "reserved for V1.5") {
		t.Fatalf("claude provider must be rejected with the V1.5 pointer, got: %v", err)
	}
}

func TestUnknownProviderRejected(t *testing.T) {
	body := strings.Replace(validConfig, "label: sub-2", "label: sub-2\n      provider: gemini", 1)
	_, err := Load(writeConfig(t, body))
	if err == nil || !strings.Contains(err.Error(), "unknown provider") {
		t.Fatalf("unknown provider must fail loud, got: %v", err)
	}
}

func TestUnknownStrategyRejected(t *testing.T) {
	body := strings.Replace(validConfig, "strategy: headroom", "strategy: roulette", 1)
	_, err := Load(writeConfig(t, body))
	if err == nil || !strings.Contains(err.Error(), "not supported in V1") {
		t.Fatalf("unknown strategy must fail loud, got: %v", err)
	}
}

func TestUnknownFieldsRejected(t *testing.T) {
	body := validConfig + "  surprise_field: true\n"
	_, err := Load(writeConfig(t, body))
	if err == nil {
		t.Fatal("unknown top-level field must fail loud (no silent config drift)")
	}
}

func TestMissingUpstreamsRejected(t *testing.T) {
	body := `
pool:
  listen: "127.0.0.1:4141"
  upstreams: []
`
	_, err := Load(writeConfig(t, body))
	if err == nil || !strings.Contains(err.Error(), "at least one upstream") {
		t.Fatalf("empty upstreams must fail loud, got: %v", err)
	}
}

func TestAuthJSONPathExpandsTilde(t *testing.T) {
	u := UpstreamConfig{Label: "sub-1", CodexHome: "~/.codex"}
	p, err := u.AuthJSONPath()
	if err != nil {
		t.Fatal(err)
	}
	home, _ := os.UserHomeDir()
	want := filepath.Join(home, ".codex", "auth.json")
	if p != want {
		t.Errorf("AuthJSONPath = %q, want %q", p, want)
	}
}
