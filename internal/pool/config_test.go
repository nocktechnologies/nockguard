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

const validBudgetConfig = `
pool:
  listen: "127.0.0.1:4141"
  upstreams:
    - label: cheap-1
      codex_home: ~/.codex-cheap
      tier: cheap
      cost_per_call_usd: 0.01
    - label: opus-1
      codex_home: ~/.codex-opus
      tier: expensive
      cost_per_call_usd: 0.10
    - label: legacy-untiered
      codex_home: ~/.codex-legacy
      cost_per_call_usd: 0.25
  routing:
    strategy: headroom
    cooldown_seconds: 60
  budget:
    max_cost_usd: 1.00
    ask_thresholds_usd: [0.50, 0.75]
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

func TestLoadValidBudgetConfig(t *testing.T) {
	cfg, err := Load(writeConfig(t, validBudgetConfig))
	if err != nil {
		t.Fatalf("valid budget config rejected: %v", err)
	}
	cfg.Normalize()
	if !cfg.Pool.Budget.Enabled() {
		t.Fatal("budget with max_cost_usd should be enabled")
	}
	if cfg.Pool.Upstreams[0].Tier != TierCheap {
		t.Errorf("tier = %q, want cheap", cfg.Pool.Upstreams[0].Tier)
	}
	if cfg.Pool.Upstreams[2].EffectiveTier() != TierExpensive {
		t.Errorf("untiered upstream effective tier = %q, want expensive", cfg.Pool.Upstreams[2].EffectiveTier())
	}
	if got := cfg.Pool.Upstreams[1].CostPerCallUSD; got != 0.10 {
		t.Errorf("cost_per_call_usd = %v, want 0.10", got)
	}
}

func TestBudgetAbsentIsDisabled(t *testing.T) {
	cfg, err := Load(writeConfig(t, validConfig))
	if err != nil {
		t.Fatal(err)
	}
	if cfg.Pool.Budget.Enabled() {
		t.Fatal("absent/zero budget must be disabled")
	}
}

func TestUnknownTierRejected(t *testing.T) {
	body := strings.Replace(validBudgetConfig, "tier: expensive", "tier: premium", 1)
	_, err := Load(writeConfig(t, body))
	if err == nil || !strings.Contains(err.Error(), "unknown tier") {
		t.Fatalf("unknown tier must fail loud, got: %v", err)
	}
}

func TestNegativeBudgetCostRejected(t *testing.T) {
	body := strings.Replace(validBudgetConfig, "cost_per_call_usd: 0.10", "cost_per_call_usd: -0.01", 1)
	_, err := Load(writeConfig(t, body))
	if err == nil || !strings.Contains(err.Error(), "cost_per_call_usd must be >= 0") {
		t.Fatalf("negative upstream cost must fail loud, got: %v", err)
	}
}

func TestNegativeAskThresholdRejected(t *testing.T) {
	body := strings.Replace(validBudgetConfig, "ask_thresholds_usd: [0.50, 0.75]", "ask_thresholds_usd: [0.50, -0.01]", 1)
	_, err := Load(writeConfig(t, body))
	if err == nil || !strings.Contains(err.Error(), "ask_thresholds_usd[1] must be >= 0") {
		t.Fatalf("negative ask threshold must fail loud, got: %v", err)
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
