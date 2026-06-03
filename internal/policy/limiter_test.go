package policy

import "testing"

func TestLimiterForDisabledWhenUnset(t *testing.T) {
	path := writePolicy(t, `
agents:
  kit:
    allow:
      - "nockcc_*"
`)
	eng, err := Load(path)
	if err != nil {
		t.Fatal(err)
	}
	lim, err := eng.LimiterFor("kit")
	if err != nil {
		t.Fatalf("LimiterFor: %v", err)
	}
	if lim.Enabled() {
		t.Error("agent with no rate_limit/spend_cap should get a disabled limiter")
	}
}

func TestLimiterForRateLimit(t *testing.T) {
	path := writePolicy(t, `
agents:
  kit:
    rate_limit:
      max_calls: 2
      window: 1m
`)
	eng, err := Load(path)
	if err != nil {
		t.Fatal(err)
	}
	lim, err := eng.LimiterFor("kit")
	if err != nil {
		t.Fatalf("LimiterFor: %v", err)
	}
	if !lim.Enabled() {
		t.Fatal("rate_limit config should enable the limiter")
	}
	if _, ok := lim.Allow(); !ok {
		t.Fatal("call 1 should pass")
	}
	if _, ok := lim.Allow(); !ok {
		t.Fatal("call 2 should pass")
	}
	if reason, ok := lim.Allow(); ok || reason != "rate" {
		t.Fatalf("call 3 should be rate-blocked, got ok=%v reason=%q", ok, reason)
	}
}

func TestLimiterForSpendCap(t *testing.T) {
	path := writePolicy(t, `
agents:
  kit:
    spend_cap:
      max_calls: 1
`)
	eng, err := Load(path)
	if err != nil {
		t.Fatal(err)
	}
	lim, err := eng.LimiterFor("kit")
	if err != nil {
		t.Fatalf("LimiterFor: %v", err)
	}
	if _, ok := lim.Allow(); !ok {
		t.Fatal("first call should pass")
	}
	if reason, ok := lim.Allow(); ok || reason != "spend-cap" {
		t.Fatalf("second call should hit spend cap, got ok=%v reason=%q", ok, reason)
	}
}

func TestLimiterForInvalidWindowErrors(t *testing.T) {
	path := writePolicy(t, `
agents:
  kit:
    rate_limit:
      max_calls: 5
      window: "not-a-duration"
`)
	eng, err := Load(path)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := eng.LimiterFor("kit"); err == nil {
		t.Fatal("invalid window duration should fail loud at build time")
	}
}

func TestLimiterForMissingWindowErrors(t *testing.T) {
	path := writePolicy(t, `
agents:
  kit:
    rate_limit:
      max_calls: 5
`)
	eng, err := Load(path)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := eng.LimiterFor("kit"); err == nil {
		t.Fatal("rate_limit with max_calls but no window should fail loud")
	}
}

func TestLimiterForFallsBackToDefault(t *testing.T) {
	path := writePolicy(t, `
agents:
  default:
    spend_cap:
      max_calls: 1
`)
	eng, err := Load(path)
	if err != nil {
		t.Fatal(err)
	}
	lim, err := eng.LimiterFor("unlisted_agent")
	if err != nil {
		t.Fatalf("LimiterFor: %v", err)
	}
	if !lim.Enabled() {
		t.Error("unlisted agent should inherit the default spend cap")
	}
}
