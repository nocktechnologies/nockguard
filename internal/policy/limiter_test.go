package policy

import (
	"fmt"
	"testing"
)

func TestRateLimitWindowValidation(t *testing.T) {
	for _, tc := range []struct {
		window string
		valid  bool
	}{
		{"0s", false}, {"-1m", false}, {"", false}, {"not-a-duration", false}, {"1m", true}, {"0.5s", true},
	} {
		t.Run(tc.window, func(t *testing.T) {
			// Validate the default too, even before any agent constructs a limiter.
			body := fmt.Sprintf("agents:\n  default:\n    rate_limit:\n      max_calls: 1\n      window: %q\n", tc.window)
			for _, load := range []func() (*Engine, error){
				func() (*Engine, error) { return LoadBytes([]byte(body)) },
				func() (*Engine, error) { return Load(writePolicy(t, body)) },
			} {
				eng, err := load()
				if (err == nil) != tc.valid {
					t.Fatalf("window %q: err=%v, valid=%v", tc.window, err, tc.valid)
				}
				if !tc.valid {
					continue
				}
				lim, err := eng.LimiterFor("unlisted")
				if err != nil {
					t.Fatal(err)
				}
				if _, ok := lim.Allow(); !ok {
					t.Fatal("first call denied")
				}
				if _, ok := lim.Allow(); ok {
					t.Fatal("second call bypassed limit")
				}
			}
		})
	}
}

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

func TestTrustForDisabledWhenUnset(t *testing.T) {
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
	acc, err := eng.TrustFor("kit")
	if err != nil {
		t.Fatalf("TrustFor: %v", err)
	}
	if acc != nil {
		t.Fatal("missing trust config should return nil")
	}
}

func TestTrustForEnabled(t *testing.T) {
	dir := t.TempDir()
	path := writePolicy(t, `
agents:
  kit:
    trust:
      enabled: true
      path: `+dir+`/kit.json
`)
	eng, err := Load(path)
	if err != nil {
		t.Fatal(err)
	}
	acc, err := eng.TrustFor("kit")
	if err != nil {
		t.Fatalf("TrustFor: %v", err)
	}
	if !acc.Enabled() {
		t.Fatal("enabled trust config should return enabled accumulator")
	}
	if got := acc.RateLimitFor(10); got != 10 {
		t.Fatalf("baseline trust should preserve base rate cap, got %d", got)
	}
}
