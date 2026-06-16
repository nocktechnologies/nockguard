package ratelimit

import (
	"testing"
	"time"
)

// clocked builds a Limiter with a controllable clock for deterministic tests.
func clocked(t *testing.T, cfg Config, now *time.Time) *Limiter {
	t.Helper()
	l := New(cfg)
	l.clock = func() time.Time { return *now }
	return l
}

func TestDisabledWhenNoLimits(t *testing.T) {
	if New(Config{}).Enabled() {
		t.Fatal("limiter with no limits configured must report disabled")
	}
	var nilL *Limiter
	if nilL.Enabled() {
		t.Fatal("nil limiter must report disabled")
	}
}

func TestEnabledWhenEitherLimitSet(t *testing.T) {
	if !New(Config{MaxCalls: 1, Window: time.Minute}).Enabled() {
		t.Error("rate limit alone should enable the limiter")
	}
	if !New(Config{SpendCap: 1}).Enabled() {
		t.Error("spend cap alone should enable the limiter")
	}
}

func TestRateLimitBlocksOverWindow(t *testing.T) {
	now := time.Unix(0, 0)
	l := clocked(t, Config{MaxCalls: 3, Window: time.Minute}, &now)

	for i := 0; i < 3; i++ {
		if reason, ok := l.Allow(); !ok {
			t.Fatalf("call %d should be allowed, blocked as %q", i+1, reason)
		}
	}
	if reason, ok := l.Allow(); ok || reason != "rate" {
		t.Fatalf("4th call should be rate-blocked, got ok=%v reason=%q", ok, reason)
	}

	// Slide past the window: the earliest calls expire, room frees up.
	now = now.Add(61 * time.Second)
	if reason, ok := l.Allow(); !ok {
		t.Fatalf("call after window should be allowed, blocked as %q", reason)
	}
}

func TestSpendCapHardStopNeverRefills(t *testing.T) {
	now := time.Unix(0, 0)
	l := clocked(t, Config{SpendCap: 2}, &now)

	if _, ok := l.Allow(); !ok {
		t.Fatal("call 1 should be allowed")
	}
	if _, ok := l.Allow(); !ok {
		t.Fatal("call 2 should be allowed")
	}
	if reason, ok := l.Allow(); ok || reason != "spend-cap" {
		t.Fatalf("call 3 should hit spend cap, got ok=%v reason=%q", ok, reason)
	}

	// A spend cap is a hard ceiling — time passing does NOT refill it.
	now = now.Add(24 * time.Hour)
	if reason, ok := l.Allow(); ok || reason != "spend-cap" {
		t.Fatalf("spend cap must persist across time, got ok=%v reason=%q", ok, reason)
	}
}

func TestBlockedCallsDoNotConsumeBudget(t *testing.T) {
	now := time.Unix(0, 0)
	// Window holds 1 call; session allows 2 total. A rate-block must not burn
	// spend budget, or a runaway loop would exhaust the cap on rejected calls.
	l := clocked(t, Config{MaxCalls: 1, Window: time.Minute, SpendCap: 2}, &now)

	if _, ok := l.Allow(); !ok { // allowed: window 1/1, spend 1/2
		t.Fatal("first call should be allowed")
	}
	if reason, ok := l.Allow(); ok || reason != "rate" { // window full
		t.Fatalf("second call should be rate-blocked, got ok=%v reason=%q", ok, reason)
	}

	now = now.Add(61 * time.Second) // window clears; spend should still be 1, not 2
	if _, ok := l.Allow(); !ok {    // allowed: spend 2/2
		t.Fatal("call after window should be allowed (rate-block must not have consumed spend)")
	}
	if reason, ok := l.Allow(); ok || reason != "spend-cap" {
		t.Fatalf("now spend cap should bind, got ok=%v reason=%q", ok, reason)
	}
}

func TestSpendCapTakesPrecedenceOverRate(t *testing.T) {
	now := time.Unix(0, 0)
	l := clocked(t, Config{MaxCalls: 1, Window: time.Minute, SpendCap: 1}, &now)

	if _, ok := l.Allow(); !ok {
		t.Fatal("first call should be allowed")
	}
	// Second call violates both the window (1/1) and the cap (1/1).
	// The hard stop wins: report spend-cap, not rate.
	if reason, ok := l.Allow(); ok || reason != "spend-cap" {
		t.Fatalf("expected spend-cap precedence, got ok=%v reason=%q", ok, reason)
	}
}

func TestDynamicMaxCalls(t *testing.T) {
	now := time.Unix(0, 0)
	l := clocked(t, Config{MaxCalls: 10, Window: time.Minute}, &now).
		WithMaxCallsFunc(func(baseMax int) int {
			if baseMax != 10 {
				t.Fatalf("dynamic cap saw baseMax=%d, want 10", baseMax)
			}
			return 5
		})

	for i := 0; i < 5; i++ {
		if reason, ok := l.Allow(); !ok {
			t.Fatalf("call %d should pass under dynamic cap, got %q", i+1, reason)
		}
	}
	if reason, ok := l.Allow(); ok || reason != "rate" {
		t.Fatalf("6th call should hit dynamic rate cap, got ok=%v reason=%q", ok, reason)
	}
}
