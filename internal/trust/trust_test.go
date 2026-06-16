package trust

import (
	"os"
	"path/filepath"
	"testing"
	"time"
)

func testAccumulator(t *testing.T, now *time.Time) *Accumulator {
	t.Helper()
	a, err := New(Config{
		Enabled: true,
		Path:    filepath.Join(t.TempDir(), "kit.json"),
		Agent:   "kit",
	}, WithClock(func() time.Time { return *now }))
	if err != nil {
		t.Fatal(err)
	}
	return a
}

func TestOutcomeAsymmetry(t *testing.T) {
	now := time.Unix(0, 0).UTC()
	a := testAccumulator(t, &now)

	if got := a.ApplyOutcome(OutcomeAllow); got != 0.51 {
		t.Fatalf("allow score = %.2f, want 0.51", got)
	}
	if got := a.ApplyOutcome(OutcomeWarn); got != 0.49 {
		t.Fatalf("warn score = %.2f, want 0.49", got)
	}
	if got := a.ApplyOutcome(OutcomeDeny); got != 0.44 {
		t.Fatalf("deny score = %.2f, want 0.44", got)
	}
}

func TestDecayBeforeDelta(t *testing.T) {
	now := time.Unix(0, 0).UTC()
	a := testAccumulator(t, &now)
	a.ApplyOutcome(OutcomeDeny) // 0.45

	now = now.Add(30 * time.Second) // decays halfway back to 0.475, then deny.
	got := a.ApplyOutcome(OutcomeDeny)
	if got < 0.4249 || got > 0.4251 {
		t.Fatalf("score after decay-before-delta = %.4f, want 0.4250", got)
	}
}

func TestLazyDecayOnRead(t *testing.T) {
	now := time.Unix(0, 0).UTC()
	a := testAccumulator(t, &now)
	a.ApplyOutcome(OutcomeDeny)

	now = now.Add(60 * time.Second)
	if got := a.Score(); got != Baseline {
		t.Fatalf("lazy read score = %.2f, want baseline %.2f", got, Baseline)
	}
}

func TestDeniedAgentRateDropsThenRecoversAfterDecay(t *testing.T) {
	now := time.Unix(0, 0).UTC()
	a := testAccumulator(t, &now)
	a.ApplyOutcome(OutcomeDeny)

	if got := a.RateLimitFor(10); got != 5 {
		t.Fatalf("denied agent rate cap = %d, want reduced cap 5", got)
	}
	now = now.Add(60 * time.Second)
	if got := a.RateLimitFor(10); got != 10 {
		t.Fatalf("rate cap after lazy decay = %d, want baseline cap 10", got)
	}
}

func TestTierMultiplierAndRateLimit(t *testing.T) {
	tests := []struct {
		score      float64
		tier       Tier
		multiplier float64
		limit      int
	}{
		{0.81, TierExcellent, 2.0, 20},
		{0.50, TierNormal, 1.0, 10},
		{0.49, TierReduced, 0.5, 5},
		{0.29, TierRestricted, 0.1, 1},
	}
	for _, tt := range tests {
		if got := TierFor(tt.score); got != tt.tier {
			t.Errorf("TierFor(%.2f) = %s, want %s", tt.score, got, tt.tier)
		}
		if got := MultiplierFor(tt.score); got != tt.multiplier {
			t.Errorf("MultiplierFor(%.2f) = %.1f, want %.1f", tt.score, got, tt.multiplier)
		}
		if got := RateLimitForScore(10, tt.score); got != tt.limit {
			t.Errorf("RateLimitForScore(10, %.2f) = %d, want %d", tt.score, got, tt.limit)
		}
	}
}

func TestPersistenceRoundTrip(t *testing.T) {
	now := time.Unix(0, 0).UTC()
	path := filepath.Join(t.TempDir(), "kit.json")
	a, err := New(Config{Enabled: true, Path: path, Agent: "kit"}, WithClock(func() time.Time { return now }))
	if err != nil {
		t.Fatal(err)
	}
	a.ApplyOutcome(OutcomeDeny)

	reloaded, err := New(Config{Enabled: true, Path: path, Agent: "kit"}, WithClock(func() time.Time { return now }))
	if err != nil {
		t.Fatal(err)
	}
	if got := reloaded.Score(); got != 0.45 {
		t.Fatalf("reloaded score = %.2f, want 0.45", got)
	}
	if _, err := os.Stat(path); err != nil {
		t.Fatalf("trust file not written: %v", err)
	}
}

func TestDisabledAndNilAreNoops(t *testing.T) {
	disabled, err := New(Config{Enabled: false, Path: filepath.Join(t.TempDir(), "kit.json")})
	if err != nil {
		t.Fatal(err)
	}
	if disabled.Enabled() {
		t.Fatal("disabled accumulator should report disabled")
	}
	if got := disabled.ApplyOutcome(OutcomeDeny); got != Baseline {
		t.Fatalf("disabled ApplyOutcome = %.2f, want baseline", got)
	}
	var nilAccumulator *Accumulator
	if nilAccumulator.Enabled() {
		t.Fatal("nil accumulator should report disabled")
	}
	if got := nilAccumulator.RateLimitFor(10); got != 10 {
		t.Fatalf("nil RateLimitFor = %d, want unchanged base", got)
	}
}

func TestDecisionToOutcomeUsesProxyDecisionStrings(t *testing.T) {
	tests := map[string]Outcome{
		"allow":            OutcomeAllow,
		"approval-granted": OutcomeAllow,
		"warn":             OutcomeWarn,
		"block":            OutcomeWarn,
		"ratelimit":        OutcomeWarn,
		"approval-denied":  OutcomeWarn,
		"deny":             OutcomeDeny,
	}
	for decision, want := range tests {
		got, ok := DecisionToOutcome(decision)
		if !ok || got != want {
			t.Fatalf("DecisionToOutcome(%q) = %q/%v, want %q/true", decision, got, ok, want)
		}
	}
	if _, ok := DecisionToOutcome("hide"); ok {
		t.Fatal("hide should not affect behavioral trust")
	}
}
