package pool

import (
	"errors"
	"testing"
	"time"
)

var (
	t0       = time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	cool60   = 60 * time.Second
	twoLabels = []string{"sub-1", "sub-2"}
)

func newRouter(labels []string) *Router {
	return NewRouter(labels, cool60)
}

// ── sticky session ────────────────────────────────────────────────────────────

func TestStickySessionReturnsPin(t *testing.T) {
	r := newRouter(twoLabels)
	r.Pin("sess-A", "sub-2")

	label, reason, err := r.Route("sess-A", t0)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if label != "sub-2" {
		t.Errorf("label = %q, want sub-2", label)
	}
	if reason != "sticky-session sub-2" {
		t.Errorf("reason = %q, want sticky-session sub-2", reason)
	}
}

func TestUnknownSessionFallsThrough(t *testing.T) {
	r := newRouter(twoLabels)
	// no pin — falls through to headroom

	label, reason, err := r.Route("sess-new", t0)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if label == "" {
		t.Error("expected a label, got empty")
	}
	if reason != "max-headroom "+label {
		t.Errorf("reason = %q, want max-headroom %s", reason, label)
	}
}

func TestEmptySessionIDFallsThrough(t *testing.T) {
	r := newRouter(twoLabels)
	label, reason, err := r.Route("", t0)
	if err != nil {
		t.Fatal(err)
	}
	if label == "" {
		t.Error("expected a label, got empty")
	}
	if reason != "max-headroom "+label {
		t.Errorf("reason = %q, want max-headroom %s", reason, label)
	}
}

// ── headroom routing ──────────────────────────────────────────────────────────

func TestMaxHeadroomPicksHigher(t *testing.T) {
	r := newRouter(twoLabels)
	r.RecordHeadroom("sub-1", 0.2)
	r.RecordHeadroom("sub-2", 0.8)

	label, _, err := r.Route("", t0)
	if err != nil {
		t.Fatal(err)
	}
	if label != "sub-2" {
		t.Errorf("label = %q, want sub-2 (higher headroom)", label)
	}
}

func TestMaxHeadroomReasonString(t *testing.T) {
	r := newRouter(twoLabels)
	r.RecordHeadroom("sub-1", 0.1)
	r.RecordHeadroom("sub-2", 0.9)

	_, reason, _ := r.Route("", t0)
	if reason != "max-headroom sub-2" {
		t.Errorf("reason = %q, want max-headroom sub-2", reason)
	}
}

func TestEqualHeadroomPicksFirst(t *testing.T) {
	r := newRouter(twoLabels)
	// same headroom (both unknown = default 1.0)

	label, _, err := r.Route("", t0)
	if err != nil {
		t.Fatal(err)
	}
	if label != "sub-1" {
		t.Errorf("label = %q, want sub-1 (first when equal)", label)
	}
}

func TestHeadroomUpdateChangesRouting(t *testing.T) {
	r := newRouter(twoLabels)
	r.RecordHeadroom("sub-1", 0.9)
	r.RecordHeadroom("sub-2", 0.1)

	label, _, _ := r.Route("", t0)
	if label != "sub-1" {
		t.Fatalf("expected sub-1 first, got %q", label)
	}

	// Now sub-2 gets more headroom
	r.RecordHeadroom("sub-1", 0.1)
	r.RecordHeadroom("sub-2", 0.9)

	label, _, _ = r.Route("", t0)
	if label != "sub-2" {
		t.Errorf("expected sub-2 after headroom update, got %q", label)
	}
}

// ── cooldown ──────────────────────────────────────────────────────────────────

func TestCooldownSkipsFailedLabel(t *testing.T) {
	r := newRouter(twoLabels)
	r.RecordFailure("sub-1", t0)

	// sub-1 is on cooldown; sub-2 should be chosen
	label, reason, err := r.Route("", t0.Add(1*time.Second))
	if err != nil {
		t.Fatal(err)
	}
	if label != "sub-2" {
		t.Errorf("label = %q, want sub-2 (sub-1 on cooldown)", label)
	}
	if reason != "cooldown-skip sub-2" {
		t.Errorf("reason = %q, want cooldown-skip sub-2", reason)
	}
}

func TestCooldownExpiresAfterWindow(t *testing.T) {
	r := newRouter(twoLabels)
	r.RecordHeadroom("sub-1", 0.9)
	r.RecordHeadroom("sub-2", 0.1)
	r.RecordFailure("sub-1", t0)

	// Within cooldown window: sub-2
	label, _, _ := r.Route("", t0.Add(30*time.Second))
	if label != "sub-2" {
		t.Fatalf("within window: expected sub-2, got %q", label)
	}

	// After cooldown window: sub-1 back (it has more headroom)
	label, reason, err := r.Route("", t0.Add(61*time.Second))
	if err != nil {
		t.Fatal(err)
	}
	if label != "sub-1" {
		t.Errorf("after expiry: label = %q, want sub-1", label)
	}
	if reason != "max-headroom sub-1" {
		t.Errorf("after expiry: reason = %q, want max-headroom sub-1", reason)
	}
}

func TestAllUpstreamsOnCooldown(t *testing.T) {
	r := newRouter(twoLabels)
	r.RecordFailure("sub-1", t0)
	r.RecordFailure("sub-2", t0)

	label, reason, err := r.Route("", t0.Add(1*time.Second))
	if !errors.Is(err, ErrAllExhausted) {
		t.Fatalf("err = %v, want ErrAllExhausted", err)
	}
	if label != "" {
		t.Errorf("label should be empty on exhausted, got %q", label)
	}
	if reason != "all-upstreams-exhausted" {
		t.Errorf("reason = %q, want all-upstreams-exhausted", reason)
	}
}

func TestCooldownReasonVsNoCooldown(t *testing.T) {
	r := newRouter(twoLabels)
	// No cooldowns — reason should be max-headroom
	_, reason, _ := r.Route("", t0)
	if reason != "max-headroom sub-1" {
		t.Errorf("no-cooldown: reason = %q, want max-headroom sub-1", reason)
	}

	// Put sub-1 on cooldown — reason should be cooldown-skip
	r.RecordFailure("sub-1", t0)
	_, reason, _ = r.Route("", t0.Add(time.Second))
	if reason != "cooldown-skip sub-2" {
		t.Errorf("with-cooldown: reason = %q, want cooldown-skip sub-2", reason)
	}
}

// ── sticky session + cooldown interaction ─────────────────────────────────────

func TestStickySessionOnCooldownStillRoutes(t *testing.T) {
	// Sticky sessions always win — the proxy layer decides whether to
	// honour that or clear the pin after a failure. The router itself
	// does not break a pin because the account is on cooldown.
	r := newRouter(twoLabels)
	r.Pin("sess-A", "sub-1")
	r.RecordFailure("sub-1", t0)

	label, reason, err := r.Route("sess-A", t0.Add(time.Second))
	if err != nil {
		t.Fatal(err)
	}
	if label != "sub-1" {
		t.Errorf("sticky pin should survive cooldown: label = %q, want sub-1", label)
	}
	if reason != "sticky-session sub-1" {
		t.Errorf("reason = %q, want sticky-session sub-1", reason)
	}
}

// ── single upstream ───────────────────────────────────────────────────────────

func TestSingleUpstreamAlwaysRoutes(t *testing.T) {
	r := newRouter([]string{"only"})
	label, reason, err := r.Route("", t0)
	if err != nil {
		t.Fatal(err)
	}
	if label != "only" {
		t.Errorf("label = %q, want only", label)
	}
	if reason != "max-headroom only" {
		t.Errorf("reason = %q, want max-headroom only", reason)
	}
}

func TestSingleUpstreamOnCooldownExhausted(t *testing.T) {
	r := newRouter([]string{"only"})
	r.RecordFailure("only", t0)

	_, _, err := r.Route("", t0.Add(time.Second))
	if !errors.Is(err, ErrAllExhausted) {
		t.Fatalf("single upstream on cooldown: err = %v, want ErrAllExhausted", err)
	}
}

// ── pin lifecycle ─────────────────────────────────────────────────────────────

func TestPinCanBeOverwritten(t *testing.T) {
	r := newRouter(twoLabels)
	r.Pin("sess-A", "sub-1")
	r.Pin("sess-A", "sub-2") // overwrite

	label, reason, _ := r.Route("sess-A", t0)
	if label != "sub-2" {
		t.Errorf("label = %q, want sub-2 (overwritten pin)", label)
	}
	if reason != "sticky-session sub-2" {
		t.Errorf("reason = %q, want sticky-session sub-2", reason)
	}
}

func TestUnpinClearsStickiness(t *testing.T) {
	r := newRouter(twoLabels)
	r.Pin("sess-A", "sub-2")
	r.Unpin("sess-A")

	// Should fall through to headroom (sub-1 first by equal headroom)
	label, reason, _ := r.Route("sess-A", t0)
	if label != "sub-1" {
		t.Errorf("after unpin: label = %q, want sub-1", label)
	}
	if reason != "max-headroom sub-1" {
		t.Errorf("after unpin: reason = %q, want max-headroom sub-1", reason)
	}
}
