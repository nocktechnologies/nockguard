package pool

import (
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"
	"time"

	"github.com/nocktechnologies/nockguard/internal/forward"
)

func newBudgetRouterForTest(t *testing.T) *Router {
	t.Helper()
	cfg, err := Load(writeConfig(t, validBudgetConfig))
	if err != nil {
		t.Fatal(err)
	}
	cfg.Normalize()
	r := NewRouterFromConfig(cfg)
	r.RecordHeadroom("cheap-1", 0.4)
	r.RecordHeadroom("opus-1", 0.9)
	r.RecordHeadroom("legacy-untiered", 1.0)
	return r
}

func TestRouteWithBudgetUnderCapUsesNormalRoute(t *testing.T) {
	r := newBudgetRouterForTest(t)

	got, err := r.RouteWithBudget(RouteBudgetRequest{
		SessionID:     "sess-A",
		RootSessionID: "root-A",
		Now:           t0,
	})
	if err != nil {
		t.Fatalf("RouteWithBudget: %v", err)
	}
	if got.Label != "legacy-untiered" {
		t.Errorf("label = %q, want legacy-untiered while under cap normal headroom wins", got.Label)
	}
	if got.Reason != "max-headroom legacy-untiered" {
		t.Errorf("reason = %q, want max-headroom legacy-untiered", got.Reason)
	}
	if got.Downgraded {
		t.Fatal("under-cap route should not be marked downgraded")
	}
	if spend := r.SpendUSD("root-A"); spend != 0.25 {
		t.Errorf("root spend = %.2f, want 0.25", spend)
	}
}

func TestRouteWithBudgetWithoutBudgetPreservesRoute(t *testing.T) {
	r := newRouter(twoLabels)
	r.RecordHeadroom("sub-1", 0.1)
	r.RecordHeadroom("sub-2", 0.9)

	got, err := r.RouteWithBudget(RouteBudgetRequest{SessionID: "sess-A", RootSessionID: "root-A", Now: t0})
	if err != nil {
		t.Fatal(err)
	}
	if got.Label != "sub-2" || got.Reason != "max-headroom sub-2" || got.Downgraded {
		t.Fatalf("RouteWithBudget without budget should mirror Route, got %+v", got)
	}
	if spend := r.SpendUSD("root-A"); spend != 0 {
		t.Fatalf("disabled budget should not record spend, got %.2f", spend)
	}
}

func TestRouteWithBudgetAtCapDowngradesToCheap(t *testing.T) {
	r := newBudgetRouterForTest(t)
	r.RecordSpend("root-A", 1.00)

	got, err := r.RouteWithBudget(RouteBudgetRequest{
		SessionID:     "sess-A",
		RootSessionID: "root-A",
		Now:           t0,
	})
	if err != nil {
		t.Fatalf("RouteWithBudget: %v", err)
	}
	if got.Label != "cheap-1" {
		t.Errorf("label = %q, want cheap-1 at cap", got.Label)
	}
	if got.Reason != "budget-downgrade cheap-1" {
		t.Errorf("reason = %q, want budget-downgrade cheap-1", got.Reason)
	}
	if !got.Downgraded {
		t.Fatal("at-cap route should be marked downgraded")
	}
}

func TestRouteWithBudgetAtCapTreatsUntieredAsExpensive(t *testing.T) {
	cfg, err := Load(writeConfig(t, `
pool:
  listen: "127.0.0.1:4141"
  upstreams:
    - label: legacy-untiered
      codex_home: ~/.codex-legacy
      cost_per_call_usd: 0.20
  budget:
    max_cost_usd: 1.00
`))
	if err != nil {
		t.Fatal(err)
	}
	cfg.Normalize()
	r := NewRouterFromConfig(cfg)
	r.RecordSpend("root-A", 1.00)

	_, err = r.RouteWithBudget(RouteBudgetRequest{RootSessionID: "root-A", Now: t0})
	if !errors.Is(err, ErrAllExhausted) {
		t.Fatalf("err = %v, want ErrAllExhausted when only untiered upstream remains at cap", err)
	}
}

func TestRouteWithBudgetAggregatesSpendByRootSessionID(t *testing.T) {
	r := newBudgetRouterForTest(t)

	for _, sessionID := range []string{"child-A", "child-B", "child-C", "child-D"} {
		if _, err := r.RouteWithBudget(RouteBudgetRequest{
			SessionID:     sessionID,
			RootSessionID: "root-shared",
			Now:           t0,
		}); err != nil {
			t.Fatalf("RouteWithBudget(%s): %v", sessionID, err)
		}
	}

	if spend := r.SpendUSD("root-shared"); spend != 1.00 {
		t.Fatalf("root spend = %.2f, want 1.00", spend)
	}
	got, err := r.RouteWithBudget(RouteBudgetRequest{
		SessionID:     "child-E",
		RootSessionID: "root-shared",
		Now:           t0,
	})
	if err != nil {
		t.Fatal(err)
	}
	if got.Label != "cheap-1" || !got.Downgraded {
		t.Fatalf("shared root at cap should downgrade to cheap-1, got %+v", got)
	}
}

func TestRouteWithBudgetAsksOncePerThresholdPerRoot(t *testing.T) {
	cap := &budgetCapture{}
	srv := httptest.NewServer(cap.handler())
	defer srv.Close()
	f := forward.New(forward.Config{BaseURL: srv.URL, APIKey: "k"})
	f.Start()
	defer f.Stop()

	r := newBudgetRouterForTest(t)
	for i := 0; i < 4; i++ {
		if _, err := r.RouteWithBudget(RouteBudgetRequest{
			Agent:         "hammer",
			RootSessionID: "root-A",
			Now:           t0.Add(time.Duration(i) * time.Second),
			Forwarder:     f,
		}); err != nil {
			t.Fatalf("RouteWithBudget #%d: %v", i, err)
		}
	}
	f.Stop()

	decisions := cap.decisions()
	if got := decisions["budget-ask"]; got != 2 {
		t.Fatalf("budget-ask forwards = %d, want exactly 2 thresholds once each", got)
	}
}

func TestRouteWithBudgetForwardsDowngradeEvent(t *testing.T) {
	cap := &budgetCapture{}
	srv := httptest.NewServer(cap.handler())
	defer srv.Close()
	f := forward.New(forward.Config{BaseURL: srv.URL, APIKey: "k"})
	f.Start()
	defer f.Stop()

	r := newBudgetRouterForTest(t)
	r.RecordSpend("root-A", 1.00)
	got, err := r.RouteWithBudget(RouteBudgetRequest{
		Agent:         "hammer",
		RootSessionID: "root-A",
		Now:           t0,
		Forwarder:     f,
	})
	if err != nil {
		t.Fatal(err)
	}
	if got.Label != "cheap-1" || !got.Downgraded {
		t.Fatalf("expected downgrade to cheap-1, got %+v", got)
	}
	f.Stop()

	decisions := cap.decisions()
	if decisions["downgrade"] != 1 {
		t.Fatalf("downgrade forwards = %d, want 1", decisions["downgrade"])
	}
}

type budgetCapture struct {
	mu       sync.Mutex
	requests []map[string]any
}

func (c *budgetCapture) handler() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		raw, _ := io.ReadAll(r.Body)
		var body map[string]any
		_ = json.Unmarshal(raw, &body)
		c.mu.Lock()
		c.requests = append(c.requests, body)
		c.mu.Unlock()
		w.WriteHeader(http.StatusCreated)
	}
}

func (c *budgetCapture) decisions() map[string]int {
	c.mu.Lock()
	defer c.mu.Unlock()
	out := map[string]int{}
	for _, req := range c.requests {
		blob, _ := req["data_blob"].(map[string]any)
		decision, _ := blob["decision"].(string)
		out[decision]++
	}
	return out
}
