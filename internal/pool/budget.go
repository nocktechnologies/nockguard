package pool

import (
	"fmt"
	"time"

	"github.com/nocktechnologies/nockguard/internal/forward"
)

// Tier classifies an upstream for cost-aware downgrade routing.
type Tier string

const (
	TierCheap     Tier = "cheap"
	TierStandard  Tier = "standard"
	TierExpensive Tier = "expensive"
)

// Valid reports whether t is a known tier. Empty is valid config and is
// intentionally fail-closed by EffectiveTier.
func (t Tier) Valid() bool {
	switch t {
	case "", TierCheap, TierStandard, TierExpensive:
		return true
	default:
		return false
	}
}

// EffectiveTier returns the tier used for routing decisions.
func (u UpstreamConfig) EffectiveTier() Tier {
	if u.Tier == "" {
		return TierExpensive
	}
	return u.Tier
}

type budgetState struct {
	maxCostUSD float64
	thresholds []float64
	upstreams  map[string]budgetUpstream
	spend      map[string]float64
	asked      map[string]map[float64]bool
}

type budgetUpstream struct {
	tier           Tier
	costPerCallUSD float64
}

// RouteBudgetRequest is the budget-aware routing input. A zero-value request is
// valid; when the router has no active budget it behaves like Route("", now).
type RouteBudgetRequest struct {
	SessionID     string
	RootSessionID string
	Agent         string
	Now           time.Time
	Forwarder     *forward.Forwarder
}

// RouteBudgetResult is the budget-aware routing result.
type RouteBudgetResult struct {
	Label         string
	Reason        string
	Downgraded    bool
	AskThresholds []float64
}

// RouteWithBudget routes a request and records its configured cost against the
// root session tree. Without an active budget it delegates to Route.
func (r *Router) RouteWithBudget(req RouteBudgetRequest) (RouteBudgetResult, error) {
	if req.Now.IsZero() {
		req.Now = time.Now()
	}
	if r.budget == nil || r.budget.maxCostUSD <= 0 {
		label, reason, err := r.Route(req.SessionID, req.Now)
		return RouteBudgetResult{Label: label, Reason: reason}, err
	}

	r.mu.Lock()
	label, reason, downgraded, err := r.routeLocked(req.SessionID, req.RootSessionID, req.Now)
	if err != nil {
		r.mu.Unlock()
		return RouteBudgetResult{Reason: reason}, err
	}
	root := budgetRoot(req.RootSessionID, req.SessionID)
	cost := r.budget.upstreams[label].costPerCallUSD
	before := r.budget.spend[root]
	capUSD := r.budget.maxCostUSD
	after := before + cost
	r.budget.spend[root] = after
	asks := r.newAskThresholdsLocked(root, before, after)
	r.mu.Unlock()

	for _, threshold := range asks {
		enqueueBudgetEvent(req.Forwarder, req.Agent, "budget-ask",
			fmt.Sprintf("rootSessionID=%s threshold=%.2f spend=%.2f", root, threshold, after))
	}
	if downgraded {
		enqueueBudgetEvent(req.Forwarder, req.Agent, "downgrade",
			fmt.Sprintf("rootSessionID=%s spend=%.2f cap=%.2f upstream=%s", root, before, capUSD, label))
	}

	return RouteBudgetResult{
		Label:         label,
		Reason:        reason,
		Downgraded:    downgraded,
		AskThresholds: asks,
	}, nil
}

// RecordSpend adds externally observed spend to a root session tree.
func (r *Router) RecordSpend(rootSessionID string, costUSD float64) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.budget == nil || costUSD <= 0 {
		return
	}
	r.budget.spend[budgetRoot(rootSessionID, "")] += costUSD
}

// SpendUSD returns the current tracked spend for a root session tree.
func (r *Router) SpendUSD(rootSessionID string) float64 {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.budget == nil {
		return 0
	}
	return r.budget.spend[budgetRoot(rootSessionID, "")]
}

func newBudgetState(cfg *Config) *budgetState {
	if cfg == nil || !cfg.Pool.Budget.Enabled() {
		return nil
	}
	upstreams := make(map[string]budgetUpstream, len(cfg.Pool.Upstreams))
	for _, u := range cfg.Pool.Upstreams {
		upstreams[u.Label] = budgetUpstream{
			tier:           u.EffectiveTier(),
			costPerCallUSD: u.CostPerCallUSD,
		}
	}
	thresholds := append([]float64(nil), cfg.Pool.Budget.AskThresholdsUSD...)
	return &budgetState{
		maxCostUSD: cfg.Pool.Budget.MaxCostUSD,
		thresholds: thresholds,
		upstreams:  upstreams,
		spend:      map[string]float64{},
		asked:      map[string]map[float64]bool{},
	}
}

func (r *Router) routeLocked(sessionID, rootSessionID string, now time.Time) (label, reason string, downgraded bool, err error) {
	root := budgetRoot(rootSessionID, sessionID)
	atCap := r.budget.spend[root] >= r.budget.maxCostUSD
	if !atCap {
		label, reason, err = r.routeCandidatesLocked(sessionID, now, nil)
		return label, reason, false, err
	}

	cheapOnly := func(label string) bool {
		meta, ok := r.budget.upstreams[label]
		return ok && meta.tier == TierCheap
	}
	label, _, err = r.routeCandidatesLocked("", now, cheapOnly)
	if err != nil {
		return "", "budget-no-cheap-upstreams", false, err
	}
	return label, "budget-downgrade " + label, true, nil
}

func (r *Router) routeCandidatesLocked(sessionID string, now time.Time, allow func(string) bool) (label, reason string, err error) {
	if sessionID != "" {
		if pinned, ok := r.sessions[sessionID]; ok {
			if allow == nil || allow(pinned) {
				return pinned, "sticky-session " + pinned, nil
			}
		}
	}

	var best string
	bestH := -1.0
	anyCooled := false
	for _, l := range r.upstreams {
		if allow != nil && !allow(l) {
			continue
		}
		if !r.coolUntil[l].IsZero() && now.Before(r.coolUntil[l]) {
			anyCooled = true
			continue
		}
		h, known := r.headroom[l]
		if !known {
			h = 1.0
		}
		if best == "" || h > bestH {
			best = l
			bestH = h
		}
	}
	if best == "" {
		return "", "all-upstreams-exhausted", ErrAllExhausted
	}
	if anyCooled {
		return best, "cooldown-skip " + best, nil
	}
	return best, "max-headroom " + best, nil
}

func (r *Router) newAskThresholdsLocked(root string, before, after float64) []float64 {
	var out []float64
	for _, threshold := range r.budget.thresholds {
		if before >= threshold || after < threshold {
			continue
		}
		if r.budget.asked[root] == nil {
			r.budget.asked[root] = map[float64]bool{}
		}
		if r.budget.asked[root][threshold] {
			continue
		}
		r.budget.asked[root][threshold] = true
		out = append(out, threshold)
	}
	return out
}

func budgetRoot(rootSessionID, sessionID string) string {
	if rootSessionID != "" {
		return rootSessionID
	}
	if sessionID != "" {
		return sessionID
	}
	return "default"
}

func enqueueBudgetEvent(f *forward.Forwarder, agent, decision, reason string) {
	if agent == "" {
		agent = "pool"
	}
	f.Enqueue(forward.Event{
		Agent:    agent,
		Tool:     "pool:budget",
		Decision: decision,
		Reason:   reason,
	})
}
