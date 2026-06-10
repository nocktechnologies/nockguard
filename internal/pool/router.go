// Package pool — Router implements the V1 pool routing algorithm.
// Design contract: docs/POOL_ROUTER.md. Any behavior not in that doc is a bug.
package pool

import (
	"errors"
	"fmt"
	"sync"
	"time"
)

// ErrAllExhausted is returned by Route when every upstream is on cooldown.
var ErrAllExhausted = errors.New("pool: all upstreams exhausted (all on cooldown)")

// Router holds the in-memory routing state for V1.
// Session pins, headroom readings, and cooldown demotions are all memory-only;
// they reset on restart (documented in POOL_ROUTER.md "What is stored").
//
// All methods are safe for concurrent use.
type Router struct {
	mu        sync.Mutex
	upstreams []string             // ordered; determines tie-break for equal headroom
	sessions  map[string]string    // session-id → label (sticky pins)
	headroom  map[string]float64   // label → remaining quota (0–1; default 1.0 = unknown/full)
	coolUntil map[string]time.Time // label → cooldown expiry (zero = not cooling)
	cooldown  time.Duration
}

// NewRouter creates a Router from an ordered list of account labels and a
// cooldown duration. Labels must match the config upstreams; the router itself
// holds no credentials or I/O.
func NewRouter(labels []string, cooldown time.Duration) *Router {
	r := &Router{
		upstreams: make([]string, len(labels)),
		sessions:  make(map[string]string),
		headroom:  make(map[string]float64),
		coolUntil: make(map[string]time.Time),
		cooldown:  cooldown,
	}
	copy(r.upstreams, labels)
	return r
}

// NewRouterFromConfig builds a Router from a validated, normalised Config.
func NewRouterFromConfig(cfg *Config) *Router {
	labels := make([]string, len(cfg.Pool.Upstreams))
	for i, u := range cfg.Pool.Upstreams {
		labels[i] = u.Label
	}
	return NewRouter(labels, cfg.Pool.Routing.Cooldown())
}

// Route picks an upstream for the given request.
//
// Priority:
//  1. Sticky session — if sessionID is non-empty and pinned, return it.
//  2. Max headroom — pick the upstream with the highest remaining quota,
//     skipping any on cooldown.
//
// Reason strings match the enumerated contract in docs/POOL_ROUTER.md:
//   - "sticky-session <label>"
//   - "max-headroom <label>"
//   - "cooldown-skip <label>"
//   - "all-upstreams-exhausted"
//
// ErrAllExhausted is returned only when every upstream is on cooldown.
func (r *Router) Route(sessionID string, now time.Time) (label, reason string, err error) {
	r.mu.Lock()
	defer r.mu.Unlock()

	// 1. Sticky session wins unconditionally.
	if sessionID != "" {
		if pinned, ok := r.sessions[sessionID]; ok {
			return pinned, "sticky-session " + pinned, nil
		}
	}

	// 2. Headroom pass — collect candidates (not on cooldown).
	var best string
	bestH := -1.0
	anyCooled := false

	for _, l := range r.upstreams {
		if !r.coolUntil[l].IsZero() && now.Before(r.coolUntil[l]) {
			anyCooled = true
			continue
		}
		h, known := r.headroom[l]
		if !known {
			// unset = unknown quota; treat as full so we don't penalise fresh upstreams
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

// Pin records a session → label binding (sticky session).
// Overwrites any existing pin for the session.
func (r *Router) Pin(sessionID, label string) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.sessions[sessionID] = label
}

// Unpin removes the sticky binding for a session.
func (r *Router) Unpin(sessionID string) {
	r.mu.Lock()
	defer r.mu.Unlock()
	delete(r.sessions, sessionID)
}

// RecordHeadroom updates the headroom for an upstream after reading
// x-codex-* response headers. remaining is in [0, 1] where 1 = full quota.
func (r *Router) RecordHeadroom(label string, remaining float64) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.headroom[label] = remaining
}

// RecordFailure demotes label to cooldown starting at now. The upstream is
// excluded from Route results until now + cooldown elapses.
func (r *Router) RecordFailure(label string, now time.Time) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.coolUntil[label] = now.Add(r.cooldown)
}

// Status returns a snapshot of each upstream's routing state, suitable for
// audit display and the Wall. Safe to call concurrently.
func (r *Router) Status(now time.Time) []UpstreamStatus {
	r.mu.Lock()
	defer r.mu.Unlock()

	out := make([]UpstreamStatus, len(r.upstreams))
	for i, l := range r.upstreams {
		s := UpstreamStatus{Label: l}
		if h, ok := r.headroom[l]; ok {
			s.HeadroomKnown = true
			s.Headroom = h
		}
		if !r.coolUntil[l].IsZero() && now.Before(r.coolUntil[l]) {
			s.OnCooldown = true
			s.CooldownRemaining = r.coolUntil[l].Sub(now)
		}
		out[i] = s
	}
	return out
}

// UpstreamStatus is a snapshot of one upstream for display / audit.
type UpstreamStatus struct {
	Label             string
	HeadroomKnown     bool
	Headroom          float64
	OnCooldown        bool
	CooldownRemaining time.Duration
}

// String returns a short human-readable representation.
func (s UpstreamStatus) String() string {
	if s.OnCooldown {
		return fmt.Sprintf("%s [COOLDOWN %.0fs]", s.Label, s.CooldownRemaining.Seconds())
	}
	if s.HeadroomKnown {
		return fmt.Sprintf("%s [%.0f%%]", s.Label, s.Headroom*100)
	}
	return fmt.Sprintf("%s [?]", s.Label)
}
