// Package ratelimit implements NockGuard Phase 3: per-agent rate limiting and
// spend caps on MCP tool calls.
//
// Two independent, opt-in controls guard a proxy session:
//
//   - Rate limit: at most MaxCalls tool calls within a sliding Window. This
//     bounds burst/runaway behavior (e.g. an agent stuck in a tool-call loop)
//     while letting normal traffic through; the allowance refills as the window
//     slides.
//
//   - Spend cap: a hard cumulative ceiling (SpendCap) on the number of tool
//     calls for the whole proxy session. Unlike the rate limit it never refills
//     — once hit, every further call is blocked. This is the kill-before-runaway
//     stop that bounds total cost when an agent is left running unattended.
//
// NockGuard sits at the MCP layer and sees tool *calls*, not upstream API token
// spend, so "spend cap" here is denominated in tool calls — a proxy for cost,
// enforced before the call reaches the server. Both controls are disabled by
// default, preserving Phase 1/2 behavior for configs that don't set them.
package ratelimit

import (
	"sync"
	"time"
)

// Config is the resolved per-agent limit configuration. Zero values disable the
// corresponding control.
type Config struct {
	MaxCalls int           // rate-limit allowance per Window (0 = no rate limit)
	Window   time.Duration // rate-limit sliding window
	SpendCap int           // hard cumulative call ceiling for the session (0 = no cap)
}

// Limiter enforces a Config against a single proxy session. It is safe for
// concurrent use. A nil *Limiter is treated as disabled.
type Limiter struct {
	cfg   Config
	clock func() time.Time

	mu    sync.Mutex
	times []time.Time // timestamps of allowed calls still inside the window
	total int         // cumulative allowed calls (for the spend cap)
}

// New builds a Limiter for the given config. The returned limiter uses the wall
// clock; tests substitute clock.
func New(cfg Config) *Limiter {
	return &Limiter{cfg: cfg, clock: time.Now}
}

// Enabled reports whether any control is configured. A nil limiter is disabled,
// letting callers guard with `if l.Enabled()` exactly like the Phase 2 validator.
func (l *Limiter) Enabled() bool {
	if l == nil {
		return false
	}
	return l.cfg.MaxCalls > 0 || l.cfg.SpendCap > 0
}

// Allow records and decides a single tool call. It returns ("", true) when the
// call is permitted; otherwise it returns a reason ("spend-cap" or "rate") and
// false. Blocked calls do not consume any budget — they are rejected, not
// counted — so a runaway loop cannot exhaust the spend cap on rejected calls.
//
// The hard spend cap is checked before the rate limit, so when a call violates
// both, the kill-before-runaway reason ("spend-cap") is reported.
func (l *Limiter) Allow() (string, bool) {
	if !l.Enabled() {
		return "", true
	}

	l.mu.Lock()
	defer l.mu.Unlock()

	if l.cfg.SpendCap > 0 && l.total >= l.cfg.SpendCap {
		return "spend-cap", false
	}

	now := l.clock()
	if l.cfg.MaxCalls > 0 {
		l.prune(now)
		if len(l.times) >= l.cfg.MaxCalls {
			return "rate", false
		}
		l.times = append(l.times, now)
	}

	l.total++
	return "", true
}

// prune drops timestamps that have fallen out of the sliding window.
func (l *Limiter) prune(now time.Time) {
	cutoff := now.Add(-l.cfg.Window)
	i := 0
	for i < len(l.times) && !l.times[i].After(cutoff) {
		i++
	}
	if i > 0 {
		l.times = l.times[i:]
	}
}
