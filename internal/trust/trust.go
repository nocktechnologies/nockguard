// Package trust tracks per-agent behavioral trust scores and converts them into
// rate-limit multipliers.
//
// The model is intentionally small and auditable: every policy decision nudges
// a score around the neutral baseline of 0.5, with asymmetric punishment
// (allow +0.01, warn -0.02, deny -0.05). Scores decay lazily back to baseline
// over 60 seconds, so an agent that had a bad burst recovers without a timer or
// background goroutine. Consumers opt in by constructing an Accumulator; a nil
// accumulator is disabled and safe to call.
package trust

import (
	"encoding/json"
	"fmt"
	"math"
	"os"
	"path/filepath"
	"sync"
	"time"
)

const (
	Baseline    = 0.5
	DefaultHalf = 60 * time.Second

	OutcomeAllow Outcome = "allow"
	OutcomeWarn  Outcome = "warn"
	OutcomeDeny  Outcome = "deny"
)

type Outcome string

type Tier string

const (
	TierExcellent  Tier = "excellent"
	TierNormal     Tier = "normal"
	TierReduced    Tier = "reduced"
	TierRestricted Tier = "restricted"
)

type Config struct {
	Enabled bool
	Path    string
	Agent   string
}

type Option func(*Accumulator)

type Accumulator struct {
	mu      sync.Mutex
	path    string
	score   float64
	updated time.Time
	clock   func() time.Time
	enabled bool
}

type snapshot struct {
	Agent     string  `json:"agent,omitempty"`
	Score     float64 `json:"score"`
	UpdatedAt string  `json:"updated_at"`
}

func New(cfg Config, opts ...Option) (*Accumulator, error) {
	a := &Accumulator{
		path:    cfg.Path,
		score:   Baseline,
		clock:   time.Now,
		enabled: cfg.Enabled,
	}
	for _, opt := range opts {
		opt(a)
	}
	if !a.enabled {
		return a, nil
	}
	if a.path == "" {
		home, err := os.UserHomeDir()
		if err != nil {
			return nil, err
		}
		a.path = filepath.Join(home, ".nockguard", "trust", safeAgentName(cfg.Agent)+".json")
	}
	a.updated = a.clock().UTC()
	if err := a.load(); err != nil {
		return nil, err
	}
	return a, nil
}

func WithClock(clock func() time.Time) Option {
	return func(a *Accumulator) {
		if clock != nil {
			a.clock = clock
		}
	}
}

func (a *Accumulator) Enabled() bool {
	return a != nil && a.enabled
}

func (a *Accumulator) Score() float64 {
	if !a.Enabled() {
		return Baseline
	}
	a.mu.Lock()
	defer a.mu.Unlock()
	a.decayTo(a.clock().UTC())
	_ = a.save()
	return a.score
}

func (a *Accumulator) ApplyOutcome(outcome Outcome) float64 {
	if !a.Enabled() {
		return Baseline
	}
	a.mu.Lock()
	defer a.mu.Unlock()
	a.decayTo(a.clock().UTC())
	switch outcome {
	case OutcomeAllow:
		a.score += 0.01
	case OutcomeWarn:
		a.score -= 0.02
	case OutcomeDeny:
		a.score -= 0.05
	}
	a.score = clamp(a.score)
	_ = a.save()
	return a.score
}

func (a *Accumulator) Tier() Tier {
	return TierFor(a.Score())
}

func (a *Accumulator) Multiplier() float64 {
	return MultiplierFor(a.Score())
}

func (a *Accumulator) RateLimitFor(baseMax int) int {
	if !a.Enabled() {
		return baseMax
	}
	return RateLimitForScore(baseMax, a.Score())
}

func TierFor(score float64) Tier {
	switch {
	case score >= 0.8:
		return TierExcellent
	case score >= 0.5:
		return TierNormal
	case score >= 0.3:
		return TierReduced
	default:
		return TierRestricted
	}
}

func MultiplierFor(score float64) float64 {
	switch TierFor(score) {
	case TierExcellent:
		return 2.0
	case TierNormal:
		return 1.0
	case TierReduced:
		return 0.5
	default:
		return 0.1
	}
}

func RateLimitForScore(baseMax int, score float64) int {
	if baseMax <= 0 {
		return baseMax
	}
	adjusted := int(math.Ceil(float64(baseMax) * MultiplierFor(score)))
	if adjusted < 1 {
		return 1
	}
	return adjusted
}

func DecisionToOutcome(decision string) (Outcome, bool) {
	switch decision {
	case "allow", "approval-granted":
		return OutcomeAllow, true
	case "warn", "ratelimit", "block", "approval-denied":
		return OutcomeWarn, true
	case "deny":
		return OutcomeDeny, true
	default:
		return "", false
	}
}

func (a *Accumulator) load() error {
	if a.path == "" {
		return nil
	}
	data, err := os.ReadFile(a.path)
	if err != nil {
		if os.IsNotExist(err) {
			return a.save()
		}
		return err
	}
	var s snapshot
	if err := json.Unmarshal(data, &s); err != nil {
		return err
	}
	if s.UpdatedAt != "" {
		t, err := time.Parse(time.RFC3339Nano, s.UpdatedAt)
		if err != nil {
			return fmt.Errorf("trust updated_at: %w", err)
		}
		a.updated = t.UTC()
	}
	a.score = clamp(s.Score)
	return nil
}

func (a *Accumulator) save() error {
	if a.path == "" {
		return nil
	}
	if err := os.MkdirAll(filepath.Dir(a.path), 0o755); err != nil {
		return err
	}
	data, err := json.MarshalIndent(snapshot{
		Score:     a.score,
		UpdatedAt: a.updated.UTC().Format(time.RFC3339Nano),
	}, "", "  ")
	if err != nil {
		return err
	}
	err = os.WriteFile(a.path, append(data, '\n'), 0o644)
	return err
}

func (a *Accumulator) decayTo(now time.Time) {
	if a.updated.IsZero() {
		a.updated = now
		return
	}
	if !now.After(a.updated) || a.score == Baseline {
		a.updated = now
		return
	}
	elapsed := now.Sub(a.updated)
	if elapsed >= DefaultHalf {
		a.score = Baseline
		a.updated = now
		return
	}
	progress := float64(elapsed) / float64(DefaultHalf)
	a.score = Baseline + (a.score-Baseline)*(1-progress)
	a.score = clamp(a.score)
	a.updated = now
}

func clamp(v float64) float64 {
	if v < 0 {
		return 0
	}
	if v > 1 {
		return 1
	}
	return v
}

func safeAgentName(agent string) string {
	name := filepath.Base(filepath.Clean(agent))
	if name == "." || name == ".." || name == "" {
		return "unknown-agent"
	}
	return name
}
