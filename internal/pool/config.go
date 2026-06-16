// Package pool implements the NockGuard pool router configuration (V1
// scaffold). The behavioral contract lives in docs/POOL_ROUTER.md — code that
// diverges from that document is wrong, not the document.
package pool

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"gopkg.in/yaml.v3"
)

// Config is the root of pool.yaml.
type Config struct {
	Pool PoolConfig `yaml:"pool"`
}

// PoolConfig declares the listener, upstream accounts, and routing knobs.
type PoolConfig struct {
	// Listen is the bind address. V1 refuses non-loopback binds unless the
	// operator sets AllowNonLocal explicitly — spending credentials is the
	// blast radius, so localhost is the default posture, same as the Wall.
	Listen        string           `yaml:"listen"`
	AllowNonLocal bool             `yaml:"allow_non_local"`
	Upstreams     []UpstreamConfig `yaml:"upstreams"`
	Routing       RoutingConfig    `yaml:"routing"`
	Budget        BudgetConfig     `yaml:"budget"`
}

// UpstreamConfig is one subscription account. V1 supports provider "codex"
// (identified by its codex home directory); the provider field exists now so
// a Claude upstream lands later without a breaking config change. The router
// reads (and on refresh, rewrites) the home's auth.json; credentials are
// never copied anywhere else.
type UpstreamConfig struct {
	// Label names this account in audit events and the Wall. It is the only
	// identifier that ever leaves the router — never emails or account ids.
	Label string `yaml:"label"`
	// Provider selects the upstream protocol. Empty defaults to "codex";
	// "claude" is reserved (documented in docs/POOL_ROUTER.md scope fence)
	// and rejected until the V1.5 spike confirms proxy pass-through.
	Provider  string `yaml:"provider"`
	CodexHome string `yaml:"codex_home"`
	// Tier classifies the upstream for budget-aware downgrade routing. Empty
	// means untiered, which is treated as expensive by EffectiveTier so an
	// unclassified model cannot bypass a cap.
	Tier Tier `yaml:"tier"`
	// CostPerCallUSD is the configured estimated cost charged to the root
	// session tree whenever this upstream is selected by RouteWithBudget.
	CostPerCallUSD float64 `yaml:"cost_per_call_usd"`
}

// RoutingConfig holds the V1 routing knobs.
type RoutingConfig struct {
	// Strategy selects the ranking for accounts without a session pin.
	// V1 supports only "headroom" (maximum remaining self-reported quota).
	Strategy string `yaml:"strategy"`
	// CooldownSeconds demotes an upstream after a failure (429/5xx/auth) for
	// this many seconds. 0 means the documented default of 60.
	CooldownSeconds int `yaml:"cooldown_seconds"`
}

// BudgetConfig holds opt-in cost guardrails. Zero MaxCostUSD disables the gate.
type BudgetConfig struct {
	MaxCostUSD       float64   `yaml:"max_cost_usd"`
	AskThresholdsUSD []float64 `yaml:"ask_thresholds_usd"`
}

// Enabled reports whether budget routing is active.
func (b BudgetConfig) Enabled() bool {
	return b.MaxCostUSD > 0
}

const defaultCooldown = 60 * time.Second

// Cooldown returns the effective demotion window.
func (r RoutingConfig) Cooldown() time.Duration {
	if r.CooldownSeconds <= 0 {
		return defaultCooldown
	}
	return time.Duration(r.CooldownSeconds) * time.Second
}

// AuthJSONPath returns the credential file the router reads for this
// upstream, with ~ expanded.
func (u UpstreamConfig) AuthJSONPath() (string, error) {
	home, err := expandHome(u.CodexHome)
	if err != nil {
		return "", err
	}
	return filepath.Join(home, "auth.json"), nil
}

// Load reads and validates pool.yaml. Every failure is loud and names the
// field; a config that half-loads is a config that misroutes spend.
func Load(path string) (*Config, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("pool config: %w", err)
	}
	var cfg Config
	dec := yaml.NewDecoder(strings.NewReader(string(raw)))
	dec.KnownFields(true)
	if err := dec.Decode(&cfg); err != nil {
		return nil, fmt.Errorf("pool config %s: %w", path, err)
	}
	if err := cfg.Validate(); err != nil {
		return nil, fmt.Errorf("pool config %s: %w", path, err)
	}
	return &cfg, nil
}

// Validate enforces the documented V1 contract.
func (c *Config) Validate() error {
	p := c.Pool
	if p.Listen == "" {
		return fmt.Errorf("pool.listen is required (e.g. \"127.0.0.1:4141\")")
	}
	if !p.AllowNonLocal && !isLoopback(p.Listen) {
		return fmt.Errorf("pool.listen %q is not loopback; set allow_non_local: true only if you understand anyone reaching this port can spend your subscriptions", p.Listen)
	}
	if len(p.Upstreams) < 1 {
		return fmt.Errorf("pool.upstreams: at least one upstream is required")
	}
	seenLabel := map[string]bool{}
	seenHome := map[string]bool{}
	for i, u := range p.Upstreams {
		if u.Label == "" {
			return fmt.Errorf("pool.upstreams[%d]: label is required (it names the account in audit events)", i)
		}
		switch u.Provider {
		case "", "codex":
			// "" defaults to codex; recorded explicitly by Normalize.
		case "claude":
			return fmt.Errorf("pool.upstreams[%d] (%s): provider \"claude\" is reserved for V1.5 (pending the subscription proxy spike, docs/POOL_ROUTER.md)", i, u.Label)
		default:
			return fmt.Errorf("pool.upstreams[%d] (%s): unknown provider %q", i, u.Label, u.Provider)
		}
		if u.CodexHome == "" {
			return fmt.Errorf("pool.upstreams[%d] (%s): codex_home is required", i, u.Label)
		}
		if !u.Tier.Valid() {
			return fmt.Errorf("pool.upstreams[%d] (%s): unknown tier %q (want cheap, standard, expensive, or empty)", i, u.Label, u.Tier)
		}
		if u.CostPerCallUSD < 0 {
			return fmt.Errorf("pool.upstreams[%d] (%s): cost_per_call_usd must be >= 0", i, u.Label)
		}
		if seenLabel[u.Label] {
			return fmt.Errorf("pool.upstreams: duplicate label %q", u.Label)
		}
		home, err := expandHome(u.CodexHome)
		if err != nil {
			return fmt.Errorf("pool.upstreams[%d] (%s): %w", i, u.Label, err)
		}
		if seenHome[home] {
			return fmt.Errorf("pool.upstreams: duplicate codex_home %q (two labels, one account would double-spend it)", u.CodexHome)
		}
		seenLabel[u.Label] = true
		seenHome[home] = true
	}
	switch p.Routing.Strategy {
	case "", "headroom":
		// "" defaults to headroom; recorded explicitly by Normalize.
	default:
		return fmt.Errorf("pool.routing.strategy %q is not supported in V1 (only \"headroom\")", p.Routing.Strategy)
	}
	if p.Budget.MaxCostUSD < 0 {
		return fmt.Errorf("pool.budget.max_cost_usd must be >= 0")
	}
	for i, threshold := range p.Budget.AskThresholdsUSD {
		if threshold < 0 {
			return fmt.Errorf("pool.budget.ask_thresholds_usd[%d] must be >= 0", i)
		}
	}
	return nil
}

// Normalize fills documented defaults after validation.
func (c *Config) Normalize() {
	if c.Pool.Routing.Strategy == "" {
		c.Pool.Routing.Strategy = "headroom"
	}
	for i := range c.Pool.Upstreams {
		if c.Pool.Upstreams[i].Provider == "" {
			c.Pool.Upstreams[i].Provider = "codex"
		}
	}
}

func expandHome(p string) (string, error) {
	if p == "~" || strings.HasPrefix(p, "~/") {
		home, err := os.UserHomeDir()
		if err != nil {
			return "", fmt.Errorf("expanding %q: %w", p, err)
		}
		return filepath.Join(home, strings.TrimPrefix(strings.TrimPrefix(p, "~"), "/")), nil
	}
	return p, nil
}

func isLoopback(addr string) bool {
	host := addr
	if i := strings.LastIndex(addr, ":"); i >= 0 {
		host = addr[:i]
	}
	switch host {
	case "127.0.0.1", "::1", "[::1]", "localhost":
		return true
	}
	return strings.HasPrefix(host, "127.")
}
