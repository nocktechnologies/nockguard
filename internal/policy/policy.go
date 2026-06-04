package policy

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/nocktechnologies/nockguard/internal/audit"
	"github.com/nocktechnologies/nockguard/internal/ratelimit"
	"github.com/nocktechnologies/nockguard/internal/validate"
	"gopkg.in/yaml.v3"
)

type Config struct {
	Agents map[string]AgentPolicy `yaml:"agents"`
	// Phase 4 audit trail (opt-in, proxy-wide). Absent or enabled=false = no
	// audit file (Phase 1/2/3 behavior preserved).
	Audit *AuditPolicy `yaml:"audit"`
}

// AuditPolicy configures the structured JSONL audit trail. Path defaults to
// ~/.nockguard/logs/audit.jsonl when omitted.
type AuditPolicy struct {
	Enabled bool   `yaml:"enabled"`
	Path    string `yaml:"path"`
}

// DefaultAuditPath is where the audit trail is written when audit is enabled
// without an explicit path.
const DefaultAuditPath = ".nockguard/logs/audit.jsonl"

type AgentPolicy struct {
	Allow []string `yaml:"allow"`
	Deny  []string `yaml:"deny"`
	Mode  string   `yaml:"mode"` // "allow" or "deny"
	// Phase 2 input validation (opt-in). ValidateInput lists built-in rule
	// categories ("sqli", "path_traversal", "secrets"); BlockParams adds
	// custom regexes. Empty = no validation (Phase 1 behavior preserved).
	ValidateInput []string `yaml:"validate_input"`
	BlockParams   []string `yaml:"block_params"`
	// Phase 3 rate limiting + spend caps (opt-in). Both nil = no limiting
	// (Phase 1/2 behavior preserved).
	RateLimit *RateLimitPolicy `yaml:"rate_limit"`
	SpendCap  *SpendCapPolicy  `yaml:"spend_cap"`
}

// RateLimitPolicy bounds tool-call rate: at most MaxCalls within Window (a Go
// duration string, e.g. "1m", "30s", "1h"). The allowance refills as the window
// slides.
type RateLimitPolicy struct {
	MaxCalls int    `yaml:"max_calls"`
	Window   string `yaml:"window"`
}

// SpendCapPolicy is a hard cumulative ceiling on tool calls for the whole proxy
// session. It never refills.
type SpendCapPolicy struct {
	MaxCalls int `yaml:"max_calls"`
}

type Engine struct {
	config Config
}

func Load(path string) (*Engine, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var cfg Config
	if err := yaml.Unmarshal(data, &cfg); err != nil {
		return nil, err
	}
	return &Engine{config: cfg}, nil
}

func (e *Engine) Check(agent, tool string) bool {
	pol, ok := e.config.Agents[agent]
	if !ok {
		pol, ok = e.config.Agents["default"]
		if !ok {
			return true
		}
	}

	for _, pattern := range pol.Deny {
		if matchPattern(pattern, tool) {
			return false
		}
	}

	if len(pol.Allow) > 0 {
		for _, pattern := range pol.Allow {
			if matchPattern(pattern, tool) {
				return true
			}
		}
		return false
	}

	if pol.Mode == "deny" {
		return false
	}
	return true
}

// ValidatorFor builds the input validator for an agent (falling back to the
// "default" policy). Returns a nil validator if the agent has no validation
// configured — callers should treat a nil/disabled validator as "no checks".
func (e *Engine) ValidatorFor(agent string) (*validate.Validator, error) {
	pol, ok := e.config.Agents[agent]
	if !ok {
		pol = e.config.Agents["default"]
	}
	if len(pol.ValidateInput) == 0 && len(pol.BlockParams) == 0 {
		return nil, nil
	}
	return validate.New(pol.ValidateInput, pol.BlockParams)
}

// LimiterFor builds the Phase 3 rate/spend limiter for an agent (falling back
// to the "default" policy). Returns a nil limiter when neither control is
// configured — callers guard with limiter.Enabled() (nil-safe), exactly like
// ValidatorFor. A rate_limit with a missing or unparseable window is a
// misconfiguration and returns an error so it fails loud at startup.
func (e *Engine) LimiterFor(agent string) (*ratelimit.Limiter, error) {
	pol, ok := e.config.Agents[agent]
	if !ok {
		pol = e.config.Agents["default"]
	}
	if pol.RateLimit == nil && pol.SpendCap == nil {
		return nil, nil
	}

	var cfg ratelimit.Config
	if pol.RateLimit != nil {
		if pol.RateLimit.Window == "" {
			return nil, fmt.Errorf("rate_limit for agent %q requires a window (e.g. \"1m\")", agent)
		}
		window, err := time.ParseDuration(pol.RateLimit.Window)
		if err != nil {
			return nil, fmt.Errorf("rate_limit window %q for agent %q: %w", pol.RateLimit.Window, agent, err)
		}
		cfg.MaxCalls = pol.RateLimit.MaxCalls
		cfg.Window = window
	}
	if pol.SpendCap != nil {
		cfg.SpendCap = pol.SpendCap.MaxCalls
	}
	return ratelimit.New(cfg), nil
}

// Auditor builds the Phase 4 audit trail sink from config. Returns a disabled
// (nil-safe) Auditor when audit is absent or disabled. An enabled audit block
// with no path falls back to ~/.nockguard/logs/audit.jsonl.
func (e *Engine) Auditor() (*audit.Auditor, error) {
	if e.config.Audit == nil || !e.config.Audit.Enabled {
		return audit.New("")
	}
	path := e.config.Audit.Path
	if path == "" {
		home, err := os.UserHomeDir()
		if err != nil {
			return nil, err
		}
		path = filepath.Join(home, DefaultAuditPath)
	}
	return audit.New(path)
}

func (e *Engine) FilterTools(agent string, tools []string) []string {
	var allowed []string
	for _, t := range tools {
		if e.Check(agent, t) {
			allowed = append(allowed, t)
		}
	}
	return allowed
}

func matchPattern(pattern, tool string) bool {
	if strings.Contains(pattern, "*") {
		matched, _ := filepath.Match(pattern, tool)
		return matched
	}
	return pattern == tool
}
