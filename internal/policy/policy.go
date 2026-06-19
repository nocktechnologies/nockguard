package policy

import (
	"fmt"
	"log"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/nocktechnologies/nockguard/internal/audit"
	"github.com/nocktechnologies/nockguard/internal/forward"
	"github.com/nocktechnologies/nockguard/internal/ratelimit"
	"github.com/nocktechnologies/nockguard/internal/trust"
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
	// SignKeyEnv names the environment variable holding the HMAC key that makes
	// the trail tamper-evident (Phase 4 3/3). Empty = unsigned. The key is never
	// stored in the policy file; an enabled value that does not resolve fails loud.
	SignKeyEnv string `yaml:"sign_key_env"`
	// SignEd25519KeyEnv names the environment variable holding a hex-encoded
	// Ed25519 private key (32-byte seed or 64-byte key) for NON-REPUDIABLE signing.
	// When set it takes precedence over SignKeyEnv: the trail is verified with the
	// corresponding PUBLIC key, which cannot forge entries, so a passing
	// verification proves who signed. Empty = fall back to HMAC or unsigned. The
	// key is never stored in the policy file; an unresolved value fails loud.
	SignEd25519KeyEnv string `yaml:"sign_ed25519_key_env"`
	// Forward optionally streams enforcement decisions to the NockCC ops-log.
	Forward *ForwardPolicy `yaml:"forward"`
}

// ForwardPolicy configures forwarding of enforcement decisions (deny / block /
// ratelimit) to the NockCC ops-log. The API key is read from the named
// environment variable rather than stored in the policy file.
type ForwardPolicy struct {
	Enabled   bool   `yaml:"enabled"`
	URL       string `yaml:"url"`
	APIKeyEnv string `yaml:"api_key_env"`
}

// DefaultAuditPath is where the audit trail is written when audit is enabled
// without an explicit path.
const DefaultAuditPath = ".nockguard/logs/audit.jsonl"

type AgentPolicy struct {
	Allow []string `yaml:"allow"`
	Deny  []string `yaml:"deny"`
	// Shadow is a dry-run allowlist. A miss is recorded as a would-deny basis
	// while preserving the live verdict, so observe mode can measure an enforce
	// allowlist before a human flips mode to deny.
	Shadow []string `yaml:"shadow"`
	// Ask holds tools for a human verdict as a policy-engine-native approval
	// verdict. RequireApproval remains below as the legacy Phase 5 gate so
	// existing policy files keep their original tool-list visibility.
	Ask      []string `yaml:"ask"`
	FailMode string   `yaml:"fail_mode"`
	Mode     string   `yaml:"mode"` // "allow" or "deny"
	// Phase 2 input validation (opt-in). ValidateInput lists built-in rule
	// categories ("sqli", "path_traversal", "secrets"); BlockParams adds
	// custom regexes. Empty = no validation (Phase 1 behavior preserved).
	ValidateInput []string `yaml:"validate_input"`
	BlockParams   []string `yaml:"block_params"`
	// Phase 3 rate limiting + spend caps (opt-in). Both nil = no limiting
	// (Phase 1/2 behavior preserved).
	RateLimit *RateLimitPolicy `yaml:"rate_limit"`
	SpendCap  *SpendCapPolicy  `yaml:"spend_cap"`
	// Behavioral trust scoring is opt-in. When enabled, audit decisions persist
	// to ~/.nockguard/trust/<agent>.json and scale the rate_limit cap.
	Trust *TrustPolicy `yaml:"trust"`
	// Phase 5 interactive approval gates (opt-in). Tool patterns that require a
	// human nod before the call is forwarded upstream, even when the tool is
	// allowed by policy. Empty = no approval gate (Phase 1-4 behavior preserved).
	RequireApproval []string `yaml:"require_approval"`
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

type TrustPolicy struct {
	Enabled bool   `yaml:"enabled"`
	Path    string `yaml:"path"`
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

// SigningKeyEnvNames returns the names of the environment variables that hold
// the audit signing secret (the Ed25519 seed and/or the HMAC key), as configured
// in the policy. The proxy strips these from the upstream child's environment so
// the policed agent cannot read the seed from its own /proc/self/environ and forge
// the audit trail. The key value itself is parsed into the Auditor at startup, so
// the child never needs the variable. Returns nil when audit signing is unset.
func (e *Engine) SigningKeyEnvNames() []string {
	if e.config.Audit == nil {
		return nil
	}
	var names []string
	if n := e.config.Audit.SignEd25519KeyEnv; n != "" {
		names = append(names, n)
	}
	if n := e.config.Audit.SignKeyEnv; n != "" {
		names = append(names, n)
	}
	return names
}

// HasPolicyFor reports whether an explicit policy governs the given agent —
// either a named entry or a "default" fallback. When false, Check fails CLOSED
// (denies every tool), so callers should warn loudly at startup that the agent
// is unconfigured rather than let the deny-all surprise the operator.
func (e *Engine) HasPolicyFor(agent string) bool {
	if _, ok := e.config.Agents[agent]; ok {
		return true
	}
	_, ok := e.config.Agents["default"]
	return ok
}

type Verdict int

const (
	Allow Verdict = iota
	Deny
	Ask
)

func (v Verdict) String() string {
	switch v {
	case Allow:
		return "allow"
	case Deny:
		return "deny"
	case Ask:
		return "ask"
	default:
		return fmt.Sprintf("unknown(%d)", int(v))
	}
}

// StateWrite is an explicit side-effect intent produced by policy evaluation.
// The proxy applies these only after an Ask verdict is approved; denied or timed
// out approval prompts drop them.
type StateWrite struct {
	Label string
	State string
}

func (w StateWrite) Reason() string {
	if w.Label == "" && w.State == "" {
		return "state-write"
	}
	if w.Label == "" {
		return w.State
	}
	if w.State == "" {
		return w.Label
	}
	return w.Label + " " + w.State
}

// Decision is the outcome of evaluating a (agent, tool) pair against policy. It
// carries not just the allow/deny verdict but the BASIS for it — which rule
// matched, or that none did — so the audit trail can name WHY a call was allowed
// or denied instead of recording an opaque "policy". Every enforcement decision
// points back at its source rule; this is the explainability layer.
type Decision struct {
	Verdict Verdict
	// Reason is a short, audit-ready phrase naming the basis for the verdict,
	// e.g. `deny-rule "*delete*"`, `allow-rule "nockcc_nock_*"`,
	// "no allow-rule matched", "default-allow (no allow list)", or
	// "no policy for agent (fail-closed)".
	Reason   string
	Withheld []StateWrite
	// ShadowWouldDeny marks a dry-run Shadow allowlist miss. It never changes
	// Verdict; callers record it as a separate would-deny audit event.
	ShadowWouldDeny bool
}

func (d Decision) Allowed() bool {
	return d.Verdict == Allow
}

// Evaluate resolves the policy decision for a (agent, tool) pair AND its basis.
// It mirrors Check's precedence exactly — explicit deny first, then the allow
// list (present ⇒ must match), then mode/default — but returns the matching rule
// so callers can record a non-opaque audit reason. Check delegates here, so the
// boolean verdict and the reason can never drift apart.
func (e *Engine) Evaluate(agent, tool string) Decision {
	pol, ok := e.config.Agents[agent]
	if !ok {
		pol, ok = e.config.Agents["default"]
		if !ok {
			// Fail CLOSED: an agent with no named policy and no "default" is
			// unrecognized, so denying every tool is the only safe reading of
			// "default-deny". (Previously Check returned true — allow-everything —
			// which silently unrestricted any unconfigured --agent value.)
			return Decision{Verdict: Deny, Reason: "no policy for agent (fail-closed)"}
		}
	}

	shadowMiss := len(pol.Shadow) > 0 && !matchesAny(pol.Shadow, tool)

	withShadow := func(dec Decision) Decision {
		if shadowMiss && dec.Verdict == Allow {
			dec.ShadowWouldDeny = true
			dec.Reason = dec.Reason + "; would-deny shadow (no shadow-rule matched)"
		}
		return dec
	}

	for _, pattern := range pol.Deny {
		if matchPattern(pattern, tool) {
			return Decision{Verdict: Deny, Reason: fmt.Sprintf("deny-rule %q", pattern)}
		}
	}

	for _, pattern := range pol.Ask {
		if matchPattern(pattern, tool) {
			reason := fmt.Sprintf("ask-rule %q", pattern)
			return Decision{
				Verdict:  Ask,
				Reason:   reason,
				Withheld: []StateWrite{{Label: "approval-state", State: "approved for " + reason}},
			}
		}
	}

	if len(pol.Allow) > 0 {
		for _, pattern := range pol.Allow {
			if matchPattern(pattern, tool) {
				return withShadow(Decision{Verdict: Allow, Reason: fmt.Sprintf("allow-rule %q", pattern)})
			}
		}
		return Decision{Verdict: Deny, Reason: "no allow-rule matched"}
	}

	if pol.Mode == "deny" {
		return Decision{Verdict: Deny, Reason: `mode "deny", no allow list`}
	}
	return withShadow(Decision{Verdict: Allow, Reason: "default-allow (no allow list)"})
}

// Check reports whether a (agent, tool) call is permitted. It is the boolean
// view of Evaluate, preserved for callers that only need the verdict.
func (e *Engine) Check(agent, tool string) bool {
	return e.Evaluate(agent, tool).Allowed()
}

// RequiresApproval reports whether a (agent, tool) call must be held for a human
// nod before it is forwarded upstream. This is the Phase 5 third gate: it is
// independent of Check (a tool can be allowed AND still require approval).
// Absence of any require_approval rule (or no policy for the agent and no
// "default") means no approval gate — Phase 1-4 behavior is preserved.
func (e *Engine) RequiresApproval(agent, tool string) bool {
	pol, ok := e.config.Agents[agent]
	if !ok {
		pol, ok = e.config.Agents["default"]
		if !ok {
			return false
		}
	}
	for _, pattern := range pol.RequireApproval {
		if matchPattern(pattern, tool) {
			return true
		}
	}
	return false
}

func (e *Engine) FailModeVerdict(agent, reason string) Decision {
	pol, ok := e.config.Agents[agent]
	if !ok {
		pol, ok = e.config.Agents["default"]
		if !ok {
			return Decision{Verdict: Deny, Reason: reason}
		}
	}
	if pol.FailMode == "ask" {
		return Decision{
			Verdict:  Ask,
			Reason:   reason,
			Withheld: []StateWrite{{Label: "approval-state", State: "approved for " + reason}},
		}
	}
	return Decision{Verdict: Deny, Reason: reason}
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

// TrustFor builds the opt-in behavioral trust accumulator for an agent. Missing
// or disabled trust config returns nil, preserving the previous static limiter
// behavior.
func (e *Engine) TrustFor(agent string) (*trust.Accumulator, error) {
	if !ValidAgentName(agent) {
		return nil, fmt.Errorf("invalid agent name %q: only alphanumerics, hyphens, and dots are allowed", agent)
	}
	pol, ok := e.config.Agents[agent]
	if !ok {
		pol = e.config.Agents["default"]
	}
	if pol.Trust == nil || !pol.Trust.Enabled {
		return nil, nil
	}
	return trust.New(trust.Config{
		Enabled: true,
		Path:    pol.Trust.Path,
		Agent:   agent,
	})
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
	return e.auditorAt(path)
}

// AuditorAt builds an Auditor at an explicit path while reusing the policy's
// existing signing-key configuration. It is used by CLI modes that accept an
// --audit path override but must keep the same signed-chain semantics.
func (e *Engine) AuditorAt(path string) (*audit.Auditor, error) {
	if path == "" {
		return e.Auditor()
	}
	return e.auditorAt(path)
}

func (e *Engine) auditorAt(path string) (*audit.Auditor, error) {
	var opts []audit.Option
	// Ed25519 (non-repudiable) takes precedence over HMAC when both are configured.
	if e.config.Audit != nil && e.config.Audit.SignEd25519KeyEnv != "" {
		env := e.config.Audit.SignEd25519KeyEnv
		raw := os.Getenv(env)
		if raw == "" {
			return nil, fmt.Errorf("audit.sign_ed25519_key_env %q is not set in the environment", env)
		}
		priv, err := audit.PrivateKeyFromHex(raw)
		if err != nil {
			return nil, fmt.Errorf("audit.sign_ed25519_key_env %q: %w", env, err)
		}
		opts = append(opts, audit.WithEd25519Key(priv))
	} else if e.config.Audit != nil && e.config.Audit.SignKeyEnv != "" {
		env := e.config.Audit.SignKeyEnv
		key := os.Getenv(env)
		if key == "" {
			return nil, fmt.Errorf("audit.sign_key_env %q is not set in the environment", env)
		}
		opts = append(opts, audit.WithSigningKey([]byte(key)))
	}
	return audit.New(path, opts...)
}

// ValidAgentName reports whether an agent name is safe to embed in environment
// variable names and file-system paths. Only alphanumerics, hyphens, and dots
// are accepted — this matches every real fleet agent name (kit, mira-nockos,
// mar-nockos, …) and excludes path separators or traversal sequences.
func ValidAgentName(agent string) bool {
	if agent == "" {
		return false
	}
	for _, r := range agent {
		if !((r >= 'a' && r <= 'z') || (r >= 'A' && r <= 'Z') || (r >= '0' && r <= '9') || r == '-' || r == '.') {
			return false
		}
	}
	return true
}

// AgentKeyEnvName returns the canonical environment variable name for an
// agent's Ed25519 private key seed. Hyphens and dots in the agent name are
// replaced with underscores and the result is uppercased:
//
//	mira-nockos → NOCKGUARD_AGENT_MIRA_NOCKOS_ED25519_KEY
func AgentKeyEnvName(agent string) string {
	upper := strings.ToUpper(strings.NewReplacer("-", "_", ".", "_").Replace(agent))
	return "NOCKGUARD_AGENT_" + upper + "_ED25519_KEY"
}

// AgentPubKeyEnvName returns the canonical environment variable name for an
// agent's Ed25519 public key (the verifier-side counterpart of AgentKeyEnvName).
func AgentPubKeyEnvName(agent string) string {
	upper := strings.ToUpper(strings.NewReplacer("-", "_", ".", "_").Replace(agent))
	return "NOCKGUARD_AGENT_" + upper + "_ED25519_PUB"
}

// AgentAuditPath derives the per-agent audit file path from the shared base
// path by inserting the agent name before the filename:
//
//	~/.nockguard/logs/audit.jsonl, "kit" → ~/.nockguard/logs/kit.audit.jsonl
//
// Defense-in-depth: even if the caller skips ValidAgentName, filepath.Base
// strips any leading path components from the agent string so it cannot
// traverse outside dir.
func AgentAuditPath(basePath, agent string) string {
	dir := filepath.Dir(basePath)
	base := filepath.Base(basePath)
	safeAgent := filepath.Base(filepath.Clean(agent))
	if safeAgent == "." || safeAgent == ".." || safeAgent == "" {
		safeAgent = "unknown-agent"
	}
	return filepath.Join(dir, safeAgent+"."+base)
}

// AuditorFor builds an Auditor for a specific agent. When the agent has its own
// Ed25519 key set via the env var returned by AgentKeyEnvName, that key is used
// and the trail is written to an agent-specific path (AgentAuditPath). When no
// per-agent key is set, AuditorFor falls back to the policy-wide Auditor.
func (e *Engine) AuditorFor(agent string) (*audit.Auditor, error) {
	if !ValidAgentName(agent) {
		return nil, fmt.Errorf("invalid agent name %q: only alphanumerics, hyphens, and dots are allowed", agent)
	}
	// Check audit enabled first — no point parsing a key we won't use.
	if e.config.Audit == nil || !e.config.Audit.Enabled {
		return audit.New("")
	}
	envName := AgentKeyEnvName(agent)
	raw := os.Getenv(envName)
	if raw == "" {
		return e.Auditor()
	}
	priv, err := audit.PrivateKeyFromHex(raw)
	if err != nil {
		return nil, fmt.Errorf("per-agent key %q: %w", envName, err)
	}
	path := e.config.Audit.Path
	if path == "" {
		home, err := os.UserHomeDir()
		if err != nil {
			return nil, err
		}
		path = filepath.Join(home, DefaultAuditPath)
	}
	return audit.New(AgentAuditPath(path, agent), audit.WithEd25519Key(priv))
}

// SigningKeyEnvNamesFor extends SigningKeyEnvNames with the per-agent key env
// var for the given agent when it is present in the environment. The proxy uses
// this to strip ALL signing seeds (global + per-agent) from the child process
// before spawning it, so the policed agent cannot read and forge any key.
func (e *Engine) SigningKeyEnvNamesFor(agent string) []string {
	names := e.SigningKeyEnvNames()
	envName := AgentKeyEnvName(agent)
	if os.Getenv(envName) != "" {
		names = append(names, envName)
	}
	return names
}

// Forwarder builds the NockCC ops-log forwarder from config. Returns a disabled
// (nil-safe) forwarder when forwarding is absent or disabled. An enabled forward
// block must specify a url and, if api_key_env is given, that variable must
// resolve — both are checked loud at startup so misconfiguration fails fast
// rather than silently dropping every forward.
func (e *Engine) Forwarder() (*forward.Forwarder, error) {
	if e.config.Audit == nil || e.config.Audit.Forward == nil || !e.config.Audit.Forward.Enabled {
		return forward.New(forward.Config{}), nil
	}
	fc := e.config.Audit.Forward
	if fc.URL == "" {
		return nil, fmt.Errorf("audit.forward.enabled requires a url")
	}
	apiKey := ""
	if fc.APIKeyEnv != "" {
		apiKey = os.Getenv(fc.APIKeyEnv)
		if apiKey == "" {
			return nil, fmt.Errorf("audit.forward.api_key_env %q is not set in the environment", fc.APIKeyEnv)
		}
	}
	return forward.New(forward.Config{
		BaseURL: fc.URL,
		APIKey:  apiKey,
		// A nil logger silently swallows every forward failure, which
		// contradicts the fail-loud posture everywhere else in nockguard:
		// an operator watching an empty Live Wall has no way to learn the
		// POSTs are erroring. Surface forward errors on stderr.
		Logger: log.New(os.Stderr, "[nockguard-forward] ", log.LstdFlags),
	}), nil
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

func matchesAny(patterns []string, tool string) bool {
	for _, pattern := range patterns {
		if matchPattern(pattern, tool) {
			return true
		}
	}
	return false
}
