// Package approval is the Phase 5 interactive approval gate. When a tool call has
// cleared policy, validation and rate/spend limits but matches an agent's
// require_approval patterns, the proxy HOLDS it and asks an Approver for a human
// verdict before forwarding it upstream. Fail-safe: any approver that cannot get
// an affirmative answer (timeout, transport error) must return Approved=false, so
// a missed prompt never auto-approves a consequential call.
package approval

import "encoding/json"

// Request is a held tool call awaiting a human verdict.
type Request struct {
	Agent  string
	Tool   string
	Params json.RawMessage
}

// Verdict is the human (or fail-safe) answer. Reason is recorded in the audit
// trail — e.g. "approved", "denied", "timeout", "transport-error".
type Verdict struct {
	Approved bool
	Reason   string
}

// Approver decides whether a held call may proceed. Implementations MUST fail
// safe (return Approved=false) when they cannot obtain an affirmative answer.
type Approver interface {
	Ask(Request) Verdict
}

// StaticApprover always returns the same verdict. It is the fail-safe default and
// the deterministic seam used by end-to-end tests (and an explicit, audited
// "auto-approve"/"auto-deny" policy mode if a deployment ever wants one).
type StaticApprover struct {
	verdict Verdict
}

// NewStaticApprover builds an Approver that always answers with approved/reason.
func NewStaticApprover(approved bool, reason string) *StaticApprover {
	return &StaticApprover{verdict: Verdict{Approved: approved, Reason: reason}}
}

// Ask returns the fixed verdict.
func (s *StaticApprover) Ask(Request) Verdict { return s.verdict }

// Environment variable names for the Phase 5 approval gate. EnvBotToken and
// EnvChatID carry the DEDICATED Telegram approval bot's secrets; EnvTestSeam is
// the deterministic e2e seam (approve|deny). All three are read by the PROXY
// process itself at startup (buildApprover) to construct the approver, which
// runs IN the proxy — so the upstream MCP child NEVER needs them. Single source
// of truth: main.go reads via these names, and the proxy strips the same names
// from the child's environment (see CredEnvNames).
const (
	EnvBotToken = "NOCKGUARD_APPROVAL_BOT_TOKEN"
	EnvChatID   = "NOCKGUARD_APPROVAL_CHAT_ID"
	EnvTestSeam = "NOCKGUARD_APPROVAL_TEST"
)

// CredEnvNames returns the environment variable names carrying approval-gate
// credentials, for the proxy to strip from the upstream child's environment.
// These are PROXY-ONLY secrets: the approver runs in the proxy process (its own
// os.Getenv is unaffected by sanitizing the child's cmd.Env), so the child never
// needs them — and a compromised or malicious child that COULD read the bot
// token/chat could drive Telegram approve/callback APIs to self-approve a
// human-gated call, defeating the gate. Mirrors the audit signing-seed isolation
// (policy.SigningKeyEnvNamesFor). EnvTestSeam is stripped too so a child can
// never forge the deterministic approve/deny seam.
func CredEnvNames() []string {
	return []string{EnvBotToken, EnvChatID, EnvTestSeam}
}
