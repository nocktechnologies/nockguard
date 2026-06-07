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
