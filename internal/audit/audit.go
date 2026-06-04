// Package audit implements NockGuard Phase 4: a structured, append-only audit
// trail of policy decisions, written as JSON Lines.
//
// Each tool-call decision the proxy makes (allow / deny / block / ratelimit /
// hide) is recorded as one JSON object per line at a configured path
// (default ~/.nockguard/logs/audit.jsonl). This turns the firewall from a gate
// into an accountable record — what each agent attempted and what the policy
// did about it.
//
// Deliberate omission: NockGuard does NOT write raw tool-call parameters to the
// audit file. Logging arguments would persist exactly the secrets and injection
// payloads that Phase 2 input-validation exists to keep out — so the trail
// records the decision (agent, tool, outcome, reason), not the payload.
//
// Auditing is opt-in: an empty path yields a disabled, nil-safe Auditor, and a
// disabled Auditor's Record is a no-op. Audit writes never block or fail a tool
// call — a write error is returned to the caller (which logs and proceeds);
// auditing is fail-open by design.
package audit

import (
	"encoding/json"
	"os"
	"path/filepath"
	"sync"
	"time"
)

// Event is one recorded policy decision. Time is stamped by the Auditor.
type Event struct {
	Time     string `json:"ts"`
	Agent    string `json:"agent"`
	Tool     string `json:"tool"`
	Decision string `json:"decision"` // allow | deny | block | ratelimit | hide
	Reason   string `json:"reason,omitempty"`
}

// Auditor appends Events as JSON Lines to a file. It is safe for concurrent use.
// A nil *Auditor and one built from an empty path are both disabled.
type Auditor struct {
	clock func() time.Time

	mu sync.Mutex
	f  *os.File
}

// New opens (creating parent dirs as needed) the audit file at path in append
// mode. An empty path returns a disabled Auditor (no file opened).
func New(path string) (*Auditor, error) {
	if path == "" {
		return &Auditor{clock: time.Now}, nil
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return nil, err
	}
	f, err := os.OpenFile(path, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o644)
	if err != nil {
		return nil, err
	}
	return &Auditor{clock: time.Now, f: f}, nil
}

// Enabled reports whether the Auditor is writing to a file. Nil-safe, so callers
// can guard with `if a.Enabled()` exactly like the validator and limiter.
func (a *Auditor) Enabled() bool {
	return a != nil && a.f != nil
}

// Record stamps the event with the current time and appends it as one JSON line.
// It is a no-op on a disabled (or nil) Auditor. The write is serialized so that
// concurrent records never interleave within a line.
func (a *Auditor) Record(ev Event) error {
	if !a.Enabled() {
		return nil
	}
	ev.Time = a.clock().Format(time.RFC3339)
	line, err := json.Marshal(ev)
	if err != nil {
		return err
	}
	line = append(line, '\n')

	a.mu.Lock()
	defer a.mu.Unlock()
	_, err = a.f.Write(line)
	return err
}

// Close flushes and closes the underlying file. Safe to call on a disabled Auditor.
func (a *Auditor) Close() error {
	if !a.Enabled() {
		return nil
	}
	a.mu.Lock()
	defer a.mu.Unlock()
	err := a.f.Close()
	a.f = nil
	return err
}
