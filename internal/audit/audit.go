// Package audit implements NockGuard Phase 4: a structured, append-only audit
// trail of policy decisions, written as JSON Lines.
//
// Each tool-call decision the proxy makes (allow / deny / block / ratelimit /
// hide) is recorded as one JSON object per line at a configured path
// (default ~/.nockguard/logs/audit.jsonl). This turns the firewall from a gate
// into an accountable record — what each agent attempted and what the policy
// did about it.
//
// Phase 4 (3/3) — tamper-evidence. When a signing key is supplied, each entry is
// HMAC-SHA256 signed over its canonical content AND the previous entry's
// signature, forming a hash chain. Any edit, deletion, insertion, or reorder of
// the trail breaks the chain and is caught by Verify. The key never lives in the
// policy file (it is read from an environment variable), and signing is opt-in:
// an unsigned trail behaves exactly as before.
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
	"bufio"
	"bytes"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"time"
)

// Event is one recorded policy decision. Time is stamped by the Auditor. Sig, when
// present, is the hex HMAC chain signature over the entry's canonical content
// (every field except Sig) and the previous entry's Sig.
type Event struct {
	Time     string `json:"ts"`
	Agent    string `json:"agent"`
	Tool     string `json:"tool"`
	Decision string `json:"decision"` // allow | deny | block | ratelimit | hide
	Reason   string `json:"reason,omitempty"`
	Sig      string `json:"sig,omitempty"`
}

// Auditor appends Events as JSON Lines to a file. It is safe for concurrent use.
// A nil *Auditor and one built from an empty path are both disabled. When a
// signing key is set, each Record links into a tamper-evident hash chain.
type Auditor struct {
	clock func() time.Time

	mu      sync.Mutex
	f       *os.File
	key     []byte // HMAC signing key; empty = unsigned trail
	prevSig string // last written signature, seeded from the file on open
}

// Option configures an Auditor at construction.
type Option func(*Auditor)

// WithSigningKey enables tamper-evident hash-chain signing with the given key.
// The key is supplied by the caller (read from an environment variable upstream),
// never persisted by this package.
func WithSigningKey(key []byte) Option {
	return func(a *Auditor) { a.key = key }
}

// New opens (creating parent dirs as needed) the audit file at path in append
// mode. An empty path returns a disabled Auditor (no file opened). When signing
// is enabled, the chain is seeded from the last signature already in the file so
// that appends across restarts stay verifiable.
func New(path string, opts ...Option) (*Auditor, error) {
	a := &Auditor{clock: time.Now}
	for _, o := range opts {
		o(a)
	}
	if path == "" {
		return a, nil
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return nil, err
	}
	if len(a.key) > 0 {
		last, err := lastSig(path)
		if err != nil {
			return nil, err
		}
		a.prevSig = last
	}
	f, err := os.OpenFile(path, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o644)
	if err != nil {
		return nil, err
	}
	a.f = f
	return a, nil
}

// Enabled reports whether the Auditor is writing to a file. Nil-safe, so callers
// can guard with `if a.Enabled()` exactly like the validator and limiter.
func (a *Auditor) Enabled() bool {
	return a != nil && a.f != nil
}

// Record stamps the event with the current time and appends it as one JSON line.
// It is a no-op on a disabled (or nil) Auditor. The write is serialized so that
// concurrent records never interleave within a line and the signature chain
// stays consistent.
func (a *Auditor) Record(ev Event) error {
	if !a.Enabled() {
		return nil
	}
	ev.Time = a.clock().Format(time.RFC3339)
	ev.Sig = "" // canonical content never includes the signature itself

	a.mu.Lock()
	defer a.mu.Unlock()

	if len(a.key) > 0 {
		canonical, err := json.Marshal(ev)
		if err != nil {
			return err
		}
		sig := signLine(a.key, canonical, a.prevSig)
		ev.Sig = sig
		a.prevSig = sig
	}

	line, err := json.Marshal(ev)
	if err != nil {
		return err
	}
	line = append(line, '\n')
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

// signLine computes the hex HMAC-SHA256 of an entry's canonical bytes chained to
// the previous signature. The newline separator is unambiguous because canonical
// JSON never contains a raw newline.
func signLine(key, canonical []byte, prev string) string {
	m := hmac.New(sha256.New, key)
	m.Write(canonical)
	m.Write([]byte{'\n'})
	m.Write([]byte(prev))
	return hex.EncodeToString(m.Sum(nil))
}

// lastSig returns the signature of the final non-empty line in the file, or ""
// if the file is absent or empty. Used to seed the chain on open.
func lastSig(path string) (string, error) {
	f, err := os.Open(path)
	if err != nil {
		if os.IsNotExist(err) {
			return "", nil
		}
		return "", err
	}
	defer f.Close()
	sc := bufio.NewScanner(f)
	sc.Buffer(make([]byte, 0, 64*1024), 1024*1024)
	last := ""
	for sc.Scan() {
		if len(bytes.TrimSpace(sc.Bytes())) == 0 {
			continue
		}
		var ev Event
		if err := json.Unmarshal(sc.Bytes(), &ev); err != nil {
			return "", fmt.Errorf("seed chain: %w", err)
		}
		last = ev.Sig
	}
	return last, sc.Err()
}

// Verify walks a signed audit file and checks the hash chain end to end. It
// returns the number of entries verified, or the 1-based line number and an
// error at the first entry whose signature does not match — which happens if any
// entry was edited, deleted, inserted, or reordered, or if the wrong key is used.
func Verify(path string, key []byte) (int, error) {
	f, err := os.Open(path)
	if err != nil {
		return 0, err
	}
	defer f.Close()
	sc := bufio.NewScanner(f)
	sc.Buffer(make([]byte, 0, 64*1024), 1024*1024)
	prev := ""
	n := 0
	for sc.Scan() {
		raw := sc.Bytes()
		if len(bytes.TrimSpace(raw)) == 0 {
			continue
		}
		n++
		var ev Event
		if err := json.Unmarshal(raw, &ev); err != nil {
			return n, fmt.Errorf("line %d: invalid json: %w", n, err)
		}
		got := ev.Sig
		if got == "" {
			return n, fmt.Errorf("line %d: entry is not signed", n)
		}
		ev.Sig = ""
		canonical, err := json.Marshal(ev)
		if err != nil {
			return n, err
		}
		want := signLine(key, canonical, prev)
		if !hmac.Equal([]byte(got), []byte(want)) {
			return n, fmt.Errorf("line %d: signature mismatch — trail was tampered, deleted from, reordered, or signed with a different key", n)
		}
		prev = got
	}
	if err := sc.Err(); err != nil {
		return n, err
	}
	return n, nil
}
