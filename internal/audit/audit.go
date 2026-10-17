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
// disabled Auditor's Record is a no-op. Record returns errors for the caller's
// policy to handle; RecordRequired additionally syncs storage and latches errors.
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
// Auditable references: a small, declared set of MCP tools (nockcc_nock_* tools)
// carry extracted fields in each audit entry that link it to the card or request
// it acted for. These fields — NockID, PR, ReviewID — are extracted from tool
// arguments by the extract package (internal/extract) and are INCLUDED in the
// Ed25519 signature chain, making them tamper-evident proof of what the call acted for.
// Unknown tools and calls never carry these fields; the feature is conservative
// and never guesses.
//
// Deliberate omission: NockGuard does NOT write raw tool-call parameters to the
// audit file. Logging arguments would persist exactly the secrets and injection
// payloads that Phase 2 input-validation exists to keep out — so the trail
// records the decision (agent, tool, outcome, reason), not the payload. Extracted
// references are an exception: they are typed, declared, and never raw arguments.
//
// Auditing is opt-in: an empty path yields a disabled, nil-safe Auditor, and a
// disabled Auditor's Record is a no-op. RecordRequired rejects a disabled writer,
// syncs the trail and checkpoint, and latches write failures. The caller decides
// whether an audit failure must stop a tool call.

package audit

import (
	"bufio"
	"bytes"
	"crypto/ed25519"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"time"
)

// Event is one recorded policy decision. Time is stamped by the Auditor. Sig, when
// present, is the hex HMAC chain signature over the entry's canonical content
// (every field except Sig) and the previous entry's Sig.
//
// Auditable fields (NockID, PR, ReviewID, ParentAuditSeq) are extracted from
// tool-call arguments by declared extractors. These fields are INCLUDED in the
// canonical payload signed by the Ed25519 chain, so they form part of the
// tamper-evident trail. Unknown tools and calls never carry these fields.
//
// SessionID and KeyID (N10647) are additive, omitempty correlation fields.
// SessionID is stamped from NOCKLOCK_SESSION_ID (the nocklock session that
// wrapped this agent, if any) at Record time. KeyID is the signing Ed25519
// key's fingerprint (hex(sha256(pub))), stamped only when the trail is
// Ed25519-signed; it is never present for HMAC or unsigned trails. Both are
// omitted when empty, so an event with neither set marshals byte-identically
// to before this field was added, and existing signed trails still verify.
// When present, both are part of the canonical payload and therefore covered
// by the signature chain like every other field.
type Event struct {
	Time               string `json:"ts"`
	Agent              string `json:"agent"`
	Tool               string `json:"tool"`
	Decision           string `json:"decision"` // dispatch | allow | deny | block | ratelimit | hide
	Reason             string `json:"reason,omitempty"`
	ApprovalActor      string `json:"approval_actor,omitempty"`   // local approver's kernel-authenticated uid; never a tool caller
	NockID             int    `json:"nock_id,omitempty"`          // NockCC card id, extracted from nockcc_nock_* tools or set by session stamp
	PR                 string `json:"pr,omitempty"`               // GitHub PR reference owner/repo#n, extracted from gh_* tools
	ReviewID           string `json:"review_id,omitempty"`        // NockCC review id, extracted from known tools
	ParentAuditSeq     int    `json:"parent_audit_seq,omitempty"` // Reserved for future use; never populated
	SessionID          string `json:"session_id,omitempty"`       // nocklock session correlation, from NOCKLOCK_SESSION_ID
	KeyID              string `json:"key_id,omitempty"`           // hex(sha256(pub)) of the Ed25519 signing key; empty for HMAC/unsigned
	SchemaVersion      int    `json:"schema_version,omitempty"`
	RecordType         string `json:"record_type,omitempty"`
	RunID              string `json:"run_id,omitempty"`
	RunSeq             uint64 `json:"run_seq,omitempty"`
	RunEvent           string `json:"run_event,omitempty"`
	RunCount           uint64 `json:"run_count,omitempty"`
	RunHead            string `json:"run_head,omitempty"`
	ActionID           string `json:"action_id,omitempty"`
	Observation        string `json:"observation,omitempty"`
	Cause              string `json:"cause,omitempty"`
	ResponseClass      string `json:"response_class,omitempty"`
	MCPIsError         *bool  `json:"mcp_is_error,omitempty"`
	ToolHashVersion    string `json:"tool_hash_version,omitempty"`
	ToolDefinitionHash string `json:"tool_definition_hash,omitempty"`
	ToolPinHash        string `json:"tool_pin_hash,omitempty"`
	ToolPinStatus      string `json:"tool_pin_status,omitempty"`
	Sig                string `json:"sig,omitempty"`
}

// nocklockSessionIDEnv is the environment variable nocklock's `wrap` exports
// into the child process carrying the session id to correlate against.
const nocklockSessionIDEnv = "NOCKLOCK_SESSION_ID"

// Auditor appends Events as JSON Lines to a file. It is safe for concurrent use
// both within a process (the mutex) and ACROSS processes when signing is enabled
// (an flock held across each signed append — see Record). A nil *Auditor and one
// built from an empty path are both disabled. When a signing key is set, each
// Record links into a tamper-evident hash chain.
type Auditor struct {
	clock func() time.Time

	mu            sync.Mutex
	f             *os.File
	path          string             // audit file path; used to re-read the on-disk chain head under the flock
	key           []byte             // HMAC signing key; empty = unsigned trail
	edPriv        ed25519.PrivateKey // Ed25519 signing key; non-nil = non-repudiable trail (takes precedence over key)
	keyID         string             // hex(sha256(pub)) of edPriv's public key; stamped on Events when edPriv is set
	runSeqs       map[string]uint64  // last durably appended v2 sequence per fresh process run id
	actionPairing bool               // seed existing v2 run sequences only for the opt-in pairing writer
	closed        bool
	requiredErr   error
}

// Option configures an Auditor at construction.
type Option func(*Auditor)

// WithSigningKey enables tamper-evident hash-chain signing with the given key.
// The key is supplied by the caller (read from an environment variable upstream),
// never persisted by this package.
func WithSigningKey(key []byte) Option {
	return func(a *Auditor) { a.key = key }
}

// WithEd25519Key enables non-repudiable hash-chain signing with the given
// Ed25519 private key. Unlike the symmetric HMAC mode — where the verifier holds
// the same key that produced the signatures and could therefore forge them —
// Ed25519 is asymmetric: only the holder of this private key can sign, and the
// trail is verified with the corresponding PUBLIC key (see VerifyEd25519), which
// cannot produce signatures. That makes the trail non-repudiable: a verifier
// proves WHO signed without ever holding the signing key. Takes precedence over
// WithSigningKey if both are supplied. The key is supplied by the caller (read
// from an environment variable upstream), never persisted by this package.
func WithEd25519Key(priv ed25519.PrivateKey) Option {
	return func(a *Auditor) {
		a.edPriv = priv
		// key_id is computed from the PUBLIC key derived from this private key,
		// never from any env text — see Event.KeyID.
		if pub, ok := priv.Public().(ed25519.PublicKey); ok {
			sum := sha256.Sum256(pub)
			a.keyID = hex.EncodeToString(sum[:])
		}
	}
}

// WithActionPairing enables resuming v2 run sequences from an existing trail.
// The default audit path does not scan unsigned trails on open.
func WithActionPairing() Option {
	return func(a *Auditor) { a.actionPairing = true }
}

// signing reports whether any signing mode is active.
func (a *Auditor) signing() bool {
	return len(a.key) > 0 || a.edPriv != nil
}

// sign produces the hex chain signature for canonical bytes linked to prev,
// using whichever signing mode is configured (Ed25519 takes precedence).
func (a *Auditor) sign(canonical []byte, prev string) string {
	if a.edPriv != nil {
		return signLineEd25519(a.edPriv, canonical, prev)
	}
	return signLine(a.key, canonical, prev)
}

// New opens (creating parent dirs as needed) the audit file at path in append
// mode. An empty path returns a disabled Auditor (no file opened). When signing
// is enabled, the chain is seeded from the last signature already in the file so
// that appends across restarts stay verifiable.
func New(path string, opts ...Option) (*Auditor, error) {
	a := &Auditor{clock: time.Now, runSeqs: make(map[string]uint64)}
	for _, o := range opts {
		o(a)
	}
	if path == "" {
		return a, nil
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return nil, err
	}
	if a.signing() {
		if FailureStatus(path) {
			if _, err := os.Stat(path); err != nil {
				return nil, fmt.Errorf("cannot verify failed audit trail on reopen: %w", err)
			}
		}
		// Verify the existing chain BEFORE the auditor starts appending. Without
		// this, a trail tampered or truncated mid-chain during downtime would be
		// silently accepted: the next append chains onto the broken tail, baking
		// the tamper in as the new baseline so the trail verifies clean from that
		// point on forever. Refuse to open instead — turn a silent permanent
		// corruption into a loud startup failure. The chain head is re-read from
		// the file under a lock on each append (see Record), so there is no
		// in-memory tail to seed here.
		if err := a.verifyExisting(path); err != nil {
			return nil, fmt.Errorf("audit trail %s failed verification on open — refusing to append onto a tampered or broken chain: %w", path, err)
		}
	} else if a.actionPairing {
		// Unsigned v1 users retain the legacy open path. Only the opt-in v2
		// pairing writer needs to scan for a run sequence to resume.
		if err := a.seedRunSequences(path); err != nil {
			return nil, fmt.Errorf("seed audit run sequences: %w", err)
		}
	}
	f, err := os.OpenFile(path, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o644)
	if err != nil {
		return nil, err
	}
	a.f = f
	a.path = path
	if a.signing() {
		// A verified reopen is the required writer's recovery boundary.
		_ = os.Remove(path + ".audit-failing")
	}
	return a, nil
}

// verifyExisting walks the existing trail and confirms the hash chain is intact
// before the auditor starts appending. When action pairing is enabled, it also
// seeds the per-run v2 sequence counters. A missing file is a no-op. For Ed25519
// the public key is derived from the configured private key, so the same
// verification the external `audit verify` command runs is enforced at open time.
func (a *Auditor) verifyExisting(path string) error {
	if _, err := os.Stat(path); err != nil {
		if os.IsNotExist(err) {
			return nil
		}
		return err
	}
	if a.edPriv != nil {
		pub, ok := a.edPriv.Public().(ed25519.PublicKey)
		if !ok {
			return fmt.Errorf("ed25519 private key has no usable public key")
		}
		if _, err := VerifyEd25519(path, pub); err != nil {
			return err
		}
	} else if _, err := Verify(path, a.key); err != nil {
		return err
	}
	if a.actionPairing {
		return a.seedRunSequences(path)
	}
	return nil
}

// seedRunSequences resumes each v2 run counter from its highest existing row.
// Signed trails are verified before this scan. This also preserves sequence
// continuity when an unsigned trail is reopened with the same run id.
func (a *Auditor) seedRunSequences(path string) error {
	f, err := os.Open(path)
	if os.IsNotExist(err) {
		return nil
	}
	if err != nil {
		return err
	}
	defer f.Close()
	scanner := bufio.NewScanner(f)
	scanner.Buffer(make([]byte, 64*1024), 16*1024*1024)
	for scanner.Scan() {
		line := bytes.TrimSpace(scanner.Bytes())
		if len(line) == 0 {
			continue
		}
		var ev Event
		if err := json.Unmarshal(line, &ev); err != nil || ev.SchemaVersion != 2 || validateAuditLine(line, ev) != nil {
			continue
		}
		if ev.RunSeq > a.runSeqs[ev.RunID] {
			a.runSeqs[ev.RunID] = ev.RunSeq
		}
	}
	if err := scanner.Err(); err != nil {
		return fmt.Errorf("seed audit run sequences: %w", err)
	}
	return nil
}

// Enabled reports whether the Auditor is writing to a file. Nil-safe, so callers
// can guard with `if a.Enabled()` exactly like the validator and limiter.
func (a *Auditor) Enabled() bool {
	if a == nil {
		return false
	}
	a.mu.Lock()
	defer a.mu.Unlock()
	return a.f != nil && !a.closed
}

// Record stamps the event with the current time and appends it as one JSON line.
// It is a no-op on a disabled (or nil) Auditor. The write is serialized within the
// process by the mutex; when signing, it is ALSO serialized across processes by an
// flock so that concurrent records never interleave within a line and the
// signature chain stays consistent end to end.
func (a *Auditor) Record(ev Event) error {
	return a.record(ev, false)
}

// RecordRequired writes an event and waits until the trail, and its signed
// high-water mark when signing is enabled, have been synchronized to storage.
// Any record or durability failure is latched: callers must close and reopen
// the auditor, which verifies the on-disk trail, before required writes resume.
func (a *Auditor) RecordRequired(ev Event) error {
	return a.record(ev, true)
}

// FailureStatus reports the last required-audit write failure for a trail.
// Only a verified reopen or an explicit best-effort choice clears the signal.
func FailureStatus(path string) bool {
	_, err := os.Lstat(path + ".audit-failing")
	return !os.IsNotExist(err)
}

// ClearFailureStatus removes the required-writer marker when a caller explicitly
// switches this trail to best-effort audit. It does not reset a latched writer.
func (a *Auditor) ClearFailureStatus() {
	if a != nil && a.path != "" {
		_ = os.Remove(a.path + ".audit-failing")
	}
}

// RequiredError reports known writer failures. A nil result means the writer is
// open and has not latched a failure, not that the next write will succeed.
// RecordRequired must persist the event before its caller forwards a tool call.
func (a *Auditor) RequiredError() error {
	if a == nil {
		return fmt.Errorf("required audit writer unavailable: nil auditor")
	}
	a.mu.Lock()
	defer a.mu.Unlock()
	if a.requiredErr != nil {
		return a.requiredErr
	}
	if a.closed {
		return fmt.Errorf("required audit writer closed")
	}
	if a.f == nil {
		return fmt.Errorf("required audit writer unavailable")
	}
	return nil
}

func (a *Auditor) record(ev Event, required bool) (err error) {
	if a == nil {
		if required {
			return fmt.Errorf("required audit writer unavailable: nil auditor")
		}
		return nil
	}
	a.mu.Lock()
	defer a.mu.Unlock()
	latchRequiredFailure := true
	if required {
		defer func() {
			// The trail cannot report its own failed write. Keep an operator
			// signal beside it for status and the Wall. Enforcement relies on
			// requiredErr, never on this best-effort marker.
			if err != nil && latchRequiredFailure {
				if a.requiredErr == nil {
					a.requiredErr = err
				}
				if a.path != "" {
					_ = os.Mkdir(a.path+".audit-failing", 0o700)
				}
			}
		}()
	}
	if a.requiredErr != nil && required {
		return fmt.Errorf("required audit writer failed; close and reopen it: %w", a.requiredErr)
	}
	if a.closed {
		if required {
			return fmt.Errorf("required audit writer closed")
		}
		return nil
	}
	if a.f == nil {
		if required {
			return fmt.Errorf("required audit writer unavailable")
		}
		return nil
	}
	if err := validateApprovalActor(ev); err != nil {
		latchRequiredFailure = false // rejected input; nothing was written
		return err
	}
	if a.signing() {
		// Serialize the timestamp with signed appends across processes.
		if err := lockExclusive(a.f.Fd()); err != nil {
			return err
		}
		defer UnlockFile(a.f.Fd())
	}

	ev.Time = a.clock().Format(time.RFC3339)
	ev.Sig = "" // canonical content never includes the signature itself
	if ev.SchemaVersion == 2 {
		if !required {
			latchRequiredFailure = false
			return fmt.Errorf("schema v2 audit rows require durable writes")
		}
		if ev.RunSeq != 0 {
			latchRequiredFailure = false
			return fmt.Errorf("schema v2 run_seq is assigned by the auditor")
		}
		if a.runSeqs[ev.RunID] == ^uint64(0) {
			latchRequiredFailure = false
			return fmt.Errorf("schema v2 run_seq exhausted; start a new run")
		}
		ev.RunSeq = a.runSeqs[ev.RunID] + 1
	} else if ev.SchemaVersion != 0 {
		latchRequiredFailure = false
		return fmt.Errorf("unsupported audit schema_version %d", ev.SchemaVersion)
	}
	if err := validateAuditEvent(ev); err != nil {
		latchRequiredFailure = false
		return err
	}
	if required {
		if err = a.checkPathIdentity(); err != nil {
			return err
		}
	}

	// N10647: stamp correlation fields before the canonical bytes are computed
	// (below and in the final marshal) so both are part of the signed payload
	// when signing is active. A caller-set SessionID is never overwritten.
	// Empty/unset env -> field stays empty -> omitempty drops it, so an
	// unsessioned event marshals exactly like before this field existed.
	if ev.SessionID == "" {
		ev.SessionID = os.Getenv(nocklockSessionIDEnv)
	}
	// key_id is NEVER caller-supplied: a caller-set Event.KeyID is discarded
	// unconditionally and only re-populated from the Auditor's own Ed25519 key.
	// Trusting caller input here would let any caller forge a key_id in HMAC or
	// unsigned mode (false attribution to a signing key that never signed
	// anything), and would let a caller stamp the WRONG Ed25519 key_id even in
	// Ed25519 mode.
	ev.KeyID = ""
	if a.edPriv != nil {
		ev.KeyID = a.keyID
	}

	var checkpointCount int
	if a.signing() {
		// Cross-process safety. The mutex only serializes writers within ONE
		// process. Multiple proxy processes each seed prevSig from the tail at
		// open and, left to their in-memory copy, would chain off a stale head —
		// forking the single on-disk chain and tripping a false TAMPER on Verify.
		// Hold an exclusive flock across the whole read-tail → sign → append
		// sequence, and re-read the TRUE on-disk chain head under it, so every
		// entry links onto the real tail regardless of how many processes write.
		// lastSig seeks from end (O(1) in file size); the flock makes the read
		// see the stable tail regardless of how many processes write.
		last, err := lastSig(a.path)
		if err != nil {
			return err
		}
		checkpointCount, err = a.checkpointCount(last)
		if err != nil {
			return fmt.Errorf("audit checkpoint before append: %w", err)
		}
		canonical, err := json.Marshal(ev)
		if err != nil {
			return err
		}
		sig := a.sign(canonical, last)
		ev.Sig = sig
	}

	line, err := json.Marshal(ev)
	if err != nil {
		return err
	}
	line = append(line, '\n')
	if required {
		// Recheck directly before append: the signed tail is read by path while
		// the append uses the already-open descriptor, so replacement or unlink
		// must fail closed instead of forking the chain.
		if err = a.checkPathIdentity(); err != nil {
			return err
		}
	}
	if err = writeAll(a.f, line); err != nil {
		return err
	}
	if required {
		if err = a.f.Sync(); err != nil {
			return fmt.Errorf("sync audit trail: %w", err)
		}
		if err = syncDirectory(filepath.Dir(a.path)); err != nil {
			return fmt.Errorf("sync audit trail directory: %w", err)
		}
	}
	// Signing mode only, still under the flock held above: advance the
	// tail-truncation high-water-mark so a later removal of this entry is
	// detectable (N8154). ev.Sig is this entry's signature.
	if a.signing() {
		if err := a.updateHighWaterMark(checkpointCount+1, ev.Sig, required); err != nil {
			return err
		}
	}
	if ev.SchemaVersion == 2 {
		a.runSeqs[ev.RunID] = ev.RunSeq
	}
	return nil
}

// validateApprovalActor keeps this attribution field constrained to the
// kernel-derived local-approver namespace and to approval decision rows.
func validateApprovalActor(ev Event) error {
	if ev.ApprovalActor == "" {
		return nil
	}
	if ev.Decision != "approval-granted" && ev.Decision != "approval-denied" {
		return fmt.Errorf("approval_actor is only valid on approval decision rows")
	}
	const prefix = "local:uid:"
	if !strings.HasPrefix(ev.ApprovalActor, prefix) {
		return fmt.Errorf("approval_actor must use the local:uid:<decimal> form")
	}
	decimal := strings.TrimPrefix(ev.ApprovalActor, prefix)
	uid, err := strconv.ParseUint(decimal, 10, 32)
	if err != nil || strconv.FormatUint(uid, 10) != decimal {
		return fmt.Errorf("approval_actor must use a canonical uint32 decimal uid")
	}
	return nil
}

func (a *Auditor) checkPathIdentity() error {
	opened, err := a.f.Stat()
	if err != nil {
		return fmt.Errorf("stat open audit trail: %w", err)
	}
	if !opened.Mode().IsRegular() {
		return fmt.Errorf("open audit trail is not a regular file")
	}
	current, err := os.Stat(a.path)
	if err != nil {
		return fmt.Errorf("stat audit trail path: %w", err)
	}
	if !current.Mode().IsRegular() || !os.SameFile(opened, current) {
		return fmt.Errorf("audit trail path no longer refers to the open file")
	}
	return nil
}

func syncDirectory(path string) error {
	dir, err := os.Open(path)
	if err != nil {
		return err
	}
	syncErr := dir.Sync()
	closeErr := dir.Close()
	if syncErr != nil {
		return syncErr
	}
	return closeErr
}

// Close flushes and closes the underlying file. Safe to call on a disabled Auditor.
func (a *Auditor) Close() error {
	if a == nil {
		return nil
	}
	a.mu.Lock()
	defer a.mu.Unlock()
	if a.f == nil {
		a.closed = true
		return nil
	}
	err := a.f.Close()
	a.f = nil
	a.closed = true
	return err
}

// checkpointCount returns the current entry count under Record's flock. The
// normal path is O(1). If a crash left the checkpoint behind, verify the whole
// trail and recover its actual count before appending anything. Missing,
// forged, or truncated checkpoints must not be repaired into a trusted state.
func (a *Auditor) checkpointCount(last string) (int, error) {
	prev, err := readHighWaterMark(a.path + hwmSuffix)
	if err != nil {
		return 0, err
	}
	if prev != nil && prev.Count > 0 && prev.LastSig == last {
		want := a.sign(hwmSignedBytes(prev.Count, prev.LastSig), "")
		if !hmac.Equal([]byte(want), []byte(prev.Sig)) {
			return 0, fmt.Errorf("high-water-mark signature invalid")
		}
		return prev.Count, nil
	}
	if a.edPriv != nil {
		return VerifyEd25519(a.path, a.edPriv.Public().(ed25519.PublicKey))
	}
	return Verify(a.path, a.key)
}

// updateHighWaterMark rewrites the signed sidecar after an entry is appended.
// MUST be called under the same exclusive flock Record holds while signing, so
// the count read -> increment -> write is atomic across processes. newSig is the
// signature of the just-appended entry and becomes the checkpoint's last_sig.
// The sidecar is written AFTER the trail append (never before): a crash between
// the two leaves the sidecar one entry BEHIND the trail (n >= count, which Verify
// accepts), never ahead (which would false-trip truncation). A sidecar failure
// is returned after the trail append. RecordRequired treats it as a failure even
// if the trail itself was already synced; Record leaves handling to its caller.
func (a *Auditor) updateHighWaterMark(count int, newSig string, durable bool) error {
	hwmPath := a.path + hwmSuffix
	hwm := highWaterMark{Count: count, LastSig: newSig}
	hwm.Sig = a.sign(hwmSignedBytes(count, newSig), "")
	data, err := json.Marshal(hwm)
	if err != nil {
		return err
	}
	// Atomic replace so a reader never sees a half-written checkpoint. Required
	// records sync the temp file before rename and the containing directory after
	// rename; syncing the trail alone would leave the signed anchor volatile.
	tmp := hwmPath + ".tmp"
	f, err := os.OpenFile(tmp, os.O_CREATE|os.O_TRUNC|os.O_WRONLY, 0o644)
	if err != nil {
		return err
	}
	removeTmp := true
	defer func() {
		if removeTmp {
			_ = os.Remove(tmp)
		}
	}()
	if err := writeAll(f, append(data, '\n')); err != nil {
		_ = f.Close()
		return err
	}
	if durable {
		if err := f.Sync(); err != nil {
			_ = f.Close()
			return fmt.Errorf("sync audit checkpoint: %w", err)
		}
	}
	if err := f.Close(); err != nil {
		return err
	}
	if err := os.Rename(tmp, hwmPath); err != nil {
		return err
	}
	removeTmp = false
	if durable {
		if err := syncDirectory(filepath.Dir(hwmPath)); err != nil {
			return fmt.Errorf("sync audit checkpoint directory: %w", err)
		}
	}
	return nil
}

func writeAll(w io.Writer, data []byte) error {
	for len(data) > 0 {
		n, err := w.Write(data)
		if n > 0 {
			data = data[n:]
		}
		if err != nil {
			return err
		}
		if n == 0 {
			return io.ErrShortWrite
		}
	}
	return nil
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

// chainedMessage assembles the exact bytes that get signed for an entry: its
// canonical content, an unambiguous newline separator (canonical JSON never
// contains a raw newline), and the previous signature. Shared by the HMAC and
// Ed25519 paths so the two modes chain identically.
func chainedMessage(canonical []byte, prev string) []byte {
	msg := make([]byte, 0, len(canonical)+1+len(prev))
	msg = append(msg, canonical...)
	msg = append(msg, '\n')
	msg = append(msg, prev...)
	return msg
}

// signLineEd25519 computes the hex Ed25519 signature of an entry's canonical
// bytes chained to the previous signature. The signature is verifiable with the
// corresponding public key alone (see VerifyEd25519) — the property that makes
// the trail non-repudiable.
func signLineEd25519(priv ed25519.PrivateKey, canonical []byte, prev string) string {
	return hex.EncodeToString(ed25519.Sign(priv, chainedMessage(canonical, prev)))
}

// PrivateKeyFromHex decodes a hex-encoded Ed25519 private key — accepting either
// a 32-byte seed (the compact form to store in an env var) or a full 64-byte
// private key — into an ed25519.PrivateKey. Used to load the signing key from the
// environment without ever writing it to the policy file.
func PrivateKeyFromHex(s string) (ed25519.PrivateKey, error) {
	b, err := hex.DecodeString(strings.TrimSpace(s))
	if err != nil {
		return nil, fmt.Errorf("ed25519 private key is not valid hex: %w", err)
	}
	switch len(b) {
	case ed25519.SeedSize: // 32-byte seed
		return ed25519.NewKeyFromSeed(b), nil
	case ed25519.PrivateKeySize: // 64-byte full key
		return ed25519.PrivateKey(b), nil
	default:
		return nil, fmt.Errorf("ed25519 private key must be %d-byte seed or %d-byte key (got %d bytes)", ed25519.SeedSize, ed25519.PrivateKeySize, len(b))
	}
}

// PublicKeyFromHex decodes a 32-byte hex-encoded Ed25519 public key — the value a
// verifier needs (and the only value it needs) to check a non-repudiable trail.
func PublicKeyFromHex(s string) (ed25519.PublicKey, error) {
	b, err := hex.DecodeString(strings.TrimSpace(s))
	if err != nil {
		return nil, fmt.Errorf("ed25519 public key is not valid hex: %w", err)
	}
	if len(b) != ed25519.PublicKeySize {
		return nil, fmt.Errorf("ed25519 public key must be %d bytes (got %d)", ed25519.PublicKeySize, len(b))
	}
	return ed25519.PublicKey(b), nil
}

// lastSig returns the signature of the final non-empty line in the file, or ""
// if the file is absent or empty. Used to seed the chain on open.
//
// Implementation seeks from end rather than scanning the whole file, giving
// O(1) behavior in file size. It reads backward in expanding windows (4 KB →
// 16 KB → 64 KB → whole file) so that unusually long entries are handled
// without the O(n) scan the naive scanner would require.
func lastSig(path string) (string, error) {
	f, err := os.Open(path)
	if err != nil {
		if os.IsNotExist(err) {
			return "", nil
		}
		return "", err
	}
	defer f.Close()
	return lastSigSeek(f)
}

// lastSigSeek implements the seek-from-end strategy for lastSig.
func lastSigSeek(f *os.File) (string, error) {
	size, err := f.Seek(0, io.SeekEnd)
	if err != nil {
		return "", err
	}
	if size == 0 {
		return "", nil
	}

	// Try progressively larger windows until we find a complete JSON line.
	// 4 KB covers hundreds of typical audit entries in a single read.
	for _, window := range []int64{4 * 1024, 16 * 1024, 64 * 1024, size} {
		readSize := window
		if readSize > size {
			readSize = size
		}
		offset := size - readSize
		buf := make([]byte, readSize)
		if _, err := f.ReadAt(buf, offset); err != nil {
			return "", err
		}

		// When offset > 0 the first bytes may be a partial line from the
		// previous chunk. Skip forward to the first newline so that
		// buf[start:] contains only complete lines.
		start := 0
		if offset > 0 {
			idx := bytes.IndexByte(buf, '\n')
			if idx < 0 {
				// No newline at all — the last line is longer than this
				// window. Try a bigger window.
				continue
			}
			start = idx + 1
		}

		sig, found, err := lastSigInSlice(buf[start:])
		if err != nil {
			return "", err
		}
		if found {
			return sig, nil
		}
		// All lines in this window were empty. If we read the whole file,
		// the file contains no entries with signatures.
		if readSize == size {
			return "", nil
		}
	}
	return "", nil
}

// lastSigInSlice scans b backward over newline-separated JSON lines and
// returns the Sig field of the last non-empty entry, plus found=true.
// Returns ("", false, nil) when b contains no non-empty entry.
func lastSigInSlice(b []byte) (string, bool, error) {
	lines := bytes.Split(b, []byte("\n"))
	for i := len(lines) - 1; i >= 0; i-- {
		line := bytes.TrimSpace(lines[i])
		if len(line) == 0 {
			continue
		}
		var ev Event
		if err := json.Unmarshal(line, &ev); err != nil {
			return "", false, fmt.Errorf("seed chain: %w", err)
		}
		return ev.Sig, true, nil
	}
	return "", false, nil
}

// --- N8154: tail-truncation detection via a signed high-water-mark -----------
//
// A pure hash chain catches edits, reorders, and MID-deletes (the next entry's
// prev-sig link breaks), but a truncated PREFIX still verifies clean. A signed
// sidecar at "<trail>.hwm" records the entry COUNT and the last entry's
// signature, so a SHORTENED trail (the tail lopped off) becomes detectable.
//
// Honest threat model: this is DEFENSE-IN-DEPTH, not absolute. An attacker with
// write access to truncate the trail can also delete the sidecar — verification
// then falls back to the legacy chain-only check (fail-open on absence). It
// raises the bar (automated/sloppy truncation is caught; the attacker must now
// destroy BOTH) and pairs with the off-box NockCC forward, which is the real
// anti-truncation anchor. The sidecar is signed with the SAME key as the chain,
// so its count cannot be forged downward without the signing key.

const hwmSuffix = ".hwm"

type highWaterMark struct {
	Count   int    `json:"count"`
	LastSig string `json:"last_sig"`
	Sig     string `json:"sig"`
}

// hwmSignedBytes is the canonical, domain-separated message signed for a
// high-water-mark. The distinct prefix means an entry signature can never be
// replayed as a checkpoint signature, or vice versa.
func hwmSignedBytes(count int, lastSig string) []byte {
	return []byte(fmt.Sprintf("nockguard-hwm-v1\n%d\n%s", count, lastSig))
}

// readHighWaterMark loads the sidecar at hwmPath. Returns (nil, nil) when it is
// absent — a legacy trail with no checkpoint, which callers verify chain-only.
func readHighWaterMark(hwmPath string) (*highWaterMark, error) {
	data, err := os.ReadFile(hwmPath)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, nil
		}
		return nil, err
	}
	return parseHighWaterMark(data, hwmPath)
}

// parseHighWaterMark decodes sidecar bytes; name labels the error only.
func parseHighWaterMark(data []byte, name string) (*highWaterMark, error) {
	var hwm highWaterMark
	if err := json.Unmarshal(bytes.TrimSpace(data), &hwm); err != nil {
		return nil, fmt.Errorf("high-water-mark %s is corrupt: %w", name, err)
	}
	return &hwm, nil
}

// checkHighWaterMark validates a freshly-walked chain against the signed
// checkpoint. n is the number of entries the walk verified; sigAtCount is the
// signature of the entry at the checkpoint's count (or "" if the walk never
// reached it). verifySig checks the checkpoint's OWN signature with the trail's
// key. A nil hwm (absent sidecar) passes — legacy trails are unaffected. Fails
// if the trail is shorter than the checkpoint (tail truncated) or the checkpoint
// entry's signature does not match (the recorded entry was altered or replaced).
func checkHighWaterMark(hwm *highWaterMark, n int, sigAtCount string, verifySig func(signed []byte, sigHex string) bool) error {
	if hwm == nil {
		// An absent sidecar on a signed, non-empty trail is suspicious: every
		// Record() call since N8154 writes or updates .hwm immediately after
		// appending the signed entry. If the sidecar is gone but the trail has
		// entries, the most likely explanation is that an attacker deleted it
		// alongside a tail truncation to defeat the count check. Treat this as
		// a potential tamper rather than silently passing (N8182 finding #2).
		if n > 0 {
			return fmt.Errorf("signed trail has no high-water-mark sidecar (.hwm) — sidecar may have been deleted alongside a tail truncation")
		}
		return nil
	}
	if !verifySig(hwmSignedBytes(hwm.Count, hwm.LastSig), hwm.Sig) {
		return fmt.Errorf("high-water-mark signature invalid — checkpoint was tampered or signed with a different key")
	}
	if n < hwm.Count {
		return fmt.Errorf("trail truncated — %d entries on disk but the signed high-water-mark records %d (entries removed from the tail)", n, hwm.Count)
	}
	if sigAtCount != hwm.LastSig {
		return fmt.Errorf("high-water-mark mismatch — entry %d signature does not match the signed checkpoint (entry altered or replaced)", hwm.Count)
	}
	return nil
}

// rejectDuplicateObjectKeys returns an error if raw is not a single JSON
// object or contains a duplicate member name at any depth. This closes a forgery the typed
// unmarshal + re-marshal verification path is blind to (N8179): Go's
// encoding/json is LAST-WINS on duplicate keys, so a line such as
//
//	{"decision":"deny", <the originally-signed allow body incl decision:"allow">, "sig":...}
//
// decodes Decision="allow", re-canonicalizes to the originally-signed bytes, and
// passes ed25519/HMAC verification — while a human reading the raw JSONL sees the
// forged "deny". By rejecting duplicate names before signature checking,
// the verifier refuses any line that is not in canonical (one-key-each) form, so
// the only bytes that can verify are the bytes that were actually signed. This
// mirrors the proxy's canonicalToolCall defense in internal/proxy/stdio.go, which
// collapses such parser differentials on the request path.
//
// It uses a streaming token decoder (not json.Unmarshal into a map, which would
// itself silently collapse the duplicate) so each duplicate is observed before
// it is discarded.
func rejectDuplicateObjectKeys(raw []byte) error {
	dec := json.NewDecoder(bytes.NewReader(raw))
	tok, err := dec.Token()
	if err != nil {
		return fmt.Errorf("invalid json: %w", err)
	}
	delim, ok := tok.(json.Delim)
	if !ok || delim != '{' {
		return fmt.Errorf("audit line is not a JSON object")
	}
	if err := consumeObjectMembers(dec); err != nil {
		return err
	}
	if _, err := dec.Token(); err != io.EOF {
		if err == nil {
			return fmt.Errorf("trailing JSON after audit object")
		}
		return fmt.Errorf("invalid json: %w", err)
	}
	return nil
}

func consumeObjectMembers(dec *json.Decoder) error {
	seen := make(map[string]struct{})
	for dec.More() {
		tok, err := dec.Token()
		if err != nil {
			return fmt.Errorf("invalid json: %w", err)
		}
		key, ok := tok.(string)
		if !ok {
			return fmt.Errorf("invalid JSON object member name")
		}
		if _, dup := seen[key]; dup {
			return fmt.Errorf("duplicate object key %q — non-canonical (possible forgery)", key)
		}
		seen[key] = struct{}{}
		if err := consumeJSONValue(dec); err != nil {
			return err
		}
	}
	if _, err := dec.Token(); err != nil {
		return fmt.Errorf("invalid json: %w", err)
	}
	return nil
}

func consumeJSONValue(dec *json.Decoder) error {
	tok, err := dec.Token()
	if err != nil {
		return fmt.Errorf("invalid json: %w", err)
	}
	delim, ok := tok.(json.Delim)
	if !ok {
		return nil
	}
	switch delim {
	case '{':
		return consumeObjectMembers(dec)
	case '[':
		for dec.More() {
			if err := consumeJSONValue(dec); err != nil {
				return err
			}
		}
		if _, err := dec.Token(); err != nil {
			return fmt.Errorf("invalid json: %w", err)
		}
		return nil
	default:
		return fmt.Errorf("invalid JSON delimiter %q", delim)
	}
}

// rejectNonStringApprovalActor prevents null or another JSON type from being
// collapsed to Event.ApprovalActor's zero value by encoding/json.
func rejectNonStringApprovalActor(raw []byte) error {
	dec := json.NewDecoder(bytes.NewReader(raw))
	tok, err := dec.Token()
	if err != nil {
		return err
	}
	if tok != json.Delim('{') {
		return nil // rejectDuplicateObjectKeys reports the more useful shape error.
	}
	for dec.More() {
		tok, err := dec.Token()
		if err != nil {
			return err
		}
		key, ok := tok.(string)
		if !ok {
			return fmt.Errorf("invalid top-level JSON key")
		}
		var value json.RawMessage
		if err := dec.Decode(&value); err != nil {
			return err
		}
		if key == "approval_actor" && (len(value) == 0 || value[0] != '"') {
			return fmt.Errorf("approval_actor must be a JSON string")
		}
		if key == "approval_actor" {
			var actor string
			if err := json.Unmarshal(value, &actor); err != nil {
				return err
			}
			if actor == "" {
				return fmt.Errorf("empty approval_actor must be omitted")
			}
		}
	}
	return nil
}

var auditFieldNames = map[string]struct{}{
	"ts": {}, "agent": {}, "tool": {}, "decision": {}, "reason": {},
	"approval_actor": {}, "nock_id": {}, "pr": {}, "review_id": {},
	"parent_audit_seq": {}, "session_id": {}, "key_id": {}, "sig": {},
	"schema_version": {}, "record_type": {}, "run_id": {}, "run_seq": {},
	"run_event": {}, "run_count": {}, "run_head": {}, "action_id": {},
	"observation": {}, "cause": {}, "response_class": {}, "mcp_is_error": {},
	"tool_hash_version": {}, "tool_definition_hash": {}, "tool_pin_hash": {},
	"tool_pin_status": {},
}

var v2OnlyAuditFields = []string{
	"record_type", "run_id", "run_seq", "run_event", "run_count", "run_head",
	"action_id", "observation", "cause", "response_class", "mcp_is_error",
	"tool_hash_version", "tool_definition_hash", "tool_pin_hash", "tool_pin_status",
}

// validateAuditLine applies the lossless envelope rules before typed decoding.
// Missing schema_version is the historical v1 format; explicit v1 and any
// unrecognized extension are refused so encoding/json cannot silently discard
// signed content. V1 canonical bytes still come from json.Marshal(Event).
func validateAuditLine(raw []byte, ev Event) error {
	if err := rejectDuplicateObjectKeys(raw); err != nil {
		return err
	}
	var fields map[string]json.RawMessage
	if err := json.Unmarshal(raw, &fields); err != nil || fields == nil {
		if err == nil {
			err = fmt.Errorf("audit line is not a JSON object")
		}
		return err
	}
	if actorRaw, ok := fields["approval_actor"]; ok {
		actorRaw = bytes.TrimSpace(actorRaw)
		if len(actorRaw) == 0 || actorRaw[0] != '"' {
			return fmt.Errorf("approval_actor must be a JSON string")
		}
		var actor string
		if err := json.Unmarshal(actorRaw, &actor); err != nil {
			return fmt.Errorf("approval_actor must be a JSON string")
		}
		if actor == "" {
			return fmt.Errorf("empty approval_actor must be omitted")
		}
	}
	for key := range fields {
		if _, known := auditFieldNames[key]; !known {
			for exact := range auditFieldNames {
				if strings.EqualFold(key, exact) {
					return fmt.Errorf("non-canonical audit field %q; use %q", key, exact)
				}
			}
			return fmt.Errorf("unknown audit field %q", key)
		}
	}
	if _, hasVersion := fields["schema_version"]; !hasVersion {
		for _, name := range v2OnlyAuditFields {
			if _, present := fields[name]; present {
				return fmt.Errorf("v2 field %q requires schema_version 2", name)
			}
		}
		return validateApprovalActor(ev)
	}
	if ev.SchemaVersion != 2 {
		return fmt.Errorf("unsupported audit schema_version %d", ev.SchemaVersion)
	}
	return validateV2Event(ev, fields)
}

func validateAuditEvent(ev Event) error {
	if ev.SchemaVersion == 0 {
		for _, name := range v2OnlyAuditFields {
			if auditEventFieldSet(ev, name) {
				return fmt.Errorf("v2 field %q requires schema_version 2", name)
			}
		}
		return validateApprovalActor(ev)
	}
	if ev.SchemaVersion != 2 {
		return fmt.Errorf("unsupported audit schema_version %d", ev.SchemaVersion)
	}
	return validateV2Event(ev, nil)
}

func auditEventFieldSet(ev Event, field string) bool {
	switch field {
	case "record_type":
		return ev.RecordType != ""
	case "run_id":
		return ev.RunID != ""
	case "run_seq":
		return ev.RunSeq != 0
	case "run_event":
		return ev.RunEvent != ""
	case "run_count":
		return ev.RunCount != 0
	case "run_head":
		return ev.RunHead != ""
	case "action_id":
		return ev.ActionID != ""
	case "observation":
		return ev.Observation != ""
	case "cause":
		return ev.Cause != ""
	case "response_class":
		return ev.ResponseClass != ""
	case "mcp_is_error":
		return ev.MCPIsError != nil
	case "tool_hash_version":
		return ev.ToolHashVersion != ""
	case "tool_definition_hash":
		return ev.ToolDefinitionHash != ""
	case "tool_pin_hash":
		return ev.ToolPinHash != ""
	case "tool_pin_status":
		return ev.ToolPinStatus != ""
	default:
		return false
	}
}

func validateV2Event(ev Event, fields map[string]json.RawMessage) error {
	if fields != nil {
		for _, name := range []string{"ts", "agent", "tool", "decision", "schema_version", "record_type", "run_id", "run_seq"} {
			if _, ok := fields[name]; !ok {
				return fmt.Errorf("schema v2 row is missing required field %q", name)
			}
		}
		for _, name := range []string{
			"ts", "agent", "tool", "decision", "reason", "approval_actor", "pr", "review_id", "session_id", "key_id", "sig", "record_type", "run_id", "run_event", "run_head", "action_id", "observation", "cause", "response_class", "tool_hash_version", "tool_definition_hash", "tool_pin_hash", "tool_pin_status",
		} {
			if raw, ok := fields[name]; ok {
				if len(raw) == 0 || raw[0] != '"' {
					return fmt.Errorf("%s must be a JSON string", name)
				}
				var value string
				if err := json.Unmarshal(raw, &value); err != nil {
					return fmt.Errorf("%s must be a JSON string", name)
				}
				if value == "" && name != "tool" && name != "decision" {
					return fmt.Errorf("empty %s must be omitted", name)
				}
			}
		}
		for _, name := range []string{"run_seq", "run_count"} {
			if raw, ok := fields[name]; ok {
				var value uint64
				if err := json.Unmarshal(raw, &value); err != nil || value == 0 {
					return fmt.Errorf("%s must be a positive integer", name)
				}
			}
		}
		for _, name := range []string{"nock_id", "parent_audit_seq"} {
			if raw, ok := fields[name]; ok {
				var value int
				if err := json.Unmarshal(raw, &value); err != nil || value <= 0 {
					return fmt.Errorf("%s must be a positive integer", name)
				}
			}
		}
		if raw, ok := fields["mcp_is_error"]; ok && string(raw) != "true" && string(raw) != "false" {
			return fmt.Errorf("mcp_is_error must be a JSON boolean")
		}
	}

	if ev.SchemaVersion != 2 || len(ev.RunID) != 32 || strings.ToLower(ev.RunID) != ev.RunID {
		return fmt.Errorf("schema v2 requires a lowercase 128-bit run_id and schema_version 2")
	}
	if _, err := hex.DecodeString(ev.RunID); err != nil || ev.RunSeq == 0 {
		return fmt.Errorf("schema v2 requires a lowercase 128-bit run_id and positive run_seq")
	}
	if ev.Time == "" || ev.Agent == "" {
		return fmt.Errorf("schema v2 requires non-empty ts and agent")
	}
	switch ev.RecordType {
	case "run":
		if ev.Tool != "" || ev.Decision != "" || ev.ActionID != "" || ev.Observation != "" || ev.Cause != "" || ev.ResponseClass != "" || ev.MCPIsError != nil {
			return fmt.Errorf("run records cannot carry tool-call fields")
		}
		switch ev.RunEvent {
		case "open":
			if ev.RunSeq != 1 || ev.RunCount != 0 || ev.RunHead != "" {
				return fmt.Errorf("run/open must be the first row and omit close fields")
			}
		case "heartbeat":
			if ev.RunSeq < 2 || ev.RunCount != 0 || ev.RunHead != "" {
				return fmt.Errorf("run/heartbeat has invalid sequence or close fields")
			}
		case "close":
			if ev.RunSeq < 2 || ev.RunCount == 0 || ev.RunCount != ev.RunSeq-1 || ev.RunHead == "" {
				return fmt.Errorf("run/close must commit its preceding count and head")
			}
		default:
			return fmt.Errorf("invalid run_event %q", ev.RunEvent)
		}
	case "decision":
		if ev.Decision == "" || ev.RunEvent != "" || ev.Observation != "" || ev.Cause != "" || ev.ResponseClass != "" || ev.MCPIsError != nil || ev.RunCount != 0 || ev.RunHead != "" {
			return fmt.Errorf("decision record has invalid lifecycle or observation fields")
		}
		if ev.Decision == "dispatch" && ev.ActionID == "" {
			return fmt.Errorf("schema v2 dispatch requires action_id")
		}
		if ev.Decision == "dispatch" && ev.Tool == "" {
			return fmt.Errorf("schema v2 dispatch requires a tool")
		}
	case "action_observation":
		if ev.Decision != "" || ev.RunEvent != "" || ev.RunCount != 0 || ev.RunHead != "" || ev.ActionID == "" {
			return fmt.Errorf("action_observation requires action_id without a decision")
		}
		if ev.Observation != "not_forwarded" && ev.Observation != "response_observed" && ev.Observation != "outcome_unknown" && ev.Observation != "late_response_observed" {
			return fmt.Errorf("invalid observation %q", ev.Observation)
		}
		if (ev.Observation == "response_observed" || ev.Observation == "late_response_observed") != (ev.ResponseClass != "") {
			return fmt.Errorf("response_class is required only for observed responses")
		}
		if ev.ResponseClass != "" && ev.ResponseClass != "jsonrpc_result" && ev.ResponseClass != "jsonrpc_error" {
			return fmt.Errorf("invalid response_class %q", ev.ResponseClass)
		}
		if ev.Observation == "late_response_observed" && ev.Cause != "late_response" {
			return fmt.Errorf("late_response_observed requires cause late_response")
		}
	default:
		return fmt.Errorf("invalid record_type %q", ev.RecordType)
	}
	if ev.ActionID != "" {
		parts := strings.Split(ev.ActionID, ".")
		if len(parts) != 2 || parts[0] != ev.RunID {
			return fmt.Errorf("action_id must be <run_id>.<action_seq>")
		}
		seq, err := strconv.ParseUint(parts[1], 10, 64)
		if err != nil || seq == 0 || strconv.FormatUint(seq, 10) != parts[1] {
			return fmt.Errorf("action_id must use a positive canonical action_seq")
		}
	}
	if ev.Cause != "" {
		switch ev.Cause {
		case "policy_denied", "validation_blocked", "approval_denied", "limit_reached", "audit_unavailable", "timeout", "client_cancel", "transport_lost", "upstream_exit", "shutdown", "late_response", "tool_catalog_refresh_required", "pin_mismatch", "pin_unverified":
		default:
			return fmt.Errorf("invalid cause %q", ev.Cause)
		}
	}
	if ev.ToolHashVersion != "" && ev.ToolHashVersion != "jcs-rfc8785-v1" {
		return fmt.Errorf("invalid tool_hash_version %q", ev.ToolHashVersion)
	}
	for field, digest := range map[string]string{"tool_definition_hash": ev.ToolDefinitionHash, "tool_pin_hash": ev.ToolPinHash} {
		if digest != "" {
			if len(digest) != 64 || strings.ToLower(digest) != digest {
				return fmt.Errorf("%s must be lowercase SHA-256 hex", field)
			}
			if _, err := hex.DecodeString(digest); err != nil {
				return fmt.Errorf("%s must be lowercase SHA-256 hex", field)
			}
		}
	}
	if ev.RunHead != "" {
		if (len(ev.RunHead) != 64 && len(ev.RunHead) != 128) || strings.ToLower(ev.RunHead) != ev.RunHead {
			return fmt.Errorf("run_head must be a lowercase chain signature")
		}
		if _, err := hex.DecodeString(ev.RunHead); err != nil {
			return fmt.Errorf("run_head must be a lowercase chain signature")
		}
	}
	if ev.ToolPinStatus != "" {
		switch ev.ToolPinStatus {
		case "matched", "mismatch", "unobserved", "unpinned", "unhashable":
		default:
			return fmt.Errorf("invalid tool_pin_status %q", ev.ToolPinStatus)
		}
	}
	return validateApprovalActor(ev)
}

// Error classification for trail verification.
//
// A caller must be able to tell a REAL chain/signature break (an edit, deletion,
// insertion, reorder, forgery, wrong key, or tail truncation) apart from a benign
// IO/scan failure that merely stopped the trail being read to the end (e.g. a
// line longer than the scanner buffer). The first means the record can no longer
// be trusted — TAMPER. The second means verification is UNAVAILABLE, not failed,
// and must never raise a tamper alarm.
//
// Classification adds NO text to any existing error message: each wrapper's
// Error() returns the underlying detection text verbatim, and callers classify
// purely through errors.Is / errors.As against the sentinels below. Every legacy
// caller that only checks `err != nil` (the CLI verify, evidence, and the
// open-time refusal in New) keeps behaving exactly as before.

// ErrTamper matches (via errors.Is) every error returned for a genuine
// chain/signature break. IO/scan errors never match it.
var ErrTamper = errors.New("audit chain tamper")

// ErrScan matches (via errors.Is) an error that stopped the walk before the trail
// was fully read — verification is UNAVAILABLE for that trail, not tampered.
var ErrScan = errors.New("audit trail read/scan error")

// TamperError classifies a genuine tamper detection. Line is the 1-based entry at
// the break (0 when not line-scoped). Its message is the detection message,
// unchanged, so existing error strings and their assertions are unaffected.
type TamperError struct {
	Line int
	Err  error
}

func (e *TamperError) Error() string        { return e.Err.Error() }
func (e *TamperError) Unwrap() error        { return e.Err }
func (e *TamperError) Is(target error) bool { return target == ErrTamper }

// ScanError classifies a read/scan failure while walking the trail. Its message
// is the underlying scanner error, unchanged.
type ScanError struct{ Err error }

func (e *ScanError) Error() string        { return e.Err.Error() }
func (e *ScanError) Unwrap() error        { return e.Err }
func (e *ScanError) Is(target error) bool { return target == ErrScan }

// markTamper tags err as a genuine tamper at the given 1-based line.
func markTamper(line int, err error) error {
	if err == nil {
		return nil
	}
	return &TamperError{Line: line, Err: err}
}

// markBoundaryTamper tags a REAL tamper that is not attributable to a single
// scanned entry: a high-water-mark / checkpoint failure (tail truncation, a
// deleted sidecar, or an altered checkpoint). The chain break is genuine so the
// banner must fire, but every entry the walk actually reached verified clean —
// the break is at the boundary, not a line — so Line is 0. Consumers then keep
// entries_verified = n and omit break_at instead of fingering a valid entry. The
// error text still carries the boundary specifics (which entry/count).
func markBoundaryTamper(err error) error {
	if err == nil {
		return nil
	}
	return &TamperError{Line: 0, Err: err}
}

// markScan tags err as a read/scan failure (verification unavailable).
func markScan(err error) error {
	if err == nil {
		return nil
	}
	return &ScanError{Err: err}
}

// MaxTrailLineBytes caps a single audit-trail line the verifier — and the wall's
// replay/tail scanners — will read. The previous 1 MiB cap made a legitimately
// long entry trip bufio.ErrTooLong, which the wall then misread as a chain break
// (crying wolf). 8 MiB sits far above any real decision record yet stays bounded,
// so a pathological line still surfaces as an ErrScan (unavailable), never as a
// tamper and never as unbounded memory growth. Shared so every trail-walking
// scanner uses the identical cap and their 1-based line counts stay aligned.
const MaxTrailLineBytes = 8 * 1024 * 1024

// scanBufferCap is the live cap — a package var (not the const directly) so tests
// can shrink it to exercise the oversized-line (ErrScan) path without an 8 MiB
// fixture.
var scanBufferCap = MaxTrailLineBytes

// Verify walks a signed audit file and checks the hash chain end to end. It
// returns the number of entries verified, or the 1-based line number and an
// error at the first entry whose signature does not match — which happens if any
// entry was edited, deleted, inserted, or reordered, or if the wrong key is used.
//
// Error classification: a genuine chain/signature break is a *TamperError
// (errors.Is(err, ErrTamper)); a read/scan failure that stopped the walk early is
// a *ScanError (errors.Is(err, ErrScan)). Messages are unchanged.
func Verify(path string, key []byte) (int, error) {
	n, _, err := VerifyWithCheckpoint(path, key)
	return n, err
}

// VerifyWithCheckpoint is Verify and also returns the checkpoint count that
// was loaded for that verification. A checkpoint behind the verified trail
// tail remains a successful prefix verification; callers that need a verdict
// for the whole trail can compare the returned count with n.
func VerifyWithCheckpoint(path string, key []byte) (n, checkpointCount int, err error) {
	f, err := os.Open(path)
	if err != nil {
		return 0, 0, err
	}
	defer f.Close()
	hwm, herr := readHighWaterMark(path + hwmSuffix)
	if herr != nil {
		return 0, 0, herr
	}
	n, err = verifyHMACStream(f, hwm, key)
	if hwm != nil {
		checkpointCount = hwm.Count
	}
	return n, checkpointCount, err
}

// VerifyBytes is Verify over an immutable in-memory snapshot. trail holds the
// audit bytes and hwm the bytes of its .hwm sidecar (nil when absent).
func VerifyBytes(trail, hwm, key []byte) (int, error) {
	n, _, err := VerifyWithCheckpointBytes(trail, hwm, key)
	return n, err
}

// VerifyWithCheckpointBytes is VerifyWithCheckpoint over an immutable
// in-memory snapshot. It returns the checkpoint count loaded from hwm, or zero
// when hwm is absent.
func VerifyWithCheckpointBytes(trail, hwm, key []byte) (n, checkpointCount int, err error) {
	var mark *highWaterMark
	if hwm != nil {
		m, err := parseHighWaterMark(hwm, "(snapshot)")
		if err != nil {
			return 0, 0, err
		}
		mark = m
	}
	n, err = verifyHMACStream(bytes.NewReader(trail), mark, key)
	if mark != nil {
		checkpointCount = mark.Count
	}
	return n, checkpointCount, err
}

func verifyHMACStream(r io.Reader, hwm *highWaterMark, key []byte) (int, error) {
	sc := bufio.NewScanner(r)
	sc.Buffer(make([]byte, 0, 64*1024), scanBufferCap)
	prev := ""
	n := 0
	sigAtCount := ""
	for sc.Scan() {
		raw := sc.Bytes()
		if len(bytes.TrimSpace(raw)) == 0 {
			continue
		}
		n++
		var ev Event
		if err := json.Unmarshal(raw, &ev); err != nil {
			return n, markTamper(n, fmt.Errorf("line %d: invalid json: %w", n, err))
		}
		if err := validateAuditLine(raw, ev); err != nil {
			return n, markTamper(n, fmt.Errorf("line %d: invalid audit record: %w", n, err))
		}
		got := ev.Sig
		if got == "" {
			return n, markTamper(n, fmt.Errorf("line %d: entry is not signed", n))
		}
		ev.Sig = ""
		canonical, err := json.Marshal(ev)
		if err != nil {
			// Re-marshaling an already-parsed Event does not fail in practice; this
			// is an internal serialization error, not evidence of tampering, so it
			// is left unclassified (surfaces as unavailable, never a tamper alarm).
			return n, err
		}
		want := signLine(key, canonical, prev)
		if !hmac.Equal([]byte(got), []byte(want)) {
			return n, markTamper(n, fmt.Errorf("line %d: signature mismatch — trail was tampered, deleted from, reordered, or signed with a different key", n))
		}
		prev = got
		if hwm != nil && n == hwm.Count {
			sigAtCount = got
		}
	}
	// The scanner-error check MUST stay before checkHighWaterMark: a read glitch
	// aborts the walk with n < the real entry count, and the hwm check would then
	// report a false "trail truncated" tamper. Classify it as a scan error
	// (unavailable) here so a benign read failure never launders into tamper.
	if err := sc.Err(); err != nil {
		return n, markScan(err)
	}
	if err := checkHighWaterMark(hwm, n, sigAtCount, func(signed []byte, sigHex string) bool {
		return hmac.Equal([]byte(signLine(key, signed, "")), []byte(sigHex))
	}); err != nil {
		return n, markBoundaryTamper(err)
	}
	return n, nil
}

// VerifyEd25519 walks an Ed25519-signed audit file and checks the hash chain end
// to end using ONLY the public key. It returns the number of entries verified,
// or the 1-based line number and an error at the first entry whose signature
// does not verify — which happens if any entry was edited, deleted, inserted, or
// reordered, or if the trail was signed by a different private key. Because the
// public key cannot produce signatures, a passing verification is proof the
// holder of the matching private key signed every entry: non-repudiation.
func VerifyEd25519(path string, pub ed25519.PublicKey) (int, error) {
	n, _, err := VerifyEd25519WithCheckpoint(path, pub)
	return n, err
}

// VerifyEd25519WithCheckpoint is VerifyEd25519 and also returns the checkpoint
// count that was loaded for that verification. Prefix semantics are unchanged:
// signatures beyond a valid checkpoint are still verified and returned in n,
// with no error, so writer recovery can inspect them.
func VerifyEd25519WithCheckpoint(path string, pub ed25519.PublicKey) (n, checkpointCount int, err error) {
	f, err := os.Open(path)
	if err != nil {
		return 0, 0, err
	}
	defer f.Close()
	hwm, herr := readHighWaterMark(path + hwmSuffix)
	if herr != nil {
		return 0, 0, herr
	}
	n, err = verifyEd25519Stream(f, hwm, pub)
	if hwm != nil {
		checkpointCount = hwm.Count
	}
	return n, checkpointCount, err
}

// VerifyEd25519Bytes is VerifyEd25519 over an in-memory snapshot: trail holds
// the trail's bytes and hwm the bytes of its .hwm sidecar (nil when the sidecar
// is absent). A caller that must verify and then read the SAME bytes (for
// example to select rows from them) reads the file once and passes the bytes
// here, so nothing can be swapped between verification and use. Checks and
// error classification are identical to VerifyEd25519.
func VerifyEd25519Bytes(trail, hwm []byte, pub ed25519.PublicKey) (int, error) {
	n, _, err := VerifyEd25519WithCheckpointBytes(trail, hwm, pub)
	return n, err
}

// VerifyEd25519WithCheckpointBytes is VerifyEd25519WithCheckpoint over an
// immutable in-memory snapshot. It returns the checkpoint count loaded from
// hwm, or zero when hwm is absent.
func VerifyEd25519WithCheckpointBytes(trail, hwm []byte, pub ed25519.PublicKey) (n, checkpointCount int, err error) {
	var mark *highWaterMark
	if hwm != nil {
		m, err := parseHighWaterMark(hwm, "(snapshot)")
		if err != nil {
			return 0, 0, err
		}
		mark = m
	}
	n, err = verifyEd25519Stream(bytes.NewReader(trail), mark, pub)
	if mark != nil {
		checkpointCount = mark.Count
	}
	return n, checkpointCount, err
}

// verifyEd25519Stream is the shared Ed25519 chain walk plus high-water-mark
// check behind VerifyEd25519 and VerifyEd25519Bytes.
func verifyEd25519Stream(r io.Reader, hwm *highWaterMark, pub ed25519.PublicKey) (int, error) {
	sc := bufio.NewScanner(r)
	sc.Buffer(make([]byte, 0, 64*1024), scanBufferCap)
	prev := ""
	n := 0
	sigAtCount := ""
	for sc.Scan() {
		raw := sc.Bytes()
		if len(bytes.TrimSpace(raw)) == 0 {
			continue
		}
		n++
		var ev Event
		if err := json.Unmarshal(raw, &ev); err != nil {
			return n, markTamper(n, fmt.Errorf("line %d: invalid json: %w", n, err))
		}
		if err := validateAuditLine(raw, ev); err != nil {
			return n, markTamper(n, fmt.Errorf("line %d: invalid audit record: %w", n, err))
		}
		if ev.Sig == "" {
			return n, markTamper(n, fmt.Errorf("line %d: entry is not signed", n))
		}
		sig, err := hex.DecodeString(ev.Sig)
		if err != nil {
			return n, markTamper(n, fmt.Errorf("line %d: signature is not valid hex: %w", n, err))
		}
		got := ev.Sig
		ev.Sig = ""
		canonical, err := json.Marshal(ev)
		if err != nil {
			// Internal serialization error (see Verify): not tamper, left unclassified.
			return n, err
		}
		if !ed25519.Verify(pub, chainedMessage(canonical, prev), sig) {
			return n, markTamper(n, fmt.Errorf("line %d: signature mismatch — trail was tampered, deleted from, reordered, or signed with a different key", n))
		}
		prev = got
		if hwm != nil && n == hwm.Count {
			sigAtCount = got
		}
	}
	// See Verify: the scan-error check stays ahead of the hwm check so a read
	// glitch surfaces as unavailable, not a false truncation tamper.
	if err := sc.Err(); err != nil {
		return n, markScan(err)
	}
	if err := checkHighWaterMark(hwm, n, sigAtCount, func(signed []byte, sigHex string) bool {
		sigBytes, derr := hex.DecodeString(sigHex)
		if derr != nil {
			return false
		}
		return ed25519.Verify(pub, chainedMessage(signed, ""), sigBytes)
	}); err != nil {
		return n, markBoundaryTamper(err)
	}
	return n, nil
}
