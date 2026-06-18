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
	"crypto/ed25519"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
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

// Auditor appends Events as JSON Lines to a file. It is safe for concurrent use
// both within a process (the mutex) and ACROSS processes when signing is enabled
// (an flock held across each signed append — see Record). A nil *Auditor and one
// built from an empty path are both disabled. When a signing key is set, each
// Record links into a tamper-evident hash chain.
type Auditor struct {
	clock func() time.Time

	mu     sync.Mutex
	f      *os.File
	path   string             // audit file path; used to re-read the on-disk chain head under the flock
	key    []byte             // HMAC signing key; empty = unsigned trail
	edPriv ed25519.PrivateKey // Ed25519 signing key; non-nil = non-repudiable trail (takes precedence over key)
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
	return func(a *Auditor) { a.edPriv = priv }
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
	if a.signing() {
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
	}
	f, err := os.OpenFile(path, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o644)
	if err != nil {
		return nil, err
	}
	a.f = f
	a.path = path
	return a, nil
}

// verifyExisting walks the existing trail and confirms the hash chain is intact
// before the auditor seeds its prevSig from the tail and starts appending. A
// missing file (nothing recorded yet) and unsigned mode are both no-ops. For
// Ed25519 the public key is derived from the configured private key, so the same
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
		_, err := VerifyEd25519(path, pub)
		return err
	}
	_, err := Verify(path, a.key)
	return err
}

// Enabled reports whether the Auditor is writing to a file. Nil-safe, so callers
// can guard with `if a.Enabled()` exactly like the validator and limiter.
func (a *Auditor) Enabled() bool {
	return a != nil && a.f != nil
}

// Record stamps the event with the current time and appends it as one JSON line.
// It is a no-op on a disabled (or nil) Auditor. The write is serialized within the
// process by the mutex; when signing, it is ALSO serialized across processes by an
// flock so that concurrent records never interleave within a line and the
// signature chain stays consistent end to end.
func (a *Auditor) Record(ev Event) error {
	if !a.Enabled() {
		return nil
	}
	ev.Time = a.clock().Format(time.RFC3339)
	ev.Sig = "" // canonical content never includes the signature itself

	a.mu.Lock()
	defer a.mu.Unlock()

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
		if err := lockExclusive(a.f.Fd()); err != nil {
			return err
		}
		defer unlockFile(a.f.Fd())

		last, err := lastSig(a.path)
		if err != nil {
			return err
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
	if _, err = a.f.Write(line); err != nil {
		return err
	}
	// Signing mode only, still under the flock held above: advance the
	// tail-truncation high-water-mark so a later removal of this entry is
	// detectable (N8154). ev.Sig is this entry's signature.
	if a.signing() {
		return a.updateHighWaterMark(ev.Sig)
	}
	return nil
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

// updateHighWaterMark rewrites the signed sidecar after an entry is appended.
// MUST be called under the same exclusive flock Record holds while signing, so
// the count read -> increment -> write is atomic across processes. newSig is the
// signature of the just-appended entry and becomes the checkpoint's last_sig.
// The sidecar is written AFTER the trail append (never before): a crash between
// the two leaves the sidecar one entry BEHIND the trail (n >= count, which Verify
// accepts), never ahead (which would false-trip truncation). Best-effort: a
// sidecar write failure is returned to Record but the entry is already durably
// appended, so the chain itself is never compromised by a checkpoint problem.
func (a *Auditor) updateHighWaterMark(newSig string) error {
	hwmPath := a.path + hwmSuffix
	prev, err := readHighWaterMark(hwmPath)
	if err != nil {
		return err
	}
	var count int
	if prev != nil {
		count = prev.Count + 1
	} else {
		// First checkpoint on this trail: count the file once (it now includes
		// the just-appended entry). O(n) one time; O(1) increments thereafter.
		count, err = countEntries(a.path)
		if err != nil {
			return err
		}
	}
	hwm := highWaterMark{Count: count, LastSig: newSig}
	hwm.Sig = a.sign(hwmSignedBytes(count, newSig), "")
	data, err := json.Marshal(hwm)
	if err != nil {
		return err
	}
	// Atomic replace so a reader never sees a half-written checkpoint.
	tmp := hwmPath + ".tmp"
	if err := os.WriteFile(tmp, append(data, '\n'), 0o644); err != nil {
		return err
	}
	return os.Rename(tmp, hwmPath)
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
	var hwm highWaterMark
	if err := json.Unmarshal(bytes.TrimSpace(data), &hwm); err != nil {
		return nil, fmt.Errorf("high-water-mark %s is corrupt: %w", hwmPath, err)
	}
	return &hwm, nil
}

// countEntries returns the number of non-empty lines in a JSONL trail. Used once
// when a high-water-mark is first written onto a pre-existing trail; thereafter
// the count is incremented from the sidecar in O(1).
func countEntries(path string) (int, error) {
	f, err := os.Open(path)
	if err != nil {
		if os.IsNotExist(err) {
			return 0, nil
		}
		return 0, err
	}
	defer f.Close()
	sc := bufio.NewScanner(f)
	sc.Buffer(make([]byte, 0, 64*1024), 1024*1024)
	n := 0
	for sc.Scan() {
		if len(bytes.TrimSpace(sc.Bytes())) > 0 {
			n++
		}
	}
	return n, sc.Err()
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
	hwm, herr := readHighWaterMark(path + hwmSuffix)
	if herr != nil {
		return 0, herr
	}
	sc := bufio.NewScanner(f)
	sc.Buffer(make([]byte, 0, 64*1024), 1024*1024)
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
		if hwm != nil && n == hwm.Count {
			sigAtCount = got
		}
	}
	if err := sc.Err(); err != nil {
		return n, err
	}
	if err := checkHighWaterMark(hwm, n, sigAtCount, func(signed []byte, sigHex string) bool {
		return hmac.Equal([]byte(signLine(key, signed, "")), []byte(sigHex))
	}); err != nil {
		return n, err
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
	f, err := os.Open(path)
	if err != nil {
		return 0, err
	}
	defer f.Close()
	hwm, herr := readHighWaterMark(path + hwmSuffix)
	if herr != nil {
		return 0, herr
	}
	sc := bufio.NewScanner(f)
	sc.Buffer(make([]byte, 0, 64*1024), 1024*1024)
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
			return n, fmt.Errorf("line %d: invalid json: %w", n, err)
		}
		if ev.Sig == "" {
			return n, fmt.Errorf("line %d: entry is not signed", n)
		}
		sig, err := hex.DecodeString(ev.Sig)
		if err != nil {
			return n, fmt.Errorf("line %d: signature is not valid hex: %w", n, err)
		}
		got := ev.Sig
		ev.Sig = ""
		canonical, err := json.Marshal(ev)
		if err != nil {
			return n, err
		}
		if !ed25519.Verify(pub, chainedMessage(canonical, prev), sig) {
			return n, fmt.Errorf("line %d: signature mismatch — trail was tampered, deleted from, reordered, or signed with a different key", n)
		}
		prev = got
		if hwm != nil && n == hwm.Count {
			sigAtCount = got
		}
	}
	if err := sc.Err(); err != nil {
		return n, err
	}
	if err := checkHighWaterMark(hwm, n, sigAtCount, func(signed []byte, sigHex string) bool {
		sigBytes, derr := hex.DecodeString(sigHex)
		if derr != nil {
			return false
		}
		return ed25519.Verify(pub, chainedMessage(signed, ""), sigBytes)
	}); err != nil {
		return n, err
	}
	return n, nil
}
