// Package evidence builds compliance-evidence packs from NockGuard's signed,
// tamper-evident audit trail. It does NOT re-implement signature verification —
// it calls internal/audit's HMAC or Ed25519 verifier, then applies the shared
// sessionverify GuardVerdict checkpoint-coverage rule used by `nockguard verify`.
//
// The whole value of the pack is that its Integrity Attestation FAILS LOUD when
// the chain is broken: a tampered, truncated, reordered, or wrong-key trail
// yields ChainIntact=false (not an error that aborts the pack), and that failure
// is rendered prominently. A pack over a broken trail is still produced — so a
// reviewer SEES the failure — but it can never claim the evidence is intact.
package evidence

import (
	"bufio"
	"bytes"
	"crypto/ed25519"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"sort"
	"time"

	"github.com/nocktechnologies/nockguard/internal/audit"
	"github.com/nocktechnologies/nockguard/internal/sessionverify"
)

// VerifyMode names the cryptographic mode used to verify a trail.
type VerifyMode string

const (
	ModeHMAC    VerifyMode = "hmac"
	ModeEd25519 VerifyMode = "ed25519"
)

// PackOptions configures a BuildPack call. Exactly one verification key source
// must be supplied: HMACKey (symmetric, tamper-evident) OR Ed25519PubHex
// (asymmetric, non-repudiable). AuditFiles lists one or more audit JSONL files
// to aggregate; filters narrow which entries land in the pack.
type PackOptions struct {
	Framework  Framework // which control set to map against (e.g. FrameworkSOC2)
	AuditFiles []string  // one or more audit JSONL paths to read & verify

	// Exactly one of these selects the verification mode.
	HMACKey       []byte // HMAC signing key (tamper-evident)
	Ed25519PubHex string // hex Ed25519 public key (non-repudiable)

	// Filters (all optional). Agent matches Event.Agent exactly. From/To bound
	// the entry timestamp inclusively; zero values mean unbounded.
	Agent string
	From  time.Time
	To    time.Time

	// Now overrides the generated-at clock for deterministic output (tests).
	Now func() time.Time
}

// VerificationResult is the Integrity Attestation: the outcome of verifying the
// underlying audit chain. It is the load-bearing claim of the whole pack.
type VerificationResult struct {
	Mode            VerifyMode `json:"mode"`
	EntriesVerified int        `json:"entries_verified"` // entries the chain verified before any break
	ChainIntact     bool       `json:"chain_intact"`     // false the instant any file fails verification
	PubKeyHex       string     `json:"pubkey_hex,omitempty"`
	VerifiedAt      string     `json:"verified_at"`
	// FileResults is the per-file outcome, so a multi-file pack shows exactly
	// which trail broke.
	FileResults []FileVerification `json:"file_results"`
	// Detail carries the human-readable failure reason when ChainIntact is false.
	Detail string `json:"detail,omitempty"`
}

// FileVerification is the verification outcome for a single audit file.
type FileVerification struct {
	Path            string `json:"path"`
	EntriesVerified int    `json:"entries_verified"`
	Intact          bool   `json:"intact"`
	Error           string `json:"error,omitempty"`
}

// ControlEvidence is one framework control plus the audit events that evidence
// it (after filtering).
type ControlEvidence struct {
	Control Control       `json:"control"`
	Events  []audit.Event `json:"events"`
}

// Pack is a complete, self-describing compliance-evidence pack.
type Pack struct {
	Framework     Framework          `json:"framework"`
	FrameworkName string             `json:"framework_name"`
	GeneratedAt   string             `json:"generated_at"`
	Agent         string             `json:"agent,omitempty"` // empty = all agents
	From          string             `json:"from,omitempty"`
	To            string             `json:"to,omitempty"`
	Agents        []string           `json:"agents"` // distinct agents present in the filtered evidence
	Verification  VerificationResult `json:"verification"`
	Controls      []ControlEvidence  `json:"controls"`
	AllEvents     []audit.Event      `json:"all_events"` // raw appendix: every filtered entry, in file+line order
}

// BuildPack reads, verifies, filters, and buckets the configured audit trails
// into a compliance-evidence pack. A verification failure on any trail is
// recorded into the attestation (ChainIntact=false) rather than aborting — so a
// pack over a tampered trail is still produced, with its failure rendered loud.
// It returns an error only for setup problems the caller must fix (no framework,
// no files, no/ambiguous key, unreadable file).
func BuildPack(opts PackOptions) (Pack, error) {
	now := time.Now
	if opts.Now != nil {
		now = opts.Now
	}

	def, ok := frameworkDef(opts.Framework)
	if !ok {
		return Pack{}, fmt.Errorf("unknown framework %q", opts.Framework)
	}
	if len(opts.AuditFiles) == 0 {
		return Pack{}, errors.New("no audit files supplied")
	}

	mode, pub, err := resolveMode(opts)
	if err != nil {
		return Pack{}, err
	}

	// 1) Snapshot each trail and checkpoint under the audit writer's shared
	// lock. Parse the trail snapshot for the raw appendix and control buckets; a
	// tampered trail still yields its now-suspect entries, which the attestation
	// flags and the evidence shows.
	snapshots := make([]auditSnapshot, 0, len(opts.AuditFiles))
	var allEntries []audit.Event
	for _, path := range opts.AuditFiles {
		snapshot, rerr := readAuditSnapshot(path)
		if rerr != nil {
			return Pack{}, fmt.Errorf("reading audit file %s: %w", path, rerr)
		}
		entries, rerr := parseEntries(snapshot.trail)
		if rerr != nil {
			return Pack{}, fmt.Errorf("reading audit file %s: %w", path, rerr)
		}
		allEntries = append(allEntries, entries...)
		snapshots = append(snapshots, snapshot)
	}

	// 2) Verify each file's chain via the existing audit package. Harden the
	// failure path: ANY file that fails verification (or errors) flips
	// ChainIntact to false for the whole pack — never let one passing file mask
	// another's break.
	vr := VerificationResult{
		Mode:        mode,
		ChainIntact: true,
		VerifiedAt:  now().UTC().Format(time.RFC3339),
	}
	if mode == ModeEd25519 {
		vr.PubKeyHex = opts.Ed25519PubHex
	}
	for _, snapshot := range snapshots {
		fv := verifyFile(snapshot, mode, opts.HMACKey, pub)
		vr.FileResults = append(vr.FileResults, fv)
		vr.EntriesVerified += fv.EntriesVerified
		if !fv.Intact {
			vr.ChainIntact = false
			if vr.Detail == "" {
				vr.Detail = fmt.Sprintf("%s: %s", snapshot.path, fv.Error)
			}
		}
	}

	// 3) Filter (agent + date range), preserving file+line order.
	filtered := make([]audit.Event, 0, len(allEntries))
	for _, ev := range allEntries {
		if !matchFilters(ev, opts) {
			continue
		}
		filtered = append(filtered, ev)
	}

	// 4) Bucket filtered events into the framework's controls.
	controls := make([]ControlEvidence, 0, len(def.Controls))
	for _, c := range def.Controls {
		ce := ControlEvidence{Control: c, Events: []audit.Event{}}
		for _, ev := range filtered {
			if c.matches(ev) {
				ce.Events = append(ce.Events, ev)
			}
		}
		controls = append(controls, ce)
	}

	pack := Pack{
		Framework:     def.ID,
		FrameworkName: def.Name,
		GeneratedAt:   now().UTC().Format(time.RFC3339),
		Agent:         opts.Agent,
		Agents:        distinctAgents(filtered),
		Verification:  vr,
		Controls:      controls,
		AllEvents:     filtered,
	}
	if !opts.From.IsZero() {
		pack.From = opts.From.UTC().Format(time.RFC3339)
	}
	if !opts.To.IsZero() {
		pack.To = opts.To.UTC().Format(time.RFC3339)
	}
	return pack, nil
}

// resolveMode validates that exactly one key source is set and returns the
// resolved mode (plus the parsed public key for Ed25519).
func resolveMode(opts PackOptions) (VerifyMode, ed25519.PublicKey, error) {
	hasHMAC := len(opts.HMACKey) > 0
	hasEd := opts.Ed25519PubHex != ""
	switch {
	case hasHMAC && hasEd:
		return "", nil, errors.New("provide exactly one verification key: HMACKey or Ed25519PubHex, not both")
	case hasEd:
		pub, err := audit.PublicKeyFromHex(opts.Ed25519PubHex)
		if err != nil {
			return "", nil, fmt.Errorf("invalid Ed25519 public key: %w", err)
		}
		return ModeEd25519, pub, nil
	case hasHMAC:
		return ModeHMAC, nil, nil
	default:
		return "", nil, errors.New("no verification key supplied: set HMACKey or Ed25519PubHex")
	}
}

// auditSnapshot holds one trail read and its corresponding checkpoint read.
type auditSnapshot struct {
	path          string
	trail         []byte
	checkpoint    []byte
	checkpointErr error
}

// readAuditSnapshot reads the checkpoint first, then the trail through one open
// file. Regular trails use the shared flock signed writers take exclusively.
func readAuditSnapshot(path string) (snapshot auditSnapshot, err error) {
	snapshot.path = path
	f, err := os.Open(path)
	if err != nil {
		return snapshot, err
	}
	defer f.Close()
	info, err := f.Stat()
	if err != nil {
		snapshot.checkpointErr = fmt.Errorf("stating audit snapshot: %w", err)
	} else if info.Mode().IsRegular() {
		if err := audit.LockShared(f.Fd()); err != nil {
			snapshot.checkpointErr = fmt.Errorf("locking audit snapshot: %w", err)
		} else {
			defer func() {
				if err := audit.UnlockFile(f.Fd()); err != nil && snapshot.checkpointErr == nil {
					snapshot.checkpointErr = fmt.Errorf("unlocking audit snapshot: %w", err)
				}
			}()
		}
	}

	checkpoint, checkpointErr := os.ReadFile(path + ".hwm")
	if errors.Is(checkpointErr, os.ErrNotExist) {
		checkpoint = nil
		checkpointErr = nil
	}
	snapshot.checkpoint = checkpoint
	if snapshot.checkpointErr == nil {
		snapshot.checkpointErr = checkpointErr
	}
	snapshot.trail, err = io.ReadAll(f)
	return snapshot, err
}

// verifyFile checks a trail snapshot and captures verification failures in the
// attestation so they remain visible in the pack.
func verifyFile(snapshot auditSnapshot, mode VerifyMode, key []byte, pub ed25519.PublicKey) FileVerification {
	var (
		n               int
		checkpointCount int
		err             error
	)
	fv := FileVerification{Path: snapshot.path}
	if snapshot.checkpointErr != nil {
		fv.Error = snapshot.checkpointErr.Error()
		return fv
	}
	if mode == ModeEd25519 {
		n, checkpointCount, err = audit.VerifyEd25519WithCheckpointBytes(snapshot.trail, snapshot.checkpoint, pub)
	} else {
		n, checkpointCount, err = audit.VerifyWithCheckpointBytes(snapshot.trail, snapshot.checkpoint, key)
	}
	fv.EntriesVerified = n
	if err != nil {
		fv.Error = err.Error()
		return fv
	}
	switch sessionverify.GuardVerdict(n, checkpointCount == n) {
	case sessionverify.VerdictNoRows:
		fv.Error = "NO_ROWS: audit trail is empty"
	case sessionverify.VerdictUnanchored:
		fv.Error = fmt.Sprintf("UNANCHORED: signed checkpoint covers %d of %d verified entries", checkpointCount, n)
	default:
		fv.Intact = true
	}
	return fv
}

// parseEntries parses every non-empty JSONL line of an audit snapshot into
// Events, in order. Verification remains the audit package's job.
func parseEntries(data []byte) ([]audit.Event, error) {
	sc := bufio.NewScanner(bytes.NewReader(data))
	sc.Buffer(make([]byte, 0, 64*1024), audit.MaxTrailLineBytes)
	var out []audit.Event
	line := 0
	for sc.Scan() {
		line++
		raw := sc.Bytes()
		if len(bytes.TrimSpace(raw)) == 0 {
			continue
		}
		var ev audit.Event
		if err := json.Unmarshal(raw, &ev); err != nil {
			return nil, fmt.Errorf("line %d: invalid json: %w", line, err)
		}
		out = append(out, ev)
	}
	if err := sc.Err(); err != nil {
		return nil, err
	}
	return out, nil
}

// matchFilters reports whether an event passes the agent and date-range filters.
// Timestamps that fail to parse are treated as out of range (excluded) only when
// a bound is set — an unbounded query keeps every entry regardless of timestamp
// shape.
func matchFilters(ev audit.Event, opts PackOptions) bool {
	if opts.Agent != "" && ev.Agent != opts.Agent {
		return false
	}
	if opts.From.IsZero() && opts.To.IsZero() {
		return true
	}
	ts, err := time.Parse(time.RFC3339, ev.Time)
	if err != nil {
		// A malformed timestamp can't be placed in a bounded window; exclude it
		// rather than silently include an unplaceable entry.
		return false
	}
	if !opts.From.IsZero() && ts.Before(opts.From) {
		return false
	}
	if !opts.To.IsZero() && ts.After(opts.To) {
		return false
	}
	return true
}

// distinctAgents returns the sorted, de-duplicated set of agent names present.
func distinctAgents(evs []audit.Event) []string {
	seen := map[string]struct{}{}
	var out []string
	for _, ev := range evs {
		if ev.Agent == "" {
			continue
		}
		if _, ok := seen[ev.Agent]; ok {
			continue
		}
		seen[ev.Agent] = struct{}{}
		out = append(out, ev.Agent)
	}
	sort.Strings(out)
	return out
}
