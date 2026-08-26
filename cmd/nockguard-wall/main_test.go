package main

import (
	"bytes"
	"crypto/ed25519"
	"encoding/csv"
	"encoding/hex"
	"encoding/json"
	"log"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/nocktechnologies/nockguard/internal/audit"
)

func TestBrokerUnregisterDoesNotDependOnBackgroundRunLoop(t *testing.T) {
	b := newBroker()
	c := make(chan event, 1)

	b.register(c)
	b.unregister(c)

	select {
	case _, ok := <-c:
		if ok {
			t.Fatal("client channel remains open after unregister")
		}
	case <-time.After(100 * time.Millisecond):
		t.Fatal("unregister did not close client channel")
	}
}

func TestComputePulse(t *testing.T) {
	evs := []event{
		{Agent: "kit", Tool: "Read", Decision: "allow"},
		{Agent: "kit", Tool: "Bash: rm -rf /", Decision: "block", Reason: "destructive"},
		{Agent: "ash", Tool: "WebFetch", Decision: "ratelimit"},
		{Agent: "ash", Tool: "Read", Decision: "allow"},
		{Agent: "ash", Tool: "mcp__x", Decision: "deny"},
		{Agent: "bob", Tool: "Read", Decision: "allow"},
		{Agent: "bob", Tool: "Edit", Decision: "hide"},
		{Agent: "vale", Tool: "Read", Decision: "hide"},
	}

	// No filters: every event counted, bucketed by decision.
	p := computePulse(evs, "", "", "")
	if p.Total != 8 {
		t.Fatalf("total: got %d want 8", p.Total)
	}
	if p.Approved != 3 || p.Pending != 1 || p.Blocked != 4 {
		t.Fatalf("buckets: approved=%d pending=%d blocked=%d want 3/1/4", p.Approved, p.Pending, p.Blocked)
	}
	// Threat tiers, derived from (decision, reason): the "rm -rf" block is
	// critical, the reasonless deny is high, and the ratelimit + two hides are
	// low; the three allows are none (not counted as caught).
	if p.Threats != 5 || p.Critical != 1 || p.High != 1 || p.Low != 3 {
		t.Fatalf("threats: threats=%d crit=%d high=%d low=%d want 5/1/1/3",
			p.Threats, p.Critical, p.High, p.Low)
	}
	// Top agents by volume; the tie at 2 (bob, kit) breaks by name, and the cap
	// of 3 drops vale.
	if len(p.TopAgents) != 3 {
		t.Fatalf("top agents: got %d want 3", len(p.TopAgents))
	}
	if p.TopAgents[0] != (agentCount{"ash", 3}) ||
		p.TopAgents[1] != (agentCount{"bob", 2}) ||
		p.TopAgents[2] != (agentCount{"kit", 2}) {
		t.Fatalf("top agents order: got %+v want ash/3, bob/2, kit/2", p.TopAgents)
	}

	// Decision filter respected: only allow events survive.
	if pa := computePulse(evs, "", "allow", ""); pa.Total != 3 || pa.Approved != 3 || pa.Blocked != 0 || pa.Threats != 0 {
		t.Fatalf("decision filter: got %+v want total 3, approved 3, blocked 0, threats 0", pa)
	}

	// Text filter respected: case-insensitive substring over "agent tool".
	if pk := computePulse(evs, "KIT", "", ""); pk.Total != 2 || pk.Approved != 1 || pk.Blocked != 1 {
		t.Fatalf("agent text filter: got %+v want total 2, approved 1, blocked 1", pk)
	}
	if pf := computePulse(evs, "webfetch", "", ""); pf.Total != 1 || pf.Pending != 1 {
		t.Fatalf("tool text filter: got %+v want total 1, pending 1", pf)
	}

	// Severity filter respected. "threat" = any live catch (crit+high+low): the 3
	// allows drop, leaving the 5 caught events.
	if pt := computePulse(evs, "", "", "threat"); pt.Total != 5 || pt.Approved != 0 || pt.Threats != 5 {
		t.Fatalf("threat severity filter: got %+v want total 5, approved 0, threats 5", pt)
	}
	// Exact tier: only the critical "rm -rf" block.
	if pcrit := computePulse(evs, "", "", "critical"); pcrit.Total != 1 || pcrit.Critical != 1 || pcrit.Blocked != 1 {
		t.Fatalf("critical severity filter: got %+v want total 1, critical 1, blocked 1", pcrit)
	}
	// "none" is a real severity (allows only), NOT the same as no filter.
	if pn := computePulse(evs, "", "", "none"); pn.Total != 3 || pn.Approved != 3 || pn.Threats != 0 {
		t.Fatalf("none severity filter: got %+v want total 3, approved 3, threats 0", pn)
	}
	// "low" = ratelimit + two hides.
	if pl := computePulse(evs, "", "", "low"); pl.Total != 3 || pl.Low != 3 {
		t.Fatalf("low severity filter: got %+v want total 3, low 3", pl)
	}

	// Combined filters intersect (text ∩ decision).
	pc := computePulse(evs, "ash", "allow", "")
	if pc.Total != 1 || len(pc.TopAgents) != 1 || pc.TopAgents[0].Agent != "ash" {
		t.Fatalf("combined filter: got %+v want total 1, top agent ash", pc)
	}
	// Combined text ∩ severity: "ash" as a substring over "agent tool" catches
	// kit's "Bash: rm -rf /" (critical) too, plus ash's ratelimit (low) and
	// reasonless deny (high) — three threats; ash's allow drops as none.
	if pcs := computePulse(evs, "ash", "", "threat"); pcs.Total != 3 || pcs.Threats != 3 || pcs.Critical != 1 || pcs.High != 1 || pcs.Low != 1 {
		t.Fatalf("combined text+severity filter: got %+v want total 3, threats 3, crit/high/low 1/1/1", pcs)
	}
}

func TestReplayHistoryLogsScannerErrors(t *testing.T) {
	f, err := os.CreateTemp(t.TempDir(), "audit-*.jsonl")
	if err != nil {
		t.Fatal(err)
	}
	// Must exceed the shared trail-line cap (N9870 raised it to audit.MaxTrailLineBytes)
	// so the wall's replay scanner still errors and logs on a genuinely over-cap line.
	longLine := strings.Repeat("x", audit.MaxTrailLineBytes+1)
	if _, err := f.WriteString(longLine + "\n"); err != nil {
		t.Fatal(err)
	}
	if err := f.Close(); err != nil {
		t.Fatal(err)
	}

	var logs bytes.Buffer
	previousWriter := log.Writer()
	log.SetOutput(&logs)
	t.Cleanup(func() { log.SetOutput(previousWriter) })

	b := newBroker()
	b.auditPath = f.Name()
	b.replayHistory(&bytes.Buffer{})

	if !strings.Contains(logs.String(), "error replaying history") {
		t.Fatalf("expected scanner error log, got %q", logs.String())
	}
}

// exportEvents is the sample window shared by the export tests: a mix of
// decisions and agents so the filter and formula-escaping paths are exercised.
var exportEvents = []event{
	{Ts: "t1", Agent: "kit", Tool: "Read", Decision: "allow"},
	{Ts: "t2", Agent: "kit", Tool: "Bash: rm -rf /", Decision: "block", Reason: "destructive"},
	{Ts: "t3", Agent: "ash", Tool: "WebFetch", Decision: "ratelimit"},
	{Ts: "t4", Agent: "ash", Tool: "Read", Decision: "allow"},
	{Ts: "t5", Agent: "ash", Tool: "mcp__x", Decision: "deny"},
}

// TestFilterEventsMatchesPulse locks the invariant that the export and the
// pulse aggregate never disagree: filterEvents must return exactly as many rows
// as computePulse counts as Total, for the same filters. Both go through the
// single shared matches() predicate, so a drift here is a real regression.
func TestFilterEventsMatchesPulse(t *testing.T) {
	cases := []struct{ q, decision, severity string }{
		{"", "", ""},
		{"", "allow", ""},
		{"ash", "", ""},
		{"KIT", "", ""},      // case-insensitive
		{"webfetch", "", ""}, // matches tool, not agent
		{"ash", "allow", ""}, // combined
		{"nomatch", "", ""},  // empty result
		{"", "nonsense", ""}, // unknown decision → empty
		{"", "", "threat"},   // any live catch (crit+high+low)
		{"", "", "critical"}, // exact tier
		{"", "", "high"},
		{"", "", "low"},
		{"", "", "none"},        // allows only — distinct from no filter
		{"", "", "nonsense"},    // unknown tier → empty
		{"ash", "", "threat"},   // text ∩ severity
		{"", "deny", "high"},    // decision ∩ severity
		{"", "allow", "threat"}, // contradictory (allow is never a threat) → empty
	}
	for _, c := range cases {
		got := len(filterEvents(exportEvents, c.q, c.decision, c.severity))
		want := computePulse(exportEvents, c.q, c.decision, c.severity).Total
		if got != want {
			t.Fatalf("filterEvents/pulse drift for q=%q decision=%q severity=%q: rows=%d total=%d", c.q, c.decision, c.severity, got, want)
		}
	}
}

func TestCSVSafe(t *testing.T) {
	cases := map[string]string{
		"":                  "",
		"Read":              "Read",
		"=cmd|'/c calc'!A1": "'=cmd|'/c calc'!A1",
		"+1":                "'+1",
		"-1":                "'-1",
		"@SUM(A1)":          "'@SUM(A1)",
		"Bash: rm -rf /":    "Bash: rm -rf /", // leading 'B', not a formula lead
		// OWASP also lists tab/CR/LF as formula-injection leads (a spreadsheet
		// swallows them to reach the operator behind).
		"\t=1+1": "'\t=1+1",
		"\r=1+1": "'\r=1+1",
		"\n=1+1": "'\n=1+1",
		// Full-width Unicode operators normalise back to ASCII on import; these
		// are multi-byte, so the byte-0 check the original used would miss them.
		"＝1+1":   "'＝1+1",
		"＋1":     "'＋1",
		"－1":     "'－1",
		"＠SUM()": "'＠SUM()",
	}
	for in, want := range cases {
		if got := csvSafe(in); got != want {
			t.Fatalf("csvSafe(%q) = %q, want %q", in, got, want)
		}
	}
}

// TestHandleExportCSV drives the endpoint over a real audit file and asserts
// the CSV header, that a formula-injection reason is neutralised, and that the
// row count equals what /pulse counts for the same filter (screen==file parity
// at the server layer).
func TestHandleExportCSV(t *testing.T) {
	f, err := os.CreateTemp(t.TempDir(), "audit-*.jsonl")
	if err != nil {
		t.Fatal(err)
	}
	rows := []event{
		{Ts: "t1", Agent: "kit", Tool: "Read", Decision: "allow"},
		{Ts: "t2", Agent: "ash", Tool: "Edit", Decision: "block", Reason: "=DANGER()"},
		{Ts: "t3", Agent: "ash", Tool: "WebFetch", Decision: "ratelimit"},
	}
	for _, ev := range rows {
		b, _ := json.Marshal(ev)
		if _, err := f.Write(append(b, '\n')); err != nil {
			t.Fatal(err)
		}
	}
	if err := f.Close(); err != nil {
		t.Fatal(err)
	}

	b := newBroker()
	b.auditPath = f.Name()

	req := httptest.NewRequest(http.MethodGet, "/export?decision=block", nil).WithContext(t.Context())
	rec := httptest.NewRecorder()
	b.handleExport(rec, req)

	if ct := rec.Header().Get("Content-Type"); !strings.HasPrefix(ct, "text/csv") {
		t.Fatalf("content-type: got %q want text/csv", ct)
	}
	if cd := rec.Header().Get("Content-Disposition"); !strings.Contains(cd, "nockguard-wall.csv") {
		t.Fatalf("content-disposition: got %q", cd)
	}

	recs, err := csv.NewReader(strings.NewReader(rec.Body.String())).ReadAll()
	if err != nil {
		t.Fatalf("export is not valid CSV: %v", err)
	}
	if len(recs) != 2 { // header + 1 filtered row
		t.Fatalf("csv rows: got %d want 2 (header + block row)", len(recs))
	}
	if got := strings.Join(recs[0], ","); got != "ts,agent,tool,decision,severity,reason" {
		t.Fatalf("csv header: got %q", got)
	}
	// The block row's reason "=DANGER()" must be prefixed with a quote.
	if reason := recs[1][5]; reason != "'=DANGER()" {
		t.Fatalf("formula injection not neutralised: reason=%q", reason)
	}
	// Server parity: exported data rows == pulse Total for the same filter.
	total := computePulse(loadEvents(b.auditPath), "", "block", "").Total
	if dataRows := len(recs) - 1; dataRows != total {
		t.Fatalf("export/pulse row parity: csv=%d pulse=%d", dataRows, total)
	}
}

func TestHandleExportJSON(t *testing.T) {
	f, err := os.CreateTemp(t.TempDir(), "audit-*.jsonl")
	if err != nil {
		t.Fatal(err)
	}
	for _, ev := range []event{
		{Ts: "t1", Agent: "kit", Tool: "Read", Decision: "allow"},
		{Ts: "t2", Agent: "ash", Tool: "Edit", Decision: "block", Reason: "x"},
	} {
		b, _ := json.Marshal(ev)
		if _, err := f.Write(append(b, '\n')); err != nil {
			t.Fatal(err)
		}
	}
	if err := f.Close(); err != nil {
		t.Fatal(err)
	}

	b := newBroker()
	b.auditPath = f.Name()
	req := httptest.NewRequest(http.MethodGet, "/export?format=json&decision=allow", nil).WithContext(t.Context())
	rec := httptest.NewRecorder()
	b.handleExport(rec, req)

	if ct := rec.Header().Get("Content-Type"); !strings.HasPrefix(ct, "application/json") {
		t.Fatalf("content-type: got %q want application/json", ct)
	}
	var out []event
	if err := json.Unmarshal(rec.Body.Bytes(), &out); err != nil {
		t.Fatalf("json export not decodable: %v", err)
	}
	if len(out) != 1 || out[0].Decision != "allow" {
		t.Fatalf("json export: got %+v want 1 allow row", out)
	}
	// severity is derived on load, so the export carries it.
	if out[0].Severity == "" {
		t.Fatalf("expected derived severity on exported event, got empty")
	}
}

// --- audit-chain verification (N9868) ---------------------------------------

// writeSignedTrail records the given events into an Ed25519-signed trail through
// the REAL auditor, so the .hwm sidecar and chain are produced exactly as in
// production. Tests then tamper the file in place to synthesize a chain break.
func writeSignedTrail(t *testing.T, path string, priv ed25519.PrivateKey, evs []audit.Event) {
	t.Helper()
	a, err := audit.New(path, audit.WithEd25519Key(priv))
	if err != nil {
		t.Fatalf("audit.New: %v", err)
	}
	for _, ev := range evs {
		if err := a.Record(ev); err != nil {
			t.Fatalf("Record: %v", err)
		}
	}
	if err := a.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}
}

// writeHMACTrail records the given events into an HMAC-signed trail through the
// REAL auditor (WithSigningKey), so the .hwm sidecar and chain are produced
// exactly as in production — the symmetric counterpart to writeSignedTrail.
func writeHMACTrail(t *testing.T, path string, key []byte, evs []audit.Event) {
	t.Helper()
	a, err := audit.New(path, audit.WithSigningKey(key))
	if err != nil {
		t.Fatalf("audit.New: %v", err)
	}
	for _, ev := range evs {
		if err := a.Record(ev); err != nil {
			t.Fatalf("Record: %v", err)
		}
	}
	if err := a.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}
}

func sampleTrailEvents() []audit.Event {
	return []audit.Event{
		{Agent: "kit", Tool: "Read", Decision: "allow"},
		{Agent: "ash", Tool: "Bash", Decision: "block", Reason: "secret-exfil"},
		{Agent: "vale", Tool: "WebFetch", Decision: "ratelimit", Reason: "rate"},
	}
}

func doVerify(t *testing.T, b *broker) verifyReport {
	t.Helper()
	req := httptest.NewRequest(http.MethodGet, "/verify", nil).WithContext(t.Context())
	w := httptest.NewRecorder()
	b.handleVerify(w, req)
	res := w.Result()
	defer res.Body.Close()
	if res.StatusCode != http.StatusOK {
		t.Fatalf("/verify status = %d, want 200", res.StatusCode)
	}
	var rep verifyReport
	if err := json.NewDecoder(res.Body).Decode(&rep); err != nil {
		t.Fatalf("decode /verify: %v", err)
	}
	return rep
}

// TestVerifyEndpoint proves /verify reports a clean chain as intact and flags a
// tampered chain with the break index, sourcing the trusted key SERVER-SIDE by
// env-var name (decision b) — never a request parameter.
func TestVerifyEndpoint(t *testing.T) {
	pub, priv, _ := ed25519.GenerateKey(nil)
	path := filepath.Join(t.TempDir(), "audit.jsonl")
	writeSignedTrail(t, path, priv, sampleTrailEvents())

	t.Setenv("NOCKGUARD_TEST_AUDIT_PUB", hex.EncodeToString(pub))
	v, err := newVerifier("NOCKGUARD_TEST_AUDIT_PUB", "")
	if err != nil {
		t.Fatalf("newVerifier: %v", err)
	}
	b := newBroker()
	b.auditPath = path
	b.verifier = v

	// Clean trail: chain intact, all three entries verified, no break.
	rep := doVerify(t, b)
	if rep.ChainIntact == nil || !*rep.ChainIntact {
		t.Fatalf("clean trail: chain_intact = %v, want true", rep.ChainIntact)
	}
	if rep.EntriesVerified != 3 {
		t.Fatalf("clean trail: entries_verified = %d, want 3", rep.EntriesVerified)
	}
	if rep.BreakAt != nil {
		t.Fatalf("clean trail: break_at = %v, want nil", *rep.BreakAt)
	}

	// Tamper the MIDDLE entry — flip the recorded block to allow. A mid-line edit
	// yields a deterministic break at entry 2.
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	tampered := strings.Replace(string(data), `"decision":"block"`, `"decision":"allow"`, 1)
	if tampered == string(data) {
		t.Fatal("tamper replacement did not change the trail")
	}
	if err := os.WriteFile(path, []byte(tampered), 0o644); err != nil {
		t.Fatal(err)
	}

	rep = doVerify(t, b)
	if rep.ChainIntact == nil || *rep.ChainIntact {
		t.Fatalf("tampered trail: chain_intact = %v, want false", rep.ChainIntact)
	}
	if rep.BreakAt == nil || *rep.BreakAt != 2 {
		t.Fatalf("tampered trail: break_at = %v, want 2", rep.BreakAt)
	}
	if rep.EntriesVerified != 1 {
		t.Fatalf("tampered trail: entries_verified = %d, want 1 (the entry before the break)", rep.EntriesVerified)
	}
	if rep.Detail == nil || *rep.Detail == "" {
		t.Fatal("tampered trail: expected a non-empty detail")
	}
}

// TestVerifyEndpointHMAC exercises the modeHMAC branch of the verifier — the
// default: case that calls audit.Verify — which the Ed25519 tests never reach.
// The trusted HMAC key is sourced SERVER-SIDE by env-var name (--verify-key-env),
// exactly as the wall resolves it in production. A clean HMAC trail verifies
// intact; tampering the middle entry breaks the chain at entry 2.
func TestVerifyEndpointHMAC(t *testing.T) {
	key := []byte("test-hmac-audit-key-not-a-real-secret")
	path := filepath.Join(t.TempDir(), "audit.jsonl")
	writeHMACTrail(t, path, key, sampleTrailEvents())

	t.Setenv("NOCKGUARD_TEST_AUDIT_HMAC", string(key))
	// pubEnv MUST be "": Ed25519 takes precedence in newVerifier, so a populated
	// pub env would silently route to modeEd25519 and this would not test HMAC.
	v, err := newVerifier("", "NOCKGUARD_TEST_AUDIT_HMAC")
	if err != nil {
		t.Fatalf("newVerifier: %v", err)
	}
	if v.mode != modeHMAC {
		t.Fatalf("verifier mode = %d, want modeHMAC (%d)", v.mode, modeHMAC)
	}
	b := newBroker()
	b.auditPath = path
	b.verifier = v

	// Clean trail: chain intact, all three entries verified, no break.
	rep := doVerify(t, b)
	if rep.ChainIntact == nil || !*rep.ChainIntact {
		t.Fatalf("clean HMAC trail: chain_intact = %v, want true", rep.ChainIntact)
	}
	if rep.EntriesVerified != 3 {
		t.Fatalf("clean HMAC trail: entries_verified = %d, want 3", rep.EntriesVerified)
	}
	if rep.BreakAt != nil {
		t.Fatalf("clean HMAC trail: break_at = %v, want nil", *rep.BreakAt)
	}

	// Tamper the MIDDLE entry so the break lands inside the scan loop (entry 2),
	// not the post-scan .hwm path — a deterministic, mid-chain break.
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	tampered := strings.Replace(string(data), `"decision":"block"`, `"decision":"allow"`, 1)
	if tampered == string(data) {
		t.Fatal("tamper replacement did not change the trail")
	}
	if err := os.WriteFile(path, []byte(tampered), 0o644); err != nil {
		t.Fatal(err)
	}

	rep = doVerify(t, b)
	if rep.ChainIntact == nil || *rep.ChainIntact {
		t.Fatalf("tampered HMAC trail: chain_intact = %v, want false", rep.ChainIntact)
	}
	if rep.BreakAt == nil || *rep.BreakAt != 2 {
		t.Fatalf("tampered HMAC trail: break_at = %v, want 2", rep.BreakAt)
	}
	if rep.EntriesVerified != 1 {
		t.Fatalf("tampered HMAC trail: entries_verified = %d, want 1 (the entry before the break)", rep.EntriesVerified)
	}
	if rep.Detail == nil || *rep.Detail == "" {
		t.Fatal("tampered HMAC trail: expected a non-empty detail")
	}
}

// TestReplayHistoryEnrichesVerifyState proves per-event enrichment: replay tags
// entries before the break "ok", the broken entry "broken", and everything after
// it "unknown".
func TestReplayHistoryEnrichesVerifyState(t *testing.T) {
	pub, priv, _ := ed25519.GenerateKey(nil)
	path := filepath.Join(t.TempDir(), "audit.jsonl")
	writeSignedTrail(t, path, priv, sampleTrailEvents())

	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte(strings.Replace(string(data), `"decision":"block"`, `"decision":"allow"`, 1)), 0o644); err != nil {
		t.Fatal(err)
	}

	t.Setenv("NOCKGUARD_TEST_AUDIT_PUB2", hex.EncodeToString(pub))
	v, err := newVerifier("NOCKGUARD_TEST_AUDIT_PUB2", "")
	if err != nil {
		t.Fatal(err)
	}
	b := newBroker()
	b.auditPath = path
	b.verifier = v

	var buf bytes.Buffer
	b.replayHistory(&buf)

	states := replayedVerifyStates(t, &buf)
	want := []string{"ok", "broken", "unknown"}
	if len(states) != len(want) {
		t.Fatalf("enriched %d events, want %d (%v)", len(states), len(want), states)
	}
	for i := range want {
		if states[i] != want[i] {
			t.Fatalf("event %d verifyState = %q, want %q (all: %v)", i, states[i], want[i], states)
		}
	}
}

// TestVerifyDisabledIsUnknown proves that with no key configured the wall reports
// chain_intact:null (not false) so the tamper banner never falsely fires, and
// live events fall back to "unknown".
func TestVerifyDisabledIsUnknown(t *testing.T) {
	path := filepath.Join(t.TempDir(), "audit.jsonl")
	writeSignedTrail(t, path, ed25519.NewKeyFromSeed(make([]byte, ed25519.SeedSize)), sampleTrailEvents())

	// Point at an env var that is not set → verifier disabled.
	v, err := newVerifier("NOCKGUARD_TEST_UNSET_ENV", "")
	if err != nil {
		t.Fatalf("newVerifier: %v", err)
	}
	b := newBroker()
	b.auditPath = path
	b.verifier = v

	rep := doVerify(t, b)
	if rep.ChainIntact != nil {
		t.Fatalf("disabled verifier: chain_intact = %v, want null", *rep.ChainIntact)
	}
	if got := b.tailState(); got != "unknown" {
		t.Fatalf("tailState = %q, want unknown", got)
	}
}

// TestTailTipPendingOnIntactChain proves that a LIVE tailed entry badges as
// "unknown" (pending re-verify) even when the cached snapshot reports an intact,
// server-verified chain. A live tip has not been individually verified at tail
// time, so it must not inherit "ok" from an intact snapshot — that would let a
// freshly appended, not-yet-verified (possibly tampered) entry wear the verified
// badge until the next /verify cycle. "ok" is earned only via the replay/snapshot
// path once /verify confirms the entry.
func TestTailTipPendingOnIntactChain(t *testing.T) {
	pub, priv, _ := ed25519.GenerateKey(nil)
	path := filepath.Join(t.TempDir(), "audit.jsonl")
	writeSignedTrail(t, path, priv, sampleTrailEvents())

	t.Setenv("NOCKGUARD_TEST_AUDIT_PUB", hex.EncodeToString(pub))
	v, err := newVerifier("NOCKGUARD_TEST_AUDIT_PUB", "")
	if err != nil {
		t.Fatalf("newVerifier: %v", err)
	}
	b := newBroker()
	b.auditPath = path
	b.verifier = v

	// Populate the cached snapshot with an intact, server-verified chain.
	rep := doVerify(t, b)
	if rep.ChainIntact == nil || !*rep.ChainIntact {
		t.Fatalf("clean trail: chain_intact = %v, want true", rep.ChainIntact)
	}

	// Even so, the live tip is pending — never "ok".
	if got := b.tailState(); got != "unknown" {
		t.Fatalf("tailState on intact chain = %q, want unknown (live tip is pending, not server-verified)", got)
	}
}

func replayedVerifyStates(t *testing.T, buf *bytes.Buffer) []string {
	t.Helper()
	var out []string
	for _, ln := range strings.Split(buf.String(), "\n") {
		ln = strings.TrimSpace(ln)
		if !strings.HasPrefix(ln, "data: ") {
			continue
		}
		var ev event
		if err := json.Unmarshal([]byte(strings.TrimPrefix(ln, "data: ")), &ev); err != nil {
			t.Fatalf("unmarshal replayed event: %v", err)
		}
		out = append(out, ev.VerifyState)
	}
	return out
}
