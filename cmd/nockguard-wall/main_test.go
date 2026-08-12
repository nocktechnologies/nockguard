package main

import (
	"bytes"
	"encoding/csv"
	"encoding/json"
	"log"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"
	"time"
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
	p := computePulse(evs, "", "")
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
	if pa := computePulse(evs, "", "allow"); pa.Total != 3 || pa.Approved != 3 || pa.Blocked != 0 || pa.Threats != 0 {
		t.Fatalf("decision filter: got %+v want total 3, approved 3, blocked 0, threats 0", pa)
	}

	// Text filter respected: case-insensitive substring over "agent tool".
	if pk := computePulse(evs, "KIT", ""); pk.Total != 2 || pk.Approved != 1 || pk.Blocked != 1 {
		t.Fatalf("agent text filter: got %+v want total 2, approved 1, blocked 1", pk)
	}
	if pf := computePulse(evs, "webfetch", ""); pf.Total != 1 || pf.Pending != 1 {
		t.Fatalf("tool text filter: got %+v want total 1, pending 1", pf)
	}

	// Combined filters intersect.
	pc := computePulse(evs, "ash", "allow")
	if pc.Total != 1 || len(pc.TopAgents) != 1 || pc.TopAgents[0].Agent != "ash" {
		t.Fatalf("combined filter: got %+v want total 1, top agent ash", pc)
	}
}

func TestReplayHistoryLogsScannerErrors(t *testing.T) {
	f, err := os.CreateTemp(t.TempDir(), "audit-*.jsonl")
	if err != nil {
		t.Fatal(err)
	}
	longLine := strings.Repeat("x", 1024*1024+1)
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

	replayHistory(f.Name(), &bytes.Buffer{})

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
	cases := []struct{ q, decision string }{
		{"", ""},
		{"", "allow"},
		{"ash", ""},
		{"KIT", ""},      // case-insensitive
		{"webfetch", ""}, // matches tool, not agent
		{"ash", "allow"}, // combined
		{"nomatch", ""},  // empty result
		{"", "nonsense"}, // unknown decision → empty
	}
	for _, c := range cases {
		got := len(filterEvents(exportEvents, c.q, c.decision))
		want := computePulse(exportEvents, c.q, c.decision).Total
		if got != want {
			t.Fatalf("filterEvents/pulse drift for q=%q decision=%q: rows=%d total=%d", c.q, c.decision, got, want)
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
	f.Close()

	b := newBroker()
	b.auditPath = f.Name()

	req := httptest.NewRequest(http.MethodGet, "/export?decision=block", nil)
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
	total := computePulse(loadEvents(b.auditPath), "", "block").Total
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
		f.Write(append(b, '\n'))
	}
	f.Close()

	b := newBroker()
	b.auditPath = f.Name()
	req := httptest.NewRequest(http.MethodGet, "/export?format=json&decision=allow", nil)
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
