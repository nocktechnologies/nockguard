package main

import (
	"bytes"
	"log"
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
