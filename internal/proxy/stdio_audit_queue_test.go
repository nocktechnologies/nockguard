package proxy

import (
	"bytes"
	"log"
	"sort"
	"strings"
	"sync"
	"testing"

	"github.com/nocktechnologies/nockguard/internal/extract"
	"github.com/nocktechnologies/nockguard/internal/policy"
)

// TestStdioDrainDoesNotLoseResolvedAudits verifies that when the upstream
// closes, drainAudits marks all still-pending seqs as resolved and flushes
// them, ensuring resolved seqs blocked behind unresolved ones are emitted.
func TestStdioDrainDoesNotLoseResolvedAudits(t *testing.T) {
	auditor, auditPath, _ := newEd25519Auditor(t)
	proxy := newGate(t, "agents:\n  mira:\n    mode: allow\n    deny:\n      - secret_tool\n", nil, auditor)

	// Simulate two audits:
	// seq 0: forwarded tool call (not yet resolved, e.g., waiting for upstream response)
	// seq 1: policy-denied call (resolved immediately)

	// Reserve seq 0
	seq0 := uint64(0)
	proxy.appendAudit(seq0, "forwarded_tool", "allow", "forwarded", nil)

	// seq 1: denied at request time
	seq1 := uint64(1)
	proxy.appendAudit(seq1, "secret_tool", "deny", "policy", nil)
	proxy.resolveAudit(seq1) // This marks seq 1 as resolved

	// At this point: seq 0 is not resolved, seq 1 is resolved but blocked by seq 0
	// Now drain (upstream closed)
	proxy.drainAudits()

	if err := auditor.Close(); err != nil {
		t.Fatal(err)
	}

	evs := readAuditEvents(t, auditPath)
	if len(evs) != 2 {
		t.Fatalf("expected 2 audit rows, got %d", len(evs))
	}

	// Verify seq 0 comes before seq 1 in the output
	if evs[0].Tool != "forwarded_tool" || evs[1].Tool != "secret_tool" {
		t.Errorf("audit order wrong: got %s then %s, want forwarded_tool then secret_tool", evs[0].Tool, evs[1].Tool)
	}
}

// TestStdioOutOfOrderResponseStampingIsCorrect verifies that when card state
// is committed before a later audit is flushed, the later audit gets the
// correct card state stamp at flush time.
func TestStdioOutOfOrderResponseStampingIsCorrect(t *testing.T) {
	auditor, auditPath, _ := newEd25519Auditor(t)
	proxy := newGate(t, "agents:\n  mira:\n    mode: allow\n", nil, auditor)

	// Simulate the claim (seq 0) and generic_tool (seq 1) calls.
	// Even if they resolve in different orders, the generic_tool audit
	// should be stamped with the nock_id from the claim.
	seq0 := uint64(0)
	seq1 := uint64(1)

	proxy.appendAudit(seq0, "nockcc_nock_claim", "allow", "forwarded", nil)
	proxy.appendAudit(seq1, "generic_tool", "allow", "forwarded", nil)

	// Simulate claim response arriving and updating card state
	refs := &extract.References{NockID: 12345}
	proxy.updateCardState(seq0, "nockcc_nock_claim", refs)
	proxy.resolveAudit(seq0)

	// Simulate generic_tool response arriving and resolving
	proxy.resolveAudit(seq1)

	if err := auditor.Close(); err != nil {
		t.Fatal(err)
	}

	evs := readAuditEvents(t, auditPath)
	if len(evs) != 2 {
		t.Fatalf("expected 2 audit rows, got %d", len(evs))
	}

	// Sort by tool name for stable ordering
	sort.Slice(evs, func(i, j int) bool { return evs[i].Tool < evs[j].Tool })

	// The generic_tool audit should be stamped with nock_id 12345 (from the claim)
	var genericToolNockID int
	for _, ev := range evs {
		if ev.Tool == "generic_tool" {
			genericToolNockID = ev.NockID
			break
		}
	}

	if genericToolNockID != 12345 {
		t.Errorf("generic_tool audit nock_id = %d, want 12345", genericToolNockID)
	}
}

// TestStdioResolveAuditIsIdempotent verifies that resolving an already-flushed
// sequence a second time is a no-op and does not leak an auditResolved entry.
// Handlers legitimately double-resolve (decide() resolves a denied call and the
// listener resolves the same seq again); without the frontier guard, the second
// resolve reinserts a key below auditNext that flushAuditsLocked never revisits.
func TestStdioResolveAuditIsIdempotent(t *testing.T) {
	auditor, _, _ := newEd25519Auditor(t)
	proxy := newGate(t, "agents:\n  mira:\n    mode: allow\n", nil, auditor)

	// Resolve seq 0 once — it flushes and advances the frontier past 0.
	proxy.appendAudit(0, "forwarded_tool", "allow", "forwarded", nil)
	proxy.resolveAudit(0)

	// Repeat resolves of the already-flushed seq must not grow auditResolved.
	proxy.resolveAudit(0)
	proxy.resolveAudit(0)

	proxy.auditMutex.Lock()
	leaked := len(proxy.auditResolved)
	proxy.auditMutex.Unlock()
	if leaked != 0 {
		t.Errorf("auditResolved leaked %d entries after repeated resolve of a flushed seq, want 0", leaked)
	}

	if err := auditor.Close(); err != nil {
		t.Fatal(err)
	}
}

func TestStdioInjectedCallAuditsInjectThenAllowWithoutDrain(t *testing.T) {
	auditor, auditPath, _ := newEd25519Auditor(t)
	engine, err := policy.LoadBytes([]byte(`
agents:
  mira:
    mode: allow
    inject:
      - tools: ["echo_args"]
        ref: "env:ECHO_TOKEN"
        arg: "headers.Authorization"
`))
	if err != nil {
		t.Fatalf("LoadBytes: %v", err)
	}
	validator, err := engine.ValidatorFor("mira")
	if err != nil {
		t.Fatalf("ValidatorFor: %v", err)
	}
	var logs bytes.Buffer
	proxy := NewStdioProxy(nil, "mira", engine, validator, nil, auditor, nil, log.New(&logs, "", 0))
	proxy.WithResolver(&mockResolver{
		values: map[string]string{
			"env:ECHO_TOKEN": "audit-secret-0001",
		},
	})

	pending := &sync.Map{}
	call := `{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"echo_args","arguments":{}}}`
	var upstream bytes.Buffer
	if err := proxy.agentToUpstream(strings.NewReader(call+"\n"), &upstream, pending); err != nil {
		t.Fatalf("agentToUpstream: %v", err)
	}
	if upstream.Len() == 0 {
		t.Fatal("injected call was not forwarded")
	}

	response := `{"jsonrpc":"2.0","id":1,"result":{"content":[{"type":"text","text":"ok"}]}}`
	var agent bytes.Buffer
	if err := proxy.upstreamToAgent(strings.NewReader(response+"\n"), &agent, pending); err != nil {
		t.Fatalf("upstreamToAgent: %v", err)
	}
	proxy.drainAudits()
	if err := auditor.Close(); err != nil {
		t.Fatal(err)
	}

	if strings.Contains(logs.String(), "AUDIT-DRAIN") {
		t.Fatalf("clean injected call logged AUDIT-DRAIN: %s", logs.String())
	}
	evs := readAuditEvents(t, auditPath)
	if len(evs) != 2 {
		t.Fatalf("expected exactly inject + allow rows, got %d: %+v", len(evs), evs)
	}
	if evs[0].Tool != "echo_args" || evs[0].Decision != "inject" {
		t.Fatalf("first audit row = %+v, want inject for echo_args", evs[0])
	}
	if evs[1].Tool != "echo_args" || evs[1].Decision != "allow" {
		t.Fatalf("second audit row = %+v, want allow for echo_args", evs[1])
	}
}

// TestStdioMismatchedReleaseKeepsCardStamp verifies that a nockcc_nock_release
// whose nock_id does NOT match the current card leaves the card active, so a
// later audit is still stamped with the claimed card rather than a false 0.
func TestStdioMismatchedReleaseKeepsCardStamp(t *testing.T) {
	auditor, auditPath, _ := newEd25519Auditor(t)
	proxy := newGate(t, "agents:\n  mira:\n    mode: allow\n", nil, auditor)

	// seq 0: claim 12345
	proxy.appendAudit(0, "nockcc_nock_claim", "allow", "forwarded", nil)
	proxy.updateCardState(0, "nockcc_nock_claim", &extract.References{NockID: 12345})
	proxy.resolveAudit(0)

	// seq 1: release a DIFFERENT card (99999) — does not match currentCard 12345.
	proxy.appendAudit(1, "nockcc_nock_release", "allow", "forwarded", nil)
	proxy.updateCardState(1, "nockcc_nock_release", &extract.References{NockID: 99999})
	proxy.resolveAudit(1)

	// seq 2: a generic tool after the mismatched release — card is still 12345.
	proxy.appendAudit(2, "generic_tool", "allow", "forwarded", nil)
	proxy.resolveAudit(2)

	if err := auditor.Close(); err != nil {
		t.Fatal(err)
	}

	evs := readAuditEvents(t, auditPath)
	var got int
	found := false
	for _, ev := range evs {
		if ev.Tool == "generic_tool" {
			got = ev.NockID
			found = true
		}
	}
	if !found {
		t.Fatalf("generic_tool row missing; got %d rows", len(evs))
	}
	if got != 12345 {
		t.Errorf("generic_tool nock_id after mismatched release = %d, want 12345 (card still claimed)", got)
	}
}
