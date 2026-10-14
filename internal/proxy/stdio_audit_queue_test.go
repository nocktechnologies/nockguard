package proxy

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"
	"log"
	"sort"
	"strings"
	"sync"
	"testing"

	"github.com/nocktechnologies/nockguard/internal/approval"
	"github.com/nocktechnologies/nockguard/internal/extract"
	"github.com/nocktechnologies/nockguard/internal/policy"
)

type auditWriteCheck func([]byte) (int, error)

func (f auditWriteCheck) Write(p []byte) (int, error) { return f(p) }

func TestStdioOutOfOrderResponseAuditLimit(t *testing.T) {
	auditor, path, _ := newEd25519Auditor(t)
	defer auditor.Close()
	gate := newGate(t, "agents:\n  mira:\n    mode: allow\n", nil, auditor)
	pending := &sync.Map{}
	forwards := 0
	forward := auditWriteCheck(func(p []byte) (int, error) {
		forwards++
		rows := readAuditEvents(t, path)
		if len(rows) != forwards || rows[forwards-1].Decision != "dispatch" {
			t.Fatalf("forward %d preceded its durable dispatch: %+v", forwards, rows)
		}
		return len(p), nil
	})
	input := toolCall("1", "first_tool") + "\n" + toolCall("2", "second_tool") + "\n"
	if err := gate.agentToUpstream(strings.NewReader(input), forward, pending); err != nil {
		t.Fatal(err)
	}
	if forwards != 2 {
		t.Fatalf("forwards=%d, want 2", forwards)
	}
	rows := readAuditEvents(t, path)
	if len(rows) != 2 || rows[0].Tool != "first_tool" || rows[1].Tool != "second_tool" {
		t.Fatalf("both dispatch rows should precede upstream responses: %+v", rows)
	}
	var agent bytes.Buffer
	second := `{"jsonrpc":"2.0","id":2,"result":{}}` + "\n"
	if err := gate.upstreamToAgent(strings.NewReader(second), &agent, pending, nil); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(agent.String(), `"id":2`) || !strings.Contains(agent.String(), `"result"`) {
		t.Fatalf("out-of-order response was held: %s", agent.String())
	}
	if rows = readAuditEvents(t, path); len(rows) != 2 {
		t.Fatalf("deferred decision overtook pending first call: %+v", rows)
	}
	first := `{"jsonrpc":"2.0","id":1,"result":{}}` + "\n"
	if err := gate.upstreamToAgent(strings.NewReader(first), io.Discard, pending, nil); err != nil {
		t.Fatal(err)
	}
	rows = readAuditEvents(t, path)
	if len(rows) != 4 || rows[2].Tool != "first_tool" || rows[2].Decision != "allow" || rows[3].Tool != "second_tool" || rows[3].Decision != "allow" {
		t.Fatalf("deferred decisions not written in request order: %+v", rows)
	}
}

func TestStdioPendingRequestRegisteredBeforeWrite(t *testing.T) {
	for _, tc := range []struct {
		name               string
		respondDuringWrite bool
	}{
		{name: "response before write returns", respondDuringWrite: true},
		{name: "response after write returns", respondDuringWrite: false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			gate := newGate(t, "agents:\n  mira:\n    mode: allow\n", nil, nil)
			pending := &sync.Map{}
			var agent bytes.Buffer
			response := `{"jsonrpc":"2.0","id":1,"result":{"content":[]}}` + "\n"
			forward := auditWriteCheck(func(p []byte) (int, error) {
				if !strings.Contains(string(p), "nockcc_nock_claim") {
					t.Errorf("upstream write = %s, want claim request", p)
				}
				if tc.respondDuringWrite {
					if _, ok := pending.Load("1"); !ok {
						t.Error("pending request was not registered before upstream Write")
					}
					if err := gate.upstreamToAgent(strings.NewReader(response), &agent, pending, nil); err != nil {
						return 0, err
					}
				}
				return len(p), nil
			})

			call := `{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"nockcc_nock_claim","arguments":{"id":11711}}}` + "\n"
			if err := gate.agentToUpstream(strings.NewReader(call), forward, pending); err != nil {
				t.Fatalf("agentToUpstream: %v", err)
			}
			if !tc.respondDuringWrite {
				if err := gate.upstreamToAgent(strings.NewReader(response), &agent, pending, nil); err != nil {
					t.Fatalf("upstreamToAgent: %v", err)
				}
			}

			gate.cardMu.Lock()
			currentCard := gate.currentCard
			gate.cardMu.Unlock()
			if currentCard != 11711 {
				t.Errorf("currentCard = %d, want 11711", currentCard)
			}
			if !strings.Contains(agent.String(), `"id":1`) {
				t.Errorf("response was not forwarded to agent: %s", agent.String())
			}
			if _, ok := pending.Load("1"); ok {
				t.Error("pending request remains after its response")
			}

			assertStdioAuditQueueResolved(t, gate)
		})
	}
}

func TestStdioUpstreamWriteFailureRemovesPendingAndResolvesAudit(t *testing.T) {
	gate := newGate(t, "agents:\n  mira:\n    mode: allow\n", nil, nil)
	pending := &sync.Map{}
	writeErr := errors.New("upstream write failed")
	forward := auditWriteCheck(func([]byte) (int, error) { return 0, writeErr })
	call := `{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"nockcc_nock_claim","arguments":{"id":11711}}}` + "\n"
	if err := gate.agentToUpstream(strings.NewReader(call), forward, pending); !errors.Is(err, writeErr) {
		t.Fatalf("agentToUpstream error = %v, want %v", err, writeErr)
	}
	if _, ok := pending.Load("1"); ok {
		t.Fatal("pending request remains after upstream write failure")
	}
	assertStdioAuditQueueResolved(t, gate)
}

func assertStdioAuditQueueResolved(t *testing.T, gate *StdioProxy) {
	t.Helper()
	gate.auditMutex.Lock()
	defer gate.auditMutex.Unlock()
	if gate.auditNext != 1 || len(gate.auditTodo) != 0 || len(gate.auditResolved) != 0 {
		t.Errorf("audit queue = next %d, todo %d, resolved %d; want next 1 with empty queues",
			gate.auditNext, len(gate.auditTodo), len(gate.auditResolved))
	}
}

func TestStdioWriteFailureLeavesResolutionToResponseOwner(t *testing.T) {
	for _, method := range []string{"tools/call", "tools/list"} {
		t.Run(method, func(t *testing.T) {
			gate := newGate(t, "agents:\n  mira:\n    mode: allow\n", nil, nil)
			pending := &sync.Map{}
			writeErr := errors.New("upstream write failed")
			forward := auditWriteCheck(func([]byte) (int, error) {
				// Pause the response path after it claims the entry, before it
				// commits response-backed state and resolves the sequence.
				if _, ok := pending.LoadAndDelete("1"); !ok {
					t.Fatal("response path could not claim pending request")
				}
				return 0, writeErr
			})
			call := `{"jsonrpc":"2.0","id":1,"method":"` + method + `","params":{"name":"nockcc_nock_claim","arguments":{"id":11711}}}` + "\n"
			if err := gate.agentToUpstream(strings.NewReader(call), forward, pending); !errors.Is(err, writeErr) {
				t.Fatalf("agentToUpstream error = %v, want %v", err, writeErr)
			}
			gate.auditMutex.Lock()
			next := gate.auditNext
			gate.auditMutex.Unlock()
			if next != 0 {
				t.Fatalf("write failure resolved response-owned sequence: auditNext = %d", next)
			}
			gate.resolveAudit(0)
			assertStdioAuditQueueResolved(t, gate)
		})
	}
}

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

func TestHandleFailModeAskKeepsCallerDenyAudit(t *testing.T) {
	auditor, auditPath, _ := newEd25519Auditor(t)
	proxy := newGate(t, "agents:\n  mira:\n    fail_mode: ask\n", nil, auditor)
	proxy.WithApprover(approval.NewStaticApprover(true, "approved by test"))

	const seq = uint64(0)
	if !proxy.handleFailModeAsk("echo_args", json.RawMessage(`{"name":"echo_args"}`), "canonical-marshal-failed", seq) {
		t.Fatal("fail-mode Ask was not approved")
	}
	proxy.appendAudit(seq, "echo_args", "deny", "canonical-marshal-failed", nil)
	proxy.resolveAudit(seq)

	if err := auditor.Close(); err != nil {
		t.Fatal(err)
	}

	events := readAuditEvents(t, auditPath)
	decisions := make([]string, 0, len(events))
	for _, event := range events {
		decisions = append(decisions, event.Decision)
	}
	if strings.Join(decisions, ",") != "approval-granted,state-write,deny" {
		t.Fatalf("audit decisions = %v, want approval-granted, state-write, deny; rows=%+v", decisions, events)
	}
	if events[0].Tool != "echo_args" || events[0].Reason != "approved by test" || events[2].Tool != "echo_args" || events[2].Reason != "canonical-marshal-failed" {
		t.Fatalf("audit rows = %+v, want the approval and caller denial for echo_args", events)
	}
	if len(proxy.auditTodo) != 0 {
		t.Fatalf("auditTodo has %d entries after resolving caller denial, want empty", len(proxy.auditTodo))
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
	proxy.WithBestEffortAudit() // this case isolates deferred queue ordering
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
	if err := proxy.upstreamToAgent(strings.NewReader(response+"\n"), &agent, pending, nil); err != nil {
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
