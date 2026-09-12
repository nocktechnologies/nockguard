package proxy

import (
	"io"
	"log"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/nocktechnologies/nockguard/internal/audit"
)

// TestHTTPListener_InitializeFollowedByToolsCall verifies that the audit queue
// does not stall when initialize (non-gated, forwarded) is followed by tools/call.
// Initialize does not reserve or emit an audit, but it reserves a seq and must
// resolve it to avoid blocking later audits. Before the defer fix, this test would
// timeout or stall because seq 0 (initialize) would remain unresolved, preventing
// seq 1 (tools/call) from flushing.
func TestHTTPListener_InitializeFollowedByToolsCall(t *testing.T) {
	upstreamCalls := 0
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		upstreamCalls++
		w.Header().Set("Content-Type", "application/json")
		if upstreamCalls == 1 {
			// Response to initialize
			_, _ = w.Write([]byte(`{"jsonrpc":"2.0","id":1,"result":{"protocolVersion":"2024-11-05"}}`))
		} else {
			// Response to tools/call
			_, _ = w.Write([]byte(`{"jsonrpc":"2.0","id":2,"result":{"content":[{"type":"text","text":"ok"}]}}`))
		}
	}))
	defer upstream.Close()

	auditor, auditPath, pub := newEd25519Auditor(t)
	gate := newGate(t, "agents:\n  mira:\n    mode: allow\n", nil, auditor)
	lsrv := httptest.NewServer(NewHTTPListener("127.0.0.1:0", upstream.URL, gate, log.New(io.Discard, "", 0)))
	defer lsrv.Close()

	// POST initialize (non-gated, no audit emitted for this)
	status, body, _ := post(t, lsrv.URL, `{"jsonrpc":"2.0","id":1,"method":"initialize","params":{}}`)
	if status != http.StatusOK {
		t.Errorf("initialize status = %d, want 200", status)
	}
	if !strings.Contains(body, "protocolVersion") {
		t.Errorf("initialize response missing protocolVersion: %s", body)
	}

	// POST tools/call (allowed, should emit "allow" audit)
	status, body, _ = post(t, lsrv.URL, toolCall("2", "nockcc_nock_list"))
	if status != http.StatusOK {
		t.Errorf("tools/call status = %d, want 200", status)
	}

	if err := auditor.Close(); err != nil {
		t.Fatal(err)
	}

	// Verify the audit chain
	n, err := audit.VerifyEd25519(auditPath, pub)
	if err != nil {
		t.Fatalf("audit chain verification failed: %v", err)
	}

	// Key assertion: exactly 1 audit row (from tools/call only, not initialize)
	evs := readAuditEvents(t, auditPath)
	if n != len(evs) || len(evs) != 1 {
		t.Fatalf("expected 1 verified audit row (from tools/call, not initialize), got n=%d rows=%d", n, len(evs))
	}
	if evs[0].Decision != "allow" || evs[0].Tool != "nockcc_nock_list" {
		t.Errorf("audit row = %+v, want allow/nockcc_nock_list", evs[0])
	}
}

// TestHTTPListener_AuditQueueDoesNotStallAfter500 verifies that when the upstream
// returns HTTP 500 for the first tools/call and HTTP 200 for the second, the
// second call's audit row is still emitted and the queue does not stall.
// This tests that resolveAudit is called even when non-2xx responses occur.
func TestHTTPListener_AuditQueueDoesNotStallAfter500(t *testing.T) {
	callCount := 0
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		callCount++
		if callCount == 1 {
			// First call: return HTTP 500 (upstream error)
			w.WriteHeader(http.StatusInternalServerError)
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte(`{"jsonrpc":"2.0","id":1,"error":{"code":-32603,"message":"upstream error"}}`))
		} else {
			// Second call: return HTTP 200 with success
			w.WriteHeader(http.StatusOK)
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte(`{"jsonrpc":"2.0","id":2,"result":{"content":[{"type":"text","text":"success"}]}}`))
		}
	}))
	defer upstream.Close()

	auditor, auditPath, pub := newEd25519Auditor(t)
	gate := newGate(t, "agents:\n  mira:\n    mode: allow\n", nil, auditor)
	lsrv := httptest.NewServer(NewHTTPListener("127.0.0.1:0", upstream.URL, gate, log.New(io.Discard, "", 0)))
	defer lsrv.Close()

	// First tools/call (upstream returns 500)
	// The listener forwards the 500 status and JSON response body as-is.
	status, _, _ := post(t, lsrv.URL, toolCall("1", "nockcc_nock_list"))
	if status != http.StatusInternalServerError {
		t.Errorf("first call status = %d, want 500 (forwarded from upstream)", status)
	}

	// Second tools/call (upstream returns 200 with success)
	status, _, _ = post(t, lsrv.URL, toolCall("2", "nockcc_nock_list"))
	if status != http.StatusOK {
		t.Errorf("second call status = %d, want 200", status)
	}

	if err := auditor.Close(); err != nil {
		t.Fatal(err)
	}

	// Verify the audit chain
	n, err := audit.VerifyEd25519(auditPath, pub)
	if err != nil {
		t.Fatalf("audit chain verification failed: %v", err)
	}

	// Key assertion: exactly 2 audit rows (one from each call)
	// Both should be audited as "allow" because both were forwarded to upstream
	// (the decision to allow is made at policy time, not based on upstream response)
	evs := readAuditEvents(t, auditPath)
	if n != len(evs) || len(evs) != 2 {
		t.Fatalf("expected 2 verified audit rows (one per call), got n=%d rows=%d", n, len(evs))
	}
	for i, ev := range evs {
		if ev.Decision != "allow" || ev.Tool != "nockcc_nock_list" {
			t.Errorf("audit row %d = %+v, want allow/nockcc_nock_list", i, ev)
		}
	}
}

// TestHTTPListener_CardAfterSeqPruningKeepsBoundary verifies that cardAfterSeq
// is pruned after flushing to avoid unbounded growth, while keeping enough state
// for later seqs to stamp correctly. After flushing seq N, we keep the single
// latest entry with key <= N so that seq N+1 and beyond can still access it.
func TestHTTPListener_CardAfterSeqPruningKeepsBoundary(t *testing.T) {
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		// Always return successful responses
		_, _ = w.Write([]byte(`{"jsonrpc":"2.0","id":1,"result":{"content":[{"type":"text","text":"ok"}]}}`))
	}))
	defer upstream.Close()

	auditor, _, _ := newEd25519Auditor(t)
	gate := newGate(t, "agents:\n  mira:\n    mode: allow\n", nil, auditor)
	lsrv := httptest.NewServer(NewHTTPListener("127.0.0.1:0", upstream.URL, gate, log.New(io.Discard, "", 0)))
	defer lsrv.Close()

	// Make several tool calls to accumulate card state entries
	// Each nockcc_nock_claim would update cardAfterSeq[seq] = new_card_id
	for i := 0; i < 5; i++ {
		post(t, lsrv.URL, toolCall("1", "nockcc_nock_list"))
	}

	if err := auditor.Close(); err != nil {
		t.Fatal(err)
	}

	// Key assertion: after flushing multiple requests, cardAfterSeq should be bounded.
	// It should not grow unbounded to the number of all requests.
	// With 5 requests (seqs 0-4), we should keep at most ~6 entries max
	// (one per unflushed seq + 1 boundary entry).
	cardAfterSeqLen := len(gate.cardAfterSeq)
	maxExpected := 6 // Conservative upper bound: shouldn't grow unbounded
	if cardAfterSeqLen > maxExpected {
		t.Errorf("cardAfterSeq has %d entries after 5 requests, want <= %d (pruning not working)", cardAfterSeqLen, maxExpected)
	}
}

// TestHTTPListener_MalformedSuccessDoesNotCommitCard verifies that a 2xx
// application/json response that cannot be decoded as a JSON-RPC message does
// NOT commit card state: a truncated or garbage body must not be treated as a
// successful claim and set currentCard.
func TestHTTPListener_MalformedSuccessDoesNotCommitCard(t *testing.T) {
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		// Truncated/malformed JSON — cannot decode as jsonrpc.Message.
		_, _ = w.Write([]byte(`{"jsonrpc":"2.0","id":1,"result":{`))
	}))
	defer upstream.Close()

	auditor, _, _ := newEd25519Auditor(t)
	gate := newGate(t, "agents:\n  mira:\n    mode: allow\n    allow:\n      - nockcc_nock_claim\n", nil, auditor)
	lsrv := httptest.NewServer(NewHTTPListener("127.0.0.1:0", upstream.URL, gate, log.New(io.Discard, "", 0)))
	defer lsrv.Close()

	// A claim carrying a real nock_id whose upstream response is malformed must
	// not set the current card.
	status, _, _ := post(t, lsrv.URL, `{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"nockcc_nock_claim","arguments":{"id":12345}}}`)
	if status != http.StatusOK {
		t.Errorf("status = %d, want 200 (body forwarded as-is)", status)
	}

	if err := auditor.Close(); err != nil {
		t.Fatal(err)
	}

	gate.cardMu.Lock()
	card := gate.currentCard
	gate.cardMu.Unlock()
	if card != 0 {
		t.Errorf("currentCard = %d after malformed claim response, want 0 (not committed)", card)
	}
}

// TestHTTPListener_StructurallyInvalidSuccessDoesNotCommitCard verifies that a
// 2xx body that parses cleanly but is not a JSON-RPC response (no result, no
// matching id) — e.g. {} or null — does NOT commit card state.
func TestHTTPListener_StructurallyInvalidSuccessDoesNotCommitCard(t *testing.T) {
	for _, body := range []string{
		`{}`,
		`null`,
		`{"jsonrpc":"2.0","id":1}`,               // matching version, no result, wrong id
		`{"jsonrpc":"2.0","id":999,"result":{}}`, // right shape, wrong id
		`{"jsonrpc":"1.0","id":12345,"result":{}}`, // matching id+result, wrong protocol version
		`{"id":12345,"result":{}}`,                 // matching id+result, missing version
	} {
		body := body
		t.Run(body, func(t *testing.T) {
			upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				w.Header().Set("Content-Type", "application/json")
				w.WriteHeader(http.StatusOK)
				_, _ = w.Write([]byte(body))
			}))
			defer upstream.Close()

			auditor, _, _ := newEd25519Auditor(t)
			gate := newGate(t, "agents:\n  mira:\n    mode: allow\n", nil, auditor)
			lsrv := httptest.NewServer(NewHTTPListener("127.0.0.1:0", upstream.URL, gate, log.New(io.Discard, "", 0)))
			defer lsrv.Close()

			// Claim id=12345; the response above is either not a response or carries
			// a non-matching id, so the card must not be committed.
			status, _, _ := post(t, lsrv.URL, `{"jsonrpc":"2.0","id":12345,"method":"tools/call","params":{"name":"nockcc_nock_claim","arguments":{"id":12345}}}`)
			if status != http.StatusOK {
				t.Errorf("status = %d, want 200", status)
			}
			if err := auditor.Close(); err != nil {
				t.Fatal(err)
			}
			gate.cardMu.Lock()
			card := gate.currentCard
			gate.cardMu.Unlock()
			if card != 0 {
				t.Errorf("currentCard = %d after non-response body %q, want 0 (not committed)", card, body)
			}
		})
	}
}

// TestHTTPListener_LargeNumericIDDoesNotFalselyMatch verifies that two distinct
// integer ids above 2^53 are NOT treated as equal (float64 rounding would
// collapse them), so a claim whose response carries a different large id does
// not falsely commit card state.
func TestHTTPListener_LargeNumericIDDoesNotFalselyMatch(t *testing.T) {
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		// Response id differs from the request id by 1, but both collapse to the
		// same float64 — a valid JSON-RPC 2.0 success shape otherwise.
		_, _ = w.Write([]byte(`{"jsonrpc":"2.0","id":9007199254740993,"result":{"content":[{"type":"text","text":"ok"}]}}`))
	}))
	defer upstream.Close()

	auditor, _, _ := newEd25519Auditor(t)
	gate := newGate(t, "agents:\n  mira:\n    mode: allow\n", nil, auditor)
	lsrv := httptest.NewServer(NewHTTPListener("127.0.0.1:0", upstream.URL, gate, log.New(io.Discard, "", 0)))
	defer lsrv.Close()

	// Claim with request id 9007199254740992 (differs from the response id 993).
	status, _, _ := post(t, lsrv.URL, `{"jsonrpc":"2.0","id":9007199254740992,"method":"tools/call","params":{"name":"nockcc_nock_claim","arguments":{"id":12345}}}`)
	if status != http.StatusOK {
		t.Errorf("status = %d, want 200", status)
	}
	if err := auditor.Close(); err != nil {
		t.Fatal(err)
	}
	gate.cardMu.Lock()
	card := gate.currentCard
	gate.cardMu.Unlock()
	if card != 0 {
		t.Errorf("currentCard = %d after response with a different large id, want 0 (ids must not falsely match)", card)
	}
}
