package proxy

import (
	"bufio"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"sync/atomic"
	"testing"
	"testing/iotest"
	"time"

	"github.com/nocktechnologies/nockguard/internal/audit"
)

const discoveryResponse = `{"jsonrpc":"2.0","id":9007199254740993,"_meta":{"vendor":"envelope"},"result":{"tools":[{"name":"safe_tool","title":"Safe","inputSchema":{"type":"object"},"outputSchema":{"type":"object"},"annotations":{"readOnlyHint":true},"_meta":{"vendor":9007199254740993}},{"name":"blocked"}],"nextCursor":"page2","_meta":{"vendor":"result"}}}`
const discoveryRequest = `{"jsonrpc":"2.0","id":9007199254740993,"method":"tools/list"}`

func assertDiscovery(t *testing.T, got []byte) {
	t.Helper()
	if !json.Valid(got) {
		t.Fatalf("invalid JSON: %s", got)
	}
	for _, field := range []string{`"nextCursor":"page2"`, `"outputSchema"`, `"annotations"`, `"vendor":9007199254740993`, `"vendor":"envelope"`, `"vendor":"result"`, `"title":"Safe"`} {
		if !strings.Contains(string(got), field) {
			t.Errorf("missing %s in %s", field, got)
		}
	}
	if strings.Contains(string(got), `"blocked"`) {
		t.Errorf("denied tool leaked: %s", got)
	}
}

func TestToolDiscoveryPreservesMetadata(t *testing.T) {
	gate := newGate(t, "agents:\n  mira:\n    allow: [safe_tool]\n", nil, nil)
	assertDiscovery(t, gate.filterToolListResponse([]byte(discoveryResponse), 0))
	gate = newGate(t, "agents:\n  mira:\n    mode: deny\n", nil, nil)
	got := gate.filterToolListResponse([]byte(discoveryResponse), 0)
	if !strings.Contains(string(got), `"tools":[]`) {
		t.Errorf("want empty array: %s", got)
	}
}

func TestHTTPToolDiscoveryJSONAndSSE(t *testing.T) {
	for _, sse := range []bool{false, true} {
		t.Run(fmt.Sprint(sse), func(t *testing.T) {
			release := make(chan struct{})
			defer close(release)
			upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				w.Header().Set("Mcp-Session-Id", "test-session")
				if sse {
					w.Header().Set("Content-Type", "text/event-stream")
					io.WriteString(w, ": heartbeat\r\nid: notification\r\ndata: {\"jsonrpc\":\"2.0\",\"method\":\"notifications/tools/list_changed\"}\r\n\r\n")
					w.(http.Flusher).Flush()
					// Bare CR and multiline data are both legal SSE framing.
					data := strings.Replace(discoveryResponse, `"result":`, "\rdata: \"result\":", 1)
					io.WriteString(w, "id: page-1\revent: message\rdata: "+data+"\r\r")
					w.(http.Flusher).Flush()
					select {
					case <-release:
					case <-r.Context().Done():
					}
				} else {
					w.Header().Set("Content-Type", "application/json")
					w.Header().Set("Content-Length", fmt.Sprint(len(discoveryResponse)))
					io.WriteString(w, discoveryResponse)
				}
			}))
			defer upstream.Close()
			gate := newGate(t, "agents:\n  mira:\n    allow: [safe_tool]\n", nil, nil)
			listener := httptest.NewServer(NewHTTPListener("127.0.0.1:0", upstream.URL, gate, log.New(io.Discard, "", 0)))
			defer listener.Close()
			resp, err := http.Post(listener.URL, "application/json", strings.NewReader(discoveryRequest))
			if err != nil {
				t.Fatal(err)
			}
			defer resp.Body.Close()
			if resp.Header.Get("Mcp-Session-Id") != "test-session" {
				t.Error("session header lost")
			}
			if sse {
				reader := bufio.NewReader(resp.Body)
				first := readSSEEvent(t, reader)
				if !strings.Contains(first, "notifications/tools/list_changed") {
					t.Fatalf("notification lost: %s", first)
				}
				second := readSSEEvent(t, reader)
				assertDiscovery(t, []byte(strings.TrimSpace(strings.TrimPrefix(second, "data:"))))
			} else {
				body, err := io.ReadAll(resp.Body)
				if err != nil {
					t.Fatal(err)
				}
				assertDiscovery(t, body)
			}
		})
	}
}

func TestMalformedToolDiscoveryFailsClosed(t *testing.T) {
	gate := newGate(t, "agents:\n  mira:\n    mode: allow\n", nil, nil)
	for _, result := range []string{`null`, `{}`, `{"tools":null}`, `{"tools":[{"name":7}]}`, `{"tools":[null]}`} {
		got := gate.filterToolListResponse([]byte(`{"jsonrpc":"2.0","id":1,"result":`+result+`}`), 0)
		if !strings.Contains(string(got), `"error"`) {
			t.Errorf("malformed listing not rejected: %s", got)
		}
	}
}

func TestDiscoverySSEPreservesEventFieldsAndOtherMessages(t *testing.T) {
	gate := newGate(t, "agents:\n  mira:\n    allow: [safe_tool]\n", nil, nil)
	l := NewHTTPListener("127.0.0.1:0", "", gate, log.New(io.Discard, "", 0))
	other := `data: {"jsonrpc":"2.0","id":9007199254740992,"result":{"other":true}}`
	for _, ending := range []string{"\n", "\r", "\r\n"} {
		input := strings.Join([]string{"\ufeff: heartbeat", "data:", "", other, "", "id: page-1", "retry: 3000", "event: message", "data: " + discoveryResponse, "", ""}, ending)
		w := httptest.NewRecorder()
		if err := l.streamToolList(w, iotest.OneByteReader(strings.NewReader(input)), []byte(discoveryRequest), 0, func() {}); err != nil {
			t.Fatal(err)
		}
		out := w.Body.String()
		for _, preserved := range []string{": heartbeat", other, "id: page-1", "retry: 3000", "event: message"} {
			if !strings.Contains(out, preserved) {
				t.Errorf("lost SSE field/message %q", preserved)
			}
		}
		if strings.Contains(out, `"blocked"`) || !strings.Contains(out, `"nextCursor":"page2"`) {
			t.Errorf("incorrect discovery filtering: %s", out)
		}
	}
}

func TestHTTPDiscoveryRejectsUninspectableResponses(t *testing.T) {
	gate := newGate(t, "agents:\n  mira:\n    mode: allow\n", nil, nil)
	l := NewHTTPListener("127.0.0.1:0", "", gate, log.New(io.Discard, "", 0))
	for _, tc := range []struct{ name, contentType, body string }{
		{"malformed", "application/json", `{"tools":["blocked"]`},
		{"mismatched-id", "application/json", strings.Replace(discoveryResponse, "9007199254740993", "9007199254740992", 1)},
		{"oversized-json", "application/json", strings.Repeat(" ", httpListenerBodyCap) + discoveryResponse},
		{"malformed-sse", "text/event-stream", "data: not-json-blocked\n\n"},
		{"oversized-sse", "text/event-stream", "data: " + strings.Repeat(" ", httpListenerBodyCap) + discoveryResponse + "\n\n"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			w := httptest.NewRecorder()
			resp := &http.Response{StatusCode: 200, Header: http.Header{"Content-Type": {tc.contentType}}, Body: io.NopCloser(strings.NewReader(tc.body))}
			l.forwardToolList(w, resp, []byte(discoveryRequest), json.RawMessage("9007199254740993"), 0, func() {})
			if strings.Contains(w.Body.String(), "blocked") || !strings.Contains(w.Body.String(), `"error"`) {
				t.Errorf("uninspectable response did not fail closed")
			}
		})
	}
}

// TestHTTPToolDiscoverySSEResolvesAuditBeforeStreamCloses verifies that the
// audit sequence for a tools/list SSE discovery response resolves as soon as
// the matching discovery event has been filtered and flushed, not only once
// the upstream eventually closes the stream. Audits flush strictly in
// sequence order, so an upstream that keeps the SSE connection open after
// delivering the discovery result must never block a later request's audit
// row from being written — that is the ordered-audit-frontier stall this
// test pins down.
func TestHTTPToolDiscoverySSEResolvesAuditBeforeStreamCloses(t *testing.T) {
	release := make(chan struct{})
	requestStarted := make(chan struct{})
	// The only upstream call this test drives is the tools/list discovery
	// request: the later tools/call below is denied at the gate and never
	// reaches upstream, so this handler has a single branch.
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Deliver the matching discovery event, then hold the stream open — a
		// keep-alive upstream pattern that must never block a later request's
		// audit from flushing.
		w.Header().Set("Content-Type", "text/event-stream")
		w.WriteHeader(http.StatusOK)
		io.WriteString(w, "event: message\ndata: "+discoveryResponse+"\n\n")
		w.(http.Flusher).Flush()
		close(requestStarted)
		select {
		case <-release:
		case <-r.Context().Done():
		}
	}))
	defer upstream.Close()

	auditor, auditPath, _ := newEd25519Auditor(t)
	gate := newGate(t, "agents:\n  mira:\n    allow: [safe_tool]\n", nil, auditor)
	lsrv := httptest.NewServer(NewHTTPListener("127.0.0.1:0", upstream.URL, gate, log.New(io.Discard, "", 0)))
	defer lsrv.Close()

	go func() {
		resp, err := http.Post(lsrv.URL, "application/json", strings.NewReader(discoveryRequest))
		if err == nil {
			_, _ = io.Copy(io.Discard, resp.Body)
			resp.Body.Close()
		}
	}()

	select {
	case <-requestStarted:
	case <-time.After(2 * time.Second):
		t.Fatalf("upstream never received the tools/list request")
	}

	// seq0 (tools/list) queued a "hide" audit for the blocked tool in the
	// discovery event. seq1 (this denied tools/call) queues a "deny" audit.
	// flushAuditsLocked only emits in sequence order, so both must flush
	// promptly — without waiting for the still-open SSE stream to close.
	status, _, _ := post(t, lsrv.URL, toolCall("2", "not_allowed_tool"))
	if status != http.StatusOK {
		t.Fatalf("denied tools/call status = %d, want 200 (JSON-RPC error body)", status)
	}

	deadline := time.Now().Add(2 * time.Second)
	var evs []audit.Event
	for time.Now().Before(deadline) {
		data, err := os.ReadFile(auditPath)
		if err == nil {
			evs = nil
			for _, line := range strings.Split(strings.TrimSpace(string(data)), "\n") {
				if line == "" {
					continue
				}
				var ev audit.Event
				if json.Unmarshal([]byte(line), &ev) == nil {
					evs = append(evs, ev)
				}
			}
			if len(evs) >= 2 {
				break
			}
		}
		time.Sleep(20 * time.Millisecond)
	}
	if len(evs) < 2 {
		close(release)
		t.Fatalf("audit queue stalled behind the open discovery SSE stream: got %d row(s) (want >=2: hide + deny) while the stream was still open: %+v", len(evs), evs)
	}
	var foundHide, foundDeny bool
	for _, ev := range evs {
		if ev.Decision == "hide" && ev.Tool == "blocked" {
			foundHide = true
		}
		if ev.Decision == "deny" && ev.Tool == "not_allowed_tool" {
			foundDeny = true
		}
	}
	if !foundHide || !foundDeny {
		close(release)
		t.Fatalf("missing expected audit rows while stream open: hide=%v deny=%v rows=%+v", foundHide, foundDeny, evs)
	}

	// Ending the still-open SSE stream afterwards must not double-resolve the
	// sequence or duplicate any audit row.
	close(release)
	time.Sleep(50 * time.Millisecond)
	if err := auditor.Close(); err != nil {
		t.Fatal(err)
	}
	finalEvs := readAuditEvents(t, auditPath)
	if len(finalEvs) != len(evs) {
		t.Fatalf("stream close changed audit row count: before=%d after=%d (want no duplicate resolution)", len(evs), len(finalEvs))
	}
}

// TestHTTPToolDiscoverySSEDropsRepeatedResult verifies that a second SSE event
// on the same stream matching the forwarded tools/list request id (JSON-RPC
// allows exactly one response per id) is dropped outright: never forwarded to
// the connector, never re-run through filterToolListResponse. Before the drop
// guard, a misbehaving upstream that repeated the discovery result could leak
// its raw denied tool to the connector and would re-queue its hide audit onto
// a sequence the audit queue had already flushed past — silent audit loss.
func TestHTTPToolDiscoverySSEDropsRepeatedResult(t *testing.T) {
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/event-stream")
		w.WriteHeader(http.StatusOK)
		io.WriteString(w, "event: message\ndata: "+discoveryResponse+"\n\n")
		w.(http.Flusher).Flush()
		// A misbehaving upstream repeats the same tools/list result (with the
		// denied "blocked" tool) a second time on the same stream, then closes.
		io.WriteString(w, "event: message\ndata: "+discoveryResponse+"\n\n")
		w.(http.Flusher).Flush()
	}))
	defer upstream.Close()

	auditor, auditPath, _ := newEd25519Auditor(t)
	gate := newGate(t, "agents:\n  mira:\n    allow: [safe_tool]\n", nil, auditor)
	lsrv := httptest.NewServer(NewHTTPListener("127.0.0.1:0", upstream.URL, gate, log.New(io.Discard, "", 0)))
	defer lsrv.Close()

	resp, err := http.Post(lsrv.URL, "application/json", strings.NewReader(discoveryRequest))
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatal(err)
	}

	if resultCount := strings.Count(string(body), `"nextCursor":"page2"`); resultCount != 1 {
		t.Fatalf("connector received %d tools/list result event(s) for the request id, want exactly 1: %s", resultCount, body)
	}
	if strings.Contains(string(body), `"blocked"`) {
		t.Fatalf("denied tool leaked to the connector: %s", body)
	}

	if err := auditor.Close(); err != nil {
		t.Fatal(err)
	}
	evs := readAuditEvents(t, auditPath)
	var hideCount int
	for _, ev := range evs {
		if ev.Decision == "hide" && ev.Tool == "blocked" {
			hideCount++
		}
	}
	if hideCount != 1 {
		t.Fatalf("audit file has %d hide row(s) for the repeated discovery event, want exactly 1 (no leak, no loss): %+v", hideCount, evs)
	}
}

// TestHTTPToolDiscoverySSEBodylessStatusFailsClosed verifies that when an
// upstream answers a tools/list SSE request with a status that cannot carry a
// body (204, 304), the connector gets a usable JSON-RPC error over HTTP 200
// instead of an unusable bodyless 204/304: net/http itself suppresses any body
// written under those statuses, so streaming SSE (or even the invalid()
// fallback event) under the upstream's own status would silently vanish.
// forwardToolList is exercised directly with an explicit Content-Type, the
// same way TestHTTPDiscoveryErrorUsesBodyPermittingStatus does below — a real
// round trip against a Go httptest upstream is not used here because Go's own
// net/http SERVER strips Content-Type from a 304 it writes (RFC 7232 section
// 4.1, net/http/transfer.go suppressedHeaders304), which would test that
// server-side quirk instead of this fix. A non-Go (or non-compliant) upstream
// MCP server can still send a bare 304 with Content-Type: text/event-stream on
// the wire, and Go's HTTP CLIENT does not strip headers it merely reads — so
// this branch is reachable in production against such an upstream, not just
// in this direct unit test.
func TestHTTPToolDiscoverySSEBodylessStatusFailsClosed(t *testing.T) {
	gate := newGate(t, "agents:\n  mira:\n    allow: [safe_tool]\n", nil, nil)
	l := NewHTTPListener("127.0.0.1:0", "", gate, log.New(io.Discard, "", 0))
	for _, upstreamStatus := range []int{http.StatusNoContent, http.StatusNotModified} {
		t.Run(http.StatusText(upstreamStatus), func(t *testing.T) {
			w := httptest.NewRecorder()
			resp := &http.Response{StatusCode: upstreamStatus, Header: http.Header{"Content-Type": {"text/event-stream"}}, Body: io.NopCloser(strings.NewReader(""))}
			l.forwardToolList(w, resp, []byte(discoveryRequest), json.RawMessage("9007199254740993"), 0, func() {})
			if w.Code != http.StatusOK {
				t.Fatalf("upstream %d: connector status = %d, want 200 (JSON-RPC error body)", upstreamStatus, w.Code)
			}
			if !json.Valid(w.Body.Bytes()) || !strings.Contains(w.Body.String(), `"error"`) {
				t.Fatalf("upstream %d: connector body is not a JSON-RPC error: %q", upstreamStatus, w.Body.String())
			}
		})
	}
}

// blockingReadCloser never returns from Read until Close is called, at which
// point Read reports io.EOF. It models what a Go HTTP client hands back for a
// 101 Switching Protocols response: resp.Body IS the upgraded bidirectional
// connection, so reading it (e.g. via io.Copy) blocks until the far end closes
// the connection — which for an upgraded stream may be never.
type blockingReadCloser struct {
	done   chan struct{}
	closed atomic.Bool
}

func newBlockingReadCloser() *blockingReadCloser {
	return &blockingReadCloser{done: make(chan struct{})}
}

func (b *blockingReadCloser) Read(p []byte) (int, error) {
	<-b.done
	return 0, io.EOF
}

func (b *blockingReadCloser) Close() error {
	if b.closed.CompareAndSwap(false, true) {
		close(b.done)
	}
	return nil
}

// TestHTTPToolDiscoverySSESwitchingProtocolsClosesNotDrains verifies that a
// 101 Switching Protocols response under Content-Type: text/event-stream is
// closed, not drained: statusHasNoBody treats 101 as bodyless, but a Go HTTP
// client exposes a 101 response body as the live upgraded connection, so
// draining it with io.Copy would block until the upstream closes it — hanging
// this request and, with it, every later request's audit behind the
// still-unresolved sequence (forward() only resolves after forwardToolList
// returns). closing the body instead must let this return promptly.
func TestHTTPToolDiscoverySSESwitchingProtocolsClosesNotDrains(t *testing.T) {
	body := newBlockingReadCloser()
	gate := newGate(t, "agents:\n  mira:\n    allow: [safe_tool]\n", nil, nil)
	l := NewHTTPListener("127.0.0.1:0", "", gate, log.New(io.Discard, "", 0))
	w := httptest.NewRecorder()
	resp := &http.Response{StatusCode: http.StatusSwitchingProtocols, Header: http.Header{"Content-Type": {"text/event-stream"}}, Body: body}

	done := make(chan struct{})
	go func() {
		l.forwardToolList(w, resp, []byte(discoveryRequest), json.RawMessage("9007199254740993"), 0, func() {})
		close(done)
	}()

	select {
	case <-done:
	case <-time.After(1 * time.Second):
		t.Fatalf("forwardToolList blocked on a 101 Switching Protocols body instead of closing it")
	}

	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200 (JSON-RPC error body)", w.Code)
	}
	if !json.Valid(w.Body.Bytes()) || !strings.Contains(w.Body.String(), `"error"`) {
		t.Fatalf("body is not a JSON-RPC error: %q", w.Body.String())
	}
	if !body.closed.Load() {
		t.Fatalf("upstream 101 body was never closed")
	}
}

// TestHTTPDiscoverySSENoMatchingResponseFailsClosed verifies that an SSE
// stream carrying only a notification and a mismatched-id result — never the
// requested tools/list response — does not close as a silent success: the
// connector must still see a JSON-RPC error for its request id once the
// stream ends, alongside the unrelated messages relayed unchanged.
func TestHTTPDiscoverySSENoMatchingResponseFailsClosed(t *testing.T) {
	gate := newGate(t, "agents:\n  mira:\n    allow: [safe_tool]\n", nil, nil)
	l := NewHTTPListener("127.0.0.1:0", "", gate, log.New(io.Discard, "", 0))
	input := strings.Join([]string{
		`data: {"jsonrpc":"2.0","method":"notifications/tools/list_changed"}`, "",
		`data: {"jsonrpc":"2.0","id":9007199254740992,"result":{"other":true}}`, "",
	}, "\n")
	w := httptest.NewRecorder()
	resp := &http.Response{StatusCode: http.StatusOK, Header: http.Header{"Content-Type": {"text/event-stream"}}, Body: io.NopCloser(strings.NewReader(input))}
	l.forwardToolList(w, resp, []byte(discoveryRequest), json.RawMessage("9007199254740993"), 0, func() {})

	out := w.Body.String()
	if !strings.Contains(out, "notifications/tools/list_changed") {
		t.Fatalf("relayed notification lost: %s", out)
	}
	events := strings.Split(strings.TrimRight(out, "\n"), "\n\n")
	last := events[len(events)-1]
	if !strings.Contains(last, `"error"`) || !strings.Contains(last, "9007199254740993") {
		t.Fatalf("stream with no matching response did not end with a JSON-RPC error for the request id: %s", out)
	}
}

// TestHTTPDiscoverySSEEmptyStreamFailsClosed verifies that an SSE response
// with no events at all (upstream closes immediately) still yields a
// JSON-RPC error to the connector rather than a silently empty 200.
func TestHTTPDiscoverySSEEmptyStreamFailsClosed(t *testing.T) {
	gate := newGate(t, "agents:\n  mira:\n    allow: [safe_tool]\n", nil, nil)
	l := NewHTTPListener("127.0.0.1:0", "", gate, log.New(io.Discard, "", 0))
	w := httptest.NewRecorder()
	resp := &http.Response{StatusCode: http.StatusOK, Header: http.Header{"Content-Type": {"text/event-stream"}}, Body: io.NopCloser(strings.NewReader(""))}
	l.forwardToolList(w, resp, []byte(discoveryRequest), json.RawMessage("9007199254740993"), 0, func() {})

	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", w.Code)
	}
	out := w.Body.String()
	if !strings.Contains(out, `"error"`) || !strings.Contains(out, "9007199254740993") {
		t.Fatalf("empty SSE stream did not fail closed with a JSON-RPC error event: %q", out)
	}
}

func TestHTTPDiscoveryErrorUsesBodyPermittingStatus(t *testing.T) {
	gate := newGate(t, "agents:\n  mira:\n    allow: [safe_tool]\n", nil, nil)
	l := NewHTTPListener("127.0.0.1:0", "", gate, log.New(io.Discard, "", 0))
	for _, upstreamStatus := range []int{http.StatusNoContent, http.StatusNotModified} {
		t.Run(http.StatusText(upstreamStatus), func(t *testing.T) {
			w := httptest.NewRecorder()
			resp := &http.Response{StatusCode: upstreamStatus, Header: make(http.Header), Body: http.NoBody}
			l.forwardToolList(w, resp, []byte(discoveryRequest), json.RawMessage("9007199254740993"), 0, func() {})
			if w.Code != http.StatusOK || !strings.Contains(w.Body.String(), `"error"`) {
				t.Fatalf("want body-bearing JSON-RPC error, got status %d body %q", w.Code, w.Body.String())
			}
		})
	}
	t.Run("valid response preserves status", func(t *testing.T) {
		w := httptest.NewRecorder()
		resp := &http.Response{StatusCode: http.StatusCreated, Header: http.Header{"Content-Type": {"application/json"}}, Body: io.NopCloser(strings.NewReader(discoveryResponse))}
		l.forwardToolList(w, resp, []byte(discoveryRequest), json.RawMessage("9007199254740993"), 0, func() {})
		if w.Code != http.StatusCreated {
			t.Fatalf("want upstream status %d, got %d", http.StatusCreated, w.Code)
		}
		assertDiscovery(t, w.Body.Bytes())
	})
}
