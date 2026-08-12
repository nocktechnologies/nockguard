package proxy

import (
	"bufio"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/json"
	"io"
	"log"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/nocktechnologies/nockguard/internal/audit"
	"github.com/nocktechnologies/nockguard/internal/policy"
	"github.com/nocktechnologies/nockguard/internal/ratelimit"
)

// httpTestAgent is the agent identity every listener test gates as.
const httpTestAgent = "mira"

// newGate builds a StdioProxy carrying only the enforcement pipeline (no stdio
// upstream — the HTTP listener never calls Run/agentToUpstream, only decide()).
func newGate(t *testing.T, policyYAML string, limiter *ratelimit.Limiter, auditor *audit.Auditor) *StdioProxy {
	t.Helper()
	engine, err := policy.LoadBytes([]byte(policyYAML))
	if err != nil {
		t.Fatalf("LoadBytes: %v", err)
	}
	validator, err := engine.ValidatorFor(httpTestAgent)
	if err != nil {
		t.Fatalf("ValidatorFor: %v", err)
	}
	return NewStdioProxy(nil, httpTestAgent, engine, validator, limiter, auditor, nil, log.New(io.Discard, "", 0))
}

// newEd25519Auditor returns an Ed25519-signing Auditor writing to a temp
// mira.audit.jsonl, plus the path and public key for chain verification.
func newEd25519Auditor(t *testing.T) (*audit.Auditor, string, ed25519.PublicKey) {
	t.Helper()
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(t.TempDir(), "mira.audit.jsonl")
	auditor, err := audit.New(path, audit.WithEd25519Key(priv))
	if err != nil {
		t.Fatal(err)
	}
	return auditor, path, pub
}

// readAuditEvents parses every JSON-Lines audit row at path.
func readAuditEvents(t *testing.T, path string) []audit.Event {
	t.Helper()
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read audit file: %v", err)
	}
	var out []audit.Event
	for _, line := range strings.Split(strings.TrimSpace(string(data)), "\n") {
		if line == "" {
			continue
		}
		var ev audit.Event
		if err := json.Unmarshal([]byte(line), &ev); err != nil {
			t.Fatalf("unmarshal audit row %q: %v", line, err)
		}
		out = append(out, ev)
	}
	return out
}

func toolCall(id, name string) string {
	return `{"jsonrpc":"2.0","id":` + id + `,"method":"tools/call","params":{"name":"` + name + `"}}`
}

// post drives one JSON-RPC body through a listener wrapped in an httptest server
// and returns the status, response body, and content-type.
func post(t *testing.T, srvURL, body string) (int, string, string) {
	t.Helper()
	resp, err := http.Post(srvURL, "application/json", strings.NewReader(body))
	if err != nil {
		t.Fatalf("POST: %v", err)
	}
	defer resp.Body.Close()
	b, _ := io.ReadAll(resp.Body)
	return resp.StatusCode, string(b), resp.Header.Get("Content-Type")
}

// TestHTTPListener_AllowForwardsAndAudits: an allowed tools/call reaches the
// upstream, its response is streamed back, and a signed "allow" row is written.
func TestHTTPListener_AllowForwardsAndAudits(t *testing.T) {
	var called bool
	var gotBody []byte
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		called = true
		gotBody, _ = io.ReadAll(r.Body)
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"jsonrpc":"2.0","id":1,"result":{"content":[{"type":"text","text":"ok"}]}}`))
	}))
	defer upstream.Close()

	auditor, auditPath, pub := newEd25519Auditor(t)
	gate := newGate(t, "agents:\n  mira:\n    mode: allow\n", nil, auditor)
	lsrv := httptest.NewServer(NewHTTPListener("127.0.0.1:0", upstream.URL, gate, log.New(io.Discard, "", 0)))
	defer lsrv.Close()

	status, respBody, _ := post(t, lsrv.URL, toolCall("1", "nockcc_nock_list"))
	if err := auditor.Close(); err != nil {
		t.Fatal(err)
	}

	if !called {
		t.Fatal("upstream was not contacted for an allowed call")
	}
	if !strings.Contains(string(gotBody), "tools/call") {
		t.Errorf("upstream body missing tools/call: %s", gotBody)
	}
	if status != http.StatusOK {
		t.Errorf("status = %d, want 200", status)
	}
	if !strings.Contains(respBody, "content") {
		t.Errorf("upstream response not streamed back: %s", respBody)
	}
	n, err := audit.VerifyEd25519(auditPath, pub)
	if err != nil {
		t.Fatalf("audit chain verification failed: %v", err)
	}
	evs := readAuditEvents(t, auditPath)
	if n != len(evs) || len(evs) != 1 {
		t.Fatalf("expected 1 verified audit row, got n=%d rows=%d", n, len(evs))
	}
	if evs[0].Decision != "allow" || evs[0].Tool != "nockcc_nock_list" || evs[0].Agent != "mira" {
		t.Errorf("audit row = %+v, want allow/nockcc_nock_list/mira", evs[0])
	}
}

// TestHTTPListener_DenyReturnsErrorNoUpstream: a policy-denied tools/call returns
// a JSON-RPC error as a 200 body and NEVER contacts upstream.
func TestHTTPListener_DenyReturnsErrorNoUpstream(t *testing.T) {
	var called bool
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		called = true
	}))
	defer upstream.Close()

	auditor, auditPath, _ := newEd25519Auditor(t)
	gate := newGate(t, "agents:\n  mira:\n    mode: allow\n    deny:\n      - nockcc_kill_switch_set\n", nil, auditor)
	lsrv := httptest.NewServer(NewHTTPListener("127.0.0.1:0", upstream.URL, gate, log.New(io.Discard, "", 0)))
	defer lsrv.Close()

	status, respBody, ctype := post(t, lsrv.URL, toolCall("2", "nockcc_kill_switch_set"))
	_ = auditor.Close()

	if called {
		t.Fatal("upstream MUST NOT be contacted for a denied call")
	}
	if status != http.StatusOK {
		t.Errorf("deny status = %d, want 200 (so the agent sees the policy reason)", status)
	}
	if !strings.HasPrefix(ctype, "application/json") {
		t.Errorf("deny content-type = %q, want application/json", ctype)
	}
	var msg struct {
		Error *struct {
			Code    int    `json:"code"`
			Message string `json:"message"`
		} `json:"error"`
	}
	if err := json.Unmarshal([]byte(respBody), &msg); err != nil {
		t.Fatalf("deny body is not JSON-RPC: %v (%s)", err, respBody)
	}
	if msg.Error == nil || !strings.Contains(msg.Error.Message, "denied") {
		t.Errorf("deny body missing denied error: %s", respBody)
	}
	if evs := readAuditEvents(t, auditPath); len(evs) != 1 || evs[0].Decision != "deny" {
		t.Errorf("expected 1 deny audit row, got %+v", evs)
	}
}

// TestHTTPListener_RateLimitReturnsError: with a session spend cap of 1, the
// first call forwards and the second is rate-limited with no upstream contact.
func TestHTTPListener_RateLimitReturnsError(t *testing.T) {
	var upstreamCalls int
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		upstreamCalls++
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"jsonrpc":"2.0","id":1,"result":{}}`))
	}))
	defer upstream.Close()

	limiter := ratelimit.New(ratelimit.Config{SpendCap: 1})
	gate := newGate(t, "agents:\n  mira:\n    mode: allow\n", limiter, nil)
	lsrv := httptest.NewServer(NewHTTPListener("127.0.0.1:0", upstream.URL, gate, log.New(io.Discard, "", 0)))
	defer lsrv.Close()

	if status, _, _ := post(t, lsrv.URL, toolCall("1", "nockcc_nock_list")); status != http.StatusOK {
		t.Fatalf("first call status = %d, want 200", status)
	}
	status, respBody, _ := post(t, lsrv.URL, toolCall("2", "nockcc_nock_list"))
	if status != http.StatusOK {
		t.Errorf("rate-limited status = %d, want 200", status)
	}
	if !strings.Contains(respBody, "exceeded") {
		t.Errorf("second call should be rate-limited: %s", respBody)
	}
	if upstreamCalls != 1 {
		t.Errorf("upstream contacted %d times, want exactly 1 (rate-limited call must not reach upstream)", upstreamCalls)
	}
}

// TestHTTPListener_SSEPassthroughStreamedUnchanged: an SSE upstream response is
// relayed frame-for-frame AND incrementally — the first event reaches the
// connector while the upstream is provably still blocked before writing the
// second, proving the listener does not buffer the whole stream.
func TestHTTPListener_SSEPassthroughStreamedUnchanged(t *testing.T) {
	release := make(chan struct{})
	const ev1 = `data: {"jsonrpc":"2.0","id":1,"result":{"chunk":1}}`
	const ev2 = `data: {"jsonrpc":"2.0","id":1,"result":{"chunk":2}}`
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/event-stream")
		w.WriteHeader(http.StatusOK)
		fl, ok := w.(http.Flusher)
		if !ok {
			t.Error("upstream ResponseWriter is not a Flusher")
			return
		}
		_, _ = io.WriteString(w, ev1+"\n\n")
		fl.Flush()
		<-release // block until the test has read event 1
		_, _ = io.WriteString(w, ev2+"\n\n")
		fl.Flush()
	}))
	defer upstream.Close()

	gate := newGate(t, "agents:\n  mira:\n    mode: allow\n", nil, nil)
	lsrv := httptest.NewServer(NewHTTPListener("127.0.0.1:0", upstream.URL, gate, log.New(io.Discard, "", 0)))
	defer lsrv.Close()

	resp, err := http.Post(lsrv.URL, "application/json", strings.NewReader(toolCall("1", "nockcc_nock_list")))
	if err != nil {
		t.Fatalf("POST: %v", err)
	}
	defer resp.Body.Close()
	if ct := resp.Header.Get("Content-Type"); !strings.HasPrefix(ct, "text/event-stream") {
		t.Fatalf("content-type = %q, want text/event-stream (SSE passed through unchanged)", ct)
	}

	br := bufio.NewReader(resp.Body)
	first := readSSEEvent(t, br) // must arrive before release is closed
	if !strings.Contains(first, `"chunk":1`) || !strings.HasPrefix(first, "data: ") {
		t.Fatalf("first SSE event wrong/unframed: %q", first)
	}
	// Getting here proves incremental streaming: the upstream is blocked on
	// <-release and has NOT written event 2 yet, yet event 1 already reached us.
	close(release)
	second := readSSEEvent(t, br)
	if !strings.Contains(second, `"chunk":2`) || !strings.HasPrefix(second, "data: ") {
		t.Fatalf("second SSE event wrong/unframed: %q", second)
	}
}

// readSSEEvent reads lines until a non-empty "data:" line, guarded by a timeout
// so a buffering regression fails loudly instead of hanging the suite.
func readSSEEvent(t *testing.T, br *bufio.Reader) string {
	t.Helper()
	type res struct {
		line string
		err  error
	}
	ch := make(chan res, 1)
	go func() {
		for {
			line, err := br.ReadString('\n')
			trimmed := strings.TrimRight(line, "\r\n")
			if strings.HasPrefix(trimmed, "data: ") {
				ch <- res{line: trimmed}
				return
			}
			if err != nil {
				ch <- res{err: err}
				return
			}
		}
	}()
	select {
	case r := <-ch:
		if r.err != nil {
			t.Fatalf("reading SSE event: %v", r.err)
		}
		return r.line
	case <-time.After(5 * time.Second):
		t.Fatal("timed out waiting for an SSE event — response was buffered, not streamed")
		return ""
	}
}

// TestHTTPListener_AuditRowShapeMatchesStdio: the SAME tools/call driven through
// the stdio proxy's Probe seam and through the HTTP listener produces
// field-identical audit rows (ignoring per-entry ts/sig), proving both
// transports share one enforcement path so `nockguard verify` / the Live Wall
// read one consistent trail.
func TestHTTPListener_AuditRowShapeMatchesStdio(t *testing.T) {
	const pol = "agents:\n  mira:\n    mode: allow\n    deny:\n      - nockcc_kill_switch_set\n"
	call := toolCall("7", "nockcc_kill_switch_set")

	// stdio path via Probe.
	stdioAuditor, stdioPath, _ := newEd25519Auditor(t)
	stdioGate := newGate(t, pol, nil, stdioAuditor)
	if _, _, err := stdioGate.Probe([]byte(call)); err != nil {
		t.Fatalf("Probe: %v", err)
	}
	_ = stdioAuditor.Close()

	// HTTP path via the listener (deny → no upstream needed).
	httpAuditor, httpPath, _ := newEd25519Auditor(t)
	httpGate := newGate(t, pol, nil, httpAuditor)
	lsrv := httptest.NewServer(NewHTTPListener("127.0.0.1:0", "http://127.0.0.1:1", httpGate, log.New(io.Discard, "", 0)))
	defer lsrv.Close()
	post(t, lsrv.URL, call)
	_ = httpAuditor.Close()

	stdioEvs := readAuditEvents(t, stdioPath)
	httpEvs := readAuditEvents(t, httpPath)
	if len(stdioEvs) != 1 || len(httpEvs) != 1 {
		t.Fatalf("expected 1 row each, got stdio=%d http=%d", len(stdioEvs), len(httpEvs))
	}
	s, h := stdioEvs[0], httpEvs[0]
	if s.Agent != h.Agent || s.Tool != h.Tool || s.Decision != h.Decision || s.Reason != h.Reason {
		t.Errorf("audit row shape differs:\n  stdio: %+v\n  http:  %+v", s, h)
	}
	if h.Decision != "deny" || h.Tool != "nockcc_kill_switch_set" {
		t.Errorf("unexpected http audit row: %+v", h)
	}
}

// TestHTTPListener_DeniedNotificationAccepted: a denied tools/call NOTIFICATION
// (no id) has no JSON-RPC response channel, so the listener returns an empty 202
// and never contacts upstream — it must NOT fall through to the forward path.
func TestHTTPListener_DeniedNotificationAccepted(t *testing.T) {
	var called bool
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { called = true }))
	defer upstream.Close()

	gate := newGate(t, "agents:\n  mira:\n    mode: allow\n    deny:\n      - nockcc_kill_switch_set\n", nil, nil)
	lsrv := httptest.NewServer(NewHTTPListener("127.0.0.1:0", upstream.URL, gate, log.New(io.Discard, "", 0)))
	defer lsrv.Close()

	notif := `{"jsonrpc":"2.0","method":"tools/call","params":{"name":"nockcc_kill_switch_set"}}`
	status, body, _ := post(t, lsrv.URL, notif)
	if called {
		t.Fatal("denied notification MUST NOT contact upstream")
	}
	if status != http.StatusAccepted {
		t.Errorf("denied-notification status = %d, want 202", status)
	}
	if strings.TrimSpace(body) != "" {
		t.Errorf("denied-notification body = %q, want empty", body)
	}
}

// TestHTTPListener_NonToolsCallForwardedVerbatim: initialize (and other
// non-tools/call methods) are not gated — they forward to upstream unchanged.
func TestHTTPListener_NonToolsCallForwardedVerbatim(t *testing.T) {
	var called bool
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		called = true
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"jsonrpc":"2.0","id":1,"result":{"protocolVersion":"2024-11-05"}}`))
	}))
	defer upstream.Close()

	// default-deny policy: even so, initialize is non-gated and must forward.
	gate := newGate(t, "agents:\n  mira:\n    mode: deny\n", nil, nil)
	lsrv := httptest.NewServer(NewHTTPListener("127.0.0.1:0", upstream.URL, gate, log.New(io.Discard, "", 0)))
	defer lsrv.Close()

	status, body, _ := post(t, lsrv.URL, `{"jsonrpc":"2.0","id":1,"method":"initialize","params":{}}`)
	if !called {
		t.Fatal("initialize should forward to upstream even under default-deny")
	}
	if status != http.StatusOK || !strings.Contains(body, "protocolVersion") {
		t.Errorf("initialize passthrough failed: status=%d body=%s", status, body)
	}
}

// TestHTTPListener_AuthAndSessionPassthrough: the connector's own Authorization
// and Mcp-Session-Id headers are forwarded upstream unchanged (design risk #3),
// and the upstream's Mcp-Session-Id flows back to the connector.
func TestHTTPListener_AuthAndSessionPassthrough(t *testing.T) {
	var gotAuth, gotSession string
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotAuth = r.Header.Get("Authorization")
		gotSession = r.Header.Get("Mcp-Session-Id")
		w.Header().Set("Content-Type", "application/json")
		w.Header().Set("Mcp-Session-Id", "sess-from-upstream")
		_, _ = w.Write([]byte(`{"jsonrpc":"2.0","id":1,"result":{}}`))
	}))
	defer upstream.Close()

	gate := newGate(t, "agents:\n  mira:\n    mode: allow\n", nil, nil)
	lsrv := httptest.NewServer(NewHTTPListener("127.0.0.1:0", upstream.URL, gate, log.New(io.Discard, "", 0)))
	defer lsrv.Close()

	req, _ := http.NewRequest(http.MethodPost, lsrv.URL, strings.NewReader(toolCall("1", "nockcc_nock_list")))
	req.Header.Set("Authorization", "Bearer connector-own-token")
	req.Header.Set("Mcp-Session-Id", "sess-from-connector")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("do: %v", err)
	}
	defer resp.Body.Close()
	_, _ = io.ReadAll(resp.Body)

	if gotAuth != "Bearer connector-own-token" {
		t.Errorf("upstream Authorization = %q, want the connector's own token forwarded unchanged", gotAuth)
	}
	if gotSession != "sess-from-connector" {
		t.Errorf("upstream Mcp-Session-Id = %q, want the connector's session forwarded", gotSession)
	}
	if got := resp.Header.Get("Mcp-Session-Id"); got != "sess-from-upstream" {
		t.Errorf("connector-facing Mcp-Session-Id = %q, want the upstream's session relayed back", got)
	}
}

// TestHTTPListener_MCPProtocolHeadersPassthrough: the Streamable-HTTP protocol
// headers the connector owns — MCP-Protocol-Version (mandatory on every POST)
// and Last-Event-ID (SSE resumption) — are forwarded upstream unchanged.
func TestHTTPListener_MCPProtocolHeadersPassthrough(t *testing.T) {
	var gotVersion, gotLastEvent string
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotVersion = r.Header.Get("MCP-Protocol-Version")
		gotLastEvent = r.Header.Get("Last-Event-ID")
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"jsonrpc":"2.0","id":1,"result":{}}`))
	}))
	defer upstream.Close()

	gate := newGate(t, "agents:\n  mira:\n    mode: allow\n", nil, nil)
	lsrv := httptest.NewServer(NewHTTPListener("127.0.0.1:0", upstream.URL, gate, log.New(io.Discard, "", 0)))
	defer lsrv.Close()

	req, _ := http.NewRequest(http.MethodPost, lsrv.URL, strings.NewReader(toolCall("1", "nockcc_nock_list")))
	req.Header.Set("MCP-Protocol-Version", "2026-07-28")
	req.Header.Set("Last-Event-ID", "42")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("do: %v", err)
	}
	defer resp.Body.Close()
	_, _ = io.ReadAll(resp.Body)

	if gotVersion != "2026-07-28" {
		t.Errorf("upstream MCP-Protocol-Version = %q, want the connector's version forwarded", gotVersion)
	}
	if gotLastEvent != "42" {
		t.Errorf("upstream Last-Event-ID = %q, want the connector's resumption id forwarded", gotLastEvent)
	}
}

// TestHTTPListener_UpstreamErrorNotEchoed: when the upstream is unreachable, the
// client-facing JSON-RPC error is a fixed message — it must NOT leak the raw
// transport error, which carries the upstream URL and internal host/port.
func TestHTTPListener_UpstreamErrorNotEchoed(t *testing.T) {
	// Allow policy so the call reaches the forward path, pointed at a refused
	// port so client.Do returns a *url.Error naming the upstream address.
	const unreachable = "http://127.0.0.1:1/mcp"
	gate := newGate(t, "agents:\n  mira:\n    mode: allow\n", nil, nil)
	lsrv := httptest.NewServer(NewHTTPListener("127.0.0.1:0", unreachable, gate, log.New(io.Discard, "", 0)))
	defer lsrv.Close()

	status, body, _ := post(t, lsrv.URL, toolCall("1", "nockcc_nock_list"))
	if status != http.StatusOK {
		t.Errorf("status = %d, want 200 (JSON-RPC error body)", status)
	}
	if !strings.Contains(body, "upstream unreachable") {
		t.Errorf("body should carry the fixed message: %s", body)
	}
	if strings.Contains(body, "127.0.0.1:1") || strings.Contains(body, "dial") {
		t.Errorf("client-facing error leaked the raw upstream detail: %s", body)
	}
}

// TestRequireLoopback guards the bind: only explicit loopback hosts are allowed,
// because the loopback listener receives a live bearer token.
func TestRequireLoopback(t *testing.T) {
	tests := []struct {
		addr    string
		wantErr bool
	}{
		{"127.0.0.1:8790", false},
		{"127.0.0.1:0", false},
		{"[::1]:8790", false},
		{"0.0.0.0:8790", true},
		{":8790", true},
		{"8.8.8.8:80", true},
		{"example.com:80", true},
		{"not-an-addr", true},
	}
	for _, tt := range tests {
		t.Run(tt.addr, func(t *testing.T) {
			err := requireLoopback(tt.addr)
			if (err != nil) != tt.wantErr {
				t.Errorf("requireLoopback(%q) err = %v, wantErr = %v", tt.addr, err, tt.wantErr)
			}
		})
	}
}

// TestHTTPListener_MethodNotAllowed: only POST carries JSON-RPC; GET is refused.
func TestHTTPListener_MethodNotAllowed(t *testing.T) {
	gate := newGate(t, "agents:\n  mira:\n    mode: allow\n", nil, nil)
	lsrv := httptest.NewServer(NewHTTPListener("127.0.0.1:0", "http://127.0.0.1:1", gate, log.New(io.Discard, "", 0)))
	defer lsrv.Close()

	resp, err := http.Get(lsrv.URL)
	if err != nil {
		t.Fatalf("GET: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusMethodNotAllowed {
		t.Errorf("GET status = %d, want 405", resp.StatusCode)
	}
}
