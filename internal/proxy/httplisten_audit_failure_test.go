package proxy

import (
	"bufio"
	"encoding/json"
	"io"
	"log"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/nocktechnologies/nockguard/internal/audit"
)

// Required audit mode must fail closed before an allowed action is sent to the
// upstream when the configured audit writer has already failed.
func TestHTTPListener_RequiredAuditFailureBlocksBeforeForward(t *testing.T) {
	var upstreamCalls atomic.Int32
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		upstreamCalls.Add(1)
		w.Header().Set("Content-Type", "application/json")
		_, _ = io.WriteString(w, `{"jsonrpc":"2.0","id":1,"result":{"content":[{"type":"text","text":"upstream-ok"}]}}`)
	}))
	defer upstream.Close()

	auditor, _, _ := newEd25519Auditor(t)
	if err := auditor.Close(); err != nil {
		t.Fatal(err)
	}
	gate := newGate(t, "agents:\n  mira:\n    mode: allow\n", nil, auditor)
	listener := httptest.NewServer(NewHTTPListener("127.0.0.1:0", upstream.URL, gate, log.New(io.Discard, "", 0)).WithRequiredAudit())
	defer listener.Close()

	_, body, _ := post(t, listener.URL, toolCall("1", "nockcc_nock_list"))
	if got := upstreamCalls.Load(); got != 0 {
		t.Fatalf("upstream received %d calls after required audit was unavailable; response=%s", got, body)
	}
	if !strings.Contains(strings.ToLower(body), "audit") {
		t.Fatalf("response %q does not surface the required audit failure", body)
	}
}

// A writer can be healthy at request entry but fail while persisting the
// dispatch event. That write failure must latch the shared Auditor and prevent
// both the current and subsequent calls from reaching upstream.
func TestHTTPListener_RequiredDispatchWriteFailureBlocksAndLatches(t *testing.T) {
	var upstreamCalls atomic.Int32
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		upstreamCalls.Add(1)
		w.Header().Set("Content-Type", "application/json")
		_, _ = io.WriteString(w, `{"jsonrpc":"2.0","id":1,"result":{}}`)
	}))
	defer upstream.Close()

	auditor, auditPath, _ := newEd25519Auditor(t)
	defer func() { _ = auditor.Close() }()
	if err := auditor.RequiredError(); err != nil {
		t.Fatalf("fresh required auditor is unhealthy: %v", err)
	}
	// RecordRequired writes the signed high-water mark through this temporary
	// path. Turning it into a directory forces a real filesystem error without
	// replacing or mocking the Auditor.
	if err := os.Mkdir(auditPath+".hwm.tmp", 0700); err != nil {
		t.Fatalf("create hwm temp directory: %v", err)
	}
	gate := newGate(t, "agents:\n  mira:\n    mode: allow\n", nil, auditor)
	listener := httptest.NewServer(NewHTTPListener("127.0.0.1:0", upstream.URL, gate, log.New(io.Discard, "", 0)).WithRequiredAudit())
	defer listener.Close()

	_, firstBody, _ := post(t, listener.URL, toolCall("1", "nockcc_nock_list"))
	if got := upstreamCalls.Load(); got != 0 {
		t.Fatalf("upstream received %d calls after dispatch write failed; response=%s", got, firstBody)
	}
	if err := auditor.RequiredError(); err == nil {
		t.Fatal("dispatch write failure did not latch the shared Auditor")
	}
	_, secondBody, _ := post(t, listener.URL, toolCall("2", "nockcc_nock_list"))
	if got := upstreamCalls.Load(); got != 0 {
		t.Fatalf("upstream received %d calls after required writer latched; response=%s", got, secondBody)
	}
}

// Required auditing still forwards a healthy call after the dispatch record is
// durable and exposes success only after the completion record is durable.
func TestHTTPListener_RequiredAuditHealthySignedPositiveControl(t *testing.T) {
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = io.WriteString(w, `{"jsonrpc":"2.0","id":1,"result":{"content":[{"type":"text","text":"upstream-ok"}]}}`)
	}))
	defer upstream.Close()

	auditor, auditPath, pub := newEd25519Auditor(t)
	gate := newGate(t, "agents:\n  mira:\n    mode: allow\n", nil, auditor)
	listener := httptest.NewServer(NewHTTPListener("127.0.0.1:0", upstream.URL, gate, log.New(io.Discard, "", 0)).WithRequiredAudit())
	defer listener.Close()

	_, body, _ := post(t, listener.URL, toolCall("1", "nockcc_nock_list"))
	if err := auditor.Close(); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(body, "upstream-ok") {
		t.Fatalf("healthy audited call did not return upstream result: %s", body)
	}
	n, err := audit.VerifyEd25519(auditPath, pub)
	if err != nil {
		t.Fatalf("verify signed audit trail: %v", err)
	}
	if n != 2 {
		t.Fatalf("verified audit entries = %d, want dispatch and allow", n)
	}
	events := readAuditEvents(t, auditPath)
	if len(events) != 2 || events[0].Decision != "dispatch" || events[1].Decision != "allow" {
		t.Fatalf("audit decisions = %+v, want dispatch followed by allow", events)
	}
}

// The upstream may have completed its action before the completion audit
// fails. In that case the listener must hide the apparent success, warn the
// caller that execution may have happened, never retry it, and latch the
// shared required auditor so later actions cannot proceed either.
func TestHTTPListener_RequiredCompletionAuditFailureHidesSuccessAndLatches(t *testing.T) {
	var upstreamCalls atomic.Int32
	upstreamActionDone := make(chan struct{})
	releaseResponse := make(chan struct{})
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		upstreamCalls.Add(1)
		close(upstreamActionDone)
		<-releaseResponse
		w.Header().Set("Content-Type", "application/json")
		_, _ = io.WriteString(w, `{"jsonrpc":"2.0","id":1,"result":{"content":[{"type":"text","text":"action-completed"}]}}`)
	}))
	defer upstream.Close()

	auditor, _, _ := newEd25519Auditor(t)
	defer func() {
		if err := auditor.Close(); err != nil {
			t.Errorf("close auditor: %v", err)
		}
	}()
	gate := newGate(t, "agents:\n  mira:\n    mode: allow\n", nil, auditor)
	listener := httptest.NewServer(NewHTTPListener("127.0.0.1:0", upstream.URL, gate, log.New(io.Discard, "", 0)).WithRequiredAudit())
	defer listener.Close()

	firstResponse := make(chan struct {
		status int
		body   string
		err    error
	}, 1)
	go func() {
		resp, err := http.Post(listener.URL, "application/json", strings.NewReader(toolCall("1", "nockcc_nock_list")))
		if err != nil {
			firstResponse <- struct {
				status int
				body   string
				err    error
			}{err: err}
			return
		}
		defer resp.Body.Close()
		body, err := io.ReadAll(resp.Body)
		firstResponse <- struct {
			status int
			body   string
			err    error
		}{resp.StatusCode, string(body), err}
	}()

	<-upstreamActionDone
	if err := auditor.Close(); err != nil {
		t.Fatal(err)
	}
	close(releaseResponse)
	first := <-firstResponse
	if first.err != nil {
		t.Fatalf("first POST: %v", first.err)
	}
	if strings.Contains(first.body, "action-completed") {
		t.Fatalf("listener exposed upstream success after completion audit failed: status=%d body=%s", first.status, first.body)
	}
	if !strings.Contains(strings.ToLower(first.body), "may have executed") || !strings.Contains(strings.ToLower(first.body), "retry") {
		t.Fatalf("response must explain that the action may have executed and must not be retried automatically: %s", first.body)
	}
	if got := upstreamCalls.Load(); got != 1 {
		t.Fatalf("upstream call count after failed completion audit = %d, want exactly 1 (no retry)", got)
	}

	_, secondBody, _ := post(t, listener.URL, toolCall("2", "nockcc_nock_list"))
	if got := upstreamCalls.Load(); got != 1 {
		t.Fatalf("latched audit failure allowed another upstream call; count=%d response=%s", got, secondBody)
	}
	if !strings.Contains(strings.ToLower(secondBody), "audit") {
		t.Fatalf("later response %q does not surface the latched audit failure", secondBody)
	}
}

// A matching result on SSE is still completion of the action. If the required
// audit writer fails before that result is emitted, the successful event must
// be replaced with an uncertain-execution error frame.
func TestHTTPListener_RequiredSSECompletionAuditFailureWithholdsResult(t *testing.T) {
	auditor, _, _ := newEd25519Auditor(t)
	var upstreamCalls atomic.Int32
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		upstreamCalls.Add(1)
		if err := auditor.Close(); err != nil {
			t.Errorf("close auditor from upstream: %v", err)
		}
		w.Header().Set("Content-Type", "text/event-stream")
		flusher := w.(http.Flusher)
		_, _ = io.WriteString(w, "data: {\"jsonrpc\":\"2.0\",\"id\":1,\"result\":{\"content\":[{\"type\":\"text\",\"text\":\"sse-action-completed\"}]}}\n\n")
		flusher.Flush()
	}))
	defer upstream.Close()
	gate := newGate(t, "agents:\n  mira:\n    mode: allow\n", nil, auditor)
	listener := httptest.NewServer(NewHTTPListener("127.0.0.1:0", upstream.URL, gate, log.New(io.Discard, "", 0)).WithRequiredAudit())
	defer listener.Close()

	resp, err := http.Post(listener.URL, "application/json", strings.NewReader(toolCall("1", "nockcc_nock_list")))
	if err != nil {
		t.Fatalf("POST: %v", err)
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("read SSE body: %v", err)
	}
	if got := upstreamCalls.Load(); got != 1 {
		t.Fatalf("upstream calls = %d, want 1; the result failure must not trigger a retry", got)
	}
	if strings.Contains(string(body), "sse-action-completed") {
		t.Fatalf("listener exposed successful SSE result after audit failure: %s", body)
	}
	if !strings.Contains(strings.ToLower(string(body)), "may have executed") || !strings.Contains(strings.ToLower(string(body)), "do not retry automatically") {
		t.Fatalf("SSE body does not explain uncertain execution and no-retry guidance: %s", body)
	}
}

// Required SSE handling releases the connector as soon as the matching result
// is audited, even when the upstream keeps its event stream open afterward.
func TestHTTPListener_RequiredSSEHealthyResultReleasesBeforeUpstreamEnds(t *testing.T) {
	releaseUpstream := make(chan struct{})
	var releaseOnce sync.Once
	upstreamStillOpen := make(chan struct{})
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/event-stream")
		w.WriteHeader(http.StatusOK)
		_, _ = io.WriteString(w, "data: {\"jsonrpc\":\"2.0\",\"id\":1,\"result\":{\"content\":[{\"type\":\"text\",\"text\":\"sse-action-completed\"}]}}\n\n")
		w.(http.Flusher).Flush()
		close(upstreamStillOpen)
		<-releaseUpstream
	}))
	defer upstream.Close()
	defer releaseOnce.Do(func() { close(releaseUpstream) })
	auditor, _, _ := newEd25519Auditor(t)
	defer func() { _ = auditor.Close() }()
	gate := newGate(t, "agents:\n  mira:\n    mode: allow\n", nil, auditor)
	listener := httptest.NewServer(NewHTTPListener("127.0.0.1:0", upstream.URL, gate, log.New(io.Discard, "", 0)).WithRequiredAudit())
	defer listener.Close()

	resp, err := http.Post(listener.URL, "application/json", strings.NewReader(toolCall("1", "nockcc_nock_list")))
	if err != nil {
		t.Fatalf("POST: %v", err)
	}
	defer resp.Body.Close()
	if ct := resp.Header.Get("Content-Type"); !strings.HasPrefix(ct, "text/event-stream") {
		t.Fatalf("content-type = %q, want text/event-stream", ct)
	}
	select {
	case <-upstreamStillOpen:
	case <-time.After(2 * time.Second):
		t.Fatal("upstream did not reach its keep-alive wait")
	}
	result := readSSEEvent(t, bufio.NewReader(resp.Body))
	if !strings.Contains(result, "sse-action-completed") {
		t.Fatalf("SSE result event = %q", result)
	}
	if !strings.Contains(result, "data: ") {
		t.Fatalf("result was not delivered as an SSE data event: %q", result)
	}
	// The response has ended even though the upstream handler is still blocked.
	// A healthy required audit must not wait for the upstream stream to close.
	readDone := make(chan error, 1)
	go func() {
		_, readErr := io.Copy(io.Discard, resp.Body)
		readDone <- readErr
	}()
	select {
	case <-readDone:
	case <-time.After(2 * time.Second):
		t.Fatal("listener kept the connector response open after the matching SSE result")
	}
	releaseOnce.Do(func() { close(releaseUpstream) })
}

// Required audit failure is shared at the Auditor level. Two HTTPListeners
// with separate gates cannot bypass a failure latched by the first listener.
func TestHTTPListener_RequiredAuditFailureBlocksOtherListenerSharingAuditor(t *testing.T) {
	auditor, _, _ := newEd25519Auditor(t)
	var firstCalls, secondCalls atomic.Int32
	firstUpstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		firstCalls.Add(1)
		if err := auditor.Close(); err != nil {
			t.Errorf("close auditor from first upstream: %v", err)
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = io.WriteString(w, `{"jsonrpc":"2.0","id":1,"result":{"content":[{"type":"text","text":"first-action-completed"}]}}`)
	}))
	defer firstUpstream.Close()
	secondUpstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		secondCalls.Add(1)
		w.Header().Set("Content-Type", "application/json")
		_, _ = io.WriteString(w, `{"jsonrpc":"2.0","id":2,"result":{"content":[{"type":"text","text":"second-action-completed"}]}}`)
	}))
	defer secondUpstream.Close()

	firstGate := newGate(t, "agents:\n  mira:\n    mode: allow\n", nil, auditor)
	secondGate := newGate(t, "agents:\n  mira:\n    mode: allow\n", nil, auditor)
	firstListener := httptest.NewServer(NewHTTPListener("127.0.0.1:0", firstUpstream.URL, firstGate, log.New(io.Discard, "", 0)).WithRequiredAudit())
	defer firstListener.Close()
	secondListener := httptest.NewServer(NewHTTPListener("127.0.0.1:0", secondUpstream.URL, secondGate, log.New(io.Discard, "", 0)).WithRequiredAudit())
	defer secondListener.Close()

	_, firstBody, _ := post(t, firstListener.URL, toolCall("1", "nockcc_nock_list"))
	if strings.Contains(firstBody, "first-action-completed") {
		t.Fatalf("first listener exposed success after the shared audit failed: %s", firstBody)
	}
	_, secondBody, _ := post(t, secondListener.URL, toolCall("2", "nockcc_nock_list"))
	if got := firstCalls.Load(); got != 1 {
		t.Fatalf("first upstream calls = %d, want exactly 1", got)
	}
	if got := secondCalls.Load(); got != 0 {
		t.Fatalf("second listener reached upstream after shared audit failure; calls=%d response=%s", got, secondBody)
	}
	if !strings.Contains(strings.ToLower(secondBody), "audit") {
		t.Fatalf("second listener response %q does not surface shared audit failure", secondBody)
	}
}

// Required tool calls with a bodyless upstream SSE status still need a visible
// JSON-RPC outcome. HTTP 204 cannot carry the error frame that would otherwise
// be appended to an SSE stream, so report that execution may have happened.
func TestHTTPListener_RequiredToolSSEBodyless204ReturnsUncertainOutcome(t *testing.T) {
	cases := []struct {
		name            string
		status          int
		contentType     string
		contentEncoding string
		upstreamBody    string
	}{
		{
			name:         "204 event stream has no body",
			status:       http.StatusNoContent,
			contentType:  "text/event-stream",
			upstreamBody: "data: must-not-be-delivered\n\n",
		},
		{
			name:         "unsupported MIME",
			status:       http.StatusOK,
			contentType:  "application/octet-stream",
			upstreamBody: `{"jsonrpc":"2.0","id":1,"result":{"text":"must-not-be-delivered"}}`,
		},
		{
			name:            "unsupported content encoding",
			status:          http.StatusOK,
			contentType:     "text/event-stream",
			contentEncoding: "br",
			upstreamBody:    "data: must-not-be-delivered\n\n",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			auditor, _, _ := newEd25519Auditor(t)
			defer func() { _ = auditor.Close() }()
			var upstreamCalls atomic.Int32
			upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				upstreamCalls.Add(1)
				w.Header().Set("Content-Type", tc.contentType)
				if tc.contentEncoding != "" {
					w.Header().Set("Content-Encoding", tc.contentEncoding)
				}
				w.WriteHeader(tc.status)
				_, _ = io.WriteString(w, tc.upstreamBody)
			}))
			defer upstream.Close()
			gate := newGate(t, "agents:\n  mira:\n    mode: allow\n", nil, auditor)
			listener := NewHTTPListener("127.0.0.1:0", upstream.URL, gate, log.New(io.Discard, "", 0)).WithRequiredAudit()
			lsrv := httptest.NewServer(listener)
			defer lsrv.Close()

			status, body, contentType := post(t, lsrv.URL, toolCall("1", "nockcc_nock_list"))
			if status != http.StatusOK {
				t.Fatalf("connector status = %d, want visible JSON-RPC response with HTTP 200; body=%s", status, body)
			}
			if !strings.HasPrefix(contentType, "application/json") {
				t.Fatalf("content-type = %q, want application/json carrying the JSON-RPC error", contentType)
			}
			var response struct {
				JSONRPC string          `json:"jsonrpc"`
				ID      json.RawMessage `json:"id"`
				Error   *struct {
					Message string `json:"message"`
				} `json:"error"`
			}
			if err := json.Unmarshal([]byte(body), &response); err != nil {
				t.Fatalf("decode visible JSON-RPC outcome %q: %v", body, err)
			}
			if response.JSONRPC != "2.0" || string(response.ID) != "1" || response.Error == nil {
				t.Fatalf("response = %+v, want JSON-RPC error for request id 1", response)
			}
			if !strings.Contains(strings.ToLower(response.Error.Message), "may have executed") || !strings.Contains(strings.ToLower(response.Error.Message), "do not retry automatically") {
				t.Fatalf("error message %q must warn about uncertain execution and retries", response.Error.Message)
			}
			if strings.Contains(body, "must-not-be-delivered") {
				t.Fatalf("unverified upstream result escaped: %s", body)
			}
			if got := upstreamCalls.Load(); got != 1 {
				t.Fatalf("upstream calls = %d, want exactly one", got)
			}
		})
	}
}

// A required SSE stream that only sends heartbeats or responses for other IDs
// must not pin the listener's serialized request path forever. The same bounded
// response deadline applies to both tool calls and tools/list discovery.
func TestHTTPListener_RequiredSSEWithoutMatchingResponseTimesOut(t *testing.T) {
	for _, method := range []string{"tools/call", "tools/list"} {
		t.Run(method, func(t *testing.T) {
			auditor, _, _ := newEd25519Auditor(t)
			defer func() { _ = auditor.Close() }()
			eventsSent := make(chan struct{})
			releaseUpstream := make(chan struct{})
			var releaseOnce sync.Once
			var upstreamCalls atomic.Int32
			upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				upstreamCalls.Add(1)
				w.Header().Set("Content-Type", "text/event-stream")
				w.WriteHeader(http.StatusOK)
				_, _ = io.WriteString(w, ": heartbeat\n\n"+
					"data: {\"jsonrpc\":\"2.0\",\"id\":999,\"result\":{\"unrelated\":true}}\n\n")
				w.(http.Flusher).Flush()
				close(eventsSent)
				<-releaseUpstream
			}))
			defer upstream.Close()
			gate := newGate(t, "agents:\n  mira:\n    mode: allow\n", nil, auditor)
			listener := NewHTTPListener("127.0.0.1:0", upstream.URL, gate, log.New(io.Discard, "", 0)).WithRequiredAudit()
			listener.streamResponseTimeout = 30 * time.Millisecond
			lsrv := httptest.NewServer(listener)
			defer lsrv.Close()
			defer releaseOnce.Do(func() { close(releaseUpstream) })

			requestBody := toolCall("1", "nockcc_nock_list")
			if method == "tools/list" {
				requestBody = `{"jsonrpc":"2.0","id":1,"method":"tools/list","params":{}}`
			}
			req, err := http.NewRequest(http.MethodPost, lsrv.URL, strings.NewReader(requestBody))
			if err != nil {
				t.Fatal(err)
			}
			resp, err := http.DefaultClient.Do(req)
			if err != nil {
				t.Fatalf("POST: %v", err)
			}
			defer resp.Body.Close()
			select {
			case <-eventsSent:
			case <-time.After(time.Second):
				t.Fatal("upstream did not send heartbeat and unrelated-id event")
			}

			readResult := make(chan struct {
				body string
				err  error
			}, 1)
			go func() {
				body, err := io.ReadAll(resp.Body)
				readResult <- struct {
					body string
					err  error
				}{string(body), err}
			}()
			var result struct {
				body string
				err  error
			}
			select {
			case result = <-readResult:
			case <-time.After(2 * time.Second):
				releaseOnce.Do(func() { close(releaseUpstream) })
				t.Fatalf("required %s SSE listener did not release the connector after its short deadline", method)
			}
			if result.err != nil {
				t.Fatalf("read response: %v", result.err)
			}
			if !strings.Contains(result.body, `"jsonrpc":"2.0"`) || !strings.Contains(result.body, `"id":1`) || !strings.Contains(result.body, `"error"`) {
				t.Fatalf("required %s timeout did not return a JSON-RPC error for id 1: %s", method, result.body)
			}
			if method == "tools/call" && (!strings.Contains(strings.ToLower(result.body), "may have executed") || !strings.Contains(strings.ToLower(result.body), "do not retry automatically")) {
				t.Fatalf("required tools/call timeout did not report uncertain execution: %s", result.body)
			}
			if method == "tools/list" && !strings.Contains(strings.ToLower(result.body), "invalid tools/list response") {
				t.Fatalf("required tools/list timeout should report an invalid discovery response: %s", result.body)
			}
			if got := upstreamCalls.Load(); got != 1 {
				t.Fatalf("upstream calls = %d, want exactly one", got)
			}
			releaseOnce.Do(func() { close(releaseUpstream) })
		})
	}
}
