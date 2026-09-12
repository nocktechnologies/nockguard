package proxy

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"reflect"
	"strings"
	"sync/atomic"
	"time"

	"github.com/nocktechnologies/nockguard/internal/extract"
	"github.com/nocktechnologies/nockguard/internal/jsonrpc"
	"github.com/nocktechnologies/nockguard/internal/proxy/forwardhttp"
)

// httpListenerBodyCap mirrors mcphttp's 10 MB scanner max-token cap: the largest
// single JSON-RPC message the listener will read from the connector before
// rejecting it. Large tool RESULTS (a long nock_list / identity doc) travel on
// the RESPONSE path, which is streamed and uncapped; this bounds only the
// inbound REQUEST the connector POSTs.
const httpListenerBodyCap = 10 * 1024 * 1024

// HTTPListener is the N8761 Option-A local HTTP forward-proxy. It puts the SAME
// enforcement gate the stdio proxy runs (StdioProxy.decide: policy → validate →
// rate-limit → approval → Ed25519 audit) behind an HTTP listener the flagship
// seat's managed remote-HTTP MCP connector can re-point its NockCC endpoint at.
//
// It gates on the MCP TOOL NAME, not on egress host — so its audit rows are
// identical in shape to the stdio proxy's and `nockguard verify` / the Live Wall
// stay consistent across both proxy modes. It reuses forwardhttp's server
// skeleton (Run / http.Server / graceful shutdown / hop-by-hop stripping) but
// NOT its egress/SSRF/CONNECT semantics: the upstream is a single
// operator-configured endpoint, so there is no arbitrary-host SSRF surface here.
//
// The connector holds its OWN NockCC bearer token; the listener forwards that
// inbound Authorization header upstream unchanged and never logs or audits it.
// It binds 127.0.0.1 only — a loopback listener now receives a live bearer
// token, and any local process reaching a wildcard bind could harvest it.
type HTTPListener struct {
	// gate carries the enforcement pipeline (engine, validator, limiter, auditor,
	// forwarder, trust, approver). Its stdio upstream field is unused here — only
	// decide() is called, which never touches it.
	gate     *StdioProxy
	listen   string
	upstream string
	client   *http.Client
	logger   *log.Logger
}

// NewHTTPListener builds a listener that binds listen (must be a loopback
// host:port, e.g. 127.0.0.1:8790), gates traffic through gate, and forwards
// allowed calls to the upstream MCP endpoint (e.g.
// https://cc.nocktechnologies.io/mcp).
func NewHTTPListener(listen, upstream string, gate *StdioProxy, logger *log.Logger) *HTTPListener {
	// Clone DefaultTransport rather than build a bare one, so we inherit its
	// DialContext timeout, TLSHandshakeTimeout, and HTTP(S)_PROXY/NO_PROXY
	// handling. A zero-value Transport has none of those: a TCP connect or TLS
	// handshake to an unreachable upstream would hang unbounded because
	// ResponseHeaderTimeout only starts after the request is written.
	transport := http.DefaultTransport.(*http.Transport).Clone()
	// Bound only the time-to-first-response-header. We deliberately do NOT set
	// Client.Timeout (it also bounds body reads and would sever a long-lived SSE
	// stream mid-flight); the streamed body stays uncapped.
	transport.ResponseHeaderTimeout = 60 * time.Second
	return &HTTPListener{
		gate:     gate,
		listen:   listen,
		upstream: upstream,
		logger:   logger,
		client:   &http.Client{Transport: transport},
	}
}

// Run starts the listener and blocks until ctx is cancelled, then gracefully
// shuts the server down. The skeleton mirrors forwardhttp.Run. Binding is
// refused unless listen is an explicit loopback host.
func (l *HTTPListener) Run(ctx context.Context) error {
	if err := requireLoopback(l.listen); err != nil {
		return err
	}
	srv := &http.Server{
		Addr:              l.listen,
		Handler:           l,
		ReadHeaderTimeout: 10 * time.Second,
	}
	errCh := make(chan error, 1)
	go func() { errCh <- srv.ListenAndServe() }()

	select {
	case <-ctx.Done():
		shutdownCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		if err := srv.Shutdown(shutdownCtx); err != nil {
			return err
		}
		if err := <-errCh; err != nil && err != http.ErrServerClosed {
			return err
		}
		return nil
	case err := <-errCh:
		if err == http.ErrServerClosed {
			return nil
		}
		return err
	}
}

// requireLoopback refuses any bind that is not an explicit loopback address. A
// wildcard or routable bind would expose the live bearer token the connector
// sends to a localhost endpoint (design risk #3).
func requireLoopback(addr string) error {
	host, _, err := net.SplitHostPort(addr)
	if err != nil {
		return fmt.Errorf("listen address %q must be host:port: %w", addr, err)
	}
	if host == "" {
		return fmt.Errorf("listen address %q must bind an explicit loopback host (e.g. 127.0.0.1), not a wildcard", addr)
	}
	ip := net.ParseIP(host)
	if ip == nil || !ip.IsLoopback() {
		return fmt.Errorf("listen host %q must be a loopback address (127.0.0.1 or ::1): the proxy receives a live bearer token and must never bind a routable interface", host)
	}
	return nil
}

// ServeHTTP is the connector-facing handler. It reads the POST body as one
// JSON-RPC message, runs it through the shared enforcement gate, and either
// forwards it upstream (allow) or returns a JSON-RPC error without ever
// contacting upstream (deny/block/rate-limit/approval-denied).
func (l *HTTPListener) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	// Read at most the cap + 1 byte so an over-cap body is detected without
	// buffering it whole. Mirrors mcphttp's 10 MB scanner limit on the inbound side.
	body, err := io.ReadAll(io.LimitReader(r.Body, httpListenerBodyCap+1))
	if err != nil {
		l.writeJSONRPCError(w, json.RawMessage("null"), -32700, "nockguard: could not read request body")
		return
	}
	if len(body) > httpListenerBodyCap {
		l.writeJSONRPCError(w, json.RawMessage("null"), -32600, "nockguard: request body exceeds the 10MB limit")
		return
	}

	seq := atomic.AddUint64(&l.gate.auditSeq, 1) - 1

	// Guarantee exactly-once resolution per reserved seq: establish defer with flag
	// that ensures even on early returns, the seq gets resolved exactly once.
	resolved := false
	defer func() {
		if !resolved {
			l.gate.resolveAudit(seq)
		}
	}()

	d := l.gate.decide(body, seq)

	if d.reject {
		if d.rejectID == nil {
			// Denied NOTIFICATION: JSON-RPC has no response channel for a message
			// with no id. There is no "drop" over HTTP, so acknowledge receipt with
			// an empty 202 and never contact upstream.
			resolved = true
			l.gate.resolveAudit(seq)
			w.WriteHeader(http.StatusAccepted)
			return
		}
		// Denied REQUEST: return the JSON-RPC error as a 200 body. A 4xx would make
		// some MCP clients treat the exchange as a transport failure and swallow the
		// policy reason; a 200 + error object surfaces "denied by policy" to the agent.
		resolved = true
		l.gate.resolveAudit(seq)
		l.writeJSONRPCError(w, d.rejectID, d.rejectCode, d.rejectMsg)
		return
	}

	// Cleared the gate (or non-tools/call traffic like initialize/tools/list):
	// forward the CANONICAL bytes upstream and stream the response back unchanged.
	// forward() will set resolved = true to prevent double-resolution in the defer.
	l.forward(w, r, d.forward, d.toolForState, d.refsForState, d.deferredAudits, d.refsForAudit, d.tool, seq, &resolved)
}

// jsonRPCIDMatches reports whether respID is present and equals the id of the
// forwarded request. A valid JSON-RPC response echoes the request id; a missing
// or mismatched id means the 2xx body is not a genuine response to this call and
// must not be treated as a committable success.
func jsonRPCIDMatches(reqBody []byte, respID json.RawMessage) bool {
	if respID == nil {
		return false
	}
	var req jsonrpc.Message
	if err := json.Unmarshal(reqBody, &req); err != nil || req.ID == nil {
		return false
	}
	var reqID, respIDVal interface{}
	if json.Unmarshal(req.ID, &reqID) != nil || json.Unmarshal(respID, &respIDVal) != nil {
		return false
	}
	return reflect.DeepEqual(reqID, respIDVal)
}

// writeJSONRPCError returns a JSON-RPC error object as a 200 response body. See
// ServeHTTP for why deny responses are 200, not 4xx.
func (l *HTTPListener) writeJSONRPCError(w http.ResponseWriter, id json.RawMessage, code int, msg string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write(jsonrpc.ErrorResponse(id, code, msg))
}

// forward POSTs the allowed body to the upstream MCP endpoint and streams the
// response (application/json or SSE) back to the connector byte-for-byte.
// deferredAudits are emitted in the response path after verifying JSON-RPC success,
// ensuring audit stamping happens after card state is committed.
func (l *HTTPListener) forward(w http.ResponseWriter, r *http.Request, body []byte, toolForState string, refsForState *extract.References, deferredAudits []deferredAudit, refsForAudit *extract.References, tool string, seq uint64, resolved *bool) {
	req, err := http.NewRequestWithContext(r.Context(), http.MethodPost, l.upstream, bytes.NewReader(body))
	if err != nil {
		l.logger.Printf("UPSTREAM-ERROR agent=%s: build request: %v", l.gate.agent, err)
		*resolved = true
		l.gate.resolveAudit(seq)
		l.writeJSONRPCError(w, json.RawMessage("null"), -32603, "nockguard: upstream request build failed")
		return
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json, text/event-stream")
	// Auth passthrough (design risk #3): the managed connector holds its OWN
	// NockCC bearer token and sends it to what it believes is NockCC. Forward it
	// upstream verbatim and NEVER log or audit it (the audit trail records tool
	// name + decision only, never headers or arguments). This is the REVERSE of
	// mcphttp, which INJECTS a configured token from --auth-env.
	if auth := r.Header.Get("Authorization"); auth != "" {
		req.Header.Set("Authorization", auth)
	}
	// Streamable-HTTP session passthrough: the connector is a spec-compliant MCP
	// HTTP client that owns its Mcp-Session-Id, so relay it upstream and let the
	// upstream's response header flow back below. Card state is intentionally
	// process/session-scoped: this design assumes one connector session per
	// listener instance with non-overlapping claim/act/release calls. Concurrent
	// multi-session HTTP traffic through one listener is out of scope for this PR.
	if sid := r.Header.Get("Mcp-Session-Id"); sid != "" {
		req.Header.Set("Mcp-Session-Id", sid)
	}
	// Streamable-HTTP protocol headers the spec requires the client to carry and
	// the server to honour: MCP-Protocol-Version pins the negotiated version on
	// every POST (a dropped header makes the upstream fall back or reject), and
	// Last-Event-ID is how the connector resumes an interrupted SSE stream. We
	// relay only the specific headers the connector owns rather than blanket-
	// copying its request headers, because this proxy re-emits a CANONICAL body:
	// forwarding the client's Content-Length/Content-Type would then describe the
	// wrong bytes. Content-Type/Accept stay proxy-managed above.
	if pv := r.Header.Get("MCP-Protocol-Version"); pv != "" {
		req.Header.Set("MCP-Protocol-Version", pv)
	}
	if leid := r.Header.Get("Last-Event-ID"); leid != "" {
		req.Header.Set("Last-Event-ID", leid)
	}

	resp, err := l.client.Do(req)
	if err != nil {
		// Log the full transport/DNS detail but do NOT echo it to the client: a
		// *url.Error carries the upstream URL and internal host/port, and Go
		// redacts only a userinfo password, so a fixed message is returned instead.
		l.logger.Printf("UPSTREAM-ERROR agent=%s: %v", l.gate.agent, err)
		*resolved = true
		l.gate.resolveAudit(seq)
		l.writeJSONRPCError(w, json.RawMessage("null"), -32603, "nockguard: upstream unreachable")
		return
	}
	defer resp.Body.Close()

	// Relay upstream response headers back unchanged, minus hop-by-hop headers
	// (reused from forwardhttp). Carrying Content-Type and Mcp-Session-Id makes the
	// response indistinguishable from a direct NockCC call.
	forwardhttp.RemoveHopByHopHeaders(resp.Header)
	for k, vals := range resp.Header {
		for _, v := range vals {
			w.Header().Add(k, v)
		}
	}
	w.WriteHeader(resp.StatusCode)

	// Card state commit and audit emission are gated on JSON-RPC-level success, not HTTP status.
	// For JSON responses, buffer and parse to check for errors before committing/auditing.
	// For SSE streams, pass through byte-faithful without buffering (no state updates over SSE).
	if (toolForState != "" || len(deferredAudits) > 0) && resp.StatusCode >= 200 && resp.StatusCode < 300 {
		ct := resp.Header.Get("Content-Type")
		if strings.HasPrefix(ct, "application/json") {
			// Buffer and parse the JSON response to check for JSON-RPC errors
			// before committing card state. Only commit if the response is a genuine
			// JSON-RPC success (no "error" field and no tool-level isError).
			respBody, readErr := io.ReadAll(resp.Body)
			if readErr != nil {
				// Read error — treat as upstream failure, do not commit state.
				l.logger.Printf("UPSTREAM-STREAM-ERROR agent=%s: read response body: %v", l.gate.agent, readErr)
				if _, werr := w.Write(respBody); werr != nil {
					return
				}
				// Resolve audits unconditionally to ensure the queue doesn't stall.
				*resolved = true
				l.gate.resolveAudit(seq)
			} else {
				// Commit card state only on a genuine JSON-RPC success response for
				// THIS request: a response shape (no method), an id that matches the
				// forwarded request, a present result, and no error. A 2xx body such
				// as {} or null unmarshals cleanly but carries no result/id and must
				// NOT commit — it would corrupt currentCard as a false success.
				shouldCommit := false
				var msg jsonrpc.Message
				if err := json.Unmarshal(respBody, &msg); err == nil {
					if msg.Method == "" && msg.Error == nil && msg.Result != nil && jsonRPCIDMatches(body, msg.ID) {
						shouldCommit = true
						// A tool-level failure (MCP result.isError=true) is a success
						// envelope but a failed tool call — do not commit.
						var result map[string]interface{}
						if err := json.Unmarshal(msg.Result, &result); err == nil {
							if toolErr, ok := result["isError"].(bool); ok && toolErr {
								shouldCommit = false
							}
						}
					}
				}
				// Write the buffered response bytes unchanged.
				if _, werr := w.Write(respBody); werr != nil {
					return
				}
				// Commit card state only if JSON-RPC succeeded.
				if shouldCommit {
					l.gate.updateCardState(seq, toolForState, refsForState)
				}
				// Resolve audits unconditionally to ensure the queue doesn't stall.
				*resolved = true
				l.gate.resolveAudit(seq)
			}
			return
		}
		// SSE and other streaming responses: pass through byte-faithful without buffering.
		// No card state is committed over streaming responses (design limitation: N/A for
		// tool calls which return JSON responses, not SSE).
		// Resolve audits unconditionally to ensure the queue doesn't stall.
		*resolved = true
		l.gate.resolveAudit(seq)
	}

	*resolved = true
	l.gate.resolveAudit(seq)
	l.streamBody(w, resp.Body)
}

// streamBody copies the upstream body to the connector, flushing each chunk so
// SSE `data:` events arrive as upstream produces them rather than buffering to
// stream end. Both application/json and SSE are byte-faithful passthrough here —
// unlike mcphttp.writeSSEResponse, which UNWRAPS `data:` frames into bare
// stdio lines (correct for a stdio client, wrong for an HTTP connector whose SSE
// parser expects intact frames).
func (l *HTTPListener) streamBody(w http.ResponseWriter, body io.Reader) {
	rc := http.NewResponseController(w)
	buf := make([]byte, 32*1024)
	for {
		n, rerr := body.Read(buf)
		if n > 0 {
			if _, werr := w.Write(buf[:n]); werr != nil {
				return
			}
			// Best-effort flush: not every ResponseWriter supports it (returns
			// ErrNotSupported), in which case the copy still completes, just buffered.
			_ = rc.Flush()
		}
		if rerr != nil {
			if rerr != io.EOF {
				l.logger.Printf("UPSTREAM-STREAM-ERROR agent=%s: %v", l.gate.agent, rerr)
			}
			return
		}
	}
}
