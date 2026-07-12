// Package httpmcp implements an observe-only, MCP-aware HTTP reverse proxy that
// terminates the MCP Streamable-HTTP transport, audits each tools/call, and
// forwards the request upstream unchanged.
//
// Why this exists (N8761, Phase-1). NockGuard's original firewall is a stdio
// proxy: it wraps an MCP server that speaks over stdin/stdout. But the flagship
// dogfood — Mira's live seat — reaches the NockCC MCP over REMOTE HTTP
// (https://cc.nocktechnologies.io/mcp via the claude.ai connector). The
// connector points at a URL and speaks HTTP; it never spawns a stdio
// subprocess, so the stdio proxy can never sit in that path and the dogfood is
// dark. This proxy is the fix: a localhost HTTP server the seat's MCP URL
// re-points to. It TERMINATES the MCP-over-HTTP connection, parses the JSON-RPC
// tool calls, records a signed audit event, then forwards upstream to the real
// endpoint and streams the response back untouched.
//
// Observe-only. This proxy NEVER blocks a call. It evaluates policy purely to
// record what enforcement WOULD do (allow / would-deny), mirroring the egress
// forward-proxy's observe mode. Enforcement is deliberately not wired.
//
// Transport coverage. The Streamable-HTTP POST path is fully implemented: a POST
// with a JSON-RPC request (single object or a batch array) is parsed for audit,
// then forwarded. The response is streamed back verbatim with per-chunk
// flushing, so a text/event-stream (SSE) response is relayed live — the proxy
// does not buffer it. The Mcp-Session-Id handshake is preserved by passing the
// header through unchanged in both directions. Server-initiated streams (a
// long-lived GET) and session teardown (DELETE) are forwarded transparently.
//
// Auth pass-through. NockGuard audits; it does not re-authenticate. The seat's
// Authorization/bearer header is forwarded upstream unchanged.
//
// Tripwire / kill-switch. Set NOCKGUARD_TRIPWIRE to any non-empty value to
// disable auditing and forward directly. The tripwire is LOUD: it logs on
// startup so a disabled guard is never silent. Enforcement is never engaged
// regardless of the tripwire — this is an observe-only build.
package httpmcp

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"net/url"
	"os"
	"time"

	"github.com/nocktechnologies/nockguard/internal/audit"
	"github.com/nocktechnologies/nockguard/internal/jsonrpc"
	"github.com/nocktechnologies/nockguard/internal/policy"
	"github.com/nocktechnologies/nockguard/internal/proxy/forwardhttp"
)

// EnvTripwire disables auditing and forwards MCP traffic directly when set to
// any non-empty value. The bypass is logged loudly at startup.
const EnvTripwire = "NOCKGUARD_TRIPWIRE"

// maxBodyBytes bounds an inspected request body so a hostile or runaway client
// cannot exhaust proxy memory. MCP tool-call requests are small; 8 MiB is
// generous headroom.
const maxBodyBytes = 8 << 20

// hopByHopHeaders are stripped in both directions — they are connection-scoped
// and must not be forwarded across the proxy boundary.
var hopByHopHeaders = []string{
	"Connection",
	"Proxy-Connection",
	"Keep-Alive",
	"Proxy-Authenticate",
	"Proxy-Authorization",
	"Te",
	"Trailer",
	"Transfer-Encoding",
	"Upgrade",
}

// Proxy is an MCP-aware HTTP reverse proxy. It terminates the MCP-over-HTTP
// transport on `listen`, audits tools/call requests for `agent` in observe
// mode, and forwards to the fixed `upstreamURL`.
type Proxy struct {
	listen      string
	upstreamURL string
	agent       string
	engine      *policy.Engine
	auditor     *audit.Auditor
	logger      *log.Logger
	client      *http.Client
	tripwire    bool
}

// New constructs a Proxy. The upstream client dials through forwardhttp's
// SSRF-guarded dialer so a forward can never be steered at an internal address,
// reusing the egress proxy's guard rather than reimplementing it. The client
// carries no overall timeout because SSE responses are long-lived; each request
// is bounded by the inbound request's context instead.
func New(listen, upstreamURL, agent string, engine *policy.Engine, auditor *audit.Auditor, logger *log.Logger) *Proxy {
	return &Proxy{
		listen:      listen,
		upstreamURL: upstreamURL,
		agent:       agent,
		engine:      engine,
		auditor:     auditor,
		logger:      logger,
		client: &http.Client{
			Transport: &http.Transport{
				Proxy:                 nil,
				DialContext:           forwardhttp.GuardedDial,
				ForceAttemptHTTP2:     true,
				MaxIdleConns:          100,
				IdleConnTimeout:       90 * time.Second,
				TLSHandshakeTimeout:   10 * time.Second,
				ExpectContinueTimeout: 1 * time.Second,
			},
		},
		tripwire: os.Getenv(EnvTripwire) != "",
	}
}

// Run serves until ctx is cancelled, then drains in-flight requests. It mirrors
// the egress proxy's shutdown handling.
func (p *Proxy) Run(ctx context.Context) error {
	if p.tripwire {
		p.logger.Printf("TRIPWIRE ENGAGED: %s is set — audit DISABLED; all MCP calls forward directly to %s without inspection. Unset it and restart to restore monitoring.", EnvTripwire, p.upstreamURL)
	}
	srv := &http.Server{
		Addr:              p.listen,
		Handler:           p,
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

// ServeHTTP terminates the MCP-over-HTTP transport. POST bodies are inspected
// for tools/call audit before forwarding; every other method (GET server-stream,
// DELETE session teardown) is forwarded transparently.
func (p *Proxy) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if r.Method == http.MethodPost {
		p.handlePost(w, r)
		return
	}
	p.forward(w, r, nil)
}

func (p *Proxy) handlePost(w http.ResponseWriter, r *http.Request) {
	body, err := io.ReadAll(http.MaxBytesReader(w, r.Body, maxBodyBytes))
	if err != nil {
		p.logger.Printf("READ-ERROR agent=%s: %v", p.agent, err)
		http.Error(w, "nockguard http-mcp: cannot read request body", http.StatusBadRequest)
		return
	}
	// Observe: audit every tools/call. Never blocks. The tripwire skips audit
	// entirely (still forwards) and was announced loudly at startup.
	if !p.tripwire {
		for _, m := range decodeMessages(body) {
			if m.Method == "tools/call" {
				p.observe(extractToolName(m.Params))
			}
		}
	}
	p.forward(w, r, body)
}

// observe evaluates policy for a tool call and records the decision. It NEVER
// blocks — a would-deny is logged and audited, then the call still forwards.
func (p *Proxy) observe(tool string) {
	dec := p.engine.Evaluate(p.agent, tool)
	decision := "allow"
	if dec.Verdict != policy.Allow {
		decision = "deny"
	}
	if p.auditor.Enabled() {
		if err := p.auditor.Record(audit.Event{
			Agent:    p.agent,
			Tool:     tool,
			Decision: decision,
			Reason:   dec.Reason,
		}); err != nil {
			p.logger.Printf("AUDIT-ERROR agent=%s tool=%s: %v", p.agent, tool, err)
		}
	}
	if decision == "deny" {
		p.logger.Printf("WARN WOULD-BLOCK (observe-only) agent=%s tool=%s reason=%q", p.agent, tool, dec.Reason)
	} else {
		p.logger.Printf("ALLOW (observe) agent=%s tool=%s reason=%q", p.agent, tool, dec.Reason)
	}
}

// forward relays r to the upstream and streams the response back. When body is
// non-nil it is the already-read POST body (re-sent to upstream); otherwise the
// live r.Body is streamed through. Response bytes are flushed per chunk so an
// SSE (text/event-stream) response is relayed live, not buffered.
func (p *Proxy) forward(w http.ResponseWriter, r *http.Request, body []byte) {
	var upstreamBody io.Reader
	switch {
	case body != nil:
		upstreamBody = bytes.NewReader(body)
	case r.Body != nil:
		upstreamBody = r.Body
	}

	req, err := http.NewRequestWithContext(r.Context(), r.Method, p.upstreamURL, upstreamBody)
	if err != nil {
		p.logger.Printf("REQUEST-ERROR agent=%s: %v", p.agent, err)
		http.Error(w, "nockguard http-mcp: cannot build upstream request", http.StatusInternalServerError)
		return
	}
	// Forward client headers unchanged (Authorization/bearer, Accept,
	// Content-Type, Mcp-Session-Id, …) minus hop-by-hop. The Host is taken from
	// the upstream URL, never the inbound Host, so the request authenticates to
	// the real endpoint.
	copyHeaders(req.Header, r.Header)

	resp, err := p.client.Do(req)
	if err != nil {
		p.logger.Printf("UPSTREAM-ERROR agent=%s: %v", p.agent, err)
		http.Error(w, "nockguard http-mcp: upstream unreachable: "+err.Error(), http.StatusBadGateway)
		return
	}
	defer resp.Body.Close()

	// Relay response headers (incl. Mcp-Session-Id) then stream the body.
	copyHeaders(w.Header(), resp.Header)
	w.WriteHeader(resp.StatusCode)
	streamFlush(w, resp.Body)
}

// streamFlush copies src to w, flushing after every chunk so a live SSE stream
// is not buffered by the proxy. A single-shot application/json response works
// under the same path (one chunk, one flush).
func streamFlush(w http.ResponseWriter, src io.Reader) {
	flusher, _ := w.(http.Flusher)
	buf := make([]byte, 32*1024)
	for {
		n, rerr := src.Read(buf)
		if n > 0 {
			if _, werr := w.Write(buf[:n]); werr != nil {
				return
			}
			if flusher != nil {
				flusher.Flush()
			}
		}
		if rerr != nil {
			return
		}
	}
}

// copyHeaders copies all headers from src to dst, skipping hop-by-hop headers.
func copyHeaders(dst, src http.Header) {
	for _, k := range hopByHopHeaders {
		src.Del(k)
	}
	for k, vs := range src {
		for _, v := range vs {
			dst.Add(k, v)
		}
	}
}

// decodeMessages parses an MCP Streamable-HTTP POST body into JSON-RPC messages.
// The body is either a single JSON-RPC object or a batch array. Undecodable
// input yields no messages (never an error): audit is best-effort and must
// never block or fail a forward.
func decodeMessages(body []byte) []*jsonrpc.Message {
	trimmed := bytes.TrimSpace(body)
	if len(trimmed) == 0 {
		return nil
	}
	if trimmed[0] == '[' {
		var arr []json.RawMessage
		if err := json.Unmarshal(trimmed, &arr); err != nil {
			return nil
		}
		out := make([]*jsonrpc.Message, 0, len(arr))
		for _, raw := range arr {
			if m, err := jsonrpc.Decode(raw); err == nil {
				out = append(out, m)
			}
		}
		return out
	}
	if m, err := jsonrpc.Decode(trimmed); err == nil {
		return []*jsonrpc.Message{m}
	}
	return nil
}

// extractToolName pulls the tool name out of a tools/call params object.
func extractToolName(params json.RawMessage) string {
	var obj struct {
		Name string `json:"name"`
	}
	if err := json.Unmarshal(params, &obj); err != nil {
		return ""
	}
	return obj.Name
}

// ValidateConfig checks the required wiring for the HTTP-MCP proxy.
func ValidateConfig(listen, upstreamURL, agent string, engine *policy.Engine) error {
	if listen == "" {
		return fmt.Errorf("--listen is required")
	}
	if agent == "" {
		return fmt.Errorf("--agent is required")
	}
	if engine == nil {
		return fmt.Errorf("policy engine is required")
	}
	if upstreamURL == "" {
		return fmt.Errorf("--upstream is required (the real MCP-over-HTTP endpoint URL)")
	}
	u, err := url.Parse(upstreamURL)
	if err != nil {
		return fmt.Errorf("--upstream is not a valid URL: %w", err)
	}
	if u.Scheme != "http" && u.Scheme != "https" {
		return fmt.Errorf("--upstream must be an http(s) URL for --http mode (got %q)", upstreamURL)
	}
	if u.Host == "" {
		return fmt.Errorf("--upstream URL has no host: %q", upstreamURL)
	}
	return nil
}
