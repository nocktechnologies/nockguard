// Package mcphttp implements an MCP stdio↔HTTP bridge that intercepts
// tools/call events for per-call audit without blocking (observe-only).
//
// Claude Code launches this as a stdio MCP server (via .mcp.json command entry);
// the proxy forwards each JSON-RPC request to an HTTP MCP upstream and writes
// responses back to stdout. The audit path adapts the existing Ed25519-signing
// Auditor from the stdio proxy — the design doc at docs/http-mcp-interception.md
// has the full rationale.
//
// Tripwire: set NOCKGUARD_TRIPWIRE=1 to disable auditing and forward directly.
// The tripwire is LOUD: it logs on every startup so there is no silent bypass.
package mcphttp

import (
	"bufio"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/nocktechnologies/nockguard/internal/audit"
	"github.com/nocktechnologies/nockguard/internal/jsonrpc"
)

// EnvTripwire is the environment variable that disables the proxy's audit and
// falls back to direct forwarding. Set to any non-empty value to engage.
const EnvTripwire = "NOCKGUARD_TRIPWIRE"

// scannerBufInit / scannerBufMax set a generous scanner buffer shared by both
// the stdin reader and the SSE response reader. MCP tool results (e.g. a long
// nock_list or identity doc) routinely exceed bufio's default 64 KB token limit;
// without this, sc.Scan() stops early with bufio.ErrTooLong and the response is
// silently dropped rather than forwarded.
const (
	scannerBufInit = 1 * 1024 * 1024  // 1 MB initial buffer
	scannerBufMax  = 10 * 1024 * 1024 // 10 MB max token size
)

// Proxy bridges stdio MCP (client-facing) to HTTP MCP (upstream). Observe-only:
// every tools/call is audited and forwarded; the proxy never blocks a call.
// Tripwire: when NOCKGUARD_TRIPWIRE is set, auditing is skipped but calls still
// forward — the operator is told loudly via logs that the guard is disabled.
type Proxy struct {
	upstreamURL string
	agent       string
	authHeader  string // e.g. "Bearer <token>"; sent as Authorization on every upstream request
	auditor     *audit.Auditor
	logger      *log.Logger

	client *http.Client

	// sessionID tracks the Mcp-Session-Id returned by the upstream on the
	// initialize response and included in all subsequent requests per the MCP
	// Streamable HTTP spec.
	mu        sync.Mutex
	sessionID string
}

// New constructs a Proxy. authHeader is the literal Authorization header value
// (e.g. "Bearer TOKEN") to forward to the upstream; pass "" to omit it.
// The auditor may be nil or disabled (audit.New("")) to disable audit writes.
func New(upstreamURL, agent, authHeader string, auditor *audit.Auditor, logger *log.Logger) *Proxy {
	return &Proxy{
		upstreamURL: upstreamURL,
		agent:       agent,
		authHeader:  authHeader,
		auditor:     auditor,
		logger:      logger,
		// ponytail: plain http.Client; upstream URL is operator-configured at
		// startup, not request-derived, so SSRF risk is low here vs. the egress
		// proxy case. Add forwardhttp.GuardedDial if upstream becomes user-controllable.
		client: &http.Client{Timeout: 60 * time.Second},
	}
}

// Run bridges os.Stdin → upstream → os.Stdout until the context is cancelled or
// stdin closes.
func (p *Proxy) Run(ctx context.Context) error {
	return p.run(ctx, os.Stdin, os.Stdout)
}

func (p *Proxy) run(ctx context.Context, in io.Reader, out io.Writer) error {
	tripwire := os.Getenv(EnvTripwire) != ""
	if tripwire {
		p.logger.Printf("TRIPWIRE ENGAGED: NOCKGUARD_TRIPWIRE is set — audit disabled; all MCP calls forwarding directly to %s without inspection. Revert .mcp.json to the direct HTTP connector to restore monitoring.", p.upstreamURL)
	}

	scanner := bufio.NewScanner(in)
	scanner.Buffer(make([]byte, 0, scannerBufInit), scannerBufMax)
	for scanner.Scan() {
		if ctx.Err() != nil {
			return ctx.Err()
		}
		if err := p.handleLine(ctx, scanner.Bytes(), out, tripwire); err != nil {
			return err
		}
	}
	return scanner.Err()
}

func (p *Proxy) handleLine(ctx context.Context, line []byte, out io.Writer, tripwire bool) error {
	msg, err := jsonrpc.Decode(line)
	if err != nil {
		// Not valid JSON-RPC — skip rather than block; log so the operator can see it.
		p.logger.Printf("WARN agent=%s: undecodable line, skipping: %v", p.agent, err)
		return nil
	}

	// Audit tools/call in observe mode (never deny; tripwire skips audit entirely).
	if msg.Method == "tools/call" && !tripwire {
		toolName := extractToolName(msg.Params)
		if err := p.record(toolName); err != nil {
			p.logger.Printf("AUDIT-ERROR agent=%s tool=%s: %v", p.agent, toolName, err)
		}
	}

	// Forward to upstream unconditionally.
	resp, err := p.post(ctx, line)
	if err != nil {
		p.logger.Printf("UPSTREAM-ERROR agent=%s: %v", p.agent, err)
		// Return a JSON-RPC error to the client on request failures so the
		// caller knows why — but don't crash the proxy stream.
		if msg.IsRequest() {
			errLine := jsonrpc.ErrorResponse(msg.ID, -32603, "nockguard mcp-http: upstream unreachable: "+err.Error())
			_, _ = fmt.Fprintf(out, "%s\n", errLine)
		}
		return nil
	}
	defer resp.Body.Close()

	// Capture session ID from the initialize response; subsequent requests will
	// include it to maintain the upstream session.
	if sid := resp.Header.Get("Mcp-Session-Id"); sid != "" {
		p.mu.Lock()
		p.sessionID = sid
		p.mu.Unlock()
	}

	return p.writeResponse(resp, out)
}

func (p *Proxy) post(ctx context.Context, body []byte) (*http.Response, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, p.upstreamURL, strings.NewReader(string(body)))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json, text/event-stream")
	if p.authHeader != "" {
		req.Header.Set("Authorization", p.authHeader)
	}
	p.mu.Lock()
	sid := p.sessionID
	p.mu.Unlock()
	if sid != "" {
		req.Header.Set("Mcp-Session-Id", sid)
	}
	return p.client.Do(req)
}

// writeResponse dispatches on Content-Type: application/json responses are
// written as a single newline-terminated line; text/event-stream responses are
// parsed as SSE and each data: payload is written as one line.
func (p *Proxy) writeResponse(resp *http.Response, out io.Writer) error {
	if strings.HasPrefix(resp.Header.Get("Content-Type"), "text/event-stream") {
		return p.writeSSEResponse(resp.Body, out)
	}
	// application/json (or anything else): read and forward as one line.
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return err
	}
	body = trimTrailingNewlines(body)
	if len(body) == 0 {
		return nil
	}
	_, err = fmt.Fprintf(out, "%s\n", body)
	return err
}

// writeSSEResponse parses an SSE stream and writes each data: payload as one
// JSON-RPC line to out. SSE format: "data: <json>\n\n" per event.
func (p *Proxy) writeSSEResponse(r io.Reader, out io.Writer) error {
	sc := bufio.NewScanner(r)
	sc.Buffer(make([]byte, 0, scannerBufInit), scannerBufMax)
	for sc.Scan() {
		line := sc.Text()
		if !strings.HasPrefix(line, "data: ") {
			continue
		}
		data := strings.TrimPrefix(line, "data: ")
		if data == "" || data == "[DONE]" {
			continue
		}
		if _, err := fmt.Fprintf(out, "%s\n", data); err != nil {
			return err
		}
	}
	return sc.Err()
}

func (p *Proxy) record(tool string) error {
	if !p.auditor.Enabled() {
		return nil
	}
	return p.auditor.Record(audit.Event{
		Agent:    p.agent,
		Tool:     tool,
		Decision: "observe",
		Reason:   "mcp-http-intercept",
	})
}

func extractToolName(params json.RawMessage) string {
	var obj struct {
		Name string `json:"name"`
	}
	if err := json.Unmarshal(params, &obj); err != nil {
		return ""
	}
	return obj.Name
}

func trimTrailingNewlines(b []byte) []byte {
	for len(b) > 0 && (b[len(b)-1] == '\n' || b[len(b)-1] == '\r') {
		b = b[:len(b)-1]
	}
	return b
}
