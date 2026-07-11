package mcphttp

import (
	"bytes"
	"context"
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

	"github.com/nocktechnologies/nockguard/internal/audit"
)

// TestMCPHTTPProxy_ToolCallReachesUpstream checks that a tools/call request
// sent over stdin reaches the stub HTTP upstream and the response lands on
// stdout — the core forwarding contract.
func TestMCPHTTPProxy_ToolCallReachesUpstream(t *testing.T) {
	called := false
	var gotBody []byte
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		called = true
		gotBody, _ = io.ReadAll(r.Body)
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"jsonrpc":"2.0","id":1,"result":{"content":[{"type":"text","text":"ok"}]}}`))
	}))
	defer srv.Close()

	p := newTestProxy(t, srv.URL, nil)
	in := strings.NewReader(`{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"nockcc_nock_list"}}` + "\n")
	var out bytes.Buffer
	if err := p.run(context.Background(), in, &out); err != nil {
		t.Fatalf("run: %v", err)
	}

	if !called {
		t.Fatal("upstream was not called")
	}
	if !strings.Contains(string(gotBody), "tools/call") {
		t.Errorf("upstream body did not contain tools/call: %s", gotBody)
	}
	if !strings.Contains(out.String(), "content") {
		t.Errorf("response not written to stdout: %s", out.String())
	}
}

// TestMCPHTTPProxy_AuditEntrySignedChain verifies that a tools/call through the
// proxy produces a signed Ed25519 audit entry with a verifying chain — the core
// accountability contract.
func TestMCPHTTPProxy_AuditEntrySignedChain(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"jsonrpc":"2.0","id":1,"result":{"content":[{"type":"text","text":"ok"}]}}`))
	}))
	defer srv.Close()

	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	auditPath := filepath.Join(dir, "mira.audit.jsonl")
	auditor, err := audit.New(auditPath, audit.WithEd25519Key(priv))
	if err != nil {
		t.Fatal(err)
	}

	p := newTestProxy(t, srv.URL, auditor)
	in := strings.NewReader(`{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"nockcc_nock_list"}}` + "\n")
	var out bytes.Buffer
	if err := p.run(context.Background(), in, &out); err != nil {
		t.Fatalf("run: %v", err)
	}
	if err := auditor.Close(); err != nil {
		t.Fatal(err)
	}

	// Chain must verify with the public key.
	n, err := audit.VerifyEd25519(auditPath, pub)
	if err != nil {
		t.Fatalf("chain verification failed: %v", err)
	}
	if n != 1 {
		t.Errorf("expected 1 audit entry, got %d", n)
	}

	// Check the entry content.
	data, _ := os.ReadFile(auditPath)
	var entry audit.Event
	if err := json.Unmarshal(bytes.TrimRight(data, "\n"), &entry); err != nil {
		t.Fatalf("parse audit entry: %v", err)
	}
	if entry.Tool != "nockcc_nock_list" {
		t.Errorf("expected tool=nockcc_nock_list, got %q", entry.Tool)
	}
	if entry.Decision != "observe" {
		t.Errorf("expected decision=observe (proxy never blocks), got %q", entry.Decision)
	}
	if entry.Agent != "mira" {
		t.Errorf("expected agent=mira, got %q", entry.Agent)
	}
}

// TestMCPHTTPProxy_ObserveOnly verifies that the proxy forwards ALL tools/call
// requests to the upstream and never blocks any, regardless of tool name.
func TestMCPHTTPProxy_ObserveOnly(t *testing.T) {
	callCount := 0
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		callCount++
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"jsonrpc":"2.0","id":1,"result":{"content":[{"type":"text","text":"ok"}]}}`))
	}))
	defer srv.Close()

	p := newTestProxy(t, srv.URL, nil)
	in := strings.NewReader(
		`{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"tool_a"}}` + "\n" +
			`{"jsonrpc":"2.0","id":2,"method":"tools/call","params":{"name":"tool_b"}}` + "\n" +
			`{"jsonrpc":"2.0","id":3,"method":"tools/call","params":{"name":"tool_c"}}` + "\n",
	)
	var out bytes.Buffer
	if err := p.run(context.Background(), in, &out); err != nil {
		t.Fatalf("run: %v", err)
	}
	if callCount != 3 {
		t.Errorf("expected 3 upstream calls (observe-only, never blocks), got %d", callCount)
	}
}

// TestMCPHTTPProxy_Tripwire verifies that NOCKGUARD_TRIPWIRE=1 disables audit
// writes while still forwarding calls to the upstream (never silently dead).
func TestMCPHTTPProxy_Tripwire(t *testing.T) {
	callCount := 0
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		callCount++
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"jsonrpc":"2.0","id":1,"result":{"content":[{"type":"text","text":"ok"}]}}`))
	}))
	defer srv.Close()

	_, priv, _ := ed25519.GenerateKey(rand.Reader)
	dir := t.TempDir()
	auditPath := filepath.Join(dir, "mira.audit.jsonl")
	auditor, err := audit.New(auditPath, audit.WithEd25519Key(priv))
	if err != nil {
		t.Fatal(err)
	}
	defer auditor.Close()

	t.Setenv(EnvTripwire, "1")

	p := newTestProxy(t, srv.URL, auditor)
	in := strings.NewReader(`{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"nockcc_nock_list"}}` + "\n")
	var out bytes.Buffer
	if err := p.run(context.Background(), in, &out); err != nil {
		t.Fatalf("run: %v", err)
	}

	// Tripwire still forwards (direct pass-through, not a dead-end).
	if callCount != 1 {
		t.Errorf("expected upstream to be called with tripwire active, got %d calls", callCount)
	}

	// Audit file must be absent or empty — tripwire disables audit writes.
	if err := auditor.Close(); err != nil {
		t.Fatal(err)
	}
	if data, _ := os.ReadFile(auditPath); len(bytes.TrimSpace(data)) != 0 {
		t.Errorf("tripwire should produce no audit entries; got:\n%s", data)
	}
}

// TestMCPHTTPProxy_SSEResponse verifies that SSE-formatted upstream responses
// are correctly parsed and written as newline-delimited JSON-RPC lines.
func TestMCPHTTPProxy_SSEResponse(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/event-stream")
		_, _ = io.WriteString(w, "event: message\n")
		_, _ = io.WriteString(w, `data: {"jsonrpc":"2.0","id":1,"result":{"content":[{"type":"text","text":"sse-ok"}]}}`+"\n")
		_, _ = io.WriteString(w, "\n")
	}))
	defer srv.Close()

	p := newTestProxy(t, srv.URL, nil)
	in := strings.NewReader(`{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"nockcc_nock_list"}}` + "\n")
	var out bytes.Buffer
	if err := p.run(context.Background(), in, &out); err != nil {
		t.Fatalf("run: %v", err)
	}
	if !strings.Contains(out.String(), "sse-ok") {
		t.Errorf("SSE response not forwarded to stdout: %s", out.String())
	}
}

// TestMCPHTTPProxy_SessionID verifies that the Mcp-Session-Id header returned
// by the upstream on initialize is captured and sent on subsequent requests.
func TestMCPHTTPProxy_SessionID(t *testing.T) {
	const wantSID = "test-session-abc"
	var gotSID string
	requestNum := 0
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requestNum++
		if requestNum == 1 {
			// initialize response — emit session ID
			w.Header().Set("Mcp-Session-Id", wantSID)
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte(`{"jsonrpc":"2.0","id":1,"result":{"protocolVersion":"2024-11-05","capabilities":{}}}`))
			return
		}
		// second request — check the client sent the session header
		gotSID = r.Header.Get("Mcp-Session-Id")
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"jsonrpc":"2.0","id":2,"result":{"content":[]}}`))
	}))
	defer srv.Close()

	p := newTestProxy(t, srv.URL, nil)
	in := strings.NewReader(
		`{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2024-11-05"}}` + "\n" +
			`{"jsonrpc":"2.0","id":2,"method":"tools/list","params":{}}` + "\n",
	)
	var out bytes.Buffer
	if err := p.run(context.Background(), in, &out); err != nil {
		t.Fatalf("run: %v", err)
	}
	if gotSID != wantSID {
		t.Errorf("expected Mcp-Session-Id=%q on second request, got %q", wantSID, gotSID)
	}
}

func newTestProxy(t *testing.T, upstreamURL string, auditor *audit.Auditor) *Proxy {
	t.Helper()
	if auditor == nil {
		a, err := audit.New("")
		if err != nil {
			t.Fatal(err)
		}
		auditor = a
	}
	return New(upstreamURL, "mira", "", auditor, log.New(io.Discard, "", 0))
}
