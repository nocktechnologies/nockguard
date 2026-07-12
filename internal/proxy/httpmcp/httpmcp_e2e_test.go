package httpmcp

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
	"time"

	"github.com/nocktechnologies/nockguard/internal/audit"
	"github.com/nocktechnologies/nockguard/internal/policy"
)

// newTestProxy builds a Proxy pointed at upstreamURL. It overrides the guarded
// client with a plain one so the loopback httptest upstream (which the SSRF
// guard would otherwise block) is reachable in-test. Production wiring keeps the
// guarded dialer from New().
func newTestProxy(t *testing.T, upstreamURL, agent string, engine *policy.Engine, auditor *audit.Auditor) *Proxy {
	t.Helper()
	logger := log.New(io.Discard, "", 0)
	p := New("127.0.0.1:0", upstreamURL, agent, engine, auditor, logger)
	p.client = &http.Client{} // plain client: reach the loopback stub upstream
	return p
}

// loadEngine writes a policy file and loads an engine from it.
func loadEngine(t *testing.T, content string) *policy.Engine {
	t.Helper()
	dir := t.TempDir()
	path := filepath.Join(dir, "policy.yaml")
	if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}
	engine, err := policy.Load(path)
	if err != nil {
		t.Fatalf("load policy: %v", err)
	}
	return engine
}

const allowAllPolicy = "agents:\n  mira:\n    allow: [\"*\"]\n"

// TestHTTPMCP_ForwardsUpstream asserts a POSTed tools/call reaches the stub
// upstream (body preserved, Authorization passed through) and the upstream's
// response — including the Mcp-Session-Id header — is streamed back to the
// client unchanged.
func TestHTTPMCP_ForwardsUpstream(t *testing.T) {
	var gotBody []byte
	var gotAuth string
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotBody, _ = io.ReadAll(r.Body)
		gotAuth = r.Header.Get("Authorization")
		w.Header().Set("Content-Type", "application/json")
		w.Header().Set("Mcp-Session-Id", "sess-123")
		_, _ = w.Write([]byte(`{"jsonrpc":"2.0","id":1,"result":{"content":[{"type":"text","text":"ok"}]}}`))
	}))
	defer upstream.Close()

	engine := loadEngine(t, allowAllPolicy)
	p := newTestProxy(t, upstream.URL, "mira", engine, nil)
	front := httptest.NewServer(p)
	defer front.Close()

	call := `{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"nockcc_nock_list"}}`
	req, _ := http.NewRequest(http.MethodPost, front.URL+"/mcp", strings.NewReader(call))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer seat-token-xyz")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("POST: %v", err)
	}
	defer resp.Body.Close()
	respBody, _ := io.ReadAll(resp.Body)

	if !strings.Contains(string(gotBody), "tools/call") {
		t.Errorf("upstream did not receive the tools/call body: %s", gotBody)
	}
	if gotAuth != "Bearer seat-token-xyz" {
		t.Errorf("Authorization not passed through unchanged: got %q", gotAuth)
	}
	if !strings.Contains(string(respBody), "content") {
		t.Errorf("upstream response not streamed back: %s", respBody)
	}
	if got := resp.Header.Get("Mcp-Session-Id"); got != "sess-123" {
		t.Errorf("Mcp-Session-Id not relayed: got %q", got)
	}
}

// TestHTTPMCP_AuditSignedChain asserts a tools/call through the proxy produces a
// signed Ed25519 audit entry whose chain verifies with the public key alone.
func TestHTTPMCP_AuditSignedChain(t *testing.T) {
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"jsonrpc":"2.0","id":1,"result":{}}`))
	}))
	defer upstream.Close()

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

	engine := loadEngine(t, allowAllPolicy)
	p := newTestProxy(t, upstream.URL, "mira", engine, auditor)
	front := httptest.NewServer(p)
	defer front.Close()

	call := `{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"nockcc_nock_list"}}`
	resp, err := http.Post(front.URL+"/mcp", "application/json", strings.NewReader(call))
	if err != nil {
		t.Fatalf("POST: %v", err)
	}
	_, _ = io.Copy(io.Discard, resp.Body)
	resp.Body.Close()
	if err := auditor.Close(); err != nil {
		t.Fatal(err)
	}

	n, err := audit.VerifyEd25519(auditPath, pub)
	if err != nil {
		t.Fatalf("chain verification failed: %v", err)
	}
	if n != 1 {
		t.Fatalf("expected 1 audit entry, got %d", n)
	}

	data, _ := os.ReadFile(auditPath)
	var entry audit.Event
	if err := json.Unmarshal(bytes.TrimRight(data, "\n"), &entry); err != nil {
		t.Fatalf("parse audit entry: %v", err)
	}
	if entry.Tool != "nockcc_nock_list" {
		t.Errorf("expected tool=nockcc_nock_list, got %q", entry.Tool)
	}
	if entry.Agent != "mira" {
		t.Errorf("expected agent=mira, got %q", entry.Agent)
	}
	if entry.Sig == "" {
		t.Error("audit entry is not signed")
	}
}

// TestHTTPMCP_ObserveNeverBlocks asserts that even a tool the policy DENIES is
// still forwarded upstream (observe-only) and the deny is recorded, never
// enforced.
func TestHTTPMCP_ObserveNeverBlocks(t *testing.T) {
	called := 0
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		called++
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"jsonrpc":"2.0","id":1,"result":{}}`))
	}))
	defer upstream.Close()

	// Policy allows only reads; the write tool is denied — but observe mode must
	// still forward it.
	deniedPolicy := "agents:\n  mira:\n    allow: [\"nockcc_nock_list\"]\n    deny: [\"nockcc_kill_switch_set\"]\n"
	engine := loadEngine(t, deniedPolicy)

	pub, priv, _ := ed25519.GenerateKey(rand.Reader)
	dir := t.TempDir()
	auditPath := filepath.Join(dir, "mira.audit.jsonl")
	auditor, err := audit.New(auditPath, audit.WithEd25519Key(priv))
	if err != nil {
		t.Fatal(err)
	}

	p := newTestProxy(t, upstream.URL, "mira", engine, auditor)
	front := httptest.NewServer(p)
	defer front.Close()

	call := `{"jsonrpc":"2.0","id":9,"method":"tools/call","params":{"name":"nockcc_kill_switch_set"}}`
	resp, err := http.Post(front.URL+"/mcp", "application/json", strings.NewReader(call))
	if err != nil {
		t.Fatalf("POST: %v", err)
	}
	body, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	auditor.Close()

	if resp.StatusCode != http.StatusOK {
		t.Errorf("observe mode must not block: got status %d", resp.StatusCode)
	}
	if called != 1 {
		t.Errorf("denied tool must still forward upstream (observe-only): upstream called %d times", called)
	}
	if !strings.Contains(string(body), "result") {
		t.Errorf("upstream response not returned: %s", body)
	}

	// The deny decision must be recorded (accountability), just not enforced.
	if _, verr := audit.VerifyEd25519(auditPath, pub); verr != nil {
		t.Fatalf("audit chain verify: %v", verr)
	}
	data, _ := os.ReadFile(auditPath)
	var entry audit.Event
	_ = json.Unmarshal(bytes.TrimRight(data, "\n"), &entry)
	if entry.Decision != "deny" {
		t.Errorf("expected recorded decision=deny (would-block), got %q", entry.Decision)
	}
}

// TestHTTPMCP_SSEStreamedBack asserts that a text/event-stream upstream response
// is relayed back to the client with its content-type preserved (the SSE
// streaming path), not buffered into a single JSON blob.
func TestHTTPMCP_SSEStreamedBack(t *testing.T) {
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/event-stream")
		w.WriteHeader(http.StatusOK)
		fl, _ := w.(http.Flusher)
		for _, chunk := range []string{
			"event: message\ndata: {\"jsonrpc\":\"2.0\",\"id\":1,\"result\":{\"step\":1}}\n\n",
			"event: message\ndata: {\"jsonrpc\":\"2.0\",\"id\":1,\"result\":{\"step\":2}}\n\n",
		} {
			_, _ = io.WriteString(w, chunk)
			if fl != nil {
				fl.Flush()
			}
		}
	}))
	defer upstream.Close()

	engine := loadEngine(t, allowAllPolicy)
	p := newTestProxy(t, upstream.URL, "mira", engine, nil)
	front := httptest.NewServer(p)
	defer front.Close()

	call := `{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"nockcc_nock_list"}}`
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	req, _ := http.NewRequestWithContext(ctx, http.MethodPost, front.URL+"/mcp", strings.NewReader(call))
	req.Header.Set("Accept", "text/event-stream")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("POST: %v", err)
	}
	defer resp.Body.Close()

	if ct := resp.Header.Get("Content-Type"); !strings.HasPrefix(ct, "text/event-stream") {
		t.Errorf("SSE content-type not relayed: got %q", ct)
	}
	body, _ := io.ReadAll(resp.Body)
	if !strings.Contains(string(body), "step\":1") || !strings.Contains(string(body), "step\":2") {
		t.Errorf("SSE events not streamed back intact: %s", body)
	}
}
