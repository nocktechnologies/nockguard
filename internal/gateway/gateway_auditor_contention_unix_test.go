//go:build unix

package gateway

import (
	"bufio"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/nocktechnologies/nockguard/internal/audit"
	"github.com/nocktechnologies/nockguard/internal/policy"
	"github.com/nocktechnologies/nockguard/internal/proxy"
)

type initProgressWriter struct {
	http.ResponseWriter
	passed chan struct{}
	once   sync.Once
}

func (w *initProgressWriter) Write(p []byte) (int, error) {
	n, err := w.ResponseWriter.Write(p)
	if strings.Contains(string(p), ": audit-gate-ready\n\n") {
		w.once.Do(func() { close(w.passed) })
	}
	return n, err
}

func (w *initProgressWriter) Unwrap() http.ResponseWriter { return w.ResponseWriter }

func TestSSEInitializeCommitDoesNotWaitForSharedAuditor(t *testing.T) {
	c := testConfig(t)
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	auditPath := filepath.Join(t.TempDir(), "audit.jsonl")
	auditor, err := audit.New(auditPath, audit.WithEd25519Key(priv))
	if err != nil {
		t.Fatal(err)
	}
	defer auditor.Close()
	engine, err := policy.LoadBytes([]byte("agents:\n  mira:\n    mode: allow\n"))
	if err != nil {
		t.Fatal(err)
	}
	var initCount atomic.Int32
	initPassedAudit := make(chan struct{})
	sendInit := make(chan struct{})
	var sendInitOnce sync.Once
	releaseInit := func() { sendInitOnce.Do(func() { close(sendInit) }) }
	toolReached := make(chan struct{}, 1)
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var msg struct {
			Method string          `json:"method"`
			ID     json.RawMessage `json:"id"`
		}
		if err := json.NewDecoder(r.Body).Decode(&msg); err != nil {
			t.Errorf("decode upstream request: %v", err)
			return
		}
		if msg.Method == "initialize" {
			count := initCount.Add(1)
			w.Header().Set("Mcp-Session-Id", fmt.Sprintf("private-upstream-%d", count))
			if count == 1 {
				w.Header().Set("Content-Type", "application/json")
				fmt.Fprintf(w, `{"jsonrpc":"2.0","id":%s,"result":{}}`, msg.ID)
				return
			}
			w.Header().Set("Content-Type", "text/event-stream")
			w.WriteHeader(http.StatusOK)
			_, _ = fmt.Fprint(w, ": audit-gate-ready\n\n")
			w.(http.Flusher).Flush()
			select {
			case <-sendInit:
			case <-r.Context().Done():
				return
			}
			fmt.Fprintf(w, "data: {\"jsonrpc\":\"2.0\",\"id\":%s,\"result\":{}}\n\n", msg.ID)
			w.(http.Flusher).Flush()
			<-r.Context().Done()
			return
		}
		if r.Header.Get("Mcp-Session-Id") == "" {
			t.Errorf("follow-up %q lacked upstream session ID", msg.Method)
		}
		if msg.Method == "tools/call" {
			toolReached <- struct{}{}
		}
		w.Header().Set("Content-Type", "application/json")
		fmt.Fprintf(w, `{"jsonrpc":"2.0","id":%s,"result":{}}`, msg.ID)
	}))
	defer upstream.Close()
	logger := log.New(io.Discard, "", 0)
	g := newTestGateway(t, c, validAuth(t, c), func() http.Handler {
		gate := proxy.NewStdioProxy(nil, c.Agent, engine, nil, nil, auditor, nil, logger)
		listener := proxy.NewHTTPListener("", upstream.URL, gate, logger).
			WithUpstreamAgentToken("test-upstream-credential").WithRequiredAudit()
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			listener.ServeHTTP(&initProgressWriter{ResponseWriter: w, passed: initPassedAudit}, r)
		})
	})
	server := httptest.NewServer(g)
	defer server.Close()
	defer releaseInit()
	client := &http.Client{Timeout: 4 * time.Second}
	post := func(body, sid string) (*http.Response, error) {
		t.Helper()
		req, err := http.NewRequest(http.MethodPost, server.URL+"/mcp", strings.NewReader(body))
		if err != nil {
			return nil, err
		}
		req.Host = "guard.example"
		req.Header.Set("Authorization", "Bearer connector-test-token")
		if sid != "" {
			req.Header.Set("Mcp-Session-Id", sid)
		}
		return client.Do(req)
	}
	readLine := func(resp *http.Response) string {
		t.Helper()
		reader := bufio.NewReader(resp.Body)
		for {
			line, err := reader.ReadString('\n')
			if err != nil {
				t.Fatalf("read response event: %q: %v", line, err)
			}
			if strings.TrimSpace(line) == "" || strings.HasPrefix(line, ":") {
				continue
			}
			return line
		}
	}

	// Create a second session whose tools/call will stall in RecordRequired.
	blockedInit, err := post(initialize, "")
	if err != nil {
		t.Fatal(err)
	}
	blockedSID := blockedInit.Header.Get("Mcp-Session-Id")
	if blockedInit.StatusCode != http.StatusOK || blockedSID == "" {
		t.Fatalf("blocked session initialize returned %d with session ID %q", blockedInit.StatusCode, blockedSID)
	}
	_ = blockedInit.Body.Close()

	// Start an SSE initialize. Its upstream first sends a comment event, and the
	// wrapper signals after HTTPListener writes that event into initWriter. This
	// proves the response-header audit check has completed before contention.
	initResult := make(chan *http.Response, 1)
	initErr := make(chan error, 1)
	go func() {
		resp, err := post(initialize, "")
		if err != nil {
			initErr <- err
			return
		}
		initResult <- resp
	}()
	select {
	case <-initPassedAudit:
	case <-time.After(2 * time.Second):
		t.Fatal("SSE initialize did not pass the response audit check")
	}

	// A shared flock blocks signed RecordRequired calls through the real Auditor
	// API while allowing the initialize request, which has passed its response
	// audit check and is now waiting for the matching SSE result, to commit.
	lockFile, err := os.OpenFile(auditPath, os.O_RDONLY, 0)
	if err != nil {
		t.Fatal(err)
	}
	defer lockFile.Close()
	if err := audit.LockShared(lockFile.Fd()); err != nil {
		t.Fatal(err)
	}
	locked := true
	defer func() {
		if locked {
			_ = audit.UnlockFile(lockFile.Fd())
		}
	}()

	type toolOutcome struct {
		resp *http.Response
		err  error
	}
	toolDone := make(chan toolOutcome, 1)
	go func() {
		resp, err := post(`{"jsonrpc":"2.0","id":2,"method":"tools/call","params":{"name":"read_item","arguments":{}}}`, blockedSID)
		toolDone <- toolOutcome{resp: resp, err: err}
	}()
	deadline := time.Now().Add(2 * time.Second)
	for {
		g.mu.Lock()
		s := g.sessions[blockedSID]
		busy := s != nil && s.busy
		g.mu.Unlock()
		if busy {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("concurrent tool call did not acquire its session")
		}
		time.Sleep(time.Millisecond)
	}
	select {
	case <-toolReached:
		t.Fatal("tools/call reached upstream while signed audit append was locked")
	case out := <-toolDone:
		if out.resp != nil {
			_ = out.resp.Body.Close()
		}
		t.Fatalf("tools/call returned before signed audit append could proceed: %v", out.err)
	case <-time.After(100 * time.Millisecond):
	}

	releaseInit()
	var initResp *http.Response
	select {
	case err := <-initErr:
		t.Fatalf("SSE initialize failed while another session's audit append was blocked: %v", err)
	case initResp = <-initResult:
	case <-time.After(2 * time.Second):
		t.Fatal("SSE initialize result waited on the other session's blocked audit append")
	}
	defer initResp.Body.Close()
	if initResp.StatusCode != http.StatusOK || initResp.Header.Get("Mcp-Session-Id") == "" {
		t.Fatalf("SSE initialize returned %d with session ID %q", initResp.StatusCode, initResp.Header.Get("Mcp-Session-Id"))
	}
	line := readLine(initResp)
	if !strings.HasPrefix(line, "data: ") {
		t.Fatalf("unexpected SSE initialize event: %q", line)
	}
	var initEnvelope struct {
		JSONRPC string          `json:"jsonrpc"`
		ID      json.Number     `json:"id"`
		Result  json.RawMessage `json:"result"`
	}
	if err := json.Unmarshal([]byte(strings.TrimSpace(strings.TrimPrefix(line, "data:"))), &initEnvelope); err != nil {
		t.Fatalf("decode SSE initialize event: %v", err)
	}
	if initEnvelope.JSONRPC != "2.0" || initEnvelope.ID.String() != "1" || len(initEnvelope.Result) == 0 {
		t.Fatalf("initialize event was not a matching successful response: %+v", initEnvelope)
	}
	select {
	case <-toolReached:
		t.Fatal("tools/call reached upstream before the audit lock was released")
	default:
	}

	if err := audit.UnlockFile(lockFile.Fd()); err != nil {
		t.Fatal(err)
	}
	locked = false
	select {
	case out := <-toolDone:
		if out.err != nil {
			t.Fatalf("tools/call failed after audit lock release: %v", out.err)
		}
		defer out.resp.Body.Close()
		if out.resp.StatusCode != http.StatusOK {
			t.Fatalf("tools/call returned %d after audit lock release", out.resp.StatusCode)
		}
		var response struct {
			JSONRPC string          `json:"jsonrpc"`
			ID      json.Number     `json:"id"`
			Result  json.RawMessage `json:"result"`
		}
		if err := json.NewDecoder(out.resp.Body).Decode(&response); err != nil {
			t.Fatalf("decode tools/call response: %v", err)
		}
		if response.JSONRPC != "2.0" || response.ID.String() != "2" || len(response.Result) == 0 {
			t.Fatalf("tools/call response was not a matching success: %+v", response)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("tools/call did not resume after audit lock release")
	}

	// Required-auditor health checks legitimately wait until the shared append
	// lock is released, so verify session readiness after releasing that lock.
	initSID := initResp.Header.Get("Mcp-Session-Id")
	follow, err := post(`{"jsonrpc":"2.0","id":3,"method":"prompts/get","params":{"name":"demo"}}`, initSID)
	if err != nil {
		t.Fatalf("SSE-initialized session follow-up failed: %v", err)
	}
	defer follow.Body.Close()
	if follow.StatusCode != http.StatusOK {
		t.Fatalf("SSE-initialized session follow-up returned %d", follow.StatusCode)
	}
	n, err := audit.VerifyEd25519(auditPath, priv.Public().(ed25519.PublicKey))
	if err != nil {
		t.Fatalf("required audit trail did not verify: %v", err)
	}
	data, err := os.ReadFile(auditPath)
	if err != nil {
		t.Fatal(err)
	}
	var events []audit.Event
	for _, line := range strings.Split(strings.TrimSpace(string(data)), "\n") {
		if line == "" {
			continue
		}
		var event audit.Event
		if err := json.Unmarshal([]byte(line), &event); err != nil {
			t.Fatalf("decode audit event: %v", err)
		}
		events = append(events, event)
	}
	if n != 2 || len(events) != 2 || events[0].Decision != "dispatch" || events[1].Decision != "allow" {
		t.Fatalf("verified audit entries = %d, events = %+v; want dispatch then allow", n, events)
	}
}
