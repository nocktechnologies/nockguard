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
	"github.com/nocktechnologies/nockguard/internal/ratelimit"
)

func TestSSEFlushAndRotatedToken(t *testing.T) {
	c := testConfig(t)
	finished := make(chan struct{})
	var once sync.Once
	defer once.Do(func() { close(finished) })
	g := newTestGateway(t, c, validAuth(t, c), func() http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if r.Header.Get("Mcp-Session-Id") == "" {
				w.Header().Set("Mcp-Session-Id", "private")
				fmt.Fprint(w, `{"jsonrpc":"2.0","id":1,"result":{}}`)
				return
			}
			if r.Header.Get("Authorization") != "" {
				t.Error("rotated token passed to handler")
			}
			w.Header().Set("Content-Type", "text/event-stream")
			fmt.Fprint(w, "data: {\"jsonrpc\":\"2.0\",\"id\":2,\"result\":{}}\n\n")
			w.(http.Flusher).Flush()
			select {
			case <-finished:
			case <-r.Context().Done():
			}
		})
	})
	w := request(g, initialize, "", nil)
	sid := w.Header().Get("Mcp-Session-Id")
	server := httptest.NewServer(g)
	defer server.Close()
	r, err := http.NewRequest("POST", server.URL+"/mcp", strings.NewReader(list))
	if err != nil {
		t.Fatal(err)
	}
	r.Host = "guard.example"
	r.Header.Set("Authorization", "Bearer rotated-connector-token")
	r.Header.Set("Mcp-Session-Id", sid)
	client := &http.Client{Timeout: 2 * time.Second}
	resp, err := client.Do(r)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	line, err := bufio.NewReader(resp.Body).ReadString('\n')
	if err != nil || !strings.HasPrefix(line, "data: ") || resp.Header.Get("Mcp-Session-Id") != sid {
		t.Fatalf("SSE did not flush: %s %v", line, err)
	}
	once.Do(func() { close(finished) })
}

const initialize = `{"jsonrpc":"2.0","id":1,"method":"initialize","params":{}}`
const list = `{"jsonrpc":"2.0","id":2,"method":"tools/list"}`

func testConfig(t *testing.T) Config {
	t.Helper()
	t.Setenv("GUARD_TEST_INTROSPECTION", "test-introspection-credential")
	t.Setenv("GUARD_TEST_UPSTREAM", "test-upstream-credential")
	return Config{Listen: "127.0.0.1:0", Resource: "https://guard.example/mcp", Issuer: "https://issuer.example", IntrospectionURL: "https://issuer.example/introspect", IntrospectionAuthHeader: "Authorization", IntrospectionTokenEnv: "GUARD_TEST_INTROSPECTION", Subject: "operator-1", ClientID: "claude-connector", Scope: "mcp", Agent: "mira", Policy: "policy.yaml", Upstream: "https://upstream.example/mcp", UpstreamTokenEnv: "GUARD_TEST_UPSTREAM"}
}

func validClaims(c Config) map[string]interface{} {
	return map[string]interface{}{"active": true, "iss": c.Issuer, "sub": c.Subject, "client_id": c.ClientID, "aud": c.Resource, "scope": c.Scope, "exp": time.Now().Add(time.Hour).Unix(), "token_type": "Bearer"}
}

func newTestGateway(t *testing.T, c Config, auth http.HandlerFunc, factory func() http.Handler) *Gateway {
	t.Helper()
	server := httptest.NewTLSServer(auth)
	t.Cleanup(server.Close)
	c.IntrospectionURL = server.URL
	g, err := New(c, factory)
	if err != nil {
		t.Fatal(err)
	}
	g.authClient.Transport = server.Client().Transport
	return g
}

func validAuth(t *testing.T, c Config) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if r.Method != "POST" || r.Header.Get("Authorization") != "Bearer test-introspection-credential" || r.FormValue("token_type_hint") != "access_token" || r.FormValue("token") == "" {
			t.Error("incorrect authenticated introspection request")
		}
		_ = json.NewEncoder(w).Encode(validClaims(c))
	}
}

func request(g *Gateway, body, sid string, tweak func(*http.Request)) *httptest.ResponseRecorder {
	r := httptest.NewRequest("POST", "https://guard.example/mcp", strings.NewReader(body))
	r.Header.Set("Authorization", "Bearer connector-test-token")
	if sid != "" {
		r.Header.Set("Mcp-Session-Id", sid)
	}
	if tweak != nil {
		tweak(r)
	}
	w := httptest.NewRecorder()
	g.ServeHTTP(w, r)
	return w
}

func TestAuthenticationFailsClosed(t *testing.T) {
	c := testConfig(t)
	cases := map[string]func(map[string]interface{}){
		"inactive":         func(m map[string]interface{}) { m["active"] = false },
		"expired":          func(m map[string]interface{}) { m["exp"] = time.Now().Unix() - 1 },
		"missing expiry":   func(m map[string]interface{}) { delete(m, "exp") },
		"wrong audience":   func(m map[string]interface{}) { m["aud"] = "nockcc-mcp" },
		"missing audience": func(m map[string]interface{}) { delete(m, "aud") },
		"wrong scope":      func(m map[string]interface{}) { m["scope"] = "mcp-admin" },
		"wrong issuer":     func(m map[string]interface{}) { m["iss"] = "https://other.example" },
		"wrong subject":    func(m map[string]interface{}) { m["sub"] = "another-agent" },
		"wrong client":     func(m map[string]interface{}) { m["client_id"] = "other-client" },
		"future nbf":       func(m map[string]interface{}) { m["nbf"] = time.Now().Unix() + 60 },
		"refresh token":    func(m map[string]interface{}) { m["token_type"] = "refresh_token" },
		"malformed expiry": func(m map[string]interface{}) { m["exp"] = "forever" },
	}
	for name, mutate := range cases {
		t.Run(name, func(t *testing.T) {
			g := newTestGateway(t, c, func(w http.ResponseWriter, r *http.Request) {
				m := validClaims(c)
				mutate(m)
				_ = json.NewEncoder(w).Encode(m)
			}, func() http.Handler { t.Fatal("unauthorized request reached gate"); return nil })
			w := request(g, initialize, "", nil)
			if w.Code != 401 || !strings.Contains(w.Header().Get("WWW-Authenticate"), "resource_metadata=") {
				t.Fatalf("status %d headers %v", w.Code, w.Header())
			}
		})
	}
	for _, name := range []string{"bad json", "server error", "redirect", "oversized", "timeout"} {
		t.Run(name, func(t *testing.T) {
			var redirected atomic.Bool
			g := newTestGateway(t, c, func(w http.ResponseWriter, r *http.Request) {
				switch name {
				case "bad json":
					fmt.Fprint(w, `{"active":true} trailing`)
				case "server error":
					http.Error(w, "secret error details", 500)
				case "redirect":
					if r.URL.Path == "/elsewhere" {
						redirected.Store(true)
					}
					http.Redirect(w, r, "/elsewhere", 307)
				case "oversized":
					fmt.Fprint(w, strings.Repeat(" ", 64*1024+1))
				case "timeout":
					_, _ = io.Copy(io.Discard, r.Body)
					select {
					case <-r.Context().Done():
					case <-time.After(time.Second):
					}
				}
			}, func() http.Handler { t.Fatal("failed auth reached gate"); return nil })
			if name == "timeout" {
				g.authClient.Timeout = 30 * time.Millisecond
			}
			w := request(g, initialize, "", nil)
			if w.Code != 401 || redirected.Load() || strings.Contains(w.Body.String(), "secret") {
				t.Fatalf("unsafe auth failure: %d %s", w.Code, w.Body.String())
			}
		})
	}
}

func TestRequestBoundaryAndDiscovery(t *testing.T) {
	c := testConfig(t)
	var authCalls atomic.Int32
	g := newTestGateway(t, c, func(w http.ResponseWriter, r *http.Request) { authCalls.Add(1); validAuth(t, c)(w, r) }, func() http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { fmt.Fprint(w, `{"jsonrpc":"2.0","id":1,"result":{}}`) })
	})
	for _, tc := range []struct {
		name   string
		status int
		tweak  func(*http.Request)
	}{
		{"missing bearer", 401, func(r *http.Request) { r.Header.Del("Authorization") }},
		{"duplicate bearer", 401, func(r *http.Request) { r.Header.Add("Authorization", "Bearer other") }},
		{"spoof host", 421, func(r *http.Request) { r.Host = "evil.example"; r.Header.Set("X-Forwarded-Host", "guard.example") }},
		{"origin", 403, func(r *http.Request) { r.Header.Set("Origin", "https://evil.example") }},
		{"query credentials", 404, func(r *http.Request) { r.URL.RawQuery = "access_token=test" }},
		{"get", 405, func(r *http.Request) { r.Method = "GET" }},
		{"delete", 405, func(r *http.Request) { r.Method = "DELETE" }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			w := request(g, initialize, "", tc.tweak)
			if w.Code != tc.status {
				t.Fatalf("status %d", w.Code)
			}
		})
	}
	if authCalls.Load() != 0 {
		t.Fatal("invalid transport inputs contacted introspection")
	}
	w := request(g, "", "", func(r *http.Request) {
		r.Method = "GET"
		r.URL.Path = "/.well-known/oauth-protected-resource/mcp"
		r.Header.Del("Authorization")
	})
	if w.Code != 200 || !strings.Contains(w.Body.String(), c.Issuer) || !strings.Contains(w.Body.String(), c.Resource) {
		t.Fatalf("bad metadata: %d %s", w.Code, w.Body.String())
	}
	if w = request(g, strings.Repeat("x", bodyLimit+1), "", nil); w.Code != 413 {
		t.Fatalf("large body: %d", w.Code)
	}
	if w = request(g, list, "", nil); w.Code != 400 {
		t.Fatalf("no session: %d", w.Code)
	}
	if w = request(g, list, "invented", nil); w.Code != 404 {
		t.Fatalf("unknown session: %d", w.Code)
	}
}

func TestSessionIsolationPolicyAndSignedAudit(t *testing.T) {
	c := testConfig(t)
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(t.TempDir(), "audit.jsonl")
	auditor, err := audit.New(path, audit.WithEd25519Key(priv))
	if err != nil {
		t.Fatal(err)
	}
	defer auditor.Close()
	engine, err := policy.LoadBytes([]byte("agents:\n  mira:\n    mode: allow\n    deny: [delete_*]\n"))
	if err != nil {
		t.Fatal(err)
	}
	var calls atomic.Int32
	var initCount atomic.Int32
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls.Add(1)
		if r.Header.Get("X-Agent-Token") != "test-upstream-credential" || r.Header.Get("Authorization") != "" || r.Header.Get("Cookie") != "" || r.Header.Get("X-Forwarded-User") != "" {
			t.Error("credential/identity boundary failed")
		}
		var msg struct {
			Method string          `json:"method"`
			ID     json.RawMessage `json:"id"`
		}
		_ = json.NewDecoder(r.Body).Decode(&msg)
		if msg.Method == "initialize" {
			w.Header().Set("Mcp-Session-Id", fmt.Sprintf("private-upstream-%d", initCount.Add(1)))
		} else if !strings.HasPrefix(r.Header.Get("Mcp-Session-Id"), "private-upstream-") {
			t.Error("gateway did not translate session")
		}
		w.Header().Set("Content-Type", "application/json")
		w.Header().Set("Set-Cookie", "upstream-secret=value")
		result := `{}`
		if msg.Method == "tools/list" {
			result = `{"tools":[{"name":"read_item"},{"name":"delete_item"}],"nextCursor":"page2"}`
		}
		fmt.Fprintf(w, `{"jsonrpc":"2.0","id":%s,"result":%s}`, msg.ID, result)
	}))
	defer upstream.Close()
	logger := log.New(io.Discard, "", 0)
	limiter := ratelimit.New(ratelimit.Config{SpendCap: 4})
	g := newTestGateway(t, c, validAuth(t, c), func() http.Handler {
		gate := proxy.NewStdioProxy(nil, c.Agent, engine, nil, limiter, auditor, nil, logger)
		return proxy.NewHTTPListener("", upstream.URL, gate, logger).WithUpstreamAgentToken("test-upstream-credential")
	})
	init := func() string {
		w := request(g, initialize, "", nil)
		sid := w.Header().Get("Mcp-Session-Id")
		if w.Code != 200 || len(sid) != 43 || strings.Contains(sid, "upstream") || w.Header().Get("Set-Cookie") != "" {
			t.Fatalf("unsafe initialization: %d %v", w.Code, w.Header())
		}
		return sid
	}
	a, b := init(), init()
	if a == b {
		t.Fatal("sessions share handles")
	}
	call := func(sid, name, args string) *httptest.ResponseRecorder {
		return request(g, fmt.Sprintf(`{"jsonrpc":"2.0","id":3,"method":"tools/call","params":{"name":%q,"arguments":%s}}`, name, args), sid, func(r *http.Request) {
			r.Header.Set("Cookie", "caller-secret=value")
			r.Header.Set("X-Forwarded-User", "admin")
			r.Header.Set("X-Agent-Token", "attacker-token")
		})
	}
	call(a, "nockcc_nock_claim", `{"id":99}`)
	call(a, "read_item", `{}`)
	call(b, "read_item", `{}`)
	before := calls.Load()
	denied := call(b, "delete_item", `{}`)
	if calls.Load() != before || !strings.Contains(denied.Body.String(), "error") {
		t.Fatal("denied tool reached upstream")
	}
	discovery := request(g, list, b, nil)
	if strings.Contains(discovery.Body.String(), "delete_item") || !strings.Contains(discovery.Body.String(), "read_item") || !strings.Contains(discovery.Body.String(), "page2") {
		t.Fatalf("unfiltered discovery: %s", discovery.Body.String())
	}
	call(a, "read_item", `{}`)
	before = calls.Load()
	limited := call(b, "read_item", `{}`)
	if calls.Load() != before || !strings.Contains(limited.Body.String(), "exceeded") {
		t.Fatal("new session reset the quota")
	}
	if _, err := audit.VerifyEd25519(path, pub); err != nil {
		t.Fatal(err)
	}
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	var cards []int
	for _, line := range strings.Split(strings.TrimSpace(string(data)), "\n") {
		var ev audit.Event
		if json.Unmarshal([]byte(line), &ev) != nil {
			t.Fatal("invalid audit")
		}
		if ev.Agent != "mira" {
			t.Fatal("wrong agent")
		}
		if ev.Tool == "read_item" && ev.Decision == "allow" {
			cards = append(cards, ev.NockID)
		}
	}
	if fmt.Sprint(cards) != "[99 0 99]" {
		t.Fatalf("card state crossed sessions: %v", cards)
	}
	for _, secret := range []string{"connector-test-token", "test-upstream-credential", "caller-secret"} {
		if strings.Contains(string(data), secret) {
			t.Fatal("credential leaked to audit")
		}
	}
}

func TestSessionBoundsExpiryOverlapAndRevocation(t *testing.T) {
	c := testConfig(t)
	var active atomic.Bool
	active.Store(true)
	entered, release := make(chan struct{}), make(chan struct{})
	g := newTestGateway(t, c, func(w http.ResponseWriter, r *http.Request) {
		m := validClaims(c)
		m["active"] = active.Load()
		m["aud"] = []string{c.Resource}
		_ = json.NewEncoder(w).Encode(m)
	}, func() http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if r.Header.Get("Mcp-Session-Id") == "private" {
				close(entered)
				<-release
			}
			w.Header().Set("Mcp-Session-Id", "private")
			fmt.Fprint(w, `{"jsonrpc":"2.0","id":1,"result":{}}`)
		})
	})
	w := request(g, initialize, "", nil)
	sid := w.Header().Get("Mcp-Session-Id")
	if w = request(g, initialize, sid, nil); w.Code != 400 {
		t.Fatal("reinitialized existing session")
	}
	var wg sync.WaitGroup
	wg.Add(1)
	go func() { defer wg.Done(); request(g, list, sid, nil) }()
	<-entered
	if w = request(g, list, sid, nil); w.Code != 429 {
		t.Fatal("overlapping session request entered gate")
	}
	close(release)
	wg.Wait()
	active.Store(false)
	if w = request(g, list, sid, nil); w.Code != 401 {
		t.Fatal("revoked token retained session access")
	}
	active.Store(true)
	g.mu.Lock()
	g.sessions[sid].lastUsed = time.Now().Add(-sessionTTL)
	g.mu.Unlock()
	if w = request(g, list, sid, nil); w.Code != 404 {
		t.Fatal("expired session retained state")
	}
	for i := 0; i < sessionLimit; i++ {
		g.sessions[fmt.Sprint(i)] = &session{lastUsed: time.Now()}
	}
	if w = request(g, initialize, "", nil); w.Code != 429 {
		t.Fatal("session cap ignored")
	}
	for i := 0; i < cap(g.inflight); i++ {
		g.inflight <- struct{}{}
	}
	if w = request(g, initialize, "", nil); w.Code != 429 {
		t.Fatal("inflight cap ignored")
	}
}

func TestInitializeSessionOnlyOnJSONRPCSuccess(t *testing.T) {
	c := testConfig(t)

	// Test (a): initialize where upstream returns 200 + JSON-RPC error
	t.Run("upstream error", func(t *testing.T) {
		g := newTestGateway(t, c, validAuth(t, c), func() http.Handler {
			return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				w.Header().Set("Content-Type", "application/json")
				fmt.Fprint(w, `{"jsonrpc":"2.0","id":1,"error":{"code":-32600,"message":"Invalid request"}}`)
			})
		})
		w := request(g, initialize, "", nil)
		if w.Code != 200 {
			t.Fatalf("expected 200, got %d", w.Code)
		}
		if w.Header().Get("Mcp-Session-Id") != "" {
			t.Fatal("session ID should not be set on JSON-RPC error")
		}
		// Verify session was not committed (follow-up request should fail)
		g.mu.Lock()
		if len(g.sessions) != 0 {
			t.Fatal("session should have been deleted on error")
		}
		g.mu.Unlock()
	})

	// Test (b): initialize with upstream unreachable
	t.Run("upstream unreachable", func(t *testing.T) {
		g := newTestGateway(t, c, validAuth(t, c), func() http.Handler {
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {}))
			server.Close()
			// Return a handler that points to a closed server
			return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				// Simulate upstream unreachable by writing an error response
				w.Header().Set("Content-Type", "application/json")
				fmt.Fprint(w, `{"jsonrpc":"2.0","id":1,"error":{"code":-32603,"message":"nockguard: upstream unreachable"}}`)
			})
		})
		w := request(g, initialize, "", nil)
		if w.Header().Get("Mcp-Session-Id") != "" {
			t.Fatal("session ID should not be set on upstream failure")
		}
		g.mu.Lock()
		if len(g.sessions) != 0 {
			t.Fatal("session should have been deleted on upstream failure")
		}
		g.mu.Unlock()
	})

	// Test (c): initialize with id mismatch
	t.Run("id mismatch", func(t *testing.T) {
		g := newTestGateway(t, c, validAuth(t, c), func() http.Handler {
			return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				w.Header().Set("Content-Type", "application/json")
				// Response id doesn't match request id (99 vs 1)
				fmt.Fprint(w, `{"jsonrpc":"2.0","id":99,"result":{}}`)
			})
		})
		w := request(g, initialize, "", nil)
		if w.Header().Get("Mcp-Session-Id") != "" {
			t.Fatal("session ID should not be set on id mismatch")
		}
		g.mu.Lock()
		if len(g.sessions) != 0 {
			t.Fatal("session should have been deleted on id mismatch")
		}
		g.mu.Unlock()
	})

	// Test (d): existing successful init tests still pass
	t.Run("successful init", func(t *testing.T) {
		g := newTestGateway(t, c, validAuth(t, c), func() http.Handler {
			return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				w.Header().Set("Content-Type", "application/json")
				w.Header().Set("Mcp-Session-Id", "upstream-session-id")
				fmt.Fprint(w, `{"jsonrpc":"2.0","id":1,"result":{}}`)
			})
		})
		w := request(g, initialize, "", nil)
		if w.Code != 200 {
			t.Fatalf("expected 200, got %d", w.Code)
		}
		sid := w.Header().Get("Mcp-Session-Id")
		if sid == "" || len(sid) == 0 {
			t.Fatal("session ID should be set on successful init")
		}
		if strings.Contains(sid, "upstream") {
			t.Fatal("gateway session ID should not contain upstream ID")
		}
		// Verify session was committed
		g.mu.Lock()
		s := g.sessions[sid]
		if s == nil {
			t.Fatal("session should have been committed")
		}
		if s.upstreamID != "upstream-session-id" {
			t.Fatal("upstream ID should have been captured")
		}
		g.mu.Unlock()
	})

	// Optional: SSE-framed init success
	t.Run("SSE init success", func(t *testing.T) {
		g := newTestGateway(t, c, validAuth(t, c), func() http.Handler {
			return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				w.Header().Set("Content-Type", "text/event-stream")
				w.Header().Set("Mcp-Session-Id", "sse-upstream-id")
				fmt.Fprint(w, "data: {\"jsonrpc\":\"2.0\",\"id\":1,\"result\":{}}\n\n")
			})
		})
		w := request(g, initialize, "", nil)
		if w.Code != 200 {
			t.Fatalf("expected 200, got %d", w.Code)
		}
		sid := w.Header().Get("Mcp-Session-Id")
		if sid == "" {
			t.Fatal("session ID should be set on successful SSE init")
		}
		g.mu.Lock()
		s := g.sessions[sid]
		if s == nil {
			t.Fatal("session should have been committed for SSE init")
		}
		if s.upstreamID != "sse-upstream-id" {
			t.Fatal("upstream ID should have been captured from SSE")
		}
		g.mu.Unlock()
	})
}
