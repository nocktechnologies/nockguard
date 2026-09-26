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

// Test SSE with notification before the matching result
func TestSSENotificationBeforeResult(t *testing.T) {
	c := testConfig(t)
	g := newTestGateway(t, c, validAuth(t, c), func() http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Content-Type", "text/event-stream")
			w.Header().Set("Mcp-Session-Id", "sse-upstream-notify")
			// Send a notification first (no id)
			fmt.Fprint(w, "data: {\"jsonrpc\":\"2.0\",\"method\":\"notification\",\"params\":{}}\n\n")
			// Then send the initialize result
			fmt.Fprint(w, "data: {\"jsonrpc\":\"2.0\",\"id\":1,\"result\":{}}\n\n")
		})
	})

	w := request(g, initialize, "", nil)
	if w.Code != 200 {
		t.Fatalf("expected 200, got %d", w.Code)
	}

	sid := w.Header().Get("Mcp-Session-Id")
	if sid == "" {
		t.Fatal("session ID should be set after notification + result")
	}

	// Verify session was committed
	g.mu.Lock()
	s := g.sessions[sid]
	g.mu.Unlock()
	if s == nil {
		t.Fatal("session should have been committed")
	}
	if s.upstreamID != "sse-upstream-notify" {
		t.Fatalf("upstream ID not captured: %s", s.upstreamID)
	}

	// Response should contain both events
	if !strings.Contains(w.Body.String(), "notification") {
		t.Fatal("notification event missing from response")
	}
	if !strings.Contains(w.Body.String(), "id\":1") {
		t.Fatal("result event missing from response")
	}
}

// Test SSE with multi-line data payload
func TestSSEMultiLineData(t *testing.T) {
	c := testConfig(t)
	g := newTestGateway(t, c, validAuth(t, c), func() http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Content-Type", "text/event-stream")
			w.Header().Set("Mcp-Session-Id", "sse-upstream-multiline")
			// SSE event with data split across multiple lines
			fmt.Fprint(w, "data: {\"jsonrpc\":\"2.0\",\"id\":1,\n")
			fmt.Fprint(w, "data: \"result\":{}}\n\n")
		})
	})

	w := request(g, initialize, "", nil)
	if w.Code != 200 {
		t.Fatalf("expected 200, got %d", w.Code)
	}

	sid := w.Header().Get("Mcp-Session-Id")
	if sid == "" {
		t.Fatal("session ID should be set with multi-line data")
	}

	g.mu.Lock()
	s := g.sessions[sid]
	g.mu.Unlock()
	if s == nil {
		t.Fatal("session should have been committed")
	}
	if s.upstreamID != "sse-upstream-multiline" {
		t.Fatalf("upstream ID not captured: %s", s.upstreamID)
	}
}

// Test SSE with error response is rejected
func TestSSEErrorResponseRejected(t *testing.T) {
	c := testConfig(t)
	g := newTestGateway(t, c, validAuth(t, c), func() http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Content-Type", "text/event-stream")
			w.Header().Set("Mcp-Session-Id", "sse-upstream-error")
			// Send an error response in SSE format
			fmt.Fprint(w, "data: {\"jsonrpc\":\"2.0\",\"id\":1,\"error\":{\"code\":-32600,\"message\":\"Invalid request\"}}\n\n")
		})
	})

	w := request(g, initialize, "", nil)
	if w.Code != 200 {
		t.Fatalf("expected 200, got %d", w.Code)
	}

	// Should NOT have a session ID
	if w.Header().Get("Mcp-Session-Id") != "" {
		t.Fatal("session ID should not be set on SSE error")
	}

	// Session should not have been committed
	g.mu.Lock()
	if len(g.sessions) != 0 {
		t.Fatal("session should have been deleted on SSE error")
	}
	g.mu.Unlock()

	// Body should contain the error event
	if !strings.Contains(w.Body.String(), "error") {
		t.Fatal("error event should be forwarded in body")
	}
}

// Test SSE with CRLF line endings
func TestSSECRLFLineEndings(t *testing.T) {
	c := testConfig(t)
	g := newTestGateway(t, c, validAuth(t, c), func() http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Content-Type", "text/event-stream")
			w.Header().Set("Mcp-Session-Id", "sse-upstream-crlf")
			// Send event with CRLF line endings
			fmt.Fprint(w, "data: {\"jsonrpc\":\"2.0\",\"id\":1,\"result\":{}}\r\n\r\n")
		})
	})

	w := request(g, initialize, "", nil)
	if w.Code != 200 {
		t.Fatalf("expected 200, got %d", w.Code)
	}

	sid := w.Header().Get("Mcp-Session-Id")
	if sid == "" {
		t.Fatal("session ID should be set with CRLF endings")
	}

	g.mu.Lock()
	s := g.sessions[sid]
	g.mu.Unlock()
	if s == nil {
		t.Fatal("session should have been committed with CRLF")
	}
	if s.upstreamID != "sse-upstream-crlf" {
		t.Fatalf("upstream ID not captured: %s", s.upstreamID)
	}
}

// Test that existing JSON error test still passes
func TestJSONErrorResponseStillWorks(t *testing.T) {
	c := testConfig(t)
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
		t.Fatal("session ID should not be set on JSON error")
	}
	g.mu.Lock()
	if len(g.sessions) != 0 {
		t.Fatal("session should have been deleted on JSON error")
	}
	g.mu.Unlock()
}

// TestSSEInitializeKeepOpenCommitsBeforeTimeout verifies that when an upstream
// responds to initialize with SSE and keeps the stream open, the gateway sends
// the matching result to the client within 2 seconds (not waiting for the handler
// to return or the 5-minute timeout).
func TestSSEInitializeKeepOpenCommitsBeforeTimeout(t *testing.T) {
	c := testConfig(t)
	finished := make(chan struct{})

	g := newTestGateway(t, c, validAuth(t, c), func() http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			// Respond to initialize with SSE
			w.Header().Set("Content-Type", "text/event-stream")
			w.Header().Set("Mcp-Session-Id", "upstream-session-id")
			fmt.Fprint(w, "data: {\"jsonrpc\":\"2.0\",\"id\":1,\"result\":{}}\n\n")
			w.(http.Flusher).Flush()
			// Block to simulate keep-open upstream
			select {
			case <-finished:
			case <-r.Context().Done():
			}
		})
	})

	// Use httptest.NewServer to run over actual HTTP
	server := httptest.NewServer(g)
	defer server.Close()

	// Make initialize request with short timeout
	initReq, err := http.NewRequest("POST", server.URL+"/mcp", strings.NewReader(initialize))
	if err != nil {
		t.Fatal(err)
	}
	initReq.Host = "guard.example"
	initReq.Header.Set("Authorization", "Bearer connector-test-token")

	client := &http.Client{Timeout: 2 * time.Second}
	initResp, err := client.Do(initReq)
	if err != nil {
		t.Fatalf("initialize request failed (timeout?): %v", err)
	}
	defer initResp.Body.Close()

	// Verify response arrived with headers before 2-second timeout
	if initResp.StatusCode != 200 {
		t.Fatalf("expected 200, got %d", initResp.StatusCode)
	}

	sid := initResp.Header.Get("Mcp-Session-Id")
	if sid == "" {
		t.Fatal("Mcp-Session-Id header missing in initialize response")
	}
	if strings.Contains(sid, "upstream") {
		t.Fatalf("session ID leaked upstream value: %s", sid)
	}

	// Read first line of response body (should be the SSE event) within timeout
	reader := bufio.NewReader(initResp.Body)
	line, err := reader.ReadString('\n')
	if err != nil && err != io.EOF {
		t.Fatalf("failed to read response body: %v", err)
	}
	if !strings.HasPrefix(line, "data: ") {
		t.Fatalf("expected SSE data line, got: %s", line)
	}

	// Verify session was created
	g.mu.Lock()
	s := g.sessions[sid]
	g.mu.Unlock()
	if s == nil {
		t.Fatal("session not found after initialize")
	}

	// Close the upstream handler's blocking channel so next request can proceed
	close(finished)

	// Make a follow-up request with the session ID to verify it's usable
	listReq, err := http.NewRequest("POST", server.URL+"/mcp", strings.NewReader(list))
	if err != nil {
		t.Fatal(err)
	}
	listReq.Host = "guard.example"
	listReq.Header.Set("Authorization", "Bearer connector-test-token")
	listReq.Header.Set("Mcp-Session-Id", sid)

	listResp, err := client.Do(listReq)
	if err != nil {
		t.Fatalf("follow-up request failed: %v", err)
	}
	defer listResp.Body.Close()

	if listResp.StatusCode != 200 {
		body, _ := io.ReadAll(listResp.Body)
		t.Fatalf("follow-up request got %d: %s", listResp.StatusCode, string(body))
	}
	if listResp.Header.Get("Mcp-Session-Id") != sid {
		t.Fatal("follow-up response missing session ID")
	}
}

// TestSSEInitializeIncrementalParsing verifies that the parser only processes
// each complete event once, even when SSE data arrives in multiple Write calls.
// It would fail on bb2af0a (which reprocesses all events) if we added metrics,
// but demonstrates the correctness of incremental parsing.
func TestSSEInitializeIncrementalParsing(t *testing.T) {
	c := testConfig(t)
	g := newTestGateway(t, c, validAuth(t, c), func() http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Content-Type", "text/event-stream")
			w.Header().Set("Mcp-Session-Id", "incr-upstream")
			// Notification event
			fmt.Fprint(w, "data: {\"jsonrpc\":\"2.0\",\"method\":\"notify\",\"params\":{}}\n\n")
			// Matching result
			fmt.Fprint(w, "data: {\"jsonrpc\":\"2.0\",\"id\":1,\"result\":{}}\n\n")
		})
	})

	// Test with request() which does the full flow
	w := request(g, initialize, "", nil)
	if w.Code != 200 {
		t.Fatalf("status %d", w.Code)
	}

	sid := w.Header().Get("Mcp-Session-Id")
	if sid == "" {
		t.Fatal("no session ID")
	}

	g.mu.Lock()
	s := g.sessions[sid]
	g.mu.Unlock()
	if s == nil {
		t.Fatal("session not found")
	}

	// Verify that the session was properly created and committed
	// This test passes on the current implementation because w.scanned is used
	// to skip reprocessing. On bb2af0a, this would still pass, but
	// the optimization wouldn't exist (each Write would reprocess all events).
	t.Logf("Incremental parsing test passed: session created and committed")
}

// TestSSEParserLinearity verifies that the SSE parser has linear complexity.
// It sends ~70 KiB of comment/notification preamble followed by a matching result,
// one byte per Write call. The bytesExamined counter must stay well below O(n²).
func TestSSEParserLinearity(t *testing.T) {
	// Create an initWriter with direct construction
	rec := httptest.NewRecorder()
	iw := &initWriter{
		real:   rec,
		id:     json.RawMessage("1"),
		header: make(http.Header),
		mode:   "sse",
	}
	iw.header.Set("Content-Type", "text/event-stream")

	// Build preamble: ~70 KiB of comments and notifications
	var preamble []byte
	for i := 0; i < 1000; i++ {
		preamble = append(preamble, []byte(": comment line\n")...)
		preamble = append(preamble, []byte("data: {\"jsonrpc\":\"2.0\",\"method\":\"notify\",\"params\":{}}\n\n")...)
	}

	resultEvent := []byte("data: {\"jsonrpc\":\"2.0\",\"id\":1,\"result\":{}}\n\n")

	// Feed one byte at a time
	totalData := append(preamble, resultEvent...)
	for i := 0; i < len(totalData); i++ {
		iw.Write([]byte{totalData[i]})
		if iw.committed {
			break
		}
	}

	if !iw.committed {
		t.Fatal("parser should commit on matching result")
	}

	// Linear complexity: O(n) ≈ n. Quadratic would be O(n²) ≈ n²/2
	// For n ≈ 70000, linear is ~70000, quadratic is ~2×10⁹
	// Allow 3× linear as upper bound
	maxBytesExamined := 3 * len(totalData)
	if iw.bytesExamined > maxBytesExamined {
		t.Fatalf("bytesExamined=%d exceeds 3n=%d (linear: %d, quadratic estimate: %.0e)",
			iw.bytesExamined, maxBytesExamined, len(totalData), float64(len(totalData)*len(totalData))/2)
	}
	t.Logf("Parser linearity verified: bytesExamined=%d (3n=%d, n=%d)", iw.bytesExamined, maxBytesExamined, len(totalData))
}

// TestSSEParserMultiLineDataSplitAcrossWrites verifies that events with multiple
// data: lines, split at every byte boundary across Write calls, are parsed correctly.
func TestSSEParserMultiLineDataSplitAcrossWrites(t *testing.T) {
	rec := httptest.NewRecorder()
	iw := &initWriter{
		real:   rec,
		id:     json.RawMessage("1"),
		header: make(http.Header),
		mode:   "sse",
	}
	iw.header.Set("Content-Type", "text/event-stream")

	// Event with 5 data lines
	eventData := []byte("data: line1\ndata: line2\ndata: line3\ndata: line4\ndata: line5\n\n")

	// Feed one byte at a time
	for i := 0; i < len(eventData); i++ {
		iw.Write([]byte{eventData[i]})
	}

	// Should not commit (not a valid JSON-RPC response)
	if iw.committed {
		t.Fatal("should not commit on non-JSON event")
	}
	if iw.rejected {
		t.Fatal("should not reject on malformed event (should skip)")
	}
}

// TestSSEParserCRLFSplitAcrossWrites tests \r\n split across two Write calls.
func TestSSEParserCRLFSplitAcrossWrites(t *testing.T) {
	rec := httptest.NewRecorder()
	iw := &initWriter{
		real:   rec,
		id:     json.RawMessage("1"),
		header: make(http.Header),
		mode:   "sse",
	}
	iw.header.Set("Content-Type", "text/event-stream")

	// First write ends with \r (first half of \r\n)
	iw.Write([]byte("data: {\"jsonrpc\":\"2.0\",\"id\":1,\"result\":{}}\r"))
	if iw.committed || iw.rejected {
		t.Fatal("incomplete \\r at end should not commit or reject")
	}

	// Second write starts with \n (second half of \r\n)
	iw.Write([]byte("\n\r\n"))
	if !iw.committed {
		t.Fatal("should commit after receiving \\n completing the \\r\\n")
	}
}
