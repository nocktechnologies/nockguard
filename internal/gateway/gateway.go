package gateway

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"slices"
	"sync"
	"time"
)

const bodyLimit = 10 * 1024 * 1024
const sessionLimit = 64
const sessionTTL = 30 * time.Minute
const requestTimeout = 5 * time.Minute

type session struct {
	handler    http.Handler
	upstreamID string
	lastUsed   time.Time
	busy       bool
}

// Gateway owns session gates; newHandler must return a fresh gate, with shared
// agent quotas and audit writer. Only the configured subject/client can enter.
type Gateway struct {
	config             Config
	host               string
	metadataURL        string
	introspectionToken string
	authClient         *http.Client
	newHandler         func() http.Handler
	inflight           chan struct{}
	mu                 sync.Mutex
	sessions           map[string]*session
}

func New(c Config, newHandler func() http.Handler) (*Gateway, error) {
	if err := c.Validate(); err != nil {
		return nil, err
	}
	token, err := Secret(c.IntrospectionTokenEnv)
	if err != nil {
		return nil, err
	}
	if newHandler == nil {
		return nil, fmt.Errorf("session handler factory is required")
	}
	u, _ := url.Parse(c.Resource)
	return &Gateway{config: c, host: u.Host, metadataURL: "https://" + u.Host + "/.well-known/oauth-protected-resource/mcp", introspectionToken: token,
		authClient: &http.Client{Timeout: 5 * time.Second, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }},
		newHandler: newHandler, inflight: make(chan struct{}, sessionLimit), sessions: make(map[string]*session)}, nil
}

func (g *Gateway) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Cache-Control", "no-store")
	if r.Host != g.host {
		http.Error(w, "invalid host", http.StatusMisdirectedRequest)
		return
	}
	if origins := r.Header.Values("Origin"); len(origins) > 0 && (len(origins) != 1 || !slices.Contains(g.config.AllowedOrigins, origins[0])) {
		http.Error(w, "origin forbidden", http.StatusForbidden)
		return
	}
	if r.URL.RawQuery != "" || r.URL.ForceQuery || r.URL.RawPath != "" {
		http.NotFound(w, r)
		return
	}
	if r.URL.Path == "/.well-known/oauth-protected-resource/mcp" && r.Method == http.MethodGet {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]interface{}{"resource": g.config.Resource, "authorization_servers": []string{g.config.Issuer}, "scopes_supported": []string{g.config.Scope}, "bearer_methods_supported": []string{"header"}})
		return
	}
	if r.URL.Path != "/mcp" {
		http.NotFound(w, r)
		return
	}
	if r.Method != http.MethodPost {
		w.Header().Set("Allow", "POST")
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	select {
	case g.inflight <- struct{}{}:
		defer func() { <-g.inflight }()
	default:
		g.busy(w)
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), requestTimeout)
	defer cancel()
	c, err := g.authenticate(ctx, r)
	if err != nil {
		w.Header().Set("WWW-Authenticate", fmt.Sprintf("Bearer resource_metadata=%q, scope=%q", g.metadataURL, g.config.Scope))
		http.Error(w, "authentication required", http.StatusUnauthorized)
		return
	}
	ctx, expire := context.WithDeadline(ctx, time.Unix(c.Expires, 0))
	defer expire()
	deadline, _ := ctx.Deadline()
	_ = http.NewResponseController(w).SetWriteDeadline(deadline)
	_ = http.NewResponseController(w).SetReadDeadline(time.Now().Add(30 * time.Second))
	body, err := io.ReadAll(io.LimitReader(r.Body, bodyLimit+1))
	if err != nil {
		http.Error(w, "could not read request", http.StatusBadRequest)
		return
	}
	if len(body) > bodyLimit {
		http.Error(w, "request too large", http.StatusRequestEntityTooLarge)
		return
	}
	var msg struct {
		Method string          `json:"method"`
		ID     json.RawMessage `json:"id"`
	}
	if json.Unmarshal(body, &msg) != nil {
		http.Error(w, "invalid request", http.StatusBadRequest)
		return
	}
	if len(r.Header.Values("Mcp-Session-Id")) > 1 {
		http.Error(w, "invalid session", http.StatusBadRequest)
		return
	}
	id := r.Header.Get("Mcp-Session-Id")
	initializing := id == ""
	if (initializing && (msg.Method != "initialize" || len(msg.ID) == 0 || string(msg.ID) == "null")) || (!initializing && msg.Method == "initialize") {
		http.Error(w, "initialize requires a new session", http.StatusBadRequest)
		return
	}
	s, id, status := g.acquire(id)
	if status != http.StatusOK {
		if status == http.StatusTooManyRequests {
			g.busy(w)
		} else {
			http.Error(w, "session not found", status)
		}
		return
	}
	success := !initializing
	defer func() {
		g.mu.Lock()
		defer g.mu.Unlock()
		s.busy = false
		s.lastUsed = time.Now()
		if !success {
			delete(g.sessions, id)
		}
	}()
	// Build an allowlist of transport headers. No caller credentials, cookies,
	// forwarding/identity headers or upstream session IDs cross this boundary.
	forward := r.Clone(ctx)
	forward.Body = io.NopCloser(bytes.NewReader(body))
	forward.ContentLength = int64(len(body))
	forward.Header = make(http.Header)
	forward.Header.Set("Content-Type", "application/json")
	forward.Header.Set("Accept", "application/json, text/event-stream")
	for _, h := range []string{"MCP-Protocol-Version", "Last-Event-ID"} {
		if v := r.Header.Get(h); v != "" {
			forward.Header.Set(h, v)
		}
	}
	if s.upstreamID != "" {
		forward.Header.Set("Mcp-Session-Id", s.upstreamID)
	}
	rw := &response{ResponseWriter: w, onHeader: func(status int) {
		if initializing && status >= 200 && status < 300 {
			s.upstreamID = w.Header().Get("Mcp-Session-Id")
			success = true
		}
		for key := range w.Header() {
			if key != "Content-Type" && key != "Content-Length" && key != "Mcp-Protocol-Version" {
				w.Header().Del(key)
			}
		}
		w.Header().Set("Cache-Control", "no-store")
		if success {
			w.Header().Set("Mcp-Session-Id", id)
		}
	}}
	s.handler.ServeHTTP(rw, forward)
}

func (g *Gateway) busy(w http.ResponseWriter) {
	w.Header().Set("Retry-After", "1")
	http.Error(w, "gateway busy", http.StatusTooManyRequests)
}

func (g *Gateway) acquire(id string) (*session, string, int) {
	g.mu.Lock()
	defer g.mu.Unlock()
	now := time.Now()
	for key, s := range g.sessions {
		if !s.busy && now.Sub(s.lastUsed) >= sessionTTL {
			delete(g.sessions, key)
		}
	}
	if id != "" {
		s := g.sessions[id]
		if s == nil {
			return nil, id, http.StatusNotFound
		}
		if s.busy {
			return nil, id, http.StatusTooManyRequests
		}
		s.busy = true
		return s, id, http.StatusOK
	}
	if len(g.sessions) >= sessionLimit {
		return nil, id, http.StatusTooManyRequests
	}
	var b [32]byte
	if _, err := rand.Read(b[:]); err != nil {
		return nil, id, http.StatusServiceUnavailable
	}
	id = base64.RawURLEncoding.EncodeToString(b[:])
	s := &session{handler: g.newHandler(), lastUsed: now, busy: true}
	g.sessions[id] = s
	return s, id, http.StatusOK
}

type response struct {
	http.ResponseWriter
	onHeader func(int)
	written  bool
}

func (w *response) WriteHeader(code int) {
	if w.written {
		return
	}
	w.written = true
	w.onHeader(code)
	w.ResponseWriter.WriteHeader(code)
}
func (w *response) Write(b []byte) (int, error) {
	if !w.written {
		w.WriteHeader(http.StatusOK)
	}
	return w.ResponseWriter.Write(b)
}
func (w *response) Unwrap() http.ResponseWriter { return w.ResponseWriter }
func (w *response) Flush() {
	if !w.written {
		w.WriteHeader(http.StatusOK)
	}
	_ = http.NewResponseController(w.ResponseWriter).Flush()
}

func (g *Gateway) Run(ctx context.Context) error {
	srv := &http.Server{Addr: g.config.Listen, Handler: g, ReadHeaderTimeout: 10 * time.Second, ReadTimeout: 30 * time.Second, WriteTimeout: requestTimeout, IdleTimeout: 60 * time.Second, MaxHeaderBytes: 16 * 1024}
	errCh := make(chan error, 1)
	go func() { errCh <- srv.ListenAndServe() }()
	select {
	case err := <-errCh:
		if err == http.ErrServerClosed {
			return nil
		}
		return err
	case <-ctx.Done():
		shutdown, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		if err := srv.Shutdown(shutdown); err != nil {
			_ = srv.Close()
			return err
		}
		return nil
	}
}
