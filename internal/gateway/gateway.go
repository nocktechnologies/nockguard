package gateway

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"slices"
	"strings"
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
	if initializing {
		// Use incremental validating writer for initialize
		iw := &initWriter{
			real:   w,
			id:     msg.ID,
			sid:    id,
			header: make(http.Header),
			mode:   "undecided",
		}
		s.handler.ServeHTTP(iw, forward)

		if iw.committed {
			s.upstreamID = iw.upstreamID
			success = true
		} else {
			iw.finalize()
			if iw.committed {
				s.upstreamID = iw.upstreamID
				success = true
			}
		}
	} else {
		// Non-initialize requests stream normally
		rw := &response{ResponseWriter: w, onHeader: func(status int) {
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

// initWriter implements http.ResponseWriter for incremental initialize response validation.
// It buffers and validates the response to ensure:
// - JSON responses: complete buffering and validation as before
// - SSE responses: incremental event parsing, commit on first matching-id result
type initWriter struct {
	real          http.ResponseWriter
	id            json.RawMessage
	sid           string
	header        http.Header
	status        int
	mode          string // "undecided", "buffer", or "sse"
	held          bytes.Buffer
	pos           int  // start of current event in held buffer
	lineStart     int  // start of current line in held buffer
	searchFrom    int  // offset to search from for next line terminator
	bytesExamined int  // for testing: count of bytes examined
	skipLF        bool // skip next LF if it's the second half of a CRLF
	committed     bool
	rejected      bool
	upstreamID    string
	overflow      bool
}

func (w *initWriter) Header() http.Header {
	return w.header
}

func (w *initWriter) WriteHeader(code int) {
	if w.status == 0 {
		w.status = code
		// Determine mode based on status and Content-Type
		ct := w.header.Get("Content-Type")
		if code >= 200 && code < 300 && strings.HasPrefix(ct, "text/event-stream") {
			w.mode = "sse"
		} else {
			w.mode = "buffer"
		}
	}
}

func (w *initWriter) Write(p []byte) (int, error) {
	if w.status == 0 {
		w.WriteHeader(http.StatusOK)
	}

	if w.rejected {
		return 0, errors.New("gateway: initialize rejected")
	}

	if w.committed {
		// Stream through with flushing
		n, err := w.real.Write(p)
		if err == nil {
			_ = http.NewResponseController(w.real).Flush()
		}
		return n, err
	}

	// Still deciding: buffer and parse
	if w.mode == "buffer" {
		if w.overflow {
			return 0, bytes.ErrTooLarge
		}
		if w.held.Len()+len(p) > bodyLimit {
			w.overflow = true
			w.reject()
			return 0, bytes.ErrTooLarge
		}
		return w.held.Write(p)
	}

	// SSE mode: incremental parsing
	if w.held.Len()+len(p) > bodyLimit {
		w.overflow = true
		w.reject()
		return 0, bytes.ErrTooLarge
	}
	w.held.Write(p)

	// Try to parse complete events
	w.parseSSEEvents()

	// If decision made, commit
	if w.committed {
		w.commitSSE()
		return len(p), nil
	}
	if w.rejected {
		return 0, errors.New("gateway: initialize rejected")
	}

	return len(p), nil
}

func (w *initWriter) Flush() {
	// Only flush if committed; buffer mode does no-op, SSE streaming handled in Write
	if w.committed {
		_ = http.NewResponseController(w.real).Flush()
	}
}

func (w *initWriter) parseSSEEvents() {
	if w.committed || w.rejected {
		return
	}

	data := w.held.Bytes()
	if len(data) == 0 {
		return
	}

	// Linear scan starting from searchFrom
	i := w.searchFrom
	for i < len(data) {
		w.bytesExamined++
		b := data[i]

		var termLen int
		isTerminator := false

		// Detect line terminator: \n, \r\n, or bare \r
		if b == '\n' {
			isTerminator = true
			termLen = 1
		} else if b == '\r' {
			// \r is always a terminator (per WHATWG SSE parser)
			isTerminator = true
			if i+1 < len(data) && data[i+1] == '\n' {
				termLen = 2
			} else if i+1 == len(data) {
				// \r at end of buffer: set flag to skip following \n if it comes
				termLen = 1
				w.skipLF = true
			} else {
				// bare \r followed by non-\n
				termLen = 1
			}
		}

		if !isTerminator {
			i++
			continue
		}

		// We have a line from w.lineStart to i
		// Check if it's blank
		isBlank := (w.lineStart == i)

		if isBlank {
			if w.lineStart > w.pos {
				// Blank line marks end of event; dispatch it
				eventData := data[w.pos:w.lineStart]
				// Normalize line endings: replace \r\n with \n, then \r with \n
				// This handles bare \r, CRLF, and LF uniformly
				normalized := bytes.ReplaceAll(eventData, []byte("\r\n"), []byte("\n"))
				normalized = bytes.ReplaceAll(normalized, []byte("\r"), []byte("\n"))
				eventLines := bytes.Split(normalized, []byte("\n"))

				if w.processSSEEvent(eventLines) {
					w.committed = true
					return
				}
			}
			// Blank line: move past it
			w.pos = i + termLen
			w.lineStart = i + termLen
			w.searchFrom = i + termLen
		} else {
			// Non-blank line: move to next line
			w.lineStart = i + termLen
			w.searchFrom = i + termLen
		}

		i = w.searchFrom
	}

	// No more complete lines; update searchFrom for next call
	w.searchFrom = len(data)
}
func (w *initWriter) processSSEEvent(lines [][]byte) bool {
	// Collect data: lines and join with \n
	var dataParts []string
	for _, lineBytes := range lines {
		line := lineBytes
		// Strip trailing \r if present
		if len(line) > 0 && line[len(line)-1] == '\r' {
			line = line[:len(line)-1]
		}

		if bytes.HasPrefix(line, []byte("data:")) {
			data := bytes.TrimPrefix(line, []byte("data:"))
			// Strip exactly one leading space if present
			if len(data) > 0 && data[0] == ' ' {
				data = data[1:]
			}
			dataParts = append(dataParts, string(data))
		} else if bytes.HasPrefix(line, []byte(":")) {
			// Comment, skip
			continue
		} else if bytes.Contains(line, []byte(":")) {
			// Other SSE fields (event, id, retry), skip for now
			continue
		} else if len(line) > 0 {
			// Field without colon; treat as data
			dataParts = append(dataParts, string(line))
		}
	}

	if len(dataParts) == 0 {
		// Empty event, skip
		return false
	}

	payload := strings.Join(dataParts, "\n")

	// Parse as JSON-RPC response
	var msg map[string]json.RawMessage
	if err := json.Unmarshal([]byte(payload), &msg); err != nil {
		return false
	}

	// Skip if it's a request/notification (has "method")
	if _, hasMethod := msg["method"]; hasMethod {
		return false
	}

	// Skip if no id or id doesn't match
	respID, hasID := msg["id"]
	if !hasID {
		return false
	}

	if !jsonRPCIDMatches(w.id, respID) {
		return false
	}

	// Check jsonrpc == "2.0"
	jsonrpcRaw, hasJSONRPC := msg["jsonrpc"]
	if !hasJSONRPC {
		return false
	}
	var jsonrpc string
	if err := json.Unmarshal(jsonrpcRaw, &jsonrpc); err != nil {
		return false
	}
	if jsonrpc != "2.0" {
		return false
	}

	// Check for error (must not be present)
	if _, hasError := msg["error"]; hasError {
		// This is an error response, reject
		w.reject()
		return false
	}

	// Check for result (must be present)
	if _, hasResult := msg["result"]; !hasResult {
		return false
	}

	// Valid success response! Commit.
	return true
}

func (w *initWriter) reject() {
	w.rejected = true
}

func (w *initWriter) commitSSE() {
	w.upstreamID = w.header.Get("Mcp-Session-Id")
	w.writeHeaders()
	w.real.WriteHeader(w.status)
	_, _ = w.real.Write(w.held.Bytes())
	_ = http.NewResponseController(w.real).Flush()
}

func (w *initWriter) finalize() {
	if w.mode == "buffer" {
		// Validate buffered response
		if w.overflow {
			w.real.WriteHeader(http.StatusBadGateway)
			_, _ = w.real.Write([]byte("response too large"))
			return
		}

		contentType := w.header.Get("Content-Type")
		body := w.held.Bytes()

		if validateInitializeResponse(w.status, contentType, body, w.id) {
			w.upstreamID = w.header.Get("Mcp-Session-Id")
			w.writeHeaders()
			w.real.WriteHeader(w.status)
			if len(body) > 0 {
				_, _ = w.real.Write(body)
			}
			w.committed = true
		} else {
			// Validation failed, write as-is without session id
			w.writeHeadersNoSession()
			w.real.WriteHeader(w.status)
			if len(body) > 0 {
				_, _ = w.real.Write(body)
			}
		}
	} else if w.mode == "sse" {
		// SSE with no decision by end of stream: reject
		w.writeHeadersNoSession()
		w.real.WriteHeader(w.status)
		_, _ = w.real.Write(w.held.Bytes())
	}
}

func (w *initWriter) writeHeaders() {
	// Copy allowed headers and set session id
	for _, h := range []string{"Content-Type", "Content-Length", "Mcp-Protocol-Version"} {
		if v := w.header.Get(h); v != "" {
			w.real.Header().Set(h, v)
		}
	}
	w.real.Header().Set("Cache-Control", "no-store")
	w.real.Header().Set("Mcp-Session-Id", w.sid)
}

func (w *initWriter) writeHeadersNoSession() {
	// Copy allowed headers without session id
	for _, h := range []string{"Content-Type", "Content-Length", "Mcp-Protocol-Version"} {
		if v := w.header.Get(h); v != "" {
			w.real.Header().Set(h, v)
		}
	}
	w.real.Header().Set("Cache-Control", "no-store")
}

// validateInitializeResponse checks if the buffered response is a valid JSON-RPC
// success response that matches the request ID. Returns true only if:
// - status is 2xx
// - body is a JSON-RPC 2.0 response with "result" (not "error")
// - id matches the request's JSON-RPC id
// For SSE responses, it parses the first data line.
func validateInitializeResponse(status int, contentType string, body []byte, requestID json.RawMessage) bool {
	if status < 200 || status >= 300 {
		return false
	}

	// Handle SSE responses: parse the first data line
	if strings.HasPrefix(contentType, "text/event-stream") {
		body = extractFirstSSEMessage(body)
		if len(body) == 0 {
			return false
		}
	}

	// Parse the JSON-RPC response
	var msg struct {
		JSONRPC string          `json:"jsonrpc"`
		ID      json.RawMessage `json:"id"`
		Result  json.RawMessage `json:"result"`
		Error   json.RawMessage `json:"error"`
	}
	var members map[string]json.RawMessage
	if err := json.Unmarshal(body, &msg); err != nil {
		return false
	}
	if err := json.Unmarshal(body, &members); err != nil {
		return false
	}

	// Validate JSON-RPC 2.0 success response
	if msg.JSONRPC != "2.0" {
		return false
	}

	// Check for error member (must not be present)
	if _, hasError := members["error"]; hasError {
		return false
	}

	// Check for result member (must be present)
	if _, hasResult := members["result"]; !hasResult {
		return false
	}

	// Validate ID matches request ID
	return jsonRPCIDMatches(requestID, msg.ID)
}

// extractFirstSSEMessage extracts the first complete SSE data line from the body
func extractFirstSSEMessage(body []byte) []byte {
	lines := bytes.Split(body, []byte("\n"))
	for _, line := range lines {
		line = bytes.TrimSpace(line)
		if bytes.HasPrefix(line, []byte("data:")) {
			data := bytes.TrimPrefix(line, []byte("data:"))
			data = bytes.TrimSpace(data)
			return data
		}
	}
	return nil
}

// jsonRPCIDMatches reports whether respID is present and equals the id of the
// request, using number-aware comparison.
func jsonRPCIDMatches(reqID, respID json.RawMessage) bool {
	if respID == nil {
		return false
	}
	reqIDVal, ok1 := decodeIDNumberAware(reqID)
	respIDVal, ok2 := decodeIDNumberAware(respID)
	return ok1 && ok2 && compareIDValues(reqIDVal, respIDVal)
}

// compareIDValues compares two id values with proper type handling.
func compareIDValues(a, b interface{}) bool {
	aNum, aIsNum := a.(json.Number)
	bNum, bIsNum := b.(json.Number)

	if aIsNum && bIsNum {
		return aNum == bNum
	}
	if aIsNum || bIsNum {
		return false
	}

	aStr, aIsStr := a.(string)
	bStr, bIsStr := b.(string)
	if aIsStr && bIsStr {
		return aStr == bStr
	}
	if aIsStr || bIsStr {
		return false
	}

	// Otherwise compare as-is (bool, nil, etc.)
	return a == b
}

// decodeIDNumberAware decodes a JSON-RPC id with UseNumber so a large integer id
// keeps its exact literal (json.Number) instead of collapsing to float64, where
// distinct ids above 2^53 would compare equal. String and null ids keep their own
// types, so a numeric id never matches a string id of the same text.
func decodeIDNumberAware(raw json.RawMessage) (interface{}, bool) {
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.UseNumber()
	var v interface{}
	if err := dec.Decode(&v); err != nil {
		return nil, false
	}
	return v, true
}
