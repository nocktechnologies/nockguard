package proxy

import (
	"encoding/json"
	"io"
	"log"
	"net/http"
	"net/http/httptest"
	"slices"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/nocktechnologies/nockguard/internal/audit"
)

const requiredClaimCall = `{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"nockcc_nock_claim","arguments":{"id":12345}}}`

const requiredOutcomeWarning = "tool may have executed; do not retry automatically"

func TestHTTPListener_RequiredUnverifiedJSONTransportAndBodyFailuresAreUncertain(t *testing.T) {
	cases := []struct {
		name       string
		wantStatus int
		serve      func(http.ResponseWriter, *http.Request, *atomic.Int32, <-chan struct{})
	}{
		{
			name:       "upstream executed before HTTP 502",
			wantStatus: http.StatusBadGateway,
			serve: func(w http.ResponseWriter, _ *http.Request, calls *atomic.Int32, _ <-chan struct{}) {
				calls.Add(1)
				w.WriteHeader(http.StatusBadGateway)
				_, _ = io.WriteString(w, "upstream-success-marker")
			},
		},
		{
			name: "JSON body timeout",
			serve: func(w http.ResponseWriter, _ *http.Request, calls *atomic.Int32, release <-chan struct{}) {
				calls.Add(1)
				w.Header().Set("Content-Type", "application/json")
				w.WriteHeader(http.StatusOK)
				w.(http.Flusher).Flush()
				<-release
			},
		},
		{
			name: "unexpected EOF",
			serve: func(w http.ResponseWriter, _ *http.Request, calls *atomic.Int32, _ <-chan struct{}) {
				calls.Add(1)
				w.Header().Set("Content-Type", "application/json")
				w.Header().Set("Content-Length", "128")
				w.WriteHeader(http.StatusOK)
				_, _ = io.WriteString(w, `{"jsonrpc":"2.0","id":1,"result":{"text":"upstream-success-marker"}}`)
			},
		},
		{
			name: "oversized body",
			serve: func(w http.ResponseWriter, _ *http.Request, calls *atomic.Int32, _ <-chan struct{}) {
				calls.Add(1)
				w.Header().Set("Content-Type", "application/json")
				w.WriteHeader(http.StatusOK)
				_, _ = io.WriteString(w, strings.Repeat("x", httpListenerBodyCap+1))
			},
		},
		{
			name: "transport closes before response headers",
			serve: func(w http.ResponseWriter, _ *http.Request, calls *atomic.Int32, _ <-chan struct{}) {
				calls.Add(1)
				conn, _, err := w.(http.Hijacker).Hijack()
				if err != nil {
					return
				}
				_ = conn.Close()
			},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if tc.name == "JSON body timeout" {
				oldTimeout := httpListenerJSONReadTimeout
				httpListenerJSONReadTimeout = 50 * time.Millisecond
				defer func() { httpListenerJSONReadTimeout = oldTimeout }()
			}
			auditor, auditPath, pub := newEd25519Auditor(t)
			var calls atomic.Int32
			release := make(chan struct{})
			var releaseOnce sync.Once
			upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				tc.serve(w, r, &calls, release)
			}))
			defer upstream.Close()
			defer releaseOnce.Do(func() { close(release) })

			gate := newGate(t, "agents:\n  mira:\n    mode: allow\n", nil, auditor)
			lsrv := httptest.NewServer(NewHTTPListener("127.0.0.1:0", upstream.URL, gate, log.New(io.Discard, "", 0)).WithRequiredAudit())
			defer lsrv.Close()

			status, body, contentType := post(t, lsrv.URL, requiredClaimCall)
			releaseOnce.Do(func() { close(release) })
			wantStatus := tc.wantStatus
			if wantStatus == 0 {
				wantStatus = http.StatusOK
			}
			if status != wantStatus || !strings.HasPrefix(contentType, "application/json") {
				t.Fatalf("connector response = status %d content-type %q body %s; want visible JSON-RPC error", status, contentType, body)
			}
			assertRequiredUnknownOutcome(t, body)
			if strings.Contains(body, "upstream-success-marker") {
				t.Fatalf("unverified upstream success bytes escaped: %s", body)
			}
			if got := calls.Load(); got != 1 {
				t.Fatalf("upstream call count = %d, want one call and no retry", got)
			}
			verifyRequiredAudit(t, auditor, auditPath, pub)
		})
	}
}

func TestHTTPListener_RequiredJSONResponsesRequireValidJSONRPCEnvelope(t *testing.T) {
	validError := `{"jsonrpc":"2.0","id":1,"error":{"code":-32001,"message":"upstream rejected"}}`
	validResult := `{"jsonrpc":"2.0","id":1,"result":{"content":[{"type":"text","text":"valid-upstream-result"}]}}`
	cases := []struct {
		name          string
		body          string
		valid         bool
		wantCard      int
		wantExactBody bool
	}{
		{name: "malformed JSON", body: `{"jsonrpc":"2.0","id":1,"result":{`, wantCard: 0},
		{name: "missing id", body: `{"jsonrpc":"2.0","result":{"text":"upstream-success-marker"}}`, wantCard: 0},
		{name: "mismatched id", body: `{"jsonrpc":"2.0","id":99,"result":{"text":"upstream-success-marker"}}`, wantCard: 0},
		{name: "wrong JSON-RPC version", body: `{"jsonrpc":"1.0","id":1,"result":{"text":"upstream-success-marker"}}`, wantCard: 0},
		{name: "request-shaped envelope", body: `{"jsonrpc":"2.0","id":1,"method":"tools/call","result":{"text":"upstream-success-marker"}}`, wantCard: 0},
		{name: "both result and error", body: `{"jsonrpc":"2.0","id":1,"result":{"text":"upstream-success-marker"},"error":{"code":-1,"message":"bad"}}`, wantCard: 0},
		{name: "neither result nor error", body: `{"jsonrpc":"2.0","id":1}`, wantCard: 0},
		{name: "null error member", body: `{"jsonrpc":"2.0","id":1,"error":null}`, wantCard: 0},
		{name: "malformed error object", body: `{"jsonrpc":"2.0","id":1,"error":{"code":"bad","message":"bad"}}`, wantCard: 0},
		{name: "valid JSON-RPC error", body: validError, valid: true, wantCard: 0, wantExactBody: true},
		{name: "valid result", body: validResult, valid: true, wantCard: 12345},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			auditor, auditPath, pub := newEd25519Auditor(t)
			var calls atomic.Int32
			upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
				calls.Add(1)
				w.Header().Set("Content-Type", "application/json")
				w.WriteHeader(http.StatusOK)
				_, _ = io.WriteString(w, tc.body)
			}))
			defer upstream.Close()
			gate := newGate(t, "agents:\n  mira:\n    mode: allow\n", nil, auditor)
			lsrv := httptest.NewServer(NewHTTPListener("127.0.0.1:0", upstream.URL, gate, log.New(io.Discard, "", 0)).WithRequiredAudit())
			defer lsrv.Close()

			status, body, contentType := post(t, lsrv.URL, requiredClaimCall)
			if status != http.StatusOK || !strings.HasPrefix(contentType, "application/json") {
				t.Fatalf("connector response = status %d content-type %q body %s", status, contentType, body)
			}
			if got := calls.Load(); got != 1 {
				t.Fatalf("upstream call count = %d, want exactly one", got)
			}
			if tc.valid {
				if tc.wantExactBody && body != tc.body {
					t.Fatalf("valid JSON-RPC error changed: got %q, want exact upstream body %q", body, tc.body)
				}
				if tc.wantCard == 12345 && !strings.Contains(body, "valid-upstream-result") {
					t.Fatalf("valid JSON-RPC success was not passed through: %s", body)
				}
			} else {
				assertRequiredUnknownOutcome(t, body)
				if strings.Contains(body, "upstream-success-marker") {
					t.Fatalf("invalid JSON-RPC response bytes escaped: %s", body)
				}
			}
			gate.cardMu.Lock()
			card := gate.currentCard
			gate.cardMu.Unlock()
			if card != tc.wantCard {
				t.Fatalf("current card = %d, want %d", card, tc.wantCard)
			}
			verifyRequiredAudit(t, auditor, auditPath, pub)
		})
	}
}

func assertRequiredUnknownOutcome(t *testing.T, body string) {
	t.Helper()
	var response struct {
		JSONRPC string          `json:"jsonrpc"`
		ID      json.RawMessage `json:"id"`
		Error   *struct {
			Code    int    `json:"code"`
			Message string `json:"message"`
		} `json:"error"`
	}
	if err := json.Unmarshal([]byte(body), &response); err != nil {
		t.Fatalf("decode uncertain outcome %q: %v", body, err)
	}
	if response.JSONRPC != "2.0" || string(response.ID) != "1" || response.Error == nil || response.Error.Code != -32603 {
		t.Fatalf("response = %+v, want JSON-RPC -32603 for request id 1", response)
	}
	if !strings.Contains(strings.ToLower(response.Error.Message), requiredOutcomeWarning) {
		t.Fatalf("error message %q must say the tool may have executed and must not be retried automatically", response.Error.Message)
	}
}

func verifyRequiredAudit(t *testing.T, auditor *audit.Auditor, path string, pub []byte) {
	t.Helper()
	if err := auditor.Close(); err != nil {
		t.Fatalf("close audit writer: %v", err)
	}
	n, err := audit.VerifyEd25519(path, pub)
	if err != nil {
		t.Fatalf("verify signed audit trail: %v", err)
	}
	if n < 2 {
		t.Fatalf("verified audit entries = %d, want dispatch and decision records", n)
	}
}

func TestHTTPListener_RequiredSSEResponsesRequireValidJSONRPCEnvelope(t *testing.T) {
	cases := []struct {
		name     string
		body     string
		valid    bool
		wantCard int
	}{
		{name: "both result and error", body: `{"jsonrpc":"2.0","id":1,"result":{},"error":{"code":-1,"message":"bad"}}`},
		{name: "empty method", body: `{"jsonrpc":"2.0","id":1,"method":"","result":{}}`},
		{name: "nonempty method", body: `{"jsonrpc":"2.0","id":1,"method":"tools/call","result":{}}`},
		{name: "null error", body: `{"jsonrpc":"2.0","id":1,"error":null}`},
		{name: "missing error code", body: `{"jsonrpc":"2.0","id":1,"error":{"message":"bad"}}`},
		{name: "missing error message", body: `{"jsonrpc":"2.0","id":1,"error":{"code":-1}}`},
		{name: "valid result", body: `{"jsonrpc":"2.0","id":1,"result":{}}`, valid: true, wantCard: 12345},
		{name: "valid multiline result", body: "{\n\"jsonrpc\":\"2.0\",\n\"id\":1,\n\"result\":{}\n}", valid: true, wantCard: 12345},
		{name: "valid error", body: `{"jsonrpc":"2.0","id":1,"error":{"code":-1,"message":"bad"}}`, valid: true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			auditor, auditPath, pub := newEd25519Auditor(t)
			defer auditor.Close()
			upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
				w.Header().Set("Content-Type", "text/event-stream")
				_, _ = io.WriteString(w, "data: "+strings.ReplaceAll(tc.body, "\n", "\ndata: ")+"\n\n")
			}))
			defer upstream.Close()
			gate := newGate(t, "agents:\n  mira:\n    mode: allow\n", nil, auditor)
			listener := httptest.NewServer(NewHTTPListener("127.0.0.1:0", upstream.URL, gate, log.New(io.Discard, "", 0)).WithRequiredAudit())
			defer listener.Close()
			status, body, contentType := post(t, listener.URL, requiredClaimCall)
			if status != http.StatusOK || !strings.HasPrefix(contentType, "text/event-stream") {
				t.Fatalf("response = %d %q %s", status, contentType, body)
			}
			if tc.valid {
				if body != "data: "+strings.ReplaceAll(tc.body, "\n", "\ndata: ")+"\n\n" {
					t.Fatalf("valid SSE response changed: %s", body)
				}
			} else {
				if strings.Contains(body, tc.body) {
					t.Fatalf("invalid SSE payload escaped: %s", body)
				}
				payload := strings.TrimSuffix(strings.TrimPrefix(body, "event: message\ndata: "), "\n\n")
				assertRequiredUnknownOutcome(t, payload)
			}
			gate.cardMu.Lock()
			card := gate.currentCard
			gate.cardMu.Unlock()
			if card != tc.wantCard {
				t.Fatalf("current card = %d, want %d", card, tc.wantCard)
			}
			verifyRequiredAudit(t, auditor, auditPath, pub)
		})
	}
}

// Non-2xx replies retain transport recovery signals without trusting their body.
func TestHTTPListener_RequiredNon2xxPreservesRecovery(t *testing.T) {
	for _, status := range []int{401, 404, 429, 500} {
		t.Run(http.StatusText(status), func(t *testing.T) {
			auditor, auditPath, pub := newEd25519Auditor(t)
			defer auditor.Close()
			headers := http.Header{
				"Www-Authenticate": {`Bearer realm="mcp"`, `Bearer error="invalid_token"`},
				"Retry-After":      {"60"},
				"Mcp-Session-Id":   {"recovery-session"},
			}
			upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
				for key, values := range headers {
					for _, value := range values {
						w.Header().Add(key, value)
					}
				}
				w.Header().Set("Content-Type", "text/plain")
				w.Header().Set("Content-Encoding", "gzip")
				w.Header().Set("Set-Cookie", "untrusted-cookie")
				w.Header().Set("X-Upstream-Private", "untrusted-header")
				w.WriteHeader(status)
				_, _ = io.WriteString(w, "unverified-upstream-body")
			}))
			defer upstream.Close()
			gate := newGate(t, "agents:\n  mira:\n    mode: allow\n", nil, auditor)
			listener := NewHTTPListener("127.0.0.1:0", upstream.URL, gate, log.New(io.Discard, "", 0)).WithRequiredAudit()
			server := httptest.NewServer(listener)
			defer server.Close()
			response, err := http.Post(server.URL, "application/json", strings.NewReader(requiredClaimCall))
			if err != nil {
				t.Fatal(err)
			}
			defer response.Body.Close()
			if response.StatusCode != status {
				t.Errorf("status = %d, want %d", response.StatusCode, status)
			}
			for key, want := range headers {
				if got := response.Header.Values(key); !slices.Equal(got, want) {
					t.Errorf("%s = %q, want %q", key, got, want)
				}
			}
			for _, key := range []string{"Content-Encoding", "Set-Cookie", "X-Upstream-Private"} {
				if got := response.Header.Get(key); got != "" {
					t.Errorf("untrusted %s escaped: %q", key, got)
				}
			}
			if got := response.Header.Get("Content-Type"); got != "application/json" {
				t.Errorf("Content-Type = %q", got)
			}
			data, err := io.ReadAll(response.Body)
			if err != nil {
				t.Fatal(err)
			}
			body := string(data)
			assertRequiredUnknownOutcome(t, body)
			if strings.Contains(body, "unverified-upstream-body") {
				t.Errorf("upstream body escaped: %s", body)
			}
			gate.cardMu.Lock()
			card := gate.currentCard
			gate.cardMu.Unlock()
			if card != 0 {
				t.Errorf("unverified reply committed card %d", card)
			}
			events := readAuditEvents(t, auditPath)
			if len(events) != 2 || events[0].Decision != "dispatch" || events[1].Decision != "allow" {
				t.Fatalf("audit decisions before close = %+v, want dispatch followed by allow", events)
			}
			verifyRequiredAudit(t, auditor, auditPath, pub)
		})
	}
}
