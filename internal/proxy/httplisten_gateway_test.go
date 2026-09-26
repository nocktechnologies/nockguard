package proxy

import (
	"io"
	"log"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
)

func TestGatewayUpstreamCredentialAndRedirectBoundary(t *testing.T) {
	var leaked atomic.Bool
	destination := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { leaked.Store(true) }))
	defer destination.Close()
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "" || r.Header.Get("X-Agent-Token") != "test-gateway-service-token" {
			t.Error("caller credentials forwarded or service token missing")
		}
		http.Redirect(w, r, destination.URL, http.StatusTemporaryRedirect)
	}))
	defer upstream.Close()
	gate := newGate(t, "agents:\n  mira:\n    mode: allow\n", nil, nil)
	l := NewHTTPListener("", upstream.URL, gate, log.New(io.Discard, "", 0)).WithUpstreamAgentToken("test-gateway-service-token")
	r := httptest.NewRequest("POST", "http://localhost/mcp", strings.NewReader(toolCall("1", "read_item")))
	r.Header.Set("Authorization", "Bearer caller-credential")
	w := httptest.NewRecorder()
	l.ServeHTTP(w, r)
	if leaked.Load() || w.Code != 307 {
		t.Fatal("gateway followed upstream redirect")
	}
}
