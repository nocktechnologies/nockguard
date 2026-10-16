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

func TestHTTPListener_RequestBoundary(t *testing.T) {
	var calls atomic.Int32
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls.Add(1)
		w.Header().Set("Content-Type", "application/json")
		io.WriteString(w, `{"jsonrpc":"2.0","id":1,"result":{}}`)
	}))
	defer upstream.Close()
	for _, tc := range []struct {
		name, host            string
		origins, contentTypes []string
		status                int
	}{
		{name: "hostile host", host: "other.example:8790", contentTypes: []string{"application/json"}, status: http.StatusMisdirectedRequest},
		{name: "host suffix", host: "localhost.other.example:8790", contentTypes: []string{"application/json"}, status: http.StatusMisdirectedRequest},
		{name: "cross site origin", host: "127.0.0.1:8790", origins: []string{"https://other.example"}, contentTypes: []string{"application/json"}, status: http.StatusForbidden},
		{name: "empty origin", host: "127.0.0.1:8790", origins: []string{""}, contentTypes: []string{"application/json"}, status: http.StatusForbidden},
		{name: "null origin", host: "127.0.0.1:8790", origins: []string{"null"}, contentTypes: []string{"application/json"}, status: http.StatusForbidden},
		{name: "duplicate origins", host: "127.0.0.1:8790", origins: []string{"http://127.0.0.1:8790", "https://other.example"}, contentTypes: []string{"application/json"}, status: http.StatusForbidden},
		{name: "invalid host port", host: "127.0.0.1:bad", contentTypes: []string{"application/json"}, status: http.StatusMisdirectedRequest},
		{name: "form", host: "127.0.0.1:8790", contentTypes: []string{"application/x-www-form-urlencoded"}, status: http.StatusUnsupportedMediaType},
		{name: "plain text", host: "127.0.0.1:8790", contentTypes: []string{"text/plain"}, status: http.StatusUnsupportedMediaType},
		{name: "missing content type", host: "127.0.0.1:8790", status: http.StatusUnsupportedMediaType},
		{name: "malformed content type", host: "127.0.0.1:8790", contentTypes: []string{"application/json; charset"}, status: http.StatusUnsupportedMediaType},
		{name: "duplicate content types", host: "127.0.0.1:8790", contentTypes: []string{"application/json", "text/plain"}, status: http.StatusUnsupportedMediaType},
		{name: "IPv4 JSON", host: "127.0.0.1:8790", contentTypes: []string{"application/json"}, status: http.StatusOK},
		{name: "localhost JSON", host: "localhost:8790", contentTypes: []string{"application/json; charset=utf-8"}, status: http.StatusOK},
		{name: "IPv6 no port", host: "[::1]", contentTypes: []string{"application/json"}, status: http.StatusOK},
		{name: "IPv6 non-loopback", host: "[::2]", contentTypes: []string{"application/json"}, status: http.StatusMisdirectedRequest},
		{name: "bracketed hostname", host: "[localhost]", contentTypes: []string{"application/json"}, status: http.StatusMisdirectedRequest},
		{name: "bracketed IPv4", host: "[127.0.0.1]", contentTypes: []string{"application/json"}, status: http.StatusMisdirectedRequest},
		{name: "IPv6 bare", host: "::1", contentTypes: []string{"application/json"}, status: http.StatusMisdirectedRequest},
		{name: "localhost no port", host: "localhost", contentTypes: []string{"application/json"}, status: http.StatusOK},
		{name: "IPv6 JSON", host: "[::1]:8790", contentTypes: []string{"application/json"}, status: http.StatusOK},
	} {
		t.Run(tc.name, func(t *testing.T) {
			gate := newGate(t, "agents:\n  demo:\n    mode: allow\n", nil, nil)
			listener := NewHTTPListener("127.0.0.1:8790", upstream.URL, gate, log.New(io.Discard, "", 0))
			r := httptest.NewRequest(http.MethodPost, "http://127.0.0.1:8790/mcp", strings.NewReader(toolCall("1", "read_item")))
			r.Host = tc.host
			r.Header["Origin"] = tc.origins
			r.Header["Content-Type"] = tc.contentTypes
			before := calls.Load()
			w := httptest.NewRecorder()
			listener.ServeHTTP(w, r)
			if w.Code != tc.status {
				t.Fatalf("status = %d, want %d: %s", w.Code, tc.status, w.Body.String())
			}
			wantCalls := before
			if tc.status == http.StatusOK {
				wantCalls++
			}
			if got := calls.Load(); got != wantCalls {
				t.Fatalf("upstream calls = %d, want %d", got, wantCalls)
			}
		})
	}
}
