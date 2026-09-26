package proxy

import (
	"bufio"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"testing/iotest"
)

const discoveryResponse = `{"jsonrpc":"2.0","id":9007199254740993,"_meta":{"vendor":"envelope"},"result":{"tools":[{"name":"safe_tool","title":"Safe","inputSchema":{"type":"object"},"outputSchema":{"type":"object"},"annotations":{"readOnlyHint":true},"_meta":{"vendor":9007199254740993}},{"name":"blocked"}],"nextCursor":"page2","_meta":{"vendor":"result"}}}`
const discoveryRequest = `{"jsonrpc":"2.0","id":9007199254740993,"method":"tools/list"}`

func assertDiscovery(t *testing.T, got []byte) {
	t.Helper()
	if !json.Valid(got) {
		t.Fatalf("invalid JSON: %s", got)
	}
	for _, field := range []string{`"nextCursor":"page2"`, `"outputSchema"`, `"annotations"`, `"vendor":9007199254740993`, `"vendor":"envelope"`, `"vendor":"result"`, `"title":"Safe"`} {
		if !strings.Contains(string(got), field) {
			t.Errorf("missing %s in %s", field, got)
		}
	}
	if strings.Contains(string(got), `"blocked"`) {
		t.Errorf("denied tool leaked: %s", got)
	}
}

func TestToolDiscoveryPreservesMetadata(t *testing.T) {
	gate := newGate(t, "agents:\n  mira:\n    allow: [safe_tool]\n", nil, nil)
	assertDiscovery(t, gate.filterToolListResponse([]byte(discoveryResponse), 0))
	gate = newGate(t, "agents:\n  mira:\n    mode: deny\n", nil, nil)
	got := gate.filterToolListResponse([]byte(discoveryResponse), 0)
	if !strings.Contains(string(got), `"tools":[]`) {
		t.Errorf("want empty array: %s", got)
	}
}

func TestHTTPToolDiscoveryJSONAndSSE(t *testing.T) {
	for _, sse := range []bool{false, true} {
		t.Run(fmt.Sprint(sse), func(t *testing.T) {
			release := make(chan struct{})
			defer close(release)
			upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				w.Header().Set("Mcp-Session-Id", "test-session")
				if sse {
					w.Header().Set("Content-Type", "text/event-stream")
					io.WriteString(w, ": heartbeat\r\nid: notification\r\ndata: {\"jsonrpc\":\"2.0\",\"method\":\"notifications/tools/list_changed\"}\r\n\r\n")
					w.(http.Flusher).Flush()
					// Bare CR and multiline data are both legal SSE framing.
					data := strings.Replace(discoveryResponse, `"result":`, "\rdata: \"result\":", 1)
					io.WriteString(w, "id: page-1\revent: message\rdata: "+data+"\r\r")
					w.(http.Flusher).Flush()
					select {
					case <-release:
					case <-r.Context().Done():
					}
				} else {
					w.Header().Set("Content-Type", "application/json")
					w.Header().Set("Content-Length", fmt.Sprint(len(discoveryResponse)))
					io.WriteString(w, discoveryResponse)
				}
			}))
			defer upstream.Close()
			gate := newGate(t, "agents:\n  mira:\n    allow: [safe_tool]\n", nil, nil)
			listener := httptest.NewServer(NewHTTPListener("127.0.0.1:0", upstream.URL, gate, log.New(io.Discard, "", 0)))
			defer listener.Close()
			resp, err := http.Post(listener.URL, "application/json", strings.NewReader(discoveryRequest))
			if err != nil {
				t.Fatal(err)
			}
			defer resp.Body.Close()
			if resp.Header.Get("Mcp-Session-Id") != "test-session" {
				t.Error("session header lost")
			}
			if sse {
				reader := bufio.NewReader(resp.Body)
				first := readSSEEvent(t, reader)
				if !strings.Contains(first, "notifications/tools/list_changed") {
					t.Fatalf("notification lost: %s", first)
				}
				second := readSSEEvent(t, reader)
				assertDiscovery(t, []byte(strings.TrimSpace(strings.TrimPrefix(second, "data:"))))
			} else {
				body, err := io.ReadAll(resp.Body)
				if err != nil {
					t.Fatal(err)
				}
				assertDiscovery(t, body)
			}
		})
	}
}

func TestMalformedToolDiscoveryFailsClosed(t *testing.T) {
	gate := newGate(t, "agents:\n  mira:\n    mode: allow\n", nil, nil)
	for _, result := range []string{`null`, `{}`, `{"tools":null}`, `{"tools":[{"name":7}]}`, `{"tools":[null]}`} {
		got := gate.filterToolListResponse([]byte(`{"jsonrpc":"2.0","id":1,"result":`+result+`}`), 0)
		if !strings.Contains(string(got), `"error"`) {
			t.Errorf("malformed listing not rejected: %s", got)
		}
	}
}

func TestDiscoverySSEPreservesEventFieldsAndOtherMessages(t *testing.T) {
	gate := newGate(t, "agents:\n  mira:\n    allow: [safe_tool]\n", nil, nil)
	l := NewHTTPListener("127.0.0.1:0", "", gate, log.New(io.Discard, "", 0))
	other := `data: {"jsonrpc":"2.0","id":9007199254740992,"result":{"other":true}}`
	for _, ending := range []string{"\n", "\r", "\r\n"} {
		input := strings.Join([]string{"\ufeff: heartbeat", "data:", "", other, "", "id: page-1", "retry: 3000", "event: message", "data: " + discoveryResponse, "", ""}, ending)
		w := httptest.NewRecorder()
		if err := l.streamToolList(w, iotest.OneByteReader(strings.NewReader(input)), []byte(discoveryRequest), 0); err != nil {
			t.Fatal(err)
		}
		out := w.Body.String()
		for _, preserved := range []string{": heartbeat", other, "id: page-1", "retry: 3000", "event: message"} {
			if !strings.Contains(out, preserved) {
				t.Errorf("lost SSE field/message %q", preserved)
			}
		}
		if strings.Contains(out, `"blocked"`) || !strings.Contains(out, `"nextCursor":"page2"`) {
			t.Errorf("incorrect discovery filtering: %s", out)
		}
	}
}

func TestHTTPDiscoveryRejectsUninspectableResponses(t *testing.T) {
	gate := newGate(t, "agents:\n  mira:\n    mode: allow\n", nil, nil)
	l := NewHTTPListener("127.0.0.1:0", "", gate, log.New(io.Discard, "", 0))
	for _, tc := range []struct{ name, contentType, body string }{
		{"malformed", "application/json", `{"tools":["blocked"]`},
		{"mismatched-id", "application/json", strings.Replace(discoveryResponse, "9007199254740993", "9007199254740992", 1)},
		{"oversized-json", "application/json", strings.Repeat(" ", httpListenerBodyCap) + discoveryResponse},
		{"malformed-sse", "text/event-stream", "data: not-json-blocked\n\n"},
		{"oversized-sse", "text/event-stream", "data: " + strings.Repeat(" ", httpListenerBodyCap) + discoveryResponse + "\n\n"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			w := httptest.NewRecorder()
			resp := &http.Response{StatusCode: 200, Header: http.Header{"Content-Type": {tc.contentType}}, Body: io.NopCloser(strings.NewReader(tc.body))}
			l.forwardToolList(w, resp, []byte(discoveryRequest), json.RawMessage("9007199254740993"), 0)
			if strings.Contains(w.Body.String(), "blocked") || !strings.Contains(w.Body.String(), `"error"`) {
				t.Errorf("uninspectable response did not fail closed")
			}
		})
	}
}

func TestHTTPDiscoveryErrorUsesBodyPermittingStatus(t *testing.T) {
	gate := newGate(t, "agents:\n  mira:\n    allow: [safe_tool]\n", nil, nil)
	l := NewHTTPListener("127.0.0.1:0", "", gate, log.New(io.Discard, "", 0))
	for _, upstreamStatus := range []int{http.StatusNoContent, http.StatusNotModified} {
		t.Run(http.StatusText(upstreamStatus), func(t *testing.T) {
			w := httptest.NewRecorder()
			resp := &http.Response{StatusCode: upstreamStatus, Header: make(http.Header), Body: http.NoBody}
			l.forwardToolList(w, resp, []byte(discoveryRequest), json.RawMessage("9007199254740993"), 0)
			if w.Code != http.StatusOK || !strings.Contains(w.Body.String(), `"error"`) {
				t.Fatalf("want body-bearing JSON-RPC error, got status %d body %q", w.Code, w.Body.String())
			}
		})
	}
	t.Run("valid response preserves status", func(t *testing.T) {
		w := httptest.NewRecorder()
		resp := &http.Response{StatusCode: http.StatusCreated, Header: http.Header{"Content-Type": {"application/json"}}, Body: io.NopCloser(strings.NewReader(discoveryResponse))}
		l.forwardToolList(w, resp, []byte(discoveryRequest), json.RawMessage("9007199254740993"), 0)
		if w.Code != http.StatusCreated {
			t.Fatalf("want upstream status %d, got %d", http.StatusCreated, w.Code)
		}
		assertDiscovery(t, w.Body.Bytes())
	})
}
