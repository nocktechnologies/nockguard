package proxy

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"

	"github.com/nocktechnologies/nockguard/internal/audit"
)

func TestRequestNameLimit(t *testing.T) {
	for _, transport := range []string{"stdio", "stdio-pairing", "http"} {
		for _, kind := range []string{"method", "tool"} {
			for _, size := range []int{256, 257, 10_000_000} {
				t.Run(fmt.Sprintf("%s/%s/%d", transport, kind, size), func(t *testing.T) {
					auditor, path, pub := newEd25519Auditor(t)
					defer auditor.Close()
					gate := newGate(t, "agents:\n  demo:\n    mode: allow\n", nil, auditor)
					if transport == "stdio-pairing" {
						gate = newActionPairingGate(t, auditor, "")
					}
					name := strings.Repeat("x", size)
					request := map[string]any{"jsonrpc": "2.0", "id": 1, "method": name}
					if kind == "tool" {
						request["method"] = "tools/call"
						request["params"] = map[string]any{"name": name}
					}
					body, err := json.Marshal(request)
					if err != nil {
						t.Fatal(err)
					}
					var forwarded bool
					var reply string
					if strings.HasPrefix(transport, "stdio") {
						var upstream, output bytes.Buffer
						gate.agentOut = &output
						if err := gate.agentToUpstream(strings.NewReader(string(body)+"\n"), &upstream, &sync.Map{}); err != nil {
							t.Fatal(err)
						}
						forwarded = upstream.Len() > 0
						reply = output.String()
					} else {
						upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
							forwarded = true
							w.Header().Set("Content-Type", "application/json")
							io.WriteString(w, `{"jsonrpc":"2.0","id":1,"result":{}}`)
						}))
						defer upstream.Close()
						listener := httptest.NewServer(NewHTTPListener("127.0.0.1:0", upstream.URL, gate, log.New(io.Discard, "", 0)))
						defer listener.Close()
						_, reply, _ = post(t, listener.URL, string(body))
					}
					oversized := size > 256
					if forwarded == oversized {
						t.Errorf("forwarded=%v, oversized=%v", forwarded, oversized)
					}
					if oversized && !strings.Contains(reply, `"code":-32600`) {
						t.Errorf("missing invalid-request error")
					}
					if err := auditor.Close(); err != nil {
						t.Fatal(err)
					}
					if _, err := audit.VerifyEd25519(path, pub); err != nil {
						t.Errorf("trail verification: %v", err)
					}
					if oversized {
						events := readAuditEvents(t, path)
						if len(events) != 1 {
							t.Fatalf("got %d events, want one refusal", len(events))
						}
						ev := events[0]
						if len(ev.Tool) > 64 || !strings.Contains(ev.Reason, fmt.Sprintf("bytes=%d", size)) || !strings.Contains(ev.Reason, name[:32]) {
							t.Error("refusal must contain bounded prefix and byte length")
						}
					}
				})
			}
		}
	}
}

func TestOversizedNameBeforeDuplicateActionAudit(t *testing.T) {
	auditor, path, pub := newEd25519Auditor(t)
	defer auditor.Close()
	gate := newActionPairingGate(t, auditor, "")
	var upstream, output bytes.Buffer
	gate.agentOut = &output
	pending := &sync.Map{}
	if err := gate.agentToUpstream(strings.NewReader(toolCall("1", "read_file")+"\n"), &upstream, pending); err != nil {
		t.Fatal(err)
	}
	upstream.Reset()
	// Reuse the active ID: this branch must not audit the full rejected name.
	name := strings.Repeat("x", 257)
	if err := gate.agentToUpstream(strings.NewReader(toolCall("1", name)+"\n"), &upstream, pending); err != nil {
		t.Fatal(err)
	}
	if upstream.Len() != 0 || !strings.Contains(output.String(), `"code":-32600`) {
		t.Fatal("oversized duplicate call was not refused")
	}
	events := readAuditEvents(t, path)
	if len(events) != 2 || events[1].Tool != name[:32] || strings.Contains(events[1].Reason, name) {
		t.Fatal("expected dispatch followed by one bounded refusal")
	}
	if _, err := audit.VerifyEd25519(path, pub); err != nil {
		t.Fatal(err)
	}
}

func TestOversizedMultibyteNotificationName(t *testing.T) {
	for _, kind := range []string{"method", "tool"} {
		t.Run(kind, func(t *testing.T) {
			auditor, path, pub := newEd25519Auditor(t)
			defer auditor.Close()
			gate := newGate(t, "agents:\n  demo:\n    mode: allow\n", nil, auditor)
			// 129 characters, 257 bytes; the diagnostic prefix splits a UTF-8 rune.
			name := "a" + strings.Repeat("é", 128)
			request := map[string]any{"jsonrpc": "2.0", "method": name}
			if kind == "tool" {
				request["method"] = "tools/call"
				request["params"] = map[string]any{"name": name}
			}
			body, err := json.Marshal(request)
			if err != nil {
				t.Fatal(err)
			}
			forwarded, reply, err := gate.Probe(body)
			if err != nil || forwarded || len(reply) != 0 {
				t.Fatalf("notification: forwarded=%v reply=%s err=%v", forwarded, reply, err)
			}
			if _, err := audit.VerifyEd25519(path, pub); err != nil {
				t.Fatal(err)
			}
			events := readAuditEvents(t, path)
			if len(events) != 1 || !strings.Contains(events[0].Reason, "bytes=257") {
				t.Fatal("missing bounded byte-length refusal")
			}
		})
	}
}
