package proxy

import (
	"io"
	"log"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/nocktechnologies/nockguard/internal/audit"
)

const requiredDiscoveryPolicy = `agents:
  mira:
    mode: deny
    allow: [read_safe]
`

const requiredDiscoveryRequest = `{"jsonrpc":"2.0","id":1,"method":"tools/list"}`

const requiredDiscoveryResult = `{"jsonrpc":"2.0","id":1,"result":{"tools":[{"name":"read_safe"},{"name":"hidden_write"}]}}`

func TestHTTPListener_RequiredDiscoveryAuditBeforeResult(t *testing.T) {
	for _, tc := range []struct {
		name string
		sse  bool
		fail bool
	}{
		{name: "json audit failure", fail: true},
		{name: "sse audit failure", sse: true, fail: true},
		{name: "json signed positive control"},
		{name: "sse signed positive control", sse: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			auditor, auditPath, pub := newEd25519Auditor(t)
			defer auditor.Close()
			var upstreamCalls atomic.Int32
			upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				upstreamCalls.Add(1)
				if tc.fail {
					// Force the required audit write to fail only after the upstream
					// has received and answered the discovery request.
					if err := auditor.Close(); err != nil {
						t.Errorf("close auditor in upstream: %v", err)
					}
				}
				if tc.sse {
					w.Header().Set("Content-Type", "text/event-stream")
					_, _ = io.WriteString(w, "event: message\ndata: "+requiredDiscoveryResult+"\n\n")
					if f, ok := w.(http.Flusher); ok {
						f.Flush()
					}
					return
				}
				w.Header().Set("Content-Type", "application/json")
				_, _ = io.WriteString(w, requiredDiscoveryResult)
			}))
			defer upstream.Close()

			gate := newGate(t, requiredDiscoveryPolicy, nil, auditor)
			listener := httptest.NewServer(NewHTTPListener("127.0.0.1:0", upstream.URL, gate, log.New(io.Discard, "", 0)).WithRequiredAudit())
			defer listener.Close()

			_, body, _ := post(t, listener.URL, requiredDiscoveryRequest)
			if tc.fail {
				if !strings.Contains(body, auditAfterForwardError) {
					t.Fatalf("response %q does not report the failed post-forward audit", body)
				}
				if strings.Contains(body, "read_safe") || strings.Contains(body, "hidden_write") {
					t.Fatalf("response leaked the discovery result after audit failure: %s", body)
				}
				if err := auditor.RequiredError(); err == nil {
					t.Fatal("discovery audit failure was not latched")
				}

				_, nextBody, _ := post(t, listener.URL, requiredDiscoveryRequest)
				if !strings.Contains(nextBody, "audit") {
					t.Fatalf("subsequent request did not surface the latched audit failure: %s", nextBody)
				}
				if got := upstreamCalls.Load(); got != 1 {
					t.Fatalf("upstream calls after latched failure = %d, want 1", got)
				}
				return
			}

			if !strings.Contains(body, "read_safe") || strings.Contains(body, "hidden_write") {
				t.Fatalf("healthy discovery response was not filtered: %s", body)
			}
			if got := upstreamCalls.Load(); got != 1 {
				t.Fatalf("healthy discovery upstream calls = %d, want 1", got)
			}
			if err := auditor.Close(); err != nil {
				t.Fatal(err)
			}
			if n, err := audit.VerifyEd25519(auditPath, pub); err != nil || n != 1 {
				t.Fatalf("VerifyEd25519() = (%d, %v), want one durable hide row", n, err)
			}
			events := readAuditEvents(t, auditPath)
			if len(events) != 1 || events[0].Tool != "hidden_write" || events[0].Decision != "hide" {
				t.Fatalf("audit events = %+v, want hidden_write hide row before result delivery", events)
			}
		})
	}
}
