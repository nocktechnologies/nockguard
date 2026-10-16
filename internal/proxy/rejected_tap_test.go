package proxy

import (
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/nocktechnologies/nockguard/internal/approval"
	"github.com/nocktechnologies/nockguard/internal/forward"
)

type repeatedTapApprover struct{ taps int }

func (a repeatedTapApprover) Ask(req approval.Request) approval.Verdict {
	for i := 0; i < a.taps; i++ {
		req.OnRejectedTap("telegram-callback-unlisted-sender")
	}
	return approval.Verdict{Reason: "timeout"}
}

func TestRejectedTapAuditIsBoundedOnHTTPApprovalPath(t *testing.T) {
	for _, taps := range []int{0, 1, 10} {
		t.Run(fmt.Sprintf("taps=%d", taps), func(t *testing.T) {
			var posts []map[string]any
			ops := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				var payload map[string]any
				if err := json.NewDecoder(r.Body).Decode(&payload); err != nil {
					t.Error(err)
				}
				posts = append(posts, payload)
				w.WriteHeader(http.StatusCreated)
			}))
			defer ops.Close()
			auditor, path, _ := newEd25519Auditor(t)
			gate := newGate(t, "agents:\n  demo:\n    ask: [deploy]\n", nil, auditor).WithApprover(repeatedTapApprover{taps})
			gate.forwarder = forward.New(forward.Config{BaseURL: ops.URL})
			gate.forwarder.Start()
			listener := NewHTTPListener("127.0.0.1:0", "http://127.0.0.1:1", gate, log.New(io.Discard, "", 0))
			srv := httptest.NewServer(listener)
			defer srv.Close()
			status, body, _ := post(t, srv.URL, toolCall("1", "deploy"))
			if status != 200 || !strings.Contains(body, "denied by approval gate") {
				t.Fatalf("rejected call: status=%d body=%s", status, body)
			}
			if err := auditor.Close(); err != nil {
				t.Fatal(err)
			}
			gate.forwarder.Stop()
			var blocks, denied int
			for _, ev := range readAuditEvents(t, path) {
				switch ev.Decision {
				case "block":
					blocks++
					if !strings.Contains(ev.Reason, "telegram-callback-unlisted-sender") {
						t.Errorf("block reason = %q", ev.Reason)
					}
					if taps > 1 && !strings.Contains(ev.Reason, "rejected-taps=10") {
						t.Errorf("missing tap count: %q", ev.Reason)
					}
				case "approval-denied":
					denied++
				}
			}
			wantBlocks := 0
			if taps > 0 {
				wantBlocks = 1
			}
			if blocks != wantBlocks || denied != 1 {
				t.Errorf("block=%d denied=%d, want block=%d denied=1", blocks, denied, wantBlocks)
			}
			var highBlocks int
			for _, payload := range posts {
				blob, _ := payload["data_blob"].(map[string]any)
				if blob["decision"] == "block" {
					highBlocks++
					if payload["severity"] != "high" {
						t.Errorf("block severity = %v", payload["severity"])
					}
				}
			}
			if highBlocks != wantBlocks {
				t.Errorf("high block alerts = %d, want %d", highBlocks, wantBlocks)
			}
		})
	}
}
