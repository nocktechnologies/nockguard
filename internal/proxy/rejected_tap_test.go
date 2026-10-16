package proxy

import (
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/nocktechnologies/nockguard/internal/approval"
	"github.com/nocktechnologies/nockguard/internal/forward"
	"github.com/nocktechnologies/nockguard/internal/policy"
	"github.com/nocktechnologies/nockguard/internal/trust"
)

type repeatedTapApprover struct{ taps int }

func (a repeatedTapApprover) Ask(req approval.Request) approval.Verdict {
	for i := 0; i < a.taps; i++ {
		req.OnRejectedTap("telegram-callback-unlisted-sender")
	}
	return approval.Verdict{Reason: "timeout"}
}

type heldTapApprover struct{ release <-chan struct{} }

func (a heldTapApprover) Ask(req approval.Request) approval.Verdict {
	req.OnRejectedTap("telegram-callback-unlisted-sender")
	<-a.release
	return approval.Verdict{Reason: "timeout"}
}

func TestFirstRejectedTapAlertPrecedesApprovalEnd(t *testing.T) {
	alerts := make(chan string, 2)
	ops := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var payload struct {
			Severity string `json:"severity"`
			DataBlob struct {
				Decision string `json:"decision"`
			} `json:"data_blob"`
		}
		if err := json.NewDecoder(r.Body).Decode(&payload); err != nil {
			t.Error(err)
		}
		if payload.DataBlob.Decision == "block" {
			alerts <- payload.Severity
		}
		w.WriteHeader(http.StatusCreated)
	}))
	defer ops.Close()
	auditor, _, _ := newEd25519Auditor(t)
	gate := newGate(t, "agents:\n  demo:\n    ask: [deploy]\n", nil, auditor)
	release := make(chan struct{})
	gate.WithApprover(heldTapApprover{release})
	gate.forwarder = forward.New(forward.Config{BaseURL: ops.URL})
	gate.forwarder.Start()
	seq := gate.reserveAuditSequence()
	done := make(chan struct{})
	go func() {
		gate.approveAsk("deploy", nil, nil, policy.Decision{Reason: "ask-rule"}, seq)
		close(done)
	}()
	var severity string
	select {
	case severity = <-alerts:
	case <-time.After(2 * time.Second):
	}
	select {
	case <-done:
		t.Error("approval ended before the held tap was released")
	default:
	}
	close(release)
	<-done
	gate.forwarder.Stop()
	if err := auditor.Close(); err != nil {
		t.Fatal(err)
	}
	if severity != "high" {
		t.Errorf("alert before approval ended = %q, want high", severity)
	}
}

func TestRejectedTapAuditIsBoundedOnHTTPApprovalPath(t *testing.T) {
	control, err := trust.New(trust.Config{Enabled: true, Agent: "demo", Path: filepath.Join(t.TempDir(), "control-trust.json")}, trust.WithClock(func() time.Time { return time.Unix(1000, 0) }))
	if err != nil {
		t.Fatal(err)
	}
	outcome, ok := trust.DecisionToOutcome("approval-denied")
	if !ok {
		t.Fatal("approval-denied must have a trust outcome")
	}
	control.ApplyOutcome(outcome)
	wantTrustScore := control.Score()
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
			acc, err := trust.New(trust.Config{Enabled: true, Agent: "demo", Path: filepath.Join(t.TempDir(), "trust.json")}, trust.WithClock(func() time.Time { return time.Unix(1000, 0) }))
			if err != nil {
				t.Fatal(err)
			}
			gate.WithTrust(acc)
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
					if strings.Contains(ev.Reason, "rejected-taps=") {
						t.Errorf("block row should only report the first tap: %q", ev.Reason)
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
			if got := acc.Score(); got != wantTrustScore {
				t.Errorf("third-party taps changed agent trust: got %.2f, approval-denied control %.2f", got, wantTrustScore)
			}
		})
	}
}
