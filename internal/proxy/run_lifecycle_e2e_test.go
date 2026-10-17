package proxy

import (
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/nocktechnologies/nockguard/internal/approval"
	"github.com/nocktechnologies/nockguard/internal/audit"
	"github.com/nocktechnologies/nockguard/internal/policy"
)

func TestSignedRunLifecycleCleanAndKilled(t *testing.T) {
	binary := buildBinary(t)
	keygenOut, err := exec.Command(binary, "keygen", "--print-env").Output()
	if err != nil {
		t.Fatal(err)
	}
	seed := envValue(t, string(keygenOut), "NOCKGUARD_AUDIT_ED25519_KEY")
	pubHex := envValue(t, string(keygenOut), "NOCKGUARD_AUDIT_ED25519_PUB")
	pub, err := audit.PublicKeyFromHex(pubHex)
	if err != nil {
		t.Fatal(err)
	}
	for _, killed := range []bool{false, true} {
		name := "clean"
		if killed {
			name = "killed"
		}
		t.Run(name, func(t *testing.T) {
			dir := t.TempDir()
			path := filepath.Join(dir, "audit.jsonl")
			policy := filepath.Join(dir, "policy.yaml")
			body := "agents:\n  demo:\n    mode: allow\naudit:\n  enabled: true\n  action_pairing: true\n  path: " + path + "\n  sign_ed25519_key_env: NOCKGUARD_AUDIT_ED25519_KEY\n"
			if err := os.WriteFile(policy, []byte(body), 0o600); err != nil {
				t.Fatal(err)
			}
			server := filepath.Join(dir, "server.sh")
			if err := os.WriteFile(server, []byte("#!/bin/sh\ncat >/dev/null\n"), 0o700); err != nil {
				t.Fatal(err)
			}
			cmd := exec.Command(binary, "proxy", "--upstream", server, "--agent", "demo", "--policy", policy)
			cmd.Env = append(os.Environ(), "NOCKGUARD_AUDIT_ED25519_KEY="+seed)
			if killed {
				in, err := cmd.StdinPipe()
				if err != nil {
					t.Fatal(err)
				}
				defer in.Close()
				if err := cmd.Start(); err != nil {
					t.Fatal(err)
				}
				deadline := time.Now().Add(5 * time.Second)
				for {
					// run/open is durable once the signed checkpoint covers it;
					// the trail line alone lands before the .hwm update.
					data, _ := os.ReadFile(path)
					if strings.Contains(string(data), `"run_event":"open"`) {
						if rows, count, err := audit.VerifyEd25519WithCheckpoint(path, pub); err == nil && rows > 0 && rows == count {
							break
						}
					}
					if time.Now().After(deadline) {
						_ = cmd.Process.Kill()
						t.Fatal("proxy never recorded durable run/open")
					}
					time.Sleep(20 * time.Millisecond)
				}
				if err := cmd.Process.Kill(); err != nil {
					t.Fatal(err)
				}
				_ = cmd.Wait()
			} else {
				cmd.Stdin = strings.NewReader(`{"jsonrpc":"2.0","id":1,"method":"initialize","params":{}}` + "\n")
				if out, err := cmd.CombinedOutput(); err != nil {
					t.Fatalf("clean proxy exit: %v: %s", err, out)
				}
			}
			rows, count, err := audit.VerifyEd25519WithCheckpoint(path, pub)
			if err != nil || rows != count {
				t.Fatalf("integrity rows=%d checkpoint=%d err=%v", rows, count, err)
			}
			data, err := os.ReadFile(path)
			if err != nil {
				t.Fatal(err)
			}
			now := time.Now()
			want := "LIMITED"
			if killed {
				want = "INCOMPLETE"
				now = now.Add(91 * time.Second)
			}
			if got := audit.AssessRuns(data, true, now)[0].Verdict; got != want {
				t.Fatalf("assessment = %s, want %s; trail=%s", got, want, data)
			}
		})
	}
}

type lifecycleTapApprover struct{}

func (lifecycleTapApprover) Ask(req approval.Request) approval.Verdict {
	req.OnRejectedTap("telegram-callback-unlisted-sender")
	if req.Tool == "ask_grant" {
		return approval.Verdict{Approved: true, Reason: "approved by test"}
	}
	return approval.Verdict{Reason: "denied by test"}
}

// While a run is active, recordAudit promotes every unversioned row to a v2
// decision for the run. The analyzer accepts an action-less v2 decision only
// for method-allow, method-deny and hide. Drive every other decision producer
// on the paired stdio path through one live run and require it to stay LIMITED,
// so each of those rows must carry its action_id.
func TestSignedRunDecisionRowsStayAttachedToActions(t *testing.T) {
	auditor, path, pub := newEd25519Auditor(t)
	defer auditor.Close()
	policyText := `audit:
  enabled: true
  action_pairing: true
agents:
  demo:
    mode: allow
    deny: ["denied_tool"]
    deny_methods: ["resources/list"]
    ask: ["ask_*"]
    block_params: ["forbidden-marker"]
    spend_cap:
      max_calls: 3
`
	engine, err := policy.LoadBytes([]byte(policyText))
	if err != nil {
		t.Fatal(err)
	}
	limiter, err := engine.LimiterFor(httpTestAgent)
	if err != nil {
		t.Fatal(err)
	}
	gate := newGate(t, policyText, limiter, auditor)
	gate.WithApprover(lifecycleTapApprover{})
	gate.agentOut = io.Discard
	if !gate.actionPairing || !gate.validator.Enabled() || !gate.limiter.Enabled() {
		t.Fatal("test policy must enable pairing, validation and the spend cap")
	}
	run := func(event string) {
		t.Helper()
		if err := auditor.RecordRequired(audit.Event{Agent: httpTestAgent, SchemaVersion: 2, RecordType: "run", RunID: gate.actionRunID, RunEvent: event}); err != nil {
			t.Fatal(err)
		}
	}
	run("open")
	gate.runActive.Store(true)

	oversized := strings.Repeat("x", maxRequestNameBytes+1)
	requests := []string{
		`{"jsonrpc":"2.0","id":1,"method":"initialize","params":{}}`,                           // method-allow
		`{"jsonrpc":"2.0","id":2,"method":"tools/list","params":{}}`,                           // hide on response
		`{"jsonrpc":"2.0","id":3,"method":"resources/list","params":{}}`,                       // method-deny
		callLine("4", "denied_tool", "a"),                                                      // deny
		callLine("5", "read_ok", "forbidden-marker"),                                           // block (validation)
		`{"jsonrpc":"2.0","id":6,"method":"tools/call","params":{}}`,                           // deny unextractable-name
		`{"jsonrpc":"2.0","id":7,"method":"tools/call","params":{"name":"` + oversized + `"}}`, // method-deny oversized
		callLine("8", "read_ok", "b"),                                                          // allow + dispatch
		callLine("9", "ask_grant", "c"),                                                        // block tap, approval-granted, state-write
		callLine("10", "ask_deny", "d"),                                                        // block tap, approval-denied
		callLine("8", "read_ok", "e"),                                                          // block duplicate-active-request-id
		callLine("11", "read_more", "f"),                                                       // ratelimit spend-cap
	}
	pending := &sync.Map{}
	if err := gate.agentToUpstream(strings.NewReader(strings.Join(requests, "\n")+"\n"), io.Discard, pending); err != nil {
		t.Fatal(err)
	}
	responses := []string{
		`{"jsonrpc":"2.0","id":1,"result":{}}`,
		`{"jsonrpc":"2.0","id":2,"result":{"tools":[{"name":"read_ok"},{"name":"denied_tool"}]}}`,
		`{"jsonrpc":"2.0","id":8,"result":{}}`,
		`{"jsonrpc":"2.0","id":9,"result":{}}`,
	}
	if err := gate.upstreamToAgent(strings.NewReader(strings.Join(responses, "\n")+"\n"), io.Discard, pending, nil); err != nil {
		t.Fatal(err)
	}
	gate.drainAudits()
	gate.runActive.Store(false)
	run("close")

	if rows, count, err := audit.VerifyEd25519WithCheckpoint(path, pub); err != nil || rows != count {
		t.Fatalf("integrity rows=%d checkpoint=%d err=%v", rows, count, err)
	}
	seen := map[string]bool{}
	for _, ev := range readAuditEvents(t, path) {
		if ev.SchemaVersion != 2 {
			t.Fatalf("legacy row in an active run: %+v", ev)
		}
		if ev.RecordType == "decision" {
			seen[ev.Decision] = true
			if ev.ActionID == "" && ev.Decision != "method-allow" && ev.Decision != "method-deny" && ev.Decision != "hide" {
				t.Errorf("action-less %s row: %+v", ev.Decision, ev)
			}
		}
	}
	for _, want := range []string{"method-allow", "method-deny", "hide", "deny", "block", "ratelimit", "allow", "dispatch", "approval-granted", "approval-denied", "state-write"} {
		if !seen[want] {
			t.Errorf("run did not exercise a %s row; decisions=%v", want, seen)
		}
	}
	got := audit.AssessRuns(mustRead(t, path), true, time.Now())
	if len(got) != 1 || got[0].Verdict != "LIMITED" {
		t.Fatalf("assessment = %+v, want one LIMITED run", got)
	}
}

// Close clears runActive and appends run/close while other goroutines may
// still be recording. No row may land as an unversioned v1 row in the run's
// span: a v1 row makes every run in the shared trail UNASSESSABLE.
func TestRunCloseConcurrentWithWritesLeavesNoLegacyRows(t *testing.T) {
	auditor, path, pub := newEd25519Auditor(t)
	// Start from a proxy whose run has already stopped, so writers never see
	// the pre-open state, in which rows are legacy by design.
	var current atomic.Pointer[StdioProxy]
	stopped := newActionPairingGate(t, auditor, "")
	stopped.runStopping.Store(true)
	current.Store(stopped)
	// Writers record a row the v2 writer rejects without I/O (empty decision)
	// but a v1 append would accept. They loop fast enough to straddle each
	// close transition and expose any row that escapes the run as v1.
	var writers sync.WaitGroup
	stop := make(chan struct{})
	for w := 0; w < 8; w++ {
		writers.Add(1)
		go func() {
			defer writers.Done()
			for {
				select {
				case <-stop:
					return
				default:
				}
				_ = current.Load().recordAudit(audit.Event{Agent: httpTestAgent, Tool: "initialize"})
			}
		}()
	}
	runs, passes := 0, 0
	for deadline := time.Now().Add(3 * time.Second); time.Now().Before(deadline); passes++ {
		// Each pass is a fresh proxy run on the shared trail, as after a
		// restart. The previous proxy stays closed for straggling writers.
		// Writers' rows are refused as v2, so only every 20th pass needs a
		// durable open and close; the rest exercise the transition cheaply.
		gate := newActionPairingGate(t, auditor, "")
		durable := passes%20 == 0
		if durable {
			if err := auditor.RecordRequired(audit.Event{Agent: httpTestAgent, SchemaVersion: 2, RecordType: "run", RunID: gate.actionRunID, RunEvent: "open"}); err != nil {
				t.Fatal(err)
			}
			runs++
		}
		gate.runActive.Store(true)
		current.Store(gate)
		// Mirror Run: input stops first, then the deferred close clears
		// runActive and appends run/close.
		gate.runStopping.Store(true)
		gate.runActive.Store(false)
		if durable {
			if err := auditor.RecordRequired(audit.Event{Agent: httpTestAgent, SchemaVersion: 2, RecordType: "run", RunID: gate.actionRunID, RunEvent: "close"}); err != nil {
				t.Fatal(err)
			}
		}
	}
	close(stop)
	writers.Wait()
	if err := auditor.Close(); err != nil {
		t.Fatal(err)
	}
	if rows, count, err := audit.VerifyEd25519WithCheckpoint(path, pub); err != nil || rows != count {
		t.Fatalf("integrity rows=%d checkpoint=%d err=%v", rows, count, err)
	}
	for _, ev := range readAuditEvents(t, path) {
		if ev.SchemaVersion != 2 {
			t.Fatalf("v1 row written during a run close (%d transitions): %+v", passes, ev)
		}
	}
	got := audit.AssessRuns(mustRead(t, path), true, time.Now())
	if len(got) != runs {
		t.Fatalf("assessed %d runs, want %d", len(got), runs)
	}
	for _, run := range got {
		if run.Verdict != "LIMITED" {
			t.Fatalf("run %+v, want LIMITED", run)
		}
	}
	t.Logf("%d transitions, %d durable runs closed under concurrent writes", passes, runs)
}
