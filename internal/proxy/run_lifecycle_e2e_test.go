package proxy

import (
	"crypto/ed25519"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
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
			if got := audit.AssessRuns(data, true, now); len(got) != 1 || got[0].Verdict != want {
				t.Fatalf("assessment = %+v, want one %s run; trail=%s", got, want, data)
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
		callLine("9", "ask_grant", "c"),                                                        // block tap, approval-granted
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
	for _, want := range []string{"method-allow", "method-deny", "hide", "deny", "block", "ratelimit", "allow", "dispatch", "approval-granted", "approval-denied"} {
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

// With action pairing off there is no run lifecycle: after the upstream leader
// exits, the proxy must keep forwarding client input during the output drain
// and exit cleanly on client EOF, exactly as before run lifecycle existed.
func TestLegacyProxyKeepsReadingInputAfterUpstreamLeaderExits(t *testing.T) {
	script := filepath.Join(t.TempDir(), "paced-output.sh")
	// The descendant keeps the upstream's stdin, so input forwarded after
	// the leader exits still reaches a reader.
	body := "#!/bin/bash\n(sleep 0.2; echo aaaa; read -r line && echo GOT; for i in {1..5}; do echo aaaa; sleep 0.1; done; echo DONE) <&0 &\nexit 0\n"
	if err := os.WriteFile(script, []byte(body), 0o755); err != nil {
		t.Fatal(err)
	}
	in, out, exited, stderr := runWithOpenStdinStderr(t, "bash "+script)
	// The first descendant line arrives after the leader has exited.
	if !out.Scan() || out.Text() != "aaaa" {
		t.Fatalf("first output line %q, err %v", out.Text(), out.Err())
	}
	if _, err := io.WriteString(in, `{"jsonrpc":"2.0","method":"notifications/initialized"}`+"\n"); err != nil {
		t.Fatal(err)
	}
	_ = in.Close()
	var last string
	forwarded := false
	for out.Scan() {
		last = out.Text()
		forwarded = forwarded || last == "GOT"
	}
	if last != "DONE" || !forwarded {
		t.Fatalf("output truncated or input not forwarded; last line %q, forwarded %v", last, forwarded)
	}
	select {
	case err := <-exited:
		if err != nil {
			t.Fatalf("legacy proxy exit = %v; stderr:\n%s", err, stderr.String())
		}
	case <-time.After(5 * time.Second):
		t.Fatal("proxy did not exit")
	}
	if strings.Contains(stderr.String(), "audit run is shutting down") {
		t.Fatalf("legacy proxy reported run shutdown:\n%s", stderr.String())
	}
}

// startPairedProxy starts the binary with a signed, paired policy and returns
// the command, the client's stdin, and the trail path and public key.
func startPairedProxy(t *testing.T, upstreamBody string) (*exec.Cmd, io.WriteCloser, string, ed25519.PublicKey) {
	t.Helper()
	return startPairedProxyWith(t, pairedProxyOptions{upstreamBody: upstreamBody})
}

type pairedProxyOptions struct {
	upstreamBody string    // script written as the upstream server
	upstreamArg  string    // overrides --upstream when set
	policyExtra  string    // extra lines under the demo agent
	env          []string  // extra proxy environment
	stderr       io.Writer // proxy stderr when set
}

func startPairedProxyWith(t *testing.T, opts pairedProxyOptions) (*exec.Cmd, io.WriteCloser, string, ed25519.PublicKey) {
	t.Helper()
	binary := buildBinary(t)
	keygenOut, err := exec.Command(binary, "keygen", "--print-env").Output()
	if err != nil {
		t.Fatal(err)
	}
	seed := envValue(t, string(keygenOut), "NOCKGUARD_AUDIT_ED25519_KEY")
	pub, err := audit.PublicKeyFromHex(envValue(t, string(keygenOut), "NOCKGUARD_AUDIT_ED25519_PUB"))
	if err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	path := filepath.Join(dir, "audit.jsonl")
	policyPath := filepath.Join(dir, "policy.yaml")
	body := "agents:\n  demo:\n    mode: allow\n" + opts.policyExtra + "audit:\n  enabled: true\n  action_pairing: true\n  path: " + path + "\n  sign_ed25519_key_env: NOCKGUARD_AUDIT_ED25519_KEY\n"
	if err := os.WriteFile(policyPath, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	server := opts.upstreamArg
	if server == "" {
		server = filepath.Join(dir, "server.sh")
		if err := os.WriteFile(server, []byte(opts.upstreamBody), 0o700); err != nil {
			t.Fatal(err)
		}
	}
	cmd := exec.Command(binary, "proxy", "--upstream", server, "--agent", "demo", "--policy", policyPath)
	cmd.Env = append(append(os.Environ(), "NOCKGUARD_AUDIT_ED25519_KEY="+seed), opts.env...)
	cmd.Stderr = opts.stderr
	in, err := cmd.StdinPipe()
	if err != nil {
		t.Fatal(err)
	}
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = in.Close(); _ = cmd.Process.Kill() })
	return cmd, in, path, pub
}

// waitForTrail polls until the trail contains marker and the signed
// checkpoint covers every row.
func waitForTrail(t *testing.T, path string, pub ed25519.PublicKey, marker string) {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for {
		data, _ := os.ReadFile(path)
		if strings.Contains(string(data), marker) {
			if rows, count, err := audit.VerifyEd25519WithCheckpoint(path, pub); err == nil && rows > 0 && rows == count {
				return
			}
		}
		if time.Now().After(deadline) {
			t.Fatalf("trail never recorded %s: %s", marker, data)
		}
		time.Sleep(20 * time.Millisecond)
	}
}

// assertClosedWithUnknown checks a dispatched call got outcome_unknown, the
// run has a signed close, and the run assesses LIMITED.
func assertClosedWithUnknown(t *testing.T, path string, pub ed25519.PublicKey) {
	t.Helper()
	if rows, count, err := audit.VerifyEd25519WithCheckpoint(path, pub); err != nil || rows != count {
		t.Fatalf("integrity rows=%d checkpoint=%d err=%v", rows, count, err)
	}
	data := mustRead(t, path)
	for _, want := range []string{`"decision":"dispatch"`, `"observation":"outcome_unknown"`, `"run_event":"close"`} {
		if !strings.Contains(string(data), want) {
			t.Fatalf("trail lacks %s:\n%s", want, data)
		}
	}
	if got := audit.AssessRuns(data, true, time.Now()); len(got) != 1 || got[0].Verdict != "LIMITED" {
		t.Fatalf("assessment = %+v, want one LIMITED run; trail:\n%s", got, data)
	}
}

// The upstream exits while the client keeps stdin open. The proxy must stop
// accepting input, record outcome_unknown for the dispatched call and close
// the run without waiting on the client's open stdin.
func TestPairedRunClosesWhenUpstreamExitsWithClientStdinOpen(t *testing.T) {
	cmd, in, path, pub := startPairedProxy(t, "#!/bin/sh\nread -r line\nexit 0\n")
	waitForTrail(t, path, pub, `"run_event":"open"`)
	if _, err := io.WriteString(in, callLine("1", "read_private", "x")+"\n"); err != nil {
		t.Fatal(err)
	}
	exited := make(chan error, 1)
	go func() { exited <- cmd.Wait() }()
	select {
	case <-exited:
	case <-time.After(5 * time.Second):
		t.Fatal("proxy did not exit after the upstream exited")
	}
	assertClosedWithUnknown(t, path, pub)
}

// SIGTERM with a dispatched call in flight runs the same bounded drain:
// outcome_unknown for the call, then run/close, within a hard bound.
func TestPairedRunClosesOnSignalWithInFlightDispatch(t *testing.T) {
	cmd, in, path, pub := startPairedProxy(t, "#!/bin/sh\ncat >/dev/null\n")
	waitForTrail(t, path, pub, `"run_event":"open"`)
	if _, err := io.WriteString(in, callLine("1", "read_private", "x")+"\n"); err != nil {
		t.Fatal(err)
	}
	waitForTrail(t, path, pub, `"decision":"dispatch"`)
	exited := make(chan error, 1)
	go func() { exited <- cmd.Wait() }()
	started := time.Now()
	if err := cmd.Process.Signal(syscall.SIGTERM); err != nil {
		t.Fatal(err)
	}
	select {
	case <-exited:
	case <-time.After(5 * time.Second):
		t.Fatal("proxy did not exit after SIGTERM")
	}
	if elapsed := time.Since(started); elapsed > 4*time.Second {
		t.Fatalf("signal shutdown took %s", elapsed)
	}
	assertClosedWithUnknown(t, path, pub)
}

// A paired proxy whose upstream cannot be launched never accepted input, so it
// must not leave an open run that later reads INCOMPLETE.
func TestPairedRunNotLeftOpenWhenUpstreamFailsToStart(t *testing.T) {
	missing := filepath.Join(t.TempDir(), "no-such-server")
	cmd, _, path, pub := startPairedProxyWith(t, pairedProxyOptions{upstreamArg: missing})
	exited := make(chan error, 1)
	go func() { exited <- cmd.Wait() }()
	select {
	case err := <-exited:
		if err == nil {
			t.Fatal("proxy exited 0 with a missing upstream")
		}
	case <-time.After(5 * time.Second):
		t.Fatal("proxy did not exit with a missing upstream")
	}
	data, err := os.ReadFile(path)
	if err != nil && !os.IsNotExist(err) {
		t.Fatal(err)
	}
	if len(data) > 0 {
		if rows, count, err := audit.VerifyEd25519WithCheckpoint(path, pub); err != nil || rows != count {
			t.Fatalf("integrity rows=%d checkpoint=%d err=%v", rows, count, err)
		}
	}
	if strings.Contains(string(data), `"run_event":"open"`) && !strings.Contains(string(data), `"run_event":"close"`) {
		t.Fatalf("launch failure left an unclosed run:\n%s", data)
	}
	for _, run := range audit.AssessRuns(data, true, time.Now().Add(91*time.Second)) {
		if run.Verdict == "INCOMPLETE" {
			t.Fatalf("launch failure assessed %+v", run)
		}
	}
}

// A line still inside approval when shutdown starts can register a dispatch
// after the pending-call sweep. Close must wait for that line first: the run
// either records outcome_unknown for it before run/close, or stays unclosed.
// A detached upstream child keeps the pipe open so the late forward succeeds
// and only the shutdown sweep can terminate the action.
func TestPairedSignalWaitsForLineInApprovalBeforeSweep(t *testing.T) {
	home, err := os.MkdirTemp("/tmp", "ngh")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(home) })
	pidFile := filepath.Join(home, "child.pid")
	upstream := "#!/usr/bin/env python3\nimport os, sys, time\nif os.fork() == 0:\n    os.setsid()\n    open(" + strconv.Quote(pidFile) + ", 'w').write(str(os.getpid()))\n    time.sleep(20)\n    sys.exit(0)\ntime.sleep(20)\n"
	env := []string{"HOME=" + home, "NOCKGUARD_APPROVER=local"}
	cmd, in, path, pub := startPairedProxyWith(t, pairedProxyOptions{upstreamBody: upstream, policyExtra: "    ask: [\"held_tool\"]\n", env: env})
	t.Cleanup(func() {
		if raw, err := os.ReadFile(pidFile); err == nil {
			if pid, err := strconv.Atoi(strings.TrimSpace(string(raw))); err == nil {
				_ = syscall.Kill(pid, syscall.SIGKILL)
			}
		}
	})
	waitForTrail(t, path, pub, `"run_event":"open"`)
	for deadline := time.Now().Add(10 * time.Second); ; time.Sleep(20 * time.Millisecond) {
		if raw, err := os.ReadFile(pidFile); err == nil && len(raw) > 0 {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("detached upstream child never started")
		}
	}
	if _, err := io.WriteString(in, callLine("1", "held_tool", "x")+"\n"); err != nil {
		t.Fatal(err)
	}
	approvalDir := filepath.Join(home, ".nockguard", "approvals")
	var id string
	for i := 0; i < 250 && id == ""; i++ {
		if held, err := approval.ListPending(approvalDir); err == nil {
			for _, h := range held {
				if h.Tool == "held_tool" {
					id = h.ID
				}
			}
		}
		time.Sleep(20 * time.Millisecond)
	}
	if id == "" {
		t.Fatal("held call never appeared in the local approver")
	}
	exited := make(chan error, 1)
	go func() { exited <- cmd.Wait() }()
	if err := cmd.Process.Signal(syscall.SIGTERM); err != nil {
		t.Fatal(err)
	}
	// Release the held line after shutdown has started.
	time.Sleep(20 * time.Millisecond)
	if err := approval.Decide(approvalDir, id, true); err != nil {
		t.Logf("approve after SIGTERM: %v", err)
	}
	select {
	case <-exited:
	case <-time.After(5 * time.Second):
		t.Fatal("proxy did not exit after SIGTERM")
	}
	if rows, count, err := audit.VerifyEd25519WithCheckpoint(path, pub); err != nil || rows != count {
		t.Fatalf("integrity rows=%d checkpoint=%d err=%v", rows, count, err)
	}
	data := mustRead(t, path)
	if !strings.Contains(string(data), `"run_event":"close"`) {
		return // unclosed is an honest result
	}
	got := audit.AssessRuns(data, true, time.Now())
	if len(got) != 1 || got[0].Verdict != "LIMITED" {
		t.Fatalf("closed run must have every dispatch terminated: %+v\n%s", got, data)
	}
}

// When the upstream exits while an accepted line is still held (here, in
// approval) past auditDrainBound, nothing is swept and the run stays unclosed.
// That input-idle timeout must be reported as a shutdown timeout.
func TestPairedUpstreamExitReportsInputIdleTimeout(t *testing.T) {
	home, err := os.MkdirTemp("/tmp", "ngh")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(home) })
	env := []string{"HOME=" + home, "NOCKGUARD_APPROVER=local"}
	stderr := &lockedBuffer{}
	cmd, in, path, pub := startPairedProxyWith(t, pairedProxyOptions{
		upstreamBody: "#!/bin/sh\nsleep 2\nexit 0\n",
		policyExtra:  "    ask: [\"held_tool\"]\n",
		env:          env,
		stderr:       stderr,
	})
	waitForTrail(t, path, pub, `"run_event":"open"`)
	if _, err := io.WriteString(in, callLine("1", "held_tool", "x")+"\n"); err != nil {
		t.Fatal(err)
	}
	approvalDir := filepath.Join(home, ".nockguard", "approvals")
	held := false
	for i := 0; i < 75 && !held; i++ {
		if pending, err := approval.ListPending(approvalDir); err == nil && len(pending) > 0 {
			held = true
		}
		time.Sleep(20 * time.Millisecond)
	}
	if !held {
		t.Fatal("call was not held in approval before the upstream exited")
	}
	exited := make(chan error, 1)
	go func() { exited <- cmd.Wait() }()
	select {
	case <-exited:
	case <-time.After(10 * time.Second):
		t.Fatal("proxy did not exit after the upstream exited")
	}
	logs := stderr.String()
	for _, want := range []string{"AUDIT-RUN input drain timed out", "upstream exited: audit drain deadline reached"} {
		if !strings.Contains(logs, want) {
			t.Fatalf("stderr lacks %q:\n%s", want, logs)
		}
	}
	data := mustRead(t, path)
	if strings.Contains(string(data), `"run_event":"close"`) {
		t.Fatalf("run closed while an accepted line was still held:\n%s", data)
	}
}
