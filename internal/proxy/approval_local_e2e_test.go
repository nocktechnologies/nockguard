package proxy

import (
	"bufio"
	"crypto/ed25519"
	"encoding/json"
	"io"
	"log"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/nocktechnologies/nockguard/internal/approval"
	"github.com/nocktechnologies/nockguard/internal/audit"
	"github.com/nocktechnologies/nockguard/internal/policy"
)

// runLocalApproval starts a real proxy with NOCKGUARD_APPROVER=local, sends one
// ask-gated call and asserts the call is NOT answered (so not forwarded) until
// the operator decides through the `nockguard approvals` CLI.
func runLocalApproval(t *testing.T, decision string) map[string]interface{} {
	t.Helper()
	binary := buildBinary(t)
	home, err := os.MkdirTemp("/tmp", "ngh")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { os.RemoveAll(home) })
	policyFile := filepath.Join(home, "policy.yaml")
	if err := os.WriteFile(policyFile, []byte(approvalPolicy), 0o644); err != nil {
		t.Fatal(err)
	}
	env := append(os.Environ(), "HOME="+home, "NOCKGUARD_APPROVER=local")

	cmd := exec.Command(binary, "proxy", "--upstream", writeMockServer(t), "--agent", "kit", "--policy", policyFile)
	cmd.Env = env
	stdin, _ := cmd.StdinPipe()
	stdout, _ := cmd.StdoutPipe()
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { stdin.Close(); cmd.Process.Kill(); cmd.Wait() })

	lines := make(chan string, 8)
	go func() {
		sc := bufio.NewScanner(stdout)
		for sc.Scan() {
			lines <- sc.Text()
		}
		close(lines)
	}()
	if _, err := stdin.Write([]byte(`{"jsonrpc":"2.0","id":1,"method":"tools/list","params":{}}` + "\n")); err != nil {
		t.Fatal(err)
	}
	select {
	case line := <-lines:
		var listing struct {
			Result struct {
				Tools []struct {
					Name string `json:"name"`
				} `json:"tools"`
			} `json:"result"`
		}
		if err := json.Unmarshal([]byte(line), &listing); err != nil {
			t.Fatalf("decode tools/list response: %v (%s)", err, line)
		}
		found := false
		for _, tool := range listing.Result.Tools {
			if tool.Name == "nockcc_kill_switch_set" {
				found = true
			}
		}
		if !found {
			t.Fatalf("ask tool was not listed: %s", line)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("no tools/list response")
	}
	if _, err := stdin.Write([]byte(`{"jsonrpc":"2.0","id":2,"method":"tools/call","params":{"name":"nockcc_kill_switch_set","arguments":{"k":"hunter2"}}}` + "\n")); err != nil {
		t.Fatal(err)
	}

	approvals := func(args ...string) string {
		c := exec.Command(binary, append([]string{"approvals"}, args...)...)
		c.Env = env
		out, _ := c.CombinedOutput()
		return string(out)
	}
	var id string
	for i := 0; i < 300 && id == ""; i++ {
		for _, l := range strings.Split(approvals("list"), "\n") {
			if f := strings.Fields(l); len(f) > 2 && f[1] == `"kit"` && f[2] == `"nockcc_kill_switch_set"` {
				if strings.Contains(l, "hunter2") {
					t.Fatalf("list leaked arguments: %s", l)
				}
				id = f[0]
			}
		}
		time.Sleep(20 * time.Millisecond)
	}
	if id == "" {
		t.Fatal("held call never appeared in `approvals list`")
	}
	select {
	case l := <-lines:
		t.Fatalf("held call answered/forwarded before any decision: %s", l)
	case <-time.After(200 * time.Millisecond):
	}
	if out := approvals(decision, id); !strings.HasPrefix(out, decision) {
		t.Fatalf("approvals %s: %s", decision, out)
	}
	select {
	case l := <-lines:
		var m map[string]interface{}
		if err := json.Unmarshal([]byte(l), &m); err != nil {
			t.Fatal(err)
		}
		return m
	case <-time.After(5 * time.Second):
		t.Fatal("no response after decision")
	}
	return nil
}

func TestLocalApproverApproveForwards(t *testing.T) {
	if m := runLocalApproval(t, "approve"); m["error"] != nil {
		t.Errorf("approved call should be forwarded, got %v", m["error"])
	}
}

func TestLocalApproverDenyBlocks(t *testing.T) {
	m := runLocalApproval(t, "deny")
	if msg := errorMessage(t, m); !strings.Contains(msg, "denied by approval gate") {
		t.Errorf("denied call should be blocked, got %q", msg)
	}
}

func TestLocalApprovalActorIsSignedFromKernelPeerUID(t *testing.T) {
	home, err := os.MkdirTemp("/tmp", "ngha")
	if err != nil {
		t.Fatal(err)
	}
	defer os.RemoveAll(home)

	engine, err := policy.LoadBytes([]byte(`audit:
  enabled: true
agents:
  kit:
    allow: [deploy_prod]
    ask: [deploy_prod]
`))
	if err != nil {
		t.Fatal(err)
	}
	validator, err := engine.ValidatorFor("kit")
	if err != nil {
		t.Fatal(err)
	}
	approver, err := approval.NewLocalApprover(filepath.Join(home, "approvals"), 5*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	defer approver.Close()

	pub, priv, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatal(err)
	}
	auditPath := filepath.Join(home, "audit.jsonl")
	auditor, err := audit.New(auditPath, audit.WithEd25519Key(priv))
	if err != nil {
		t.Fatal(err)
	}
	gate := NewStdioProxy(nil, "kit", engine, validator, nil, auditor, nil, log.New(io.Discard, "", 0)).WithApprover(approver)
	type probeResult struct {
		forwarded bool
		reply     []byte
		err       error
	}
	probe := make(chan probeResult, 1)
	go func() {
		forwarded, reply, probeErr := gate.Probe([]byte(`{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"deploy_prod","arguments":{}}}`))
		probe <- probeResult{forwarded: forwarded, reply: reply, err: probeErr}
	}()
	approvalsDir := filepath.Join(home, "approvals")
	var heldID string
	for i := 0; i < 300 && heldID == ""; i++ {
		pending, listErr := approval.ListPending(approvalsDir)
		if listErr != nil {
			t.Fatal(listErr)
		}
		if len(pending) > 0 {
			heldID = pending[0].ID
			break
		}
		time.Sleep(10 * time.Millisecond)
	}
	if heldID == "" {
		t.Fatal("held call never appeared in local approval socket")
	}
	if err := approval.Decide(approvalsDir, heldID, true); err != nil {
		t.Fatal(err)
	}
	select {
	case result := <-probe:
		if result.err != nil || !result.forwarded {
			t.Fatalf("approved probe forwarded=%v reply=%s err=%v", result.forwarded, result.reply, result.err)
		}
	case <-time.After(time.Second):
		t.Fatal("approved probe did not finish")
	}
	if err := auditor.Close(); err != nil {
		t.Fatal(err)
	}
	rows := readAuditFile(t, auditPath)
	wantActor := "local:uid:" + strconv.Itoa(os.Getuid())
	found := false
	for _, row := range rows {
		if row["decision"] == "approval-granted" {
			found = true
			if row["approval_actor"] != wantActor {
				t.Fatalf("approval actor = %q, want kernel peer identity %q", row["approval_actor"], wantActor)
			}
		} else if _, ok := row["approval_actor"]; ok {
			t.Fatalf("non-approval row unexpectedly has approval_actor: %v", row)
		}
	}
	if !found {
		t.Fatalf("approval-granted audit row missing: %v", rows)
	}
	if _, err := audit.VerifyEd25519(auditPath, pub); err != nil {
		t.Fatalf("signed approval actor trail failed verification: %v", err)
	}
}

func TestLocalApproverTimeoutFailsClosedThroughStdioGate(t *testing.T) {
	home, err := os.MkdirTemp("/tmp", "nghta")
	if err != nil {
		t.Fatal(err)
	}
	defer os.RemoveAll(home)
	engine, err := policy.LoadBytes([]byte(approvalPolicy))
	if err != nil {
		t.Fatal(err)
	}
	validator, err := engine.ValidatorFor("kit")
	if err != nil {
		t.Fatal(err)
	}
	approver, err := approval.NewLocalApprover(filepath.Join(home, "approvals"), 50*time.Millisecond)
	if err != nil {
		t.Fatal(err)
	}
	defer approver.Close()
	gate := NewStdioProxy(nil, "kit", engine, validator, nil, nil, nil, log.New(io.Discard, "", 0)).WithApprover(approver)
	forwarded, reply, err := gate.Probe([]byte(`{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"nockcc_kill_switch_set"}}`))
	if err != nil {
		t.Fatal(err)
	}
	if forwarded {
		t.Fatal("timed-out approval reached the upstream")
	}
	if !strings.Contains(string(reply), "denied by approval gate") {
		t.Fatalf("timeout reply = %s, want approval denial", reply)
	}
}
