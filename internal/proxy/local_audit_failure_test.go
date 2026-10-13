package proxy

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/hex"
	"io"
	"log"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/nocktechnologies/nockguard/internal/audit"
)

func TestBestEffortAuditClearsStaleFailureMarker(t *testing.T) {
	path := filepath.Join(t.TempDir(), "audit.jsonl")
	marker := path + ".audit-failing"
	if err := os.Mkdir(marker, 0700); err != nil {
		t.Fatal(err)
	}
	auditor, err := audit.New(path)
	if err != nil {
		t.Fatal(err)
	}
	defer auditor.Close()
	gate := newGate(t, "agents:\n  mira:\n    mode: allow\n", nil, auditor)
	gate.WithBestEffortAudit()
	if audit.FailureStatus(path) {
		t.Fatal("best-effort mode retained stale required-writer marker")
	}
}

func TestProxyAuditBestEffortFlag(t *testing.T) {
	binary := buildBinary(t)
	upstream := writeMockServer(t)
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	seed := hex.EncodeToString(priv.Seed())
	for _, bestEffort := range []bool{false, true} {
		name := "required"
		if bestEffort {
			name = "best-effort"
		}
		t.Run(name, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "audit.jsonl")
			policyPath := filepath.Join(t.TempDir(), "policy.yaml")
			policyYAML := "audit:\n  enabled: true\n  path: " + path + "\n  sign_ed25519_key_env: TEST_AUDIT_KEY\nagents:\n  kit:\n    mode: allow\n"
			if err := os.WriteFile(policyPath, []byte(policyYAML), 0600); err != nil {
				t.Fatal(err)
			}
			if err := os.Mkdir(path+".hwm.tmp", 0700); err != nil {
				t.Fatal(err)
			}
			args := []string{"proxy", "--upstream", upstream, "--agent", "kit", "--policy", policyPath}
			if bestEffort {
				args = append(args, "--audit-best-effort")
			}
			cmd := exec.Command(binary, args...)
			cmd.Env = append(os.Environ(), "TEST_AUDIT_KEY="+seed)
			cmd.Stdin = strings.NewReader(toolCall("1", "tool_a") + "\n" + toolCall("2", "tool_b") + "\n")
			out, err := cmd.CombinedOutput()
			if err != nil {
				t.Fatalf("proxy exited: %v\n%s", err, out)
			}
			if bestEffort {
				if strings.Count(string(out), `"result"`) != 2 || !strings.Contains(string(out), "WARNING: --audit-best-effort enabled") {
					t.Fatalf("best-effort flag did not forward both calls and warn: %s", out)
				}
			} else if strings.Count(string(out), AuditBeforeForwardError) != 2 || strings.Contains(string(out), `"result"`) {
				t.Fatalf("required mode forwarded a call or hid failure: %s", out)
			}
		})
	}
}

// A directory at the checkpoint temp path reproduces the reported filesystem
// failure. Both local transports must refuse the first and later calls, while
// the explicit best-effort mode preserves the old forwarding behavior.
func TestLocalAuditCheckpointFailure(t *testing.T) {
	call := toolCall("1", "nockcc_nock_list")
	for _, bestEffort := range []bool{false, true} {
		name := "required"
		if bestEffort {
			name = "best-effort"
		}
		t.Run("stdio/"+name, func(t *testing.T) {
			auditor, path, _ := newEd25519Auditor(t)
			defer auditor.Close()
			if err := os.Mkdir(path+".hwm.tmp", 0700); err != nil {
				t.Fatal(err)
			}
			gate := newGate(t, "agents:\n  mira:\n    mode: allow\n", nil, auditor)
			if bestEffort {
				gate.WithBestEffortAudit()
			}
			for i := 0; i < 2; i++ {
				forwarded, reply, err := gate.Probe([]byte(call))
				if err != nil {
					t.Fatal(err)
				}
				if forwarded != bestEffort {
					t.Fatalf("call %d forwarded=%v, want %v; reply=%s", i+1, forwarded, bestEffort, reply)
				}
				if !bestEffort && !strings.Contains(string(reply), AuditBeforeForwardError) {
					t.Fatalf("call %d did not report audit failure: %s", i+1, reply)
				}
			}
		})
		t.Run("http/"+name, func(t *testing.T) {
			var calls atomic.Int32
			upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				calls.Add(1)
				w.Header().Set("Content-Type", "application/json")
				_, _ = io.WriteString(w, `{"jsonrpc":"2.0","id":1,"result":{}}`)
			}))
			defer upstream.Close()
			auditor, path, _ := newEd25519Auditor(t)
			defer auditor.Close()
			if err := os.Mkdir(path+".hwm.tmp", 0700); err != nil {
				t.Fatal(err)
			}
			gate := newGate(t, "agents:\n  mira:\n    mode: allow\n", nil, auditor)
			listener := NewHTTPListener("127.0.0.1:0", upstream.URL, gate, log.New(io.Discard, "", 0))
			if bestEffort {
				listener.WithBestEffortAudit()
			}
			server := httptest.NewServer(listener)
			defer server.Close()
			for i := 0; i < 2; i++ {
				_, body, _ := post(t, server.URL, call)
				if got := calls.Load(); got != int32((i+1)*map[bool]int{true: 1, false: 0}[bestEffort]) {
					t.Fatalf("after call %d upstream calls=%d; response=%s", i+1, got, body)
				}
				if !bestEffort && !strings.Contains(body, AuditBeforeForwardError) {
					t.Fatalf("call %d did not report audit failure: %s", i+1, body)
				}
			}
		})
	}
}
