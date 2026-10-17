package proxy

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/nocktechnologies/nockguard/internal/audit"
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
					data, _ := os.ReadFile(path)
					if strings.Contains(string(data), `"run_event":"open"`) {
						break
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
