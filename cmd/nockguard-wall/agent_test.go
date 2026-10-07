package main

import (
	"bufio"
	"context"
	"crypto/ed25519"
	"encoding/hex"
	"encoding/json"
	"flag"
	"fmt"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/nocktechnologies/nockguard/internal/audit"
)

func TestWallSubprocess(t *testing.T) {
	if os.Getenv("NOCKGUARD_TEST_WALL_PROCESS") != "1" {
		return
	}
	for i, arg := range os.Args {
		if arg == "--" {
			os.Args = append([]string{os.Args[0]}, os.Args[i+1:]...)
			flag.CommandLine = flag.NewFlagSet(os.Args[0], flag.ExitOnError)
			main()
			return
		}
	}
	t.Fatal("missing wall arguments")
}

type wallOutput struct {
	mu sync.Mutex
	b  strings.Builder
}

func (o *wallOutput) Write(p []byte) (int, error) {
	o.mu.Lock()
	defer o.mu.Unlock()
	return o.b.Write(p)
}

func (o *wallOutput) String() string {
	o.mu.Lock()
	defer o.mu.Unlock()
	return o.b.String()
}

func wallCommand(t *testing.T, home string, args ...string) (*exec.Cmd, *wallOutput) {
	t.Helper()
	exe, err := os.Executable()
	if err != nil {
		t.Fatalf("test executable: %v", err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	t.Cleanup(cancel)
	cmd := exec.CommandContext(ctx, exe, append([]string{"-test.run=^TestWallSubprocess$", "--"}, args...)...)
	cmd.Env = append(os.Environ(), "NOCKGUARD_TEST_WALL_PROCESS=1", "HOME="+home)
	output := &wallOutput{}
	cmd.Stdout, cmd.Stderr = output, output
	return cmd, output
}

func freeWallAddr(t *testing.T) string {
	t.Helper()
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("reserve wall port: %v", err)
	}
	addr := l.Addr().String()
	if err := l.Close(); err != nil {
		t.Fatalf("release wall port: %v", err)
	}
	return addr
}

func startWall(t *testing.T, home string, args ...string) (string, *wallOutput) {
	t.Helper()
	addr := freeWallAddr(t)
	cmd, output := wallCommand(t, home, append([]string{"-addr", addr}, args...)...)
	if err := cmd.Start(); err != nil {
		t.Fatalf("start wall: %v", err)
	}
	t.Cleanup(func() {
		_ = cmd.Process.Kill()
		_ = cmd.Wait()
	})
	url := "http://" + addr
	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		resp, err := http.Get(url + "/verify")
		if err == nil {
			resp.Body.Close()
			return url, output
		}
		time.Sleep(20 * time.Millisecond)
	}
	t.Fatalf("wall did not start: %s", output.String())
	return "", nil
}

func wallVerify(t *testing.T, url string) verifyReport {
	t.Helper()
	resp, err := http.Get(url + "/verify")
	if err != nil {
		t.Fatalf("GET /verify: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("GET /verify: status %d", resp.StatusCode)
	}
	var report verifyReport
	if err := json.NewDecoder(resp.Body).Decode(&report); err != nil {
		t.Fatalf("decode /verify: %v", err)
	}
	return report
}

func TestWallAgentSignedTrail(t *testing.T) {
	home := t.TempDir()
	path := filepath.Join(home, ".nockguard", "logs", "local-agent.audit.jsonl")
	pub, priv, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatalf("generate signing key: %v", err)
	}
	writeSignedTrail(t, path, priv, []audit.Event{
		{Agent: "local-agent", Tool: "Read", Decision: "allow"},
		{Agent: "local-agent", Tool: "WebFetch", Decision: "deny", Reason: "policy denied"},
	})
	t.Setenv("NOCKGUARD_AGENT_LOCAL_AGENT_ED25519_PUB", hex.EncodeToString(pub))
	t.Setenv("NOCKGUARD_AGENT_LOCAL_AGENT_ED25519_KEY", hex.EncodeToString(priv.Seed()))
	url, output := startWall(t, home, "-agent", "local-agent", "-proof-signing-key-env", "NOCKGUARD_AGENT_LOCAL_AGENT_ED25519_KEY")
	if !strings.Contains(output.String(), "audit: "+path) {
		t.Errorf("wall audit path = %q; want %q", output.String(), path)
	}
	report := wallVerify(t, url)
	if report.ChainIntact == nil || !*report.ChainIntact || report.EntriesVerified != 2 {
		t.Errorf("/verify = %+v; want intact chain with two verified rows", report)
	}
	proofResp, err := http.Get(url + "/export?format=proof&since=1h")
	if err != nil {
		t.Fatal(err)
	}
	defer proofResp.Body.Close()
	var proof audit.ExportProof
	if err := json.NewDecoder(proofResp.Body).Decode(&proof); err != nil {
		t.Fatal(err)
	}
	if proofResp.StatusCode != http.StatusOK || len(proof.Rows) != 2 {
		t.Fatalf("proof export: status=%d rows=%d", proofResp.StatusCode, len(proof.Rows))
	}
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url+"/events", nil)
	if err != nil {
		t.Fatalf("create SSE request: %v", err)
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("GET /events: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("GET /events: status %d", resp.StatusCode)
	}
	scanner := bufio.NewScanner(resp.Body)
	var got []event
	for scanner.Scan() && len(got) < 2 {
		line := scanner.Text()
		if !strings.HasPrefix(line, "data: ") {
			continue
		}
		var ev event
		if err := json.Unmarshal([]byte(strings.TrimPrefix(line, "data: ")), &ev); err != nil {
			t.Fatalf("decode SSE event: %v", err)
		}
		got = append(got, ev)
	}
	if err := scanner.Err(); err != nil {
		t.Fatalf("read SSE: %v", err)
	}
	if len(got) != 2 || got[0].Tool != "Read" || got[1].Tool != "WebFetch" || got[0].VerifyState != "ok" || got[1].VerifyState != "ok" {
		t.Errorf("SSE events = %+v; want two verified audit decisions", got)
	}
}

func TestWallAgentExplicitFlagsWin(t *testing.T) {
	home := t.TempDir()
	path := filepath.Join(t.TempDir(), "custom.jsonl")
	pub, priv, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatalf("generate signing key: %v", err)
	}
	writeSignedTrail(t, path, priv, []audit.Event{{Agent: "local-agent", Tool: "Read", Decision: "allow"}})
	t.Setenv("CUSTOM_WALL_PUB", hex.EncodeToString(pub))
	t.Setenv("NOCKGUARD_AGENT_LOCAL_AGENT_ED25519_PUB", "invalid")
	_, unrelated, _ := ed25519.GenerateKey(nil)
	t.Setenv("NOCKGUARD_AGENT_LOCAL_AGENT_ED25519_KEY", hex.EncodeToString(unrelated.Seed()))
	url, output := startWall(t, home, "-agent", "local-agent", "-audit", path, "-verify-ed25519-pub-env", "CUSTOM_WALL_PUB")
	if !strings.Contains(output.String(), "audit: "+path) {
		t.Errorf("wall audit path = %q; want explicit %q", output.String(), path)
	}
	report := wallVerify(t, url)
	if report.ChainIntact == nil || !*report.ChainIntact || report.EntriesVerified != 1 {
		t.Errorf("/verify = %+v; want explicit key to verify one row", report)
	}
	resp, err := http.Get(url + "/export?format=proof&since=1h")
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusConflict {
		t.Fatalf("proof with unrelated default key = %d, want 409", resp.StatusCode)
	}
}

func TestWallExplicitProofKeyMismatchFails(t *testing.T) {
	pub, _, _ := ed25519.GenerateKey(nil)
	_, unrelated, _ := ed25519.GenerateKey(nil)
	t.Setenv("CUSTOM_WALL_PUB", hex.EncodeToString(pub))
	t.Setenv("CUSTOM_PROOF_KEY", hex.EncodeToString(unrelated.Seed()))
	cmd, output := wallCommand(t, t.TempDir(), "-verify-ed25519-pub-env", "CUSTOM_WALL_PUB", "-proof-signing-key-env", "CUSTOM_PROOF_KEY", "-addr", freeWallAddr(t))
	if err := cmd.Run(); err == nil {
		t.Fatalf("mismatched explicit proof key started Wall: %s", output.String())
	}
	if !strings.Contains(output.String(), "does not match the configured public key") {
		t.Fatalf("wrong startup error: %s", output.String())
	}
	t.Setenv("CUSTOM_PROOF_KEY", "")
	cmd, output = wallCommand(t, t.TempDir(), "-verify-ed25519-pub-env", "CUSTOM_WALL_PUB", "-proof-signing-key-env", "CUSTOM_PROOF_KEY", "-addr", freeWallAddr(t))
	if err := cmd.Run(); err == nil {
		t.Fatalf("unset explicit proof key started Wall: %s", output.String())
	}
	if !strings.Contains(output.String(), "CUSTOM_PROOF_KEY is unset") {
		t.Fatalf("wrong unset-key error: %s", output.String())
	}
}

func TestWallAgentRejectsBadNames(t *testing.T) {
	for _, name := range []string{"", ".", "..", "a..b", "../escape", "a/b", `a\b`} {
		t.Run(fmt.Sprintf("%q", name), func(t *testing.T) {
			cmd, output := wallCommand(t, t.TempDir(), "-agent", name, "-addr", freeWallAddr(t))
			err := cmd.Run()
			if err == nil {
				t.Fatalf("agent %q accepted; output: %s", name, output.String())
			}
			if !strings.Contains(output.String(), "invalid agent name") || strings.Contains(output.String(), "panic:") {
				t.Errorf("agent %q error = %q; want clear validation error", name, output.String())
			}
		})
	}
}
