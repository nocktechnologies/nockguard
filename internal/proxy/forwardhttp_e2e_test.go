package proxy

import (
	"bytes"
	"context"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"
)

// syncBuffer is a goroutine-safe bytes.Buffer wrapper. The os/exec stderr-copy
// goroutine writes to it while the test reads stderr.String() to assert on the
// still-running proxy subprocess, so Write/String must be mutex-guarded to be
// clean under `go test -race`.
type syncBuffer struct {
	mu  sync.Mutex
	buf bytes.Buffer
}

func (b *syncBuffer) Write(p []byte) (int, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buf.Write(p)
}

func (b *syncBuffer) String() string {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buf.String()
}

func TestEgressProxyObserveOnlyAuditsAndDoesNotBlock(t *testing.T) {
	binary := buildBinary(t)
	dir := t.TempDir()
	auditPath := filepath.Join(dir, "audit.jsonl")

	keygenOut, err := exec.Command(binary, "keygen").Output()
	if err != nil {
		t.Fatalf("keygen failed: %v", err)
	}
	seedHex := envValue(t, string(keygenOut), "NOCKGUARD_AUDIT_ED25519_KEY")
	pubHex := envValue(t, string(keygenOut), "NOCKGUARD_AUDIT_ED25519_PUB")

	allowed := newLoopbackServer(t, "tcp4", "127.0.0.1:0", "allowed")
	defer allowed.Close()
	denied := newLoopbackServer(t, "tcp6", "[::1]:0", "denied")
	defer denied.Close()

	policyFile := filepath.Join(dir, "egress.yaml")
	policyContent := `audit:
  enabled: true
  path: ` + auditPath + `
  sign_ed25519_key_env: NOCKGUARD_AUDIT_ED25519_KEY
agents:
  kit:
    allow:
      - "127.0.0.1"
`
	if err := os.WriteFile(policyFile, []byte(policyContent), 0o644); err != nil {
		t.Fatal(err)
	}

	listener, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen for proxy: %v", err)
	}
	listenAddr := listener.Addr().String()
	if err := listener.Close(); err != nil {
		t.Fatalf("close reserved proxy listener: %v", err)
	}

	stderr := &syncBuffer{}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	cmd := exec.CommandContext(ctx, binary, "egress-proxy",
		"--listen", listenAddr,
		"--agent", "kit",
		"--policy", policyFile,
		"--audit", auditPath,
	)
	cmd.Env = append(os.Environ(), "NOCKGUARD_AUDIT_ED25519_KEY="+seedHex)
	cmd.Stderr = stderr
	if err := cmd.Start(); err != nil {
		t.Fatalf("start egress proxy: %v", err)
	}
	defer func() {
		cancel()
		_ = cmd.Wait()
	}()

	waitForTCP(t, listenAddr)

	proxyURL, err := url.Parse("http://" + listenAddr)
	if err != nil {
		t.Fatal(err)
	}
	client := &http.Client{
		Transport: &http.Transport{Proxy: http.ProxyURL(proxyURL)},
		Timeout:   5 * time.Second,
	}

	for _, target := range []string{allowed.URL, denied.URL} {
		resp, err := client.Get(target)
		if err != nil {
			t.Fatalf("GET %s through proxy failed: %v\nproxy stderr:\n%s", target, err, stderr.String())
		}
		body, _ := io.ReadAll(resp.Body)
		_ = resp.Body.Close()
		// N8182: loopback targets are hard-blocked by the SSRF guard regardless of
		// policy (allowed.URL is 127.0.0.1, denied.URL is ::1 — both loopback).
		// observe() still fires and audits the policy decision before the block,
		// so audit entries and WOULD-BLOCK logging are unaffected.
		if resp.StatusCode != http.StatusForbidden {
			t.Fatalf("GET %s: SSRF guard must block loopback (status want 403, got %d, body=%q)", target, resp.StatusCode, body)
		}
	}

	lines := readAuditFile(t, auditPath)
	if len(lines) != 2 {
		t.Fatalf("expected 2 signed egress audit records, got %d: %v\nproxy stderr:\n%s", len(lines), lines, stderr.String())
	}
	want := []struct {
		tool     string
		decision string
	}{
		{tool: "egress:127.0.0.1", decision: "allow"},
		{tool: "egress:::1", decision: "deny"},
	}
	for i, w := range want {
		if lines[i]["agent"] != "kit" || lines[i]["tool"] != w.tool || lines[i]["decision"] != w.decision || lines[i]["sig"] == "" {
			t.Fatalf("audit record %d = %v, want agent kit tool %q decision %q with signature", i, lines[i], w.tool, w.decision)
		}
	}
	if !strings.Contains(stderr.String(), "WOULD-BLOCK (observe-only)") {
		t.Fatalf("deny was not WARN-logged as observe-only; stderr:\n%s", stderr.String())
	}

	verify := func() (string, int) {
		c := exec.Command(binary, "audit", "verify", "--ed25519-pub-env", "NOCKGUARD_AUDIT_ED25519_PUB", "--audit", auditPath)
		c.Env = append(os.Environ(), "NOCKGUARD_AUDIT_ED25519_PUB="+pubHex)
		out, err := c.CombinedOutput()
		code := 0
		if ee, ok := err.(*exec.ExitError); ok {
			code = ee.ExitCode()
		} else if err != nil {
			t.Fatalf("verify run error: %v", err)
		}
		return string(out), code
	}

	out, code := verify()
	if code != 0 || !strings.Contains(out, "OK") || !strings.Contains(out, "2 entries verified") {
		t.Fatalf("expected OK/2 entries (exit 0), got exit %d: %s", code, out)
	}

	data, err := os.ReadFile(auditPath)
	if err != nil {
		t.Fatal(err)
	}
	tampered := strings.Replace(string(data), `"tool":"egress:::1"`, `"tool":"egress:example.invalid"`, 1)
	if tampered == string(data) {
		t.Fatal("tamper substitution did not match the trail content")
	}
	if err := os.WriteFile(auditPath, []byte(tampered), 0o644); err != nil {
		t.Fatal(err)
	}

	out, code = verify()
	if code != 2 || !strings.Contains(out, "TAMPER DETECTED") {
		t.Fatalf("expected TAMPER DETECTED (exit 2), got exit %d: %s", code, out)
	}
}

func newLoopbackServer(t *testing.T, network, addr, body string) *httptest.Server {
	t.Helper()
	ln, err := net.Listen(network, addr)
	if err != nil {
		t.Skipf("loopback listener %s %s unavailable: %v", network, addr, err)
	}
	srv := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = io.WriteString(w, body)
	}))
	srv.Listener = ln
	srv.Start()
	return srv
}

func waitForTCP(t *testing.T, addr string) {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for {
		conn, err := net.DialTimeout("tcp", addr, 100*time.Millisecond)
		if err == nil {
			_ = conn.Close()
			return
		}
		if time.Now().After(deadline) {
			t.Fatalf("timed out waiting for %s: %v", addr, err)
		}
		time.Sleep(50 * time.Millisecond)
	}
}
