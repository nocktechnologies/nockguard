package proxy

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

// End-to-end through the real binary: keygen produces a keypair, the proxy signs
// the trail with the private seed (loaded via config from an env var), and
// `audit verify --ed25519-pub-env` confirms the chain using ONLY the public key.
// This is the non-repudiable path Nock Security sells — exercised exactly as a
// deployment runs it, not via internal calls.

// envValue pulls the value of a `KEY=value` line out of keygen's stdout.
func envValue(t *testing.T, out, key string) string {
	t.Helper()
	for _, line := range strings.Split(out, "\n") {
		if strings.HasPrefix(line, key+"=") {
			return strings.TrimSpace(strings.TrimPrefix(line, key+"="))
		}
	}
	t.Fatalf("keygen output missing %s=\n%s", key, out)
	return ""
}

func TestEd25519AuditEndToEnd(t *testing.T) {
	binary := buildBinary(t)
	mockServer := writeMockServer(t)
	dir := t.TempDir()
	auditPath := filepath.Join(dir, "audit.jsonl")

	// 1. keygen -> private seed + public key.
	keygenOut, err := exec.Command(binary, "keygen").Output()
	if err != nil {
		t.Fatalf("keygen failed: %v", err)
	}
	seedHex := envValue(t, string(keygenOut), "NOCKGUARD_AUDIT_ED25519_KEY")
	pubHex := envValue(t, string(keygenOut), "NOCKGUARD_AUDIT_ED25519_PUB")

	// 2. Policy with Ed25519-signed audit enabled, key sourced from the env.
	policyFile := filepath.Join(dir, "policy.yaml")
	policyContent := "agents:\n" +
		"  kit:\n" +
		"    allow:\n" +
		"      - \"nockcc_*\"\n" +
		"audit:\n" +
		"  enabled: true\n" +
		"  path: " + auditPath + "\n" +
		"  sign_ed25519_key_env: NOCKGUARD_AUDIT_ED25519_KEY\n"
	if err := os.WriteFile(policyFile, []byte(policyContent), 0644); err != nil {
		t.Fatal(err)
	}

	// 3. Run the proxy; two allowed calls -> two signed audit entries.
	requests := []string{
		`{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"nockcc_nock_list"}}`,
		`{"jsonrpc":"2.0","id":2,"method":"tools/call","params":{"name":"nockcc_nock_get"}}`,
	}
	proxyCmd := exec.Command(binary, "proxy", "--upstream", mockServer, "--agent", "kit", "--policy", policyFile)
	proxyCmd.Stdin = strings.NewReader(strings.Join(requests, "\n") + "\n")
	proxyCmd.Env = append(os.Environ(), "NOCKGUARD_AUDIT_ED25519_KEY="+seedHex)
	if out, err := proxyCmd.CombinedOutput(); err != nil {
		t.Fatalf("proxy run failed: %v\n%s", err, out)
	}

	// 4. Verify with the PUBLIC key only -> intact, exit 0.
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

	// 5. Tamper one entry -> verification must fail with exit 2.
	data, _ := os.ReadFile(auditPath)
	tampered := strings.Replace(string(data), `"tool":"nockcc_nock_get"`, `"tool":"nockcc_kill_switch_set"`, 1)
	if tampered == string(data) {
		t.Fatal("tamper substitution did not match the trail content")
	}
	os.WriteFile(auditPath, []byte(tampered), 0644)

	out, code = verify()
	if code != 2 || !strings.Contains(out, "TAMPER DETECTED") {
		t.Fatalf("expected TAMPER DETECTED (exit 2), got exit %d: %s", code, out)
	}
}
