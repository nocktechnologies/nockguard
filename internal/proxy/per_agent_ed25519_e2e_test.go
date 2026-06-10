package proxy

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

// TestPerAgentEd25519EndToEnd verifies the full per-agent keypair flow:
//   - `keygen --agent <name>` emits agent-namespaced env var names
//   - the proxy signs the trail with the per-agent private key (loaded from env)
//   - the agent-specific audit file is written (not the shared path)
//   - `audit verify --agent <name>` confirms the chain with the agent's public key
//   - a second agent with a different keypair produces a separate, independently
//     verifiable trail
func TestPerAgentEd25519EndToEnd(t *testing.T) {
	binary := buildBinary(t)
	mockServer := writeMockServer(t)
	dir := t.TempDir()

	// 1. keygen --agent kit  → NOCKGUARD_AGENT_KIT_ED25519_KEY / _PUB
	kitKeygenOut, err := exec.Command(binary, "keygen", "--agent", "kit").Output()
	if err != nil {
		t.Fatalf("keygen --agent kit: %v", err)
	}
	kitSeed := envValue(t, string(kitKeygenOut), "NOCKGUARD_AGENT_KIT_ED25519_KEY")
	kitPub := envValue(t, string(kitKeygenOut), "NOCKGUARD_AGENT_KIT_ED25519_PUB")
	if kitSeed == "" || kitPub == "" {
		t.Fatalf("keygen --agent kit missing expected output:\n%s", kitKeygenOut)
	}

	// 2. keygen --agent wren → NOCKGUARD_AGENT_WREN_ED25519_KEY / _PUB
	wrenKeygenOut, err := exec.Command(binary, "keygen", "--agent", "wren").Output()
	if err != nil {
		t.Fatalf("keygen --agent wren: %v", err)
	}
	wrenSeed := envValue(t, string(wrenKeygenOut), "NOCKGUARD_AGENT_WREN_ED25519_KEY")
	wrenPub := envValue(t, string(wrenKeygenOut), "NOCKGUARD_AGENT_WREN_ED25519_PUB")
	if wrenSeed == "" || wrenPub == "" {
		t.Fatalf("keygen --agent wren missing expected output:\n%s", wrenKeygenOut)
	}

	// Keys must be distinct (different agents → different keypairs).
	if kitSeed == wrenSeed {
		t.Error("keygen --agent must generate fresh keys each time")
	}

	// 3. Shared policy — audit enabled, no global key (per-agent keys only).
	sharedAuditPath := filepath.Join(dir, "audit.jsonl")
	policyFile := filepath.Join(dir, "policy.yaml")
	policyContent := "agents:\n" +
		"  kit:\n" +
		"    allow: [\"*\"]\n" +
		"  wren:\n" +
		"    allow: [\"*\"]\n" +
		"audit:\n" +
		"  enabled: true\n" +
		"  path: " + sharedAuditPath + "\n"
	if err := os.WriteFile(policyFile, []byte(policyContent), 0644); err != nil {
		t.Fatal(err)
	}

	call := `{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"nockcc_nock_list"}}`

	// 4. Run proxy as kit (per-agent key set via env).
	kitEnv := append(os.Environ(), "NOCKGUARD_AGENT_KIT_ED25519_KEY="+kitSeed)
	runProxyWith(t, binary, mockServer, policyFile, "kit", []string{call}, kitEnv)

	// 5. Run proxy as wren (per-agent key set via env).
	wrenEnv := append(os.Environ(), "NOCKGUARD_AGENT_WREN_ED25519_KEY="+wrenSeed)
	runProxyWith(t, binary, mockServer, policyFile, "wren", []string{call}, wrenEnv)

	// 6. Each agent should have a separate audit file; the shared base should NOT exist.
	kitAuditPath := filepath.Join(dir, "kit.audit.jsonl")
	wrenAuditPath := filepath.Join(dir, "wren.audit.jsonl")

	if _, err := os.Stat(kitAuditPath); err != nil {
		t.Fatalf("expected kit audit file at %s: %v", kitAuditPath, err)
	}
	if _, err := os.Stat(wrenAuditPath); err != nil {
		t.Fatalf("expected wren audit file at %s: %v", wrenAuditPath, err)
	}
	if _, err := os.Stat(sharedAuditPath); err == nil {
		t.Error("shared audit path should NOT be written when per-agent keys are in use")
	}

	// 7. audit verify --agent kit → passes with kit's public key.
	t.Setenv("NOCKGUARD_AGENT_KIT_ED25519_PUB", kitPub)
	kitVerify := exec.Command(binary, "audit", "verify", "--agent", "kit", "--audit-dir", dir)
	if out, err := kitVerify.CombinedOutput(); err != nil {
		t.Fatalf("audit verify --agent kit failed: %v\n%s", err, out)
	}

	// 8. audit verify --agent wren → passes with wren's public key.
	t.Setenv("NOCKGUARD_AGENT_WREN_ED25519_PUB", wrenPub)
	wrenVerify := exec.Command(binary, "audit", "verify", "--agent", "wren", "--audit-dir", dir)
	if out, err := wrenVerify.CombinedOutput(); err != nil {
		t.Fatalf("audit verify --agent wren failed: %v\n%s", err, out)
	}

	// 9. Swapped keys must FAIL (non-repudiation: kit's trail must not verify under wren's key).
	t.Setenv("NOCKGUARD_AGENT_WREN_ED25519_PUB", kitPub) // wrong key for wren
	wrenBadVerify := exec.Command(binary, "audit", "verify", "--agent", "wren", "--audit-dir", dir)
	if out, err := wrenBadVerify.CombinedOutput(); err == nil {
		t.Errorf("audit verify with wrong key should fail (non-repudiation violated)\n%s", out)
	}
}

// TestKeygenAgentOutputFormat verifies that `keygen --agent <name>` emits
// agent-namespaced variable names and a comment identifying the agent.
func TestKeygenAgentOutputFormat(t *testing.T) {
	binary := buildBinary(t)
	out, err := exec.Command(binary, "keygen", "--agent", "mira-nockos").Output()
	if err != nil {
		t.Fatalf("keygen --agent mira-nockos: %v", err)
	}
	s := string(out)
	if !strings.Contains(s, "NOCKGUARD_AGENT_MIRA_NOCKOS_ED25519_KEY=") {
		t.Errorf("missing private key line, got:\n%s", s)
	}
	if !strings.Contains(s, "NOCKGUARD_AGENT_MIRA_NOCKOS_ED25519_PUB=") {
		t.Errorf("missing public key line, got:\n%s", s)
	}
	if !strings.Contains(s, "mira-nockos") {
		t.Errorf("output should identify agent name in comments, got:\n%s", s)
	}
}

// TestKeygenLegacyUnchanged verifies that `keygen` (no --agent) still emits
// the legacy NOCKGUARD_AUDIT_ED25519_KEY / _PUB format.
func TestKeygenLegacyUnchanged(t *testing.T) {
	binary := buildBinary(t)
	out, err := exec.Command(binary, "keygen").Output()
	if err != nil {
		t.Fatalf("keygen: %v", err)
	}
	s := string(out)
	if !strings.Contains(s, "NOCKGUARD_AUDIT_ED25519_KEY=") {
		t.Errorf("legacy keygen missing NOCKGUARD_AUDIT_ED25519_KEY, got:\n%s", s)
	}
	if !strings.Contains(s, "NOCKGUARD_AUDIT_ED25519_PUB=") {
		t.Errorf("legacy keygen missing NOCKGUARD_AUDIT_ED25519_PUB, got:\n%s", s)
	}
}

// runProxyWith runs the nockguard proxy with a specific environment, feeding
// the given JSON-RPC requests and waiting for it to complete.
func runProxyWith(t *testing.T, binary, mockServer, policyFile, agent string, requests []string, env []string) {
	t.Helper()
	input := strings.Join(requests, "\n") + "\n"
	cmd := exec.Command(binary, "proxy",
		"--upstream", mockServer,
		"--agent", agent,
		"--policy", policyFile,
	)
	cmd.Stdin = strings.NewReader(input)
	cmd.Env = env
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("proxy --agent %s: %v\n%s", agent, err, out)
	}
}
