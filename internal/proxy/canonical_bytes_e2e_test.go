package proxy

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

// These tests drive the canonical-bytes enforcement that closes the four
// total-bypass holes (audit findings 1d#1-4): the proxy gated a PARSED view of
// the message but forwarded the RAW bytes, so any parser-differential — a
// top-level batch array, a duplicate "name" key, a notification-form tools/call
// with no id, or an unextractable name — let a tool call skip every gate.
//
// The assertion surface is a capture file recording the EXACT bytes the proxy
// forwarded upstream, so each test checks what the real MCP server would actually
// receive, not what the proxy thinks it sent.

// writeCaptureServer returns an --upstream command for a mock MCP server that
// appends every raw line it receives to capturePath and answers id-bearing
// tools/call requests with a trivial OK result.
func writeCaptureServer(t *testing.T, capturePath string) string {
	t.Helper()
	dir := t.TempDir()
	script := filepath.Join(dir, "capture-mcp.sh")
	content := `#!/bin/bash
while IFS= read -r line; do
  printf '%s\n' "$line" >> "` + capturePath + `"
  method=$(printf '%s' "$line" | python3 -c "import sys,json; print(json.load(sys.stdin).get('method',''))" 2>/dev/null)
  id=$(printf '%s' "$line" | python3 -c "import sys,json; print(json.load(sys.stdin).get('id',''))" 2>/dev/null)
  if [ "$method" = "tools/call" ] && [ -n "$id" ]; then
    printf '{"jsonrpc":"2.0","id":%s,"result":{"ok":true}}\n' "$id"
  fi
done
`
	if err := os.WriteFile(script, []byte(content), 0755); err != nil {
		t.Fatal(err)
	}
	return "bash " + script
}

// allow safe_tool, deny everything else (allow-list semantics).
func writeCanonicalPolicy(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()
	path := filepath.Join(dir, "policy.yaml")
	content := "agents:\n" +
		"  kit:\n" +
		"    allow:\n" +
		"      - \"safe_tool\"\n" +
		"    deny:\n" +
		"      - \"dangerous_tool\"\n"
	if err := os.WriteFile(path, []byte(content), 0644); err != nil {
		t.Fatal(err)
	}
	return path
}

// runProxyCapture pipes the given input lines through the proxy in front of the
// capture server and returns (agentStdout, forwardedUpstreamBytes).
func runProxyCapture(t *testing.T, input string) (string, string) {
	t.Helper()
	binary := buildBinary(t)
	dir := t.TempDir()
	capturePath := filepath.Join(dir, "upstream-capture.jsonl")
	if err := os.WriteFile(capturePath, nil, 0644); err != nil {
		t.Fatal(err)
	}
	mock := writeCaptureServer(t, capturePath)
	policyFile := writeCanonicalPolicy(t)

	cmd := exec.Command(binary, "proxy", "--upstream", mock, "--agent", "kit", "--policy", policyFile)
	cmd.Stdin = strings.NewReader(input)
	out, err := cmd.Output()
	if err != nil {
		// A non-zero exit is acceptable for some inputs; surface stderr for debugging.
		if ee, ok := err.(*exec.ExitError); ok {
			t.Logf("proxy stderr:\n%s", ee.Stderr)
		}
	}
	forwarded, _ := os.ReadFile(capturePath)
	return string(out), string(forwarded)
}

// 1d#1 — a top-level JSON-RPC batch array must NOT slip a tools/call past the
// gates. The array fails single-object Decode; the old code forwarded it raw.
func TestBatchArrayDoesNotBypassGates(t *testing.T) {
	input := `[{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"dangerous_tool"}}]` + "\n"
	agentOut, forwarded := runProxyCapture(t, input)

	if strings.Contains(forwarded, "dangerous_tool") {
		t.Errorf("batch-wrapped tools/call reached upstream (gate bypass):\nforwarded: %s", forwarded)
	}
	if !strings.Contains(agentOut, "nockguard") {
		t.Errorf("agent should get a nockguard rejection for a malformed/batch message; got: %s", agentOut)
	}
}

// 1d#2 — a notification-form tools/call (no id) must be gated, not waved through.
func TestNotificationFormToolCallIsGated(t *testing.T) {
	// Denied tool as a notification → must be dropped, never forwarded.
	_, forwarded := runProxyCapture(t,
		`{"jsonrpc":"2.0","method":"tools/call","params":{"name":"dangerous_tool"}}`+"\n")
	if strings.Contains(forwarded, "dangerous_tool") {
		t.Errorf("notification-form denied tools/call reached upstream (gate bypass):\nforwarded: %s", forwarded)
	}

	// Allowed tool as a notification → still forwarded (gate passes).
	_, forwarded2 := runProxyCapture(t,
		`{"jsonrpc":"2.0","method":"tools/call","params":{"name":"safe_tool"}}`+"\n")
	if !strings.Contains(forwarded2, "safe_tool") {
		t.Errorf("notification-form allowed tools/call should be forwarded; forwarded: %s", forwarded2)
	}
}

// 1d#1 — duplicate "name" keys: the proxy gates Go's last-value-wins view
// (safe_tool) but a first-key-wins upstream would run dangerous_tool. The fix
// forwards canonical bytes so upstream sees exactly the gated name, once.
func TestDuplicateKeyNameIsCanonicalized(t *testing.T) {
	input := `{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"dangerous_tool","name":"safe_tool"}}` + "\n"
	_, forwarded := runProxyCapture(t, input)

	if !strings.Contains(forwarded, "safe_tool") {
		t.Fatalf("expected the gated name in forwarded bytes; forwarded: %s", forwarded)
	}
	if strings.Contains(forwarded, "dangerous_tool") {
		t.Errorf("forwarded bytes still carry the shadow (first-key) name — parser differential open:\n%s", forwarded)
	}
	if n := strings.Count(forwarded, `"name"`); n != 1 {
		t.Errorf("forwarded params must carry exactly one name key, got %d:\n%s", n, forwarded)
	}
}

// 1d#4 — a tools/call whose name cannot be extracted (non-object params) must
// fail CLOSED. The old code only ran the deny check when toolName != "".
func TestUnextractableToolNameFailsClosed(t *testing.T) {
	input := `{"jsonrpc":"2.0","id":1,"method":"tools/call","params":"not-an-object"}` + "\n"
	agentOut, forwarded := runProxyCapture(t, input)

	if strings.Contains(forwarded, "tools/call") {
		t.Errorf("a tools/call with an unextractable name reached upstream (gate bypass):\nforwarded: %s", forwarded)
	}
	if !strings.Contains(agentOut, "nockguard") {
		t.Errorf("agent should get a nockguard rejection; got: %s", agentOut)
	}
}

// 1d#1 (top-level variant) — a DUPLICATE top-level "method" key is the same
// parser-differential one level up: Go parses it last-wins, so a second
// "method":"tools/list" can mask a "method":"tools/call", and a first-key-wins
// upstream would still run the masked call. The fix canonicalizes the whole
// top-level message, so the forwarded bytes carry exactly one method == the
// proxy's view — neither ordering can expose a different method upstream.
func TestDuplicateTopLevelMethodCannotBypass(t *testing.T) {
	// Case A: last-wins = tools/list masks a leading tools/call. Forwarded bytes
	// must NOT expose method=tools/call to a first-wins upstream.
	_, forwardedA := runProxyCapture(t,
		`{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"dangerous_tool"},"method":"tools/list"}`+"\n")
	if strings.Contains(forwardedA, "tools/call") {
		t.Errorf("forwarded bytes still expose method=tools/call to a first-wins upstream:\n%s", forwardedA)
	}
	if n := strings.Count(forwardedA, `"method"`); n > 1 {
		t.Errorf("forwarded message carries %d method keys (top-level differential open):\n%s", n, forwardedA)
	}

	// Case B: last-wins = tools/call (a denied tool) masked behind a leading
	// tools/list. The proxy gates on the canonical last-wins view → denied → the
	// call must NOT reach upstream.
	_, forwardedB := runProxyCapture(t,
		`{"jsonrpc":"2.0","id":1,"method":"tools/list","method":"tools/call","params":{"name":"dangerous_tool"}}`+"\n")
	if strings.Contains(forwardedB, "dangerous_tool") {
		t.Errorf("a denied tools/call masked by a duplicate method reached upstream:\n%s", forwardedB)
	}
}

// 1d#3 — an --agent value with no named policy AND no "default" must fail CLOSED
// (deny every tool), not silently allow everything.
func TestUnknownAgentFailsClosedE2E(t *testing.T) {
	binary := buildBinary(t)
	dir := t.TempDir()
	capturePath := filepath.Join(dir, "cap.jsonl")
	if err := os.WriteFile(capturePath, nil, 0644); err != nil {
		t.Fatal(err)
	}
	mock := writeCaptureServer(t, capturePath)
	policyFile := writeCanonicalPolicy(t) // defines "kit", no "default"

	cmd := exec.Command(binary, "proxy", "--upstream", mock, "--agent", "ghost", "--policy", policyFile)
	cmd.Stdin = strings.NewReader(`{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"safe_tool"}}` + "\n")
	out, _ := cmd.Output()
	forwarded, _ := os.ReadFile(capturePath)

	if strings.Contains(string(forwarded), "safe_tool") {
		t.Errorf("unconfigured agent should be denied; call reached upstream:\n%s", forwarded)
	}
	if !strings.Contains(string(out), "denied by policy") {
		t.Errorf("expected a policy-deny error back to the agent; got: %s", out)
	}
}

// Canonicalization must NOT mangle tool arguments — the whole reason "arguments"
// is kept as a verbatim RawMessage. A large integer must survive intact (not be
// re-encoded to 1.23e18), and floats / nested structures must pass through byte
// for byte. Proves the float-precision-safety design decision, not just asserts it.
func TestToolArgumentsPreservedThroughCanonicalization(t *testing.T) {
	input := `{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"safe_tool","arguments":{"big":1234567890123456789,"f":0.1,"nested":{"a":[1,2,3]}}}}` + "\n"
	_, forwarded := runProxyCapture(t, input)

	if !strings.Contains(forwarded, "safe_tool") {
		t.Fatalf("allowed call should be forwarded; forwarded: %s", forwarded)
	}
	if !strings.Contains(forwarded, "1234567890123456789") {
		t.Errorf("large integer argument was mangled (float re-encoding?):\n%s", forwarded)
	}
	if !strings.Contains(forwarded, "0.1") {
		t.Errorf("float argument was altered:\n%s", forwarded)
	}
	if !strings.Contains(forwarded, `"nested"`) || !strings.Contains(forwarded, "[1,2,3]") {
		t.Errorf("nested arguments not preserved verbatim:\n%s", forwarded)
	}
}

// Guardrail: a normal allowed call still works end-to-end and is forwarded.
func TestAllowedCallStillForwarded(t *testing.T) {
	input := `{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"safe_tool"}}` + "\n"
	_, forwarded := runProxyCapture(t, input)
	if !strings.Contains(forwarded, "safe_tool") {
		t.Errorf("allowed call should be forwarded upstream; forwarded: %s", forwarded)
	}
}
