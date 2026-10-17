package proxy

import (
	"bytes"
	"fmt"
	"io"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/nocktechnologies/nockguard/internal/approval"
	"github.com/nocktechnologies/nockguard/internal/audit"
)

type invalidatingApprover struct{ catalog *toolCatalog }

type blockedUpstreamWriter struct {
	started chan struct{}
	release chan struct{}
	bytes.Buffer
}

func (w *blockedUpstreamWriter) Write(p []byte) (int, error) {
	close(w.started)
	<-w.release
	return w.Buffer.Write(p)
}

func (a invalidatingApprover) Ask(approval.Request) approval.Verdict {
	a.catalog.invalidate()
	return approval.Verdict{Approved: true, Reason: "approved"}
}

func pinGate(t *testing.T, hash string, strict bool, auditor *audit.Auditor) *StdioProxy {
	t.Helper()
	text := fmt.Sprintf(`audit:
  enabled: true
  action_pairing: true
  sign_key_env: TEST_TOOL_PIN_SIGN_KEY
agents:
  demo:
    mode: allow
    strict_tool_pins: %t
    tool_pins:
      filesystem-local:
        read:
          hash_version: jcs-rfc8785-v1
          sha256: %s
`, strict, hash)
	gate := newGate(t, text, nil, auditor).WithUpstreamID("filesystem-local")
	gate.agentOut = io.Discard
	return gate
}

func TestOperatorPinsStrictAndSigned(t *testing.T) {
	approved := `{"name":"read","inputSchema":{}}`
	_, expected, err := digestToolDefinition([]byte(approved))
	if err != nil {
		t.Fatal(err)
	}
	auditor, path, pub := newEd25519Auditor(t)
	defer auditor.Close()
	gate := pinGate(t, expected, true, auditor)
	pending := &sync.Map{}
	call := func(id, tool string, forward bool) {
		t.Helper()
		var upstream bytes.Buffer
		if err := gate.agentToUpstream(strings.NewReader(callLine(id, tool, "private")+"\n"), &upstream, pending); err != nil {
			t.Fatal(err)
		}
		if (upstream.Len() > 0) != forward {
			t.Fatalf("tool %s forwarded=%t, want %t", tool, upstream.Len() > 0, forward)
		}
		if forward {
			if err := gate.upstreamToAgent(strings.NewReader(`{"jsonrpc":"2.0","id":`+id+`,"result":{}}`+"\n"), io.Discard, pending, nil); err != nil {
				t.Fatal(err)
			}
		}
	}
	call("1", "read", false) // configured pin cannot be approved before observation
	if names := listedNames(t, listPage(t, gate, pending, listRequest(2, ""), listResponse(2, `[ `+approved+`,{"name":"new","inputSchema":{}}]`, ""))); len(names) != 1 || names[0] != "read" {
		t.Fatalf("strict listing advertised unpinned tool: %v", names)
	}
	call("3", "read", true)
	call("4", "new", false)
	changed := `{"name":"read","description":"changed","inputSchema":{}}`
	_, observed, err := digestToolDefinition([]byte(changed))
	if err != nil {
		t.Fatal(err)
	}
	if names := listedNames(t, listPage(t, gate, pending, listRequest(5, ""), listResponse(5, `[`+changed+`]`, ""))); len(names) != 0 {
		t.Fatalf("mismatched definition advertised: %v", names)
	}
	call("6", "read", false) // re-list must never rewrite the operator pin
	unhashable := `{"name":"read","inputSchema":{"properties":{"x":{},"x":{}}}}`
	if names := listedNames(t, listPage(t, gate, pending, listRequest(8, ""), listResponse(8, `[`+unhashable+`]`, ""))); len(names) != 0 {
		t.Fatalf("unhashable pinned definition advertised: %v", names)
	}
	call("9", "read", false)
	if err := gate.upstreamToAgent(strings.NewReader(`{"jsonrpc":"2.0","method":"notifications/tools/list_changed"}`+"\n"), io.Discard, pending, nil); err != nil {
		t.Fatal(err)
	}
	call("10", "read", false)
	rows := actionEvents(readAuditEvents(t, path))
	var matched, mismatch, unpinned, unhashableBlocked, refreshed bool
	for _, row := range rows {
		if row.Tool != "read" && row.Tool != "new" {
			continue
		}
		if row.Tool == "read" && row.ToolPinHash != expected {
			t.Fatalf("expected hash changed: %+v", row)
		}
		switch row.ToolPinStatus {
		case "matched":
			matched = row.ToolDefinitionHash == expected
		case "mismatch":
			mismatch = row.ToolDefinitionHash == observed && row.Cause == "pin_mismatch" || mismatch
		case "unpinned":
			unpinned = row.Tool == "new" && row.Cause == "pin_unverified" || unpinned
		case "unhashable":
			unhashableBlocked = row.Tool == "read" && row.Cause == "pin_unverified" || unhashableBlocked
		case "unobserved":
			refreshed = row.Tool == "read" && row.Cause == "tool_catalog_refresh_required" || refreshed
		}
	}
	if !matched || !mismatch || !unpinned || !unhashableBlocked || !refreshed {
		t.Fatalf("missing signed pin controls: matched=%t mismatch=%t unpinned=%t unhashable=%t refresh=%t rows=%+v", matched, mismatch, unpinned, unhashableBlocked, refreshed, rows)
	}
	if _, err := audit.VerifyEd25519(path, pub); err != nil {
		t.Fatalf("signed pin rows did not verify: %v", err)
	}
}

func TestCatalogAttributionInvalidatesPinnedObservation(t *testing.T) {
	definition := `{"name":"read","inputSchema":{}}`
	_, hash, err := digestToolDefinition([]byte(definition))
	if err != nil {
		t.Fatal(err)
	}
	for _, invalid := range []string{
		`{"jsonrpc":"2.0","id":2,"method":"tools/list","params":{"Cursor":"x"}}`,
		`{"jsonrpc":"2.0","id":2,"method":"tools/list","params":"bad"}`,
		`{"jsonrpc":"2.0","id":2,"method":"tools/list","params":{"cursor":"x"},"Params":{}}`,
		`{"jsonrpc":"2.0","id":2,"method":"tools/list","params":{},"params":{"cursor":"x"}}`,
	} {
		t.Run(invalid, func(t *testing.T) {
			auditor, _, _ := newEd25519Auditor(t)
			defer auditor.Close()
			gate := pinGate(t, hash, false, auditor)
			pending := &sync.Map{}
			listedNames(t, listPage(t, gate, pending, listRequest(1, ""), listResponse(1, `[`+definition+`]`, "")))
			if gate.catalog.observe("read").hash != hash {
				t.Fatal("baseline catalog missing")
			}
			if err := gate.agentToUpstream(strings.NewReader(invalid+"\n"), io.Discard, pending); err != nil {
				t.Fatal(err)
			}
			if gate.catalog.observe("read").status != "unobserved" {
				t.Fatal("unattributed request retained approved observation")
			}
			var forwarded bytes.Buffer
			if err := gate.agentToUpstream(strings.NewReader(callLine("3", "read", "private")+"\n"), &forwarded, pending); err != nil {
				t.Fatal(err)
			}
			if forwarded.Len() != 0 {
				t.Fatal("pinned call forwarded after invalid listing")
			}
		})
	}
}

func TestConfiguredPinIsEnforcedWithoutStrictMode(t *testing.T) {
	definition := `{"name":"read","inputSchema":{}}`
	_, expected, err := digestToolDefinition([]byte(definition))
	if err != nil {
		t.Fatal(err)
	}
	auditor, _, _ := newEd25519Auditor(t)
	defer auditor.Close()
	gate := pinGate(t, expected, false, auditor)
	pending := &sync.Map{}
	listedNames(t, listPage(t, gate, pending, listRequest(1, ""), listResponse(1, `[`+definition+`,{"name":"new","inputSchema":{}}]`, "")))
	var upstream bytes.Buffer
	if err := gate.agentToUpstream(strings.NewReader(callLine("2", "new", "private")+"\n"), &upstream, pending); err != nil {
		t.Fatal(err)
	}
	if upstream.Len() == 0 {
		t.Fatal("unpinned tool was blocked with strict mode off")
	}
	if err := gate.upstreamToAgent(strings.NewReader(`{"jsonrpc":"2.0","id":2,"result":{}}`+"\n"), io.Discard, pending, nil); err != nil {
		t.Fatal(err)
	}
	gate.catalog.invalidate()
	upstream.Reset()
	if err := gate.agentToUpstream(strings.NewReader(callLine("3", "read", "private")+"\n"), &upstream, pending); err != nil {
		t.Fatal(err)
	}
	if upstream.Len() != 0 {
		t.Fatal("configured pin was bypassed with strict mode off")
	}
}

func TestToolPinsRefuseUnsignedAuditor(t *testing.T) {
	_, hash, err := digestToolDefinition([]byte(`{"name":"read","inputSchema":{}}`))
	if err != nil {
		t.Fatal(err)
	}
	auditor, err := audit.New(t.TempDir() + "/audit.jsonl")
	if err != nil {
		t.Fatal(err)
	}
	defer auditor.Close()
	gate := pinGate(t, hash, true, auditor)
	if gate.actionInitErr == nil {
		t.Fatal("pin policy accepted an unsigned audit writer")
	}
}

func TestPaginatedCatalogCannotAuthorizePin(t *testing.T) {
	definition := `{"name":"read","inputSchema":{}}`
	_, hash, err := digestToolDefinition([]byte(definition))
	if err != nil {
		t.Fatal(err)
	}
	auditor, _, _ := newEd25519Auditor(t)
	defer auditor.Close()
	gate := pinGate(t, hash, true, auditor)
	pending := &sync.Map{}
	if names := listedNames(t, listPage(t, gate, pending, listRequest(1, ""), listResponse(1, `[`+definition+`]`, `,"nextCursor":"p2"`))); len(names) != 0 {
		t.Fatalf("paginated listing advertised unverified pin: %v", names)
	}
	listedNames(t, listPage(t, gate, pending, listRequest(2, "p2"), listResponse(2, `[]`, "")))
	if gate.catalog.observe("read").status != "unobserved" {
		t.Fatal("paginated catalog claimed verified definition")
	}
	var upstream bytes.Buffer
	if err := gate.agentToUpstream(strings.NewReader(callLine("3", "read", "private")+"\n"), &upstream, pending); err != nil {
		t.Fatal(err)
	}
	if upstream.Len() != 0 {
		t.Fatal("paginated catalog authorized pinned call")
	}
}

func TestPinInvalidatedDuringApprovalHasCurrentSignedRejection(t *testing.T) {
	definition := `{"name":"read","inputSchema":{}}`
	_, hash, err := digestToolDefinition([]byte(definition))
	if err != nil {
		t.Fatal(err)
	}
	auditor, path, pub := newEd25519Auditor(t)
	defer auditor.Close()
	policyText := fmt.Sprintf(`audit:
  enabled: true
  action_pairing: true
  sign_key_env: TEST_TOOL_PIN_SIGN_KEY
agents:
  demo:
    mode: allow
    ask: [read]
    tool_pins:
      filesystem-local:
        read:
          hash_version: jcs-rfc8785-v1
          sha256: %s
`, hash)
	gate := newGate(t, policyText, nil, auditor).WithUpstreamID("filesystem-local")
	gate.agentOut = io.Discard
	gate.WithApprover(invalidatingApprover{catalog: &gate.catalog})
	pending := &sync.Map{}
	listedNames(t, listPage(t, gate, pending, listRequest(1, ""), listResponse(1, `[`+definition+`]`, "")))
	var upstream bytes.Buffer
	if err := gate.agentToUpstream(strings.NewReader(callLine("2", "read", "private")+"\n"), &upstream, pending); err != nil {
		t.Fatal(err)
	}
	if upstream.Len() != 0 {
		t.Fatal("approval bypassed invalidated pin")
	}
	var blocked, terminal bool
	rows := actionEvents(readAuditEvents(t, path))
	for _, row := range rows {
		if row.Decision == "block" && row.Reason == "tool_catalog_refresh_required" {
			blocked = row.ToolPinStatus == "unobserved" && row.ToolPinHash == hash && row.ToolDefinitionHash == ""
		}
		if row.Observation == "not_forwarded" && row.Cause == "tool_catalog_refresh_required" {
			terminal = row.ToolPinStatus == "unobserved" && row.ToolPinHash == hash && row.ToolDefinitionHash == ""
		}
	}
	if !blocked || !terminal {
		t.Fatalf("signed rejection did not reflect invalidation: block=%t terminal=%t rows=%+v", blocked, terminal, rows)
	}
	if _, err := audit.VerifyEd25519(path, pub); err != nil {
		t.Fatal(err)
	}
}

func TestPinWriteDoesNotBlockCatalogInvalidation(t *testing.T) {
	definition := `{"name":"read","inputSchema":{}}`
	_, hash, err := digestToolDefinition([]byte(definition))
	if err != nil {
		t.Fatal(err)
	}
	auditor, _, _ := newEd25519Auditor(t)
	defer auditor.Close()
	gate := pinGate(t, hash, true, auditor)
	pending := &sync.Map{}
	listedNames(t, listPage(t, gate, pending, listRequest(1, ""), listResponse(1, `[`+definition+`]`, "")))
	writer := &blockedUpstreamWriter{started: make(chan struct{}), release: make(chan struct{})}
	done := make(chan error, 1)
	go func() {
		done <- gate.agentToUpstream(strings.NewReader(callLine("2", "read", "private")+"\n"), writer, pending)
	}()
	select {
	case <-writer.started:
	case <-time.After(2 * time.Second):
		t.Fatal("pinned call never reached upstream write")
	}
	invalidated := make(chan struct{})
	go func() { gate.catalog.invalidate(); close(invalidated) }()
	select {
	case <-invalidated:
	case <-time.After(2 * time.Second):
		close(writer.release)
		t.Fatal("blocked upstream write held the catalog lock and stalled invalidation")
	}
	close(writer.release)
	select {
	case err := <-done:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("pinned upstream write did not finish")
	}
	var forwarded bytes.Buffer
	if err := gate.agentToUpstream(strings.NewReader(callLine("3", "read", "private")+"\n"), &forwarded, pending); err != nil {
		t.Fatal(err)
	}
	if forwarded.Len() != 0 {
		t.Fatal("pin remained callable after invalidation")
	}
}
