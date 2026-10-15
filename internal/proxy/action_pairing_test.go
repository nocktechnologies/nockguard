package proxy

import (
	"bytes"
	"encoding/json"
	"io"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/nocktechnologies/nockguard/internal/approval"
	"github.com/nocktechnologies/nockguard/internal/audit"
	"github.com/nocktechnologies/nockguard/internal/extract"
)

func newActionPairingGate(t *testing.T, auditor *audit.Auditor, deny string) *StdioProxy {
	t.Helper()
	policyText := `audit:
  enabled: true
  action_pairing: true
agents:
  demo:
    mode: allow
`
	if deny != "" {
		policyText = strings.Replace(policyText, "    mode: allow\n", "    mode: allow\n    deny: [\""+deny+"\"]\n", 1)
	}
	gate := newGate(t, policyText, nil, auditor)
	if !gate.actionPairing {
		t.Fatal("audit.action_pairing should enable the stdio writer")
	}
	return gate
}

func callLine(id, tool, secret string) string {
	return `{"jsonrpc":"2.0","id":` + id + `,"method":"tools/call","params":{"name":"` + tool + `","arguments":{"private":"` + secret + `"}}}`
}

func actionEvents(events []audit.Event) []audit.Event {
	var out []audit.Event
	for _, ev := range events {
		if ev.ActionID != "" {
			out = append(out, ev)
		}
	}
	return out
}

func TestStdioActionPairingResponseIsDurableAndPrivate(t *testing.T) {
	auditor, path, pub := newEd25519Auditor(t)
	defer auditor.Close()
	gate := newActionPairingGate(t, auditor, "")
	pending := &sync.Map{}
	var upstream bytes.Buffer
	call := callLine("1", "read_private", "request-secret")
	if err := gate.agentToUpstream(strings.NewReader(call+"\n"), &upstream, pending); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(upstream.String(), "read_private") {
		t.Fatalf("allowed call was not forwarded: %s", upstream.String())
	}

	var agent bytes.Buffer
	response := `{"jsonrpc":"2.0","id":1,"result":{"isError":false,"content":[{"text":"response-secret"}]}}` + "\n"
	if err := gate.upstreamToAgent(strings.NewReader(response), &agent, pending, nil); err != nil {
		t.Fatal(err)
	}
	events := readAuditEvents(t, path)
	paired := actionEvents(events)
	if len(paired) != 3 {
		t.Fatalf("action rows = %+v; want dispatch, decision, and terminal observation", paired)
	}
	if paired[0].Decision != "dispatch" || paired[0].RecordType != "decision" {
		t.Fatalf("first action row = %+v; want dispatch", paired[0])
	}
	if paired[1].RecordType != "decision" || paired[1].Decision != "allow" {
		t.Fatalf("second action row = %+v; want allow decision", paired[1])
	}
	terminal := paired[2]
	if terminal.RecordType != "action_observation" || terminal.Observation != "response_observed" || terminal.ResponseClass != "jsonrpc_result" || terminal.MCPIsError == nil || *terminal.MCPIsError {
		t.Fatalf("terminal row = %+v; want observed result with mcp_is_error=false", terminal)
	}
	for _, ev := range paired {
		if ev.ActionID != paired[0].ActionID || ev.SchemaVersion != 2 || ev.RunID == "" || ev.RunSeq == 0 {
			t.Fatalf("action correlation fields differ: %+v", paired)
		}
	}
	if strings.Contains(string(mustRead(t, path)), "request-secret") || strings.Contains(string(mustRead(t, path)), "response-secret") {
		t.Fatal("audit trail contains request or response content")
	}
	if _, err := audit.VerifyEd25519(path, pub); err != nil {
		t.Fatalf("signed v2 trail did not verify: %v", err)
	}
}

func TestStdioActionPairingOutOfOrderResponsesAndRetries(t *testing.T) {
	auditor, path, _ := newEd25519Auditor(t)
	defer auditor.Close()
	gate := newActionPairingGate(t, auditor, "")
	pending := &sync.Map{}
	input := callLine("1", "tool_one", "a") + "\n" + callLine("2", "tool_two", "b") + "\n"
	if err := gate.agentToUpstream(strings.NewReader(input), io.Discard, pending); err != nil {
		t.Fatal(err)
	}
	responses := `{"jsonrpc":"2.0","id":2,"result":{}}` + "\n" + `{"jsonrpc":"2.0","id":1,"result":{}}` + "\n"
	if err := gate.upstreamToAgent(strings.NewReader(responses), io.Discard, pending, nil); err != nil {
		t.Fatal(err)
	}

	// A client may retry with the same JSON-RPC id after receiving the first
	// response. The action identity must come from the proxy counter instead.
	if err := gate.agentToUpstream(strings.NewReader(callLine("1", "tool_one", "retry")+"\n"), io.Discard, pending); err != nil {
		t.Fatal(err)
	}
	if err := gate.upstreamToAgent(strings.NewReader(`{"jsonrpc":"2.0","id":1,"result":{}}`+"\n"), io.Discard, pending, nil); err != nil {
		t.Fatal(err)
	}

	events := actionEvents(readAuditEvents(t, path))
	ids := map[string]struct{}{}
	dispatches, terminalCount := 0, 0
	for _, ev := range events {
		if ev.Decision == "dispatch" {
			dispatches++
			ids[ev.ActionID] = struct{}{}
		}
		if ev.RecordType == "action_observation" && ev.Observation == "response_observed" {
			terminalCount++
		}
	}
	if dispatches != 3 || terminalCount != 3 || len(ids) != 3 {
		t.Fatalf("dispatches=%d observed=%d unique action ids=%d; want 3 of each; rows=%+v", dispatches, terminalCount, len(ids), events)
	}
}

func TestStdioActionPairingUsesCanonicalMethodBeforeGating(t *testing.T) {
	auditor, path, _ := newEd25519Auditor(t)
	defer auditor.Close()
	gate := newActionPairingGate(t, auditor, "")
	pending := &sync.Map{}
	line := `{"jsonrpc":"2.0","method":"tools/call","Method":"initialize","id":3,"params":{"name":"alias_tool"}}` + "\n"
	if err := gate.agentToUpstream(strings.NewReader(line), io.Discard, pending); err != nil {
		t.Fatal(err)
	}
	if err := gate.upstreamToAgent(strings.NewReader(`{"jsonrpc":"2.0","id":3,"result":{}}`+"\n"), io.Discard, pending, nil); err != nil {
		t.Fatal(err)
	}
	rows := actionEvents(readAuditEvents(t, path))
	var dispatch, observation int
	for _, ev := range rows {
		if ev.Decision == "dispatch" {
			dispatch++
		}
		if ev.Observation == "response_observed" {
			observation++
		}
	}
	if dispatch != 1 || observation != 1 {
		t.Fatalf("canonical tools/call rows dispatch/observed=%d/%d; want 1/1: %+v", dispatch, observation, rows)
	}
}

func TestStdioActionPairingRejectsActiveRequestIDReuse(t *testing.T) {
	auditor, path, _ := newEd25519Auditor(t)
	defer auditor.Close()
	gate := newActionPairingGate(t, auditor, "")
	pending := &sync.Map{}
	forwarded := 0
	upstream := auditWriteCheck(func(line []byte) (int, error) {
		forwarded++
		return len(line), nil
	})
	if err := gate.agentToUpstream(strings.NewReader(callLine("5", "first_tool", "a")+"\n"), upstream, pending); err != nil {
		t.Fatal(err)
	}
	if !pendingIDInUse(pending, []byte("5")) {
		t.Fatal("first forwarded request was not left pending")
	}
	_, _, duplicate, failure := canonicalizeMessage([]byte(callLine("5", "second_tool", "b")))
	if failure != canonicalMessageOK || duplicate == nil || !duplicate.IsRequest() || !pendingIDInUse(pending, duplicate.ID) {
		t.Fatalf("duplicate check setup failed: failure=%v message=%+v", failure, duplicate)
	}
	var agent bytes.Buffer
	gate.agentOut = &agent
	if err := gate.agentToUpstream(strings.NewReader(callLine("5", "second_tool", "b")+"\n"), upstream, pending); err != nil {
		t.Fatal(err)
	}
	toolList := `{"jsonrpc":"2.0","id":5,"method":"tools/list","params":{}}` + "\n"
	if err := gate.agentToUpstream(strings.NewReader(toolList), upstream, pending); err != nil {
		t.Fatal(err)
	}
	if forwarded != 1 {
		t.Fatalf("duplicate active request was forwarded; upstream writes=%d", forwarded)
	}
	if !strings.Contains(agent.String(), "duplicate active JSON-RPC request id") {
		t.Fatalf("duplicate request received no clear rejection: %s", agent.String())
	}
	if _, ok := pending.Load("5"); !ok {
		t.Fatal("duplicate request replaced the original pending action")
	}
	if err := gate.upstreamToAgent(strings.NewReader(`{"jsonrpc":"2.0","id":5,"result":{}}`+"\n"), io.Discard, pending, nil); err != nil {
		t.Fatal(err)
	}
	rows := actionEvents(readAuditEvents(t, path))
	var dispatch, observed, notForwarded int
	for _, ev := range rows {
		if ev.Decision == "dispatch" {
			dispatch++
		}
		if ev.Observation == "response_observed" {
			observed++
		}
		if ev.Observation == "not_forwarded" {
			notForwarded++
		}
	}
	if dispatch != 1 || observed != 1 || notForwarded != 1 {
		t.Fatalf("dispatch/observed/not-forwarded=%d/%d/%d; want 1/1/1: %+v", dispatch, observed, notForwarded, rows)
	}
}

func TestStdioActionPairingMatchesDecodedStringRequestID(t *testing.T) {
	auditor, path, _ := newEd25519Auditor(t)
	defer auditor.Close()
	gate := newActionPairingGate(t, auditor, "")
	pending := &sync.Map{}
	call := `{"jsonrpc":"2.0","id":"\u0061","method":"tools/call","params":{"name":"string_id_tool","arguments":{}}}` + "\n"
	if err := gate.agentToUpstream(strings.NewReader(call), io.Discard, pending); err != nil {
		t.Fatal(err)
	}
	response := `{"jsonrpc":"2.0","id":"a","result":{}}` + "\n"
	if err := gate.upstreamToAgent(strings.NewReader(response), io.Discard, pending, nil); err != nil {
		t.Fatal(err)
	}
	for _, ev := range actionEvents(readAuditEvents(t, path)) {
		if ev.Observation == "response_observed" {
			return
		}
	}
	t.Fatal("equivalent decoded JSON-RPC string id did not settle the pending action")
}

func TestStdioActionPairingFailedNotificationWriteIsUnknown(t *testing.T) {
	auditor, path, pub := newEd25519Auditor(t)
	defer auditor.Close()
	gate := newActionPairingGate(t, auditor, "")
	pending := &sync.Map{}
	writeErr := os.ErrClosed
	upstream := auditWriteCheck(func(line []byte) (int, error) {
		return len(line) / 2, writeErr // a short/partial write cannot prove the call was not received
	})
	call := `{"jsonrpc":"2.0","method":"tools/call","params":{"name":"notify_tool","arguments":{"private":"secret"}}}` + "\n"
	if err := gate.agentToUpstream(strings.NewReader(call), upstream, pending); err == nil {
		t.Fatal("failed notification write returned nil")
	}
	rows := actionEvents(readAuditEvents(t, path))
	var dispatch, unknown int
	for _, ev := range rows {
		if ev.Decision == "dispatch" {
			dispatch++
		}
		if ev.Observation == "outcome_unknown" && ev.Cause == "transport_lost" {
			unknown++
		}
	}
	if dispatch != 1 || unknown != 1 {
		t.Fatalf("failed notification lifecycle dispatch/unknown=%d/%d; want 1/1: %+v", dispatch, unknown, rows)
	}
	if _, err := audit.VerifyEd25519(path, pub); err != nil {
		t.Fatalf("failed notification v2 trail did not verify: %v", err)
	}
}

func TestStdioActionPairingFastReplyIsNotHeldByEarlierSlowCall(t *testing.T) {
	auditor, path, _ := newEd25519Auditor(t)
	defer auditor.Close()
	gate := newActionPairingGate(t, auditor, "")
	pending := &sync.Map{}
	forwardedCalls := 0
	upstreamWriter := auditWriteCheck(func(line []byte) (int, error) {
		if strings.Contains(string(line), `"method":"tools/call"`) {
			forwardedCalls++
		}
		return len(line), nil
	})
	var rejected bytes.Buffer
	gate.agentOut = &rejected
	input := callLine("1", "slow_tool", "a") + "\n" + callLine("2", "fast_tool", "b") + "\n"
	if err := gate.agentToUpstream(strings.NewReader(input), upstreamWriter, pending); err != nil {
		t.Fatal(err)
	}

	upstreamRead, upstreamWrite := io.Pipe()
	defer upstreamWrite.Close()
	agentLines := make(chan string, 4)
	agentWriter := auditWriteCheck(func(line []byte) (int, error) {
		agentLines <- string(line)
		return len(line), nil
	})
	outputErr := make(chan error, 1)
	go func() { outputErr <- gate.upstreamToAgent(upstreamRead, agentWriter, pending, nil) }()

	if _, err := io.WriteString(upstreamWrite, `{"jsonrpc":"2.0","id":2,"result":{"ok":true}}`+"\n"); err != nil {
		t.Fatal(err)
	}
	select {
	case got := <-agentLines:
		if !strings.Contains(got, `"id":2`) {
			t.Fatalf("fast response = %s; want id 2", got)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("fast response was held behind the earlier slow call")
	}
	deadline := time.Now().Add(2 * time.Second)
	var rows []audit.Event
	for {
		requestIDInUse := gate.requestIDInUse(pending, []byte("2"))
		rows = actionEvents(readAuditEvents(t, path))
		fastTerminalWritten := false
		for _, ev := range rows {
			if ev.Tool == "fast_tool" && ev.Observation == "response_observed" {
				fastTerminalWritten = true
				break
			}
		}
		if !requestIDInUse && fastTerminalWritten {
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("fast action did not finish durably before deadline: request_id_in_use=%v rows=%+v", requestIDInUse, rows)
		}
		time.Sleep(time.Millisecond)
	}
	var slowDispatch, slowAllow, slowTerminal, fastAllow, fastTerminal int
	for _, ev := range rows {
		switch ev.Tool {
		case "slow_tool":
			if ev.Decision == "dispatch" {
				slowDispatch++
			}
			if ev.Decision == "allow" {
				slowAllow++
			}
			if ev.Observation != "" {
				slowTerminal++
			}
		case "fast_tool":
			if ev.Decision == "allow" {
				fastAllow++
			}
			if ev.Observation == "response_observed" {
				fastTerminal++
			}
		}
	}
	if slowDispatch != 1 || slowAllow != 0 || slowTerminal != 0 || fastAllow != 1 || fastTerminal != 1 {
		t.Fatalf("fast action rows were not durable before its reply, or the slow action was settled early: slow=%d/%d/%d fast=%d/%d rows=%+v", slowDispatch, slowAllow, slowTerminal, fastAllow, fastTerminal, rows)
	}

	if err := gate.agentToUpstream(strings.NewReader(callLine("2", "retry_tool", "c")+"\n"), upstreamWriter, pending); err != nil {
		t.Fatal(err)
	}
	if forwardedCalls != 3 || strings.Contains(rejected.String(), "duplicate active JSON-RPC request id") {
		t.Fatalf("request ID could not be retried after delivery: forwards=%d rejection=%s", forwardedCalls, rejected.String())
	}
	if _, err := io.WriteString(upstreamWrite, `{"jsonrpc":"2.0","id":2,"result":{"ok":true}}`+"\n"); err != nil {
		t.Fatal(err)
	}
	select {
	case got := <-agentLines:
		if !strings.Contains(got, `"id":2`) {
			t.Fatalf("retry response = %s; want id 2", got)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("retry response was not delivered")
	}
	cancel := `{"jsonrpc":"2.0","method":"notifications/cancelled","params":{"requestId":1}}` + "\n"
	if err := gate.agentToUpstream(strings.NewReader(cancel), upstreamWriter, pending); err != nil {
		t.Fatal(err)
	}
	rows = actionEvents(readAuditEvents(t, path))
	var unknown, fastObserved, retryObserved int
	for _, ev := range rows {
		if ev.Tool == "slow_tool" && ev.Observation == "outcome_unknown" && ev.Cause == "client_cancel" {
			unknown++
		}
		if ev.Tool == "fast_tool" && ev.Observation == "response_observed" {
			fastObserved++
		}
		if ev.Tool == "retry_tool" && ev.Observation == "response_observed" {
			retryObserved++
		}
	}
	if unknown != 1 || fastObserved != 1 || retryObserved != 1 {
		t.Fatalf("slow/fast/retry terminal counts=%d/%d/%d; want 1/1/1: %+v", unknown, fastObserved, retryObserved, rows)
	}
	upstreamWrite.Close()
	if err := <-outputErr; err != nil {
		t.Fatal(err)
	}
}

func TestStdioActionPairingPrunesCardHistoryAfterFlushedActions(t *testing.T) {
	auditor, path, _ := newEd25519Auditor(t)
	defer auditor.Close()
	gate := newActionPairingGate(t, auditor, "")

	const count = 100
	const emptyCount = 100
	gate.auditMutex.Lock()
	gate.actionIDs[0] = gate.actionRunID + ".1"
	gate.auditPending[0] = struct{}{}
	gate.auditMutex.Unlock()
	gate.appendAudit(0, "slow_tool", "allow", "forwarded", nil)
	for i := 1; i <= count; i++ {
		seq := uint64(i)
		gate.auditMutex.Lock()
		gate.actionIDs[seq] = gate.actionRunID + "." + strconv.Itoa(i+1)
		gate.auditPending[seq] = struct{}{}
		gate.auditMutex.Unlock()
		gate.appendAudit(seq, "nockcc_nock_claim", "allow", "forwarded", nil)
		gate.updateCardState(seq, "nockcc_nock_claim", &extract.References{NockID: i + 1})
		gate.resolveAudit(seq)
	}
	for i := count + 1; i <= count+emptyCount; i++ {
		seq := uint64(i)
		gate.auditMutex.Lock()
		gate.auditPending[seq] = struct{}{}
		gate.auditMutex.Unlock()
		gate.resolveAudit(seq) // e.g. a ping or empty tools/list with no audit rows
	}
	if got := len(gate.auditResolved); got != 1 {
		t.Fatalf("resolved ranges = %d, want one compact range behind slow sequence 0", got)
	}
	if got := len(gate.actionIDs); got != 1 {
		t.Fatalf("action IDs retained = %d, want only the slow action", got)
	}
	if got := len(gate.auditPending); got != 1 {
		t.Fatalf("pending sequences retained = %d, want only the slow action", got)
	}
	if got := len(gate.cardAfterSeq); got > 1 {
		t.Fatalf("card history has %d entries after %d out-of-order completions, want at most 1", got, count)
	}

	gate.updateCardState(0, "nockcc_nock_claim", &extract.References{NockID: 999})
	gate.resolveAudit(0)
	futureSeq := uint64(count + emptyCount + 1)
	gate.appendAudit(futureSeq, "future_tool", "allow", "forwarded", nil)
	gate.resolveAudit(futureSeq)
	rows := readAuditEvents(t, path)
	if len(rows) != count+2 {
		t.Fatalf("audit rows = %d, want %d", len(rows), count+2)
	}
	last := rows[len(rows)-1]
	if last.Tool != "future_tool" || last.NockID != count+1 {
		t.Fatalf("future row = %+v, want card stamp %d after pruning", last, count+1)
	}
}

func TestStdioActionPairingRetainsCardStateForPendingToolsList(t *testing.T) {
	auditor, path, _ := newEd25519Auditor(t)
	defer auditor.Close()
	gate := newActionPairingGate(t, auditor, "")

	gate.auditMutex.Lock()
	gate.actionIDs[0] = gate.actionRunID + ".1"
	gate.auditPending[0] = struct{}{}
	gate.auditMutex.Unlock()
	gate.appendAudit(0, "nockcc_nock_claim", "allow", "forwarded", nil)
	gate.updateCardState(0, "nockcc_nock_claim", &extract.References{NockID: 111})
	gate.resolveAudit(0)

	gate.auditMutex.Lock()
	gate.auditPending[1] = struct{}{} // tools/list has not produced hide rows yet
	gate.actionIDs[2] = gate.actionRunID + ".2"
	gate.auditPending[2] = struct{}{}
	gate.auditMutex.Unlock()
	gate.appendAudit(2, "nockcc_nock_claim", "allow", "forwarded", nil)
	gate.updateCardState(2, "nockcc_nock_claim", &extract.References{NockID: 222})
	gate.resolveAudit(2)
	if got := gate.cardAfterSeq[0]; got != 111 {
		t.Fatalf("card state before pending tools/list = %d, want 111", got)
	}

	gate.appendAudit(1, "hidden_tool", "hide", "policy", nil)
	gate.resolveAudit(1)
	for _, ev := range readAuditEvents(t, path) {
		if ev.Tool == "hidden_tool" {
			if ev.NockID != 111 {
				t.Fatalf("tools/list hide row card = %d, want predecessor card 111", ev.NockID)
			}
			return
		}
	}
	t.Fatal("tools/list hide row was not recorded")
}

type closeObservedPipeReader struct {
	*io.PipeReader
	readEnded chan struct{}
	once      sync.Once
}

func (r *closeObservedPipeReader) Read(p []byte) (int, error) {
	n, err := r.PipeReader.Read(p)
	if err != nil {
		r.once.Do(func() { close(r.readEnded) })
	}
	return n, err
}

func TestStdioActionPairingStopsScannerWhenAgentWriteFails(t *testing.T) {
	auditor, _, _ := newEd25519Auditor(t)
	defer auditor.Close()
	gate := newActionPairingGate(t, auditor, "")
	pending := &sync.Map{}
	if err := gate.agentToUpstream(strings.NewReader(callLine("1", "tool_one", "private")+"\n"), io.Discard, pending); err != nil {
		t.Fatal(err)
	}
	pipeReader, pipeWriter := io.Pipe()
	defer pipeWriter.Close()
	reader := &closeObservedPipeReader{PipeReader: pipeReader, readEnded: make(chan struct{})}
	outputErr := make(chan error, 1)
	go func() {
		outputErr <- gate.upstreamToAgent(reader, auditWriteCheck(func([]byte) (int, error) {
			return 0, os.ErrClosed
		}), pending, nil)
	}()
	if _, err := io.WriteString(pipeWriter, `{"jsonrpc":"2.0","id":1,"result":{}}`+"\n"); err != nil {
		t.Fatal(err)
	}
	select {
	case err := <-outputErr:
		if err == nil {
			t.Fatal("closed agent writer returned nil")
		}
	case <-time.After(2 * time.Second):
		t.Fatal("upstream response loop did not return after the agent write failed")
	}
	select {
	case <-reader.readEnded:
	case <-time.After(2 * time.Second):
		t.Fatal("scanner reader remained blocked after the response loop returned")
	}
}

func TestStdioActionPairingEmptyToolDoesNotLatchRequiredWriter(t *testing.T) {
	auditor, path, _ := newEd25519Auditor(t)
	defer auditor.Close()
	gate := newGate(t, `audit:
  enabled: true
  action_pairing: true
agents:
  demo:
    mode: allow
    fail_mode: ask
`, nil, auditor)
	gate.WithApprover(approval.NewStaticApprover(true, "approved by test"))
	pending := &sync.Map{}
	var upstream, agent bytes.Buffer
	gate.agentOut = &agent
	input := callLine("1", "", "private") + "\n" + callLine("2", "safe_tool", "private") + "\n"
	if err := gate.agentToUpstream(strings.NewReader(input), &upstream, pending); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(upstream.String(), `"name":"safe_tool"`) || strings.Contains(upstream.String(), `"name":""`) {
		t.Fatalf("empty-name request was forwarded or valid request was blocked: %s", upstream.String())
	}
	if got := auditor.RequiredError(); got != nil {
		t.Fatalf("caller-supplied empty tool name latched the writer: %v", got)
	}
	var response bytes.Buffer
	if err := gate.upstreamToAgent(strings.NewReader(`{"jsonrpc":"2.0","id":2,"result":{}}`+"\n"), &response, pending, nil); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(agent.String(), `"error"`) || !strings.Contains(response.String(), `"id":2`) {
		t.Fatalf("empty-name rejection or valid response missing: rejected=%s response=%s", agent.String(), response.String())
	}
	var emptyDenied, emptyNotForwarded, validDispatch, validObserved int
	for _, ev := range actionEvents(readAuditEvents(t, path)) {
		if ev.Tool == "" && ev.Decision == "deny" {
			emptyDenied++
		}
		if ev.Tool == "" && ev.Observation == "not_forwarded" {
			emptyNotForwarded++
		}
		if ev.Tool == "safe_tool" && ev.Decision == "dispatch" {
			validDispatch++
		}
		if ev.Tool == "safe_tool" && ev.Observation == "response_observed" {
			validObserved++
		}
	}
	if emptyDenied != 1 || emptyNotForwarded != 1 || validDispatch != 1 || validObserved != 1 {
		t.Fatalf("empty/valid lifecycle rows=%d/%d/%d/%d; want 1/1/1/1", emptyDenied, emptyNotForwarded, validDispatch, validObserved)
	}
}

func TestStdioActionPairingCancelLateResponseAndTimeout(t *testing.T) {
	t.Run("cancel then late response", func(t *testing.T) {
		auditor, path, _ := newEd25519Auditor(t)
		defer auditor.Close()
		gate := newActionPairingGate(t, auditor, "")
		pending := &sync.Map{}
		input := callLine("7", "slow_tool", "private") + "\n" + `{"jsonrpc":"2.0","method":"notifications/cancelled","params":{"requestId":7}}` + "\n"
		if err := gate.agentToUpstream(strings.NewReader(input), io.Discard, pending); err != nil {
			t.Fatal(err)
		}
		if err := gate.upstreamToAgent(strings.NewReader(`{"jsonrpc":"2.0","id":7,"result":{}}`+"\n"), io.Discard, pending, nil); err != nil {
			t.Fatal(err)
		}
		var unknown, late int
		for _, ev := range actionEvents(readAuditEvents(t, path)) {
			if ev.Observation == "outcome_unknown" && ev.Cause == "client_cancel" {
				unknown++
			}
			if ev.Observation == "late_response_observed" && ev.Cause == "late_response" {
				late++
			}
		}
		if unknown != 1 || late != 1 {
			t.Fatalf("cancel/late lifecycle counts = %d/%d; want one each", unknown, late)
		}
	})

	t.Run("timeout leaves explicit unknown", func(t *testing.T) {
		auditor, path, _ := newEd25519Auditor(t)
		defer auditor.Close()
		gate := newActionPairingGate(t, auditor, "")
		pending := &sync.Map{}
		if err := gate.agentToUpstream(strings.NewReader(callLine("9", "slow_tool", "private")+"\n"), io.Discard, pending); err != nil {
			t.Fatal(err)
		}
		gate.finishPendingActions(pending, "timeout")
		gate.drainAudits()
		events := actionEvents(readAuditEvents(t, path))
		var dispatch, unknown int
		for _, ev := range events {
			if ev.Decision == "dispatch" {
				dispatch++
			}
			if ev.Observation == "outcome_unknown" && ev.Cause == "timeout" {
				unknown++
			}
		}
		if dispatch != 1 || unknown != 1 {
			t.Fatalf("outstanding pair dispatch/unknown = %d/%d; want 1/1: %+v", dispatch, unknown, events)
		}
	})
}

func TestStdioActionPairingDeniedAndFailedDispatchAreNegativeControls(t *testing.T) {
	t.Run("denied call is not dispatched", func(t *testing.T) {
		auditor, path, _ := newEd25519Auditor(t)
		defer auditor.Close()
		gate := newActionPairingGate(t, auditor, "secret_tool")
		var upstream, agent bytes.Buffer
		gate.agentOut = &agent
		pending := &sync.Map{}
		if err := gate.agentToUpstream(strings.NewReader(callLine("1", "secret_tool", "private")+"\n"), &upstream, pending); err != nil {
			t.Fatal(err)
		}
		if upstream.Len() != 0 {
			t.Fatalf("denied negative control reached upstream: %s", upstream.String())
		}
		if !strings.Contains(agent.String(), `"error"`) {
			t.Fatalf("denied call got no error response: %s", agent.String())
		}
		rows := actionEvents(readAuditEvents(t, path))
		var denied, notForwarded, dispatch int
		for _, ev := range rows {
			if ev.Decision == "deny" {
				denied++
			}
			if ev.Observation == "not_forwarded" && ev.Cause == "policy_denied" {
				notForwarded++
			}
			if ev.Decision == "dispatch" {
				dispatch++
			}
		}
		if denied != 1 || notForwarded != 1 || dispatch != 0 {
			t.Fatalf("denied pair counts deny/not-forwarded/dispatch=%d/%d/%d; want 1/1/0: %+v", denied, notForwarded, dispatch, rows)
		}
	})

	t.Run("failed required dispatch is not forwarded or recorded as success", func(t *testing.T) {
		auditor, path, _ := newEd25519Auditor(t)
		defer auditor.Close()
		gate := newActionPairingGate(t, auditor, "")
		if err := os.Remove(path); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(path, nil, 0o600); err != nil {
			t.Fatal(err)
		}
		var upstream, agent bytes.Buffer
		gate.agentOut = &agent
		pending := &sync.Map{}
		if err := gate.agentToUpstream(strings.NewReader(callLine("1", "tool_one", "private")+"\n"), &upstream, pending); err != nil {
			t.Fatal(err)
		}
		if upstream.Len() != 0 {
			t.Fatalf("call with failed required write reached upstream: %s", upstream.String())
		}
		if !strings.Contains(agent.String(), AuditBeforeForwardError) {
			t.Fatalf("call did not receive required-audit rejection: %s", agent.String())
		}
		rows := readAuditEvents(t, path)
		if len(rows) != 0 || hasActionSuccessObservation(rows) {
			t.Fatalf("failed write produced an audit row or success observation: rows=%+v", rows)
		}
		// Mutation control: write a response_observed row to a trail and parse it
		// through the same path as the failed-write assertion. This proves that
		// the assertion detects false success evidence on disk.
		mutation, err := json.Marshal(audit.Event{ActionID: "mutated.1", RecordType: "action_observation", Observation: "response_observed"})
		if err != nil {
			t.Fatal(err)
		}
		mutationPath := filepath.Join(t.TempDir(), "mutation.jsonl")
		if err := os.WriteFile(mutationPath, append(mutation, '\n'), 0o600); err != nil {
			t.Fatal(err)
		}
		if !hasActionSuccessObservation(readAuditEvents(t, mutationPath)) {
			t.Fatal("negative-control mutation on disk was not detected")
		}
	})
}

func hasActionSuccessObservation(events []audit.Event) bool {
	for _, ev := range events {
		if ev.ActionID != "" && ev.RecordType == "action_observation" && (ev.Observation == "response_observed" || ev.Observation == "late_response_observed") {
			return true
		}
	}
	return false
}

func TestActionPairingOffByDefaultAndBestEffortRejected(t *testing.T) {
	auditor, _, _ := newEd25519Auditor(t)
	defer auditor.Close()
	defaultGate := newGate(t, "agents:\n  demo:\n    mode: allow\n", nil, auditor)
	if defaultGate.actionPairing {
		t.Fatal("action pairing must remain disabled without explicit policy opt-in")
	}
	pairGate := newActionPairingGate(t, auditor, "")
	pairGate.WithBestEffortAudit()
	if pairGate.actionInitErr == nil {
		t.Fatal("best-effort audit must fail closed when action pairing is enabled")
	}
	missingWriter := newGate(t, `audit:
  enabled: true
  action_pairing: true
agents:
  demo:
    mode: allow
`, nil, nil)
	if missingWriter.actionInitErr == nil {
		t.Fatal("action pairing without an available durable writer must fail initialization")
	}
}

func mustRead(t *testing.T, path string) []byte {
	t.Helper()
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func TestActionPairingFailureAfterDispatchReturnsUnknownRetryWarning(t *testing.T) {
	auditor, path, _ := newEd25519Auditor(t)
	defer auditor.Close()
	gate := newActionPairingGate(t, auditor, "")
	pending := &sync.Map{}
	if err := gate.agentToUpstream(strings.NewReader(callLine("1", "tool_one", "private")+"\n"), io.Discard, pending); err != nil {
		t.Fatal(err)
	}
	if err := os.Remove(path); err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(path, 0o700); err != nil {
		t.Fatal(err)
	}
	var agent bytes.Buffer
	err := gate.upstreamToAgent(strings.NewReader(`{"jsonrpc":"2.0","id":1,"result":{}}`+"\n"), &agent, pending, nil)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(agent.String(), auditAfterForwardError) {
		t.Fatalf("response after failed outcome write did not warn against automatic retry: %s", agent.String())
	}
}

func TestStdioRequiredAuditFailureAfterForwardWarnsInV1Mode(t *testing.T) {
	auditor, path, _ := newEd25519Auditor(t)
	defer auditor.Close()
	gate := newGate(t, `audit:
  enabled: true
agents:
  demo:
    mode: allow
`, nil, auditor)
	pending := &sync.Map{}
	if err := gate.agentToUpstream(strings.NewReader(callLine("1", "tool_one", "private")+"\n"), io.Discard, pending); err != nil {
		t.Fatal(err)
	}
	if err := os.Remove(path); err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(path, 0o700); err != nil {
		t.Fatal(err)
	}

	var agent bytes.Buffer
	response := `{"jsonrpc":"2.0","id":1,"result":{"private":"must-not-pass"}}` + "\n"
	if err := gate.upstreamToAgent(strings.NewReader(response), &agent, pending, nil); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(agent.String(), auditAfterForwardError) || strings.Contains(agent.String(), "must-not-pass") {
		t.Fatalf("v1 response after required audit failure was not withheld with a retry warning: %s", agent.String())
	}
}

func TestStdioActionPairingWithholdsResponseWhenObservationRowFailsValidation(t *testing.T) {
	auditor, path, _ := newEd25519Auditor(t)
	defer auditor.Close()
	gate := newActionPairingGate(t, auditor, "")
	pending := &sync.Map{}
	if err := gate.agentToUpstream(strings.NewReader(callLine("1", "tool_one", "private")+"\n"), io.Discard, pending); err != nil {
		t.Fatal(err)
	}
	value, ok := pending.Load("1")
	if !ok {
		t.Fatal("forwarded action is missing from pending requests")
	}
	card, ok := value.(*pendingCard)
	if !ok {
		t.Fatalf("pending request has type %T, want *pendingCard", value)
	}

	// Simulate a queued schema-v2 observation that fails the auditor's validation.
	// RecordRequired deliberately does not latch caller-input validation failures.
	gate.actionRunID = "invalid-run-id"
	var agent bytes.Buffer
	response := `{"jsonrpc":"2.0","id":1,"result":{"secret":"must-not-pass"}}` + "\n"
	if err := gate.upstreamToAgent(strings.NewReader(response), &agent, pending, nil); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(agent.String(), unverifiedToolResponseError) || strings.Contains(agent.String(), "must-not-pass") {
		t.Fatalf("response with an unrecordable observation was released: %s", agent.String())
	}
	if card.actionID == "" {
		t.Fatal("forwarded action has no action id")
	}
	for _, ev := range actionEvents(readAuditEvents(t, path)) {
		if ev.Observation != "" {
			t.Fatalf("invalid observation unexpectedly reached the trail: %+v", ev)
		}
	}
}

func TestStdioActionPairingRejectsInvalidMatchedResponseEnvelope(t *testing.T) {
	auditor, path, _ := newEd25519Auditor(t)
	defer auditor.Close()
	gate := newActionPairingGate(t, auditor, "")
	pending := &sync.Map{}
	if err := gate.agentToUpstream(strings.NewReader(callLine("1", "tool_one", "request-private")+"\n"), io.Discard, pending); err != nil {
		t.Fatal(err)
	}
	response := `{"jsonrpc":"2.0","id":1,"result":{"content":[{"text":"untrusted-response"}]},"error":{"code":0,"message":"ambiguous"}}` + "\n"
	var agent bytes.Buffer
	if err := gate.upstreamToAgent(strings.NewReader(response), &agent, pending, nil); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(agent.String(), unverifiedToolResponseError) || strings.Contains(agent.String(), "untrusted-response") {
		t.Fatalf("invalid matched response was not replaced with an uncertainty error: %s", agent.String())
	}
	for _, ev := range actionEvents(readAuditEvents(t, path)) {
		if ev.Observation == "outcome_unknown" {
			return
		}
	}
	t.Fatal("invalid matched response was not recorded as unknown")
}

func TestStdioActionPairingRejectsAmbiguousResponseEnvelopeKeys(t *testing.T) {
	tests := []struct {
		name     string
		response string
	}{
		{
			name:     "duplicate id",
			response: `{"jsonrpc":"2.0","id":1,"id":2,"result":{"private":"must-not-pass"}}`,
		},
		{
			name:     "case alias id",
			response: `{"jsonrpc":"2.0","id":1,"ID":2,"result":{"private":"must-not-pass"}}`,
		},
		{
			name:     "unicode case-fold alias",
			response: `{"jsonrpc":"2.0","id":2,"result":{"private":"must-not-pass"},"re\u017Fult":{}}`,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			auditor, path, _ := newEd25519Auditor(t)
			defer auditor.Close()
			gate := newActionPairingGate(t, auditor, "")
			pending := &sync.Map{}
			if err := gate.agentToUpstream(strings.NewReader(callLine("2", "tool_two", "request-private")+"\n"), io.Discard, pending); err != nil {
				t.Fatal(err)
			}

			var agent bytes.Buffer
			if err := gate.upstreamToAgent(strings.NewReader(tt.response+"\n"), &agent, pending, nil); err != nil {
				t.Fatal(err)
			}
			if !strings.Contains(agent.String(), unverifiedToolResponseError) || strings.Contains(agent.String(), "must-not-pass") {
				t.Fatalf("ambiguous response was not replaced with an uncertainty error: %s", agent.String())
			}
			if !gate.requestIDInUse(pending, []byte("2")) {
				t.Fatal("ambiguous response consumed the pending request before late-response correlation")
			}

			var unknown, observed int
			for _, ev := range actionEvents(readAuditEvents(t, path)) {
				if ev.Observation == "outcome_unknown" {
					unknown++
				}
				if ev.Observation == "response_observed" {
					observed++
				}
			}
			if unknown != 1 || observed != 0 {
				t.Fatalf("ambiguous response outcomes unknown/observed=%d/%d; want 1/0", unknown, observed)
			}
		})
	}
}

func TestInvalidActionResponseIDHandlesLargeEnvelopeQuickly(t *testing.T) {
	const keys = 100_000
	var response strings.Builder
	response.Grow(keys * 16)
	response.WriteString(`{"jsonrpc":"2.0","id":1,"result":{}`)
	for i := 0; i < keys; i++ {
		response.WriteString(`,"field`)
		response.WriteString(strconv.Itoa(i))
		response.WriteString(`":0`)
	}
	response.WriteByte('}')

	start := time.Now()
	id, invalid := invalidActionResponseID([]byte(response.String()), nil)
	if invalid || string(id) != "1" {
		t.Fatalf("large valid envelope was rejected: id=%s invalid=%t", id, invalid)
	}
	// A quadratic parse needs about 5e9 key comparisons at this size. The
	// linear parse takes about 0.3s locally and about 1s on a shared macOS
	// runner under -race, so a one-second bound flaked there.
	if elapsed := time.Since(start); elapsed >= 5*time.Second {
		t.Fatalf("100,000-key response took %s to parse; want under five seconds", elapsed)
	}
}

func TestInvalidActionResponseIDKeepsDottedIKeysDistinct(t *testing.T) {
	response := []byte(`{"jsonrpc":"2.0","id":1,"\u0130d":2,"result":{}}`)
	id, invalid := invalidActionResponseID(response, nil)
	if invalid || string(id) != "1" {
		t.Fatalf("distinct dotted-I key was treated as an id alias: id=%s invalid=%t", id, invalid)
	}
}

func TestStdioActionPairingMalformedTypedErrorResolvesAndUnblocksLaterResponse(t *testing.T) {
	auditor, path, _ := newEd25519Auditor(t)
	defer auditor.Close()
	gate := newActionPairingGate(t, auditor, "")
	pending := &sync.Map{}
	input := callLine("1", "tool_one", "private-one") + "\n" + callLine("2", "tool_two", "private-two") + "\n"
	if err := gate.agentToUpstream(strings.NewReader(input), io.Discard, pending); err != nil {
		t.Fatal(err)
	}
	var agent bytes.Buffer
	malformed := `{"jsonrpc":2,"id":1,"error":{"code":"bad","message":"failure"}}` + "\n"
	if err := gate.upstreamToAgent(strings.NewReader(malformed), &agent, pending, nil); err != nil {
		t.Fatal(err)
	}
	if strings.Contains(agent.String(), `"code":"bad"`) || !strings.Contains(agent.String(), unverifiedToolResponseError) {
		t.Fatalf("malformed matched response was not replaced: %s", agent.String())
	}
	if !gate.requestIDInUse(pending, []byte("1")) {
		t.Fatal("request id became reusable before a late response could be correlated")
	}
	lateAndNext := `{"jsonrpc":"2.0","id":1,"result":{"content":[{"text":"late-private"}]}}` + "\n" +
		`{"jsonrpc":"2.0","id":2,"result":{"safe":"later"}}` + "\n"
	if err := gate.upstreamToAgent(strings.NewReader(lateAndNext), &agent, pending, nil); err != nil {
		t.Fatal(err)
	}
	if strings.Contains(agent.String(), "late-private") || !strings.Contains(agent.String(), `"safe":"later"`) {
		t.Fatalf("late reply escaped or later response was blocked: %s", agent.String())
	}
	if gate.requestIDInUse(pending, []byte("1")) {
		t.Fatal("request id remained reserved after its late response was correlated")
	}
	var unknown, observed, late int
	for _, ev := range actionEvents(readAuditEvents(t, path)) {
		if ev.ActionID == "" {
			continue
		}
		if ev.Observation == "outcome_unknown" {
			unknown++
		}
		if ev.Observation == "response_observed" {
			observed++
		}
		if ev.Observation == "late_response_observed" && ev.Cause == "late_response" {
			late++
		}
	}
	if unknown != 1 || observed != 1 || late != 1 {
		t.Fatalf("malformed/valid response outcomes = unknown %d, observed %d, late %d; want one each", unknown, observed, late)
	}
}

func TestStdioActionPairingInvalidDecodedResponseKeepsLateCorrelation(t *testing.T) {
	auditor, path, _ := newEd25519Auditor(t)
	defer auditor.Close()
	gate := newActionPairingGate(t, auditor, "")
	pending := &sync.Map{}
	if err := gate.agentToUpstream(strings.NewReader(callLine("1", "tool_one", "private")+"\n"), io.Discard, pending); err != nil {
		t.Fatal(err)
	}
	var agent bytes.Buffer
	invalid := `{"jsonrpc":"1.0","id":1,"result":{"content":[{"text":"unverified"}]}}` + "\n"
	if err := gate.upstreamToAgent(strings.NewReader(invalid), &agent, pending, nil); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(agent.String(), unverifiedToolResponseError) || !gate.requestIDInUse(pending, []byte("1")) {
		t.Fatalf("invalid response was not surfaced with an ID tombstone: output=%s in_use=%v", agent.String(), gate.requestIDInUse(pending, []byte("1")))
	}
	late := `{"jsonrpc":"2.0","id":1,"result":{"content":[{"text":"late-private"}]}}` + "\n"
	if err := gate.upstreamToAgent(strings.NewReader(late), &agent, pending, nil); err != nil {
		t.Fatal(err)
	}
	if strings.Contains(agent.String(), "late-private") || gate.requestIDInUse(pending, []byte("1")) {
		t.Fatalf("late response escaped or its request ID remained reserved: output=%s", agent.String())
	}
	var unknown, lateObserved int
	for _, ev := range actionEvents(readAuditEvents(t, path)) {
		if ev.Observation == "outcome_unknown" {
			unknown++
		}
		if ev.Observation == "late_response_observed" && ev.Cause == "late_response" {
			lateObserved++
		}
	}
	if unknown != 1 || lateObserved != 1 {
		t.Fatalf("invalid/late outcomes = unknown %d, late %d; want one each", unknown, lateObserved)
	}
}

func TestStdioActionPairingBuffersInvalidResponseWithMethod(t *testing.T) {
	auditor, path, _ := newEd25519Auditor(t)
	defer auditor.Close()
	gate := newActionPairingGate(t, auditor, "")
	pending := &sync.Map{}
	if err := gate.agentToUpstream(strings.NewReader(callLine("1", "tool_one", "private")+"\n"), io.Discard, pending); err != nil {
		t.Fatal(err)
	}
	response := `{"jsonrpc":"2.0","id":1,"Method":"unexpected","result":{"secret":"must-not-pass"}}` + "\n"
	var agent bytes.Buffer
	if err := gate.upstreamToAgent(strings.NewReader(response), &agent, pending, nil); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(agent.String(), unverifiedToolResponseError) || strings.Contains(agent.String(), "must-not-pass") {
		t.Fatalf("response-shaped method envelope was not rejected: %s", agent.String())
	}
	if !gate.requestIDInUse(pending, []byte("1")) {
		t.Fatal("request ID was released before an invalid response could be correlated")
	}
	for _, ev := range actionEvents(readAuditEvents(t, path)) {
		if ev.Observation == "outcome_unknown" {
			return
		}
	}
	t.Fatal("invalid response-shaped envelope did not resolve as unknown")
}

func TestStdioActionPairingKeepsBufferedErrorIDReservedThroughLateReply(t *testing.T) {
	auditor, path, _ := newEd25519Auditor(t)
	defer auditor.Close()
	gate := newActionPairingGate(t, auditor, "")
	pending := &sync.Map{}
	input := callLine("1", "tool_slow", "private-one") + "\n" + callLine("2", "tool_target", "private-two") + "\n"
	if err := gate.agentToUpstream(strings.NewReader(input), io.Discard, pending); err != nil {
		t.Fatal(err)
	}
	var agent bytes.Buffer
	reader, writer := io.Pipe()
	done := make(chan error, 1)
	go func() { done <- gate.upstreamToAgent(reader, &agent, pending, nil) }()
	badAndLate := `{"jsonrpc":2,"id":2,"result":{}}` + "\n" +
		`{"jsonrpc":"2.0","id":2,"result":{"content":[{"text":"late-private"}]}}` + "\n"
	if _, err := writer.Write([]byte(badAndLate)); err != nil {
		t.Fatal(err)
	}
	deadline := time.Now().Add(time.Second)
	for {
		if _, stillPending := pending.Load("2"); !stillPending {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("late response was not correlated while the earlier action remained outstanding")
		}
		time.Sleep(time.Millisecond)
	}
	if !gate.requestIDInUse(pending, []byte("2")) {
		t.Fatal("buffered uncertainty released its ID before client delivery")
	}
	firstResponse := `{"jsonrpc":"2.0","id":1,"result":{"safe":"first"}}` + "\n"
	if _, err := writer.Write([]byte(firstResponse)); err != nil {
		t.Fatal(err)
	}
	if err := writer.Close(); err != nil {
		t.Fatal(err)
	}
	if err := <-done; err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(agent.String(), unverifiedToolResponseError) || !strings.Contains(agent.String(), `"safe":"first"`) || strings.Contains(agent.String(), "late-private") {
		t.Fatalf("buffered uncertainty or late-response suppression failed: %s (auditNext=%d, events=%+v)", agent.String(), gate.auditNext, readAuditEvents(t, path))
	}
	if gate.requestIDInUse(pending, []byte("2")) {
		t.Fatal("request ID remained reserved after the buffered error was delivered and late reply correlated")
	}
	var unknown, late int
	for _, ev := range actionEvents(readAuditEvents(t, path)) {
		if ev.Observation == "outcome_unknown" {
			unknown++
		}
		if ev.Observation == "late_response_observed" && ev.Cause == "late_response" {
			late++
		}
	}
	if unknown != 1 || late != 1 {
		t.Fatalf("buffered action outcomes = unknown %d, late %d; want one each", unknown, late)
	}
}

func TestStdioActionPairingShutdownDoesNotReplyTwiceToAnsweredTombstone(t *testing.T) {
	auditor, _, _ := newEd25519Auditor(t)
	defer auditor.Close()
	gate := newActionPairingGate(t, auditor, "")
	pending := &sync.Map{}
	input := callLine("1", "tool_slow", "private-one") + "\n" + callLine("2", "tool_target", "private-two") + "\n"
	if err := gate.agentToUpstream(strings.NewReader(input), io.Discard, pending); err != nil {
		t.Fatal(err)
	}
	var agent bytes.Buffer
	gate.agentOut = &agent
	invalid := `{"jsonrpc":2,"id":2,"result":{}}` + "\n"
	if err := gate.upstreamToAgent(strings.NewReader(invalid), &agent, pending, nil, true); err != nil {
		t.Fatal(err)
	}
	gate.replyPendingAtShutdown(pending)
	var id1, id2, duplicateID2 int
	for _, line := range strings.Split(strings.TrimSpace(agent.String()), "\n") {
		var msg struct {
			ID    json.RawMessage `json:"id"`
			Error *struct {
				Message string `json:"message"`
			} `json:"error"`
		}
		if err := json.Unmarshal([]byte(line), &msg); err != nil || msg.Error == nil {
			continue
		}
		switch string(msg.ID) {
		case "1":
			id1++
		case "2":
			id2++
			if strings.Contains(msg.Error.Message, "upstream exited") {
				duplicateID2++
			}
		}
	}
	if id1 != 1 || id2 != 1 || duplicateID2 != 0 {
		t.Fatalf("shutdown produced duplicate/missing replies for retained tombstone: id1=%d id2=%d duplicate_id2=%d output=%s", id1, id2, duplicateID2, agent.String())
	}
}

func TestStdioActionPairingImmediateInvalidAliasDoesNotGetSecondShutdownReply(t *testing.T) {
	auditor, _, _ := newEd25519Auditor(t)
	defer auditor.Close()
	gate := newActionPairingGate(t, auditor, "")
	pending := &sync.Map{}
	if err := gate.agentToUpstream(strings.NewReader(callLine("1", "tool_one", "private")+"\n"), io.Discard, pending); err != nil {
		t.Fatal(err)
	}
	var agent bytes.Buffer
	gate.agentOut = &agent
	invalid := `{"jsonrpc":"2.0","id":1,"Result":{}}` + "\n"
	if err := gate.upstreamToAgent(strings.NewReader(invalid), &agent, pending, nil, true); err != nil {
		t.Fatal(err)
	}
	gate.replyPendingAtShutdown(pending)
	count := 0
	for _, line := range strings.Split(strings.TrimSpace(agent.String()), "\n") {
		var response struct {
			ID    json.RawMessage `json:"id"`
			Error *struct {
				Message string `json:"message"`
			} `json:"error"`
		}
		if json.Unmarshal([]byte(line), &response) == nil && string(response.ID) == "1" && response.Error != nil {
			count++
			if strings.Contains(response.Error.Message, "upstream exited") {
				t.Fatalf("shutdown sent a second response for the invalid envelope: %s", agent.String())
			}
		}
	}
	if count != 1 {
		t.Fatalf("responses for the invalid envelope = %d; want one: %s", count, agent.String())
	}
}
