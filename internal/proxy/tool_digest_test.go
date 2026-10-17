package proxy

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"io"
	"os"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/nocktechnologies/nockguard/internal/approval"
	"github.com/nocktechnologies/nockguard/internal/audit"
	"github.com/nocktechnologies/nockguard/internal/ratelimit"
)

func TestToolDigestCanonicalAndComplete(t *testing.T) {
	first := []byte(`{"name":"read","inputSchema":{"required":["x"],"properties":{"x":{"type":"number","minimum":1.0}}},"_meta":{"label":"<safe>"},"annotations":{"readOnlyHint":true}}`)
	reordered := []byte(`{"annotations":{"readOnlyHint":true},"_meta":{"label":"<safe>"},"inputSchema":{"properties":{"x":{"minimum":1e0,"type":"number"}},"required":["x"]},"name":"read"}`)
	_, a, err := digestToolDefinition(first)
	if err != nil {
		t.Fatal(err)
	}
	_, b, err := digestToolDefinition(reordered)
	if err != nil {
		t.Fatal(err)
	}
	if a != b {
		t.Fatalf("reordered equivalent definitions differ: %s %s", a, b)
	}
	canonical := `{"_meta":{"label":"<safe>"},"annotations":{"readOnlyHint":true},"inputSchema":{"properties":{"x":{"minimum":1,"type":"number"}},"required":["x"]},"name":"read"}`
	sum := sha256.Sum256([]byte(toolHashDomain + canonical))
	if a != hex.EncodeToString(sum[:]) {
		t.Fatalf("digest %s does not match canonical bytes", a)
	}
	changed := bytes.Replace(first, []byte(`"<safe>"`), []byte(`"<changed>"`), 1)
	_, c, err := digestToolDefinition(changed)
	if err != nil || c == a {
		t.Fatalf("metadata change did not change digest: %s %v", c, err)
	}
}

func TestToolDigestAcceptsJSONEscapes(t *testing.T) {
	for _, pair := range [][2]string{
		{`"\/"`, `"/"`},
		{`"\uD83D\uDE00"`, `"😀"`},
	} {
		_, a, err := digestToolDefinition([]byte(`{"name":"n","inputSchema":{},"description":` + pair[0] + `}`))
		if err != nil {
			t.Fatal(err)
		}
		_, b, err := digestToolDefinition([]byte(`{"name":"n","inputSchema":{},"description":` + pair[1] + `}`))
		if err != nil || a != b {
			t.Fatalf("equivalent JSON escapes differ: %s %s %v", a, b, err)
		}
	}
}

func TestToolDigestNumericAndSchemaKeyBoundaries(t *testing.T) {
	for _, pair := range [][2]string{
		{`1.0`, `1e0`},
		{`0.000001`, `1e-6`},
		{`1000000000000000000000`, `1e21`},
		{`-0`, `0`},
	} {
		a := []byte(`{"name":"n","inputSchema":{"minimum":` + pair[0] + `}}`)
		b := []byte(`{"name":"n","inputSchema":{"minimum":` + pair[1] + `}}`)
		_, left, err := digestToolDefinition(a)
		if err != nil {
			t.Fatal(err)
		}
		_, right, err := digestToolDefinition(b)
		if err != nil || left != right {
			t.Fatalf("numeric equivalents differ: %s %s: %v", left, right, err)
		}
	}
	_, lower, err := digestToolDefinition([]byte(`{"name":"n","inputSchema":{"properties":{"x":{}}}}`))
	if err != nil {
		t.Fatal(err)
	}
	_, upper, err := digestToolDefinition([]byte(`{"name":"n","inputSchema":{"properties":{"X":{}}}}`))
	if err != nil || lower == upper {
		t.Fatalf("schema property case was folded: %s %s %v", lower, upper, err)
	}
}

func TestToolDigestRejectsAmbiguousInputs(t *testing.T) {
	for _, raw := range []string{
		`{"name":"read","inputSchema":{"properties":{"x":{},"x":{}}}}`,
		`{"name":"read","Name":"other","inputSchema":{}}`,
		`{"name":"read","inputSchema":{},"title":"\uD800"}`,
		`{"name":"read","inputSchema":{"minimum":9007199254740993}}`,
		`{"name":"read","inputSchema":{"minimum":0.10000000000000001}}`,
		`{"name":"read","inputSchema":{"minimum":1e400}}`,
		`{"name":"read","inputSchema":{"minimum":1e-400}}`,
	} {
		if _, _, err := digestToolDefinition([]byte(raw)); err == nil {
			t.Errorf("accepted ambiguous definition %s", raw)
		}
	}
}

func TestCatalogPublishesOnlyCompleteGeneration(t *testing.T) {
	var c toolCatalog
	first := c.beginList(nil)
	if first == 0 {
		t.Fatal("first page did not start a build")
	}
	if c.beginList(json.RawMessage(`{"cursor":"p2"}`)) != 0 {
		t.Fatal("accepted continuation before cursor was advertised")
	}
	a, err := pageObservations([]json.RawMessage{json.RawMessage(`{"name":"a","inputSchema":{}}`)})
	if err != nil {
		t.Fatal(err)
	}
	if err := c.addPage(first, 50, a, "p2"); err != nil {
		t.Fatal(err)
	}
	if c.observe("a").status != "unobserved" {
		t.Fatal("published a partial generation")
	}
	second := c.beginList(json.RawMessage(`{"cursor":"p2"}`))
	if second != first || c.beginList(json.RawMessage(`{"cursor":"p2"}`)) != 0 {
		t.Fatal("continuation ownership was not exclusive")
	}
	b, err := pageObservations([]json.RawMessage{json.RawMessage(`{"name":"b","inputSchema":{}}`)})
	if err != nil {
		t.Fatal(err)
	}
	if err := c.addPage(second, 50, b, ""); err != nil {
		t.Fatal(err)
	}
	if len(c.published) != 2 || c.observe("a").status != "unobserved" {
		t.Fatal("paginated generation must publish without claiming call coverage")
	}
	c.invalidate()
	if c.observe("a").status != "unobserved" {
		t.Fatal("list_changed retained stale catalog")
	}
	newBuild := c.beginList(nil)
	if err := c.addPage(newBuild, 50, a, "p2"); err != nil {
		t.Fatal(err)
	}
	if c.beginList(json.RawMessage(`{"cursor":"p2"}`)) != newBuild {
		t.Fatal("continuation did not match")
	}
	if err := c.addPage(newBuild, 50, b, "p2"); err == nil {
		t.Fatal("accepted cursor cycle")
	}
	if c.observe("a").status != "unobserved" {
		t.Fatal("published a discarded generation")
	}
	newBuild = c.beginList(nil)
	if err := c.addPage(first, 50, a, ""); err != nil {
		t.Fatal(err)
	}
	if c.observe("a").status != "unobserved" {
		t.Fatal("stale page published over a new build")
	}
	if err := c.addPage(newBuild, 50, a, "p2"); err != nil {
		t.Fatal(err)
	}
	if c.beginList(json.RawMessage(`{"cursor":"p2"}`)) != newBuild {
		t.Fatal("continuation did not match")
	}
	if err := c.addPage(newBuild, 50, a, ""); err == nil {
		t.Fatal("accepted duplicate tool across pages")
	}
}

func TestUnhashableDefinitionHasNoTrustedDigest(t *testing.T) {
	definitions, err := pageObservations([]json.RawMessage{
		json.RawMessage(`{"name":"read","inputSchema":{"properties":{"x":1,"x":2}}}`),
	})
	if err != nil {
		t.Fatal(err)
	}
	if definitions["read"].status != "unhashable" || definitions["read"].hash != "" {
		t.Fatalf("ambiguous definition was trusted: %+v", definitions["read"])
	}
	var catalog toolCatalog
	id := catalog.beginList(nil)
	if err := catalog.addPage(id, 100, definitions, ""); err != nil {
		t.Fatal(err)
	}
	if catalog.observe("read").status != "unhashable" {
		t.Fatal("published catalog lost unhashable status")
	}
}

func TestStdioCatalogTracksPaginatedListingAndInvalidation(t *testing.T) {
	auditor, _, _ := newEd25519Auditor(t)
	defer auditor.Close()
	gate := newActionPairingGate(t, auditor, "")
	pending := &sync.Map{}
	first := `{"jsonrpc":"2.0","id":1,"method":"tools/list"}`
	if err := gate.agentToUpstream(strings.NewReader(first+"\n"), io.Discard, pending); err != nil {
		t.Fatal(err)
	}
	firstPage := `{"jsonrpc":"2.0","id":1,"result":{"tools":[{"name":"a","inputSchema":{}}],"nextCursor":"p2"}}`
	if err := gate.upstreamToAgent(strings.NewReader(firstPage+"\n"), io.Discard, pending, nil); err != nil {
		t.Fatal(err)
	}
	if gate.catalog.observe("a").status != "unobserved" {
		t.Fatal("partial page published")
	}
	second := `{"jsonrpc":"2.0","id":2,"method":"tools/list","params":{"cursor":"p2"}}`
	if err := gate.agentToUpstream(strings.NewReader(second+"\n"), io.Discard, pending); err != nil {
		t.Fatal(err)
	}
	lastPage := `{"jsonrpc":"2.0","id":2,"result":{"tools":[{"name":"b","inputSchema":{}}]}}`
	if err := gate.upstreamToAgent(strings.NewReader(lastPage+"\n"), io.Discard, pending, nil); err != nil {
		t.Fatal(err)
	}
	if len(gate.catalog.published) != 2 || gate.catalog.observe("a").status != "unobserved" || gate.catalog.observe("b").hash != "" {
		t.Fatal("paginated generation must publish without claiming call coverage")
	}
	changed := `{"jsonrpc":"2.0","method":"notifications/tools/list_changed"}`
	if err := gate.upstreamToAgent(strings.NewReader(changed+"\n"), io.Discard, pending, nil); err != nil {
		t.Fatal(err)
	}
	if gate.catalog.observe("a").status != "unobserved" {
		t.Fatal("notification failed to invalidate catalog")
	}
}

func TestSignedActionRowsCarryObservedDefinition(t *testing.T) {
	auditor, path, pub := newEd25519Auditor(t)
	defer auditor.Close()
	gate := newActionPairingGate(t, auditor, "")
	pending := &sync.Map{}
	if err := gate.agentToUpstream(strings.NewReader(`{"jsonrpc":"2.0","id":1,"method":"tools/list"}`+"\n"), io.Discard, pending); err != nil {
		t.Fatal(err)
	}
	definition := `{"name":"read","description":"private metadata","inputSchema":{"type":"object"}}`
	if err := gate.upstreamToAgent(strings.NewReader(`{"jsonrpc":"2.0","id":1,"result":{"tools":[`+definition+`]}}`+"\n"), io.Discard, pending, nil); err != nil {
		t.Fatal(err)
	}
	if gate.catalog.observe("read").hash == "" {
		t.Fatal("listing did not publish digest")
	}
	if err := gate.agentToUpstream(strings.NewReader(callLine("2", "read", "secret")+"\n"), io.Discard, pending); err != nil {
		t.Fatal(err)
	}
	if err := gate.upstreamToAgent(strings.NewReader(`{"jsonrpc":"2.0","id":2,"result":{}}`+"\n"), io.Discard, pending, nil); err != nil {
		t.Fatal(err)
	}
	var checked, dispatch, observed int
	for _, ev := range actionEvents(readAuditEvents(t, path)) {
		checked++
		if ev.ToolHashVersion != toolHashVersion || ev.ToolPinStatus != "unpinned" || ev.ToolDefinitionHash != gate.catalog.observe("read").hash {
			t.Fatalf("row omitted signed observation: %+v", ev)
		}
		if ev.Decision == "dispatch" {
			dispatch++
		}
		if ev.RecordType == "action_observation" && ev.Observation == "response_observed" {
			observed++
		}
	}
	if checked == 0 || dispatch != 1 || observed != 1 {
		t.Fatalf("checked %d action rows with %d dispatch and %d response_observed; want 1 of each", checked, dispatch, observed)
	}
	if _, err := audit.VerifyEd25519(path, pub); err != nil {
		t.Fatalf("observed trail did not verify: %v", err)
	}
	if bytes.Contains(mustRead(t, path), []byte("private metadata")) {
		t.Fatal("raw definition leaked into trail")
	}
}

func TestToolDigestNumberCanonicalVectors(t *testing.T) {
	for raw, want := range map[string]string{
		`0e5`:       `0`,
		`0E5`:       `0`,
		`0.0e10`:    `0`,
		`-0.0`:      `0`,
		`-0e-5`:     `0`,
		`1e0`:       `1`,
		`10e-1`:     `1`,
		`1e-7`:      `1e-7`,
		`1e21`:      `1e+21`,
		`1e20`:      `100000000000000000000`,
		`0.000001`:  `0.000001`,
		`-1.5e1`:    `-15`,
		`5e-324`:    `5e-324`,
		`1.25e-310`: `1.25e-310`,
	} {
		got, err := canonicalJCSNumber(raw)
		if err != nil || got != want {
			t.Errorf("canonicalJCSNumber(%s) = %q, %v; want %q", raw, got, err, want)
		}
	}
	// Out-of-profile numbers stay unhashable: never zero, never rounded.
	for _, raw := range []string{`1e-400`, `-1e-400`, `1e400`, `9007199254740993`, `0.10000000000000001`, `4e-324`} {
		if got, err := canonicalJCSNumber(raw); err == nil {
			t.Errorf("canonicalJCSNumber(%s) = %q; want unhashable", raw, got)
		}
	}
	_, zero, err := digestToolDefinition([]byte(`{"name":"n","inputSchema":{"minimum":0}}`))
	if err != nil {
		t.Fatal(err)
	}
	_, exponentZero, err := digestToolDefinition([]byte(`{"name":"n","inputSchema":{"minimum":0e5}}`))
	if err != nil || exponentZero != zero {
		t.Fatalf("0e5 did not canonicalize to 0: %s %s %v", zero, exponentZero, err)
	}
}

// listPage sends one client tools/list request and its upstream page through the
// gate and returns the decoded agent-facing response.
func listPage(t *testing.T, gate *StdioProxy, pending *sync.Map, request, response string) map[string]json.RawMessage {
	t.Helper()
	if err := gate.agentToUpstream(strings.NewReader(request+"\n"), io.Discard, pending); err != nil {
		t.Fatal(err)
	}
	var agent bytes.Buffer
	if err := gate.upstreamToAgent(strings.NewReader(response+"\n"), &agent, pending, nil); err != nil {
		t.Fatal(err)
	}
	var out map[string]json.RawMessage
	if err := json.Unmarshal(agent.Bytes(), &out); err != nil {
		t.Fatalf("agent response %q: %v", agent.String(), err)
	}
	return out
}

func listedNames(t *testing.T, out map[string]json.RawMessage) []string {
	t.Helper()
	if _, hasError := out["error"]; hasError {
		t.Fatalf("observation failure broke tools/list: %s", out["error"])
	}
	var result struct {
		Tools []struct {
			Name string `json:"name"`
		} `json:"tools"`
	}
	if err := json.Unmarshal(out["result"], &result); err != nil {
		t.Fatal(err)
	}
	names := make([]string, 0, len(result.Tools))
	for _, tool := range result.Tools {
		names = append(names, tool.Name)
	}
	return names
}

func toolsJSON(names ...string) string {
	parts := make([]string, 0, len(names))
	for _, name := range names {
		parts = append(parts, `{"name":"`+name+`","inputSchema":{}}`)
	}
	return "[" + strings.Join(parts, ",") + "]"
}

func listRequest(id int, cursor string) string {
	if cursor == "" {
		return `{"jsonrpc":"2.0","id":` + strconv.Itoa(id) + `,"method":"tools/list"}`
	}
	return `{"jsonrpc":"2.0","id":` + strconv.Itoa(id) + `,"method":"tools/list","params":{"cursor":"` + cursor + `"}}`
}

func listResponse(id int, tools, tail string) string {
	return `{"jsonrpc":"2.0","id":` + strconv.Itoa(id) + `,"result":{"tools":` + tools + tail + `}}`
}

func newCatalogGate(t *testing.T) *StdioProxy {
	t.Helper()
	auditor, _, _ := newEd25519Auditor(t)
	t.Cleanup(func() { auditor.Close() })
	return newActionPairingGate(t, auditor, "hidden")
}

func assertCatalogNotPublished(t *testing.T, gate *StdioProxy, tool string) {
	t.Helper()
	gate.catalog.mu.Lock()
	published, build := gate.catalog.published, gate.catalog.build
	gate.catalog.mu.Unlock()
	if published != nil || build != nil {
		t.Fatalf("failed generation was kept: published=%v build=%v", published, build)
	}
	if status := gate.catalog.observe(tool).status; status != "unobserved" {
		t.Fatalf("call observation after failed listing = %q; want unobserved", status)
	}
}

func TestCatalogFailureStillReturnsFilteredListing(t *testing.T) {
	t.Run("tool bound exceeded", func(t *testing.T) {
		gate := newCatalogGate(t)
		pending := &sync.Map{}
		names := []string{"hidden"}
		for i := 0; i < maxCatalogTools; i++ {
			names = append(names, "t"+strconv.Itoa(i))
		}
		out := listPage(t, gate, pending, listRequest(1, ""), listResponse(1, toolsJSON(names...), ""))
		if got := listedNames(t, out); len(got) != maxCatalogTools || got[0] != "t0" {
			t.Fatalf("listing was not filtered normally: %d tools", len(got))
		}
		assertCatalogNotPublished(t, gate, "t0")
	})

	t.Run("page bound exceeded", func(t *testing.T) {
		gate := newCatalogGate(t)
		pending := &sync.Map{}
		cursor := ""
		for page := 0; page < maxCatalogPages; page++ {
			next := "p" + strconv.Itoa(page+1)
			out := listPage(t, gate, pending, listRequest(page+1, cursor), listResponse(page+1, toolsJSON("t"+strconv.Itoa(page)), `,"nextCursor":"`+next+`"`))
			listedNames(t, out)
			cursor = next
		}
		out := listPage(t, gate, pending, listRequest(100, cursor), listResponse(100, toolsJSON("last", "hidden"), ""))
		if got := listedNames(t, out); len(got) != 1 || got[0] != "last" {
			t.Fatalf("over-bound page was not filtered normally: %v", got)
		}
		assertCatalogNotPublished(t, gate, "last")
	})

	t.Run("duplicate tool name in one page", func(t *testing.T) {
		gate := newCatalogGate(t)
		pending := &sync.Map{}
		out := listPage(t, gate, pending, listRequest(1, ""), listResponse(1, toolsJSON("a", "hidden", "a"), ""))
		if got := listedNames(t, out); strings.Join(got, ",") != "a,a" {
			t.Fatalf("duplicate-name page was not filtered normally: %v", got)
		}
		assertCatalogNotPublished(t, gate, "a")
	})

	t.Run("duplicate tool name across pages", func(t *testing.T) {
		gate := newCatalogGate(t)
		pending := &sync.Map{}
		listedNames(t, listPage(t, gate, pending, listRequest(1, ""), listResponse(1, toolsJSON("a"), `,"nextCursor":"p2"`)))
		out := listPage(t, gate, pending, listRequest(2, "p2"), listResponse(2, toolsJSON("a", "hidden"), ""))
		if got := listedNames(t, out); strings.Join(got, ",") != "a" {
			t.Fatalf("duplicate page was not filtered normally: %v", got)
		}
		assertCatalogNotPublished(t, gate, "a")
	})

	t.Run("cursor cycle", func(t *testing.T) {
		gate := newCatalogGate(t)
		pending := &sync.Map{}
		listedNames(t, listPage(t, gate, pending, listRequest(1, ""), listResponse(1, toolsJSON("a"), `,"nextCursor":"p2"`)))
		out := listPage(t, gate, pending, listRequest(2, "p2"), listResponse(2, toolsJSON("b", "hidden"), `,"nextCursor":"p2"`))
		if got := listedNames(t, out); strings.Join(got, ",") != "b" || !strings.Contains(string(out["result"]), `"nextCursor":"p2"`) {
			t.Fatalf("cycling page was not filtered normally: %s", out["result"])
		}
		assertCatalogNotPublished(t, gate, "a")
	})
}

func TestCatalogFinalPageCursorNullAndEmpty(t *testing.T) {
	t.Run("null publishes", func(t *testing.T) {
		gate := newCatalogGate(t)
		pending := &sync.Map{}
		out := listPage(t, gate, pending, listRequest(1, ""), listResponse(1, toolsJSON("a", "hidden"), `,"nextCursor":null`))
		if got := listedNames(t, out); strings.Join(got, ",") != "a" {
			t.Fatalf("listing was not filtered normally: %v", got)
		}
		if observed := gate.catalog.observe("a"); observed.status != "unpinned" || observed.hash == "" {
			t.Fatalf("null nextCursor did not publish: %+v", observed)
		}
	})

	t.Run("empty discards", func(t *testing.T) {
		gate := newCatalogGate(t)
		pending := &sync.Map{}
		out := listPage(t, gate, pending, listRequest(1, ""), listResponse(1, toolsJSON("a", "hidden"), `,"nextCursor":""`))
		if got := listedNames(t, out); strings.Join(got, ",") != "a" {
			t.Fatalf("listing was not filtered normally: %v", got)
		}
		assertCatalogNotPublished(t, gate, "a")
	})
}

func actionObservedCount(p *StdioProxy) int {
	n := 0
	p.actionObserved.Range(func(_, _ any) bool { n++; return true })
	return n
}

func TestEndedActionsReleaseObservedDefinitions(t *testing.T) {
	const calls = 25
	run := func(t *testing.T, gate *StdioProxy, tool, args string, wantForwarded int) {
		t.Helper()
		pending := &sync.Map{}
		listedNames(t, listPage(t, gate, pending, listRequest(1, ""), listResponse(1, toolsJSON(tool), "")))
		var input strings.Builder
		for i := 0; i < calls; i++ {
			input.WriteString(`{"jsonrpc":"2.0","id":` + strconv.Itoa(100+i) + `,"method":"tools/call","params":{"name":"` + tool + `","arguments":` + args + `}}` + "\n")
		}
		var upstream bytes.Buffer
		gate.agentOut = io.Discard
		if err := gate.agentToUpstream(strings.NewReader(input.String()), &upstream, pending); err != nil {
			t.Fatal(err)
		}
		if forwarded := strings.Count(upstream.String(), "\n"); forwarded != wantForwarded {
			t.Fatalf("forwarded %d calls; want %d", forwarded, wantForwarded)
		}
		// Answer any call that was forwarded, so only ended actions remain.
		var responses strings.Builder
		pending.Range(func(_, value any) bool {
			if card, ok := value.(*pendingCard); ok {
				responses.WriteString(`{"jsonrpc":"2.0","id":` + string(card.requestID) + `,"result":{}}` + "\n")
			}
			return true
		})
		if err := gate.upstreamToAgent(strings.NewReader(responses.String()), io.Discard, pending, nil); err != nil {
			t.Fatal(err)
		}
		if n := actionObservedCount(gate); n != 0 {
			t.Fatalf("actionObserved retained %d entries after %d ended actions", n, calls)
		}
	}
	pairing := "audit:\n  enabled: true\n  action_pairing: true\nagents:\n  demo:\n    mode: allow\n"
	gateWith := func(t *testing.T, policyText string, limiter *ratelimit.Limiter) *StdioProxy {
		auditor, _, _ := newEd25519Auditor(t)
		t.Cleanup(func() { auditor.Close() })
		return newGate(t, policyText, limiter, auditor)
	}

	t.Run("policy deny", func(t *testing.T) {
		run(t, gateWith(t, pairing+"    deny: [\"t\"]\n", nil), "t", `{}`, 0)
	})
	t.Run("validation block", func(t *testing.T) {
		run(t, gateWith(t, pairing+"    validate_input:\n      - secrets\n", nil), "t", `{"payload":"sk-NockguardSelftestCanary000000000000"}`, 0)
	})
	t.Run("rate limit", func(t *testing.T) {
		run(t, gateWith(t, pairing, ratelimit.New(ratelimit.Config{MaxCalls: 1, Window: time.Hour})), "t", `{}`, 1)
	})
	t.Run("spend cap", func(t *testing.T) {
		run(t, gateWith(t, pairing, ratelimit.New(ratelimit.Config{SpendCap: 1})), "t", `{}`, 1)
	})
	t.Run("approval denied", func(t *testing.T) {
		run(t, gateWith(t, pairing+"    ask: [\"t\"]\n", nil).WithApprover(approval.NewStaticApprover(false, "denied")), "t", `{}`, 0)
	})
	t.Run("approval timeout", func(t *testing.T) {
		run(t, gateWith(t, pairing+"    ask: [\"t\"]\n", nil).WithApprover(approval.NewStaticApprover(false, "timeout")), "t", `{}`, 0)
	})
	t.Run("approval without approver", func(t *testing.T) {
		run(t, gateWith(t, pairing+"    ask: [\"t\"]\n", nil), "t", `{}`, 0)
	})
	t.Run("required audit unavailable", func(t *testing.T) {
		auditor, path, _ := newEd25519Auditor(t)
		defer auditor.Close()
		gate := newActionPairingGate(t, auditor, "")
		pending := &sync.Map{}
		listedNames(t, listPage(t, gate, pending, listRequest(1, ""), listResponse(1, toolsJSON("t"), "")))
		if err := os.Remove(path); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(path, nil, 0o600); err != nil {
			t.Fatal(err)
		}
		gate.agentOut = io.Discard
		var input strings.Builder
		for i := 0; i < calls; i++ {
			input.WriteString(callLine(strconv.Itoa(100+i), "t", "private") + "\n")
		}
		var upstream bytes.Buffer
		if err := gate.agentToUpstream(strings.NewReader(input.String()), &upstream, pending); err != nil {
			t.Fatal(err)
		}
		if upstream.Len() != 0 {
			t.Fatalf("call reached upstream without a durable audit: %s", upstream.String())
		}
		if n := actionObservedCount(gate); n != 0 {
			t.Fatalf("actionObserved retained %d entries after %d rejected actions", n, calls)
		}
	})
}

func TestActionObservationRacesResponseTimeoutAndCancel(t *testing.T) {
	for i := 0; i < 20; i++ {
		t.Run(strconv.Itoa(i), func(t *testing.T) {
			auditor, path, _ := newEd25519Auditor(t)
			defer auditor.Close()
			gate := newActionPairingGate(t, auditor, "")
			pending := &sync.Map{}
			listedNames(t, listPage(t, gate, pending, listRequest(1, ""), listResponse(1, toolsJSON("slow_tool"), "")))
			if err := gate.agentToUpstream(strings.NewReader(callLine("7", "slow_tool", "private")+"\n"), io.Discard, pending); err != nil {
				t.Fatal(err)
			}
			var wg sync.WaitGroup
			wg.Add(3)
			go func() {
				defer wg.Done()
				_ = gate.upstreamToAgent(strings.NewReader(`{"jsonrpc":"2.0","id":7,"result":{}}`+"\n"), io.Discard, pending, nil)
			}()
			go func() {
				defer wg.Done()
				gate.finishPendingActions(pending, "timeout")
			}()
			go func() {
				defer wg.Done()
				gate.markCancelledAction(pending, json.RawMessage(`7`))
			}()
			wg.Wait()
			gate.drainAudits()
			hash := gate.catalog.observe("slow_tool").hash
			var terminal int
			for _, ev := range actionEvents(readAuditEvents(t, path)) {
				if ev.RecordType == "action_observation" && ev.Observation != "late_response_observed" {
					terminal++
				}
				if ev.ToolDefinitionHash != hash || ev.ToolPinStatus != "unpinned" {
					t.Fatalf("row lost the frozen observation: %+v", ev)
				}
			}
			if terminal != 1 {
				t.Fatalf("terminal observations = %d; want 1", terminal)
			}
			if n := actionObservedCount(gate); n != 0 {
				t.Fatalf("actionObserved retained %d entries", n)
			}
		})
	}
}
