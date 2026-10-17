package proxy

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"io"
	"strings"
	"sync"
	"testing"

	"github.com/nocktechnologies/nockguard/internal/audit"
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
	for _, ev := range actionEvents(readAuditEvents(t, path)) {
		if ev.ToolHashVersion != toolHashVersion || ev.ToolPinStatus != "unpinned" || ev.ToolDefinitionHash != gate.catalog.observe("read").hash {
			t.Fatalf("row omitted signed observation: %+v", ev)
		}
	}
	if _, err := audit.VerifyEd25519(path, pub); err != nil {
		t.Fatalf("observed trail did not verify: %v", err)
	}
	if bytes.Contains(mustRead(t, path), []byte("private metadata")) {
		t.Fatal("raw definition leaked into trail")
	}
}
