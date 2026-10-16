package proxy

import (
	"encoding/hex"
	"encoding/json"
	"io"
	"log"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/nocktechnologies/nockguard/internal/audit"
	"github.com/nocktechnologies/nockguard/internal/evidence"
	"github.com/nocktechnologies/nockguard/internal/forward"
	"github.com/nocktechnologies/nockguard/internal/policy"
	"github.com/nocktechnologies/nockguard/internal/trust"
)

func TestMethodAuditAndDeny(t *testing.T) {
	for _, deny := range []bool{false, true} {
		t.Run(map[bool]string{false: "forward", true: "deny"}[deny], func(t *testing.T) {
			config := "agents:\n  demo:\n    mode: deny\n"
			if deny {
				config += "    deny_methods: [resources/read]\n"
			}
			engine, err := policy.LoadBytes([]byte(config))
			if err != nil {
				t.Fatal(err)
			}
			path := filepath.Join(t.TempDir(), "audit.jsonl")
			auditor, err := audit.New(path)
			if err != nil {
				t.Fatal(err)
			}
			defer auditor.Close()
			gate := NewStdioProxy(nil, "demo", engine, nil, nil, auditor, nil, log.New(io.Discard, "", 0))
			for _, method := range []string{"resources/read", "prompts/get", "completion/complete", "initialize", "tools/list", "notifications/initialized"} {
				id := `,"id":1`
				if strings.HasPrefix(method, "notifications/") {
					id = ""
				}
				forwarded, reply, err := gate.Probe([]byte(`{"jsonrpc":"2.0"` + id + `,"method":"` + method + `","params":{"uri":"file:///private-method-test","secret":"method-test-secret"}}`))
				if err != nil {
					t.Fatal(err)
				}
				blocked := deny && method == "resources/read"
				if forwarded == blocked {
					t.Fatalf("%s forwarded=%v blocked=%v", method, forwarded, blocked)
				}
				if blocked && (!strings.Contains(string(reply), "method denied by policy") || !strings.Contains(string(reply), `"code":-32601`)) {
					t.Fatalf("missing policy error: %s", reply)
				}
			}
			// Client responses must not create method audit rows.
			if _, _, err := gate.Probe([]byte(`{"jsonrpc":"2.0","id":2,"result":{}}`)); err != nil {
				t.Fatal(err)
			}
			data, err := os.ReadFile(path)
			if err != nil {
				t.Fatal(err)
			}
			if strings.Contains(string(data), "private-method-test") || strings.Contains(string(data), "method-test-secret") || strings.Contains(string(data), `"params"`) {
				t.Fatalf("params leaked: %s", data)
			}
			lines := strings.Split(strings.TrimSpace(string(data)), "\n")
			if len(lines) != 6 {
				t.Fatalf("got %d method rows, want 6: %s", len(lines), data)
			}
			var row audit.Event
			if err := json.Unmarshal([]byte(lines[0]), &row); err != nil {
				t.Fatal(err)
			}
			want := "method-allow"
			if deny {
				want = "method-deny"
			}
			if row.Tool != "resources/read" || row.Decision != want {
				t.Fatalf("unexpected method row: %+v", row)
			}
		})
	}
}

func TestMethodAuditDoesNotChangeTrust(t *testing.T) {
	engine, err := policy.LoadBytes([]byte("agents:\n  demo:\n    deny_methods: [resources/read]\n"))
	if err != nil {
		t.Fatal(err)
	}
	auditor, err := audit.New(filepath.Join(t.TempDir(), "audit.jsonl"))
	if err != nil {
		t.Fatal(err)
	}
	defer auditor.Close()
	gate := NewStdioProxy(nil, "demo", engine, nil, nil, auditor, nil, log.New(io.Discard, "", 0))
	gate.trust, err = trust.New(trust.Config{Enabled: true, Agent: "demo", Path: filepath.Join(t.TempDir(), "trust.json")}, trust.WithClock(func() time.Time { return time.Unix(1000, 0) }))
	if err != nil {
		t.Fatal(err)
	}
	before := gate.trust.Score()
	for _, method := range []string{"notifications/initialized", "resources/read"} {
		forwarded, reply, err := gate.Probe([]byte(`{"jsonrpc":"2.0","method":"` + method + `"}`))
		if err != nil {
			t.Fatal(err)
		}
		if forwarded != (method != "resources/read") || len(reply) != 0 {
			t.Fatalf("notification %s forwarded=%v reply=%s", method, forwarded, reply)
		}
	}
	if got := gate.trust.Score(); got != before {
		t.Fatalf("method traffic changed trust: %v to %v", before, got)
	}
	// A required method audit failure must prevent upstream contact.
	if err := auditor.Close(); err != nil {
		t.Fatal(err)
	}
	forwarded, _, err := gate.Probe([]byte(`{"jsonrpc":"2.0","id":3,"method":"initialize"}`))
	if err != nil {
		t.Fatal(err)
	}
	if forwarded {
		t.Fatal("method forwarded after required audit failure")
	}
}

func TestMethodRowsCannotProposeTools(t *testing.T) {
	auditor, path, pub := newEd25519Auditor(t)
	defer auditor.Close()
	t.Setenv(policy.AgentPubKeyEnvName("demo"), hex.EncodeToString(pub))
	gate := newGate(t, "agents:\n  demo:\n    allow: [read_file]\n    deny: [write_file]\n    deny_methods: [resources/read]\n", nil, auditor)

	pending := &sync.Map{}
	input := `{"jsonrpc":"2.0","id":1,"method":"write_file"}` + "\n" +
		`{"jsonrpc":"2.0","id":2,"method":"initialize"}` + "\n" +
		`{"jsonrpc":"2.0","id":3,"method":"tools/list"}` + "\n" +
		toolCall("4", "read_file") + "\n" +
		`{"jsonrpc":"2.0","id":5,"method":"resources/read"}` + "\n"
	gate.agentOut = io.Discard
	if err := gate.agentToUpstream(strings.NewReader(input), io.Discard, pending); err != nil {
		t.Fatal(err)
	}
	responses := `{"jsonrpc":"2.0","id":1,"result":{}}` + "\n" + `{"jsonrpc":"2.0","id":2,"result":{}}` + "\n" + `{"jsonrpc":"2.0","id":3,"result":{"tools":[]}}` + "\n" + `{"jsonrpc":"2.0","id":4,"result":{}}` + "\n"
	if err := gate.upstreamToAgent(strings.NewReader(responses), io.Discard, pending, nil); err != nil {
		t.Fatal(err)
	}
	proposal, err := policy.ProposeShadowFromAudit("demo", path)
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(proposal.Tools, []string{"read_file"}) {
		t.Errorf("proposal=%v, want read_file only", proposal.Tools)
	}

	binary := buildBinary(t)
	output, err := exec.Command(binary, "policy", "propose", "--agent", "demo", "--audit", path).CombinedOutput()
	if err != nil {
		t.Fatalf("policy propose: %v: %s", err, output)
	}
	wantOutput := "agents:\n    demo:\n        mode: allow\n        shadow:\n            - read_file\n"
	if string(output) != wantOutput {
		t.Errorf("policy propose output=%s, want %s", output, wantOutput)
	}
	misses, err := policy.ShadowReportFromAudit("demo", path)
	if err != nil || len(misses) != 0 {
		t.Errorf("shadow misses=%v err=%v, want 0", misses, err)
	}
	pack, err := evidence.BuildPack(evidence.PackOptions{Framework: evidence.FrameworkSOC2, AuditFiles: []string{path}, Ed25519PubHex: hex.EncodeToString(pub)})
	if err != nil {
		t.Fatal(err)
	}
	if !pack.Verification.ChainIntact {
		t.Fatal("method decisions broke signed trail")
	}
	allows := 0
	for _, ev := range pack.AllEvents {
		if ev.Decision == "allow" {
			allows++
		}
	}
	if allows != 1 {
		t.Errorf("evidence tool allows=%d, want 1", allows)
	}
	for _, control := range pack.Controls {
		if control.Control.ID == "CC6.1" && len(control.Events) != 0 {
			t.Errorf("tool access control events=%d, want 0", len(control.Events))
		}
	}
	for _, render := range []func(evidence.Pack) ([]byte, error){evidence.RenderJSON, evidence.RenderHTML} {
		data, err := render(pack)
		if err != nil || !strings.Contains(string(data), "method-allow") || !strings.Contains(string(data), "method-deny") {
			t.Errorf("method labels missing: err=%v", err)
		}
	}
	approved := 0
	for _, ev := range readAuditEvents(t, path) {
		if forward.DecisionBucket(ev.Decision) == "approved" {
			approved++
		}
	}
	// The proxy emits one dispatch and one allow for the tool call.
	if approved != 2 {
		t.Errorf("Wall approved records=%d, want 2 (dispatch + tool allow)", approved)
	}
}
