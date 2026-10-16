package proxy

import (
	"encoding/json"
	"io"
	"log"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/nocktechnologies/nockguard/internal/audit"
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
				if blocked && !strings.Contains(string(reply), "method denied by policy") {
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
			want := "allow"
			if deny {
				want = "deny"
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
