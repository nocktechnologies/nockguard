package proxy

import (
	"io"
	"log"
	"testing"

	"github.com/nocktechnologies/nockguard/internal/policy"
)

// TestProbeForwardsAndBlocks proves the Probe seam reports forwarding truthfully:
// an allowed tool reaches the upstream (forwarded=true), a policy-denied tool and
// a secret-bearing argument do not (forwarded=false). This is the exact signal
// the `selftest` command relies on, exercised through the real agentToUpstream
// gate rather than a mock.
func TestProbeForwardsAndBlocks(t *testing.T) {
	const probeTool = "nockguard-selftest-probe"
	agent := "nockguard-selftest"
	call := func(args string) []byte {
		return []byte(`{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"` + probeTool + `","arguments":` + args + `}}`)
	}

	tests := []struct {
		name          string
		policyYAML    string
		probe         []byte
		wantForwarded bool
	}{
		{
			name:          "permissive policy forwards the probe",
			policyYAML:    "agents:\n  nockguard-selftest:\n    mode: allow\n",
			probe:         call(`{"note":"canary"}`),
			wantForwarded: true,
		},
		{
			name:          "deny rule blocks the probe",
			policyYAML:    "agents:\n  nockguard-selftest:\n    mode: allow\n    deny:\n      - " + probeTool + "\n",
			probe:         call(`{"note":"canary"}`),
			wantForwarded: false,
		},
		{
			name:          "secrets validation blocks a secret argument",
			policyYAML:    "agents:\n  nockguard-selftest:\n    mode: allow\n    validate_input:\n      - secrets\n",
			probe:         call(`{"payload":"sk-NockguardSelftestCanary000000000000"}`),
			wantForwarded: false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			engine, err := policy.LoadBytes([]byte(tt.policyYAML))
			if err != nil {
				t.Fatalf("LoadBytes: %v", err)
			}
			validator, err := engine.ValidatorFor(agent)
			if err != nil {
				t.Fatalf("ValidatorFor: %v", err)
			}
			p := NewStdioProxy(nil, agent, engine, validator, nil, nil, nil, log.New(io.Discard, "", 0))
			forwarded, reply, err := p.Probe(tt.probe)
			if err != nil {
				t.Fatalf("Probe: %v", err)
			}
			if forwarded != tt.wantForwarded {
				t.Fatalf("forwarded = %v, want %v (reply: %s)", forwarded, tt.wantForwarded, reply)
			}
			// A block must produce an agent-facing rejection; a forward must not.
			if !forwarded && len(reply) == 0 {
				t.Fatalf("blocked probe produced no agent-facing rejection")
			}
			if forwarded && len(reply) != 0 {
				t.Fatalf("forwarded probe unexpectedly produced an agent reply: %s", reply)
			}
		})
	}
}
