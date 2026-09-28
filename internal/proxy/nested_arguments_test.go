package proxy

import (
	"encoding/json"
	"strings"
	"testing"
)

// A typed upstream merges duplicate object members, whereas the validator's
// map decoder replaces them. Exercise the bytes sent by the shared gate.
func TestNestedArgumentsHaveOneValidatedMeaning(t *testing.T) {
	for _, args := range []string{
		`{"config":{"command":"FORBIDDEN"},"config":{}}`,
		`{"items":[{"config":{"command":"FORBIDDEN"},"config":{}}]}`,
	} {
		t.Run(args, func(t *testing.T) {
			gate := newGate(t, "agents:\n  mira:\n    mode: allow\n    block_params: [FORBIDDEN]\n", nil, nil)
			request := []byte(`{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"safe_tool","arguments":` + args + `}}`)
			d := gate.decide(request, 0)
			if d.reject {
				t.Fatal("last-wins arguments are safe and should forward")
			}
			type config struct{ Command string }
			type arguments struct {
				Config config
				Items  []struct{ Config config }
			}
			var upstream struct{ Params struct{ Arguments arguments } }
			if err := json.Unmarshal(d.forward, &upstream); err != nil {
				t.Fatal(err)
			}
			if upstream.Params.Arguments.Config.Command != "" {
				t.Fatal("typed upstream received a command hidden from validation")
			}
			for _, item := range upstream.Params.Arguments.Items {
				if item.Config.Command != "" {
					t.Fatal("hidden command in array reached upstream")
				}
			}
			control := gate.decide([]byte(`{"jsonrpc":"2.0","id":2,"method":"tools/call","params":{"name":"safe_tool","arguments":{"config":{"command":"FORBIDDEN"}}}}`), 1)
			if !control.reject {
				t.Fatal("positive control did not block forbidden command")
			}
		})
	}
}

func TestCanonicalArgumentsPreserveNumberLiterals(t *testing.T) {
	_, got, ok := canonicalToolCall(json.RawMessage(`{"name":"safe_tool","arguments":{"big":9007199254740993,"decimal":1.2300,"exponent":1e400}}`))
	if !ok || string(got) != `{"arguments":{"big":9007199254740993,"decimal":1.2300,"exponent":1e400},"name":"safe_tool"}` {
		t.Fatalf("numeric literals changed: %s", got)
	}
}

func TestCaseFoldedParamsKeyIsNotForwardedAlongsideCanonicalParams(t *testing.T) {
	gate := newGate(t, "agents:\n  mira:\n    mode: allow\n", nil, nil)
	request := []byte("{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"tools/call\",\"param\\u017f\":{\"name\":\"safe_tool\",\"arguments\":{\"safe\":true}}}")
	d := gate.decide(request, 0)
	if d.reject {
		t.Fatalf("case-folded params key should be canonicalized, got rejection: %s", d.rejectMsg)
	}
	var forwarded map[string]json.RawMessage
	if err := json.Unmarshal(d.forward, &forwarded); err != nil {
		t.Fatal(err)
	}
	if _, ok := forwarded["params"]; !ok {
		t.Fatalf("canonical params key missing from forwarded request: %s", d.forward)
	}
	for key := range forwarded {
		if key != "params" && strings.EqualFold(key, "params") {
			t.Fatalf("forwarded request retained case-folded params key %q: %s", key, d.forward)
		}
	}

	conflicting := []byte("{\"jsonrpc\":\"2.0\",\"id\":2,\"method\":\"tools/call\",\"params\":{\"name\":\"safe_tool\"},\"param\\u017f\":{\"name\":\"other_tool\"}}")
	if d := gate.decide(conflicting, 1); !d.reject {
		t.Fatalf("conflicting canonical and case-folded params keys were forwarded: %s", d.forward)
	}
}
