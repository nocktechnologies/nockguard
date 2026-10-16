package proxy

import (
	"encoding/json"
	"fmt"

	"github.com/nocktechnologies/nockguard/internal/jsonrpc"
)

// CanonicalizeForForward returns the message and tool name represented by the
// returned bytes. Transports must forward those bytes rather than the input.
func CanonicalizeForForward(line []byte) ([]byte, *jsonrpc.Message, string, error) {
	top, canonical, msg, failure := canonicalizeMessage(line)
	if failure != canonicalMessageOK {
		return nil, nil, "", fmt.Errorf("message could not be canonicalized")
	}
	if msg.Method != "tools/call" {
		return canonical, msg, "", nil
	}
	name, params, ok := canonicalToolCall(msg.Params)
	if !ok || name == "" {
		return nil, nil, "", fmt.Errorf("tool name could not be extracted")
	}
	top["params"] = params
	canonical, err := json.Marshal(top)
	if err != nil {
		return nil, nil, "", err
	}
	msg.Params = params
	return canonical, msg, name, nil
}
