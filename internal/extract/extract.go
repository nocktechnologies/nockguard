// Package extract provides declared extractors that lift auditable references
// from MCP tool-call arguments into structured audit-trail fields.
//
// The extractors are conservative: they only recognize known tools and typed
// parameter patterns. Unknown tools and malformed arguments yield no fields,
// never guesses. This keeps the audit trail faithful to what actually happened.
//
// Extracted fields are covered by the Ed25519 signature chain, so they form
// part of the tamper-evident trail and can be verified by third parties who
// only hold the public key.
package extract

import (
	"encoding/json"
	"strconv"
)

// References is the set of auditable fields extracted from a tool-call's arguments.
type References struct {
	NockID   int    // NockCC card id, or 0 if not present
	PR       string // GitHub PR reference owner/repo#n, or "" if not present
	ReviewID string // NockCC review id, or "" if not present
}

// FromToolCall extracts auditable references from the arguments of a known tool.
// The canonicalParams must be the MCP tools/call params object containing "name"
// and "arguments" fields: {"name": "...", "arguments": {...}}.
// Nil or empty params yield a zero References struct.
// Unknown tools and malformed arguments yield a zero References struct.
func FromToolCall(tool string, params json.RawMessage) References {
	if len(params) == 0 {
		return References{}
	}

	// Unmarshal the full params object to extract the arguments field.
	var paramsObj map[string]json.RawMessage
	if err := json.Unmarshal(params, &paramsObj); err != nil {
		return References{}
	}

	// Extract the "arguments" field.
	argsRaw, ok := paramsObj["arguments"]
	if !ok {
		return References{}
	}

	// Unmarshal arguments into a map.
	var arguments map[string]json.RawMessage
	if err := json.Unmarshal(argsRaw, &arguments); err != nil {
		return References{}
	}

	switch tool {
	case "nockcc_nock_claim", "nockcc_nock_update", "nockcc_nock_get", "nockcc_nock_release":
		return extractNockToolID(arguments)
	// Reserved for future GitHub PR tool extractors:
	// case "gh_pr_create", "gh_pr_update":
	//     return extractGitHubPR(arguments)
	default:
		return References{}
	}
}

// extractNockToolID extracts the numeric id parameter from nockcc_nock_* tools.
// The id may arrive as a JSON number or string (different client implementations);
// both are accepted and normalized to an integer. Invalid or missing id yields
// References{}.
func extractNockToolID(arguments map[string]json.RawMessage) References {
	idRaw, ok := arguments["id"]
	if !ok {
		return References{}
	}

	// Try numeric first (most common).
	var idNum int
	if err := json.Unmarshal(idRaw, &idNum); err == nil {
		if idNum > 0 {
			return References{NockID: idNum}
		}
		return References{}
	}

	// Try string (alternate client form).
	var idStr string
	if err := json.Unmarshal(idRaw, &idStr); err == nil {
		if idParsed, err := strconv.Atoi(idStr); err == nil && idParsed > 0 {
			return References{NockID: idParsed}
		}
	}

	return References{}
}
