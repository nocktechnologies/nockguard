package proxy

import (
	"encoding/json"
	"fmt"
	"strings"

	"github.com/nocktechnologies/nockguard/internal/policy"
)

// applyInject attempts to inject credentials into the canonical tool-call params
// for all matching inject rules. It is called only on allowed calls after validation,
// and before the final Marshal to upstream.
//
// The function is all-or-nothing across multiple matching rules: if any rule fails
// to resolve or apply, the entire call is rejected. On success, injected values are
// added to the scrub set (so they will be redacted from responses), and audit rows
// are emitted. On failure, a single block audit row is emitted.
//
// Exactly one resolution happens per rule at forward time, with no retries.
// If a secret is too short (< 8 bytes), it is treated as unresolved.
func (p *StdioProxy) applyInject(toolName string, canonicalParams json.RawMessage, rules []policy.InjectRule) (json.RawMessage, string /*rejectReason*/, bool /*success*/) {
	if len(rules) == 0 {
		return canonicalParams, "", true
	}

	// Unmarshal params to work with the structure, using map[string]json.RawMessage
	// to preserve numeric precision
	var params map[string]json.RawMessage
	if err := json.Unmarshal(canonicalParams, &params); err != nil {
		return nil, "inject-internal-error", false
	}

	// Resolve all secrets first; fail fast on any error
	type resolvedRule struct {
		rule  policy.InjectRule
		value string
	}
	resolved := make([]resolvedRule, 0, len(rules))
	for _, rule := range rules {
		val, err := p.resolver.Resolve(rule.Ref)
		if err != nil {
			p.logger.Printf("INJECT-FAIL agent=%s tool=%s reason=unresolved ref=%s error=%v", p.agent, toolName, rule.Ref, err)
			p.audit(toolName, "block", fmt.Sprintf("inject-unresolved ref=%s", rule.Ref))
			return nil, fmt.Sprintf("nockguard: tool %q injection failed", toolName), false
		}

		// Check minimum length
		if len(val) < 8 {
			p.logger.Printf("INJECT-FAIL agent=%s tool=%s reason=too-short ref=%s", p.agent, toolName, rule.Ref)
			p.audit(toolName, "block", fmt.Sprintf("inject-too-short ref=%s", rule.Ref))
			return nil, fmt.Sprintf("nockguard: tool %q injection failed", toolName), false
		}

		resolved = append(resolved, resolvedRule{rule, val})
	}

	// Check for runtime conflicts: same arg path matched by multiple rules
	argPathCount := make(map[string]int)
	for _, rr := range resolved {
		argPathCount[rr.rule.Arg]++
	}
	for argPath, count := range argPathCount {
		if count > 1 {
			p.logger.Printf("INJECT-FAIL agent=%s tool=%s reason=conflict arg=%s count=%d", p.agent, toolName, argPath, count)
			p.audit(toolName, "block", fmt.Sprintf("inject-conflict arg=%s", argPath))
			return nil, fmt.Sprintf("nockguard: tool %q injection failed", toolName), false
		}
	}

	// Apply all injections. Fail if any arg path is unsettable.
	for _, rr := range resolved {
		value := rr.value
		if rr.rule.Template != "" {
			value = strings.ReplaceAll(rr.rule.Template, "{secret}", rr.value)
		}

		// Set the value at the path in params
		if !setArgPathInParams(&params, rr.rule.Arg, value) {
			p.logger.Printf("INJECT-FAIL agent=%s tool=%s reason=unsettable arg=%s", p.agent, toolName, rr.rule.Arg)
			p.audit(toolName, "block", fmt.Sprintf("inject-unsettable arg=%s", rr.rule.Arg))
			return nil, fmt.Sprintf("nockguard: tool %q injection failed", toolName), false
		}
	}

	// Re-marshal params
	out, err := json.Marshal(params)
	if err != nil {
		p.logger.Printf("INJECT-FAIL agent=%s tool=%s reason=marshal-error", p.agent, toolName)
		p.audit(toolName, "block", "inject-marshal-error")
		return nil, fmt.Sprintf("nockguard: tool %q injection failed", toolName), false
	}

	// Success: record scrub set (both raw and templated) and emit audit rows
	for _, rr := range resolved {
		p.scrubber.add(rr.value)
		// Also register the templated value if a template was used
		if rr.rule.Template != "" {
			templated := strings.ReplaceAll(rr.rule.Template, "{secret}", rr.value)
			p.scrubber.add(templated)
		}
		p.audit(toolName, "inject", fmt.Sprintf("ref=%s arg=%s", rr.rule.Ref, rr.rule.Arg))
	}

	return out, "", true
}

// setArgPathInParams sets a value at a dot-delimited path under params.arguments,
// creating intermediate objects as needed. The parameters map is updated in-place.
// Returns false if arguments is not an object or an intermediate path cannot be set.
func setArgPathInParams(params *map[string]json.RawMessage, path string, value string) bool {
	// Get or create arguments
	var arguments map[string]json.RawMessage
	if argRaw, exists := (*params)["arguments"]; exists {
		if err := json.Unmarshal(argRaw, &arguments); err != nil {
			return false
		}
		// json.Unmarshal of JSON null leaves map nil with no error
		if arguments == nil {
			arguments = make(map[string]json.RawMessage)
		}
	} else {
		arguments = make(map[string]json.RawMessage)
	}

	// Split the path and set the value
	parts := strings.Split(path, ".")
	if !setAtPathRaw(&arguments, parts, value) {
		return false
	}

	// Re-marshal arguments back into params
	argBytes, _ := json.Marshal(arguments)
	(*params)["arguments"] = argBytes

	return true
}

// setAtPathRaw sets a value at a dot-delimited path within a map[string]json.RawMessage,
// creating intermediate objects as needed. Works recursively down the path.
func setAtPathRaw(obj *map[string]json.RawMessage, parts []string, value string) bool {
	if len(parts) == 0 {
		return false
	}

	// Base case: final key
	if len(parts) == 1 {
		valueBytes, _ := json.Marshal(value)
		(*obj)[parts[0]] = valueBytes
		return true
	}

	// Recursive case: navigate to intermediate objects
	key := parts[0]
	var next map[string]json.RawMessage

	if raw, exists := (*obj)[key]; exists {
		// Unmarshal existing value; check for both unmarshal errors and null values
		if err := json.Unmarshal(raw, &next); err != nil {
			return false
		}
		// json.Unmarshal of JSON null leaves map nil with no error; treat as absent
		if next == nil {
			next = make(map[string]json.RawMessage)
		}
	} else {
		// Create new intermediate object
		next = make(map[string]json.RawMessage)
	}

	// Recursively set in the next level
	if !setAtPathRaw(&next, parts[1:], value) {
		return false
	}

	// Marshal back and store
	nextBytes, _ := json.Marshal(next)
	(*obj)[key] = nextBytes

	return true
}
