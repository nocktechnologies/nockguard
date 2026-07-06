package approval

import (
	"encoding/json"
	"fmt"
	"regexp"
	"sort"
	"strings"

	"github.com/nocktechnologies/nockguard/internal/validate"
)

// A human can't give informed consent to a call they can't see. The approval
// prompt therefore summarizes the tool-call params — enough to recognize WHAT is
// being approved (a spend amount, a kill-switch target) — while never leaking
// secrets. The stance is deliberately conservative: sensitive-looking keys and
// long/complex values are redacted; only short scalars are shown verbatim. Raw
// params are never sent to Telegram (nor, separately, written to the audit trail).

var sensitiveKey = regexp.MustCompile(`(?i)(secret|token|key|password|passwd|pwd|auth|credential|cookie|session|private|signature)`)

const (
	maxValueLen   = 40
	maxSummaryLen = 280
)

// summarizeParams renders a redacted, length-capped summary of a tool call's
// params for the human approval prompt. Returns "" when there is nothing safe or
// useful to show.
func summarizeParams(params json.RawMessage) string {
	if len(params) == 0 {
		return ""
	}
	var obj map[string]json.RawMessage
	if err := json.Unmarshal(params, &obj); err != nil {
		// Not a JSON object we can break down — show only its size, never content.
		return fmt.Sprintf("Args: [%d bytes, not shown]", len(params))
	}
	if len(obj) == 0 {
		return ""
	}

	keys := make([]string, 0, len(obj))
	for k := range obj {
		keys = append(keys, k)
	}
	sort.Strings(keys)

	var b strings.Builder
	b.WriteString("Args:")
	for _, k := range keys {
		if b.Len() > maxSummaryLen {
			b.WriteString("\n  …")
			break
		}
		b.WriteString("\n  ")
		b.WriteString(k)
		b.WriteString(": ")
		b.WriteString(summarizeValue(k, obj[k]))
	}
	return b.String()
}

// summarizeValue renders one param value safely: redacts sensitive-keyed,
// secret-SHAPED, and long/complex values, shows short non-secret scalars
// (numbers, booleans, short strings) verbatim because those are what the human
// needs to approve.
func summarizeValue(key string, raw json.RawMessage) string {
	if sensitiveKey.MatchString(key) {
		return "[redacted]"
	}
	s := strings.TrimSpace(string(raw))
	if s == "" {
		return "[redacted]"
	}

	// Numbers, booleans, null: safe and consent-relevant — show verbatim,
	// except a bare numeric literal that matches a secret pattern (e.g. a
	// 13–16 digit card number), which is redacted with the string branch below.
	switch s {
	case "true", "false", "null":
		return s
	}
	if c := s[0]; c == '-' || (c >= '0' && c <= '9') {
		if validate.LooksLikeSecret(s) {
			return "[redacted]"
		}
		return s
	}

	// Strings: a value can be secret-SHAPED (an API key, token, SSN, card
	// number, …) under a perfectly NEUTRAL key like "id"/"value"/"body". The
	// key-name check above can't catch that, so run the SAME secret detectors
	// validation uses on EVERY string value — a credential must never reach
	// Telegram before the human approves (N8613). Then show short non-secret
	// strings and redact long blobs.
	var str string
	if err := json.Unmarshal(raw, &str); err == nil {
		if validate.LooksLikeSecret(str) {
			return fmt.Sprintf("[redacted, %d chars]", len(str))
		}
		if len(str) <= maxValueLen {
			return fmt.Sprintf("%q", str)
		}
		return fmt.Sprintf("[redacted, %d chars]", len(str))
	}

	// Objects/arrays: don't recurse — a typed placeholder, never the contents.
	switch s[0] {
	case '{':
		return "{…}"
	case '[':
		return "[…]"
	}
	return "[redacted]"
}
