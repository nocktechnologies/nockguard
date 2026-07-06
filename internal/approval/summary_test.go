package approval

import (
	"encoding/json"
	"fmt"
	"strings"
	"testing"
)

func TestSummarizeParams_ShowsConsentRelevantScalars(t *testing.T) {
	// A spend call: the human MUST be able to see the amount.
	out := summarizeParams(json.RawMessage(`{"amount":5000,"currency":"usd"}`))
	if !strings.Contains(out, "amount: 5000") {
		t.Errorf("amount not shown for consent: %q", out)
	}
	if !strings.Contains(out, `currency: "usd"`) {
		t.Errorf("short string not shown: %q", out)
	}
}

func TestSummarizeParams_ShowsKillSwitchTarget(t *testing.T) {
	out := summarizeParams(json.RawMessage(`{"halt":true,"target":"prod-fleet"}`))
	if !strings.Contains(out, "halt: true") {
		t.Errorf("bool not shown: %q", out)
	}
	if !strings.Contains(out, `target: "prod-fleet"`) {
		t.Errorf("target not shown: %q", out)
	}
}

func TestSummarizeParams_RedactsSensitiveKeys(t *testing.T) {
	for _, k := range []string{"api_key", "password", "auth_token", "secret", "session_cookie"} {
		out := summarizeParams(json.RawMessage(`{"` + k + `":"hunter2"}`))
		if strings.Contains(out, "hunter2") {
			t.Errorf("LEAKED secret value for key %q: %q", k, out)
		}
		if !strings.Contains(out, "[redacted]") {
			t.Errorf("sensitive key %q not redacted: %q", k, out)
		}
	}
}

func TestSummarizeParams_RedactsLongValues(t *testing.T) {
	blob := strings.Repeat("A", 200) // looks like a token/blob
	out := summarizeParams(json.RawMessage(`{"data":"` + blob + `"}`))
	if strings.Contains(out, blob) {
		t.Errorf("LEAKED long value: %q", out)
	}
	if !strings.Contains(out, "redacted, 200 chars") {
		t.Errorf("long value not redacted with length: %q", out)
	}
}

func TestSummarizeParams_DoesNotRecurseIntoNested(t *testing.T) {
	out := summarizeParams(json.RawMessage(`{"config":{"deep_secret":"shh"},"items":[1,2,3]}`))
	if strings.Contains(out, "shh") {
		t.Errorf("LEAKED nested secret: %q", out)
	}
	if !strings.Contains(out, "config: {…}") || !strings.Contains(out, "items: […]") {
		t.Errorf("nested structures not shown as placeholders: %q", out)
	}
}

func TestSummarizeParams_NonObjectShowsSizeNotContent(t *testing.T) {
	out := summarizeParams(json.RawMessage(`"just-a-string-not-an-object"`))
	if strings.Contains(out, "just-a-string") {
		t.Errorf("LEAKED non-object content: %q", out)
	}
	if !strings.Contains(out, "bytes, not shown") {
		t.Errorf("non-object not summarized by size: %q", out)
	}
}

func TestSummarizeParams_RedactsSecretShapedValuesUnderNeutralKeys(t *testing.T) {
	// The N8613 gap: a credential-shaped value under a NEUTRAL key (short
	// enough to dodge the >40-char cap, key name not "sensitive") was forwarded
	// to Telegram verbatim. Every one of these must be redacted.
	cases := []struct {
		name, key, secret string
	}{
		{"openai-key-under-id", "id", "sk-abcdefghijklmnop0123456789"},     // ~29 chars, < maxValueLen
		{"openai-key-under-value", "value", "sk-abcdefghijklmnop01234567"}, // ~27 chars
		{"aws-key-under-body", "body", "AKIAIOSFODNN7EXAMPLE"},             // 20 chars
		{"github-token-under-id", "id", "ghp_0123456789abcdef0123456789abcdef0123"},
		{"ssn-under-value", "value", "123-45-6789"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			// Guard the premise: the value must be short enough that ONLY the
			// new secret-shape check (not the length cap) can catch it.
			if len(tc.secret) > maxValueLen {
				t.Fatalf("test value %q is >maxValueLen (%d); not exercising the neutral-key gap", tc.secret, maxValueLen)
			}
			raw := json.RawMessage(`{"` + tc.key + `":"` + tc.secret + `"}`)
			out := summarizeParams(raw)
			if strings.Contains(out, tc.secret) {
				t.Errorf("LEAKED secret-shaped value under neutral key %q: %q", tc.key, out)
			}
			if !strings.Contains(out, "redacted") {
				t.Errorf("secret-shaped value under key %q not redacted: %q", tc.key, out)
			}
		})
	}
}

func TestSummarizeParams_ShowsHarmlessShortScalarsUnderNeutralKeys(t *testing.T) {
	// POSITIVE CONTROL: the fix must not over-redact. Harmless short scalars
	// under neutral keys must still be shown so the human can make the call.
	out := summarizeParams(json.RawMessage(`{"id":"invoice-42","status":"pending","region":"us-east-1","count":7}`))
	for _, want := range []string{`id: "invoice-42"`, `status: "pending"`, `region: "us-east-1"`, "count: 7"} {
		if !strings.Contains(out, want) {
			t.Errorf("harmless scalar over-redacted, missing %q in: %q", want, out)
		}
	}
	if strings.Contains(out, "redacted") {
		t.Errorf("harmless scalars should not trigger any redaction: %q", out)
	}
}

func TestSummarizeParams_RedactsSecretShapedBareNumber(t *testing.T) {
	// POSITIVE CONTROL for the number branch: a genuine spend amount shows,
	// but a bare credit-card-shaped numeric literal is redacted.
	out := summarizeParams(json.RawMessage(`{"amount":5000,"card":4111111111111111}`))
	if !strings.Contains(out, "amount: 5000") {
		t.Errorf("legitimate numeric amount over-redacted: %q", out)
	}
	if strings.Contains(out, "4111111111111111") {
		t.Errorf("LEAKED card-shaped bare number: %q", out)
	}
}

func TestSummarizeParams_EmptyOrAbsent(t *testing.T) {
	if got := summarizeParams(nil); got != "" {
		t.Errorf("nil params should yield empty summary, got %q", got)
	}
	if got := summarizeParams(json.RawMessage(`{}`)); got != "" {
		t.Errorf("empty object should yield empty summary, got %q", got)
	}
}

func TestSummarizeParams_CapsTotalLength(t *testing.T) {
	var sb strings.Builder
	sb.WriteString("{")
	for i := 0; i < 60; i++ {
		if i > 0 {
			sb.WriteString(",")
		}
		fmt.Fprintf(&sb, `"unique_key_%02d":1`, i) // unique keys so the object doesn't collapse
	}
	sb.WriteString("}")
	out := summarizeParams(json.RawMessage(sb.String()))
	if len(out) > maxSummaryLen+64 {
		t.Errorf("summary not length-capped: %d chars", len(out))
	}
	if !strings.Contains(out, "…") {
		t.Errorf("truncated summary should end with an ellipsis: %q", out)
	}
}
