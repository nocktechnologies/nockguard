package extract

import (
	"encoding/json"
	"testing"
)

func TestFromToolCall_NockccNockClaim(t *testing.T) {
	tests := []struct {
		name     string
		tool     string
		params   string
		expected References
	}{
		{
			name:     "nockcc_nock_claim with numeric id",
			tool:     "nockcc_nock_claim",
			params:   `{"id": 12345}`,
			expected: References{NockID: 12345},
		},
		{
			name:     "nockcc_nock_claim with string id",
			tool:     "nockcc_nock_claim",
			params:   `{"id": "67890"}`,
			expected: References{NockID: 67890},
		},
		{
			name:     "nockcc_nock_claim with zero id (invalid)",
			tool:     "nockcc_nock_claim",
			params:   `{"id": 0}`,
			expected: References{},
		},
		{
			name:     "nockcc_nock_claim with negative id (invalid)",
			tool:     "nockcc_nock_claim",
			params:   `{"id": -5}`,
			expected: References{},
		},
		{
			name:     "nockcc_nock_claim without id",
			tool:     "nockcc_nock_claim",
			params:   `{"agent_name": "mira"}`,
			expected: References{},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := FromToolCall(tt.tool, json.RawMessage(tt.params))
			if result != tt.expected {
				t.Errorf("got %+v, want %+v", result, tt.expected)
			}
		})
	}
}

func TestFromToolCall_NockccNockUpdate(t *testing.T) {
	result := FromToolCall("nockcc_nock_update", json.RawMessage(`{"id": 555}`))
	if result.NockID != 555 {
		t.Errorf("got NockID %d, want 555", result.NockID)
	}
}

func TestFromToolCall_NockccNockRelease(t *testing.T) {
	result := FromToolCall("nockcc_nock_release", json.RawMessage(`{"id": 999}`))
	if result.NockID != 999 {
		t.Errorf("got NockID %d, want 999", result.NockID)
	}
}

func TestFromToolCall_UnknownTool(t *testing.T) {
	result := FromToolCall("nockcc_unknown_tool", json.RawMessage(`{"id": 123}`))
	if result != (References{}) {
		t.Errorf("got %+v, want zero References for unknown tool", result)
	}
}

func TestFromToolCall_NilParams(t *testing.T) {
	result := FromToolCall("nockcc_nock_claim", nil)
	if result != (References{}) {
		t.Errorf("got %+v, want zero References for nil params", result)
	}
}

func TestFromToolCall_MalformedJSON(t *testing.T) {
	result := FromToolCall("nockcc_nock_claim", json.RawMessage(`{invalid json}`))
	if result != (References{}) {
		t.Errorf("got %+v, want zero References for malformed JSON", result)
	}
}

func TestFromToolCall_InvalidStringID(t *testing.T) {
	result := FromToolCall("nockcc_nock_claim", json.RawMessage(`{"id": "not_a_number"}`))
	if result != (References{}) {
		t.Errorf("got %+v, want zero References for invalid string id", result)
	}
}
