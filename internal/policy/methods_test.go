package policy

import "testing"

func TestDenyMethodsSelection(t *testing.T) {
	e, err := LoadBytes([]byte("agents:\n  default:\n    deny_methods: [resources/read]\n  named:\n    deny_methods: [prompts/get]\n"))
	if err != nil {
		t.Fatal(err)
	}
	for _, tt := range []struct {
		agent, method string
		want          bool
	}{
		{"unknown", "resources/read", true}, {"named", "resources/read", false}, {"named", "prompts/get", true}, {"named", "prompts/Get", false}, {"unknown", "initialize", false},
	} {
		if got := e.DeniesMethod(tt.agent, tt.method); got != tt.want {
			t.Errorf("%s %s: got %v", tt.agent, tt.method, got)
		}
	}
}

func TestDenyMethodsRejectInvalid(t *testing.T) {
	for _, method := range []string{"", "resources/*", " resources/read", "tools/call", "resources/?", "resources/[read]"} {
		if _, err := LoadBytes([]byte("agents:\n  default:\n    deny_methods: ['" + method + "']\n")); err == nil {
			t.Errorf("accepted %q", method)
		}
	}
}
