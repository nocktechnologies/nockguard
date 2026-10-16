package policy

import "testing"

func TestForwarderDisabledWhenAbsent(t *testing.T) {
	path := writePolicy(t, `
audit:
  enabled: true
agents:
  kit:
    allow: ["*"]
`)
	eng, err := Load(path)
	if err != nil {
		t.Fatal(err)
	}
	f, err := eng.Forwarder()
	if err != nil {
		t.Fatalf("Forwarder: %v", err)
	}
	defer f.Stop()
	if f.Enabled() {
		t.Error("no forward block should yield a disabled forwarder")
	}
}

func TestForwarderDisabledWhenEnabledFalse(t *testing.T) {
	path := writePolicy(t, `
audit:
  enabled: true
  forward:
    enabled: false
    url: https://cc.example.test
agents:
  kit:
    allow: ["*"]
`)
	eng, err := Load(path)
	if err != nil {
		t.Fatal(err)
	}
	f, err := eng.Forwarder()
	if err != nil {
		t.Fatal(err)
	}
	defer f.Stop()
	if f.Enabled() {
		t.Error("forward.enabled=false should yield a disabled forwarder")
	}
}

func TestForwarderEnabledResolvesApiKeyFromEnv(t *testing.T) {
	t.Setenv("NG_TEST_KEY", "resolved-key")
	path := writePolicy(t, `
audit:
  enabled: true
  forward:
    enabled: true
    url: https://cc.example.test
    api_key_env: NG_TEST_KEY
agents:
  kit:
    allow: ["*"]
`)
	eng, err := Load(path)
	if err != nil {
		t.Fatal(err)
	}
	f, err := eng.Forwarder()
	if err != nil {
		t.Fatalf("Forwarder: %v", err)
	}
	defer f.Stop()
	if !f.Enabled() {
		t.Error("forward.enabled=true with url + resolvable key should enable the forwarder")
	}
}

func TestForwarderEnabledRequiresURL(t *testing.T) {
	path := writePolicy(t, `
audit:
  enabled: true
  forward:
    enabled: true
agents:
  kit:
    allow: ["*"]
`)
	eng, err := Load(path)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := eng.Forwarder(); err == nil {
		t.Fatal("forward.enabled with no url should fail loud")
	}
}

func TestForwarderEnabledRequiresResolvableKey(t *testing.T) {
	path := writePolicy(t, `
audit:
  enabled: true
  forward:
    enabled: true
    url: https://cc.example.test
    api_key_env: NG_DEFINITELY_UNSET_KEY
agents:
  kit:
    allow: ["*"]
`)
	eng, err := Load(path)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := eng.Forwarder(); err == nil {
		t.Fatal("api_key_env pointing at an unset variable should fail loud")
	}
}

func TestForwarderKeyEnvNames(t *testing.T) {
	for _, tc := range []struct{ name, body, want string }{
		{"no audit", "", ""},
		{"no forwarder", "audit: {}", ""},
		{"no key", "audit: {forward: {enabled: true}}", ""},
		{"enabled", "audit: {forward: {enabled: true, api_key_env: CUSTOM_FORWARD_KEY}}", "CUSTOM_FORWARD_KEY"},
		{"disabled", "audit: {forward: {enabled: false, api_key_env: CUSTOM_FORWARD_KEY}}", "CUSTOM_FORWARD_KEY"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			eng, err := Load(writePolicy(t, "agents: {test: {allow: [\"*\"]}}\n"+tc.body))
			if err != nil {
				t.Fatal(err)
			}
			got := eng.ForwarderKeyEnvNames()
			if tc.want == "" {
				if len(got) != 0 {
					t.Fatalf("got %v, want no names", got)
				}
				return
			}
			if len(got) != 1 || got[0] != tc.want {
				t.Fatalf("got %v, want [%s]", got, tc.want)
			}
		})
	}
}
