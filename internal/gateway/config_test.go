package gateway

import (
	"os"
	"path/filepath"
	"testing"
)

func TestConfigurationRefusesUnsafeDestinations(t *testing.T) {
	base := testConfig(t)
	if err := base.Validate(); err != nil {
		t.Fatal(err)
	}
	for name, change := range map[string]func(*Config){
		"public bind":      func(c *Config) { c.Listen = "0.0.0.0:8791" },
		"hostname bind":    func(c *Config) { c.Listen = "localhost:8791" },
		"http auth":        func(c *Config) { c.IntrospectionURL = "http://issuer.example/introspect" },
		"http upstream":    func(c *Config) { c.Upstream = "http://upstream.example/mcp" },
		"userinfo":         func(c *Config) { c.Upstream = "https://secret@upstream.example/mcp" },
		"query":            func(c *Config) { c.Upstream = "https://upstream.example/mcp?token=secret" },
		"fragment":         func(c *Config) { c.Issuer = "https://issuer.example/#fragment" },
		"wrong path":       func(c *Config) { c.Resource = "https://guard.example/other" },
		"missing identity": func(c *Config) { c.Subject = "" },
		"missing client":   func(c *Config) { c.ClientID = "" },
		"scope list":       func(c *Config) { c.Scope = "mcp other" },
		"same credentials": func(c *Config) { c.UpstreamTokenEnv = c.IntrospectionTokenEnv },
		"arbitrary header": func(c *Config) { c.IntrospectionAuthHeader = "Cookie" },
		"wildcard origin":  func(c *Config) { c.AllowedOrigins = []string{"*"} },
		"origin userinfo":  func(c *Config) { c.AllowedOrigins = []string{"https://user@host.example"} },
	} {
		t.Run(name, func(t *testing.T) {
			c := base
			change(&c)
			if c.Validate() == nil {
				t.Fatal("unsafe config accepted")
			}
		})
	}
	for _, input := range []string{"unknown_key: true\n", "listen: 127.0.0.1:8791\n---\nagent: other\n"} {
		path := filepath.Join(t.TempDir(), "config.yaml")
		if err := os.WriteFile(path, []byte(input), 0600); err != nil {
			t.Fatal(err)
		}
		if _, err := Load(path); err == nil {
			t.Fatal("ambiguous configuration accepted")
		}
	}
	for _, value := range []string{"", "has space", "has\nnewline"} {
		t.Setenv("GUARD_TEST_SECRET", value)
		if _, err := Secret("GUARD_TEST_SECRET"); err == nil {
			t.Fatal("invalid credential accepted")
		}
	}
}
