package main

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/hex"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/nocktechnologies/nockguard/internal/gateway"
	"gopkg.in/yaml.v3"
)

func TestGatewayStartupRequiresCredentialsPolicyAndSignedAudit(t *testing.T) {
	for _, test := range []struct{ name, want string }{
		{"missing upstream", "empty"}, {"reused credential", "different"},
		{"unknown agent", "no policy"}, {"missing key", "Ed25519"},
		{"disabled audit", "audit.enabled"}, {"valid", ""},
	} {
		t.Run(test.name, func(t *testing.T) {
			dir := t.TempDir()
			c := gateway.Config{Listen: "127.0.0.1:0", Resource: "https://guard.example/mcp", Issuer: "https://issuer.example", IntrospectionURL: "https://issuer.example/introspect", IntrospectionAuthHeader: "X-Agent-Token", IntrospectionTokenEnv: "GUARD_TEST_AUTH", Subject: "operator", ClientID: "client", Scope: "mcp", Agent: "mira", Policy: filepath.Join(dir, "policy.yaml"), Upstream: "https://upstream.example/mcp", UpstreamTokenEnv: "GUARD_TEST_UPSTREAM"}
			t.Setenv(c.IntrospectionTokenEnv, "test-auth-service-credential")
			t.Setenv(c.UpstreamTokenEnv, "test-upstream-service-credential")
			_, key, err := ed25519.GenerateKey(rand.Reader)
			if err != nil {
				t.Fatal(err)
			}
			t.Setenv("NOCKGUARD_AGENT_MIRA_ED25519_KEY", hex.EncodeToString(key.Seed()))
			policy := map[string]interface{}{"agents": map[string]interface{}{"mira": map[string]interface{}{"mode": "deny"}}, "audit": map[string]interface{}{"enabled": true, "path": filepath.Join(dir, "audit.jsonl")}}
			switch test.name {
			case "missing upstream":
				t.Setenv(c.UpstreamTokenEnv, "")
			case "reused credential":
				t.Setenv(c.UpstreamTokenEnv, "test-auth-service-credential")
			case "unknown agent":
				c.Agent = "unconfigured"
			case "missing key":
				t.Setenv("NOCKGUARD_AGENT_MIRA_ED25519_KEY", "")
			case "disabled audit":
				delete(policy, "audit")
			}
			b, err := yaml.Marshal(policy)
			if err != nil {
				t.Fatal(err)
			}
			if err = os.WriteFile(c.Policy, b, 0600); err != nil {
				t.Fatal(err)
			}
			b, err = yaml.Marshal(c)
			if err != nil {
				t.Fatal(err)
			}
			path := filepath.Join(dir, "gateway.yaml")
			if err = os.WriteFile(path, b, 0600); err != nil {
				t.Fatal(err)
			}
			ctx, cancel := context.WithCancel(context.Background())
			cancel()
			err = serveMCPGateway(ctx, path)
			if test.want == "" {
				if err != nil {
					t.Fatal(err)
				}
			} else if err == nil || !strings.Contains(err.Error(), test.want) {
				t.Fatalf("got %v, want %s", err, test.want)
			}
		})
	}
	for _, args := range [][]string{{}, {"--unknown"}, {"--config", "file", "extra"}} {
		if runMCPGateway(args) != 1 {
			t.Fatal("invalid CLI arguments accepted")
		}
	}
}
