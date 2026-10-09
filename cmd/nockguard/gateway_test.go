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
	"github.com/nocktechnologies/nockguard/internal/policy"
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

func TestGatewayRequiresPerAgentKeyEvenWhenPolicyNamesOne(t *testing.T) {
	for _, test := range []struct {
		name                  string
		policyKey             string
		perAgentEnv, seedF    bool
		want, absentFromError string
	}{
		{"policy HMAC beats seed file", "sign_key_env", false, true, "audit.sign_key_env GUARD_TEST_POLICY_HMAC takes precedence; remove it", ""},
		{"policy Ed25519 beats seed file", "sign_ed25519_key_env", false, true, "audit.sign_ed25519_key_env GUARD_TEST_POLICY_ED25519 takes precedence; remove it", ""},
		{"per-agent env beats policy key", "sign_key_env", true, false, "", ""},
		{"seed file, no policy key", "", false, true, "", ""},
		{"nothing but a policy key", "sign_key_env", false, false, "audit.sign_key_env GUARD_TEST_POLICY_HMAC takes precedence; remove it", ""},
		{"no key anywhere", "", false, false, "no per-agent Ed25519 signing key found in NOCKGUARD_AGENT_MIRA_ED25519_KEY or a key file from `nockguard keygen --agent mira`", "takes precedence"},
	} {
		t.Run(test.name, func(t *testing.T) {
			dir, home := t.TempDir(), keygenHome(t)
			t.Setenv("NOCKGUARD_AGENT_MIRA_ED25519_KEY", "")
			t.Setenv("GUARD_TEST_AUTH", "test-auth-service-credential")
			t.Setenv("GUARD_TEST_UPSTREAM", "test-upstream-service-credential")
			seed, _ := freshEd25519(t)
			if test.perAgentEnv {
				t.Setenv("NOCKGUARD_AGENT_MIRA_ED25519_KEY", seed)
			}
			if test.seedF {
				if err := os.MkdirAll(policy.AgentKeyDir(home), 0o700); err != nil {
					t.Fatal(err)
				}
				if err := os.WriteFile(policy.AgentSeedPath(home, "mira"), []byte(seed), 0o600); err != nil {
					t.Fatal(err)
				}
			}
			auditCfg := map[string]interface{}{"enabled": true, "path": filepath.Join(dir, "audit.jsonl")}
			if test.policyKey == "sign_key_env" {
				t.Setenv("GUARD_TEST_POLICY_HMAC", "test-policy-wide-hmac-key")
				auditCfg["sign_key_env"] = "GUARD_TEST_POLICY_HMAC"
			} else if test.policyKey == "sign_ed25519_key_env" {
				t.Setenv("GUARD_TEST_POLICY_ED25519", seed)
				auditCfg["sign_ed25519_key_env"] = "GUARD_TEST_POLICY_ED25519"
			}
			c := gateway.Config{Listen: "127.0.0.1:0", Resource: "https://guard.example/mcp", Issuer: "https://issuer.example", IntrospectionURL: "https://issuer.example/introspect", IntrospectionAuthHeader: "X-Agent-Token", IntrospectionTokenEnv: "GUARD_TEST_AUTH", Subject: "operator", ClientID: "client", Scope: "mcp", Agent: "mira", Policy: filepath.Join(dir, "policy.yaml"), Upstream: "https://upstream.example/mcp", UpstreamTokenEnv: "GUARD_TEST_UPSTREAM"}
			b, err := yaml.Marshal(map[string]interface{}{"agents": map[string]interface{}{"mira": map[string]interface{}{"mode": "deny"}}, "audit": auditCfg})
			if err != nil {
				t.Fatal(err)
			}
			if err = os.WriteFile(c.Policy, b, 0600); err != nil {
				t.Fatal(err)
			}
			if b, err = yaml.Marshal(c); err != nil {
				t.Fatal(err)
			}
			path := filepath.Join(dir, "gateway.yaml")
			if err = os.WriteFile(path, b, 0600); err != nil {
				t.Fatal(err)
			}
			ctx, cancel := context.WithCancel(context.Background())
			cancel()
			err = serveMCPGateway(ctx, path)
			if err != nil {
				if _, statErr := os.Stat(auditCfg["path"].(string)); !os.IsNotExist(statErr) {
					t.Errorf("refused gateway created policy-wide trail: %v", statErr)
				}
			}
			if test.want == "" {
				if err != nil {
					t.Fatal(err)
				}
			} else if err == nil || !strings.Contains(err.Error(), test.want) ||
				(test.absentFromError != "" && strings.Contains(err.Error(), test.absentFromError)) {
				t.Fatalf("got %v, want %s without %s", err, test.want, test.absentFromError)
			}
		})
	}
}
