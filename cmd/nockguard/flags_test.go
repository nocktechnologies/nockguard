package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestCLIRejectsMalformedFlagsBeforeSideEffects(t *testing.T) {
	for _, command := range []string{"proxy", "egress-proxy", "mcp-listen", "init", "mcp-http"} {
		for _, tc := range []struct {
			name string
			args []string
			want string
		}{
			{"missing value", []string{"--policy"}, "flag needs an argument"},
			{"misspelled flag", []string{"--polciy", "policy.yaml"}, "flag provided but not defined"},
			{"unexpected argument", []string{"policy.yaml"}, "unexpected argument"},
		} {
			t.Run(command+"/"+tc.name, func(t *testing.T) {
				home := t.TempDir()
				t.Setenv("HOME", home)
				code, _, stderr := runCommandForTest(t, append([]string{command}, tc.args...)...)
				if code != 1 || !strings.Contains(stderr, tc.want) {
					t.Errorf("exit=%d stderr=%q, want usage error containing %q", code, stderr, tc.want)
				}
				if _, err := os.Stat(filepath.Join(home, ".nockguard")); !os.IsNotExist(err) {
					t.Errorf("malformed flags touched the NockGuard home: %v", err)
				}
			})
		}
	}
}

func TestProxyExplicitPolicyNeverStartsObserveMode(t *testing.T) {
	for _, value := range []string{"", filepath.Join(t.TempDir(), "missing.yaml")} {
		t.Run(value, func(t *testing.T) {
			home := t.TempDir()
			t.Setenv("HOME", home)
			code, _, stderr := runCommandForTest(t, "proxy", "--upstream", "cat", "--agent", "demo", "--policy="+value)
			if code != 1 || strings.Contains(stderr, "OBSERVE") {
				t.Fatalf("explicit policy started observe mode: exit=%d stderr=%q", code, stderr)
			}
			if _, err := os.Stat(filepath.Join(home, ".nockguard")); !os.IsNotExist(err) {
				t.Errorf("explicit unusable policy touched the NockGuard home: %v", err)
			}
		})
	}
}
