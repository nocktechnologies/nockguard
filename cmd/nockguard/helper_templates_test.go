package main

import (
	"bytes"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"github.com/nocktechnologies/nockguard/internal/policy"
)

// The repo's own .claude/commands are the maintained source; the Warden
// template ships byte-identical copies and nothing else.
func TestWardenCommandsMatchRepoCommands(t *testing.T) {
	src := filepath.Join("..", "..", ".claude", "commands")
	dst := filepath.Join("..", "..", "templates", "warden", ".claude", "commands")
	entries, err := os.ReadDir(src)
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) == 0 {
		t.Fatal("no commands found in .claude/commands")
	}
	want := map[string]bool{}
	for _, e := range entries {
		want[e.Name()] = true
		wantBytes, err := os.ReadFile(filepath.Join(src, e.Name()))
		if err != nil {
			t.Fatal(err)
		}
		if len(wantBytes) == 0 {
			t.Errorf(".claude/commands/%s is empty", e.Name())
		}
		got, err := os.ReadFile(filepath.Join(dst, e.Name()))
		if err != nil {
			t.Fatalf("Warden template is missing %s: %v", e.Name(), err)
		}
		if !bytes.Equal(wantBytes, got) {
			t.Errorf("templates/warden/.claude/commands/%s differs from .claude/commands/%s; copy the latter over it", e.Name(), e.Name())
		}
	}
	extra, err := os.ReadDir(dst)
	if err != nil {
		t.Fatal(err)
	}
	for _, e := range extra {
		if !want[e.Name()] {
			t.Errorf("templates/warden/.claude/commands/%s has no source in .claude/commands", e.Name())
		}
	}
}

// policy-lint must list every key the loader accepts, or it reports valid
// policies as broken.
func TestPolicyLintListsEveryAgentKey(t *testing.T) {
	doc, err := os.ReadFile(filepath.Join("..", "..", ".claude", "commands", "policy-lint.md"))
	if err != nil {
		t.Fatal(err)
	}
	// Restrict the search to the E002 valid-key set line.
	var valid []byte
	for _, line := range bytes.Split(doc, []byte("\n")) {
		if bytes.HasPrefix(line, []byte("valid = {")) {
			valid = line
			break
		}
	}
	if valid == nil {
		t.Fatal("policy-lint.md has no E002 `valid = {` set")
	}
	rt := reflect.TypeOf(policy.AgentPolicy{})
	for i := 0; i < rt.NumField(); i++ {
		key := strings.Split(rt.Field(i).Tag.Get("yaml"), ",")[0]
		if key == "" {
			continue
		}
		if !bytes.Contains(valid, []byte("'"+key+"'")) {
			t.Errorf("policy-lint.md E002 valid-key set omits agent key %q", key)
		}
	}
}
