package main

import (
	"bytes"
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"regexp"
	"strings"
	"testing"
	"time"

	"github.com/nocktechnologies/nockguard/internal/approval"
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
	for _, key := range yamlKeys(t, reflect.TypeOf(policy.AgentPolicy{})) {
		if !bytes.Contains(valid, []byte("'"+key+"'")) {
			t.Errorf("policy-lint.md E002 valid-key set omits agent key %q", key)
		}
	}
}

// Line numbers go stale and the Warden template copies these files into users'
// projects; cite function names. Checks must also report their own failures, so
// no template may discard a probe's stderr.
func TestShippedTemplatesCiteFunctionsAndKeepStderr(t *testing.T) {
	root := filepath.Join("..", "..")
	stderrDiscard := regexp.MustCompile(`2> ?/dev/null|&> ?/dev/null`)
	lineRef := regexp.MustCompile(`\.go:[0-9]+`)
	files := []string{filepath.Join("templates", "warden", "CLAUDE.md")}
	for _, dir := range []string{filepath.Join(".claude", "commands"), filepath.Join("templates", "warden", ".claude", "commands")} {
		entries, err := os.ReadDir(filepath.Join(root, dir))
		if err != nil {
			t.Fatal(err)
		}
		for _, e := range entries {
			files = append(files, filepath.Join(dir, e.Name()))
		}
	}
	for _, f := range files {
		body, err := os.ReadFile(filepath.Join(root, f))
		if err != nil {
			t.Fatal(err)
		}
		if m := lineRef.Find(body); m != nil {
			t.Errorf("%s cites a source line number (%q); name the function instead", f, m)
		}
		if stderrDiscard.Match(body) {
			t.Errorf("%s discards a check's stderr to /dev/null; report the failure instead", f)
		}
	}
}

// yamlKeys lists the keys yaml.v3 accepts for a struct: the tag name, else the
// lowercased field name; inline structs contribute their own keys.
func yamlKeys(t *testing.T, rt reflect.Type) []string {
	t.Helper()
	for rt.Kind() == reflect.Ptr {
		rt = rt.Elem()
	}
	if rt.Kind() != reflect.Struct {
		t.Fatalf("yamlKeys: inline field of kind %s is not a struct; teach the test how the loader reads it", rt.Kind())
	}
	var keys []string
	for i := 0; i < rt.NumField(); i++ {
		f := rt.Field(i)
		if !f.IsExported() {
			continue
		}
		tag := f.Tag.Get("yaml")
		if tag == "-" {
			continue
		}
		parts := strings.Split(tag, ",")
		inline := false
		for _, o := range parts[1:] {
			inline = inline || o == "inline"
		}
		if inline {
			keys = append(keys, yamlKeys(t, f.Type)...)
			continue
		}
		if parts[0] == "" {
			parts[0] = strings.ToLower(f.Name)
		}
		keys = append(keys, parts[0])
	}
	return keys
}

// Execute the shipped W005 helpers against the same inputs as the runtime parser.
func TestPolicyLintTelegramParity(t *testing.T) {
	doc, err := os.ReadFile(filepath.Join("..", "..", ".claude", "commands", "policy-lint.md"))
	if err != nil {
		t.Fatal(err)
	}
	start := bytes.Index(doc, []byte("def i64(s):"))
	if start < 0 {
		t.Fatal("W005 integer helper missing")
	}
	end := bytes.Index(doc[start:], []byte("with open("))
	if end < 0 {
		t.Fatal("W005 helper end missing")
	}
	helper := string(doc[start : start+end])
	cases := []struct {
		name, chat, ids string
		want            bool
	}{
		{"plain", "123", "456", true},
		{"group", "-123", "456,789", true},
		{"signed", "+123", "+456", true},
		{"id whitespace", "123", " 456 , 789 ", true},
		{"chat whitespace", " 123 ", "456", false},
		{"empty chat", "", "456", false},
		{"empty ids", "123", "", false},
		{"blank ids", "123", " ", false},
		{"empty entry", "123", "456,,789", false},
		{"trailing comma", "123", "456,", false},
		{"duplicates", "123", "456,456", true},
		{"chat nonnumeric", "group", "456", false},
		{"id nonnumeric", "123", "user", false},
		{"chat overflow", "9223372036854775808", "456", false},
		{"chat underflow", "-9223372036854775809", "456", false},
		{"id overflow", "123", "9223372036854775808", false},
		{"limits", "-9223372036854775808", "9223372036854775807", true},
		{"space separator", "123", "456 789", false},
		{"negative user", "123", "-456", false},
		{"zero user", "123", "0", false},
	}
	inputs := make([][2]string, len(cases))
	for i, tc := range cases {
		inputs[i] = [2]string{tc.chat, tc.ids}
	}
	input, err := json.Marshal(inputs)
	if err != nil {
		t.Fatal(err)
	}
	script := "import os, sys, json\n" + helper + `
results = []
for chat, ids in json.load(sys.stdin):
    os.environ['NOCKGUARD_APPROVAL_BOT_TOKEN'] = 'test-token'
    os.environ['NOCKGUARD_APPROVAL_CHAT_ID'] = chat
    os.environ['NOCKGUARD_APPROVER_IDS'] = ids
    results.append(telegram_ok())
json.dump(results, sys.stdout)
`
	cmd := exec.Command("python3", "-c", script)
	cmd.Stdin = bytes.NewReader(input)
	output, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("W005 Python helper: %v: %s", err, output)
	}
	var results []bool
	if err := json.Unmarshal(output, &results); err != nil {
		t.Fatal(err)
	}
	if len(results) != len(cases) {
		t.Fatalf("got %d results, want %d", len(results), len(cases))
	}
	for i, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			_, err := approval.NewTelegramApprover("test-token", tc.chat, tc.ids, time.Second)
			accepted := err == nil
			if accepted != tc.want || results[i] != tc.want {
				t.Errorf("chat=%q ids=%q: Go=%v Python=%v, want %v", tc.chat, tc.ids, accepted, results[i], tc.want)
			}
		})
	}
}
