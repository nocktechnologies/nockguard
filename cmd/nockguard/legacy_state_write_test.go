package main

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestVerifyV010StateWriteFixture(t *testing.T) {
	path := filepath.Join("testdata", "v0.10.0-state-write.audit.jsonl")
	trail, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(trail), `"decision":"state-write"`) {
		t.Fatal("legacy fixture must contain the removed producer's state-write row")
	}
	pub, err := os.ReadFile(filepath.Join("testdata", "v0.10.0-state-write.pub"))
	if err != nil {
		t.Fatal(err)
	}
	t.Setenv("NOCKGUARD_TEST_V010_PUB", strings.TrimSpace(string(pub)))
	code, stdout, stderr := runCommandForTest(t, "verify", "--audit", path, "--ed25519-pub-env", "NOCKGUARD_TEST_V010_PUB", "--json")
	var result verifyResult
	if err := json.Unmarshal([]byte(stdout), &result); err != nil {
		t.Fatal(err)
	}
	if code != 0 || result.Verdict != "PROTECTED" || result.EntriesVerified != 4 {
		t.Fatalf("v0.10.0 signed trail: exit=%d stdout=%s stderr=%s", code, stdout, stderr)
	}
}
