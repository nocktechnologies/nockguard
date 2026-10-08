package main

import (
	"crypto/ed25519"
	"encoding/hex"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/nocktechnologies/nockguard/internal/audit"
)

func TestVerifyExportVerdictNamesSignedUpperBound(t *testing.T) {
	pub, priv, _ := ed25519.GenerateKey(nil)
	trailPath := filepath.Join(t.TempDir(), "trail.jsonl")
	a, err := audit.New(trailPath, audit.WithEd25519Key(priv))
	if err != nil {
		t.Fatal(err)
	}
	if err := a.Record(audit.Event{Agent: "probe", Tool: "read", Decision: "allow"}); err != nil {
		t.Fatal(err)
	}
	if err := a.Close(); err != nil {
		t.Fatal(err)
	}
	trail, _ := os.ReadFile(trailPath)
	head, _ := os.ReadFile(trailPath + ".hwm")
	const bound = "2026-10-07T12:00:00Z"
	proof, err := audit.MakeExportProof(trail, head, pub, priv, audit.ExportFilters{Until: bound, CapturedAt: "2099-01-01T00:00:01Z"})
	if err != nil {
		t.Fatal(err)
	}
	proofPath := filepath.Join(t.TempDir(), "proof.json")
	if err := os.WriteFile(proofPath, proof, 0600); err != nil {
		t.Fatal(err)
	}
	t.Setenv("NOCKGUARD_TEST_EXPORT_PUB", hex.EncodeToString(pub))
	code, stdout, stderr := runCommandForTest(t, "verify", "--export", proofPath, "--ed25519-pub-env", "NOCKGUARD_TEST_EXPORT_PUB")
	if code != 0 || stderr != "" || !strings.Contains(stdout, "VERDICT: PROTECTED — complete time window through "+bound) {
		t.Fatalf("verify export = %d, stdout=%q, stderr=%q", code, stdout, stderr)
	}
	legacy, err := audit.MakeExportProof(trail, head, pub, priv, audit.ExportFilters{Since: "2020-01-01T00:00:00Z"})
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(proofPath, legacy, 0600); err != nil {
		t.Fatal(err)
	}
	code, stdout, stderr = runCommandForTest(t, "verify", "--export", proofPath, "--ed25519-pub-env", "NOCKGUARD_TEST_EXPORT_PUB")
	if code != 0 || stderr != "" || !strings.Contains(stdout, "no explicit upper time bound") {
		t.Fatalf("legacy proof = %d, stdout=%q, stderr=%q", code, stdout, stderr)
	}
}
