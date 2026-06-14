package evidence

import (
	"crypto/ed25519"
	"encoding/hex"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/nocktechnologies/nockguard/internal/audit"
)

var testHMACKey = []byte("test-signing-key-32-bytes-padding!")

// fixedNow gives BuildPack a deterministic generated-at/verified-at clock.
func fixedNow() func() time.Time {
	t := time.Date(2026, 6, 14, 12, 0, 0, 0, time.UTC)
	return func() time.Time { return t }
}

// writeSignedTrail records evs into a fresh HMAC-signed audit file and returns
// its path. Reuses the real Auditor so the chain is genuinely signed.
func writeSignedTrail(t *testing.T, evs []audit.Event) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "audit.jsonl")
	a, err := audit.New(path, audit.WithSigningKey(testHMACKey))
	if err != nil {
		t.Fatalf("audit.New: %v", err)
	}
	for _, ev := range evs {
		if err := a.Record(ev); err != nil {
			t.Fatalf("Record: %v", err)
		}
	}
	if err := a.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}
	return path
}

// sampleEvents is a known set spanning each decision type and two agents.
func sampleEvents() []audit.Event {
	return []audit.Event{
		{Agent: "kit", Tool: "Read", Decision: "allow"},
		{Agent: "kit", Tool: "Bash", Decision: "deny", Reason: "secret-exfil"},
		{Agent: "ash", Tool: "WebFetch", Decision: "block", Reason: "blocklist"},
		{Agent: "ash", Tool: "Write", Decision: "ratelimit", Reason: "rate"},
		{Agent: "kit", Tool: "nockcc_kill_switch_set", Decision: "approval-granted", Reason: "human ok"},
	}
}

func TestBuildPackCleanTrailAttestsIntact(t *testing.T) {
	path := writeSignedTrail(t, sampleEvents())

	pack, err := BuildPack(PackOptions{
		Framework:  FrameworkSOC2,
		AuditFiles: []string{path},
		HMACKey:    testHMACKey,
		Now:        fixedNow(),
	})
	if err != nil {
		t.Fatalf("BuildPack: %v", err)
	}
	if !pack.Verification.ChainIntact {
		t.Fatalf("expected ChainIntact=true on a clean trail, got false: %s", pack.Verification.Detail)
	}
	if pack.Verification.Mode != ModeHMAC {
		t.Errorf("Mode = %q, want hmac", pack.Verification.Mode)
	}
	if pack.Verification.EntriesVerified != 5 {
		t.Errorf("EntriesVerified = %d, want 5", pack.Verification.EntriesVerified)
	}
	if len(pack.AllEvents) != 5 {
		t.Errorf("AllEvents = %d, want 5", len(pack.AllEvents))
	}
	if pack.Framework != FrameworkSOC2 || pack.FrameworkName == "" {
		t.Errorf("framework metadata not populated: %+v / %q", pack.Framework, pack.FrameworkName)
	}
}

func TestBuildPackTamperPropagatesToAttestation(t *testing.T) {
	path := writeSignedTrail(t, sampleEvents())

	// The cover-up an attacker wants: flip a recorded DENY to allow. This breaks
	// the hash chain; the attestation must report ChainIntact=false.
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	tampered := strings.Replace(string(data), `"decision":"deny"`, `"decision":"allow"`, 1)
	if tampered == string(data) {
		t.Fatal("tamper substitution did not match")
	}
	if err := os.WriteFile(path, []byte(tampered), 0o644); err != nil {
		t.Fatal(err)
	}

	pack, err := BuildPack(PackOptions{
		Framework:  FrameworkSOC2,
		AuditFiles: []string{path},
		HMACKey:    testHMACKey,
		Now:        fixedNow(),
	})
	// Hardened failure path: a broken chain is NOT a BuildPack error — the pack
	// is produced so the reviewer SEES the failure rendered loud.
	if err != nil {
		t.Fatalf("BuildPack over tampered trail should still produce a pack, got error: %v", err)
	}
	if pack.Verification.ChainIntact {
		t.Fatal("expected ChainIntact=false on a tampered trail, got true — the attestation FAILED to fail loud")
	}
	if pack.Verification.Detail == "" {
		t.Error("expected a failure Detail on a broken chain")
	}
	if len(pack.Verification.FileResults) != 1 || pack.Verification.FileResults[0].Intact {
		t.Errorf("per-file result should report the break: %+v", pack.Verification.FileResults)
	}
}

func TestBuildPackEd25519TamperPropagates(t *testing.T) {
	pub, priv, _ := ed25519.GenerateKey(nil)
	path := filepath.Join(t.TempDir(), "audit.jsonl")
	a, err := audit.New(path, audit.WithEd25519Key(priv))
	if err != nil {
		t.Fatal(err)
	}
	for _, ev := range sampleEvents() {
		if err := a.Record(ev); err != nil {
			t.Fatal(err)
		}
	}
	a.Close()

	// Tamper, then build with the Ed25519 public key.
	data, _ := os.ReadFile(path)
	tampered := strings.Replace(string(data), `"tool":"Bash"`, `"tool":"Read"`, 1)
	if err := os.WriteFile(path, []byte(tampered), 0o644); err != nil {
		t.Fatal(err)
	}

	pack, err := BuildPack(PackOptions{
		Framework:     FrameworkSOC2,
		AuditFiles:    []string{path},
		Ed25519PubHex: hex.EncodeToString(pub),
		Now:           fixedNow(),
	})
	if err != nil {
		t.Fatalf("BuildPack (ed25519): %v", err)
	}
	if pack.Verification.Mode != ModeEd25519 {
		t.Errorf("Mode = %q, want ed25519", pack.Verification.Mode)
	}
	if pack.Verification.PubKeyHex != hex.EncodeToString(pub) {
		t.Errorf("PubKeyHex not recorded in attestation")
	}
	if pack.Verification.ChainIntact {
		t.Fatal("expected ChainIntact=false on a tampered Ed25519 trail, got true")
	}
}

func TestBuildPackCleanEd25519Verifies(t *testing.T) {
	pub, priv, _ := ed25519.GenerateKey(nil)
	path := filepath.Join(t.TempDir(), "audit.jsonl")
	a, _ := audit.New(path, audit.WithEd25519Key(priv))
	for _, ev := range sampleEvents() {
		_ = a.Record(ev)
	}
	a.Close()

	pack, err := BuildPack(PackOptions{
		Framework:     FrameworkSOC2,
		AuditFiles:    []string{path},
		Ed25519PubHex: hex.EncodeToString(pub),
		Now:           fixedNow(),
	})
	if err != nil {
		t.Fatalf("BuildPack: %v", err)
	}
	if !pack.Verification.ChainIntact {
		t.Fatalf("clean Ed25519 trail should attest intact: %s", pack.Verification.Detail)
	}
	if pack.Verification.EntriesVerified != 5 {
		t.Errorf("EntriesVerified = %d, want 5", pack.Verification.EntriesVerified)
	}
}

func TestBuildPackControlBucketing(t *testing.T) {
	path := writeSignedTrail(t, sampleEvents())

	pack, err := BuildPack(PackOptions{
		Framework:  FrameworkSOC2,
		AuditFiles: []string{path},
		HMACKey:    testHMACKey,
		Now:        fixedNow(),
	})
	if err != nil {
		t.Fatalf("BuildPack: %v", err)
	}

	got := map[string]int{}
	for _, ce := range pack.Controls {
		got[ce.Control.ID] = len(ce.Events)
	}
	// CC6.1 = deny|block|approval-granted|approval-denied -> deny, block, approval-granted = 3
	if got["CC6.1"] != 3 {
		t.Errorf("CC6.1 bucket = %d, want 3 (deny, block, approval-granted)", got["CC6.1"])
	}
	// CC7.2 = monitoring completeness (match-any) -> all 5
	if got["CC7.2"] != 5 {
		t.Errorf("CC7.2 bucket = %d, want 5 (all entries)", got["CC7.2"])
	}
	// CC8.1 = ratelimit|hide|approval-granted|approval-denied -> ratelimit, approval-granted = 2
	if got["CC8.1"] != 2 {
		t.Errorf("CC8.1 bucket = %d, want 2 (ratelimit, approval-granted)", got["CC8.1"])
	}
}

func TestBuildPackAgentFilter(t *testing.T) {
	path := writeSignedTrail(t, sampleEvents())

	pack, err := BuildPack(PackOptions{
		Framework:  FrameworkSOC2,
		AuditFiles: []string{path},
		HMACKey:    testHMACKey,
		Agent:      "ash",
		Now:        fixedNow(),
	})
	if err != nil {
		t.Fatalf("BuildPack: %v", err)
	}
	// ash has 2 events (block, ratelimit). The chain still verifies over the
	// whole file — filtering is a view, not a re-verification.
	if len(pack.AllEvents) != 2 {
		t.Errorf("AllEvents (agent=ash) = %d, want 2", len(pack.AllEvents))
	}
	for _, ev := range pack.AllEvents {
		if ev.Agent != "ash" {
			t.Errorf("agent filter leaked a %q event", ev.Agent)
		}
	}
	if len(pack.Agents) != 1 || pack.Agents[0] != "ash" {
		t.Errorf("Agents = %v, want [ash]", pack.Agents)
	}
	if !pack.Verification.ChainIntact {
		t.Error("filtering must not affect chain verification")
	}
}

func TestBuildPackDateFilter(t *testing.T) {
	// Three entries with explicit, increasing timestamps. We can't set the
	// recorded ts directly through the public Auditor, so write a signed trail
	// then assert the filter math against a window that excludes the boundaries.
	path := writeSignedTrail(t, sampleEvents())

	// All entries are stamped at the same instant (fixed run time); pick a
	// window strictly AFTER it and confirm everything is filtered out — proving
	// the To bound excludes. Then a window around it keeps all.
	entries, err := readEntries(path)
	if err != nil {
		t.Fatal(err)
	}
	ts, err := time.Parse(time.RFC3339, entries[0].Time)
	if err != nil {
		t.Fatalf("entry ts not RFC3339: %q", entries[0].Time)
	}

	// Window entirely after the entries -> zero kept.
	after, err := BuildPack(PackOptions{
		Framework:  FrameworkSOC2,
		AuditFiles: []string{path},
		HMACKey:    testHMACKey,
		From:       ts.Add(time.Hour),
		Now:        fixedNow(),
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(after.AllEvents) != 0 {
		t.Errorf("From=ts+1h should exclude all entries, kept %d", len(after.AllEvents))
	}

	// Window straddling the entries -> all kept.
	around, err := BuildPack(PackOptions{
		Framework:  FrameworkSOC2,
		AuditFiles: []string{path},
		HMACKey:    testHMACKey,
		From:       ts.Add(-time.Hour),
		To:         ts.Add(time.Hour),
		Now:        fixedNow(),
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(around.AllEvents) != len(entries) {
		t.Errorf("straddling window should keep all %d entries, kept %d", len(entries), len(around.AllEvents))
	}
	if around.From == "" || around.To == "" {
		t.Error("From/To should be recorded in the pack metadata when set")
	}
}

func TestBuildPackMultiFileBreakIsNotMasked(t *testing.T) {
	good := writeSignedTrail(t, sampleEvents()[:2])
	bad := writeSignedTrail(t, sampleEvents()[2:])

	// Break the second file only.
	data, _ := os.ReadFile(bad)
	tampered := strings.Replace(string(data), `"decision":"block"`, `"decision":"allow"`, 1)
	if err := os.WriteFile(bad, []byte(tampered), 0o644); err != nil {
		t.Fatal(err)
	}

	pack, err := BuildPack(PackOptions{
		Framework:  FrameworkSOC2,
		AuditFiles: []string{good, bad},
		HMACKey:    testHMACKey,
		Now:        fixedNow(),
	})
	if err != nil {
		t.Fatalf("BuildPack: %v", err)
	}
	// One good file must NOT mask the other's break.
	if pack.Verification.ChainIntact {
		t.Fatal("a broken file among good ones must flip ChainIntact=false")
	}
	if len(pack.Verification.FileResults) != 2 {
		t.Fatalf("expected 2 file results, got %d", len(pack.Verification.FileResults))
	}
	if !pack.Verification.FileResults[0].Intact {
		t.Error("the clean file should report intact")
	}
	if pack.Verification.FileResults[1].Intact {
		t.Error("the tampered file should report broken")
	}
}

func TestBuildPackSetupErrors(t *testing.T) {
	path := writeSignedTrail(t, sampleEvents())

	tests := []struct {
		name string
		opts PackOptions
	}{
		{"unknown framework", PackOptions{Framework: "nope", AuditFiles: []string{path}, HMACKey: testHMACKey}},
		{"no files", PackOptions{Framework: FrameworkSOC2, HMACKey: testHMACKey}},
		{"no key", PackOptions{Framework: FrameworkSOC2, AuditFiles: []string{path}}},
		{"both keys", PackOptions{Framework: FrameworkSOC2, AuditFiles: []string{path}, HMACKey: testHMACKey, Ed25519PubHex: "deadbeef"}},
		{"bad ed25519 hex", PackOptions{Framework: FrameworkSOC2, AuditFiles: []string{path}, Ed25519PubHex: "not-hex"}},
		{"missing file", PackOptions{Framework: FrameworkSOC2, AuditFiles: []string{filepath.Join(t.TempDir(), "nope.jsonl")}, HMACKey: testHMACKey}},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if _, err := BuildPack(tc.opts); err == nil {
				t.Fatalf("expected a setup error for %q, got nil", tc.name)
			}
		})
	}
}

func TestBuildPackStubFrameworkNoControls(t *testing.T) {
	path := writeSignedTrail(t, sampleEvents())
	pack, err := BuildPack(PackOptions{
		Framework:  FrameworkGDPR,
		AuditFiles: []string{path},
		HMACKey:    testHMACKey,
		Now:        fixedNow(),
	})
	if err != nil {
		t.Fatalf("BuildPack (gdpr stub): %v", err)
	}
	if len(pack.Controls) != 0 {
		t.Errorf("GDPR stub should have 0 controls, got %d", len(pack.Controls))
	}
	// A stub still produces a verified attestation and the raw appendix.
	if !pack.Verification.ChainIntact {
		t.Error("stub framework should still attest the chain")
	}
	if len(pack.AllEvents) != 5 {
		t.Errorf("stub should still carry the raw appendix, got %d events", len(pack.AllEvents))
	}
}

func TestKnownFramework(t *testing.T) {
	for _, f := range []Framework{FrameworkSOC2, FrameworkGDPR, FrameworkPCI, FrameworkHIPAA} {
		if !KnownFramework(f) {
			t.Errorf("%q should be known", f)
		}
	}
	if KnownFramework("bogus") {
		t.Error("bogus framework should not be known")
	}
}
