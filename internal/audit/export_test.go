package audit

import (
	"crypto/ed25519"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestExportProofWindowAndSeverity(t *testing.T) {
	pub, priv, _ := ed25519.GenerateKey(nil)
	path := filepath.Join(t.TempDir(), "audit.jsonl")
	a, err := New(path, WithEd25519Key(priv))
	if err != nil {
		t.Fatal(err)
	}
	now := time.Date(2026, 10, 7, 12, 0, 0, 0, time.UTC)
	a.clock = func() time.Time { current := now; now = now.Add(time.Second); return current }
	for _, decision := range []string{"allow", "allow", "block", "deny", "allow", "allow"} {
		ev := Event{Agent: "probe", Tool: decision, Decision: decision}
		if decision == "block" {
			ev.Reason = "secret-exfil"
		}
		if err := a.Record(ev); err != nil {
			t.Fatal(err)
		}
	}
	if err := a.Close(); err != nil {
		t.Fatal(err)
	}
	trail, _ := os.ReadFile(path)
	head, _ := os.ReadFile(path + ".hwm")
	proof, err := MakeExportProof(trail, head, pub, priv, ExportFilters{Since: "2026-10-07T12:00:02Z", Until: "2026-10-07T12:00:03Z"})
	if err != nil {
		t.Fatal(err)
	}
	if n, complete, err := VerifyExport(proof, pub, "probe"); err != nil || n != 2 || !complete {
		t.Fatalf("untouched window: n=%d complete=%v err=%v", n, complete, err)
	}
	if _, _, err := VerifyExport(proof, pub, "other"); err == nil {
		t.Fatal("wrong agent passed")
	}
	var p ExportProof
	if err := json.Unmarshal(proof, &p); err != nil {
		t.Fatal(err)
	}
	if len(p.Rows) != 2 {
		t.Fatalf("proof rows = %d, want only the two selected rows", len(p.Rows))
	}
	tampered := p
	tampered.Rows = append([]ExportRow(nil), p.Rows...)
	tampered.Rows[0].Raw = strings.Replace(tampered.Rows[0].Raw, `"decision":"block"`, `"decision":"allow"`, 1)
	bad, _ := json.Marshal(tampered)
	if _, _, err := VerifyExport(bad, pub, ""); err == nil {
		t.Fatal("tampered row passed")
	}
	deleted := p
	deleted.Rows = append([]ExportRow(nil), p.Rows[:1]...)
	bad, _ = json.Marshal(deleted)
	if _, _, err := VerifyExport(bad, pub, ""); err == nil {
		t.Fatal("deleted interior row passed")
	}
	narrowed := p
	narrowed.Filters.Since = "2026-10-07T12:00:03Z"
	bad, _ = json.Marshal(narrowed)
	if _, _, err := VerifyExport(bad, pub, ""); err == nil {
		t.Fatal("changed receipt scope passed")
	}
	all, err := MakeExportProof(trail, head, pub, priv, ExportFilters{})
	if err != nil {
		t.Fatal(err)
	}
	if n, complete, err := VerifyExport(all, pub, "probe"); err != nil || n != 6 || !complete {
		t.Fatalf("full trail: n=%d complete=%v err=%v", n, complete, err)
	}
	if err := json.Unmarshal(all, &p); err != nil {
		t.Fatal(err)
	}
	p.Rows = p.Rows[1:]
	p.ReceiptSig = hex.EncodeToString(ed25519.Sign(priv, p.receiptMessage()))
	bad, _ = json.Marshal(p)
	if _, _, err := VerifyExport(bad, pub, ""); err == nil {
		t.Fatal("signed complete trail missing its first row passed")
	}
	severity, err := MakeExportProof(trail, head, pub, priv, ExportFilters{Severity: "none"})
	if err != nil {
		t.Fatal(err)
	}
	if n, complete, err := VerifyExport(severity, pub, ""); err != nil || n != 4 || complete {
		t.Fatalf("severity: n=%d complete=%v err=%v", n, complete, err)
	}
	a, err = New(path, WithEd25519Key(priv))
	if err != nil {
		t.Fatal(err)
	}
	a.clock = func() time.Time { return time.Date(2026, 10, 7, 12, 0, 6, 0, time.UTC) }
	if err := a.Record(Event{Agent: "probe", Tool: "late", Decision: "allow"}); err != nil {
		t.Fatal(err)
	}
	if err := a.Close(); err != nil {
		t.Fatal(err)
	}
	appended, _ := os.ReadFile(path)
	broader := ExportFilters{Since: "2026-10-07T12:00:02Z", Until: "2026-10-07T12:00:06Z"}
	if _, err := MakeExportProof(appended, head, pub, priv, broader); err == nil {
		t.Fatal("stale checkpoint hid an in-window row")
	}
	newHead, _ := os.ReadFile(path + ".hwm")
	proof, err = MakeExportProof(appended, newHead, pub, priv, broader)
	if err != nil {
		t.Fatalf("fresh checkpoint: %v", err)
	}
	if n, _, err := VerifyExport(proof, pub, "probe"); err != nil || n != 5 {
		t.Fatalf("checkpoint snapshot: n=%d err=%v", n, err)
	}
}

func TestExportProofTimeRegression(t *testing.T) {
	cases := []struct {
		name     string
		times    []string
		filters  ExportFilters
		complete bool
	}{
		{"earlier jump", []string{"12:00:02", "12:00:00", "12:00:03", "12:00:04"}, ExportFilters{Since: "2026-10-07T12:00:03Z", Until: "2026-10-07T12:00:04Z"}, true},
		{"gap inside window", []string{"12:00:00", "12:00:02", "12:00:01", "12:00:03"}, ExportFilters{Since: "2026-10-07T12:00:02Z", Until: "2026-10-07T12:00:03Z"}, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			pub, priv, _ := ed25519.GenerateKey(nil)
			path := filepath.Join(t.TempDir(), "audit.jsonl")
			a, err := New(path, WithEd25519Key(priv))
			if err != nil {
				t.Fatal(err)
			}
			i := 0
			a.clock = func() time.Time { v, _ := time.Parse(time.RFC3339, "2026-10-07T"+tc.times[i]+"Z"); i++; return v }
			for range tc.times {
				if err := a.Record(Event{Agent: "probe", Tool: "Read", Decision: "allow"}); err != nil {
					t.Fatal(err)
				}
			}
			if err := a.Close(); err != nil {
				t.Fatal(err)
			}
			trail, _ := os.ReadFile(path)
			head, _ := os.ReadFile(path + ".hwm")
			proof, err := MakeExportProof(trail, head, pub, priv, tc.filters)
			if !tc.complete {
				if err == nil {
					t.Fatal("noncontiguous time window passed")
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			if n, complete, err := VerifyExport(proof, pub, "probe"); err != nil || n != 2 || !complete {
				t.Fatalf("contiguous window: n=%d complete=%v err=%v", n, complete, err)
			}
		})
	}
}
