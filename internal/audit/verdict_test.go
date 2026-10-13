package audit

import (
	"crypto/ed25519"
	"os"
	"path/filepath"
	"testing"
)

func TestClassifyTrail(t *testing.T) {
	tests := []struct {
		name   string
		result VerificationResult
		want   TrailVerdict
	}{
		{name: "empty", result: VerificationResult{}, want: TrailNoRows},
		{name: "missing checkpoint", result: VerificationResult{EntriesVerified: 21}, want: TrailUnanchored},
		{name: "checkpoint behind tail", result: VerificationResult{EntriesVerified: 21, CheckpointCount: 19, CheckpointPresent: true}, want: TrailUnanchored},
		{name: "checkpoint ahead of trail", result: VerificationResult{EntriesVerified: 19, CheckpointCount: 21, CheckpointPresent: true}, want: TrailTampered},
		{name: "fully checkpointed", result: VerificationResult{EntriesVerified: 21, CheckpointCount: 21, CheckpointPresent: true}, want: TrailProtected},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := ClassifyTrail(tt.result); got != tt.want {
				t.Fatalf("ClassifyTrail(%+v) = %q, want %q", tt.result, got, tt.want)
			}
		})
	}
}

func TestVerifyEd25519ReportClassifiesEmptyPartialAndCompleteTrails(t *testing.T) {
	pub, priv, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatal(err)
	}

	newTrail := func(t *testing.T, rows int, checkpointAt int) string {
		t.Helper()
		path := filepath.Join(t.TempDir(), "agent.audit.jsonl")
		a, err := New(path, WithEd25519Key(priv))
		if err != nil {
			t.Fatalf("New: %v", err)
		}
		var olderCheckpoint []byte
		for i := 0; i < rows; i++ {
			if err := a.Record(Event{Agent: "agent", Tool: "Read", Decision: "allow"}); err != nil {
				t.Fatalf("Record row %d: %v", i+1, err)
			}
			if i+1 == checkpointAt {
				olderCheckpoint, err = os.ReadFile(path + hwmSuffix)
				if err != nil {
					t.Fatalf("read checkpoint at row %d: %v", i+1, err)
				}
			}
		}
		if err := a.Close(); err != nil {
			t.Fatalf("Close: %v", err)
		}
		if checkpointAt > 0 && checkpointAt < rows {
			if err := os.WriteFile(path+hwmSuffix, olderCheckpoint, 0o600); err != nil {
				t.Fatalf("restore older checkpoint: %v", err)
			}
		}
		return path
	}

	t.Run("empty trail is not protected", func(t *testing.T) {
		path := newTrail(t, 0, 0)
		result, err := VerifyEd25519Report(path, pub)
		if err != nil {
			t.Fatalf("VerifyEd25519Report: %v", err)
		}
		if result.EntriesVerified != 0 || ClassifyTrail(result) != TrailNoRows {
			t.Fatalf("empty verification = %+v, verdict %s; want NO_ROWS", result, ClassifyTrail(result))
		}
	})

	t.Run("valid prefix checkpoint leaves verified suffix unanchored", func(t *testing.T) {
		path := newTrail(t, 21, 19)
		result, err := VerifyEd25519Report(path, pub)
		if err != nil {
			t.Fatalf("VerifyEd25519Report: %v", err)
		}
		if result.EntriesVerified != 21 || result.CheckpointCount != 19 || !result.CheckpointPresent {
			t.Fatalf("verification metadata = %+v, want 21 entries and checkpoint 19", result)
		}
		if got := ClassifyTrail(result); got != TrailUnanchored {
			t.Fatalf("verdict = %s, want UNANCHORED", got)
		}
		// Negative control: the low-level verifier intentionally accepts this
		// valid signed prefix and reports all 21 verified rows for writer recovery.
		if n, err := VerifyEd25519(path, pub); err != nil || n != 21 {
			t.Fatalf("VerifyEd25519() = (%d, %v), want (21, nil); prefix semantics changed", n, err)
		}
	})

	t.Run("fully checkpointed trail is protected", func(t *testing.T) {
		path := newTrail(t, 21, 0)
		result, err := VerifyEd25519Report(path, pub)
		if err != nil {
			t.Fatalf("VerifyEd25519Report: %v", err)
		}
		if result.EntriesVerified != 21 || result.CheckpointCount != 21 || ClassifyTrail(result) != TrailProtected {
			t.Fatalf("full verification = %+v, verdict %s; want PROTECTED", result, ClassifyTrail(result))
		}
	})
}
