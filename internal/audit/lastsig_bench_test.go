package audit

import (
	"os"
	"path/filepath"
	"testing"
)

// TestLastSigLargeTrailChains verifies that a large pre-existing signed trail
// still chains correctly when a new entry is appended (N8130 regression guard).
// This exercises the seek-from-end path under realistic chain depths.
func TestLastSigLargeTrailChains(t *testing.T) {
	const n = 500
	path := filepath.Join(t.TempDir(), "large.jsonl")

	evs := make([]Event, n)
	for i := range evs {
		evs[i] = Event{Agent: "kit", Tool: "nockcc_nock_list", Decision: "allow"}
	}
	recordAll(t, path, signKey, evs)

	// Append one more entry and verify the full chain end-to-end.
	a, err := New(path, WithSigningKey(signKey))
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	if err := a.Record(Event{Agent: "ash", Tool: "Bash", Decision: "deny"}); err != nil {
		t.Fatalf("Record extra entry: %v", err)
	}
	if err := a.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}

	count, err := Verify(path, signKey)
	if err != nil {
		t.Fatalf("Verify failed after large trail append: %v", err)
	}
	if count != n+1 {
		t.Errorf("Verify count = %d, want %d", count, n+1)
	}
}

// BenchmarkLastSigSeek measures the seek-from-end path on a trail of varying
// lengths to confirm O(1) behaviour relative to trail size.
func BenchmarkLastSigSeek(b *testing.B) {
	for _, n := range []int{10, 100, 1000, 10000} {
		n := n
		b.Run("entries="+itoa(n), func(b *testing.B) {
			path := filepath.Join(b.TempDir(), "audit.jsonl")
			evs := make([]Event, n)
			for i := range evs {
				evs[i] = Event{Agent: "kit", Tool: "nockcc_nock_list", Decision: "allow"}
			}
			a, err := New(path, WithSigningKey(signKey))
			if err != nil {
				b.Fatalf("New: %v", err)
			}
			for _, ev := range evs {
				if err := a.Record(ev); err != nil {
					b.Fatalf("Record: %v", err)
				}
			}
			_ = a.Close()

			b.ResetTimer()
			for i := 0; i < b.N; i++ {
				f, err := os.Open(path)
				if err != nil {
					b.Fatalf("Open: %v", err)
				}
				if _, err := lastSigSeek(f); err != nil {
					b.Fatalf("lastSigSeek: %v", err)
				}
				f.Close()
			}
		})
	}
}

func itoa(n int) string {
	if n == 0 {
		return "0"
	}
	buf := [20]byte{}
	pos := len(buf)
	for n > 0 {
		pos--
		buf[pos] = byte('0' + n%10)
		n /= 10
	}
	return string(buf[pos:])
}
