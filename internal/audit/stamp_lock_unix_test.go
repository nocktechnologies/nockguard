//go:build unix

package audit

import (
	"crypto/ed25519"
	"errors"
	"os"
	"path/filepath"
	"sync"
	"sync/atomic"
	"syscall"
	"testing"
	"time"
)

// A row's time must be taken while the append flock is held, or a row stamped
// before a reader's snapshot can be appended after it.
func TestRecordStampsTimeUnderAppendLock(t *testing.T) {
	_, priv, _ := ed25519.GenerateKey(nil)
	path := filepath.Join(t.TempDir(), "audit.jsonl")
	a, err := New(path, WithEd25519Key(priv))
	if err != nil {
		t.Fatal(err)
	}
	held := false
	a.clock = func() time.Time {
		f, err := os.Open(path)
		if err != nil {
			t.Fatal(err)
		}
		defer f.Close()
		err = syscall.Flock(int(f.Fd()), syscall.LOCK_EX|syscall.LOCK_NB)
		held = errors.Is(err, syscall.EWOULDBLOCK)
		return time.Unix(0, 0)
	}
	if err := a.Record(Event{Agent: "probe", Tool: "read", Decision: "allow"}); err != nil {
		t.Fatal(err)
	}
	a.Close()
	if !held {
		t.Fatal("event time was stamped without the append flock held")
	}
}

func TestCrossWriterTimesFollowAppendOrder(t *testing.T) {
	_, priv, _ := ed25519.GenerateKey(nil)
	path := filepath.Join(t.TempDir(), "audit.jsonl")
	var tick atomic.Int64
	clock := func() time.Time { return time.Unix(tick.Add(1), 0).UTC() }
	var wg sync.WaitGroup
	for w := 0; w < 2; w++ {
		a, err := New(path, WithEd25519Key(priv))
		if err != nil {
			t.Fatal(err)
		}
		a.clock = clock
		wg.Add(1)
		go func() {
			defer wg.Done()
			defer a.Close()
			for i := 0; i < 50; i++ {
				if err := a.Record(Event{Agent: "probe", Tool: "read", Decision: "allow"}); err != nil {
					t.Error(err)
					return
				}
			}
		}()
	}
	wg.Wait()
	prev := ""
	for i, line := range readLines(t, path) {
		ts, _ := line["time"].(string)
		if ts < prev {
			t.Fatalf("row %d time %s precedes earlier row %s", i, ts, prev)
		}
		prev = ts
	}
}
