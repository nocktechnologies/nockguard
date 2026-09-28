package audit

import (
	"crypto/ed25519"
	"crypto/rand"
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"testing"
)

func TestRecordRequiredEd25519DurableRoundTrip(t *testing.T) {
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(t.TempDir(), "required.audit.jsonl")
	a, err := New(path, WithEd25519Key(priv))
	if err != nil {
		t.Fatal(err)
	}
	defer a.Close()

	if err := a.RecordRequired(Event{Agent: "worker", Tool: "read", Decision: "allow"}); err != nil {
		t.Fatal(err)
	}
	if err := a.RequiredError(); err != nil {
		t.Fatalf("healthy writer reported an error: %v", err)
	}
	if _, err := os.Stat(path + hwmSuffix); err != nil {
		t.Fatalf("signed checkpoint missing after required record: %v", err)
	}
	if n, err := VerifyEd25519(path, pub); err != nil || n != 1 {
		t.Fatalf("VerifyEd25519() = (%d, %v), want (1, nil)", n, err)
	}
}

func TestRecordRequiredUnavailableAndClosed(t *testing.T) {
	var nilAuditor *Auditor
	if err := nilAuditor.RecordRequired(Event{}); err == nil {
		t.Fatal("RecordRequired on nil auditor succeeded")
	}
	if err := nilAuditor.RequiredError(); err == nil {
		t.Fatal("RequiredError on nil auditor returned nil")
	}
	if err := nilAuditor.Record(Event{}); err != nil {
		t.Fatalf("legacy Record on nil auditor = %v, want nil", err)
	}

	disabled, err := New("")
	if err != nil {
		t.Fatal(err)
	}
	if err := disabled.RecordRequired(Event{}); err == nil {
		t.Fatal("RecordRequired on disabled auditor succeeded")
	}
	if err := disabled.Close(); err != nil {
		t.Fatal(err)
	}
	if err := disabled.RequiredError(); err == nil {
		t.Fatal("RequiredError on closed auditor returned nil")
	}
}

func TestRecordRequiredLatchesCheckpointFailure(t *testing.T) {
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(t.TempDir(), "required.audit.jsonl")
	a, err := New(path, WithEd25519Key(priv))
	if err != nil {
		t.Fatal(err)
	}
	if err := a.RecordRequired(Event{Agent: "worker", Tool: "first", Decision: "allow"}); err != nil {
		t.Fatal(err)
	}

	// The existing checkpoint remains readable, while making the temp path a
	// directory forces the actual sidecar replacement to fail after appending.
	tmpPath := path + hwmSuffix + ".tmp"
	if err := os.Mkdir(tmpPath, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := a.RecordRequired(Event{Agent: "worker", Tool: "second", Decision: "allow"}); err == nil {
		t.Fatal("RecordRequired succeeded despite checkpoint filesystem failure")
	}
	latched := a.RequiredError()
	if latched == nil {
		t.Fatal("checkpoint failure was not latched")
	}
	if err := os.Remove(tmpPath); err != nil {
		t.Fatal(err)
	}
	if err := a.RequiredError(); err == nil {
		t.Fatal("repairing the checkpoint path cleared the latched failure")
	}
	if err := a.RecordRequired(Event{Agent: "worker", Tool: "third", Decision: "allow"}); err == nil {
		t.Fatal("required record succeeded after repair without reopen")
	}
	if err := a.Close(); err != nil {
		t.Fatal(err)
	}

	// Reopen verifies the trail and can resume from its durable, possibly
	// lagging checkpoint. The required writer itself does not self-heal.
	reopened, err := New(path, WithEd25519Key(priv))
	if err != nil {
		t.Fatalf("reopen after repairing checkpoint failure: %v", err)
	}
	defer reopened.Close()
	if err := reopened.RecordRequired(Event{Agent: "worker", Tool: "after-reopen", Decision: "allow"}); err != nil {
		t.Fatal(err)
	}
}

func TestRecordRequiredRejectsReplacedTrailPath(t *testing.T) {
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(t.TempDir(), "required.audit.jsonl")
	a, err := New(path, WithEd25519Key(priv))
	if err != nil {
		t.Fatal(err)
	}
	defer a.Close()

	if err := os.Rename(path, path+".old"); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, nil, 0o644); err != nil {
		t.Fatal(err)
	}
	if err := a.RecordRequired(Event{Agent: "worker", Tool: "replacement", Decision: "allow"}); err == nil {
		t.Fatal("required record accepted a path replacement")
	}
	if err := a.RequiredError(); err == nil {
		t.Fatal("path replacement failure was not latched")
	}
	if info, err := os.Stat(path); err != nil {
		t.Fatal(err)
	} else if info.Size() != 0 {
		t.Fatalf("replacement trail was unexpectedly appended: size %d", info.Size())
	}
}

func TestConcurrentRequiredWritersKeepEd25519Chain(t *testing.T) {
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(t.TempDir(), "required.audit.jsonl")
	a, err := New(path, WithEd25519Key(priv))
	if err != nil {
		t.Fatal(err)
	}
	defer a.Close()

	const writers, perWriter = 8, 12
	var wg sync.WaitGroup
	errCh := make(chan error, writers*perWriter)
	for writer := 0; writer < writers; writer++ {
		wg.Add(1)
		go func(writer int) {
			defer wg.Done()
			for item := 0; item < perWriter; item++ {
				if err := a.RecordRequired(Event{
					Agent: "worker", Tool: fmt.Sprintf("tool-%d-%d", writer, item), Decision: "allow",
				}); err != nil {
					errCh <- err
					return
				}
			}
		}(writer)
	}
	wg.Wait()
	close(errCh)
	for err := range errCh {
		t.Errorf("concurrent required record: %v", err)
	}
	if n, err := VerifyEd25519(path, pub); err != nil || n != writers*perWriter {
		t.Fatalf("VerifyEd25519() = (%d, %v), want (%d, nil)", n, err, writers*perWriter)
	}
}
