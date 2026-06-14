package main

import (
	"bytes"
	"log"
	"os"
	"strings"
	"testing"
	"time"
)

func TestBrokerUnregisterDoesNotDependOnBackgroundRunLoop(t *testing.T) {
	b := newBroker()
	c := make(chan event, 1)

	b.register(c)
	b.unregister(c)

	select {
	case _, ok := <-c:
		if ok {
			t.Fatal("client channel remains open after unregister")
		}
	case <-time.After(100 * time.Millisecond):
		t.Fatal("unregister did not close client channel")
	}
}

func TestReplayHistoryLogsScannerErrors(t *testing.T) {
	f, err := os.CreateTemp(t.TempDir(), "audit-*.jsonl")
	if err != nil {
		t.Fatal(err)
	}
	longLine := strings.Repeat("x", 1024*1024+1)
	if _, err := f.WriteString(longLine + "\n"); err != nil {
		t.Fatal(err)
	}
	if err := f.Close(); err != nil {
		t.Fatal(err)
	}

	var logs bytes.Buffer
	previousWriter := log.Writer()
	log.SetOutput(&logs)
	t.Cleanup(func() { log.SetOutput(previousWriter) })

	replayHistory(f.Name(), &bytes.Buffer{})

	if !strings.Contains(logs.String(), "error replaying history") {
		t.Fatalf("expected scanner error log, got %q", logs.String())
	}
}
