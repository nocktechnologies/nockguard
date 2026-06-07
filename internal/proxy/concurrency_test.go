package proxy

import (
	"bytes"
	"encoding/json"
	"fmt"
	"strings"
	"sync"
	"testing"
)

// In-process proof that writeAgentLine serializes concurrent writers. The e2e
// tests run the proxy as a subprocess, so `go test -race` cannot instrument the
// real two-goroutine stdout writes (audit §3#3). This test exercises the
// serialization primitive directly, so the race detector DOES see it: bytes.Buffer
// is not goroutine-safe, so without the mutex this both data-races and interleaves
// JSON-RPC lines; with it, every line is intact and the run is race-clean.
func TestWriteAgentLineSerializesConcurrentWriters(t *testing.T) {
	p := &StdioProxy{}
	var buf bytes.Buffer

	const n = 256
	var wg sync.WaitGroup
	for i := 0; i < n; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			line := []byte(fmt.Sprintf(`{"jsonrpc":"2.0","id":%d,"method":"tools/list"}`, i))
			if err := p.writeAgentLine(&buf, line); err != nil {
				t.Errorf("writeAgentLine: %v", err)
			}
		}(i)
	}
	wg.Wait()

	lines := strings.Split(strings.TrimSpace(buf.String()), "\n")
	if len(lines) != n {
		t.Fatalf("expected %d intact lines, got %d (interleaving?)", n, len(lines))
	}
	for _, l := range lines {
		var m map[string]json.RawMessage
		if err := json.Unmarshal([]byte(l), &m); err != nil {
			t.Errorf("corrupt/interleaved line %q: %v", l, err)
		}
	}
}
