package gateway

import (
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"
)

type jsonInitializeWriter struct {
	*httptest.ResponseRecorder
	afterWrite func()
}

func (w *jsonInitializeWriter) Write(p []byte) (int, error) {
	n, err := w.ResponseRecorder.Write(p)
	if w.afterWrite != nil {
		callback := w.afterWrite
		w.afterWrite = nil
		callback()
	}
	return n, err
}

// The recorder schedule checks that the session is ready before Write returns.
func TestGatewayJSONInitializeFollowupAtWrite(t *testing.T) {
	c := testConfig(t)
	g := newTestGateway(t, c, validAuth(t, c), func() http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Content-Type", "application/json")
			if r.Header.Get("Mcp-Session-Id") != "" {
				fmt.Fprint(w, `{"jsonrpc":"2.0","id":2,"result":{"tools":[]}}`)
				return
			}
			w.Header().Set("Mcp-Session-Id", "private-upstream-session")
			fmt.Fprintf(w, `{"jsonrpc":"2.0","id":1,"result":{"padding":"%s"}}`, strings.Repeat("x", 8192))
		})
	})
	w := &jsonInitializeWriter{ResponseRecorder: httptest.NewRecorder()}
	observed := false
	w.afterWrite = func() {
		observed = true
		sid := w.Header().Get("Mcp-Session-Id")
		if sid == "" {
			t.Fatal("initialize result exposed without session id")
		}
		if got := request(g, list, sid, nil).Code; got != http.StatusOK {
			t.Errorf("follow-up after JSON initialization bytes got %d, want 200", got)
		}
	}
	r := httptest.NewRequest(http.MethodPost, "https://guard.example/mcp", strings.NewReader(initialize))
	r.Header.Set("Authorization", "Bearer connector-test-token")
	g.ServeHTTP(w, r)
	if !observed {
		t.Fatal("response never written")
	}
}

type jsonInitializeWriteBarrier struct {
	http.ResponseWriter
	arrived chan struct{}
	release chan struct{}
	once    sync.Once
}

func (w *jsonInitializeWriteBarrier) Write(p []byte) (int, error) {
	n, err := w.ResponseWriter.Write(p)
	if n > 0 {
		w.once.Do(func() {
			if err := http.NewResponseController(w.ResponseWriter).Flush(); err != nil {
				panic(err)
			}
			close(w.arrived)
			<-w.release
		})
	}
	return n, err
}

func (w *jsonInitializeWriteBarrier) Unwrap() http.ResponseWriter { return w.ResponseWriter }

func TestGatewayJSONInitializeFollowupOverHTTP(t *testing.T) {
	c := testConfig(t)
	upstreamID := "private-upstream-session"
	var upstreamMu sync.Mutex
	var gotUpstreamID string
	g := newTestGateway(t, c, validAuth(t, c), func() http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Content-Type", "application/json")
			if r.Header.Get("Mcp-Session-Id") != "" {
				upstreamMu.Lock()
				gotUpstreamID = r.Header.Get("Mcp-Session-Id")
				upstreamMu.Unlock()
				fmt.Fprint(w, `{"jsonrpc":"2.0","id":2,"result":{"tools":[]}}`)
				return
			}
			w.Header().Set("Mcp-Session-Id", upstreamID)
			fmt.Fprintf(w, `{"jsonrpc":"2.0","id":1,"result":{"padding":"%s"}}`, strings.Repeat("x", 8192))
		})
	})

	arrived, release := make(chan struct{}), make(chan struct{})
	var releaseOnce sync.Once
	releaseWrite := func() { releaseOnce.Do(func() { close(release) }) }
	initialHandlerReturned := make(chan struct{})
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Mcp-Session-Id") != "" {
			g.ServeHTTP(w, r)
			return
		}
		defer close(initialHandlerReturned)
		bw := &jsonInitializeWriteBarrier{ResponseWriter: w, arrived: arrived, release: release}
		g.ServeHTTP(bw, r)
	}))
	defer func() {
		releaseWrite()
		server.Close()
	}()
	client := &http.Client{Timeout: 3 * time.Second}
	initReq, err := http.NewRequest(http.MethodPost, server.URL+"/mcp", strings.NewReader(initialize))
	if err != nil {
		t.Fatal(err)
	}
	initReq.Host = "guard.example"
	initReq.Header.Set("Authorization", "Bearer connector-test-token")
	initDone := make(chan struct{})
	var initResp *http.Response
	go func() {
		defer close(initDone)
		initResp, err = client.Do(initReq)
	}()

	select {
	case <-arrived:
	case <-time.After(3 * time.Second):
		t.Fatal("initialize response bytes did not reach the HTTP writer")
	}
	select {
	case <-initDone:
	case <-time.After(3 * time.Second):
		t.Fatal("HTTP client did not receive the flushed initialize headers")
	}
	if initResp == nil {
		t.Fatal("initialize request failed before producing a response")
	}
	sid := initResp.Header.Get("Mcp-Session-Id")
	if sid == "" || initResp.StatusCode != http.StatusOK {
		t.Fatalf("initialize returned status %d and session %q", initResp.StatusCode, sid)
	}
	// Read the complete JSON result while the server is deliberately paused
	// inside ResponseWriter.Write, before finalize() can resume.
	expected := fmt.Sprintf(`{"jsonrpc":"2.0","id":1,"result":{"padding":"%s"}}`, strings.Repeat("x", 8192))
	body := make([]byte, len(expected))
	if _, err := io.ReadFull(initResp.Body, body); err != nil {
		t.Fatalf("read flushed initialize body: %v", err)
	}
	_ = initResp.Body.Close()
	if string(body) != expected {
		t.Fatal("initialize body did not match the validated response")
	}

	followReq, err := http.NewRequest(http.MethodPost, server.URL+"/mcp", strings.NewReader(list))
	if err != nil {
		t.Fatal(err)
	}
	followReq.Host = "guard.example"
	followReq.Header.Set("Authorization", "Bearer connector-test-token")
	followReq.Header.Set("Mcp-Session-Id", sid)
	followResp, err := client.Do(followReq)
	if err != nil {
		t.Fatal(err)
	}
	if followResp.StatusCode != http.StatusOK {
		t.Fatalf("follow-up before initialize handler resumed got %d, want 200", followResp.StatusCode)
	}
	followBody, err := io.ReadAll(followResp.Body)
	if err != nil {
		t.Fatalf("read immediate follow-up result: %v", err)
	}
	_ = followResp.Body.Close()
	if string(followBody) != `{"jsonrpc":"2.0","id":2,"result":{"tools":[]}}` {
		t.Fatalf("immediate follow-up returned %q", followBody)
	}
	upstreamMu.Lock()
	gotImmediateUpstreamID := gotUpstreamID
	upstreamMu.Unlock()
	if gotImmediateUpstreamID != upstreamID {
		t.Fatalf("immediate follow-up used upstream session %q, want %q", gotImmediateUpstreamID, upstreamID)
	}
	releaseWrite()
	select {
	case <-initialHandlerReturned:
	case <-time.After(3 * time.Second):
		t.Fatal("initialize handler did not return after releasing the write barrier")
	}

	// A request after the first handler returns must also work, and must carry
	// the upstream's private session ID through the existing forwarding path.
	postReq, err := http.NewRequest(http.MethodPost, server.URL+"/mcp", strings.NewReader(list))
	if err != nil {
		t.Fatal(err)
	}
	postReq.Host = "guard.example"
	postReq.Header.Set("Authorization", "Bearer connector-test-token")
	postReq.Header.Set("Mcp-Session-Id", sid)
	postResp, err := client.Do(postReq)
	if err != nil {
		t.Fatal(err)
	}
	_ = postResp.Body.Close()
	upstreamMu.Lock()
	got := gotUpstreamID
	upstreamMu.Unlock()
	if postResp.StatusCode != http.StatusOK || got != upstreamID {
		t.Fatalf("post-return follow-up status=%d upstream session=%q", postResp.StatusCode, got)
	}
}

func TestGatewayInvalidJSONInitializeDoesNotCreateSession(t *testing.T) {
	c := testConfig(t)
	calls := 0
	g := newTestGateway(t, c, validAuth(t, c), func() http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			calls++
			w.Header().Set("Content-Type", "application/json")
			w.Header().Set("Mcp-Session-Id", "must-not-be-installed")
			if calls == 1 {
				fmt.Fprint(w, `{"jsonrpc":"2.0","id":99,"result":{}}`)
				return
			}
			fmt.Fprint(w, `{"jsonrpc":"2.0","id":1,"result":{}}`)
		})
	})

	first := request(g, initialize, "", nil)
	if got := first.Header().Get("Mcp-Session-Id"); got != "" {
		t.Fatalf("invalid initialize exposed gateway session %q", got)
	}
	if len(g.sessions) != 0 {
		t.Fatalf("invalid initialize retained %d gateway sessions", len(g.sessions))
	}
	second := request(g, initialize, "", nil)
	if second.Code != http.StatusOK || second.Header().Get("Mcp-Session-Id") == "" {
		t.Fatalf("valid retry after rejected initialize returned %d without session", second.Code)
	}
}
