package approval

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func TestTelegramPromptSummarizesMCPArguments(t *testing.T) {
	prompt := make(chan string, 1)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if err := r.ParseForm(); err != nil {
			t.Error(err)
		}
		prompt <- r.Form.Get("text")
		http.Error(w, "test stops before polling", http.StatusServiceUnavailable)
	}))
	defer srv.Close()
	v := newTestApprover(srv.URL, time.Second).Ask(Request{
		Agent: "kit", Tool: "spend",
		Params: json.RawMessage(`{"name":"spend","_meta":{"private":"envelope-secret"},"arguments":{"amount":5000,"currency":"usd","target":"prod-fleet","api_key":"hidden-value","config":{"password":"nested-secret"}}}`),
	})
	if v.Approved {
		t.Fatal("failed send must deny")
	}
	got := <-prompt
	for _, want := range []string{"amount: 5000", `currency: "usd"`, `target: "prod-fleet"`, "api_key: [redacted]", "config: {…}"} {
		if !strings.Contains(got, want) {
			t.Errorf("missing %q from prompt: %s", want, got)
		}
	}
	for _, secret := range []string{"hidden-value", "nested-secret", "envelope-secret"} {
		if strings.Contains(got, secret) {
			t.Error("prompt exposed secret")
		}
	}
}

func TestTelegramPromptSummarizesBareArguments(t *testing.T) {
	// Params here is the arguments object itself, no MCP envelope wrapper —
	// another non-envelope shape the fallback must handle.
	prompt := make(chan string, 1)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if err := r.ParseForm(); err != nil {
			t.Error(err)
		}
		prompt <- r.Form.Get("text")
		http.Error(w, "test stops before polling", http.StatusServiceUnavailable)
	}))
	defer srv.Close()
	v := newTestApprover(srv.URL, time.Second).Ask(Request{
		Agent: "kit", Tool: "spend",
		Params: json.RawMessage(`{"amount":5000,"currency":"usd","api_key":"hidden-value"}`),
	})
	if v.Approved {
		t.Fatal("failed send must deny")
	}
	got := <-prompt
	for _, want := range []string{"amount: 5000", `currency: "usd"`, "api_key: [redacted]"} {
		if !strings.Contains(got, want) {
			t.Errorf("missing %q from prompt: %s", want, got)
		}
	}
	if strings.Contains(got, "hidden-value") {
		t.Error("prompt exposed secret")
	}
}

func TestTelegramPromptFallsBackWithoutArgumentsEnvelope(t *testing.T) {
	// This mirrors what decideToolCall's fail-closed "unextractable-name" path
	// hands to Ask: the WHOLE JSON-RPC line, which has no top-level
	// "arguments" field at all — only params.arguments, nested one level too
	// deep for the envelope decode to find.
	prompt := make(chan string, 1)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if err := r.ParseForm(); err != nil {
			t.Error(err)
		}
		prompt <- r.Form.Get("text")
		http.Error(w, "test stops before polling", http.StatusServiceUnavailable)
	}))
	defer srv.Close()
	v := newTestApprover(srv.URL, time.Second).Ask(Request{
		Agent: "kit", Tool: "",
		Params: json.RawMessage(`{"jsonrpc":"2.0","id":7,"method":"tools/call","params":{"name":"","arguments":{"amount":5,"api_key":"hidden-value"}}}`),
	})
	if v.Approved {
		t.Fatal("failed send must deny")
	}
	got := <-prompt
	if !strings.Contains(got, "Args:") {
		t.Fatalf("expected a params summary, prompt was argument-free: %s", got)
	}
	for _, want := range []string{"method", `"tools/call"`} {
		if !strings.Contains(got, want) {
			t.Errorf("missing %q from top-level fallback summary: %s", want, got)
		}
	}
	if strings.Contains(got, "hidden-value") {
		t.Error("prompt exposed secret")
	}
}

// mockTelegram serves the three Bot API endpoints the approver uses. callbackData
// is returned once from getUpdates (empty string = never any callback, to drive
// the timeout path).
func mockTelegram(t *testing.T, callbackData string) *httptest.Server {
	return mockTelegramCallback(t, callbackData, 42, 8663043855)
}

func mockTelegramCallback(t *testing.T, callbackData string, senderID, chatID int64) *httptest.Server {
	t.Helper()
	served := false
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case strings.HasSuffix(r.URL.Path, "/sendMessage"):
			fmt.Fprint(w, `{"ok":true,"result":{"message_id":1}}`)
		case strings.HasSuffix(r.URL.Path, "/getUpdates"):
			if callbackData != "" && !served {
				served = true
				fmt.Fprintf(w, `{"ok":true,"result":[{"update_id":10,"callback_query":{"id":"cb1","data":%q,"from":{"id":%d},"message":{"chat":{"id":%d}}}}]}`, callbackData, senderID, chatID)
			} else {
				fmt.Fprint(w, `{"ok":true,"result":[]}`)
			}
		case strings.HasSuffix(r.URL.Path, "/answerCallbackQuery"):
			fmt.Fprint(w, `{"ok":true}`)
		default:
			http.Error(w, "not found", 404)
		}
	}))
}

func newTestApprover(base string, timeout time.Duration) *TelegramApprover {
	a, err := NewTelegramApprover("TESTTOKEN", "8663043855", "42, 43", timeout)
	if err != nil {
		panic(err)
	}
	a.apiBase = base
	a.poll = 5 * time.Millisecond
	a.nonce = func() string { return "n1" }
	return a
}

func TestTelegramUnauthorizedCallbacksAreIgnored(t *testing.T) {
	for _, tc := range []struct {
		name     string
		senderID int64
		chatID   int64
		reason   string
	}{
		{name: "unlisted sender", senderID: 7, chatID: 8663043855, reason: "telegram-callback-unlisted-sender"},
		{name: "wrong chat", senderID: 42, chatID: 99, reason: "telegram-callback-wrong-chat"},
		{name: "missing sender", senderID: 0, chatID: 8663043855, reason: "telegram-callback-unlisted-sender"},
		{name: "missing chat", senderID: 42, chatID: 0, reason: "telegram-callback-wrong-chat"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			srv := mockTelegramCallback(t, "approve:n1", tc.senderID, tc.chatID)
			defer srv.Close()
			var rejected []string
			v := newTestApprover(srv.URL, 80*time.Millisecond).Ask(Request{Agent: "kit", Tool: "deploy", OnRejectedTap: func(reason string) {
				rejected = append(rejected, reason)
			}})
			if v.Approved || v.Reason != "timeout" {
				t.Fatalf("unauthorized tap must leave request held until timeout: %+v", v)
			}
			if len(rejected) != 1 || rejected[0] != tc.reason {
				t.Fatalf("rejected tap audit events = %v, want [%s]", rejected, tc.reason)
			}
		})
	}
}

func TestTelegramApproverRequiresAllowlist(t *testing.T) {
	for _, ids := range []string{"", " ", "42,", "not-a-number"} {
		if a, err := NewTelegramApprover("TESTTOKEN", "8663043855", ids, time.Second); a != nil || err == nil || !strings.Contains(err.Error(), EnvApproverIDs) {
			t.Fatalf("ids=%q: approver=%v error=%v; want clear refusal", ids, a, err)
		}
	}
}

func TestTelegramNonceIsRandom(t *testing.T) {
	b, err := NewTelegramApprover("TESTTOKEN", "8663043855", "42", time.Second)
	if err != nil {
		t.Fatal(err)
	}
	if first, second := b.nonce(), b.nonce(); first == second || len(first) < 20 {
		t.Fatalf("nonce is not a distinct random token: %q, %q", first, second)
	}
}

func TestTelegramApproverApproved(t *testing.T) {
	srv := mockTelegram(t, "approve:n1")
	defer srv.Close()
	v := newTestApprover(srv.URL, 2*time.Second).Ask(Request{Agent: "kit", Tool: "nockcc_kill_switch_set"})
	if !v.Approved {
		t.Errorf("expected approved, got %+v", v)
	}
}

func TestTelegramApproverDenied(t *testing.T) {
	srv := mockTelegram(t, "deny:n1")
	defer srv.Close()
	v := newTestApprover(srv.URL, 2*time.Second).Ask(Request{Agent: "kit", Tool: "nockcc_kill_switch_set"})
	if v.Approved || v.Reason != "denied by human" {
		t.Errorf("expected denied-by-human, got %+v", v)
	}
}

func TestTelegramApproverTimeoutFailsSafe(t *testing.T) {
	srv := mockTelegram(t, "") // no callback ever
	defer srv.Close()
	v := newTestApprover(srv.URL, 80*time.Millisecond).Ask(Request{Agent: "kit", Tool: "nockcc_kill_switch_set"})
	if v.Approved || v.Reason != "timeout" {
		t.Errorf("timeout must fail safe (deny), got %+v", v)
	}
}

func TestTelegramApproverSendFailureFailsSafe(t *testing.T) {
	// Point at a closed server so sendMessage errors -> must deny.
	srv := mockTelegram(t, "approve:n1")
	url := srv.URL
	srv.Close()
	v := newTestApprover(url, 2*time.Second).Ask(Request{Agent: "kit", Tool: "x"})
	if v.Approved || v.Reason != "send-failed" {
		t.Errorf("send failure must fail safe (deny), got %+v", v)
	}
}
