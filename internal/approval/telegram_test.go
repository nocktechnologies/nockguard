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

// mockTelegram serves the three Bot API endpoints the approver uses. callbackData
// is returned once from getUpdates (empty string = never any callback, to drive
// the timeout path).
func mockTelegram(t *testing.T, callbackData string) *httptest.Server {
	t.Helper()
	served := false
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case strings.HasSuffix(r.URL.Path, "/sendMessage"):
			fmt.Fprint(w, `{"ok":true,"result":{"message_id":1}}`)
		case strings.HasSuffix(r.URL.Path, "/getUpdates"):
			if callbackData != "" && !served {
				served = true
				fmt.Fprintf(w, `{"ok":true,"result":[{"update_id":10,"callback_query":{"id":"cb1","data":%q}}]}`, callbackData)
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
	a := NewTelegramApprover("TESTTOKEN", "8663043855", timeout)
	a.apiBase = base
	a.poll = 5 * time.Millisecond
	a.nonce = func() string { return "n1" }
	return a
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
