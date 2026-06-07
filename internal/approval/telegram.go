package approval

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"time"
)

// TelegramApprover asks for a human verdict over Telegram on a DEDICATED bot
// (never the fleet's main bot — two getUpdates consumers on one token 409 each
// other; that is the exact bug that wedged the channel on 2026-06-06). It posts
// the held call with inline Approve/Deny buttons, then polls getUpdates on its
// own token for the callback. Fail-safe: a send error, a poll error, or a
// timeout all return Approved=false — a missed prompt never auto-approves.
type TelegramApprover struct {
	token   string
	chatID  string
	apiBase string        // override for tests; defaults to https://api.telegram.org
	timeout time.Duration // total wait for a human tap before failing safe
	poll    time.Duration // getUpdates long-poll/spacing
	client  *http.Client
	nonce   func() string // unique per request; overridable for tests
}

// NewTelegramApprover builds an approver bound to a dedicated bot token + chat.
func NewTelegramApprover(token, chatID string, timeout time.Duration) *TelegramApprover {
	return &TelegramApprover{
		token:   token,
		chatID:  chatID,
		apiBase: "https://api.telegram.org",
		timeout: timeout,
		poll:    2 * time.Second,
		client:  &http.Client{Timeout: 30 * time.Second},
		nonce:   func() string { return fmt.Sprintf("%d", time.Now().UnixNano()) },
	}
}

type tgUpdate struct {
	UpdateID int `json:"update_id"`
	Callback *struct {
		ID   string `json:"id"`
		Data string `json:"data"`
	} `json:"callback_query"`
}

type tgResponse struct {
	OK     bool       `json:"ok"`
	Result []tgUpdate `json:"result"`
}

// Ask posts the held call and waits for a tap. Fail-safe on every error path.
func (t *TelegramApprover) Ask(req Request) Verdict {
	id := t.nonce()
	text := fmt.Sprintf("🔒 NockGuard — approval needed\n\nAgent: %s\nTool: %s", req.Agent, req.Tool)
	if summary := summarizeParams(req.Params); summary != "" {
		text += "\n" + summary
	}
	text += "\n\nApprove this call?"
	if !t.send(text, id) {
		return Verdict{Approved: false, Reason: "send-failed"}
	}

	deadline := time.Now().Add(t.timeout)
	offset := 0
	for time.Now().Before(deadline) {
		updates, next, ok := t.getUpdates(offset)
		if !ok {
			time.Sleep(t.poll)
			continue
		}
		offset = next
		for _, u := range updates {
			if u.Callback == nil {
				continue
			}
			switch u.Callback.Data {
			case "approve:" + id:
				t.answer(u.Callback.ID, "Approved")
				return Verdict{Approved: true, Reason: "approved by human"}
			case "deny:" + id:
				t.answer(u.Callback.ID, "Denied")
				return Verdict{Approved: false, Reason: "denied by human"}
			}
		}
		time.Sleep(t.poll)
	}
	return Verdict{Approved: false, Reason: "timeout"}
}

func (t *TelegramApprover) send(text, id string) bool {
	markup := fmt.Sprintf(
		`{"inline_keyboard":[[{"text":"✅ Approve","callback_data":"approve:%s"},{"text":"⛔ Deny","callback_data":"deny:%s"}]]}`,
		id, id)
	form := url.Values{}
	form.Set("chat_id", t.chatID)
	form.Set("text", text)
	form.Set("reply_markup", markup)
	resp, err := t.client.PostForm(t.api("sendMessage"), form)
	if err != nil {
		return false
	}
	defer resp.Body.Close()
	return resp.StatusCode == http.StatusOK
}

func (t *TelegramApprover) getUpdates(offset int) ([]tgUpdate, int, bool) {
	u := fmt.Sprintf("%s?offset=%d&timeout=1&allowed_updates=%%5B%%22callback_query%%22%%5D",
		t.api("getUpdates"), offset)
	resp, err := t.client.Get(u)
	if err != nil {
		return nil, offset, false
	}
	defer resp.Body.Close()
	var r tgResponse
	if err := json.NewDecoder(resp.Body).Decode(&r); err != nil || !r.OK {
		return nil, offset, false
	}
	next := offset
	for _, up := range r.Result {
		if up.UpdateID >= next {
			next = up.UpdateID + 1
		}
	}
	return r.Result, next, true
}

func (t *TelegramApprover) answer(callbackID, text string) {
	form := url.Values{}
	form.Set("callback_query_id", callbackID)
	form.Set("text", text)
	if resp, err := t.client.PostForm(t.api("answerCallbackQuery"), form); err == nil {
		resp.Body.Close()
	}
}

func (t *TelegramApprover) api(method string) string {
	return fmt.Sprintf("%s/bot%s/%s", strings.TrimRight(t.apiBase, "/"), t.token, method)
}
