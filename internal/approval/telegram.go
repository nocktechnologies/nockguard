package approval

import (
	"context"
	"crypto/rand"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"time"
)

// TelegramApprover asks for a human verdict over Telegram on a DEDICATED bot
// (never the fleet's main bot — two getUpdates consumers on one token 409 each
// other; that is the exact bug that wedged the channel on 2026-06-06). It posts
// the held call with inline Approve/Deny buttons, then polls getUpdates on its
// own token for the callback. Fail-safe: a send error, a poll error, or a
// timeout all return Approved=false — a missed prompt never auto-approves.
type TelegramApprover struct {
	token         string
	chatID        string
	chatNumericID int64
	approverIDs   map[int64]struct{}
	apiBase       string        // override for tests; defaults to https://api.telegram.org
	timeout       time.Duration // total wait for a human tap before failing safe
	poll          time.Duration // getUpdates long-poll/spacing
	client        *http.Client
	nonce         func() string // unique per request; overridable for tests

	mu      sync.Mutex
	waiters map[string]*telegramWaiter
	polling bool
	offset  int // owned by the single poller, preserved between requests
}

type telegramWaiter struct {
	ready   chan struct{}
	updates []tgUpdate // guarded by the approver mutex
}

// NewTelegramApprover builds an approver bound to a dedicated bot token + chat.
func NewTelegramApprover(token, chatID, ids string, timeout time.Duration) (*TelegramApprover, error) {
	chatNumericID, err := strconv.ParseInt(chatID, 10, 64)
	if err != nil {
		return nil, fmt.Errorf("invalid %s: %w", EnvChatID, err)
	}
	if strings.TrimSpace(ids) == "" {
		return nil, fmt.Errorf("%s is required for Telegram approval", EnvApproverIDs)
	}
	approverIDs := make(map[int64]struct{})
	for _, raw := range strings.Split(ids, ",") {
		id, err := strconv.ParseInt(strings.TrimSpace(raw), 10, 64)
		if err != nil || id <= 0 {
			return nil, fmt.Errorf("%s must be a comma-separated list of numeric user IDs", EnvApproverIDs)
		}
		approverIDs[id] = struct{}{}
	}
	return &TelegramApprover{
		token:         token,
		chatID:        chatID,
		chatNumericID: chatNumericID,
		approverIDs:   approverIDs,
		apiBase:       "https://api.telegram.org",
		timeout:       timeout,
		poll:          2 * time.Second,
		client:        &http.Client{Timeout: 30 * time.Second},
		nonce:         rand.Text,
	}, nil
}

type tgUpdate struct {
	UpdateID int `json:"update_id"`
	Callback *struct {
		ID   string `json:"id"`
		Data string `json:"data"`
		From struct {
			ID int64 `json:"id"`
		} `json:"from"`
		Message struct {
			Chat struct {
				ID int64 `json:"id"`
			} `json:"chat"`
		} `json:"message"`
	} `json:"callback_query"`
}

type tgResponse struct {
	OK     bool       `json:"ok"`
	Result []tgUpdate `json:"result"`
}

// Ask posts the held call and waits for a tap. Fail-safe on every error path.
func (t *TelegramApprover) Ask(req Request) Verdict {
	id := t.nonce()
	waiter := &telegramWaiter{ready: make(chan struct{}, 1)}
	t.mu.Lock()
	if t.waiters == nil {
		t.waiters = make(map[string]*telegramWaiter)
	}
	if _, exists := t.waiters[id]; exists {
		t.mu.Unlock()
		return Verdict{Approved: false, Reason: "nonce-collision"}
	}
	t.waiters[id] = waiter
	t.mu.Unlock()
	defer func() {
		t.mu.Lock()
		delete(t.waiters, id)
		t.mu.Unlock()
	}()
	text := fmt.Sprintf("🔒 NockGuard — approval needed\n\nAgent: %s\nTool: %s", req.Agent, req.Tool)
	var call struct {
		Arguments json.RawMessage `json:"arguments"`
	}
	// Params is usually the MCP tools/call envelope; summarize only its
	// arguments there, since summarizing the whole envelope would hide every
	// useful scalar behind {…}. Not every caller passes an envelope, though —
	// the fail-closed unextractable-name path in decideToolCall hands over the
	// entire JSON-RPC line, which has no top-level "arguments" at all. Fall
	// back to summarizing the raw params directly whenever the envelope
	// decode fails or yields no (or a null) arguments field, so that path
	// still shows the human SOMETHING instead of an empty prompt.
	envelopeErr := json.Unmarshal(req.Params, &call)
	summaryParams := req.Params
	if envelopeErr == nil && len(call.Arguments) > 0 && string(call.Arguments) != "null" {
		summaryParams = call.Arguments
	}
	if summary := summarizeParams(summaryParams); summary != "" {
		text += "\n" + summary
	}
	text += "\n\nApprove this call?"
	if !t.send(text, id) {
		return Verdict{Approved: false, Reason: "send-failed"}
	}

	deadline := time.Now().Add(t.timeout)
	t.mu.Lock()
	if !t.polling {
		t.polling = true
		go t.pollUpdates()
	}
	t.mu.Unlock()
	timer := time.NewTimer(time.Until(deadline))
	defer timer.Stop()
	for {
		select {
		case <-timer.C:
			return Verdict{Approved: false, Reason: "timeout"}
		case <-waiter.ready:
			t.mu.Lock()
			u := waiter.updates[0]
			waiter.updates[0] = tgUpdate{}
			waiter.updates = waiter.updates[1:]
			if len(waiter.updates) > 0 {
				select {
				case waiter.ready <- struct{}{}:
				default:
				}
			}
			t.mu.Unlock()
			if !time.Now().Before(deadline) {
				return Verdict{Approved: false, Reason: "timeout"}
			}
			if u.Callback == nil {
				continue
			}
			if u.Callback.Data != "approve:"+id && u.Callback.Data != "deny:"+id {
				continue
			}
			if u.Callback.Message.Chat.ID != t.chatNumericID {
				if req.OnRejectedTap != nil {
					req.OnRejectedTap("telegram-callback-wrong-chat")
				}
				t.answer(u.Callback.ID, "Approval not allowed", deadline)
				continue
			}
			if _, allowed := t.approverIDs[u.Callback.From.ID]; !allowed {
				if req.OnRejectedTap != nil {
					req.OnRejectedTap("telegram-callback-unlisted-sender")
				}
				t.answer(u.Callback.ID, "Approval not allowed", deadline)
				continue
			}
			switch u.Callback.Data {
			case "approve:" + id:
				t.answer(u.Callback.ID, "Approved", deadline)
				return Verdict{Approved: true, Reason: "approved by human"}
			case "deny:" + id:
				t.answer(u.Callback.ID, "Denied", deadline)
				return Verdict{Approved: false, Reason: "denied by human"}
			}
		}
	}
}

// pollUpdates is the sole owner of the bot's update offset. It stops when no
// calls remain held; registration and shutdown share mu so a new call cannot
// be stranded during that transition.
func (t *TelegramApprover) pollUpdates() {
	for {
		t.mu.Lock()
		if len(t.waiters) == 0 {
			t.polling = false
			t.mu.Unlock()
			return
		}
		t.mu.Unlock()
		ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
		updates, next, ok := t.getUpdates(ctx, t.offset)
		cancel()
		if ok {
			t.offset = next
			for _, u := range updates {
				if u.Callback == nil {
					continue
				}
				action, id, valid := strings.Cut(u.Callback.Data, ":")
				if !valid || (action != "approve" && action != "deny") {
					continue
				}
				t.mu.Lock()
				if waiter := t.waiters[id]; waiter != nil {
					// A slow callback answer in one Ask must not stall
					// delivery to other held requests.
					waiter.updates = append(waiter.updates, u)
					select {
					case waiter.ready <- struct{}{}:
					default:
					}
				}
				t.mu.Unlock()
			}
		}
		time.Sleep(t.poll)
	}
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

func (t *TelegramApprover) getUpdates(ctx context.Context, offset int) ([]tgUpdate, int, bool) {
	u := fmt.Sprintf("%s?offset=%d&timeout=1&allowed_updates=%%5B%%22callback_query%%22%%5D",
		t.api("getUpdates"), offset)
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u, nil)
	if err != nil {
		return nil, offset, false
	}
	resp, err := t.client.Do(req)
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

func (t *TelegramApprover) answer(callbackID, text string, deadline time.Time) {
	form := url.Values{}
	form.Set("callback_query_id", callbackID)
	form.Set("text", text)
	ctx, cancel := context.WithTimeout(context.Background(), min(time.Until(deadline), 2*time.Second))
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, t.api("answerCallbackQuery"), strings.NewReader(form.Encode()))
	if err != nil {
		return
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	if resp, err := t.client.Do(req); err == nil {
		resp.Body.Close()
	}
}

func (t *TelegramApprover) api(method string) string {
	return fmt.Sprintf("%s/bot%s/%s", strings.TrimRight(t.apiBase, "/"), t.token, method)
}
