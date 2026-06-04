// Package forward implements NockGuard Phase 4 increment 2: asynchronously
// forwarding policy-enforcement decisions to the NockCC ops-log, so that what
// the firewall blocks across the fleet is visible in the Command Center.
//
// Only enforcement decisions (deny / block / ratelimit) should be enqueued —
// forwarding every allowed call would flood the ops-log. The local JSONL audit
// trail (internal/audit) remains the complete record; this is the
// notable-events feed.
//
// Forwarding is asynchronous and fail-open by design: Enqueue never blocks (it
// drops when the buffer is full) and HTTP/transport errors are logged but never
// propagated, so a slow or unreachable NockCC can never stall or fail a tool
// call. A disabled (no base URL) or nil *Forwarder is a safe no-op throughout.
package forward

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"strings"
	"sync"
	"time"
)

// Event is one enforcement decision to forward.
type Event struct {
	Agent    string
	Tool     string
	Decision string // deny | block | ratelimit
	Reason   string
}

// Config configures the forwarder. An empty BaseURL disables it.
type Config struct {
	BaseURL string       // e.g. https://cc.nocktechnologies.io
	APIKey  string       // sent as the X-API-Key header
	Client  *http.Client // optional; a sane default is used when nil
	Buffer  int          // channel capacity; defaults to 256
	Logger  *log.Logger  // optional; errors are logged here when set
}

// Forwarder posts enforcement events to the NockCC ops-log on a background
// worker. Safe for concurrent Enqueue. A nil *Forwarder is disabled.
type Forwarder struct {
	url    string
	apiKey string
	client *http.Client
	logger *log.Logger

	ch   chan Event
	wg   sync.WaitGroup
	once sync.Once
}

const opsLogPath = "/api/brain/ops-log/"

// New builds a Forwarder. An empty BaseURL yields a disabled forwarder.
func New(cfg Config) *Forwarder {
	if cfg.BaseURL == "" {
		return &Forwarder{}
	}
	client := cfg.Client
	if client == nil {
		client = &http.Client{Timeout: 10 * time.Second}
	}
	buf := cfg.Buffer
	if buf <= 0 {
		buf = 256
	}
	return &Forwarder{
		url:    strings.TrimRight(cfg.BaseURL, "/") + opsLogPath,
		apiKey: cfg.APIKey,
		client: client,
		logger: cfg.Logger,
		ch:     make(chan Event, buf),
	}
}

// Enabled reports whether the forwarder is configured. Nil-safe.
func (f *Forwarder) Enabled() bool {
	return f != nil && f.ch != nil
}

// Start launches the background worker. No-op on a disabled forwarder.
func (f *Forwarder) Start() {
	if !f.Enabled() {
		return
	}
	f.wg.Add(1)
	go func() {
		defer f.wg.Done()
		for ev := range f.ch {
			f.post(ev)
		}
	}()
}

// Enqueue submits an event without blocking. If the buffer is full the event is
// dropped (fail-open) rather than stalling the caller. No-op when disabled.
func (f *Forwarder) Enqueue(ev Event) {
	if !f.Enabled() {
		return
	}
	select {
	case f.ch <- ev:
	default:
		if f.logger != nil {
			f.logger.Printf("FORWARD-DROP agent=%s tool=%s (buffer full)", ev.Agent, ev.Tool)
		}
	}
}

// Stop closes the queue and waits for the worker to finish forwarding everything
// already buffered. Idempotent and safe on a disabled forwarder.
func (f *Forwarder) Stop() {
	if !f.Enabled() {
		return
	}
	f.once.Do(func() { close(f.ch) })
	f.wg.Wait()
}

func (f *Forwarder) post(ev Event) {
	payload := map[string]any{
		"agent":      ev.Agent,
		"event_type": "other",
		"severity":   severityFor(ev.Decision),
		"summary":    summaryFor(ev),
		"data_blob": map[string]string{
			"source":   "nockguard",
			"tool":     ev.Tool,
			"decision": ev.Decision,
			"reason":   ev.Reason,
		},
	}
	body, err := json.Marshal(payload)
	if err != nil {
		f.logError("marshal", ev, err)
		return
	}
	req, err := http.NewRequest(http.MethodPost, f.url, bytes.NewReader(body))
	if err != nil {
		f.logError("request", ev, err)
		return
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-API-Key", f.apiKey)

	resp, err := f.client.Do(req)
	if err != nil {
		f.logError("post", ev, err)
		return
	}
	defer resp.Body.Close()
	_, _ = io.Copy(io.Discard, resp.Body)
	if resp.StatusCode >= 300 {
		f.logError(fmt.Sprintf("status %d", resp.StatusCode), ev, nil)
	}
}

func (f *Forwarder) logError(stage string, ev Event, err error) {
	if f.logger == nil {
		return
	}
	f.logger.Printf("FORWARD-ERROR stage=%s agent=%s tool=%s decision=%s: %v", stage, ev.Agent, ev.Tool, ev.Decision, err)
}

// severityFor maps a decision to an ops-log severity. A blocked call (an
// injection or secret-exfil attempt caught by input validation) is the loudest
// signal; policy denies and rate limits are warnings.
func severityFor(decision string) string {
	if decision == "block" {
		return "high"
	}
	return "warn"
}

func summaryFor(ev Event) string {
	s := fmt.Sprintf("nockguard: agent %s %s tool %s", ev.Agent, ev.Decision, ev.Tool)
	if ev.Reason != "" {
		s += " (" + ev.Reason + ")"
	}
	if len(s) > 500 {
		s = s[:500]
	}
	return s
}
