package forward

import (
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"
)

type capture struct {
	mu       sync.Mutex
	requests []recorded
	status   int
}

type recorded struct {
	path   string
	apiKey string
	body   map[string]any
}

func (c *capture) handler() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		raw, _ := io.ReadAll(r.Body)
		var b map[string]any
		_ = json.Unmarshal(raw, &b)
		c.mu.Lock()
		c.requests = append(c.requests, recorded{path: r.URL.Path, apiKey: r.Header.Get("X-API-Key"), body: b})
		st := c.status
		c.mu.Unlock()
		if st == 0 {
			st = http.StatusCreated
		}
		w.WriteHeader(st)
	}
}

func (c *capture) all() []recorded {
	c.mu.Lock()
	defer c.mu.Unlock()
	out := make([]recorded, len(c.requests))
	copy(out, c.requests)
	return out
}

func TestDisabledWhenNoBaseURL(t *testing.T) {
	f := New(Config{})
	if f.Enabled() {
		t.Error("forwarder with no base URL must be disabled")
	}
	var nilF *Forwarder
	if nilF.Enabled() {
		t.Error("nil forwarder must report disabled")
	}
	// Enqueue/Start/Stop on a disabled forwarder are safe no-ops.
	f.Start()
	f.Enqueue(Event{Agent: "kit", Tool: "x", Decision: "deny"})
	f.Stop()
	nilF.Enqueue(Event{})
}

func TestForwardsEventToOpsLog(t *testing.T) {
	cap := &capture{}
	srv := httptest.NewServer(cap.handler())
	defer srv.Close()

	f := New(Config{BaseURL: srv.URL, APIKey: "secret-key"})
	f.Start()
	f.Enqueue(Event{Agent: "kit", Tool: "nockcc_kill_switch_set", Decision: "deny", Reason: "policy"})
	f.Stop() // drains pending before returning

	reqs := cap.all()
	if len(reqs) != 1 {
		t.Fatalf("expected 1 forwarded request, got %d", len(reqs))
	}
	r := reqs[0]
	if r.path != "/api/brain/ops-log/" {
		t.Errorf("path = %q, want /api/brain/ops-log/", r.path)
	}
	if r.apiKey != "secret-key" {
		t.Errorf("X-API-Key = %q, want secret-key", r.apiKey)
	}
	if r.body["agent"] != "kit" {
		t.Errorf("agent = %v, want kit", r.body["agent"])
	}
	if r.body["event_type"] != "other" {
		t.Errorf("event_type = %v, want other", r.body["event_type"])
	}
	if r.body["severity"] != "warn" {
		t.Errorf("severity = %v, want warn (deny)", r.body["severity"])
	}
	summary, _ := r.body["summary"].(string)
	if summary == "" {
		t.Error("summary should be non-empty")
	}
	blob, ok := r.body["data_blob"].(map[string]any)
	if !ok {
		t.Fatalf("data_blob missing/!object: %v", r.body["data_blob"])
	}
	if blob["decision"] != "deny" || blob["tool"] != "nockcc_kill_switch_set" || blob["source"] != "nockguard" {
		t.Errorf("data_blob fields wrong: %v", blob)
	}
}

func TestSeverityMapping(t *testing.T) {
	cap := &capture{}
	srv := httptest.NewServer(cap.handler())
	defer srv.Close()

	f := New(Config{BaseURL: srv.URL, APIKey: "k"})
	f.Start()
	f.Enqueue(Event{Agent: "kit", Tool: "a", Decision: "block", Reason: "sqli"})
	f.Enqueue(Event{Agent: "kit", Tool: "b", Decision: "deny", Reason: "policy"})
	f.Enqueue(Event{Agent: "kit", Tool: "c", Decision: "ratelimit", Reason: "rate"})
	f.Enqueue(Event{Agent: "kit", Tool: "d", Decision: "would-deny", Reason: "shadow"})
	f.Stop()

	got := map[string]string{} // decision -> severity
	for _, r := range cap.all() {
		blob, _ := r.body["data_blob"].(map[string]any)
		dec, _ := blob["decision"].(string)
		sev, _ := r.body["severity"].(string)
		got[dec] = sev
	}
	want := map[string]string{"block": "high", "deny": "warn", "ratelimit": "warn", "would-deny": "info"}
	for dec, sev := range want {
		if got[dec] != sev {
			t.Errorf("decision %q severity = %q, want %q", dec, got[dec], sev)
		}
	}
}

func TestSeverityThreatTiers(t *testing.T) {
	cases := []struct {
		decision, reason, want string
	}{
		// none: allows and dry-run shadow are not live catches.
		{"allow", "", ThreatNone},
		{"allow", "allow-rule \"Read\"", ThreatNone},
		{"would-deny", "would-deny shadow (no shadow-rule matched)", ThreatNone},
		{"", "", ThreatNone},

		// critical: secret-exfil — real validate rule names + demo phrasing.
		{"block", "aws-access-key", ThreatCritical},
		{"block", "openai-key", ThreatCritical},
		{"block", "github-token", ThreatCritical},
		{"block", "generic-bearer", ThreatCritical},
		{"block", "credit-card", ThreatCritical},
		{"block", "sensitive-unix-path", ThreatCritical},
		{"block", "secret-exfil: credential path", ThreatCritical},
		{"block", "secret-exfil: dotenv read", ThreatCritical},

		// critical: destructive — a drop/rm, whether blocked or denied.
		{"block", "destructive: rm -rf root", ThreatCritical},
		{"block", "sql-stacked-drop", ThreatCritical},
		{"deny", "destructive: rm -rf /", ThreatCritical},

		// high: blocks/denies of consequence that aren't secret/destructive.
		{"block", "sql-tautology", ThreatHigh},
		{"block", "injection: pipe-to-shell in args", ThreatHigh},
		{"block", "dotdot-slash", ThreatHigh},
		{"deny", "blocklist", ThreatHigh},
		{"deny", "deny-rule \"nockcc_kill_switch_set\"", ThreatHigh},
		{"deny", "", ThreatHigh}, // reasonless deny: surface rather than downgrade

		// low: routine allowlist denies, rate-limit holds, hidden tools.
		{"deny", "no allow-rule matched", ThreatLow},
		{"deny", "default-deny (no allow list)", ThreatLow},
		{"deny", "tool not in agent allowlist", ThreatLow},
		{"ratelimit", "rate limit: 60/min exceeded", ThreatLow},
		{"ratelimit", "session spend cap reached", ThreatLow},
		{"hide", "tool hidden from this agent", ThreatLow},

		// unknown enforcement outcomes surface as high, never silently none.
		{"quarantine", "some novel verdict", ThreatHigh},
	}
	for _, c := range cases {
		if got := Severity(c.decision, c.reason); got != c.want {
			t.Errorf("Severity(%q, %q) = %q, want %q", c.decision, c.reason, got, c.want)
		}
	}
}

func TestForwardsThreatTierInDataBlob(t *testing.T) {
	cap := &capture{}
	srv := httptest.NewServer(cap.handler())
	defer srv.Close()

	f := New(Config{BaseURL: srv.URL, APIKey: "k"})
	f.Start()
	f.Enqueue(Event{Agent: "kit", Tool: "Read", Decision: "block", Reason: "aws-access-key"})
	f.Stop()

	reqs := cap.all()
	if len(reqs) != 1 {
		t.Fatalf("expected 1 request, got %d", len(reqs))
	}
	blob, _ := reqs[0].body["data_blob"].(map[string]any)
	if blob["threat"] != ThreatCritical {
		t.Errorf("data_blob threat = %v, want %q", blob["threat"], ThreatCritical)
	}
	// The ops-log severity vocabulary is unchanged and independent of the tier.
	if reqs[0].body["severity"] != "high" {
		t.Errorf("ops-log severity = %v, want high (block)", reqs[0].body["severity"])
	}
}

func TestStopDrainsAllPending(t *testing.T) {
	cap := &capture{}
	srv := httptest.NewServer(cap.handler())
	defer srv.Close()

	f := New(Config{BaseURL: srv.URL, APIKey: "k"})
	f.Start()
	for i := 0; i < 10; i++ {
		f.Enqueue(Event{Agent: "kit", Tool: "t", Decision: "deny"})
	}
	f.Stop()

	if n := len(cap.all()); n != 10 {
		t.Errorf("expected all 10 events drained on Stop, got %d", n)
	}
}

func TestFailOpenOnServerError(t *testing.T) {
	cap := &capture{status: http.StatusInternalServerError}
	srv := httptest.NewServer(cap.handler())
	defer srv.Close()

	f := New(Config{BaseURL: srv.URL, APIKey: "k"})
	f.Start()
	f.Enqueue(Event{Agent: "kit", Tool: "t", Decision: "deny"})
	f.Stop() // must not hang or panic even though the server 500s

	if n := len(cap.all()); n != 1 {
		t.Errorf("expected the request to be attempted once, got %d", n)
	}
}
