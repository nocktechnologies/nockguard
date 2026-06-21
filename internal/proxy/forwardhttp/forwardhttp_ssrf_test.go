package forwardhttp

import (
	"io"
	"log"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"

	"github.com/nocktechnologies/nockguard/internal/audit"
	"github.com/nocktechnologies/nockguard/internal/policy"
)

func writeTestPolicy(t *testing.T, content string) *policy.Engine {
	t.Helper()
	dir := t.TempDir()
	path := filepath.Join(dir, "policy.yaml")
	if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}
	eng, err := policy.Load(path)
	if err != nil {
		t.Fatal(err)
	}
	return eng
}

// TestSSRFGuardBlocksLoopbackAndLinkLocal proves N8182 finding #3: the egress
// forward-proxy must hard-block loopback, link-local, and cloud-metadata
// destinations regardless of policy or observe mode, returning 403 Forbidden.
func TestSSRFGuardBlocksLoopbackAndLinkLocal(t *testing.T) {
	eng := writeTestPolicy(t, `
agents:
  kit:
    mode: allow
`)
	auditor, err := audit.New("")
	if err != nil {
		t.Fatal(err)
	}
	logger := log.New(io.Discard, "", 0)
	proxy := New("127.0.0.1:0", "kit", eng, auditor, logger)

	blocked := []struct {
		host string
		url  string
	}{
		{host: "127.0.0.1", url: "http://127.0.0.1/secret"},
		{host: "::1", url: "http://[::1]/secret"},
		{host: "169.254.169.254", url: "http://169.254.169.254/latest/meta-data/"},
		{host: "localhost", url: "http://localhost/"},
	}

	for _, tc := range blocked {
		t.Run(tc.host, func(t *testing.T) {
			req := httptest.NewRequest(http.MethodGet, tc.url, nil)
			req.Host = tc.host
			w := httptest.NewRecorder()
			proxy.ServeHTTP(w, req)
			if w.Code != http.StatusForbidden {
				t.Errorf("host %q: want 403 Forbidden, got %d", tc.host, w.Code)
			}
		})
	}
}

// TestSSRFGuardBlocksCONNECTToLoopback proves the SSRF guard also fires on
// CONNECT (HTTPS tunnel) requests to loopback addresses.
func TestSSRFGuardBlocksCONNECTToLoopback(t *testing.T) {
	eng := writeTestPolicy(t, `
agents:
  kit:
    mode: allow
`)
	auditor, err := audit.New("")
	if err != nil {
		t.Fatal(err)
	}
	logger := log.New(io.Discard, "", 0)
	proxy := New("127.0.0.1:0", "kit", eng, auditor, logger)

	req := httptest.NewRequest(http.MethodConnect, "http://127.0.0.1:443", nil)
	req.Host = "127.0.0.1:443"
	w := httptest.NewRecorder()
	proxy.ServeHTTP(w, req)
	if w.Code != http.StatusForbidden {
		t.Errorf("CONNECT to loopback: want 403 Forbidden, got %d", w.Code)
	}
}
