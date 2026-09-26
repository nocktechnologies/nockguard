package secrets

import (
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestEnvResolver(t *testing.T) {
	t.Setenv("TEST_SECRET", "test-secret-env-0")
	r := Chain()
	val, err := r.Resolve("env:TEST_SECRET")
	if err != nil {
		t.Fatalf("Resolve failed: %v", err)
	}
	if val != "test-secret-env-0" {
		t.Errorf("got %q, want test-secret-env-0", val)
	}
}

func TestEnvResolverUnset(t *testing.T) {
	r := Chain()
	_, err := r.Resolve("env:NONEXISTENT_VAR_XYZ")
	if err == nil {
		t.Fatal("expected error for unset env var")
	}
}

func TestNockCCResolverReadsEachCall(t *testing.T) {
	values := []string{"vault-value-old", "vault-value-new"}
	const agentToken = "test-nockcc-agent-token"
	requests := 0
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/api/secrets/GITHUB_TOKEN/" {
			t.Errorf("path = %q", r.URL.Path)
		}
		if got := r.Header.Get("X-Agent-Token"); got != agentToken {
			w.WriteHeader(http.StatusForbidden)
			return
		}
		if got := r.Header.Get("X-API-Key"); got != "" {
			t.Errorf("X-API-Key = %q, want empty", got)
		}
		if got := r.Header.Get("Authorization"); got != "" {
			t.Errorf("Authorization = %q, want empty", got)
		}
		_, _ = io.WriteString(w, fmt.Sprintf(`{"success":true,"data":{"value":%q}}`, values[requests]))
		requests++
	}))
	defer server.Close()
	t.Setenv("NOCKCC_BASE_URL", server.URL)
	t.Setenv("NOCKGUARD_VAULT_AGENT_TOKEN", agentToken)

	r := Chain()
	for _, want := range values {
		got, err := r.Resolve("nockcc:GITHUB_TOKEN")
		if err != nil {
			t.Fatalf("Resolve: %v", err)
		}
		if got != want {
			t.Errorf("Resolve = %q, want %q", got, want)
		}
	}
	if requests != len(values) {
		t.Errorf("vault requests = %d, want %d", requests, len(values))
	}
}

func TestNockCCResolverRejectsForbiddenAndOversizedResponses(t *testing.T) {
	const agentToken = "test-nockcc-agent-token"
	tests := []struct {
		name        string
		serverToken string
		body        string
	}{
		{
			name:        "forbidden",
			serverToken: "expected-agent-token",
		},
		{
			name:        "oversized response",
			serverToken: agentToken,
			body:        `{"success":true,"data":{"value":"` + strings.Repeat("x", nockCCResponseMaxBytes) + `"}}`,
		},
		{
			name:        "truncated response",
			serverToken: agentToken,
			body:        `{"success":true,"data":`,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if got := r.Header.Get("X-Agent-Token"); got != tt.serverToken {
					w.WriteHeader(http.StatusForbidden)
					return
				}
				_, _ = io.WriteString(w, tt.body)
			}))
			defer server.Close()
			t.Setenv("NOCKCC_BASE_URL", server.URL)
			t.Setenv("NOCKGUARD_VAULT_AGENT_TOKEN", agentToken)

			if _, err := Chain().Resolve("nockcc:GITHUB_TOKEN"); err == nil {
				t.Fatal("Resolve succeeded for an invalid vault response")
			}
		})
	}
}

func TestFileResolver(t *testing.T) {
	tmpdir := t.TempDir()
	secretPath := filepath.Join(tmpdir, "secret")

	// Write secret with 0600 mode
	if err := os.WriteFile(secretPath, []byte("file-secret-aaaa-0001\n"), 0600); err != nil {
		t.Fatalf("WriteFile failed: %v", err)
	}

	r := Chain()
	val, err := r.Resolve("file:" + secretPath)
	if err != nil {
		t.Fatalf("Resolve failed: %v", err)
	}
	if val != "file-secret-aaaa-0001" {
		t.Errorf("got %q, want file-secret-aaaa-0001", val)
	}
}

func TestFileResolverNoTrailingNewline(t *testing.T) {
	tmpdir := t.TempDir()
	secretPath := filepath.Join(tmpdir, "secret")

	// Write secret without trailing newline
	if err := os.WriteFile(secretPath, []byte("file-secret-aaaa-0002"), 0600); err != nil {
		t.Fatalf("WriteFile failed: %v", err)
	}

	r := Chain()
	val, err := r.Resolve("file:" + secretPath)
	if err != nil {
		t.Fatalf("Resolve failed: %v", err)
	}
	if val != "file-secret-aaaa-0002" {
		t.Errorf("got %q, want file-secret-aaaa-0002", val)
	}
}

func TestFileResolverRelativePath(t *testing.T) {
	r := Chain()
	_, err := r.Resolve("file:relative/path")
	if err == nil {
		t.Fatal("expected error for relative path")
	}
}

func TestFileResolverNotFound(t *testing.T) {
	r := Chain()
	_, err := r.Resolve("file:/nonexistent/path/secret")
	if err == nil {
		t.Fatal("expected error for nonexistent file")
	}
}

func TestFileResolverPermissionsTooOpen(t *testing.T) {
	tmpdir := t.TempDir()
	secretPath := filepath.Join(tmpdir, "secret")

	// Write secret and then change mode to 0644 (too open)
	if err := os.WriteFile(secretPath, []byte("too-open"), 0600); err != nil {
		t.Fatalf("WriteFile failed: %v", err)
	}
	if err := os.Chmod(secretPath, 0644); err != nil {
		t.Fatalf("Chmod failed: %v", err)
	}

	r := Chain()
	_, err := r.Resolve("file:" + secretPath)
	if err == nil {
		t.Fatal("expected error for over-permissive file")
	}
}

func TestFileResolverSymlink(t *testing.T) {
	tmpdir := t.TempDir()

	// Create a real file
	realPath := filepath.Join(tmpdir, "real")
	if err := os.WriteFile(realPath, []byte("file-secret-aaaa-0003"), 0600); err != nil {
		t.Fatalf("WriteFile failed: %v", err)
	}

	// Create a symlink to it
	linkPath := filepath.Join(tmpdir, "link")
	if err := os.Symlink(realPath, linkPath); err != nil {
		t.Fatalf("Symlink failed: %v", err)
	}

	r := Chain()
	_, err := r.Resolve("file:" + linkPath)
	if err == nil {
		t.Fatal("expected error for symlink (O_NOFOLLOW should reject it)")
	}
}

func TestUnknownScheme(t *testing.T) {
	r := Chain()
	_, err := r.Resolve("vault:mysecret")
	if err == nil {
		t.Fatal("expected error for unknown scheme")
	}
}

func TestKnownScheme(t *testing.T) {
	tests := []struct {
		ref  string
		want bool
	}{
		{"env:GITHUB_TOKEN", true},
		{"file:/etc/secret", true},
		{"nockcc:GITHUB_TOKEN", true},
		{"vault:mysecret", false},
		{"http://example.com", false},
	}
	for _, tt := range tests {
		got := KnownScheme(tt.ref)
		if got != tt.want {
			t.Errorf("KnownScheme(%q) = %v, want %v", tt.ref, got, tt.want)
		}
	}
}
