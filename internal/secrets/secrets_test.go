package secrets

import (
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
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

// Nockcc tests with mock server

func TestNockccResolverSuccess(t *testing.T) {
	// Create a fake vault server
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/api/vault/read" {
			t.Errorf("unexpected path: %s", r.URL.Path)
			http.Error(w, "not found", http.StatusNotFound)
			return
		}
		if r.Header.Get("Authorization") != "Bearer test-api-key" {
			t.Errorf("unexpected auth: %s", r.Header.Get("Authorization"))
			http.Error(w, "unauthorized", http.StatusUnauthorized)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		w.Write([]byte(`{"success": true, "data": {"value": "nockcc-secret-test-0001"}}`))
	}))
	defer server.Close()

	t.Setenv("NOCKCC_BASE_URL", server.URL)
	t.Setenv("NOCKCC_API_KEY", "test-api-key")

	r := Chain()
	val, err := r.Resolve("nockcc:TEST_SECRET")
	if err != nil {
		t.Fatalf("Resolve failed: %v", err)
	}
	if val != "nockcc-secret-test-0001" {
		t.Errorf("got %q, want nockcc-secret-test-0001", val)
	}
}

func TestNockccResolverMissingBaseURL(t *testing.T) {
	t.Setenv("NOCKCC_BASE_URL", "")
	t.Setenv("NOCKCC_API_KEY", "test-api-key")

	r := Chain()
	_, err := r.Resolve("nockcc:TEST_SECRET")
	if err == nil {
		t.Fatal("expected error when NOCKCC_BASE_URL is unset")
	}
}

func TestNockccResolverMissingAPIKey(t *testing.T) {
	t.Setenv("NOCKCC_BASE_URL", "http://localhost:8000")
	t.Setenv("NOCKCC_API_KEY", "")

	r := Chain()
	_, err := r.Resolve("nockcc:TEST_SECRET")
	if err == nil {
		t.Fatal("expected error when NOCKCC_API_KEY is unset")
	}
}

func TestNockccResolverHTTP404(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, "not found", http.StatusNotFound)
	}))
	defer server.Close()

	t.Setenv("NOCKCC_BASE_URL", server.URL)
	t.Setenv("NOCKCC_API_KEY", "test-api-key")

	r := Chain()
	_, err := r.Resolve("nockcc:TEST_SECRET")
	if err == nil {
		t.Fatal("expected error on 404")
	}
}

func TestNockccResolverHTTP500(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, "internal server error", http.StatusInternalServerError)
	}))
	defer server.Close()

	t.Setenv("NOCKCC_BASE_URL", server.URL)
	t.Setenv("NOCKCC_API_KEY", "test-api-key")

	r := Chain()
	_, err := r.Resolve("nockcc:TEST_SECRET")
	if err == nil {
		t.Fatal("expected error on 500")
	}
}

func TestNockccResolverEmptyResponse(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		w.Write([]byte(`{"success": true, "data": {"value": ""}}`))
	}))
	defer server.Close()

	t.Setenv("NOCKCC_BASE_URL", server.URL)
	t.Setenv("NOCKCC_API_KEY", "test-api-key")

	r := Chain()
	_, err := r.Resolve("nockcc:TEST_SECRET")
	if err == nil {
		t.Fatal("expected error on empty value")
	}
}

func TestNockccResolverMalformedJSON(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		w.Write([]byte(`{invalid json}`))
	}))
	defer server.Close()

	t.Setenv("NOCKCC_BASE_URL", server.URL)
	t.Setenv("NOCKCC_API_KEY", "test-api-key")

	r := Chain()
	_, err := r.Resolve("nockcc:TEST_SECRET")
	if err == nil {
		t.Fatal("expected error on malformed JSON")
	}
}

func TestNockccResolverUnsuccessfulResponse(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		w.Write([]byte(`{"success": false, "data": {"value": ""}}`))
	}))
	defer server.Close()

	t.Setenv("NOCKCC_BASE_URL", server.URL)
	t.Setenv("NOCKCC_API_KEY", "test-api-key")

	r := Chain()
	_, err := r.Resolve("nockcc:TEST_SECRET")
	if err == nil {
		t.Fatal("expected error on unsuccessful response")
	}
}

func TestKnownSchemeNockcc(t *testing.T) {
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
