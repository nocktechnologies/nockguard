package main

import (
	"context"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"testing"
)

func TestWallHostGateCoversEveryRoute(t *testing.T) {
	b := newBroker()
	b.auditPath = filepath.Join(t.TempDir(), "audit.jsonl")
	b.verifier = &verifier{}
	h := wallHandler(b, "8787", "")
	for _, path := range []string{"/", "/events", "/pulse", "/context", "/export", "/verify", "/sessions", "/missing"} {
		for _, tc := range []struct {
			host string
			want int
		}{
			{"evil.example", http.StatusForbidden},
			{"evil.example:8787", http.StatusForbidden},
			{"127.0.0.1:8787", http.StatusOK},
			{"localhost:8787", http.StatusOK},
			{"[::1]:8787", http.StatusOK},
			{"127.0.0.1:9999", http.StatusForbidden},
			{"", http.StatusForbidden},
		} {
			if path == "/missing" && tc.want == http.StatusOK {
				continue
			}
			t.Run(path+"/"+tc.host, func(t *testing.T) {
				r := httptest.NewRequest(http.MethodGet, path, nil)
				r.Host = tc.host
				if path == "/events" {
					ctx, cancel := context.WithCancel(r.Context())
					cancel()
					r = r.WithContext(ctx)
				}
				w := httptest.NewRecorder()
				h.ServeHTTP(w, r)
				if w.Code != tc.want {
					t.Fatalf("status = %d, want %d", w.Code, tc.want)
				}
			})
		}
	}
}

func TestWallSensitiveRoutesRejectCrossSiteRequests(t *testing.T) {
	b := newBroker()
	b.auditPath = filepath.Join(t.TempDir(), "audit.jsonl")
	b.verifier = &verifier{}
	h := wallHandler(b, "8787", "")
	for _, path := range []string{"/events", "/export"} {
		for _, headers := range []http.Header{
			{"Origin": {"https://evil.example"}},
			{"Origin": {"http://127.0.0.1:8787", "https://evil.example"}},
			{"Sec-Fetch-Site": {"cross-site"}},
			{"Sec-Fetch-Site": {"same-site"}},
			{"Origin": {"null"}},
		} {
			r := httptest.NewRequest(http.MethodGet, path, nil)
			r.Host = "127.0.0.1:8787"
			r.Header = headers
			w := httptest.NewRecorder()
			h.ServeHTTP(w, r)
			if w.Code != http.StatusForbidden {
				t.Fatalf("%s with %v: status = %d, want 403", path, headers, w.Code)
			}
		}
	}
}

func TestWallAllowsExplicitHostAndSameOriginRequests(t *testing.T) {
	b := newBroker()
	b.auditPath = filepath.Join(t.TempDir(), "audit.jsonl")
	b.verifier = &verifier{}
	h := wallHandler(b, "8787", "wall.example")
	for _, path := range []string{"/", "/events", "/export"} {
		r := httptest.NewRequest(http.MethodGet, path, nil)
		r.Host = "wall.example:8787"
		r.Header.Set("Origin", "http://wall.example:8787")
		r.Header.Set("Sec-Fetch-Site", "same-origin")
		if path == "/events" {
			ctx, cancel := context.WithCancel(r.Context())
			cancel()
			r = r.WithContext(ctx)
		}
		w := httptest.NewRecorder()
		h.ServeHTTP(w, r)
		if w.Code != http.StatusOK {
			t.Errorf("%s: status = %d, want 200", path, w.Code)
		}
	}
}

func TestWallHostGateOnDefaultHTTPPort(t *testing.T) {
	b := newBroker()
	b.auditPath = filepath.Join(t.TempDir(), "audit.jsonl")
	b.verifier = &verifier{}
	h := wallHandler(b, "80", "wall.example")
	for _, tc := range []struct {
		host string
		want int
	}{
		{"127.0.0.1", http.StatusOK},
		{"localhost", http.StatusOK},
		{"[::1]", http.StatusOK},
		{"wall.example", http.StatusOK},
		{"evil.example", http.StatusForbidden},
		{"127.0.0.1:81", http.StatusForbidden},
	} {
		r := httptest.NewRequest(http.MethodGet, "/", nil)
		r.Host = tc.host
		w := httptest.NewRecorder()
		h.ServeHTTP(w, r)
		if w.Code != tc.want {
			t.Errorf("Host %q: status = %d, want %d", tc.host, w.Code, tc.want)
		}
	}
}

func TestWallBindRequiresExplicitRemoteOptIn(t *testing.T) {
	for _, addr := range []string{"0.0.0.0:8787", ":8787", "192.0.2.1:8787", "[::]:8787"} {
		if _, _, err := wallListenConfig(addr, false); err == nil {
			t.Errorf("%q accepted without --allow-remote", addr)
		}
		if port, remote, err := wallListenConfig(addr, true); err != nil || port != "8787" || !remote {
			t.Errorf("%q with opt-in: port=%q remote=%v err=%v", addr, port, remote, err)
		}
	}
	for _, addr := range []string{"127.0.0.1:8787", "localhost:8787", "[::1]:8787"} {
		if port, remote, err := wallListenConfig(addr, false); err != nil || port != "8787" || remote {
			t.Errorf("%q: port=%q remote=%v err=%v", addr, port, remote, err)
		}
	}
}
