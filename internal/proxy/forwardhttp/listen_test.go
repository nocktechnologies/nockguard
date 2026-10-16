package forwardhttp

import (
	"bytes"
	"context"
	"log"
	"strings"
	"testing"
	"time"
)

func TestRunRefusesRemoteListen(t *testing.T) {
	for _, addr := range []string{"0.0.0.0:0", ":0", "[::]:0", "192.0.2.1:0", "example.com:0"} {
		t.Run(addr, func(t *testing.T) {
			ctx, cancel := context.WithTimeout(context.Background(), 20*time.Millisecond)
			defer cancel()
			err := New(addr, "test", nil, nil, nil).Run(ctx)
			if err == nil || !strings.Contains(err.Error(), "--allow-remote") {
				t.Fatalf("Run(%q) = %v; want remote bind refusal", addr, err)
			}
		})
	}
}

func TestListenConfig(t *testing.T) {
	engine := writeTestPolicy(t, "agents:\n  test:\n    mode: allow\n")
	for _, addr := range []string{"127.0.0.1:0", "localhost:0", "[::1]:0", "127.1.2.3:0", "[::ffff:127.0.0.1]:0"} {
		if err := ValidateConfig(addr, "test", engine, false); err != nil {
			t.Errorf("loopback %q: %v", addr, err)
		}
	}
	for _, addr := range []string{"0.0.0.0:0", ":0", "[::]:0", "192.0.2.1:0", "example.com:0"} {
		if err := ValidateConfig(addr, "test", engine, false); err == nil {
			t.Errorf("remote %q accepted without opt-in", addr)
		}
		if err := ValidateConfig(addr, "test", engine, true); err != nil {
			t.Errorf("remote %q refused with opt-in: %v", addr, err)
		}
	}
	for _, allow := range []bool{false, true} {
		for _, addr := range []string{"", "127.0.0.1", "::1"} {
			if err := ValidateConfig(addr, "test", engine, allow); err == nil {
				t.Errorf("malformed %q accepted (allowRemote=%v)", addr, allow)
			}
		}
	}
}

func TestRunRemoteWarning(t *testing.T) {
	for _, tc := range []struct {
		addr           string
		allow, warning bool
	}{
		{"127.0.0.1:0", false, false},
		{"localhost:0", false, false},
		{"127.0.0.1:0", true, false},
		{"0.0.0.0:0", true, true},
		{":0", true, true},
	} {
		t.Run(tc.addr, func(t *testing.T) {
			var logs bytes.Buffer
			ctx, cancel := context.WithTimeout(context.Background(), 20*time.Millisecond)
			defer cancel()
			p := New(tc.addr, "test", nil, nil, log.New(&logs, "", 0)).WithAllowRemote(tc.allow)
			if err := p.Run(ctx); err != nil {
				t.Fatal(err)
			}
			warned := strings.Contains(logs.String(), "WARNING: --allow-remote") && strings.Contains(logs.String(), "unauthenticated")
			if warned != tc.warning {
				t.Fatalf("warning=%v, want %v; logs: %s", warned, tc.warning, logs.String())
			}
		})
	}
}
