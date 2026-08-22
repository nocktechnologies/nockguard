package main

import (
	"bufio"
	"errors"
	"fmt"
	"testing"

	"github.com/nocktechnologies/nockguard/internal/audit"
)

const testNow = "2026-08-22T00:00:00Z"

// N9870: classifyVerifyResult must map a REAL tamper (audit.ErrTamper) to
// chain_intact=false (banner fires) and a benign read/scan error (audit.ErrScan
// or any non-tamper error) to a null chain_intact with status "unavailable"
// (banner stays hidden). This is the crux of the fix, tested purely — no fixture.

func TestClassifyCleanChain(t *testing.T) {
	rep := classifyVerifyResult(5, nil, testNow)
	if rep.ChainIntact == nil || !*rep.ChainIntact {
		t.Fatalf("clean chain: chain_intact = %v, want true", rep.ChainIntact)
	}
	if rep.Status != statusVerified {
		t.Fatalf("clean chain: status = %q, want %q", rep.Status, statusVerified)
	}
	if rep.EntriesVerified != 5 {
		t.Fatalf("clean chain: entries_verified = %d, want 5", rep.EntriesVerified)
	}
	if rep.BreakAt != nil {
		t.Fatalf("clean chain: break_at = %v, want nil", *rep.BreakAt)
	}
}

func TestClassifyTamperFiresBanner(t *testing.T) {
	// A genuine tamper as internal/audit produces it: a *TamperError at line 2.
	terr := &audit.TamperError{Line: 2, Err: fmt.Errorf("line 2: signature mismatch — trail was tampered")}
	rep := classifyVerifyResult(2, terr, testNow)

	if rep.ChainIntact == nil || *rep.ChainIntact {
		t.Fatalf("tamper: chain_intact = %v, want false (banner must fire)", rep.ChainIntact)
	}
	if rep.Status != statusTampered {
		t.Fatalf("tamper: status = %q, want %q", rep.Status, statusTampered)
	}
	if rep.BreakAt == nil || *rep.BreakAt != 2 {
		t.Fatalf("tamper: break_at = %v, want 2", rep.BreakAt)
	}
	if rep.EntriesVerified != 1 {
		t.Fatalf("tamper: entries_verified = %d, want 1 (entries before the break)", rep.EntriesVerified)
	}
	if rep.Detail == nil || *rep.Detail == "" {
		t.Fatal("tamper: expected a non-empty detail")
	}
}

func TestClassifyScanErrorIsUnavailableNotTamper(t *testing.T) {
	// A read/scan failure as internal/audit produces it: a *ScanError wrapping the
	// oversized-line error. It must NOT become a tamper.
	serr := &audit.ScanError{Err: bufio.ErrTooLong}
	rep := classifyVerifyResult(3, serr, testNow)

	if rep.ChainIntact != nil {
		t.Fatalf("scan error: chain_intact = %v, want null (banner must NOT fire)", *rep.ChainIntact)
	}
	if rep.Status != statusUnavailable {
		t.Fatalf("scan error: status = %q, want %q", rep.Status, statusUnavailable)
	}
	if rep.BreakAt != nil {
		t.Fatalf("scan error: break_at = %v, want nil", *rep.BreakAt)
	}
	// The count read before the failure is retained as information.
	if rep.EntriesVerified != 3 {
		t.Fatalf("scan error: entries_verified = %d, want 3", rep.EntriesVerified)
	}
	if rep.Detail == nil || *rep.Detail == "" {
		t.Fatal("scan error: expected a non-empty detail")
	}
	// Guard the exact contract the browser keys on: not an explicit false.
	if rep.ChainIntact != nil && *rep.ChainIntact == false {
		t.Fatal("scan error must never yield chain_intact:false")
	}
}

func TestClassifyGenericIOErrorIsUnavailable(t *testing.T) {
	// An absent/unreadable trail (plain error, not classified) is unavailable, not
	// a tamper — mirrors os.Open failing inside audit.Verify with n=0.
	rep := classifyVerifyResult(0, errors.New("open audit.jsonl: no such file or directory"), testNow)
	if rep.ChainIntact != nil {
		t.Fatalf("io error: chain_intact = %v, want null", *rep.ChainIntact)
	}
	if rep.Status != statusUnavailable {
		t.Fatalf("io error: status = %q, want %q", rep.Status, statusUnavailable)
	}
	if rep.BreakAt != nil {
		t.Fatalf("io error: break_at = %v, want nil (n=0 must not emit break_at:0)", *rep.BreakAt)
	}
}
