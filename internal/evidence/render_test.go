package evidence

import (
	"encoding/json"
	"flag"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/nocktechnologies/nockguard/internal/audit"
)

// -update regenerates the golden HTML file. Run: go test ./internal/evidence -run Golden -update
var updateGolden = flag.Bool("update", false, "update golden files")

// cleanPack builds a deterministic pack over a known clean trail for render tests.
func cleanPack(t *testing.T) Pack {
	t.Helper()
	path := writeSignedTrail(t, sampleEvents())
	pack, err := BuildPack(PackOptions{
		Framework:  FrameworkSOC2,
		AuditFiles: []string{path},
		HMACKey:    testHMACKey,
		Now:        fixedNow(),
	})
	if err != nil {
		t.Fatalf("BuildPack: %v", err)
	}
	// Two sources of non-determinism must be normalized for a stable golden:
	// the t.TempDir() audit path, and the per-record wall-clock timestamps the
	// real Auditor stamps (its clock is unexported, so we pin ts post-build).
	normalizePack(&pack)
	return pack
}

// normalizePack replaces the temp-dir audit paths and the wall-clock event
// timestamps with stable placeholders so golden HTML does not churn each run.
func normalizePack(p *Pack) {
	for i := range p.Verification.FileResults {
		p.Verification.FileResults[i].Path = "/audit/agent.audit.jsonl"
	}
	const stableTS = "2026-06-14T12:00:00Z"
	for i := range p.AllEvents {
		p.AllEvents[i].Time = stableTS
	}
	for ci := range p.Controls {
		for ei := range p.Controls[ci].Events {
			p.Controls[ci].Events[ei].Time = stableTS
		}
	}
}

func TestRenderHTMLContainsAttestationAndPassBanner(t *testing.T) {
	html, err := RenderHTML(cleanPack(t))
	if err != nil {
		t.Fatalf("RenderHTML: %v", err)
	}
	s := string(html)
	for _, want := range []string{
		"Integrity Attestation",
		"banner pass",
		">PASS<",
		"SOC 2 (Trust Services Criteria)",
		"CC6.1",
		"CC7.2",
		"CC8.1",
		"Raw Evidence Appendix",
		"secret-exfil", // an audit reason flows into the table
	} {
		if !strings.Contains(s, want) {
			t.Errorf("rendered HTML missing %q", want)
		}
	}
	// A clean pack must NOT show the failure banner.
	if strings.Contains(s, "banner fail") {
		t.Error("clean pack should not render a FAILED banner")
	}
}

func TestRenderHTMLShowsFailedBannerOnBrokenChain(t *testing.T) {
	path := writeSignedTrail(t, sampleEvents())
	data, _ := os.ReadFile(path)
	tampered := strings.Replace(string(data), `"decision":"deny"`, `"decision":"allow"`, 1)
	if err := os.WriteFile(path, []byte(tampered), 0o644); err != nil {
		t.Fatal(err)
	}
	pack, err := BuildPack(PackOptions{
		Framework:  FrameworkSOC2,
		AuditFiles: []string{path},
		HMACKey:    testHMACKey,
		Now:        fixedNow(),
	})
	if err != nil {
		t.Fatal(err)
	}

	html, err := RenderHTML(pack)
	if err != nil {
		t.Fatalf("RenderHTML: %v", err)
	}
	s := string(html)
	if !strings.Contains(s, "banner fail") || !strings.Contains(s, ">FAILED<") {
		t.Error("broken chain must render a prominent FAILED banner")
	}
	if !strings.Contains(s, "NOT trustworthy") {
		t.Error("FAILED banner should state the evidence is not trustworthy")
	}
	if strings.Contains(s, "banner pass") {
		t.Error("broken pack must not render a PASS banner")
	}
}

func TestRenderHTMLEscapesAuditContent(t *testing.T) {
	// An audit reason carrying HTML must be escaped, never injected as markup —
	// audit content can be attacker-influenced.
	path := writeSignedTrail(t, []audit.Event{
		{Agent: "kit", Tool: "Bash", Decision: "deny", Reason: `<script>alert(1)</script>`},
	})
	pack, _ := BuildPack(PackOptions{
		Framework:  FrameworkSOC2,
		AuditFiles: []string{path},
		HMACKey:    testHMACKey,
		Now:        fixedNow(),
	})
	html, err := RenderHTML(pack)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(html), "<script>alert(1)</script>") {
		t.Fatal("audit reason was injected raw — html/template escaping bypassed")
	}
	if !strings.Contains(string(html), "&lt;script&gt;") {
		t.Error("expected the script tag to be HTML-escaped")
	}
}

func TestRenderJSONRoundTrips(t *testing.T) {
	pack := cleanPack(t)
	b, err := RenderJSON(pack)
	if err != nil {
		t.Fatalf("RenderJSON: %v", err)
	}
	var back Pack
	if err := json.Unmarshal(b, &back); err != nil {
		t.Fatalf("RenderJSON output is not valid JSON: %v", err)
	}
	if back.Framework != pack.Framework {
		t.Errorf("framework lost in round-trip: %q vs %q", back.Framework, pack.Framework)
	}
	if back.Verification.ChainIntact != pack.Verification.ChainIntact {
		t.Error("attestation lost in round-trip")
	}
	if len(back.Controls) != len(pack.Controls) {
		t.Errorf("controls lost in round-trip: %d vs %d", len(back.Controls), len(pack.Controls))
	}
}

// TestRenderHTMLGolden pins the rendered HTML byte-for-byte against a checked-in
// golden file. Regenerate with: go test ./internal/evidence -run Golden -update
func TestRenderHTMLGolden(t *testing.T) {
	html, err := RenderHTML(cleanPack(t))
	if err != nil {
		t.Fatalf("RenderHTML: %v", err)
	}
	golden := filepath.Join("testdata", "soc2_pack.golden.html")
	if *updateGolden {
		if err := os.MkdirAll("testdata", 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(golden, html, 0o644); err != nil {
			t.Fatal(err)
		}
		t.Logf("wrote golden %s", golden)
		return
	}
	want, err := os.ReadFile(golden)
	if err != nil {
		t.Fatalf("read golden (run with -update to create): %v", err)
	}
	if string(html) != string(want) {
		t.Errorf("rendered HTML differs from golden %s — if intentional, regenerate with -update", golden)
	}
}
