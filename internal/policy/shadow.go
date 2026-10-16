package policy

import (
	"bufio"
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"sort"

	"github.com/nocktechnologies/nockguard/internal/audit"
	"github.com/nocktechnologies/nockguard/internal/sessionverify"
)

type ShadowMiss struct {
	Tool  string
	Count int
}

type ShadowProposal struct {
	Tools   []string
	Skipped []string
}

func ProposeShadowFromAudit(agent, path string) (ShadowProposal, error) {
	key, _, err := ResolveAgentPub(agent)
	if err != nil {
		return ShadowProposal{}, err
	}
	if key == "" {
		return ShadowProposal{}, fmt.Errorf("no public key configured for agent %q", agent)
	}
	pub, err := audit.PublicKeyFromHex(key)
	if err != nil {
		return ShadowProposal{}, err
	}
	// Reuse the verifier's bounded, single-read snapshot for verification and selection.
	trail, hwm, err := sessionverify.ReadGuard(path, 64*audit.MaxTrailLineBytes)
	if err != nil {
		return ShadowProposal{}, err
	}
	n, checkpoint, err := audit.VerifyEd25519WithCheckpointBytes(trail, hwm, pub)
	if err != nil {
		return ShadowProposal{}, fmt.Errorf("verify audit trail: %w", err)
	}
	if n == 0 || checkpoint != n {
		return ShadowProposal{}, fmt.Errorf("proposal requires a non-empty, fully checkpointed audit trail")
	}
	events, err := decodeAuditEvents(bytes.NewReader(trail), path)
	if err != nil {
		return ShadowProposal{}, err
	}
	seen := map[string]struct{}{}
	for _, ev := range events {
		if ev.Agent == agent && ev.Decision == "allow" && ev.Tool != "" {
			seen[ev.Tool] = struct{}{}
		}
	}
	tools := make([]string, 0, len(seen))
	var skipped []string
	for tool := range seen {
		if isGlobPattern(tool) {
			skipped = append(skipped, tool)
		} else {
			tools = append(tools, tool)
		}
	}
	sort.Strings(tools)
	sort.Strings(skipped)
	return ShadowProposal{Tools: tools, Skipped: skipped}, nil
}

func ShadowReportFromAudit(agent, path string) ([]ShadowMiss, error) {
	events, err := readAuditEvents(path)
	if err != nil {
		return nil, err
	}
	counts := map[string]int{}
	for _, ev := range events {
		if ev.Agent == agent && ev.Decision == "would-deny" && ev.Tool != "" {
			counts[ev.Tool]++
		}
	}
	out := make([]ShadowMiss, 0, len(counts))
	for tool, count := range counts {
		out = append(out, ShadowMiss{Tool: tool, Count: count})
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].Count != out[j].Count {
			return out[i].Count > out[j].Count
		}
		return out[i].Tool < out[j].Tool
	})
	return out, nil
}

func readAuditEvents(path string) ([]audit.Event, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()

	return decodeAuditEvents(f, path)
}

func decodeAuditEvents(r io.Reader, path string) ([]audit.Event, error) {
	var out []audit.Event
	sc := bufio.NewScanner(r)
	sc.Buffer(make([]byte, 0, 64*1024), audit.MaxTrailLineBytes)
	for line := 1; sc.Scan(); line++ {
		var ev audit.Event
		if err := json.Unmarshal(sc.Bytes(), &ev); err != nil {
			return nil, fmt.Errorf("%s:%d: %w", path, line, err)
		}
		out = append(out, ev)
	}
	if err := sc.Err(); err != nil {
		return nil, err
	}
	return out, nil
}
