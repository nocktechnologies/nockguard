package policy

import (
	"bufio"
	"encoding/json"
	"fmt"
	"os"
	"sort"

	"github.com/nocktechnologies/nockguard/internal/audit"
)

type ShadowMiss struct {
	Tool  string
	Count int
}

func ProposeShadowFromAudit(agent, path string) ([]string, error) {
	events, err := readAuditEvents(path)
	if err != nil {
		return nil, err
	}
	seen := map[string]struct{}{}
	for _, ev := range events {
		if ev.Agent == agent && ev.Decision == "allow" && ev.Tool != "" {
			seen[ev.Tool] = struct{}{}
		}
	}
	tools := make([]string, 0, len(seen))
	for tool := range seen {
		tools = append(tools, tool)
	}
	sort.Strings(tools)
	return tools, nil
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

	var out []audit.Event
	sc := bufio.NewScanner(f)
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
