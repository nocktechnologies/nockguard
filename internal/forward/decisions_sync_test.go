package forward

import (
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"testing"
)

// emitPatterns find every decision string Go source writes into an audit or
// forwarded event. A new emit site that is not matched here still fails closed
// at the Wall (the unknown value lands in "other"); a new value at a matched
// site fails this test until decisionBuckets and the Wall filter learn it.
var emitPatterns = []*regexp.Regexp{
	regexp.MustCompile(`appendAudit\w*\([^,]+,[^,]+,\s*"([a-z-]+)"`),
	regexp.MustCompile(`\.audit(?:Method)?\([^,]+,\s*"([a-z-]+)"`),
	regexp.MustCompile(`enqueueBudgetEvent\([^,]+,[^,]+,\s*"([a-z-]+)"`),
	regexp.MustCompile(`deferredAudit\{"([a-z-]+)"`),
	regexp.MustCompile(`\bDecision:\s*"([a-z-]+)"`),
	regexp.MustCompile(`\bdecision\s*:?=\s*"([a-z-]+)"`),
}

func goSourceDecisions(t *testing.T) []string {
	t.Helper()
	seen := map[string]bool{}
	for _, root := range []string{"../../internal", "../../cmd"} {
		err := filepath.Walk(root, func(path string, info os.FileInfo, err error) error {
			if err != nil || info.IsDir() || !strings.HasSuffix(path, ".go") || strings.HasSuffix(path, "_test.go") {
				return err
			}
			src, rerr := os.ReadFile(path)
			if rerr != nil {
				return rerr
			}
			for _, re := range emitPatterns {
				for _, m := range re.FindAllStringSubmatch(string(src), -1) {
					seen[m[1]] = true
				}
			}
			return nil
		})
		if err != nil {
			t.Fatal(err)
		}
	}
	return sortedKeys(seen)
}

func sortedKeys(m map[string]bool) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

func TestWallDecisionFilterMatchesCurrentAndHistoricalDecisions(t *testing.T) {
	emitted := goSourceDecisions(t)
	if len(emitted) < 10 {
		t.Fatalf("scan found only %v; the emit patterns no longer match the source", emitted)
	}
	// Old signed trails still contain the synthetic approval row removed in 0.10.0 cleanup.
	readable := append(emitted, "state-write")
	sort.Strings(readable)
	known := map[string]bool{}
	for d := range decisionBuckets {
		if d != "" && d != DecisionUnparseable { // unparseable is Wall-synthesized, never written to the audit log
			known[d] = true
		}
	}
	if got, want := strings.Join(readable, ","), strings.Join(sortedKeys(known), ","); got != want {
		t.Fatalf("decisionBuckets differs from current and historical decisions:\n readable: %s\n buckets: %s", got, want)
	}
	page, err := os.ReadFile("../../cmd/nockguard-wall/index.html")
	if err != nil {
		t.Fatal(err)
	}
	sel := regexp.MustCompile(`(?s)<select id="f-decision".*?</select>`).FindString(string(page))
	filter := map[string]bool{}
	for _, m := range regexp.MustCompile(`<option value="([a-z-]+)"`).FindAllStringSubmatch(sel, -1) {
		filter[m[1]] = true
	}
	if got, want := strings.Join(sortedKeys(filter), ","), strings.Join(readable, ","); got != want {
		t.Fatalf("Wall decision filter differs from current and historical decisions:\n filter: %s\n readable: %s", got, want)
	}
}
