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
	regexp.MustCompile(`appendAudit\([^,]+,[^,]+,\s*"([a-z-]+)"`),
	regexp.MustCompile(`\.audit\([^,]+,\s*"([a-z-]+)"`),
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

func TestWallDecisionFilterMatchesEmittedDecisions(t *testing.T) {
	emitted := goSourceDecisions(t)
	if len(emitted) < 10 {
		t.Fatalf("scan found only %v; the emit patterns no longer match the source", emitted)
	}
	known := map[string]bool{}
	for d := range decisionBuckets {
		if d != "" && d != DecisionUnparseable { // unparseable is Wall-synthesized, never written to the audit log
			known[d] = true
		}
	}
	if got, want := strings.Join(emitted, ","), strings.Join(sortedKeys(known), ","); got != want {
		t.Fatalf("decisionBuckets differs from decisions emitted in Go source:\n source: %s\n buckets: %s", got, want)
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
	if got, want := strings.Join(sortedKeys(filter), ","), strings.Join(emitted, ","); got != want {
		t.Fatalf("Wall decision filter differs from decisions emitted in Go source:\n filter: %s\n source: %s", got, want)
	}
}
