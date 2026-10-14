package policy

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestWardenExamplePolicyLoadsWithIncidentContextOutsideYAML(t *testing.T) {
	path := filepath.Join("..", "..", "templates", "warden", "README.md")
	markdown, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	doc := string(markdown)
	section := strings.Index(doc, "## Example policy suggestion")
	if section < 0 {
		t.Fatal("Warden README has no example policy suggestion")
	}
	start := strings.Index(doc[section:], "```yaml\n")
	if start < 0 {
		t.Fatal("Warden example policy YAML block not found")
	}
	start += section + len("```yaml\n")
	end := strings.Index(doc[start:], "\n```")
	if end < 0 {
		t.Fatal("Warden example policy YAML block is not closed")
	}
	policyYAML := []byte(doc[start : start+end])
	if _, err := LoadBytes(policyYAML); err != nil {
		t.Fatalf("Warden example policy does not pass the strict policy loader: %v", err)
	}

	contextStart := start + end + len("\n```")
	nextHeading := strings.Index(doc[contextStart:], "\n## ")
	if nextHeading < 0 {
		nextHeading = len(doc) - contextStart
	}
	context := doc[contextStart : contextStart+nextHeading]
	for _, rule := range []string{"read_file"} {
		if !strings.Contains(context, "Incident context for `"+rule+"`: No verified reference found.") {
			t.Errorf("missing out-of-YAML no-reference context for %q", rule)
		}
	}
}
