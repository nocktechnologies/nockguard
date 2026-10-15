package policy

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestWardenPolicyExamplesLoadWithStrictPolicyLoader(t *testing.T) {
	examples := []struct {
		name    string
		path    string
		start   string
		end     string
		asAgent bool
	}{
		{
			name:  "README policy example",
			path:  filepath.Join("..", "..", "templates", "warden", "README.md"),
			start: "## Example policy suggestion",
			end:   "## Security skills",
		},
		{
			name:    "threat-model rate and spend limits",
			path:    filepath.Join("..", "..", ".claude", "commands", "threat-model.md"),
			start:   "## Step 5",
			end:     "## Step 6",
			asAgent: true,
		},
		{
			name:  "vuln-scan allow-all diagnostic example",
			path:  filepath.Join("..", "..", ".claude", "commands", "vuln-scan.md"),
			start: "### 2a. Allow-all agents",
			end:   "### 2b. Missing default agent",
		},
	}

	for _, example := range examples {
		t.Run(example.name, func(t *testing.T) {
			markdown, err := os.ReadFile(example.path)
			if err != nil {
				t.Fatal(err)
			}
			snippet, err := yamlFenceBetween(string(markdown), example.start, example.end)
			if err != nil {
				t.Fatal(err)
			}
			if example.asAgent {
				snippet = wrapAgentPolicy(snippet)
			}
			if _, err := LoadBytes(snippet); err != nil {
				t.Fatalf("example does not pass the strict policy loader: %v", err)
			}
		})
	}
}

func yamlFenceBetween(markdown, start, end string) ([]byte, error) {
	sectionStart := strings.Index(markdown, start)
	if sectionStart < 0 {
		return nil, fmt.Errorf("section start %q not found", start)
	}
	sectionEnd := strings.Index(markdown[sectionStart+len(start):], end)
	if sectionEnd < 0 {
		return nil, fmt.Errorf("section end %q not found", end)
	}
	section := markdown[sectionStart+len(start) : sectionStart+len(start)+sectionEnd]
	fenceStart := strings.Index(section, "```yaml\n")
	if fenceStart < 0 {
		return nil, fmt.Errorf("YAML fence not found between %q and %q", start, end)
	}
	fenceStart += len("```yaml\n")
	fenceEnd := strings.Index(section[fenceStart:], "\n```")
	if fenceEnd < 0 {
		return nil, fmt.Errorf("YAML fence is not closed between %q and %q", start, end)
	}
	return []byte(section[fenceStart : fenceStart+fenceEnd]), nil
}

func wrapAgentPolicy(agentYAML []byte) []byte {
	lines := strings.Split(strings.TrimSuffix(string(agentYAML), "\n"), "\n")
	var policy strings.Builder
	policy.WriteString("agents:\n  coder:\n")
	for _, line := range lines {
		policy.WriteString("    ")
		policy.WriteString(line)
		policy.WriteByte('\n')
	}
	return []byte(policy.String())
}
