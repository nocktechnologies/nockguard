package policy

import (
	"os"
	"path/filepath"
	"strings"

	"github.com/nocktechnologies/nockguard/internal/validate"
	"gopkg.in/yaml.v3"
)

type Config struct {
	Agents map[string]AgentPolicy `yaml:"agents"`
}

type AgentPolicy struct {
	Allow []string `yaml:"allow"`
	Deny  []string `yaml:"deny"`
	Mode  string   `yaml:"mode"` // "allow" or "deny"
	// Phase 2 input validation (opt-in). ValidateInput lists built-in rule
	// categories ("sqli", "path_traversal", "secrets"); BlockParams adds
	// custom regexes. Empty = no validation (Phase 1 behavior preserved).
	ValidateInput []string `yaml:"validate_input"`
	BlockParams   []string `yaml:"block_params"`
}

type Engine struct {
	config Config
}

func Load(path string) (*Engine, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var cfg Config
	if err := yaml.Unmarshal(data, &cfg); err != nil {
		return nil, err
	}
	return &Engine{config: cfg}, nil
}

func (e *Engine) Check(agent, tool string) bool {
	pol, ok := e.config.Agents[agent]
	if !ok {
		pol, ok = e.config.Agents["default"]
		if !ok {
			return true
		}
	}

	for _, pattern := range pol.Deny {
		if matchPattern(pattern, tool) {
			return false
		}
	}

	if len(pol.Allow) > 0 {
		for _, pattern := range pol.Allow {
			if matchPattern(pattern, tool) {
				return true
			}
		}
		return false
	}

	if pol.Mode == "deny" {
		return false
	}
	return true
}

// ValidatorFor builds the input validator for an agent (falling back to the
// "default" policy). Returns a nil validator if the agent has no validation
// configured — callers should treat a nil/disabled validator as "no checks".
func (e *Engine) ValidatorFor(agent string) (*validate.Validator, error) {
	pol, ok := e.config.Agents[agent]
	if !ok {
		pol = e.config.Agents["default"]
	}
	if len(pol.ValidateInput) == 0 && len(pol.BlockParams) == 0 {
		return nil, nil
	}
	return validate.New(pol.ValidateInput, pol.BlockParams)
}

func (e *Engine) FilterTools(agent string, tools []string) []string {
	var allowed []string
	for _, t := range tools {
		if e.Check(agent, t) {
			allowed = append(allowed, t)
		}
	}
	return allowed
}

func matchPattern(pattern, tool string) bool {
	if strings.Contains(pattern, "*") {
		matched, _ := filepath.Match(pattern, tool)
		return matched
	}
	return pattern == tool
}
