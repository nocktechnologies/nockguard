package policy

import (
	"os"
	"path/filepath"
	"strings"

	"gopkg.in/yaml.v3"
)

type Config struct {
	Agents  map[string]AgentPolicy `yaml:"agents"`
}

type AgentPolicy struct {
	Allow []string `yaml:"allow"`
	Deny  []string `yaml:"deny"`
	Mode  string   `yaml:"mode"` // "allow" or "deny"
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
