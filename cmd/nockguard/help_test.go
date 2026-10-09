package main

import (
	"io/fs"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

func TestSubcommandHelpNoSideEffects(t *testing.T) {
	if args := os.Getenv("NOCKGUARD_HELP_TEST_ARGS"); args != "" {
		os.Exit(runCLI(strings.Fields(args)))
	}

	commands := []string{
		"init", "init --force", "init --policy", "proxy", "mcp-http", "mcp-listen", "mcp-gateway",
		"egress-proxy", "verify", "verify --session", "verify --export",
		"selftest", "policy", "policy propose", "policy shadow-report",
		"trust", "trust show", "audit", "audit verify", "audit verify --agent", "evidence",
		"keygen", "version",
	}
	for _, command := range commands {
		for _, helpFlag := range []string{"--help", "-h"} {
			t.Run(command+" "+helpFlag, func(t *testing.T) {
				root := t.TempDir()
				home := filepath.Join(root, "home")
				work := filepath.Join(root, "work")
				config := filepath.Join(home, ".config")
				data := filepath.Join(home, ".local", "share")
				cache := filepath.Join(home, ".cache")
				state := filepath.Join(home, ".local", "state")
				runtime := filepath.Join(home, ".run")
				for _, dir := range []string{home, work, config, data, cache, state, runtime} {
					if err := os.MkdirAll(dir, 0700); err != nil {
						t.Fatal(err)
					}
				}
				baseline := make(map[string]bool)
				if err := filepath.WalkDir(root, func(path string, _ fs.DirEntry, err error) error {
					baseline[path] = true
					return err
				}); err != nil {
					t.Fatal(err)
				}
				cmd := exec.Command(os.Args[0], "-test.run=^TestSubcommandHelpNoSideEffects$")
				cmd.Dir = work
				cmd.Env = append(os.Environ(),
					"NOCKGUARD_HELP_TEST_ARGS="+command+" "+helpFlag,
					"HOME="+home,
					"XDG_CONFIG_HOME="+config,
					"XDG_DATA_HOME="+data,
					"XDG_CACHE_HOME="+cache,
					"XDG_STATE_HOME="+state,
					"XDG_RUNTIME_DIR="+runtime,
				)
				output, err := cmd.CombinedOutput()
				if err != nil {
					t.Errorf("%s %s: exit = %v, want 0; output:\n%s", command, helpFlag, err, output)
				}
				if !strings.Contains(string(output), "Usage:") {
					t.Errorf("%s %s: missing usage text; output:\n%s", command, helpFlag, output)
				}
				walkErr := filepath.WalkDir(root, func(path string, _ fs.DirEntry, err error) error {
					if err != nil {
						return err
					}
					if !baseline[path] {
						t.Errorf("%s %s: created path %s", command, helpFlag, path)
					}
					return nil
				})
				if walkErr != nil {
					t.Fatal(walkErr)
				}
			})
		}
	}
}
