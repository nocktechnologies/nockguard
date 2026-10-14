package policy

import (
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"testing"
)

// TestMain points HOME at an empty directory so per-agent key-file lookups never
// read the developer's real ~/.nockguard/keys.
func TestMain(m *testing.M) {
	home, err := os.MkdirTemp("", "policy-test-home-")
	if err != nil {
		panic(err)
	}
	os.Setenv("HOME", home)
	code := m.Run()
	if err := removeHome(home); err != nil {
		fmt.Fprintln(os.Stderr, "test home cleanup failed:", err)
		code = 1
	}
	os.Exit(code)
}

// removeHome makes read-only directories (such as 0500 key dirs) writable so
// RemoveAll can delete them, and reports any failure.
func removeHome(home string) error {
	_ = filepath.WalkDir(home, func(path string, d fs.DirEntry, err error) error {
		if err == nil && d.IsDir() {
			_ = os.Chmod(path, 0o700)
		}
		return nil
	})
	return os.RemoveAll(home)
}
