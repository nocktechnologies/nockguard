package main

import (
	"os"
	"testing"
)

// TestMain points HOME at an empty directory so per-agent key-file lookups never
// read the developer's real ~/.nockguard/keys.
func TestMain(m *testing.M) {
	home, err := os.MkdirTemp("", "nockguard-test-home-")
	if err != nil {
		panic(err)
	}
	os.Setenv("HOME", home)
	code := m.Run()
	os.RemoveAll(home)
	os.Exit(code)
}
