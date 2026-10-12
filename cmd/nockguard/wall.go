package main

import (
	"errors"
	"fmt"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"syscall"
)

func runWall(args []string) int {
	wallPath := ""
	if executable, err := os.Executable(); err == nil {
		candidate := filepath.Join(filepath.Dir(executable), "nockguard-wall")
		if info, err := os.Stat(candidate); err == nil && !info.IsDir() {
			wallPath = candidate
		}
	}
	if wallPath == "" {
		var err error
		wallPath, err = exec.LookPath("nockguard-wall")
		if err != nil {
			fmt.Fprintln(os.Stderr, "error: nockguard-wall is not installed beside nockguard or on PATH")
			return 1
		}
	}

	cmd := exec.Command(wallPath, args...)
	cmd.Stdin, cmd.Stdout, cmd.Stderr = os.Stdin, os.Stdout, os.Stderr
	signals := make(chan os.Signal, 1)
	signal.Notify(signals, os.Interrupt, syscall.SIGHUP, syscall.SIGTERM)
	defer signal.Stop(signals)
	if err := cmd.Start(); err != nil {
		fmt.Fprintf(os.Stderr, "error starting nockguard-wall: %v\n", err)
		return 1
	}
	finished, forwarded := make(chan struct{}), make(chan struct{})
	go func() {
		defer close(forwarded)
		for {
			select {
			case sig := <-signals:
				_ = cmd.Process.Signal(sig)
			case <-finished:
				return
			}
		}
	}()
	err := cmd.Wait()
	close(finished)
	<-forwarded
	if err != nil {
		var exitErr *exec.ExitError
		if errors.As(err, &exitErr) {
			if exitCode := exitErr.ExitCode(); exitCode >= 0 {
				return exitCode
			}
			return 1
		}
		fmt.Fprintf(os.Stderr, "error waiting for nockguard-wall: %v\n", err)
		return 1
	}
	return 0
}
