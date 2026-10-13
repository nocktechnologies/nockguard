//go:build !linux

package proxy

import "os/exec"

func observeLeaderExit(cmd *exec.Cmd) <-chan error {
	ch := make(chan error, 1)
	go func() { ch <- cmd.Wait() }()
	return ch
}

func reapLeader(_ *exec.Cmd, observed error) error { return observed }
