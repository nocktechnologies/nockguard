package proxy

import (
	"errors"
	"os/exec"

	"golang.org/x/sys/unix"
)

// waitid observes the leader's exit without reaping it. Its PID remains
// reserved until Run has killed the process group and calls cmd.Wait.
func observeLeaderExit(cmd *exec.Cmd) <-chan error {
	ch := make(chan error, 1)
	go func() {
		var info unix.Siginfo
		for {
			err := unix.Waitid(unix.P_PID, cmd.Process.Pid, &info, unix.WEXITED|unix.WNOWAIT, nil)
			if errors.Is(err, unix.EINTR) {
				continue
			}
			ch <- err
			return
		}
	}()
	return ch
}

func reapLeader(cmd *exec.Cmd, observed error) error {
	if observed != nil {
		_ = cmd.Wait()
		return observed
	}
	return cmd.Wait()
}
