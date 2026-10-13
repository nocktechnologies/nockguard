package proxy

import (
	"os/exec"
	"syscall"
	"unsafe"
)

// Darwin exposes waitid as syscall 173, but Go does not wrap it. WNOWAIT
// observes exit without freeing the leader's PID before process-group cleanup.
func observeLeaderExit(cmd *exec.Cmd) <-chan error {
	ch := make(chan error, 1)
	go func() {
		const pPID = 1 // Darwin's P_PID idtype_t value.
		// siginfo_t fits in this aligned buffer; its fields are not inspected.
		var info [32]uint64
		for {
			_, _, errno := syscall.Syscall6(syscall.SYS_WAITID, pPID, uintptr(cmd.Process.Pid),
				uintptr(unsafe.Pointer(&info[0])), syscall.WEXITED|syscall.WNOWAIT, 0, 0)
			if errno == syscall.EINTR {
				continue
			}
			if errno != 0 {
				ch <- errno
			} else {
				ch <- nil
			}
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
