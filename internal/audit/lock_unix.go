//go:build unix

package audit

import "syscall"

// lockExclusive takes an advisory exclusive (LOCK_EX) flock on the open file.
// flock is keyed to the open file description, so two processes — each with its
// own open of the same audit file — mutually exclude. This is what makes the
// hash chain safe across processes, which the in-process mutex alone cannot do.
func lockExclusive(fd uintptr) error { return syscall.Flock(int(fd), syscall.LOCK_EX) }

// unlockFile releases the flock taken by lockExclusive.
func unlockFile(fd uintptr) error { return syscall.Flock(int(fd), syscall.LOCK_UN) }
