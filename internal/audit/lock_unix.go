//go:build unix

package audit

import "syscall"

// lockExclusive takes an advisory exclusive (LOCK_EX) flock on the open file.
// flock is keyed to the open file description, so two processes — each with its
// own open of the same audit file — mutually exclude. This is what makes the
// hash chain safe across processes, which the in-process mutex alone cannot do.
func lockExclusive(fd uintptr) error { return syscall.Flock(int(fd), syscall.LOCK_EX) }

// LockShared blocks signed appends while an export captures its checkpoint and trail.
func LockShared(fd uintptr) error { return syscall.Flock(int(fd), syscall.LOCK_SH) }

// UnlockFile releases either kind of flock.
func UnlockFile(fd uintptr) error { return syscall.Flock(int(fd), syscall.LOCK_UN) }
