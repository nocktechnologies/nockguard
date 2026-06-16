//go:build !unix

package audit

// On non-unix platforms NockGuard does not take a cross-process file lock; the
// in-process mutex still serializes writers within a single process. NockGuard
// targets unix fleets (macOS + Linux), so this fallback exists only to keep the
// package building everywhere, not to provide multi-process safety off-unix.
func lockExclusive(fd uintptr) error { return nil }

func unlockFile(fd uintptr) error { return nil }
