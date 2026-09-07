package secrets

import (
	"fmt"
	"io"
	"os"
	"strings"
	"syscall"
)

// Resolver resolves a secret reference string (e.g. "env:GITHUB_TOKEN" or
// "file:/etc/nockguard/secret") to its plaintext value. Implementations must
// fail closed on any error: unresolved ref, missing file, permission issues, etc.
// The resolver is called at forward time, not load time, so credential rotation
// works without restart.
type Resolver interface {
	Resolve(ref string) (string, error)
}

// Chain creates a resolver that tries multiple schemes: env: then file:,
// then any future schemes. Unknown schemes return unresolved.
func Chain() Resolver {
	return &chainResolver{}
}

type chainResolver struct{}

func (c *chainResolver) Resolve(ref string) (string, error) {
	if strings.HasPrefix(ref, "env:") {
		name := strings.TrimPrefix(ref, "env:")
		val := os.Getenv(name)
		if val == "" {
			return "", fmt.Errorf("env var %q unset", name)
		}
		return val, nil
	}
	if strings.HasPrefix(ref, "file:") {
		path := strings.TrimPrefix(ref, "file:")
		return resolveFile(path)
	}
	// Unknown scheme
	return "", fmt.Errorf("unknown secret scheme in %q", ref)
}

// resolveFile reads a secret from an absolute file path with strict security checks.
// The file must be a regular file with mode <= 0600, owned by the proxy's euid or 0.
// Read from the open fd (fstat, not stat). Refuse symlinks outright (O_NOFOLLOW).
// Trim one trailing newline if present.
func resolveFile(path string) (string, error) {
	// Absolute path check
	if !strings.HasPrefix(path, "/") {
		return "", fmt.Errorf("file path not absolute: %q", path)
	}

	// Open with O_NOFOLLOW to reject symlinks, and read-only
	fd, err := os.OpenFile(path, os.O_RDONLY|syscall.O_NOFOLLOW, 0)
	if err != nil {
		return "", fmt.Errorf("failed to open %q: %w", path, err)
	}
	defer fd.Close()

	// fstat the open fd to check permissions and ownership
	fi, err := fd.Stat()
	if err != nil {
		return "", fmt.Errorf("failed to stat %q: %w", path, err)
	}

	// Validate file
	if err := validateFileStats(fi.Mode(), fi.IsDir()); err != nil {
		return "", fmt.Errorf("file %q fails security check: %w", path, err)
	}

	// Check owner UID and permissions
	sys := fi.Sys().(*syscall.Stat_t)
	euid := os.Geteuid()
	if sys.Uid != uint32(euid) && sys.Uid != 0 {
		return "", fmt.Errorf("file %q owned by uid %d, not %d or 0", path, sys.Uid, euid)
	}

	// Read content from the validated fd with size limit (64 KiB)
	// Use 64*1024+1 to detect if file exceeds the limit
	data, err := io.ReadAll(io.LimitReader(fd, 64*1024+1))
	if err != nil {
		return "", fmt.Errorf("failed to read %q: %w", path, err)
	}
	if len(data) > 64*1024 {
		return "", fmt.Errorf("secret file %q exceeds 64 KiB", path)
	}

	// Trim one trailing newline
	val := strings.TrimSuffix(string(data), "\n")
	return val, nil
}

// validateFileStats checks that a file's mode and type are appropriate for a secret.
// The file must be regular with mode no more permissive than 0600.
func validateFileStats(mode os.FileMode, isDir bool) error {
	if isDir {
		return fmt.Errorf("is a directory, not a file")
	}
	if !mode.IsRegular() {
		return fmt.Errorf("not a regular file")
	}
	// Check permissions: mode & 0777 should be <= 0600
	// If there are any bits set outside 0600, fail
	perms := mode & 0777
	if perms&0o077 != 0 {
		return fmt.Errorf("file mode %#o more permissive than 0600", perms)
	}
	return nil
}

// KnownScheme reports whether ref starts with a supported secret scheme prefix.
// Used at policy load time to validate inject rules early.
func KnownScheme(ref string) bool {
	return strings.HasPrefix(ref, "env:") || strings.HasPrefix(ref, "file:")
}
