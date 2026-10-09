package policy

import (
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"

	"golang.org/x/sys/unix"
)

// AgentKeyDir is where `nockguard keygen` stores per-agent keys: ~/.nockguard/keys.
func AgentKeyDir(home string) string { return filepath.Join(home, ".nockguard", "keys") }

// AgentSeedPath is the private seed file for an agent (hex, mode 0600).
func AgentSeedPath(home, agent string) string {
	return filepath.Join(AgentKeyDir(home), agent+".ed25519")
}

// AgentPubPath is the public key file for an agent (hex, mode 0644).
func AgentPubPath(home, agent string) string {
	return filepath.Join(AgentKeyDir(home), agent+".pub")
}

// ResolveAgentSeed returns the agent's hex signing seed. The env var
// (AgentKeyEnvName) wins; otherwise ~/.nockguard/keys/<agent>.ed25519 is used, but
// only if it is a regular, non-symlink file owned by the current user with no
// group/other permission bits. An unsafe, unreadable or empty file is an error,
// never a quiet fallback to a weaker signing mode. An empty result with a nil
// error means no key is configured, including when the home directory cannot be
// resolved (there is then no key file to find).
func ResolveAgentSeed(agent string) (string, error) {
	v, _, err := resolveAgentKey(AgentKeyEnvName(agent), AgentSeedPath, agent, true)
	return v, err
}

// ResolveAgentPub is the verifier-side counterpart of ResolveAgentSeed: the env
// var (AgentPubKeyEnvName) wins, then ~/.nockguard/keys/<agent>.pub, which must be
// a regular, non-symlink file owned by the current user and not group/other
// writable. source names where a non-empty key came from: the env var name or the
// file path. An empty key with a nil error means neither exists.
func ResolveAgentPub(agent string) (key, source string, err error) {
	return resolveAgentKey(AgentPubKeyEnvName(agent), AgentPubPath, agent, false)
}

func resolveAgentKey(envName string, path func(home, agent string) string, agent string, secret bool) (key, source string, err error) {
	if v := os.Getenv(envName); v != "" {
		return v, envName, nil
	}
	home, herr := os.UserHomeDir()
	if herr != nil {
		return "", "", nil
	}
	p := path(home, agent)
	key, err = readAgentKeyFile(p, secret)
	if key == "" || err != nil {
		return "", "", err
	}
	return key, p, nil
}

// readAgentKeyFile reads a hex key file through a no-follow descriptor. secret
// files must have no group/other bits; public files must not be group/other
// writable. A missing file or key directory yields ("", nil); a file that exists
// but is empty is an error.
func readAgentKeyFile(path string, secret bool) (string, error) {
	dir := filepath.Dir(path)
	var dst unix.Stat_t
	if err := unix.Lstat(dir, &dst); err != nil {
		if errors.Is(err, unix.ENOENT) {
			return "", nil
		}
		return "", err
	}
	if dst.Mode&unix.S_IFMT != unix.S_IFDIR {
		return "", fmt.Errorf("key directory %s is a symlink or not a directory", dir)
	}
	if dst.Uid != uint32(os.Geteuid()) {
		return "", fmt.Errorf("key directory %s owner uid = %d, want %d", dir, dst.Uid, os.Geteuid())
	}
	if mode := uint32(dst.Mode) & 0o777; mode&0o022 != 0 {
		return "", fmt.Errorf("key directory %s permissions = %o: group/other writable", dir, mode)
	}

	// O_NONBLOCK: opening a FIFO read-only would otherwise hang before the regular-file check.
	fd, err := unix.Open(path, unix.O_RDONLY|unix.O_NOFOLLOW|unix.O_NONBLOCK|unix.O_CLOEXEC, 0)
	if errors.Is(err, unix.ENOENT) {
		return "", nil
	}
	if errors.Is(err, unix.ELOOP) {
		return "", fmt.Errorf("key file %s is a symlink", path)
	}
	if err != nil {
		return "", err
	}
	f := os.NewFile(uintptr(fd), path)
	defer f.Close()
	var st unix.Stat_t
	if err := unix.Fstat(fd, &st); err != nil {
		return "", err
	}
	if st.Mode&unix.S_IFMT != unix.S_IFREG {
		return "", fmt.Errorf("key file %s is not a regular file", path)
	}
	if st.Uid != uint32(os.Geteuid()) {
		return "", fmt.Errorf("key file %s owner uid = %d, want %d", path, st.Uid, os.Geteuid())
	}
	mode := uint32(st.Mode) & 0o777
	if secret && mode&0o077 != 0 {
		return "", fmt.Errorf("key file %s permissions = %o: group/other accessible; run chmod 600 or regenerate with `nockguard keygen --force`", path, mode)
	}
	if !secret && mode&0o022 != 0 {
		return "", fmt.Errorf("key file %s permissions = %o: group/other writable", path, mode)
	}
	b, err := io.ReadAll(io.LimitReader(f, 4096))
	if err != nil {
		return "", err
	}
	key := strings.TrimSpace(string(b))
	if key == "" {
		return "", fmt.Errorf("key file %s is empty", path)
	}
	return key, nil
}
