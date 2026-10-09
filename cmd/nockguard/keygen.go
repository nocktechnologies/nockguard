package main

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/nocktechnologies/nockguard/internal/policy"
	"golang.org/x/sys/unix"
)

// runKeygen generates a fresh Ed25519 keypair for non-repudiable audit signing.
// By default the seed and public key are written to ~/.nockguard/keys/<name>.ed25519
// (0600) and <name>.pub (0644); only the paths and the public key are printed, so
// the secret never reaches a terminal, shell log or agent transcript. Without
// --agent the name is "default", the same identity zero-config observe mode uses.
// --print-env restores the legacy behavior: print env assignment lines, write no files.
func runKeygen(args []string) int {
	var agentName string
	var force, printEnv bool
	for i := 0; i < len(args); i++ {
		name, value, hasValue := strings.Cut(args[i], "=")
		switch name {
		case "--agent":
			if !hasValue {
				if i+1 >= len(args) {
					fmt.Fprintln(os.Stderr, "error: --agent requires a value")
					return 1
				}
				i++
				value = args[i]
			}
			agentName = value
			if !policy.ValidAgentName(agentName) {
				fmt.Fprintf(os.Stderr, "error: invalid agent name %q: only alphanumerics, hyphens, and dots are allowed\n", agentName)
				return 1
			}
		case "--force", "--print-env":
			if hasValue {
				fmt.Fprintf(os.Stderr, "error: flag %s takes no value\n", name)
				return 1
			}
			if name == "--force" {
				force = true
			} else {
				printEnv = true
			}
		default:
			fmt.Fprintf(os.Stderr, "error: unknown flag %q\n", args[i])
			return 1
		}
	}
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		fmt.Fprintf(os.Stderr, "keygen failed: %v\n", err)
		return 1
	}
	seedHex, pubHex := hex.EncodeToString(priv.Seed()), hex.EncodeToString(pub)

	if printEnv {
		fmt.Fprintln(os.Stderr, "WARNING: --print-env prints the PRIVATE seed to stdout. It is secret: it will land in terminal scrollback and any log capturing this output. No key files were written.")
		keyEnv, pubEnv, who := "NOCKGUARD_AUDIT_ED25519_KEY", "NOCKGUARD_AUDIT_ED25519_PUB", "audit signing"
		if agentName != "" {
			keyEnv, pubEnv, who = policy.AgentKeyEnvName(agentName), policy.AgentPubKeyEnvName(agentName), "agent: "+agentName
		}
		fmt.Printf("# Ed25519 keypair for %s\n", who)
		fmt.Printf("# PRIVATE seed — secret. Set in the proxy environment; never commit.\n")
		fmt.Printf("%s=%s\n\n", keyEnv, seedHex)
		fmt.Printf("# PUBLIC key — share with verifiers. Cannot produce signatures.\n")
		fmt.Printf("%s=%s\n", pubEnv, pubHex)
		return 0
	}

	name := agentName
	if name == "" {
		name = defaultObserveAgent
	}
	home, err := os.UserHomeDir()
	if err != nil {
		fmt.Fprintf(os.Stderr, "error: cannot determine home directory: %v\n", err)
		return 1
	}
	replaced, err := writeKeyFiles(home, name, seedHex, pubHex, force)
	if err != nil {
		fmt.Fprintf(os.Stderr, "keygen failed: %v\n", err)
		return 1
	}
	if replaced {
		fmt.Fprintf(os.Stderr, "warning: replaced the existing key for %q; trails signed by the old key will no longer verify.\n", name)
	}
	fmt.Printf("private seed (secret, 0600): %s\n", policy.AgentSeedPath(home, name))
	fmt.Printf("public key   (shareable):    %s\n", policy.AgentPubPath(home, name))
	fmt.Printf("public key hex: %s\n", pubHex)
	return 0
}

// writeKeyFiles publishes <name>.ed25519 and <name>.pub into ~/.nockguard/keys.
// It refuses a symlink at either file always, and an existing file unless force.
// The state directories are opened no-follow and validated (owner, no group/other
// access) by openOrCreateObserveDir, the same code zero-config observe uses.
func writeKeyFiles(home, name, seedHex, pubHex string, force bool) (replaced bool, err error) {
	homeDir, err := os.Open(home)
	if err != nil {
		return false, fmt.Errorf("opening home dir %s: %w", home, err)
	}
	defer homeDir.Close()
	nockguardDir, err := openOrCreateObserveDir(int(homeDir.Fd()), ".nockguard", 0o700, unix.Fsync)
	if err != nil {
		return false, fmt.Errorf("opening nockguard state dir: %w", err)
	}
	defer nockguardDir.Close()
	keyDir, err := openOrCreateObserveDir(int(nockguardDir.Fd()), "keys", 0o700, unix.Fsync)
	if err != nil {
		return false, fmt.Errorf("opening key dir: %w", err)
	}
	defer keyDir.Close()

	seedName, pubName := name+".ed25519", name+".pub"
	for _, n := range []string{seedName, pubName} {
		path := filepath.Join(policy.AgentKeyDir(home), n)
		var st unix.Stat_t
		err := unix.Fstatat(int(keyDir.Fd()), n, &st, unix.AT_SYMLINK_NOFOLLOW)
		if errors.Is(err, unix.ENOENT) {
			continue
		}
		if err != nil {
			return false, fmt.Errorf("checking %s: %w", path, err)
		}
		if st.Mode&unix.S_IFMT == unix.S_IFLNK {
			return false, fmt.Errorf("%s is a symlink; refusing to write through it", path)
		}
		if !force {
			return false, fmt.Errorf("%s already exists; pass --force to replace it", path)
		}
		replaced = true
	}
	if err := publishKeyFile(keyDir, seedName, []byte(seedHex), 0o600, force); err != nil {
		return false, fmt.Errorf("writing %s: %w", seedName, err)
	}
	if err := publishKeyFile(keyDir, pubName, []byte(pubHex), 0o644, force); err != nil {
		return false, fmt.Errorf("writing %s: %w", pubName, err)
	}
	return replaced, nil
}

// publishKeyFile writes data to dir/name via a complete same-directory temp file
// (O_EXCL|O_NOFOLLOW, fsynced). replace=false links it into place and fails with
// EEXIST rather than overwrite; replace=true renames over the target. Readers can
// therefore only ever observe the whole file.
func publishKeyFile(dir *os.File, name string, data []byte, perm uint32, replace bool) error {
	dfd := int(dir.Fd())
	var (
		f        *os.File
		tempName string
	)
	for range 32 {
		var suffix [16]byte
		if _, err := rand.Read(suffix[:]); err != nil {
			return fmt.Errorf("creating temporary key name: %w", err)
		}
		tempName = ".key-" + hex.EncodeToString(suffix[:])
		fd, err := unix.Openat(dfd, tempName, unix.O_WRONLY|unix.O_CREAT|unix.O_EXCL|unix.O_NOFOLLOW|unix.O_CLOEXEC, perm)
		if errors.Is(err, unix.EEXIST) {
			continue
		}
		if err != nil {
			return fmt.Errorf("creating temporary key: %w", err)
		}
		f = os.NewFile(uintptr(fd), tempName)
		break
	}
	if f == nil {
		return errors.New("creating temporary key: could not choose a unique name")
	}
	defer unix.Unlinkat(dfd, tempName, 0)
	if err := unix.Fchmod(int(f.Fd()), perm); err != nil {
		_ = f.Close()
		return fmt.Errorf("setting permissions: %w", err)
	}
	if _, err := f.Write(data); err != nil {
		_ = f.Close()
		return fmt.Errorf("writing temporary key: %w", err)
	}
	if err := f.Sync(); err != nil {
		_ = f.Close()
		return fmt.Errorf("syncing temporary key: %w", err)
	}
	if err := f.Close(); err != nil {
		return fmt.Errorf("closing temporary key: %w", err)
	}
	var err error
	if replace {
		err = unix.Renameat(dfd, tempName, dfd, name)
	} else {
		err = unix.Linkat(dfd, tempName, dfd, name, 0)
	}
	if err != nil {
		return err
	}
	// The new directory entry is only durable once the directory itself is fsynced.
	if err := unix.Fsync(dfd); err != nil {
		return fmt.Errorf("syncing key dir: %w", err)
	}
	return nil
}

// requirePubHex returns the hex public key a verifier should use. pubEnv is the
// env var the caller settled on; when it is the agent's canonical one (not an
// explicit --ed25519-pub-env override), an unset var falls back to the agent's
// ~/.nockguard/keys/<agent>.pub. Not finding a key is an error naming where it looked.
func requirePubHex(pubEnv, agent string) (string, error) {
	if agent == "" || pubEnv != policy.AgentPubKeyEnvName(agent) {
		if v := os.Getenv(pubEnv); v != "" {
			return v, nil
		}
		return "", fmt.Errorf("%s is not set in the environment", pubEnv)
	}
	v, err := policy.ResolveAgentPub(agent)
	if err != nil || v != "" {
		return v, err
	}
	hint := ""
	if home, herr := os.UserHomeDir(); herr == nil {
		hint = fmt.Sprintf(" and %s does not exist (create it with `nockguard keygen --agent %s`)", policy.AgentPubPath(home, agent), agent)
	}
	return "", fmt.Errorf("%s is not set in the environment%s", pubEnv, hint)
}
