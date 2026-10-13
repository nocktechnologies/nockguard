package approval

import (
	"crypto/rand"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"log"
	"net"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"sync"
	"syscall"
	"time"
)

// Darwin's sockaddr_un.sun_path is 104 bytes including the terminator. Keep
// paths below that limit so the same bound is safe on supported Unix systems.
const maxUnixSocketPathBytes = 100

// Twenty PID digits, a hyphen, sixteen random hex digits, and ".sock".
const maxLocalSocketName = "18446744073709551615-0123456789abcdef.sock"

// LocalApprover holds a call until the operator decides it over a unix socket on
// the same machine — no network. The socket lives at <dir>/<pid>-<16 hex>.sock
// (random, so two proxies never collide); dir is
// 0700 and the socket 0600, both owned by the proxy's uid, and newLocal refuses
// to start (the caller then has no approver and every ask fails CLOSED) if that
// cannot be proven.
//
// Trust boundary: the channel is protected by filesystem permissions and a
// peer-uid check, nothing more. A process running as the SAME user as the proxy
// can open the socket and approve its own calls, so an agent that runs as the
// operator's uid is not stopped by this approver alone. Run the agent as a
// different uid, or fence ~/.nockguard away from it (for example NockLock's
// filesystem fence), to make the boundary real.
//
// The listing and the audit trail carry the agent, tool and reason only — never
// the call's arguments.
type LocalApprover struct {
	timeout time.Duration
	uid     uint32
	ln      net.Listener
	base    string // socket file name without ".sock"; prefix of every hold id

	// beforeTimeoutCheck is a test seam: it runs when the timer fires, before
	// Ask looks at the hold, so a test can force a decision into that window.
	beforeTimeoutCheck func()

	mu      sync.Mutex
	n       int
	pending map[string]*localHold
}

type localHold struct {
	Pending
	decide chan Verdict
}

// Pending is one held call as shown to the operator. No arguments.
type Pending struct {
	ID     string `json:"id"`
	Agent  string `json:"agent"`
	Tool   string `json:"tool"`
	Reason string `json:"reason"`
	AgeSec int64  `json:"age_s"`

	since time.Time
}

type localMsg struct {
	Op      string    `json:"op"`
	ID      string    `json:"id,omitempty"`
	Approve bool      `json:"approve,omitempty"`
	Pending []Pending `json:"pending,omitempty"`
	OK      bool      `json:"ok,omitempty"`
	Error   string    `json:"error,omitempty"`
}

// DefaultLocalDir is ~/.nockguard/approvals unless that would make the longest
// local socket name exceed the safe Unix socket path length. Long home or temp
// paths use a private per-uid directory under the resolved /tmp instead.
func DefaultLocalDir() (string, error) {
	home, err := os.UserHomeDir()
	if err != nil {
		return "", err
	}
	dir := filepath.Join(home, ".nockguard", "approvals")
	if len(filepath.Join(dir, maxLocalSocketName)) <= maxUnixSocketPathBytes {
		return dir, nil
	}
	tmp, err := filepath.EvalSymlinks("/tmp")
	if err != nil {
		return "", fmt.Errorf("resolve short local approver directory /tmp: %w", err)
	}
	dir = filepath.Join(tmp, fmt.Sprintf("nockguard-%d", os.Getuid()), "approvals")
	if n := len(filepath.Join(dir, maxLocalSocketName)); n > maxUnixSocketPathBytes {
		return "", fmt.Errorf("short local approver Unix socket path is %d bytes, exceeding the safe limit of %d", n, maxUnixSocketPathBytes)
	}
	return dir, nil
}

// NewLocalApprover creates dir (0700) if absent, verifies it and its parent, and
// listens on a fresh <pid>-<random>.sock. It never removes anything it did not
// create: leftovers from crashed proxies are harmless and `approvals prune`
// clears them.
func NewLocalApprover(dir string, timeout time.Duration) (*LocalApprover, error) {
	maxSock := filepath.Join(dir, maxLocalSocketName)
	if n := len(maxSock); n > maxUnixSocketPathBytes {
		return nil, fmt.Errorf("local approver Unix socket path is too long (%d bytes; maximum %d): %s", n, maxUnixSocketPathBytes, maxSock)
	}
	uid := uint32(os.Getuid())
	// Create only what is absent, and refuse a symlink before creating anything
	// beneath it, so nothing is ever made through a symlink.
	parent := filepath.Dir(dir)
	if err := mkdirIfAbsent(parent); err != nil {
		return nil, err
	}
	if err := checkParentDir(parent, uid); err != nil {
		return nil, err
	}
	if err := mkdirIfAbsent(dir); err != nil {
		return nil, err
	}
	if err := checkClientDir(dir); err != nil {
		return nil, err
	}
	var rnd [8]byte
	if _, err := rand.Read(rnd[:]); err != nil {
		return nil, err
	}
	base := fmt.Sprintf("%d-%x", os.Getpid(), rnd)
	sock := filepath.Join(dir, base+".sock")
	ln, err := net.Listen("unix", sock)
	if err != nil {
		return nil, fmt.Errorf("bind local approver Unix socket %s: %w", sock, err)
	}
	if err := os.Chmod(sock, 0o600); err != nil {
		ln.Close()
		return nil, err
	}
	if err := checkOwned(sock, uid, os.ModeSocket, 0o600); err != nil {
		ln.Close()
		return nil, err
	}
	a := &LocalApprover{timeout: timeout, uid: uid, ln: ln, base: base, pending: map[string]*localHold{}}
	go a.serve()
	return a, nil
}

// Close stops listening; closing the listener unlinks this approver's own socket
// and nothing else.
func (a *LocalApprover) Close() error { return a.ln.Close() }

// checkOwned fails unless path is (not a symlink) of kind, owned by uid, with exactly perm.
func checkOwned(path string, uid uint32, kind os.FileMode, perm os.FileMode) error {
	fi, err := os.Lstat(path)
	if err != nil {
		return err
	}
	if fi.Mode()&os.ModeType != kind {
		return fmt.Errorf("%s: unexpected file type %v", path, fi.Mode().Type())
	}
	if fi.Mode().Perm() != perm {
		return fmt.Errorf("%s has mode %04o, want %04o (refusing: approvals channel must be operator-only)", path, fi.Mode().Perm(), perm)
	}
	if owner, ok := fileOwner(fi); !ok || owner != uid {
		return fmt.Errorf("%s is not owned by uid %d", path, uid)
	}
	return nil
}

// Ask holds the call until the operator decides or the timeout elapses.
func (a *LocalApprover) Ask(req Request) Verdict {
	h := &localHold{
		Pending: Pending{Agent: req.Agent, Tool: req.Tool, Reason: req.Reason, since: time.Now()},
		decide:  make(chan Verdict, 1),
	}
	a.mu.Lock()
	a.n++
	h.ID = fmt.Sprintf("%s-%d", a.base, a.n)
	a.pending[h.ID] = h
	a.mu.Unlock()
	defer func() {
		a.mu.Lock()
		delete(a.pending, h.ID)
		a.mu.Unlock()
	}()

	t := time.NewTimer(a.timeout)
	defer t.Stop()
	select {
	case v := <-h.decide:
		return v
	case <-t.C:
		if a.beforeTimeoutCheck != nil {
			a.beforeTimeoutCheck()
		}
		// Check and delete under one lock: either the timeout owns the hold (a
		// later decide gets "no such pending call") or a decide already took it
		// and its verdict, already reported to the operator, is honored.
		a.mu.Lock()
		_, still := a.pending[h.ID]
		delete(a.pending, h.ID)
		a.mu.Unlock()
		if !still {
			return <-h.decide
		}
		return Verdict{Approved: false, Reason: "timeout"}
	}
}

func (a *LocalApprover) serve() {
	var delay time.Duration
	for {
		c, err := a.ln.Accept()
		if err != nil {
			if errors.Is(err, net.ErrClosed) {
				return
			}
			if acceptTemporary(err) {
				log.Printf("nockguard: local approver accept: %v (retrying)", err)
				if delay == 0 {
					delay = 5 * time.Millisecond
				} else if delay *= 2; delay > time.Second {
					delay = time.Second
				}
				time.Sleep(delay)
				continue
			}
			log.Printf("nockguard: local approver STOPPED accepting: %v — every held call will now time out and be denied", err)
			return
		}
		delay = 0
		go a.handle(c)
	}
}

func acceptTemporary(err error) bool {
	var ne net.Error
	return errors.Is(err, syscall.EMFILE) || errors.Is(err, syscall.ENFILE) ||
		errors.Is(err, syscall.ECONNABORTED) || (errors.As(err, &ne) && ne.Timeout())
}

func (a *LocalApprover) handle(c net.Conn) {
	defer c.Close()
	_ = c.SetDeadline(time.Now().Add(10 * time.Second))
	peer, err := peerUID(c)
	if err != nil || peer != a.uid {
		return // wrong or unknowable peer: say nothing, decide nothing
	}
	var m localMsg
	if json.NewDecoder(io.LimitReader(c, 4096)).Decode(&m) != nil {
		return
	}
	var resp localMsg
	switch m.Op {
	case "list":
		a.mu.Lock()
		for _, h := range a.pending {
			p := h.Pending
			p.AgeSec = int64(time.Since(h.since).Seconds())
			resp.Pending = append(resp.Pending, p)
		}
		a.mu.Unlock()
		resp.OK = true
	case "decide":
		a.mu.Lock()
		h, ok := a.pending[m.ID]
		delete(a.pending, m.ID)
		a.mu.Unlock()
		if !ok {
			resp.Error = "no such pending call (decided, timed out, or wrong id)"
			break
		}
		who := fmt.Sprintf("local:%d", peer)
		verb := "denied"
		if m.Approve {
			verb = "approved"
		}
		h.decide <- Verdict{Approved: m.Approve, Reason: verb + " by " + who}
		resp.OK = true
	default:
		resp.Error = "unknown op"
	}
	_ = json.NewEncoder(c).Encode(resp)
}

// checkClientDir refuses to talk to sockets under dir unless dir (and its
// parent, typically ~/.nockguard) are real directories owned by us and dir is
// 0700, so a planted symlink or foreign directory cannot feed us a fake server.
// The proxy applies the same check before listening, so both sides agree.
func checkClientDir(dir string) error {
	uid := uint32(os.Getuid())
	if err := checkParentDir(filepath.Dir(dir), uid); err != nil {
		return err
	}
	return checkOwned(dir, uid, os.ModeDir, 0o700)
}

// mkdirIfAbsent creates d (0700) only when Lstat says nothing is there. A
// concurrent first-run proxy may win the race; EEXIST is success here because
// the caller re-checks type, owner and mode on whatever now exists.
func mkdirIfAbsent(d string) error {
	if _, err := os.Lstat(d); !errors.Is(err, fs.ErrNotExist) {
		return err
	}
	if err := os.Mkdir(d, 0o700); err != nil && !errors.Is(err, fs.ErrExist) {
		return err
	}
	return nil
}

// checkParentDir fails unless parent is a plain directory (not a symlink) owned by uid.
func checkParentDir(parent string, uid uint32) error {
	fi, err := os.Lstat(parent)
	if err != nil {
		return err
	}
	if !fi.IsDir() {
		return fmt.Errorf("%s is not a plain directory (symlink?); refusing", parent)
	}
	if owner, ok := fileOwner(fi); !ok || owner != uid {
		return fmt.Errorf("%s is not owned by uid %d; refusing", parent, uid)
	}
	return nil
}

// localCall dials sock and talks to it only if the socket is ours (0600, our
// uid) and the server on the other end runs as our uid.
func localCall(sock string, m localMsg) (localMsg, error) {
	uid := uint32(os.Getuid())
	if err := checkOwned(sock, uid, os.ModeSocket, 0o600); err != nil {
		return localMsg{}, err
	}
	c, err := net.DialTimeout("unix", sock, 2*time.Second)
	if err != nil {
		return localMsg{}, err
	}
	defer c.Close()
	if peer, err := peerUID(c); err != nil || peer != uid {
		return localMsg{}, fmt.Errorf("%s: server is not running as uid %d; refusing", sock, uid)
	}
	_ = c.SetDeadline(time.Now().Add(10 * time.Second))
	if err := json.NewEncoder(c).Encode(m); err != nil {
		return localMsg{}, err
	}
	var r localMsg
	if err := json.NewDecoder(c).Decode(&r); err != nil {
		return localMsg{}, err
	}
	if r.Error != "" {
		return r, errors.New(r.Error)
	}
	return r, nil
}

// ListPending asks every live proxy under dir for its held calls, oldest first.
// Sockets nobody answers on (a proxy that exited) are skipped, never removed;
// PruneStale is the explicit operator command for that.
func ListPending(dir string) ([]Pending, error) {
	if err := checkClientDir(dir); err != nil {
		return nil, err
	}
	socks, err := filepath.Glob(filepath.Join(dir, "*.sock"))
	if err != nil {
		return nil, err
	}
	var all []Pending
	for _, s := range socks {
		r, err := localCall(s, localMsg{Op: "list"})
		if err == nil {
			all = append(all, r.Pending...)
		}
	}
	sort.Slice(all, func(i, j int) bool { return all[i].AgeSec > all[j].AgeSec })
	return all, nil
}

// sockBase matches the socket name stem <pid>-<16 hex>.
var sockBase = regexp.MustCompile(`^[0-9]+-[0-9a-f]{16}$`)

// Decide approves or denies held call id (as printed by ListPending).
func Decide(dir, id string, approve bool) error {
	i := strings.LastIndex(id, "-")
	if i < 0 || !sockBase.MatchString(id[:i]) {
		return fmt.Errorf("malformed id %q", id)
	}
	if err := checkClientDir(dir); err != nil {
		return err
	}
	_, err := localCall(filepath.Join(dir, id[:i]+".sock"), localMsg{Op: "decide", ID: id, Approve: approve})
	return err
}

// PruneStale removes sockets under dir that are owned by our uid and refuse
// two dials 1 s apart (ECONNREFUSED: nobody is listening). On macOS a full
// listen backlog also reports ECONNREFUSED, so one refusal is not proof; run it
// when no proxies are running. Anything else — a live socket, a non-socket, a
// foreign owner, or any other dial error — is left alone. It returns the
// removed paths.
func PruneStale(dir string) ([]string, error) {
	if err := checkClientDir(dir); err != nil {
		return nil, err
	}
	socks, err := filepath.Glob(filepath.Join(dir, "*.sock"))
	if err != nil {
		return nil, err
	}
	uid := uint32(os.Getuid())
	var removed []string
	for _, s := range socks {
		fi, err := os.Lstat(s)
		if err != nil || fi.Mode()&os.ModeType != os.ModeSocket {
			continue
		}
		if owner, ok := fileOwner(fi); !ok || owner != uid {
			continue
		}
		if !refusedTwice(s) {
			continue
		}
		if err := os.Remove(s); err != nil {
			return removed, err
		}
		removed = append(removed, s)
	}
	return removed, nil
}

// refusedTwice reports whether two dials of sock, 1 s apart, were both refused.
func refusedTwice(sock string) bool {
	for i := 0; i < 2; i++ {
		if i > 0 {
			time.Sleep(time.Second)
		}
		c, err := net.DialTimeout("unix", sock, time.Second)
		if err == nil {
			c.Close()
			return false
		}
		if !errors.Is(err, syscall.ECONNREFUSED) {
			return false
		}
	}
	return true
}
