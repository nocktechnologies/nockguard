package approval

import (
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"
)

// LocalApprover holds a call until the operator decides it over a unix socket on
// the same machine — no network. The socket lives at <dir>/<pid>.sock; dir is
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

// DefaultLocalDir is ~/.nockguard/approvals.
func DefaultLocalDir() (string, error) {
	home, err := os.UserHomeDir()
	if err != nil {
		return "", err
	}
	return filepath.Join(home, ".nockguard", "approvals"), nil
}

// NewLocalApprover creates dir (0700) if absent, verifies it, and listens.
func NewLocalApprover(dir string, timeout time.Duration) (*LocalApprover, error) {
	uid := uint32(os.Getuid())
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return nil, err
	}
	if err := checkOwned(dir, uid, os.ModeDir, 0o700); err != nil {
		return nil, err
	}
	sock := filepath.Join(dir, strconv.Itoa(os.Getpid())+".sock")
	_ = os.Remove(sock) // our own stale socket from a recycled pid
	ln, err := net.Listen("unix", sock)
	if err != nil {
		return nil, err
	}
	if err := os.Chmod(sock, 0o600); err != nil {
		ln.Close()
		return nil, err
	}
	if err := checkOwned(sock, uid, os.ModeSocket, 0o600); err != nil {
		ln.Close()
		return nil, err
	}
	a := &LocalApprover{timeout: timeout, uid: uid, ln: ln, pending: map[string]*localHold{}}
	go a.serve()
	return a, nil
}

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
	h.ID = fmt.Sprintf("%d-%d", os.Getpid(), a.n)
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
		return Verdict{Approved: false, Reason: "timeout"}
	}
}

func (a *LocalApprover) serve() {
	for {
		c, err := a.ln.Accept()
		if err != nil {
			return
		}
		go a.handle(c)
	}
}

func (a *LocalApprover) handle(c net.Conn) {
	defer c.Close()
	_ = c.SetDeadline(time.Now().Add(10 * time.Second))
	peer, err := peerUID(c)
	if err != nil || peer != a.uid {
		return // wrong or unknowable peer: say nothing, decide nothing
	}
	var m localMsg
	if json.NewDecoder(c).Decode(&m) != nil {
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

func localCall(sock string, m localMsg) (localMsg, error) {
	c, err := net.DialTimeout("unix", sock, 2*time.Second)
	if err != nil {
		return localMsg{}, err
	}
	defer c.Close()
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
// Sockets nobody answers on (a proxy that exited) are skipped.
func ListPending(dir string) ([]Pending, error) {
	socks, err := filepath.Glob(filepath.Join(dir, "*.sock"))
	if err != nil {
		return nil, err
	}
	var all []Pending
	for _, s := range socks {
		if r, err := localCall(s, localMsg{Op: "list"}); err == nil {
			all = append(all, r.Pending...)
		}
	}
	sort.Slice(all, func(i, j int) bool { return all[i].AgeSec > all[j].AgeSec })
	return all, nil
}

// Decide approves or denies held call id (as printed by ListPending).
func Decide(dir, id string, approve bool) error {
	pid, _, ok := strings.Cut(id, "-")
	if _, err := strconv.Atoi(pid); !ok || err != nil {
		return fmt.Errorf("malformed id %q", id)
	}
	_, err := localCall(filepath.Join(dir, pid+".sock"), localMsg{Op: "decide", ID: id, Approve: approve})
	return err
}
