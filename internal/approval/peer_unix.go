//go:build linux || darwin

package approval

import (
	"net"
	"os"
	"syscall"
)

func peerUID(c net.Conn) (uint32, error) {
	raw, err := c.(*net.UnixConn).SyscallConn()
	if err != nil {
		return 0, err
	}
	var uid uint32
	var serr error
	if err := raw.Control(func(fd uintptr) { uid, serr = peerCred(int(fd)) }); err != nil {
		return 0, err
	}
	return uid, serr
}

func fileOwner(fi os.FileInfo) (uint32, bool) {
	st, ok := fi.Sys().(*syscall.Stat_t)
	if !ok {
		return 0, false
	}
	return st.Uid, true
}
