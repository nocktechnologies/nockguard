package approval

import (
	"net"
	"os"
	"syscall"

	"golang.org/x/sys/unix"
)

func peerUID(c net.Conn) (uint32, error) {
	raw, err := c.(*net.UnixConn).SyscallConn()
	if err != nil {
		return 0, err
	}
	var uid uint32
	var serr error
	if err := raw.Control(func(fd uintptr) {
		u, e := unix.GetsockoptUcred(int(fd), unix.SOL_SOCKET, unix.SO_PEERCRED)
		if e != nil {
			serr = e
			return
		}
		uid = u.Uid
	}); err != nil {
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
