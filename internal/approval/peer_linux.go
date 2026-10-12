package approval

import "golang.org/x/sys/unix"

func peerCred(fd int) (uint32, error) {
	u, err := unix.GetsockoptUcred(fd, unix.SOL_SOCKET, unix.SO_PEERCRED)
	if err != nil {
		return 0, err
	}
	return u.Uid, nil
}
