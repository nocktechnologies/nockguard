package approval

import "golang.org/x/sys/unix"

func peerCred(fd int) (uint32, error) {
	x, err := unix.GetsockoptXucred(fd, unix.SOL_LOCAL, unix.LOCAL_PEERCRED)
	if err != nil {
		return 0, err
	}
	return x.Uid, nil
}
