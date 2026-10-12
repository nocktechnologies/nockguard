//go:build !linux && !darwin

package approval

import (
	"errors"
	"net"
	"os"
)

// No peer-credential support: the local approver cannot prove who is deciding,
// so it never starts (every ask fails closed).
func peerUID(net.Conn) (uint32, error) {
	return 0, errors.New("peer credentials unsupported on this platform")
}
func fileOwner(os.FileInfo) (uint32, bool) { return 0, false }
