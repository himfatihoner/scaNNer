//go:build linux

package shared

import "syscall"

// markSocket stamps SO_MARK (Linux fwmark) on a socket so the host OUTPUT
// killswitch rule can recognise scan egress. Best-effort: any setsockopt error
// is swallowed here and the caller ignores it — a missing CAP_NET_ADMIN (e.g.
// default routing mode) must never fail a dial.
func markSocket(c syscall.RawConn, mark int) {
	_ = c.Control(func(fd uintptr) {
		_ = syscall.SetsockoptInt(int(fd), syscall.SOL_SOCKET, syscall.SO_MARK, mark)
	})
}
