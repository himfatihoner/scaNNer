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

// bindToDevice pins a socket's egress to a named interface (SO_BINDTODEVICE) so
// an in-process Go dial actually leaves via the killswitch's pinned interface —
// not merely with its source IP while the kernel routes it out the default
// interface (where the fail-closed OUTPUT rule then DROPs it). Best-effort: it
// needs CAP_NET_RAW, and any error is swallowed so a dial never fails on the
// bind alone (it just falls back to source-IP binding, the prior behaviour).
func bindToDevice(c syscall.RawConn, iface string) {
	if iface == "" {
		return
	}
	_ = c.Control(func(fd uintptr) {
		_ = syscall.SetsockoptString(int(fd), syscall.SOL_SOCKET, syscall.SO_BINDTODEVICE, iface)
	})
}
