//go:build !linux

package shared

import "syscall"

// markSocket is a no-op on non-Linux platforms (SO_MARK is Linux-only). The
// killswitch itself is Linux-only (see netns_other.go), so nothing is lost.
func markSocket(c syscall.RawConn, mark int) {}

// bindToDevice is a no-op on non-Linux (SO_BINDTODEVICE is Linux-only; the
// killswitch itself is Linux-only too).
func bindToDevice(c syscall.RawConn, iface string) {}
