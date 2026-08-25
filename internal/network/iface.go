// Package network centralizes outbound-binding helpers. scaNNer uses
// this to:
//
//   - List system network interfaces for the Settings dropdown.
//   - Resolve a user-selected interface to its primary IPv4 (so we can
//     hand the resulting net.IP to net.Dialer.LocalAddr).
//   - Verify at scan-time that the selected interface is still UP and
//     still carries the expected IPv4 — the runtime killswitch's
//     trigger condition.
//
// All operations are user-space; no CAP_NET_RAW or root required.
package network

import (
	"errors"
	"fmt"
	"net"
	"strings"
)

// InterfaceInfo is the at-a-glance shape rendered by the Settings UI
// and consumed by the SettingsSave handler when validating a user
// choice. Includes both IPv4 and IPv6 addresses so the dropdown can
// show them as a hint; only the first IPv4 is actually used for
// binding.
type InterfaceInfo struct {
	Name     string   // "eth0", "tun0", "wlan0", "lo"
	IPv4     string   // primary IPv4 — empty if none assigned
	IPv6     []string // any link-local + global IPv6
	Up       bool     // interface is administratively UP
	Loopback bool     // user shouldn't normally pick this
}

// Display returns "eth0 — 192.168.1.50" or "tun0 (no IPv4)" for the
// dropdown.
func (i InterfaceInfo) Display() string {
	if i.IPv4 == "" {
		return fmt.Sprintf("%s (no IPv4)", i.Name)
	}
	return fmt.Sprintf("%s — %s", i.Name, i.IPv4)
}

// ListInterfaces enumerates every system network interface and returns
// a stable, sorted-by-name slice suitable for rendering as a dropdown.
// Down interfaces are included so the user can SEE them disabled —
// hiding them entirely would make "where did tun0 go?" debugging hard.
// Loopback is included with Loopback=true so the UI can dim it.
func ListInterfaces() ([]InterfaceInfo, error) {
	ifaces, err := net.Interfaces()
	if err != nil {
		return nil, fmt.Errorf("list interfaces: %w", err)
	}
	out := make([]InterfaceInfo, 0, len(ifaces))
	for _, iface := range ifaces {
		info := InterfaceInfo{
			Name:     iface.Name,
			Up:       iface.Flags&net.FlagUp != 0,
			Loopback: iface.Flags&net.FlagLoopback != 0,
		}
		addrs, _ := iface.Addrs()
		for _, addr := range addrs {
			// addr is *net.IPNet like "192.168.1.50/24"; trim mask.
			ipNet, ok := addr.(*net.IPNet)
			if !ok {
				continue
			}
			ip := ipNet.IP
			if v4 := ip.To4(); v4 != nil {
				if info.IPv4 == "" {
					info.IPv4 = v4.String()
				}
			} else {
				info.IPv6 = append(info.IPv6, ip.String())
			}
		}
		out = append(out, info)
	}
	return out, nil
}

// ResolvePrimaryIPv4 looks up a single interface by name and returns
// its first assigned IPv4 address. Used at settings-save time to cache
// the IP in AppSettings.NetworkInterfaceIP so the runtime monitor can
// detect if the interface's IP changes later (e.g. VPN reconnect with
// a new lease).
//
// Returns ErrInterfaceNotFound if the name doesn't resolve at all,
// ErrInterfaceNoIPv4 if it has no IPv4 assigned (down VPN, etc).
func ResolvePrimaryIPv4(name string) (string, error) {
	name = strings.TrimSpace(name)
	if name == "" {
		return "", ErrInterfaceNotFound
	}
	iface, err := net.InterfaceByName(name)
	if err != nil {
		return "", fmt.Errorf("%w: %s", ErrInterfaceNotFound, name)
	}
	addrs, err := iface.Addrs()
	if err != nil {
		return "", fmt.Errorf("get addrs for %s: %w", name, err)
	}
	for _, addr := range addrs {
		ipNet, ok := addr.(*net.IPNet)
		if !ok {
			continue
		}
		if v4 := ipNet.IP.To4(); v4 != nil {
			return v4.String(), nil
		}
	}
	return "", fmt.Errorf("%w: %s", ErrInterfaceNoIPv4, name)
}

// CheckInterfaceUp is the pre-flight gate used before every scan
// starts AND the runtime monitor's per-tick health check. Verifies:
//
//  1. The named interface still exists.
//  2. Its administrative flag is UP.
//  3. Its primary IPv4 still matches the expected value (so a
//     VPN reconnect that handed out a new IP doesn't silently route
//     scans through the new address — the user-pinned IP is what
//     mattered when settings were saved).
//
// expectedIPv4 may be empty; in that case only #1 and #2 are checked
// (used by tests and by the initial save path).
func CheckInterfaceUp(name, expectedIPv4 string) error {
	if name == "" {
		// Default mode — no check needed.
		return nil
	}
	iface, err := net.InterfaceByName(name)
	if err != nil {
		return fmt.Errorf("%w: %s", ErrInterfaceNotFound, name)
	}
	if iface.Flags&net.FlagUp == 0 {
		return fmt.Errorf("%w: %s", ErrInterfaceDown, name)
	}
	if expectedIPv4 == "" {
		return nil
	}
	addrs, err := iface.Addrs()
	if err != nil {
		return fmt.Errorf("get addrs for %s: %w", name, err)
	}
	for _, addr := range addrs {
		ipNet, ok := addr.(*net.IPNet)
		if !ok {
			continue
		}
		if v4 := ipNet.IP.To4(); v4 != nil && v4.String() == expectedIPv4 {
			return nil
		}
	}
	return fmt.Errorf("%w: %s no longer has %s", ErrInterfaceIPChanged, name, expectedIPv4)
}

// Errors are sentinel values so callers (settings UI, killswitch, scan
// handlers) can branch on them with errors.Is. Each one maps to a
// distinct user-visible message.
var (
	ErrInterfaceNotFound  = errors.New("interface not found")
	ErrInterfaceDown      = errors.New("interface is down")
	ErrInterfaceNoIPv4    = errors.New("interface has no IPv4 address")
	ErrInterfaceIPChanged = errors.New("interface IP changed since settings were saved")
)
