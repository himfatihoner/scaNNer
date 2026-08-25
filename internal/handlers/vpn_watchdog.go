package handlers

import (
	"context"
	"fmt"
	"net"
	"os/exec"
	"strings"
	"time"
)

// VPN watchdog helpers. The connectivity monitor (connectivity.go) uses these
// when Settings has VPNAutoReconnect on: it watches the VPN device directly so a
// tunnel drop is caught even while the box still has plain internet via another
// interface (the exact split-DNS/leak case), pauses running scans, and actively
// brings the tunnel back with nmcli.

const vpnReconnectCooldown = 30 * time.Second // minimum spacing between reconnect attempts

// vpnInterfaceHealthy reports whether the named device (e.g. "tun0") is UP and
// carries a real (non-loopback, non-link-local) IPv4 — i.e. the tunnel is live.
// A missing device, an admin-DOWN device, or one with no routable IPv4 (the
// "zombie" state where NetworkManager still reports the VPN connected) all read
// as unhealthy.
func vpnInterfaceHealthy(name string) bool {
	if name == "" {
		return false
	}
	ifi, err := net.InterfaceByName(name)
	if err != nil {
		return false
	}
	if ifi.Flags&net.FlagUp == 0 {
		return false
	}
	addrs, err := ifi.Addrs()
	if err != nil {
		return false
	}
	for _, a := range addrs {
		var ip net.IP
		switch v := a.(type) {
		case *net.IPNet:
			ip = v.IP
		case *net.IPAddr:
			ip = v.IP
		}
		if ip4 := ip.To4(); ip4 != nil && !ip4.IsLoopback() && !ip4.IsLinkLocalUnicast() {
			return true
		}
	}
	return false
}

// reconnectVPN forces the named NetworkManager connection back to a real tunnel
// with a DOWN→UP bounce. A plain `up` is a no-op when NetworkManager still
// believes the connection is active — the exact "zombie" case (NM reports the
// VPN connected while tun0 is actually dead, and it never reconnected after a
// silent server-side drop/ping-restart). Bringing it down first evicts the
// stale instance so the up re-establishes a live tunnel.
//
// Each nmcli call tries plain invocation first (works in an active user session
// or with a polkit rule); on an authorization failure it retries under
// passwordless sudo (scripts/install.sh provisions the scoped sudoers rule).
// NOT routed through shared.Command — nmcli is a host control command and must
// never be wrapped in the killswitch network namespace.
func reconnectVPN(name string) error {
	if strings.TrimSpace(name) == "" {
		return fmt.Errorf("no VPN connection name configured")
	}
	nm := func(action string) ([]byte, error) {
		run := func(bin string, args ...string) ([]byte, error) {
			ctx, cancel := context.WithTimeout(context.Background(), 45*time.Second)
			defer cancel()
			return exec.CommandContext(ctx, bin, args...).CombinedOutput()
		}
		out, err := run("nmcli", "connection", action, "id", name)
		if err == nil {
			return out, nil
		}
		low := strings.ToLower(string(out) + " " + err.Error())
		// Only an authorization failure is worth the sudo retry; "unknown
		// connection" / "not active" / timeout wouldn't be helped by it.
		if strings.Contains(low, "not authorized") || strings.Contains(low, "permission") ||
			strings.Contains(low, "insufficient") || strings.Contains(low, "authoriz") {
			return run("sudo", "-n", "nmcli", "connection", action, "id", name)
		}
		return out, err
	}
	// down is best-effort: it "fails" when the connection is already inactive,
	// which is fine — we only care that up succeeds.
	_, _ = nm("down")
	if out, err := nm("up"); err != nil {
		return fmt.Errorf("nmcli up %q failed: %v: %s", name, err, strings.TrimSpace(string(out)))
	}
	return nil
}
