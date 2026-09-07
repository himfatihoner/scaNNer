// Package network's netns layer builds the isolated network namespace
// (scanner-ns) used by scaNNer's outbound killswitch. The Setup/Teardown
// API is platform-specific; this file holds the platform-agnostic
// constants + the exported API surface. Real implementations live in
// netns_linux.go (the only platform that has Linux namespaces) and
// netns_other.go (no-op stubs for everything else).
package network

import "sync/atomic"

const (
	// NamespaceName is the named netns scaNNer creates. The name doubles
	// as the iptables --comment tag so we can identify our own rules.
	NamespaceName   = "scanner-ns"
	HostVethName    = "scanner0" // host side of the veth pair
	NsVethName      = "scanner1" // namespace side
	HostVethIP      = "10.200.0.1"
	NsVethIP        = "10.200.0.2"
	VethCIDR        = "10.200.0.0/24"
	IptablesComment = "scaNNer-killswitch"

	// ScanFwMark is the firewall mark stamped on scan sockets via SO_MARK
	// (shared.BoundDialer's Control hook) so the host OUTPUT killswitch rule
	// can single out SCAN egress in scan_only mode. Kept here so the iptables
	// rule (network pkg) and the setsockopt (shared pkg, which imports this
	// pkg) reference one source of truth.
	ScanFwMark = 0x5343 // "SC"

	// KillswitchScope values — how far the host OUTPUT fail-closed rules reach.
	KillswitchScopeScanOnly   = "scan_only"   // confine only SO_MARK'd scan egress
	KillswitchScopeAllTraffic = "all_traffic" // confine ALL of the scanner's egress
)

// killswitchScope holds the admin-chosen OUTPUT-rule scope. It is set (before
// Setup) from Settings at the save handler + startup; Setup() and HealthCheck()
// read it here so the monitor's self-heal Setup(iface) call needs no extra
// parameter — avoiding a signature change across every arm site.
var killswitchScope atomic.Value // holds string

// SetKillswitchScope records the scope for subsequent Setup()/HealthCheck().
// Unknown/empty values normalise to the safe default (scan_only).
func SetKillswitchScope(scope string) {
	if scope != KillswitchScopeAllTraffic {
		scope = KillswitchScopeScanOnly
	}
	killswitchScope.Store(scope)
}

// KillswitchScope returns the current scope, defaulting to scan_only.
func KillswitchScope() string {
	if v, ok := killswitchScope.Load().(string); ok && v != "" {
		return v
	}
	return KillswitchScopeScanOnly
}
