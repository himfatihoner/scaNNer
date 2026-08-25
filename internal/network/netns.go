// Package network's netns layer builds the isolated network namespace
// (scanner-ns) used by scaNNer's outbound killswitch. The Setup/Teardown
// API is platform-specific; this file holds the platform-agnostic
// constants + the exported API surface. Real implementations live in
// netns_linux.go (the only platform that has Linux namespaces) and
// netns_other.go (no-op stubs for everything else).
package network

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
)
