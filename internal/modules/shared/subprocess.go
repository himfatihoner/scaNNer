package shared

import (
	"context"
	"os/exec"

	scannet "scanner/internal/network"
)

// Command builds a namespace-aware *exec.Cmd. Every external-tool spawn
// in scaNNer (nmap, nuclei, wpscan, hydra, smbclient, snmpwalk,
// theHarvester, whatweb, etc.) should construct its command through
// this helper rather than calling exec.CommandContext directly.
//
// Resolution:
//
//   - Killswitch active  → returns `ip netns exec scanner-ns <name> <args>`
//   - Killswitch dormant → returns plain exec.CommandContext(ctx, name, args...)
//
// API is identical to exec.CommandContext: same return type, same
// pipe/Wait/Output semantics. Callers attach StdoutPipe, set
// Cmd.Env, etc. unchanged — the namespace wrapping is invisible.
//
// Centralizing this means a single edit changes binding semantics
// across all 20+ spawn sites; previously each one would need its
// own iface-flag injection (the approach we just reverted).
func Command(ctx context.Context, name string, args ...string) *exec.Cmd {
	var cmd *exec.Cmd
	if scannet.IsActive() {
		cmd = scannet.Exec(ctx, name, args...)
	} else {
		cmd = exec.CommandContext(ctx, name, args...)
	}
	// Every spawn runs in its OWN process group, and on context cancellation
	// (scan cancel, killswitch trip, or a per-tool timeout) the WHOLE group is
	// killed — not just the direct child. Without this, two classes of process
	// survive the scan and keep running in the background after it is marked
	// done:
	//   1. Killswitch armed: the direct child is `ip netns exec`, which
	//      fork+execs the real tool (nmap/sslscan/openssl/…) as a GRANDCHILD.
	//      exec's default cancel SIGKILLs only `ip`, orphaning the tool inside
	//      the namespace.
	//   2. Wrapper tools that fork their own children (theHarvester/python,
	//      recon-ng, amass, bloodhound-python, puredns): killing the wrapper
	//      leaves the children running.
	// See subprocess_unix.go / subprocess_other.go.
	applyProcessGroupKill(cmd)
	return cmd
}
