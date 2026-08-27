//go:build linux

package network

import (
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"strings"
	"sync"
	"sync/atomic"
)

// active flips true once Setup() has successfully built the namespace
// + veth + iptables + DNS. Subprocess helper reads this lock-free to
// decide whether to wrap commands with `ip netns exec`.
var active atomic.Bool

// setupMu serializes Setup/Teardown so a concurrent SettingsSave +
// startup race can't double-install or double-delete rules.
var setupMu sync.Mutex

// lastSetupError stores the most recent Setup() failure string. Surfaced
// in the Settings page banner so the user sees WHY the killswitch is off
// — distinct from RequiresPrivilege errors. Examples on Kali rolling:
//
//   - "iptables ... Could not fetch rule set generation id (xtables.lock
//     permission denied)" — process has CAP_NET_ADMIN but can't lock the
//     iptables mutex because /run/xtables.lock is root:root 0600.
//   - "nft: Operation not permitted" — kernel netlink path still requires
//     real root on the current Kali kernel.
//   - "iptable_nat: module not loaded" — modprobe needs CAP_SYS_MODULE.
//
// Empty string when the last Setup either succeeded or never ran. Cleared
// on successful Setup so a recovered system doesn't show stale errors.
var lastSetupErrorStore atomic.Pointer[string]

// LastSetupError returns the most recent setup-failure message, or empty
// when Setup last succeeded / hasn't been invoked. Safe to call from any
// goroutine.
func LastSetupError() string {
	if p := lastSetupErrorStore.Load(); p != nil {
		return *p
	}
	return ""
}

func storeSetupError(s string) {
	if s == "" {
		lastSetupErrorStore.Store(nil)
		return
	}
	lastSetupErrorStore.Store(&s)
}

// Setup builds the killswitch environment around targetIface.
//
// Steps (each idempotent in isolation, the whole sequence not):
//
//  1. Teardown any leftover from a previous (crashed) run.
//  2. Verify the target interface exists and is UP.
//  3. `ip netns add scanner-ns`
//  4. `ip link add scanner0 type veth peer name scanner1`
//  5. Move scanner1 into scanner-ns; assign IPs; bring UP; default route.
//  6. Enable host-wide IPv4 forwarding (idempotent sysctl).
//  7. iptables FORWARD ACCEPT (in→targetIface), FORWARD DROP (in→anywhere else),
//     FORWARD ACCEPT (targetIface→in), NAT POSTROUTING MASQUERADE.
//     Every rule tagged with --comment scaNNer-killswitch so Teardown
//     can find and remove exactly our rules.
//  8. DNS: copy host /etc/resolv.conf to /etc/netns/scanner-ns/resolv.conf
//     so a VPN-pushed DNS (already in host's resolv.conf) is honored
//     inside the namespace.
//
// Returns nil + sets IsActive() == true on success. On failure, any
// partial state from this run is rolled back via Teardown.
func Setup(targetIface string) error {
	setupMu.Lock()
	defer setupMu.Unlock()

	// Wrap every return so the most recent failure is observable to the
	// Settings page banner. Success path clears the store at the end.
	var setupErr error
	defer func() {
		if setupErr == nil {
			storeSetupError("")
		} else {
			storeSetupError(setupErr.Error())
		}
	}()

	// Pre-clean a crashed previous run.
	_ = teardownLocked()

	// Sanity: target iface must exist + be UP before we wire anything.
	if err := CheckInterfaceUp(targetIface, ""); err != nil {
		setupErr = fmt.Errorf("target interface not usable: %w", err)
		return setupErr
	}

	// Each ipCmd call returns on first error → caller cleans up.
	steps := [][]string{
		// 1. Namespace
		{"ip", "netns", "add", NamespaceName},
		// 2. veth pair (created in host ns by default)
		{"ip", "link", "add", HostVethName, "type", "veth", "peer", "name", NsVethName},
		// 3. Move ns side into the namespace
		{"ip", "link", "set", NsVethName, "netns", NamespaceName},
		// 4. Host-side IP + UP
		{"ip", "addr", "add", HostVethIP + "/24", "dev", HostVethName},
		{"ip", "link", "set", HostVethName, "up"},
		// 5. Namespace-side IP + UP + lo + default route
		{"ip", "-n", NamespaceName, "addr", "add", NsVethIP + "/24", "dev", NsVethName},
		{"ip", "-n", NamespaceName, "link", "set", NsVethName, "up"},
		{"ip", "-n", NamespaceName, "link", "set", "lo", "up"},
		{"ip", "-n", NamespaceName, "route", "add", "default", "via", HostVethIP},
	}
	for _, step := range steps {
		if err := runStep(step); err != nil {
			_ = teardownLocked()
			setupErr = fmt.Errorf("netns setup step %q: %w", strings.Join(step, " "), err)
			return setupErr
		}
	}

	// Host-wide IP forwarding. The installer sets net.ipv4.ip_forward=1 in a
	// sysctl drop-in, so normally it is already on and we don't need to write
	// /proc/sys (which a non-root service can't do anyway — it's 0644 root). Only
	// attempt the write if it isn't already 1; a failure then is a real problem.
	// We DON'T flip this back in Teardown — other apps might depend on it.
	if cur, _ := os.ReadFile("/proc/sys/net/ipv4/ip_forward"); strings.TrimSpace(string(cur)) != "1" {
		if err := os.WriteFile("/proc/sys/net/ipv4/ip_forward", []byte("1\n"), 0644); err != nil {
			_ = teardownLocked()
			setupErr = fmt.Errorf("enable ip_forward (run installer, or set net.ipv4.ip_forward=1): %w", err)
			return setupErr
		}
	}

	// iptables rules. Order matters: ACCEPT for the allowed path first,
	// then explicit DROP for everything else from veth → host. The DROP
	// is what becomes the killswitch when targetIface goes down — the
	// ACCEPT rule no longer matches because the output device is gone,
	// so packets fall through to the DROP rule.
	rules := [][]string{
		// FORWARD: namespace egress → only via targetIface
		{"iptables", "-A", "FORWARD", "-i", HostVethName, "-o", targetIface, "-j", "ACCEPT", "-m", "comment", "--comment", IptablesComment},
		// FORWARD: namespace egress → anywhere else gets dropped
		{"iptables", "-A", "FORWARD", "-i", HostVethName, "!", "-o", targetIface, "-j", "DROP", "-m", "comment", "--comment", IptablesComment},
		// FORWARD: replies from targetIface back into the namespace
		{"iptables", "-A", "FORWARD", "-i", targetIface, "-o", HostVethName, "-j", "ACCEPT", "-m", "comment", "--comment", IptablesComment},
		// NAT: rewrite source IP so replies come back addressed to us
		{"iptables", "-t", "nat", "-A", "POSTROUTING", "-s", VethCIDR, "-o", targetIface, "-j", "MASQUERADE", "-m", "comment", "--comment", IptablesComment},
	}
	for _, rule := range rules {
		if err := runStep(rule); err != nil {
			_ = teardownLocked()
			setupErr = fmt.Errorf("netns iptables %q: %w", strings.Join(rule, " "), err)
			return setupErr
		}
	}

	// DNS: copy host's current /etc/resolv.conf into the per-netns
	// override location. `ip netns exec` automatically bind-mounts this
	// over /etc/resolv.conf inside the namespace. So a VPN-pushed DNS
	// already in host's resolv.conf comes along for the ride.
	if err := copyResolvConf(); err != nil {
		// Non-fatal — namespace works without DNS for IP-targeted scans.
		// Just log via stderr so it's visible at setup time.
		fmt.Fprintf(os.Stderr, "netns: warning: resolv.conf copy failed: %v\n", err)
	}

	active.Store(true)
	return nil
}

// Teardown reverses Setup. Safe to call multiple times — every step
// is "delete if exists" and errors are non-fatal.
func Teardown() error {
	setupMu.Lock()
	defer setupMu.Unlock()
	return teardownLocked()
}

// teardownLocked is the lock-free worker used by both Setup
// (for pre-clean) and Teardown.
func teardownLocked() error {
	active.Store(false)

	// Remove iptables rules — strictly by comment so we don't disturb
	// rules other apps installed. -D needs the exact rule spec; we
	// iterate the FORWARD + nat POSTROUTING chains looking for our
	// comment tag and delete by line number from the bottom up.
	deleteByComment("iptables", "FORWARD")
	deleteByCommentNat("iptables", "POSTROUTING")

	// Delete veth pair (kernel removes the peer automatically).
	// We delete the host side, which also unhooks scanner1 inside the ns.
	_ = exec.Command("ip", "link", "del", HostVethName).Run()

	// Delete the namespace. This also unhooks any remaining links inside.
	_ = exec.Command("ip", "netns", "del", NamespaceName).Run()

	// Remove DNS override file. /etc/netns/scanner-ns/ is ours to manage.
	_ = os.RemoveAll("/etc/netns/" + NamespaceName)

	return nil
}

// Exec returns an *exec.Cmd that will spawn `name args...` inside
// scanner-ns via `ip netns exec`. Stdin/stdout/stderr inherit the
// usual semantics — caller can attach pipes, redirect, etc.
//
// Context cancellation propagates: ctx done → ip netns exec wrapper
// receives SIGKILL → wrapper exits → child terminated by kernel.
func Exec(ctx context.Context, name string, args ...string) *exec.Cmd {
	full := append([]string{"netns", "exec", NamespaceName, name}, args...)
	return exec.CommandContext(ctx, "ip", full...)
}

// IsActive reports whether the killswitch is live.
func IsActive() bool { return active.Load() }

// HealthCheck inspects every piece of state Setup built. Used by the
// runtime monitor to detect drift (interface dropped, iptables rule
// flushed by another admin tool, etc.). Returns nil on a fully-healthy
// namespace, descriptive error otherwise.
func HealthCheck(targetIface, expectedIP string) error {
	if !IsActive() {
		return errors.New("killswitch not active")
	}
	// 1. Target iface still UP and still on expected IP.
	if err := CheckInterfaceUp(targetIface, expectedIP); err != nil {
		return fmt.Errorf("target interface: %w", err)
	}
	// 2. Namespace still exists.
	if err := exec.Command("ip", "netns", "list").Run(); err != nil {
		return fmt.Errorf("ip netns list: %w", err)
	}
	out, _ := exec.Command("ip", "netns", "list").Output()
	if !strings.Contains(string(out), NamespaceName) {
		return fmt.Errorf("namespace %q missing", NamespaceName)
	}
	// 3. veth pair still wired.
	if err := exec.Command("ip", "link", "show", HostVethName).Run(); err != nil {
		return fmt.Errorf("host veth %q missing", HostVethName)
	}
	// 4. iptables rules still tagged with our comment.
	checkOut, _ := exec.Command("iptables", "-S", "FORWARD").Output()
	if !strings.Contains(string(checkOut), IptablesComment) {
		return fmt.Errorf("iptables FORWARD rules missing")
	}
	return nil
}

// RequiresPrivilege returns nil if scaNNer can manipulate the namespace
// + iptables, or a descriptive error otherwise. setcap or root is fine.
func RequiresPrivilege() error {
	// Probe 1 — iptables: listing the nat table needs CAP_NET_ADMIN and, on
	// Kali, access to /run/xtables.lock (the installer grants both).
	if err := exec.Command("iptables", "-t", "nat", "-S", "POSTROUTING").Run(); err != nil {
		return errors.New("cannot use iptables (needs CAP_NET_ADMIN + /run/xtables.lock access — run: sudo scripts/install.sh)")
	}
	// Probe 2 — namespace: actually create + delete a throwaway netns. This is
	// the operation that most often fails as a non-root service, because it
	// needs CAP_SYS_ADMIN (unshare/mount) AND a writable /run/netns — both set
	// up by the installer. Doing the real op is the only reliable check.
	const probe = "scanner-privprobe"
	_ = exec.Command("ip", "netns", "del", probe).Run() // clear any leftover
	if out, err := exec.Command("ip", "netns", "add", probe).CombinedOutput(); err != nil {
		return fmt.Errorf("cannot create a network namespace (needs CAP_SYS_ADMIN + a writable /run/netns — run: sudo scripts/install.sh): %s", strings.TrimSpace(string(out)))
	}
	_ = exec.Command("ip", "netns", "del", probe).Run()
	return nil
}

// runStep runs a single `ip` / `iptables` command and returns whatever
// CombinedOutput says on failure so caller can log it.
func runStep(argv []string) error {
	cmd := exec.Command(argv[0], argv[1:]...)
	out, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("%w: %s", err, strings.TrimSpace(string(out)))
	}
	return nil
}

// deleteByComment scans a chain for our comment tag and deletes those
// rules by line number, from highest to lowest. Doing it bottom-up
// keeps the line numbers stable as we delete.
func deleteByComment(table, chain string) {
	out, err := exec.Command(table, "-L", chain, "--line-numbers", "-n").Output()
	if err != nil {
		return
	}
	var lines []int
	for _, line := range strings.Split(string(out), "\n") {
		if !strings.Contains(line, IptablesComment) {
			continue
		}
		// Format: "  3   ACCEPT  all  ..." — first field is the index.
		fields := strings.Fields(line)
		if len(fields) == 0 {
			continue
		}
		var idx int
		if _, err := fmt.Sscanf(fields[0], "%d", &idx); err != nil {
			continue
		}
		lines = append(lines, idx)
	}
	// Delete in reverse so each delete doesn't shift the others.
	for i := len(lines) - 1; i >= 0; i-- {
		_ = exec.Command(table, "-D", chain, fmt.Sprintf("%d", lines[i])).Run()
	}
}

// deleteByCommentNat is the nat-table variant. iptables wants `-t nat`
// inserted between the binary name and the chain selector.
func deleteByCommentNat(table, chain string) {
	out, err := exec.Command(table, "-t", "nat", "-L", chain, "--line-numbers", "-n").Output()
	if err != nil {
		return
	}
	var lines []int
	for _, line := range strings.Split(string(out), "\n") {
		if !strings.Contains(line, IptablesComment) {
			continue
		}
		fields := strings.Fields(line)
		if len(fields) == 0 {
			continue
		}
		var idx int
		if _, err := fmt.Sscanf(fields[0], "%d", &idx); err != nil {
			continue
		}
		lines = append(lines, idx)
	}
	for i := len(lines) - 1; i >= 0; i-- {
		_ = exec.Command(table, "-t", "nat", "-D", chain, fmt.Sprintf("%d", lines[i])).Run()
	}
}

// copyResolvConf duplicates the host's current /etc/resolv.conf into
// the per-namespace override path. `ip netns exec` automatically
// bind-mounts this file into the child's namespace as /etc/resolv.conf.
func copyResolvConf() error {
	src, err := os.Open("/etc/resolv.conf")
	if err != nil {
		return err
	}
	defer src.Close()
	if err := os.MkdirAll("/etc/netns/"+NamespaceName, 0755); err != nil {
		return err
	}
	dst, err := os.Create("/etc/netns/" + NamespaceName + "/resolv.conf")
	if err != nil {
		return err
	}
	defer dst.Close()
	_, err = io.Copy(dst, src)
	return err
}
