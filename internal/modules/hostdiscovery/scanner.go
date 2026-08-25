package hostdiscovery

import (
	"context"
	"fmt"
	"net"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"scanner/internal/modules/shared"
)

// PortFinding represents one open port for a target.
type PortFinding struct {
	Port     int    `json:"port"`
	Protocol string `json:"protocol"`
	State    string `json:"state"`
	Service  string `json:"service,omitempty"`
}

// TargetResult holds ping/no-ping outcomes plus the merged port list.
type TargetResult struct {
	Target string `json:"target"`
	IP     string `json:"ip,omitempty"`
	Host   string `json:"host,omitempty"`

	// Two-pass status: did the host respond to ping? Did it respond at all?
	PingReachable bool   `json:"ping_reachable"`
	PingReason    string `json:"ping_reason,omitempty"`
	HostUp        bool   `json:"host_up"`

	// Hidden-host flag: set when ping says down BUT -Pn pass found open ports.
	IcmpFiltered bool `json:"icmp_filtered,omitempty"`

	Ports     []PortFinding `json:"ports"`
	OpenCount int           `json:"open_count"`

	// SuspectedFirewall is set when nmap reported >100 "open" ports — we
	// treat that as a stateful firewall reflecting probes and hide the
	// per-port list. FirewalledCount is the dropped count for the warning
	// badge. hostdiscovery does no -sV so we can't verify any of them; the
	// user should re-run portservice (with -sV) on the host to confirm.
	SuspectedFirewall bool `json:"suspected_firewall,omitempty"`
	FirewalledCount   int  `json:"firewalled_count,omitempty"`

	Error string `json:"error,omitempty"`
}

type ScanResult struct {
	Results []TargetResult `json:"results"`
}

// Scope mirrors the form's port-scope dropdown.
type Scope string

const (
	ScopeCommon Scope = "common"
	ScopeCustom Scope = "custom"
	ScopeRange  Scope = "range"
	ScopeFull   Scope = "full"
)

type Config struct {
	Targets     []string
	Scope       Scope
	PortSpec    string // raw value when scope=custom or scope=range
	Concurrency int    // parallel nmap invocations
}

type ProgressFunc func(done int, msg string)
type PartialFunc func(*ScanResult)

func Scan(ctx context.Context, cfg Config, progress ProgressFunc, partial PartialFunc) *ScanResult {
	if ctx == nil {
		ctx = context.Background()
	}
	if cfg.Concurrency <= 0 {
		cfg.Concurrency = 4
	}
	out := &ScanResult{}
	var mu sync.Mutex
	sem := make(chan struct{}, cfg.Concurrency)
	var wg sync.WaitGroup
	done := 0
	// Total host count, expanding CIDRs/ranges. Used so progress shows
	// /24 → 0/256 instead of 0/1. Each scanOne result bumps `done` by
	// len(rows) so the indicator reflects the host count nmap actually
	// processed for that target.
	totalHosts := len(shared.ExpandTargets(cfg.Targets, 65536))
	if totalHosts < len(cfg.Targets) {
		totalHosts = len(cfg.Targets)
	}

	// Audit S2: per-target marshal was O(N²). Throttle to 2s.
	throttle := shared.NewPartialThrottler(2 * time.Second)
	pushPartial := func() {
		if partial == nil {
			return
		}
		if !throttle.ShouldFire() {
			return
		}
		mu.Lock()
		snap := &ScanResult{Results: append([]TargetResult(nil), out.Results...)}
		mu.Unlock()
		partial(snap)
	}

	for _, t := range cfg.Targets {
		if ctx.Err() != nil {
			break
		}
		// audit K04: target string flows straight into nmap argv; "-target"
		// or "--script=..." would inject flags. Drop unsafe targets early.
		safe, ok := shared.SafeTarget(t)
		if !ok {
			mu.Lock()
			out.Results = append(out.Results, TargetResult{Target: t, Error: "rejected: contains shell/flag characters"})
			done++
			mu.Unlock()
			pushPartial()
			if progress != nil {
				progress(done, fmt.Sprintf("✗ rejected unsafe target %q", t))
			}
			continue
		}
		t = safe
		wg.Add(1)
		sem <- struct{}{}
		go func(target string) {
			defer wg.Done()
			defer func() { <-sem }()

			// Per-goroutine logger so command lines and per-step status all
			// flow through the existing progress channel. Anything starting
			// with "$ " is treated as a shell command by the live console.
			emit := func(msg string) {
				if progress != nil {
					mu.Lock()
					cur := done
					mu.Unlock()
					progress(cur, msg)
				}
			}

			// Audit Q01: a single CIDR/range target like 10.0.0.0/16 with
			// scope=Full used to disappear into a single scanOne() call
			// lasting hours, with no partial / no progress increment until
			// the goroutine returned. We chunk multi-host targets into
			// batches of `chunkSize` IPs so progress and partial snapshots
			// land every few minutes, even on huge sweeps.
			const chunkSize = 256
			hostsInTarget := countHostsFor(target)
			if hostsInTarget < 1 {
				hostsInTarget = 1
			}

			// chunks: each entry is a list of nmap target tokens. For
			// single-host targets there's one chunk of one token. For
			// multi-host targets we pre-expand and slice into batches.
			chunks := [][]string{{target}}
			if isMultiHostTarget(target) && hostsInTarget > chunkSize {
				if expanded := shared.ExpandTargets([]string{target}, hostsInTarget+8); len(expanded) > 0 {
					chunks = chunks[:0]
					for i := 0; i < len(expanded); i += chunkSize {
						end := i + chunkSize
						if end > len(expanded) {
							end = len(expanded)
						}
						batch := make([]string, end-i)
						copy(batch, expanded[i:end])
						chunks = append(chunks, batch)
					}
				}
			}

			for ci, chunk := range chunks {
				if ctx.Err() != nil {
					break
				}
				if len(chunks) > 1 {
					emit(fmt.Sprintf("→ Scanning %s chunk %d/%d (%d IPs) …", target, ci+1, len(chunks), len(chunk)))
				} else {
					emit(fmt.Sprintf("→ Scanning %s …", target))
				}
				rows := scanOneMulti(ctx, target, chunk, cfg, emit)

				chunkHosts := len(chunk)
				if len(chunks) == 1 {
					chunkHosts = hostsInTarget
				}
				if chunkHosts < 1 {
					chunkHosts = 1
				}

				// Audit B07: progress(cur, …) must be ordered with the
				// mutation of `done`. Two goroutines finishing
				// concurrently could write progress values out of order
				// to the DB, causing the bar to step backwards. Call
				// progress while still holding the lock.
				mu.Lock()
				done += chunkHosts
				out.Results = append(out.Results, rows...)
				cur := done
				if progress != nil {
					up, openTotal, fw := 0, 0, 0
					for _, r := range rows {
						if r.HostUp {
							up++
						}
						if r.SuspectedFirewall {
							fw++
						}
						openTotal += r.OpenCount
					}
					label := target
					if len(chunks) > 1 {
						label = fmt.Sprintf("%s [chunk %d/%d]", target, ci+1, len(chunks))
					}
					summary := fmt.Sprintf("✓ %s [%d/%d] · %d up · %d open", label, cur, totalHosts, up, openTotal)
					if fw > 0 {
						summary += fmt.Sprintf(" · %d firewalled", fw)
					}
					progress(cur, summary)
				}
				mu.Unlock()
				pushPartial()
			}
		}(t)
	}
	wg.Wait()
	throttle.Force()
	pushPartial()
	return out
}

// scanOne runs two nmap passes for a single user-supplied target (which may
// be a single IP/hostname OR a CIDR block / range — nmap parses these natively).
// Returns ONE result per host nmap reports, not just the first one. The log
// callback is used to surface the actual command line and intermediate steps
// to the live console (caller passes nil if it doesn't care).
func scanOne(ctx context.Context, target string, cfg Config, log func(string)) []TargetResult {
	return scanOneMulti(ctx, target, []string{target}, cfg, log)
}

// scanOneMulti is the chunk-aware variant: `label` is the user-supplied
// target string used for display, while `nmapTargets` is the (possibly
// expanded) list of nmap target tokens for this invocation. This lets the
// caller chunk a /16 into /24-sized batches without losing the original
// label and without re-running isMultiHostTarget heuristics.
func scanOneMulti(ctx context.Context, label string, nmapTargets []string, cfg Config, log func(string)) []TargetResult {
	portArgs := portArgList(cfg.Scope, cfg.PortSpec)
	isMulti := isMultiHostTarget(label) || len(nmapTargets) > 1

	if log == nil {
		log = func(string) {}
	}
	if len(nmapTargets) == 0 {
		nmapTargets = []string{label}
	}

	// Audit P/Q: bound per-host time. portservice carries the same wrapper
	// for the same reason — a silent host with many filtered ports can
	// drag a -T4 sweep into the double-digit-minute range. Scale with the
	// scope: Full (-p-, 65535 ports) needs the largest envelope.
	hostTimeout := "5m"
	switch cfg.Scope {
	case ScopeFull:
		hostTimeout = "30m"
	case ScopeRange, ScopeCustom:
		hostTimeout = "10m"
	}
	timeoutArgs := []string{"--host-timeout", hostTimeout, "--max-retries", "2"}

	// Pass 1: with ping. Collect every host nmap reports.
	pingArgs := append([]string{"-T4", "-n"}, timeoutArgs...)
	pingArgs = append(pingArgs, portArgs...)
	pingArgs = append(pingArgs, nmapTargets...)
	log("$ " + shared.FormatNmap(pingArgs))
	pingResult, _, err := shared.RunNmapProgress(ctx, pingArgs, func(pct float64, _ string) {
		log(fmt.Sprintf("→ ping/port scan: about %.0f%% done", pct))
	})

	pingReachable := map[string]shared.NmapHost{} // ip → host (state=up + ports)
	pingDown := map[string]shared.NmapHost{}      // ip → host (state=down)
	pingErr := ""
	if err != nil {
		pingErr = err.Error()
	} else if pingResult != nil {
		for _, h := range pingResult.Hosts {
			ip := h.PrimaryAddress()
			if ip == "" {
				continue
			}
			if h.Status.State == "up" {
				pingReachable[ip] = h
			} else {
				pingDown[ip] = h
			}
		}
	}

	// Pass 2: -Pn — only needed for hosts that didn't respond to ping. For a
	// single target, always run it (so we can detect ICMP-filtered hosts). For
	// CIDR/range, only run it if there are silent IPs OR the user gave a small
	// block; we cap the second pass to keep large /16-style sweeps reasonable.
	var pnHosts map[string]shared.NmapHost
	needPn := !isMulti || len(pingReachable) == 0 || len(pingDown) > 0
	if needPn {
		pnArgs := append([]string{"-T4", "-n", "-Pn"}, timeoutArgs...)
		pnArgs = append(pnArgs, portArgs...)
		pnArgs = append(pnArgs, nmapTargets...)
		log("$ " + shared.FormatNmap(pnArgs))
		pnResult, _, err2 := shared.RunNmapProgress(ctx, pnArgs, func(pct float64, _ string) {
			log(fmt.Sprintf("→ -Pn deep scan: about %.0f%% done", pct))
		})
		if err2 == nil && pnResult != nil {
			pnHosts = map[string]shared.NmapHost{}
			for _, h := range pnResult.Hosts {
				ip := h.PrimaryAddress()
				if ip != "" {
					pnHosts[ip] = h
				}
			}
		} else if err2 != nil && pingErr == "" {
			pingErr = err2.Error()
		}
	}

	// Merge: union of IPs seen across both passes.
	seen := map[string]struct{}{}
	for ip := range pingReachable {
		seen[ip] = struct{}{}
	}
	for ip := range pingDown {
		seen[ip] = struct{}{}
	}
	for ip := range pnHosts {
		seen[ip] = struct{}{}
	}
	if len(seen) == 0 {
		// Fall back to the original target string if nothing came back.
		tr := TargetResult{Target: label, Error: "nmap returned no host record"}
		if pingErr != "" {
			tr.Error = pingErr
		}
		return []TargetResult{tr}
	}

	results := make([]TargetResult, 0, len(seen))
	for ip := range seen {
		tr := TargetResult{Target: label, IP: ip}
		if isMulti {
			// For CIDR/range, label the row by the IP so the table reads cleanly.
			tr.Target = ip
		}
		// Prefer ping-reachable host record (richer status reason).
		if h, ok := pingReachable[ip]; ok {
			tr.Host = h.PrimaryHostname()
			tr.PingReachable = true
			tr.PingReason = h.Status.Reason
			tr.HostUp = true
			tr.Ports = portsFromHost(h)
			tr.OpenCount = countOpen(tr.Ports)
		} else if h, ok := pnHosts[ip]; ok {
			tr.Host = h.PrimaryHostname()
			tr.Ports = portsFromHost(h)
			tr.OpenCount = countOpen(tr.Ports)
			if tr.OpenCount > 0 {
				tr.HostUp = true
				tr.IcmpFiltered = true
			}
			if dh, ok := pingDown[ip]; ok {
				tr.PingReason = dh.Status.Reason
			}
		} else if h, ok := pingDown[ip]; ok {
			tr.PingReason = h.Status.Reason
		}
		applyFirewallHeuristic(&tr)
		results = append(results, tr)
	}
	sort.Slice(results, func(i, j int) bool { return ipLess(results[i].IP, results[j].IP) })
	return results
}

// numericRangeRe matches strict nmap-style numeric ranges (CIDR is handled
// separately above). Examples that should match:
//
//	10.0.0.1-50
//	10.0.0-10.1-20
//	192.168.1.10-192.168.1.50
//
// Examples that should NOT match (hostnames containing a digit-hyphen):
//
//	node1-foo.example.com
//	host2-bar.corp
//	k8s1-prod
//
// We require the string to be made of digits, dots, and hyphens only.
var numericRangeRe = regexp.MustCompile(`^[0-9]+(\.[0-9]+){0,3}(-[0-9]+(\.[0-9]+){0,3})+$`)

// isMultiHostTarget returns true if target is a CIDR or a hyphen-range that
// nmap would expand into multiple hosts. Audit B09 / B19: the previous
// heuristic ('any digit followed by -') misidentified hostnames like
// 'node1-foo.example.com' as ranges, causing the result row's Target column
// to be overwritten by the resolved IP.
func isMultiHostTarget(target string) bool {
	t := strings.TrimSpace(target)
	if t == "" {
		return false
	}
	if strings.Contains(t, "/") {
		// Only treat as CIDR if it parses (or at least looks like dotted-quad/bits).
		if _, _, err := net.ParseCIDR(t); err == nil {
			return true
		}
		// Fallback: if everything before the slash is digits-and-dots, accept.
		if slash := strings.IndexByte(t, '/'); slash > 0 {
			head := t[:slash]
			for _, r := range head {
				if !(r == '.' || (r >= '0' && r <= '9')) {
					return false
				}
			}
			return true
		}
		return false
	}
	// For non-CIDR strings, only treat as a range when the string is
	// numeric-and-dotted with a hyphen between numeric octets — hostnames
	// containing '-' (very common in DNS labels) must NOT trigger this.
	return numericRangeRe.MatchString(t)
}

// ipToUint32 parses a dotted-quad IPv4 into a 32-bit integer for fast
// numeric comparison. Returns (0, false) for inputs that aren't a clean
// IPv4 address. Used as the sort key in ipLess so we avoid fmt.Sscanf
// reflection per-comparison on large result sets.
func ipToUint32(s string) (uint32, bool) {
	ip := net.ParseIP(strings.TrimSpace(s))
	if ip == nil {
		return 0, false
	}
	v4 := ip.To4()
	if v4 == nil {
		return 0, false
	}
	return uint32(v4[0])<<24 | uint32(v4[1])<<16 | uint32(v4[2])<<8 | uint32(v4[3]), true
}

// ipLess sorts dotted-quad IPv4 addresses numerically so result rows read in
// natural order (10.0.0.1, 10.0.0.2, ... 10.0.0.10) instead of lexicographic.
// Audit P06: replaced per-octet fmt.Sscanf with a single net.ParseIP+shift,
// roughly 50x faster on large result lists.
func ipLess(a, b string) bool {
	ua, oka := ipToUint32(a)
	ub, okb := ipToUint32(b)
	if !oka || !okb {
		return a < b
	}
	return ua < ub
}

// countHostsFor returns how many distinct hosts the given target string
// would expand into, parsing CIDR widths and hyphen ranges numerically so
// the call is O(1) instead of O(N). A non-CIDR/non-range value counts as 1.
// Audit P05: ExpandTargets allocated a flat slice + map of every IP just
// to take len(); that work is wasted here and was running once per target
// inside the worker goroutine.
func countHostsFor(target string) int {
	t := strings.TrimSpace(target)
	if t == "" {
		return 1
	}
	// CIDR
	if slash := strings.IndexByte(t, '/'); slash >= 0 {
		bits, err := strconv.Atoi(t[slash+1:])
		if err != nil || bits < 0 || bits > 32 {
			return 1
		}
		hostCount := 1 << uint(32-bits)
		// Match ExpandTargets's network/broadcast trim for blocks /30 or larger.
		if bits <= 30 && hostCount >= 2 {
			hostCount -= 2
		}
		if hostCount < 1 {
			hostCount = 1
		}
		return hostCount
	}
	// Hyphen-range on the last octet only: "10.0.0.10-50".
	if idx := strings.LastIndexByte(t, '-'); idx > 0 {
		left := t[:idx]
		right := t[idx+1:]
		// Last-octet form: a.b.c.X-Y
		if strings.Count(left, ".") == 3 && !strings.Contains(right, ".") {
			dot := strings.LastIndexByte(left, '.')
			loStr := left[dot+1:]
			lo, errLo := strconv.Atoi(loStr)
			hi, errHi := strconv.Atoi(right)
			if errLo == nil && errHi == nil && hi >= lo {
				return hi - lo + 1
			}
		}
		// Full IP-to-IP form: a.b.c.d-w.x.y.z
		if strings.Count(left, ".") == 3 && strings.Count(right, ".") == 3 {
			lo, okLo := ipToUint32(left)
			hi, okHi := ipToUint32(right)
			if okLo && okHi && hi >= lo {
				diff := hi - lo + 1
				if diff > 1<<24 { // sanity clamp at /8 to avoid runaway
					diff = 1 << 24
				}
				return int(diff)
			}
		}
	}
	return 1
}

func portArgList(scope Scope, custom string) []string {
	switch scope {
	case ScopeFull:
		return []string{"-p-"}
	case ScopeCustom:
		c := strings.TrimSpace(custom)
		if c == "" {
			c = "80,443,22,21,3389,445"
		}
		return []string{"-p", c}
	case ScopeRange:
		c := strings.TrimSpace(custom)
		if c == "" {
			c = "1-1024"
		}
		return []string{"-p", c}
	default: // ScopeCommon
		return []string{"--top-ports", "1000"}
	}
}

func portsFromHost(h shared.NmapHost) []PortFinding {
	out := []PortFinding{}
	for _, p := range h.Ports.Ports {
		if p.State.State != "open" && p.State.State != "open|filtered" {
			continue
		}
		out = append(out, PortFinding{
			Port:     p.PortID,
			Protocol: p.Protocol,
			State:    p.State.State,
			Service:  p.Service.Name,
		})
	}
	return out
}

func countOpen(p []PortFinding) int {
	n := 0
	for _, x := range p {
		if x.State == "open" {
			n++
		}
	}
	return n
}

// applyFirewallHeuristic flags hosts that nmap declared "fully open" because
// a stateful firewall is reflecting every probe. Threshold: >100 reported
// open ports. For host discovery we DON'T try to verify individual ports
// (that's the portservice module's job) — we just mark the IP as
// "Potential firewall, +N ports" and stop. The Ports list is cleared so
// nothing downstream tries to act on the spurious entries; the user is
// expected to follow up with portservice for service-level confirmation.
const firewallSuspicionThreshold = 100

func applyFirewallHeuristic(tr *TargetResult) {
	if tr == nil || len(tr.Ports) <= firewallSuspicionThreshold {
		return
	}
	tr.FirewalledCount = len(tr.Ports)
	tr.SuspectedFirewall = true
	tr.Ports = nil
	tr.OpenCount = 0
}
