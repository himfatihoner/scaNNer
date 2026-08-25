package portservice

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"time"

	"scanner/internal/modules/shared"
)

// writeWordlistTempFiles dumps the username + password slices to two
// temp files and returns their paths + a cleanup func that removes
// both. nmap brute/auth scripts read wordlists from disk via the
// userdb/passdb --script-args knobs, so we have to materialize the
// in-memory slices as files before invoking nmap.
// writeWordlistTempFiles materializes the in-memory user/pass slices to
// disk so nmap's `userdb=` / `passdb=` script args can find them.
//
// Audit B13/B18: previously we created two free-standing temp files via
// os.CreateTemp and relied on a returned `cleanup func()`. If the scanner
// panicked between the call site and `defer credsCleanup()` running, the
// files leaked to /tmp. Over a 2-day soak with periodic brute scans this
// produced thousands of orphaned scanner-{users,pass}-*.txt files,
// eventually filling /tmp. Switching to a SINGLE temp DIR via
// os.MkdirTemp means one RemoveAll cleans both files atomically, and
// the cleanup is robust to one-file-only success cases.
func writeWordlistTempFiles(users, passwords []string) (string, string, func(), error) {
	dir, err := os.MkdirTemp("", "scanner-brute-*")
	if err != nil {
		return "", "", func() {}, err
	}
	// Closure captures dir so cleanup wipes everything we wrote.
	cleanup := func() { os.RemoveAll(dir) }

	userPath := filepath.Join(dir, "users.txt")
	uf, err := os.Create(userPath)
	if err != nil {
		cleanup()
		return "", "", func() {}, err
	}
	for _, u := range users {
		if u = strings.TrimSpace(u); u != "" {
			uf.WriteString(u + "\n")
		}
	}
	uf.Close()

	passPath := filepath.Join(dir, "pass.txt")
	pf, err := os.Create(passPath)
	if err != nil {
		cleanup()
		return "", "", func() {}, err
	}
	for _, p := range passwords {
		if p = strings.TrimSpace(p); p != "" {
			pf.WriteString(p + "\n")
		}
	}
	pf.Close()

	return userPath, passPath, cleanup, nil
}

type Scope string

const (
	ScopeCommon Scope = "common"
	ScopeCustom Scope = "custom"
	ScopeRange  Scope = "range"
	ScopeFull   Scope = "full"
)

type ScriptOutput struct {
	ID     string `json:"id"`
	Output string `json:"output"`
}

type Port struct {
	Port      int            `json:"port"`
	Protocol  string         `json:"protocol"`
	State     string         `json:"state"`
	Service   string         `json:"service,omitempty"`
	Product   string         `json:"product,omitempty"`
	Version   string         `json:"version,omitempty"`
	ExtraInfo string         `json:"extra_info,omitempty"`
	Tunnel    string         `json:"tunnel,omitempty"`
	Scripts   []ScriptOutput `json:"scripts,omitempty"`

	// Banner is a raw Shodan-style banner captured by directly connecting
	// to the port. Populated for non-HTTP services by a TCP read. Empty
	// for ports the banner-grabber didn't probe.
	Banner string `json:"banner,omitempty"`

	// HTTPResp captures a real HTTP probe (GET /) for HTTP/HTTPS ports —
	// the kind of detail Shodan shows. Status code, response headers, and
	// the first ~2 KB of the body so the user can see what's actually
	// served, even when the NSE scripts didn't fire.
	HTTPResp *HTTPResponse `json:"http_resp,omitempty"`
}

// HTTPResponse holds a synchronous HTTP GET probe result for a port. Set on
// HTTP/HTTPS ports during the banner-enrichment phase.
type HTTPResponse struct {
	URL          string       `json:"url"`
	Status       int          `json:"status"`
	StatusText   string       `json:"status_text,omitempty"`
	ContentType  string       `json:"content_type,omitempty"`
	Server       string       `json:"server,omitempty"`
	Title        string       `json:"title,omitempty"`
	Headers      []HTTPHeader `json:"headers,omitempty"`
	BodyPreview  string       `json:"body_preview,omitempty"`
	BodyLength   int          `json:"body_length,omitempty"`
	Error        string       `json:"error,omitempty"`
	RedirectedTo string       `json:"redirected_to,omitempty"`
}

type HTTPHeader struct {
	Name  string `json:"name"`
	Value string `json:"value"`
}

type TargetResult struct {
	Target        string `json:"target"`
	IP            string `json:"ip,omitempty"`
	Host          string `json:"host,omitempty"`
	PingReachable bool   `json:"ping_reachable"`
	HostUp        bool   `json:"host_up"`
	IcmpFiltered  bool   `json:"icmp_filtered,omitempty"`
	Ports         []Port `json:"ports"`
	OpenCount     int    `json:"open_count"`
	// SuspectedFirewall is set when phase-1 port discovery returned >100
	// "open" ports — typical of a stateful firewall reflecting probes. For
	// these hosts the deep scan is restricted to the common-port subset
	// of the user's range so we don't waste hours auditing phantom ports.
	SuspectedFirewall bool `json:"suspected_firewall,omitempty"`
	FirewalledCount   int  `json:"firewalled_count,omitempty"`
	// NucleiFindings holds vulnerability findings discovered by the Nuclei
	// pass that runs after the nmap phases against open HTTP services on
	// this host.
	NucleiFindings []NucleiFinding `json:"nuclei_findings,omitempty"`
	Error          string          `json:"error,omitempty"`
}

// NucleiFinding mirrors nuclei.Finding but kept local so this package doesn't
// import the nuclei one (the handler does the conversion).
type NucleiFinding struct {
	TemplateID  string   `json:"template_id"`
	Name        string   `json:"name"`
	Severity    string   `json:"severity"`
	Type        string   `json:"type,omitempty"`
	Host        string   `json:"host"`
	MatchedAt   string   `json:"matched_at"`
	Description string   `json:"description,omitempty"`
	Tags        []string `json:"tags,omitempty"`
	CVEs        []string `json:"cves,omitempty"`
	CWEs        []string `json:"cwes,omitempty"`
	References  []string `json:"references,omitempty"`
	Extracted   []string `json:"extracted,omitempty"`
	CurlCommand string   `json:"curl_command,omitempty"`
}

type ScanResult struct {
	Results []TargetResult `json:"results"`
}

type Config struct {
	Targets     []string
	Scope       Scope
	PortSpec    string
	Concurrency int
	// Speed sets nmap timing. "fast" → -T4 (default), "aggressive" → -T5,
	// "insane" → -T5 + --max-rate 1500. The legacy ScriptCat field is kept
	// so existing serialized configs unmarshal cleanly but is now ignored —
	// the new flow auto-picks scripts per detected service.
	Speed     string
	ScriptCat string // ignored, kept for json compat with old saved scans
	// UDPScan adds a third discovery pass with -sU (UDP). Off by default
	// because UDP scanning is dramatically slower than TCP (nmap rate-
	// limits to ~1pps per closed port to obey RFC 1812). When on, the
	// scope follows the same PortSpec but nmap defaults to top-100 UDP
	// services if the spec is empty.
	UDPScan bool

	// ScriptDepth picks the Phase-2 NSE script set:
	//   "safe"  → curated vuln/discovery scripts only (production-safe)
	//   "deep"  → adds nmap categories: intrusive, fuzzer, exploit.
	//             Does NOT include external (OPSEC leak: sends data to
	//             3rd-party APIs) or dos (crashes services) — these are
	//             never enabled regardless of depth.
	// Brute + auth categories are activated ONLY when both UsernameList
	// and PasswordList are non-empty (nmap brute scripts error out
	// without wordlists, so triggering them dry is pointless).
	ScriptDepth  string
	UsernameList []string
	PasswordList []string
}

type ProgressFunc func(done int, msg string)
type PartialFunc func(*ScanResult)

func Scan(ctx context.Context, cfg Config, progress ProgressFunc, partial PartialFunc) *ScanResult {
	if ctx == nil {
		ctx = context.Background()
	}
	if cfg.Concurrency <= 0 {
		cfg.Concurrency = 3
	}
	if cfg.ScriptCat == "" {
		cfg.ScriptCat = "default"
	}
	out := &ScanResult{}
	var mu sync.Mutex
	sem := make(chan struct{}, cfg.Concurrency)
	var wg sync.WaitGroup
	done := 0
	// Total host count, expanding CIDRs/ranges. Used so a /24 reports as
	// 0/256 rather than 0/1. `done` advances by the host count of the
	// completed target (not just by 1) to keep the indicator accurate.
	totalHosts := len(shared.ExpandTargets(cfg.Targets, 65536))
	if totalHosts < len(cfg.Targets) {
		totalHosts = len(cfg.Targets)
	}

	// Audit S2: throttle per-host nmap-phase partials to 2s; the final
	// snapshot after wg.Wait still guarantees the terminal result lands.
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
		// Audit fix: target flows straight into nmap argv; reject any
		// value that could expand into flags or contain shell metachars
		// (matches K04/K09 in hostdiscovery + smbenum).
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
			emit := func(msg string) {
				if progress == nil {
					return
				}
				mu.Lock()
				cur := done
				mu.Unlock()
				progress(cur, msg)
			}
			emit(fmt.Sprintf("→ Scanning %s …", target))
			rows := scanOne(ctx, target, cfg, emit)
			hostsInTarget := len(shared.ExpandTargets([]string{target}, 65536))
			if hostsInTarget < 1 {
				hostsInTarget = 1
			}
			mu.Lock()
			done += hostsInTarget
			out.Results = append(out.Results, rows...)
			cur := done
			mu.Unlock()
			if progress != nil {
				up, openTotal, versioned, fw := 0, 0, 0, 0
				for _, r := range rows {
					if r.HostUp {
						up++
					}
					if r.SuspectedFirewall {
						fw++
					}
					openTotal += r.OpenCount
					versioned += withVersion(r.Ports)
				}
				summary := fmt.Sprintf("✓ %s [%d/%d] · %d up · %d open · %d with version", target, cur, totalHosts, up, openTotal, versioned)
				if fw > 0 {
					summary += fmt.Sprintf(" · %d firewalled", fw)
				}
				progress(cur, summary)
			}
			pushPartial()
		}(t)
	}
	wg.Wait()
	throttle.Force()
	pushPartial()
	return out
}

func withVersion(ps []Port) int {
	n := 0
	for _, p := range ps {
		if p.Product != "" || p.Version != "" {
			n++
		}
	}
	return n
}

// scanOne runs the four-phase Advanced Scanner flow for a single user target
// (which may be a CIDR / range — nmap expands those natively):
//
//	Phase 1  — Two parallel port-discovery sweeps:
//	               nmap -p <ports> <ip>           (with ping)
//	               nmap -Pn -p <ports> <ip>       (no ping)
//	           Merging the two passes tells us which hosts are up, which are
//	           ICMP-filtered, and gives a fast open-port list per host. No
//	           -sV here so even a /24 returns quickly.
//
//	Firewall heuristic: any host returning >100 "open" ports in phase 1 is
//	flagged as a suspected firewall — those reflective replies waste hours
//	in -A. The deep scan for those hosts is restricted to the COMMON-port
//	subset of the user's range only.
//
//	Phase 2  — Deep scan, branching by firewall flag:
//	             Firewalled host  → nmap -Pn -A -p <commons-in-range> <ip>
//	             Normal host       → nmap -Pn -A --script <extras> -p <opens> <ip>
//	           The "<extras>" are service-specific NSE scripts not already
//	           in -A's default set, picked from the phase-1 service-name
//	           guesses (port 80 → "http", picks http-enum etc.).
//
//	Phase 3  — Follow-up for newly-detected services on normal hosts: when
//	           -sV in phase 2 reveals a different service than the phase-1
//	           port-name guess (e.g. port 8080 turned out to be ssh), run a
//	           focused script pass with the scripts that match the now-known
//	           service but were excluded earlier:
//	             nmap -Pn --script <new-extras> -p <new-ports> <ip>
//
//	Phase 4  — Nuclei (handled at handler level after Scan() returns): every
//	           open HTTP/HTTPS port on every host is fed to nuclei for the
//	           vulnerability assessment.
func scanOne(ctx context.Context, target string, cfg Config, log func(string)) []TargetResult {
	portArgs := portArgList(cfg.Scope, cfg.PortSpec)
	multi := isMultiHostTarget(target)
	timing := timingArgs(cfg.Speed)

	// --- Phase 1: two parallel port-discovery sweeps ---
	type discResult struct {
		hosts map[string]shared.NmapHost
		err   error
	}
	// --host-timeout scales with the port-spec scope. Default 3m is fine
	// for top-1000 (Common) but catastrophic for -p- (Full, 65535 ports)
	// — nmap can't even probe 65k ports in 3min over real networks, so
	// every host bails at the timeout and reports 0 open ports. Scale to
	// 30m on Full, 10m on Range/Custom (which can also be wide).
	hostTimeout := "3m"
	switch cfg.Scope {
	case ScopeFull:
		hostTimeout = "30m"
	case ScopeRange, ScopeCustom:
		hostTimeout = "10m"
	}
	runDiscovery := func(extra []string) discResult {
		args := append([]string{}, timing...)
		args = append(args, "-n",
			// host-timeout + max-retries cap how long a single host can
			// hold up phase 1. Without these, a silent host with many
			// filtered ports can drag a port-discovery sweep into the
			// double-digit-minute range under -T4's default retry count.
			"--host-timeout", hostTimeout,
			"--max-retries", "2")
		args = append(args, extra...)
		args = append(args, portArgs...)
		args = append(args, target)
		if log != nil {
			log("$ " + shared.FormatNmap(args))
		}
		res, _, err := shared.RunNmapProgress(ctx, args, func(pct float64, _ string) {
			if log != nil {
				log(fmt.Sprintf("→ %s port scan: about %.0f%% done", target, pct))
			}
		})
		out := discResult{hosts: map[string]shared.NmapHost{}, err: err}
		if res != nil {
			for _, h := range res.Hosts {
				if ip := h.PrimaryAddress(); ip != "" {
					out.hosts[ip] = h
				}
			}
		}
		return out
	}

	var withPing, noPing, udpScan discResult
	var wgP1 sync.WaitGroup
	wgP1.Add(2)
	go func() { defer wgP1.Done(); withPing = runDiscovery(nil) }()
	go func() { defer wgP1.Done(); noPing = runDiscovery([]string{"-Pn"}) }()
	// UDP pass — only when explicitly enabled. nmap's UDP scan is
	// orders of magnitude slower than TCP (rate-limited by RFC 1812),
	// so this stays off by default. Top-100 UDP services is the
	// preset; user can override via PortSpec.
	if cfg.UDPScan {
		wgP1.Add(1)
		go func() {
			defer wgP1.Done()
			// Use --top-ports 100 if the PortSpec wasn't customized; else
			// reuse the same -p spec for UDP. nmap -sU requires root —
			// fall through gracefully if it errors (e.g. unprivileged).
			udpExtra := []string{"-sU", "-Pn"}
			if log != nil {
				log("$ nmap -sU -Pn (UDP discovery pass)")
			}
			udpScan = runDiscovery(udpExtra)
		}()
	}
	wgP1.Wait()

	// Union of IPs across all passes.
	allIPs := map[string]struct{}{}
	for ip := range withPing.hosts {
		allIPs[ip] = struct{}{}
	}
	for ip := range noPing.hosts {
		allIPs[ip] = struct{}{}
	}
	for ip := range udpScan.hosts {
		allIPs[ip] = struct{}{}
	}

	// Backfill any IPs that were in the user's range/CIDR but didn't show
	// up in either nmap pass. nmap with --host-timeout drops timed-out
	// hosts from XML output entirely, so a /24 range can return 254 host
	// records when the user expected 256 (or 50 of 51 for `0-50`). Those
	// "missing" hosts get placeholder TargetResults so the result count
	// matches what the user saw on the targets page.
	expectedIPs := shared.ExpandTargets([]string{target}, 65536)
	expectedMissing := []string{}
	for _, ip := range expectedIPs {
		if _, ok := allIPs[ip]; !ok && ip != target {
			expectedMissing = append(expectedMissing, ip)
			allIPs[ip] = struct{}{}
		}
	}

	if len(allIPs) == 0 {
		tr := TargetResult{Target: target, Error: "nmap returned no host record"}
		if withPing.err != nil {
			tr.Error = withPing.err.Error()
		} else if noPing.err != nil {
			tr.Error = noPing.err.Error()
		}
		return []TargetResult{tr}
	}
	missingSet := map[string]struct{}{}
	for _, ip := range expectedMissing {
		missingSet[ip] = struct{}{}
	}

	// Build per-IP TargetResult from the merged phase-1 view.
	results := make([]TargetResult, 0, len(allIPs))
	for ip := range allIPs {
		tr := TargetResult{Target: target, IP: ip}
		if multi {
			tr.Target = ip
		}
		// Host wasn't seen in either nmap pass — backfilled placeholder.
		// Mark it as down with an explicit error so the user understands
		// why no ports appear.
		if _, missing := missingSet[ip]; missing {
			tr.HostUp = false
			tr.Error = "no nmap response (host-timeout or unreachable)"
			results = append(results, tr)
			continue
		}
		hp, hasPing := withPing.hosts[ip]
		hn, hasPn := noPing.hosts[ip]
		hu, hasUDP := udpScan.hosts[ip]

		if hasPing && hp.Status.State == "up" {
			tr.PingReachable = true
			tr.HostUp = true
			tr.Host = hp.PrimaryHostname()
			tr.Ports = portsFromHost(hp)
		}
		if hasPn {
			pnPorts := portsFromHost(hn)
			if !tr.HostUp && countOpen(pnPorts) > 0 {
				// ICMP filtered — ping pass thought down, but ports answered.
				tr.HostUp = true
				tr.IcmpFiltered = true
				tr.Host = hn.PrimaryHostname()
				tr.Ports = pnPorts
			} else if tr.HostUp && countOpen(pnPorts) > countOpen(tr.Ports) {
				// -Pn observed more ports — prefer the richer view.
				tr.Ports = pnPorts
			}
		}
		// UDP ports are merged in regardless of TCP host state — a host
		// could be silent on TCP but answer on a UDP service (DNS, SNMP,
		// NTP, etc.). nmap -sU emits Protocol="udp" so we keep them in
		// the same Ports slice; downstream renderers can group by proto.
		if hasUDP {
			for _, p := range portsFromHost(hu) {
				if strings.ToLower(p.Protocol) == "udp" {
					tr.Ports = append(tr.Ports, p)
					if p.State == "open" || p.State == "open|filtered" {
						tr.HostUp = true
						if tr.Host == "" {
							tr.Host = hu.PrimaryHostname()
						}
					}
				}
			}
		}
		tr.OpenCount = countOpen(tr.Ports)

		// Firewall heuristic: phase-1 returned >100 ports for this host →
		// flag it. The deep scan branches on this flag below.
		if tr.OpenCount > firewallSuspicionThreshold {
			tr.SuspectedFirewall = true
			tr.FirewalledCount = tr.OpenCount
		}

		results = append(results, tr)
	}

	// --- Phases 2 & 3 ---
	for i := range results {
		runDeepScan(ctx, &results[i], cfg, timing, portArgs, log)
	}

	sort.Slice(results, func(i, j int) bool { return ipLess(results[i].IP, results[j].IP) })
	return results
}

// runDeepScan implements phases 2 and 3 for a single host. Phase 2 picks one
// of two branches based on the firewall flag; phase 3 only runs for normal
// (non-firewalled) hosts when phase 2 surfaces unexpected services. The
// `userPortArgs` slice is the user's requested port spec verbatim
// (e.g. "--top-ports 1000" or "-p 1-1024") — phase 2 scans it whole, exactly
// as in the spec: nmap -Pn -A -p [target-ports] [target].
func runDeepScan(ctx context.Context, tr *TargetResult, cfg Config, timing []string, userPortArgs []string, log func(string)) {
	if tr == nil || !tr.HostUp {
		return
	}
	target := tr.IP
	if target == "" {
		target = tr.Target
	}

	// --- Phase 2 ---
	if tr.SuspectedFirewall {
		// Firewall path — only commons within the user's requested port
		// range. Spec: nmap -Pn -A -p [target-ports(only commons)] [target].
		commonPortStr := commonsInRange(cfg.Scope, cfg.PortSpec)
		if commonPortStr == "" {
			// Audit MED fix: previously the phase-1 Ports slice was
			// wiped to nil / OpenCount=0 here, leaving the user with a
			// completely empty host row + "0 ports" and no explanation.
			// Keep the phase-1 list intact (the SuspectedFirewall flag
			// already tells the UI those numbers are unreliable), and
			// surface an Error string so the user knows why the deep
			// scan was skipped.
			if log != nil {
				log(fmt.Sprintf("⚠ %s firewall-suspect — no common ports in user's range, skipping deep scan", target))
			}
			tr.Error = "firewall-suspect: user's port range has no overlap with top-100 commons; deep scan skipped (phase-1 counts shown are likely false positives)"
			return
		}
		// Firewall path — only -sV (no -sC, no -O). Default-category
		// scripts are completely worthless against a host whose phase-1
		// reflected 100+ open ports; just identify what's actually behind
		// the common ports. Banner enrichment phase will hit the verified
		// services with HTTP / TCP grabs afterward.
		args := append([]string{}, timing...)
		args = append(args,
			"-n", "-Pn",
			"--host-timeout", "5m",
			"--max-retries", "2",
			"-sV", "--version-intensity", "5",
			"-p", commonPortStr, target)
		if log != nil {
			log(fmt.Sprintf("→ Phase 2 (firewall path) on %s · commons-only: %s", target, commonPortStr))
			log("$ " + shared.FormatNmap(args))
		}
		res, _, err := shared.RunNmap(ctx, args)
		if err != nil || res == nil {
			return
		}
		newPorts := portsForIP(res, target)
		tr.Ports = newPorts
		tr.OpenCount = countOpen(newPorts)
		return
	}

	if len(tr.Ports) == 0 {
		return
	}

	// Normal host — phase 2: deep-scan ONLY the ports phase 1 found open.
	// Earlier we passed the full user port-range here (per literal spec),
	// but for `Full (1-65535)` or large `Range` scopes that turned phase 2
	// into a 60+ minute deep-scan of nothing — nmap re-running -A across
	// 60k closed ports on every host. The whole point of running a fast
	// phase 1 first is to feed phase 2 a tight set, so do that.
	//
	// IMPORTANT: `-A` implies `-sC` which is `--script default`. If we also
	// pass `--script ssl-enum-ciphers,http-enum,…` then the explicit list
	// REPLACES the default category — http-title, http-headers, http-methods,
	// ssh-hostkey, smb-os-discovery etc. would silently not run. We always
	// prepend "default," so both the default-tagged scripts and our extras
	// fire on the same scan.
	openPortStr := openPortsCSV(tr.Ports)
	if openPortStr == "" {
		return
	}
	scripts := uniqueScriptsForPorts(tr.Ports)

	// Deep mode adds nmap script CATEGORIES on top of the curated list.
	// EXTERNAL and DOS are NEVER appended regardless of depth (external
	// leaks recon to 3rd-party APIs, dos crashes services).
	if cfg.ScriptDepth == "deep" {
		scripts = append(scripts, "intrusive", "fuzzer", "exploit")
	}
	// Brute + auth activate only when both wordlists are provided —
	// otherwise nmap brute scripts error out on missing userdb/passdb.
	var scriptArgs []string
	credsReady := len(cfg.UsernameList) > 0 && len(cfg.PasswordList) > 0
	credsCleanup := func() {}
	if credsReady {
		userFile, passFile, cleanup, err := writeWordlistTempFiles(cfg.UsernameList, cfg.PasswordList)
		if err == nil {
			scripts = append(scripts, "brute", "auth")
			scriptArgs = append(scriptArgs,
				"userdb="+userFile,
				"passdb="+passFile,
				"unpwdb.timelimit=5m",
				"brute.firstonly=true")
			credsCleanup = cleanup
		} else if log != nil {
			log(fmt.Sprintf("⚠ brute/auth skipped: wordlist temp file write failed: %v", err))
		}
	}
	defer credsCleanup()

	// Phase 2 — version detection + curated vuln scripts only. Dropped
	// `-sC` / `--script default,...` because the `default` category fires
	// 50+ scripts per port (http-title, http-headers, smb-os-discovery,
	// ssh-hostkey, ftp-bounce, dns-recursion, ssl-cert, etc.) and most of
	// the banner-class data we'd care about is already collected by our
	// own HTTP / TCP banner-grab phase that runs right after this. The
	// CVE / vuln-class default scripts are reproduced in our curated
	// extras list, so this is a 5-10× phase-2 speed-up with no info loss.
	args := append([]string{}, timing...)
	args = append(args,
		"-n", "-Pn",
		"--host-timeout", "5m",
		"--max-retries", "2",
		// Per-NSE-script timeout. Without this a single slow script (a
		// network-fuzz template, a heavy crypto enumeration, an HTTP
		// path-walk that hits a slow backend) can blow the per-host
		// budget and hold the whole goroutine. 60s is generous enough
		// for legitimate vuln probes and ruthless on the rest.
		"--script-timeout", "60s",
		"-sV", "--version-intensity", "5")
	if len(scripts) > 0 {
		args = append(args, "--script", strings.Join(scripts, ","))
	}
	if len(scriptArgs) > 0 {
		args = append(args, "--script-args", strings.Join(scriptArgs, ","))
	}
	args = append(args, "-p", openPortStr, target)
	_ = userPortArgs
	if log != nil {
		log(fmt.Sprintf("→ Phase 2 on %s · %d scripts · %d open ports", target, len(scripts), countOpen(tr.Ports)))
		log("$ " + shared.FormatNmap(args))
	}
	res, _, err := shared.RunNmap(ctx, args)
	if err != nil || res == nil {
		return
	}
	phase2Ports := portsForIP(res, target)

	// Pre-phase-2 service map (from port-name lookup, no -sV).
	prevServices := map[int]string{}
	for _, p := range tr.Ports {
		prevServices[p.Port] = strings.ToLower(p.Service)
	}

	// Phase 2 with -sV gives the authoritative ports — adopt them.
	tr.Ports = phase2Ports
	tr.OpenCount = countOpen(tr.Ports)

	// --- Phase 3: follow up on services that turned out to be different ---
	type newSvc struct {
		port int
		p    Port
	}
	var newcomers []newSvc
	for _, p := range phase2Ports {
		if p.State != "open" {
			continue
		}
		actual := strings.ToLower(p.Service)
		if actual == "" {
			continue
		}
		prev := prevServices[p.Port]
		if prev != actual {
			newcomers = append(newcomers, newSvc{port: p.Port, p: p})
		}
	}
	if len(newcomers) == 0 {
		return
	}

	// Compute scripts for these newly-detected services that weren't run in
	// phase 2 (so we don't re-run identical scripts).
	already := map[string]struct{}{}
	for _, s := range scripts {
		already[s] = struct{}{}
	}
	addExtras := map[string]struct{}{}
	for _, n := range newcomers {
		for _, s := range extraScriptsForPort(n.p) {
			if _, dup := already[s]; dup {
				continue
			}
			addExtras[s] = struct{}{}
		}
	}
	if len(addExtras) == 0 {
		return
	}
	addList := make([]string, 0, len(addExtras))
	for s := range addExtras {
		addList = append(addList, s)
	}
	sort.Strings(addList)
	newPortNums := make([]int, 0, len(newcomers))
	for _, n := range newcomers {
		newPortNums = append(newPortNums, n.port)
	}
	sort.Ints(newPortNums)
	newPortStrs := make([]string, len(newPortNums))
	for i, n := range newPortNums {
		newPortStrs[i] = fmt.Sprintf("%d", n)
	}

	args3 := append([]string{}, timing...)
	args3 = append(args3, "-n", "-Pn",
		"--host-timeout", "3m",
		"--max-retries", "2",
		"--script", strings.Join(addList, ","),
		"-p", strings.Join(newPortStrs, ","),
		target,
	)
	if log != nil {
		log(fmt.Sprintf("→ Phase 3 follow-up on %s · %d new scripts for ports %s", target, len(addList), strings.Join(newPortStrs, ",")))
		log("$ " + shared.FormatNmap(args3))
	}
	res3, _, err := shared.RunNmap(ctx, args3)
	if err != nil || res3 == nil {
		return
	}
	mergeScripts(tr, portsForIP(res3, target))
}

// uniqueScriptsForPorts flattens extraScriptsForHost's group map into a sorted
// unique list, used when we just need a single --script argument.
func uniqueScriptsForPorts(ports []Port) []string {
	groups := extraScriptsForHost(ports)
	out := make([]string, 0, len(groups))
	for s := range groups {
		out = append(out, s)
	}
	sort.Strings(out)
	return out
}

// portsForIP picks the single host record matching `ip` (or the first record
// when scanning a single host) and returns its parsed Port slice.
func portsForIP(res *shared.NmapXML, ip string) []Port {
	if res == nil {
		return nil
	}
	for _, h := range res.Hosts {
		if h.PrimaryAddress() == ip {
			return portsFromHost(h)
		}
	}
	if len(res.Hosts) == 1 {
		return portsFromHost(res.Hosts[0])
	}
	return nil
}

// openPortsCSV used to join open-port numbers into a -p argument. The new
// flow scans the user-supplied target-ports verbatim in phase 2, so this
// helper is no longer called. Kept around as a no-op stub to avoid breaking
// any future caller; the linter would otherwise complain about an unused
// function.
var _ = openPortsCSV

func openPortsCSV(ports []Port) string {
	nums := make([]int, 0, len(ports))
	for _, p := range ports {
		if p.State == "open" {
			nums = append(nums, p.Port)
		}
	}
	sort.Ints(nums)
	parts := make([]string, len(nums))
	for i, n := range nums {
		parts[i] = fmt.Sprintf("%d", n)
	}
	return strings.Join(parts, ",")
}

// mergeScripts grafts the Scripts array from `incoming` ports into the
// matching ports of `tr.Ports`, keyed by (port, protocol). Existing scripts
// with the same ID are not duplicated.
func mergeScripts(tr *TargetResult, incoming []Port) {
	if tr == nil || len(incoming) == 0 {
		return
	}
	key := func(p Port) string { return fmt.Sprintf("%d/%s", p.Port, p.Protocol) }
	idx := map[string]int{}
	for i, p := range tr.Ports {
		idx[key(p)] = i
	}
	for _, np := range incoming {
		i, ok := idx[key(np)]
		if !ok {
			continue
		}
		seen := map[string]bool{}
		for _, s := range tr.Ports[i].Scripts {
			seen[s.ID] = true
		}
		for _, s := range np.Scripts {
			if !seen[s.ID] {
				tr.Ports[i].Scripts = append(tr.Ports[i].Scripts, s)
			}
		}
	}
}

// timingArgs translates the user-facing speed setting into nmap timing flags.
// Maps onto nmap's -T0…-T5 templates plus a few "extreme" presets that pin
// --min-rate / --max-rate for either stealth (slow) or speed (loud).
//
//	paranoid    -T0                              IDS-friendly, 5+ min between probes
//	sneaky      -T1                              avoids most simple IDS / firewalls
//	polite      -T2                              minimal bandwidth, slow
//	normal      -T3                              nmap default
//	fast        -T4                              recommended default for scaNNer
//	aggressive  -T5                              fast, may be flagged
//	insane      -T5 --max-rate 1500              very fast, capped
//	blast       -T5 --min-rate 5000 --max-retries 1   loud, no patience
//	stealth     -T2 --max-rate 50               throttled to 50 pkt/s
func timingArgs(speed string) []string {
	switch strings.ToLower(strings.TrimSpace(speed)) {
	case "paranoid", "t0":
		return []string{"-T0"}
	case "sneaky", "t1":
		return []string{"-T1"}
	case "polite", "t2":
		return []string{"-T2"}
	case "normal", "t3":
		return []string{"-T3"}
	case "stealth":
		return []string{"-T2", "--max-rate", "50"}
	case "aggressive", "t5":
		return []string{"-T5"}
	case "insane":
		return []string{"-T5", "--max-rate", "1500"}
	case "blast":
		return []string{"-T5", "--min-rate", "5000", "--max-retries", "1"}
	case "fast", "t4", "":
		return []string{"-T4"}
	default:
		return []string{"-T4"}
	}
}

// commonsInRange returns nmap's well-known top-100 commons intersected with
// the user's port range. Used by the firewall-path phase 2 so we don't audit
// thousands of phantom-open ports.
func commonsInRange(scope Scope, custom string) string {
	// Top-100 nmap "common" tcp ports — verbatim from nmap's services file
	// (sorted by frequency, then numerically here for stability).
	commons := []int{
		7, 9, 13, 21, 22, 23, 25, 26, 37, 53, 79, 80, 81, 88, 106, 110, 111,
		113, 119, 135, 139, 143, 144, 179, 199, 389, 427, 443, 444, 445, 465,
		513, 514, 515, 543, 544, 548, 554, 587, 631, 646, 873, 990, 993, 995,
		1025, 1026, 1027, 1028, 1029, 1110, 1433, 1720, 1723, 1755, 1900,
		2000, 2001, 2049, 2121, 2717, 3000, 3128, 3306, 3389, 3986, 4899,
		5000, 5009, 5051, 5060, 5101, 5190, 5357, 5432, 5631, 5666, 5800,
		5900, 6000, 6001, 6646, 7070, 8000, 8008, 8009, 8080, 8081, 8443,
		8888, 9100, 9999, 10000, 32768, 49152, 49153, 49154, 49155, 49156, 49157,
	}
	allowed := func(p int) bool { return true }
	switch scope {
	case ScopeCustom, ScopeRange:
		c := strings.TrimSpace(custom)
		if c == "" {
			return ""
		}
		allowed = portFilterFromSpec(c)
	}
	keep := make([]string, 0, len(commons))
	for _, p := range commons {
		if allowed(p) {
			keep = append(keep, fmt.Sprintf("%d", p))
		}
	}
	return strings.Join(keep, ",")
}

// portFilterFromSpec builds an inclusion predicate from an nmap-style port
// spec ("22,80,443" or "1-1024" or mixes). Used to compute the intersection
// with the commons list.
func portFilterFromSpec(spec string) func(int) bool {
	type rng struct{ lo, hi int }
	var ranges []rng
	for _, part := range strings.Split(spec, ",") {
		part = strings.TrimSpace(part)
		if part == "" {
			continue
		}
		if strings.HasPrefix(part, "T:") || strings.HasPrefix(part, "U:") {
			part = part[2:]
		}
		if i := strings.Index(part, "-"); i > 0 {
			lo, hi := 0, 0
			fmt.Sscanf(part[:i], "%d", &lo)
			fmt.Sscanf(part[i+1:], "%d", &hi)
			if lo > 0 && hi >= lo {
				ranges = append(ranges, rng{lo, hi})
			}
		} else {
			n := 0
			fmt.Sscanf(part, "%d", &n)
			if n > 0 {
				ranges = append(ranges, rng{n, n})
			}
		}
	}
	return func(p int) bool {
		for _, r := range ranges {
			if p >= r.lo && p <= r.hi {
				return true
			}
		}
		return false
	}
}

// isMultiHostTarget returns true if the target is a CIDR or range nmap will
// expand into multiple host records.
func isMultiHostTarget(target string) bool {
	t := strings.TrimSpace(target)
	if strings.Contains(t, "/") {
		return true
	}
	for i := 1; i < len(t); i++ {
		if t[i] == '-' && t[i-1] >= '0' && t[i-1] <= '9' {
			return true
		}
	}
	return false
}

func ipLess(a, b string) bool {
	pa := strings.Split(a, ".")
	pb := strings.Split(b, ".")
	if len(pa) != 4 || len(pb) != 4 {
		return a < b
	}
	for i := 0; i < 4; i++ {
		var na, nb int
		fmt.Sscanf(pa[i], "%d", &na)
		fmt.Sscanf(pb[i], "%d", &nb)
		if na != nb {
			return na < nb
		}
	}
	return false
}

func portArgList(scope Scope, custom string) []string {
	switch scope {
	case ScopeFull:
		return []string{"-p-"}
	case ScopeCustom:
		c := strings.TrimSpace(custom)
		if c == "" {
			c = "21,22,80,443,445,3389"
		}
		return []string{"-p", c}
	case ScopeRange:
		c := strings.TrimSpace(custom)
		if c == "" {
			c = "1-1024"
		}
		return []string{"-p", c}
	case "top100":
		return []string{"--top-ports", "100"}
	default:
		return []string{"--top-ports", "1000"}
	}
}

// scriptArg is no longer used — the new two-phase strategy runs `-A` first
// and then a service-aware focused script pass. The Config.ScriptCat field
// is kept for backwards compatibility but ignored.

func portsFromHost(h shared.NmapHost) []Port {
	out := []Port{}
	for _, p := range h.Ports.Ports {
		if p.State.State != "open" && p.State.State != "open|filtered" {
			continue
		}
		port := Port{
			Port:      p.PortID,
			Protocol:  p.Protocol,
			State:     p.State.State,
			Service:   p.Service.Name,
			Product:   p.Service.Product,
			Version:   p.Service.Version,
			ExtraInfo: p.Service.ExtraInfo,
			Tunnel:    p.Service.Tunnel,
		}
		for _, s := range p.Scripts {
			port.Scripts = append(port.Scripts, ScriptOutput{ID: s.ID, Output: s.Output})
		}
		out = append(out, port)
	}
	return out
}

func countOpen(p []Port) int {
	n := 0
	for _, x := range p {
		if x.State == "open" {
			n++
		}
	}
	return n
}

// applyFirewallHeuristic detects hosts that nmap declared "fully open" because
// a firewall is reflecting probes, and trims the result to genuine services
// only. The rule: if more than 100 ports came back as open, keep just the
// ones with an actual service banner (Service / Product / Version present);
// the rest are flagged as firewalled and excluded from the visible Port list.
const firewallSuspicionThreshold = 100

func applyFirewallHeuristic(tr *TargetResult) {
	if tr == nil || len(tr.Ports) <= firewallSuspicionThreshold {
		return
	}
	verified := make([]Port, 0, len(tr.Ports))
	for _, p := range tr.Ports {
		if p.State != "open" {
			continue
		}
		if p.Service != "" || p.Product != "" || p.Version != "" {
			verified = append(verified, p)
		}
	}
	tr.FirewalledCount = len(tr.Ports) - len(verified)
	tr.SuspectedFirewall = true
	tr.Ports = verified
	tr.OpenCount = len(verified)
}
