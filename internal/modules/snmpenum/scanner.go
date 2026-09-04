package snmpenum

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"scanner/internal/modules/shared"
	"strings"
	"sync"
	"time"
)

// Walk holds the output of snmpwalk for a particular OID branch.
type Walk struct {
	Label     string `json:"label"`
	OID       string `json:"oid"`
	LineCount int    `json:"line_count"`
	Output    string `json:"output"`
}

type TargetResult struct {
	Target           string   `json:"target"`
	ValidCommunities []string `json:"valid_communities"`
	// WriteCommunities is the subset of ValidCommunities that were
	// confirmed to grant write (RW) access via an snmpset round-trip
	// on sysContact (1.3.6.1.2.1.1.4.0). RW access is a near-instant
	// escalation path on most network gear and so is surfaced
	// separately in the UI.
	WriteCommunities []string `json:"write_communities,omitempty"`
	SystemDescr      string   `json:"system_descr,omitempty"`
	SystemUptime     string   `json:"system_uptime,omitempty"`
	SystemContact    string   `json:"system_contact,omitempty"`
	SystemName       string   `json:"system_name,omitempty"`
	SystemLocation   string   `json:"system_location,omitempty"`
	Walks            []Walk   `json:"walks"`
	Error            string   `json:"error,omitempty"`
}

type ScanResult struct {
	Results []TargetResult `json:"results"`
	// Warnings holds non-fatal, module-wide notices — chiefly a missing
	// external tool (snmpget/snmpwalk/snmpset not on PATH) or an OID
	// branch walk that failed with a real error (timeout/auth) rather
	// than legitimately returning no data. Surfaced as an amber note on
	// the results page so a scan that produced empty/partial data shows
	// the true cause instead of looking like a clean "nothing found".
	// Audit fix: eliminate silent tool degradation (mirrors dnsenum).
	Warnings []string `json:"warnings,omitempty"`
}

type Config struct {
	Targets         []string
	Communities     []string // brute candidates (v1/v2c)
	Walks           []string // selected branches: "system","interfaces","processes","software","users","tcp","udp","installed-services"
	Concurrency     int
	SkipBrute       bool   // if true, only try the first community as-is
	ForcedCommunity string // if set, skip brute and use this directly
	// SNMPv3 support. v3 has per-user authentication + optional
	// privacy. If V3User is set the scanner skips community brute
	// entirely and connects with these credentials instead. SecLevel
	// is one of: "noAuthNoPriv", "authNoPriv", "authPriv".
	V3User      string
	V3AuthPass  string
	V3PrivPass  string
	V3AuthProto string // "MD5" or "SHA" (default SHA)
	V3PrivProto string // "DES" or "AES" (default AES)
	V3SecLevel  string // noAuthNoPriv | authNoPriv | authPriv

	// v3ConfPath is the directory containing the per-scan snmp.conf
	// that holds defAuthPassphrase / defPrivPassphrase. It is set by
	// Scan() at startup and consumed via the SNMPCONFPATH env var on
	// each *exec.Cmd so v3 passphrases never appear in argv (where
	// any local user could read them via /proc/<pid>/cmdline).
	v3ConfPath string
}

type ProgressFunc func(done int, msg string)
type PartialFunc func(*ScanResult)

// Default community brute list — the classics.
var DefaultCommunities = []string{
	"public", "private", "manager", "admin", "router", "cisco", "default",
	"community", "snmp", "snmpd", "guest", "read", "write", "snmp_trap",
}

// Branch labels → OID
//
// Audit fix (MEDIUM quality): the original list missed the
// lateral-movement staples that snmp-check, snmpwalk-cookbooks, and
// the standard HTB/OSCP "got SNMP, now what" workflow target — ARP
// table, routing table, IP addresses, LanMan shares, Windows service
// names, Cisco CDP neighbors. Added below. `installed-services` also
// pointed at hrSWRunName (already covered by the `processes` branch
// via its parent OID) so it's re-pointed at hrSWInstalledTable — the
// actual "what's installed on this Windows/Linux host" table.
var Branches = map[string]string{
	"system":             "1.3.6.1.2.1.1",
	"interfaces":         "1.3.6.1.2.1.2.2",
	"processes":          "1.3.6.1.2.1.25.4.2",
	"software":           "1.3.6.1.2.1.25.6.3.1.2",
	"users":              "1.3.6.1.4.1.77.1.2.25",
	"tcp":                "1.3.6.1.2.1.6.13",
	"udp":                "1.3.6.1.2.1.7.5",
	"installed-services": "1.3.6.1.2.1.25.6.3",
	"arp":                "1.3.6.1.2.1.4.22.1.2",
	"routes":             "1.3.6.1.2.1.4.21.1",
	"ipaddrs":            "1.3.6.1.2.1.4.20",
	"shares":             "1.3.6.1.4.1.77.1.2.27",
	"win32-services":     "1.3.6.1.4.1.77.1.2.3.1.1",
	"cdp":                "1.3.6.1.4.1.9.9.23.1.2.1.1.6",
}

func Scan(ctx context.Context, cfg Config, progress ProgressFunc, partial PartialFunc) *ScanResult {
	if ctx == nil {
		ctx = context.Background()
	}
	if cfg.Concurrency <= 0 {
		cfg.Concurrency = 16
	}
	if len(cfg.Communities) == 0 {
		cfg.Communities = DefaultCommunities
	}
	if len(cfg.Walks) == 0 {
		cfg.Walks = []string{"system", "interfaces", "processes"}
	}

	// Audit fix (HIGH): SNMPv3 auth/priv passwords used to flow into
	// argv ("-A <pass>", "-X <pass>") where any local user could grab
	// them from /proc/<pid>/cmdline. Now we write a per-scan snmp.conf
	// with mode 0600 holding defAuthPassphrase/defPrivPassphrase and
	// point net-snmp at it via the SNMPCONFPATH env var on each child
	// process. The conf file (and its containing dir) is removed when
	// this Scan returns.
	if cfg.V3User != "" && (cfg.V3AuthPass != "" || cfg.V3PrivPass != "") {
		if dir, err := writeV3ConfDir(cfg); err == nil && dir != "" {
			cfg.v3ConfPath = dir
			defer os.RemoveAll(dir)
			// Blank the in-memory pass fields so any downstream
			// log/print path can't leak them.
			cfg.V3AuthPass = ""
			cfg.V3PrivPass = ""
		}
	}

	out := &ScanResult{}
	var mu sync.Mutex
	sem := make(chan struct{}, cfg.Concurrency)
	var wg sync.WaitGroup
	done := 0

	// addWarn records a de-duplicated, module-wide non-fatal notice.
	// Safe to call from the per-target goroutines (guards out.Warnings
	// with mu). Warnings never clobber results — a scan that found data
	// on some targets still shows it alongside the amber note.
	addWarn := func(msg string) {
		if msg == "" {
			return
		}
		mu.Lock()
		for _, existing := range out.Warnings {
			if existing == msg {
				mu.Unlock()
				return
			}
		}
		out.Warnings = append(out.Warnings, msg)
		mu.Unlock()
	}

	// Audit fix (silent tool degradation): preflight the net-snmp
	// binaries and surface any that are missing as module-wide,
	// non-fatal warnings. Without this a host with SNMP open but the
	// scanner missing snmpget looks identical to a hardened host — the
	// brute pass just returns no communities and every target reports
	// "no valid community found", which reads as "box is locked down"
	// rather than "the tool isn't installed". snmpget is the sole
	// enumeration engine; snmpwalk backs the OID-branch walks; snmpset
	// backs the RW-community probe. We only warn on an outright missing
	// binary here — a tool that is present but times out is handled
	// per-call, and legitimate zero-result scans stay quiet.
	if _, err := exec.LookPath("snmpget"); err != nil {
		addWarn("snmpget not installed — SNMP enumeration cannot run (apt install snmp / net-snmp).")
	}
	if len(cfg.Walks) > 0 {
		if _, err := exec.LookPath("snmpwalk"); err != nil {
			addWarn("snmpwalk not installed — OID branch walks return no data (apt install snmp / net-snmp).")
		}
	}
	if cfg.V3User == "" {
		if _, err := exec.LookPath("snmpset"); err != nil {
			addWarn("snmpset not installed — read/write (RW) community detection skipped (apt install snmp / net-snmp).")
		}
	}

	// Audit S2: throttle per-target snapshot+marshal to 2s.
	throttle := shared.NewPartialThrottler(2 * time.Second)
	pushPartial := func() {
		if partial == nil {
			return
		}
		if !throttle.ShouldFire() {
			return
		}
		mu.Lock()
		snap := &ScanResult{
			Results:  append([]TargetResult(nil), out.Results...),
			Warnings: append([]string(nil), out.Warnings...),
		}
		mu.Unlock()
		partial(snap)
	}
	// Audit fix (MEDIUM quality): give enumerate a way to push a
	// snapshot mid-flight (after system OIDs, after each walk) so
	// single-target scans don't stare at a blank results page for the
	// full walk duration. The snapshot merges completed targets with a
	// copy of the in-progress TargetResult; throttle still caps at 2s.
	pushPartialMid := func(cur *TargetResult) {
		if partial == nil {
			return
		}
		if !throttle.ShouldFire() {
			return
		}
		mu.Lock()
		snapRes := append([]TargetResult(nil), out.Results...)
		snapWarn := append([]string(nil), out.Warnings...)
		mu.Unlock()
		if cur != nil {
			snapRes = append(snapRes, *cur)
		}
		partial(&ScanResult{Results: snapRes, Warnings: snapWarn})
	}

	for _, t := range cfg.Targets {
		if ctx.Err() != nil {
			break
		}
		// Audit fix: target flows into snmpwalk/snmpget argv; reject
		// values that could become flags or shell injection (K04/K09 shape).
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
			if progress != nil {
				mu.Lock()
				cur := done
				mu.Unlock()
				progress(cur, fmt.Sprintf("Probing %s ...", target))
			}
			tr := enumerate(ctx, target, cfg, func(msg string) {
				mu.Lock()
				cur := done
				mu.Unlock()
				if progress == nil {
					return
				}
				// Audit fix (MEDIUM quality): "$ "-prefixed messages
				// are command-line crumbs that the DB captures into
				// scans.commands. Pass them through unmodified so the
				// prefix survives the target-context wrap.
				if strings.HasPrefix(msg, "$ ") {
					progress(cur, msg)
				} else {
					progress(cur, fmt.Sprintf("%s · %s", target, msg))
				}
			}, addWarn, pushPartialMid)
			mu.Lock()
			done++
			out.Results = append(out.Results, *tr)
			cur := done
			mu.Unlock()
			if progress != nil {
				rwNote := ""
				if len(tr.WriteCommunities) > 0 {
					rwNote = fmt.Sprintf(" (%d RW)", len(tr.WriteCommunities))
				}
				progress(cur, fmt.Sprintf("[%d/%d] %s — %d valid communities%s, %d walks", cur, len(cfg.Targets), target, len(tr.ValidCommunities), rwNote, len(tr.Walks)))
			}
			pushPartial()
		}(t)
	}
	wg.Wait()
	throttle.Force()
	pushPartial()
	return out
}

func enumerate(ctx context.Context, target string, cfg Config, log func(string), warn func(string), pushMid func(*TargetResult)) *TargetResult {
	tr := &TargetResult{Target: target}
	// midFlush is a nil-safe convenience for pushing a mid-flight
	// snapshot of the in-progress TargetResult back to the caller so
	// the UI can render partial data (system identity, first N walks)
	// before the whole target finishes.
	midFlush := func() {
		if pushMid != nil {
			pushMid(tr)
		}
	}

	// v3: skip community brute entirely — auth flows through the configured
	// USM user. We still record a synthetic "ValidCommunities" entry so the
	// UI shows the v3 mode used; the community argument is ignored by the
	// snmpget/snmpwalk CLIs once -v3 -u is passed.
	var candidates []string
	if cfg.V3User != "" {
		_, label := snmpAuthArgs(cfg, "")
		candidates = []string{label + ":" + cfg.V3User}
		if log != nil {
			log("v3 auth: user=" + cfg.V3User + " level=" + label)
		}
	} else if cfg.ForcedCommunity != "" {
		candidates = []string{cfg.ForcedCommunity}
	} else if cfg.SkipBrute {
		candidates = []string{"public"}
	} else {
		candidates = bruteCommunities(ctx, target, cfg.Communities, log)
		if len(candidates) == 0 {
			tr.Error = "no valid SNMP community string found"
			return tr
		}
	}
	tr.ValidCommunities = candidates

	// Use the first valid community for walks (ignored under v3).
	community := candidates[0]
	if cfg.V3User == "" && log != nil {
		log("walking with community: " + community)
	}

	// Pull system identity (always). Audit fix (MEDIUM perf): collapse
	// five sequential snmpget round-trips into a single multi-OID call.
	// net-snmp accepts multiple OIDs on the same command line and emits
	// one value per line (with -Oqv); this saves four fork/exec cycles
	// and four worst-case retry budgets per target.
	sysOIDs := []string{
		"1.3.6.1.2.1.1.1.0",
		"1.3.6.1.2.1.1.3.0",
		"1.3.6.1.2.1.1.4.0",
		"1.3.6.1.2.1.1.5.0",
		"1.3.6.1.2.1.1.6.0",
	}
	// Audit fix (MEDIUM quality): emit a "$ "-prefixed command crumb
	// so the results page's Commands tab shows the exact invocation
	// (with -Oqv redacted / community values still visible for repro).
	if log != nil {
		auth, _ := snmpAuthArgs(cfg, community)
		sysArgs := append([]string{}, auth...)
		sysArgs = append(sysArgs, "-Oqv", "-t", "2", "-r", "1", "--", target)
		sysArgs = append(sysArgs, sysOIDs...)
		log("$ " + shared.FormatCommand("snmpget", sysArgs))
	}
	sysVals := snmpgetMulti(ctx, cfg, target, community, sysOIDs)
	if len(sysVals) > 0 {
		tr.SystemDescr = sysVals[0]
	}
	if len(sysVals) > 1 {
		tr.SystemUptime = sysVals[1]
	}
	if len(sysVals) > 2 {
		tr.SystemContact = sysVals[2]
	}
	if len(sysVals) > 3 {
		tr.SystemName = sysVals[3]
	}
	if len(sysVals) > 4 {
		tr.SystemLocation = sysVals[4]
	}
	// Audit fix (MEDIUM quality): flush a mid-flight snapshot now so
	// the UI can render system identity even before the walks begin.
	midFlush()

	// Audit fix (HIGH): probe each valid v2c community for RW access
	// by round-tripping sysContact.0 via snmpset, then restoring the
	// original value captured above. RW access on SNMP is a
	// near-instant escalation path (running-config write, OS image
	// upload, route table rewrite, etc.) and worth flagging
	// separately from RO.
	//
	// We only probe v1/v2c — the existing v3 path connects with a
	// single user/level supplied by the operator, so "did this
	// community grant RW" reduces to "did the user have RW," which
	// the operator already knows.
	if cfg.V3User == "" {
		for _, c := range candidates {
			if ctx.Err() != nil {
				break
			}
			if checkRWCommunity(ctx, cfg, target, c, tr.SystemContact, log) {
				tr.WriteCommunities = append(tr.WriteCommunities, c)
			}
		}
	}

	// Walk each requested branch.
	for _, w := range cfg.Walks {
		oid, ok := Branches[w]
		if !ok {
			continue
		}
		if log != nil {
			// Audit fix (MEDIUM quality): "$ " prefix so the DB
			// captures the crumb into scans.commands, plus include
			// the fully-formed snmpwalk argv for copy-paste repro.
			auth, _ := snmpAuthArgs(cfg, community)
			args := append([]string{}, auth...)
			args = append(args, "-Oqs", "-t", "2", "-r", "1", "--", target, oid)
			log("$ " + shared.FormatCommand("snmpwalk", args))
		}
		out, walkErr := snmpwalkCfg(ctx, cfg, target, community, oid)
		if out == "" {
			// Audit fix (silent tool degradation): a walk that exits
			// with a real error (timeout, auth failure) and no output
			// is NOT the same as a branch the device legitimately
			// doesn't implement. Surface the former as a non-fatal
			// note so the operator can tell "branch empty" from "walk
			// failed"; stay quiet on a clean empty branch (walkErr == "").
			if walkErr != "" && warn != nil {
				reason, ok := shared.TranslateToolError(walkErr)
				if !ok {
					reason = firstNonEmptyLine(walkErr, 180)
				}
				if reason != "" {
					warn(fmt.Sprintf("%s: %s branch walk failed — %s", target, w, reason))
				}
			}
			continue
		}
		tr.Walks = append(tr.Walks, Walk{
			Label:     w,
			OID:       oid,
			LineCount: strings.Count(out, "\n") + 1,
			Output:    truncate(out, 24*1024),
		})
		// Audit fix (MEDIUM quality): flush a snapshot after each
		// walk so long-running enumerations (interfaces on a chassis
		// switch, processes/software on a jump host) stream results
		// into the UI instead of appearing all-at-once at the end.
		midFlush()
	}
	return tr
}

// bruteCommunities tries each candidate via onesixtyone (very fast UDP burst).
// Falls back to per-community snmpget if onesixtyone is unavailable.
func bruteCommunities(ctx context.Context, target string, candidates []string, log func(string)) []string {
	if len(candidates) == 0 {
		return nil
	}
	// Cancel guard (audit B62): skip the brute pass if the scan has
	// already been cancelled — onesixtyone's UDP burst still takes
	// several seconds even on small candidate lists.
	if ctx.Err() != nil {
		return nil
	}
	if _, err := exec.LookPath("onesixtyone"); err == nil {
		// onesixtyone -c <file> <ip>
		f, err := os.CreateTemp("", "snmp-comm-*.txt")
		if err == nil {
			for _, c := range candidates {
				fmt.Fprintln(f, c)
			}
			f.Close()
			defer os.Remove(f.Name())
			if log != nil {
				// Audit fix (MEDIUM quality): "$ " prefix so the DB
				// captures the crumb into scans.commands.
				log("$ " + shared.FormatCommand("onesixtyone", []string{"-c", f.Name(), target}))
			}
			cmd := shared.Command(ctx, "onesixtyone", "-c", f.Name(), target)
			out, err := cmd.CombinedOutput()
			// Audit fix (silent tool degradation): don't log an
			// unconditional success line. onesixtyone was found on PATH
			// above, so a non-zero exit here is a real failure (bad
			// args, killed) — note it and fall through to the per-
			// community snmpget probe below instead of implying the
			// burst completed. Stay quiet on cancellation.
			if err != nil && ctx.Err() == nil {
				if log != nil {
					reason, ok := shared.TranslateToolError(err.Error())
					if !ok {
						reason, ok = shared.TranslateToolError(string(out))
					}
					if !ok {
						reason = firstNonEmptyLine(string(out), 180)
						if reason == "" {
							reason = err.Error()
						}
					}
					log("$ onesixtyone failed (" + reason + ") — falling back to snmpget probes")
				}
			} else if err == nil && log != nil {
				log(fmt.Sprintf("onesixtyone tried %d communities", len(candidates)))
			}
			var found []string
			for _, line := range strings.Split(string(out), "\n") {
				// Lines look like:  10.0.0.1 [public] Linux ...
				lb := strings.Index(line, "[")
				rb := strings.Index(line, "]")
				if lb >= 0 && rb > lb+1 {
					comm := line[lb+1 : rb]
					if comm != "" && !contains(found, comm) {
						found = append(found, comm)
					}
				}
			}
			if len(found) > 0 {
				return found
			}
		}
	}
	// Fallback: snmpget probe per candidate. Audit fix (MEDIUM perf):
	// the previous loop was fully sequential (~4s worst-case per
	// candidate with -t 2 -r 1) and never checked ctx mid-loop, so a
	// cancel during the 14-candidate default list could still take
	// ~56s to land on an unreachable host. Run probes in parallel via
	// a small bounded worker pool (8 wide is enough — these are UDP
	// roundtrips, not CPU work) and propagate cancellation.
	const bruteWorkers = 8
	sem := make(chan struct{}, bruteWorkers)
	var mu sync.Mutex
	var found []string
	var wg sync.WaitGroup
	for _, c := range candidates {
		if ctx.Err() != nil {
			break
		}
		wg.Add(1)
		sem <- struct{}{}
		go func(community string) {
			defer wg.Done()
			defer func() { <-sem }()
			if ctx.Err() != nil {
				return
			}
			if v := snmpget(ctx, target, community, "1.3.6.1.2.1.1.1.0"); v != "" {
				mu.Lock()
				found = append(found, community)
				mu.Unlock()
			}
		}(c)
	}
	wg.Wait()
	return found
}

// snmpAuthArgs builds the common SNMP authentication arguments for v1/v2c
// (community-based) vs v3 (user-based). Honors cfg.V3User: when set, we
// switch the whole call from "-v2c -c <community>" to the v3 USM form.
// Returns args + a "human" version label for log messages.
//
// When cfg.v3ConfPath is set, the v3 passphrases are loaded from the
// per-scan snmp.conf (defAuthPassphrase / defPrivPassphrase) instead
// of being passed via -A / -X. This keeps secrets out of argv (visible
// to other local users via /proc/<pid>/cmdline).
func snmpAuthArgs(cfg Config, community string) ([]string, string) {
	if cfg.V3User == "" {
		// Legacy v2c.
		return []string{"-v2c", "-c", community}, "v2c"
	}
	level := cfg.V3SecLevel
	if level == "" {
		level = "authPriv"
	}
	args := []string{"-v3", "-u", cfg.V3User, "-l", level, "-t", "2", "-r", "1"}
	if level == "authNoPriv" || level == "authPriv" {
		proto := cfg.V3AuthProto
		if proto == "" {
			proto = "SHA"
		}
		args = append(args, "-a", proto)
		// Only inline the passphrase when the snmp.conf path wasn't
		// prepared (e.g. write failed). The conf file sets
		// defAuthPassphrase so net-snmp picks it up implicitly.
		if cfg.v3ConfPath == "" {
			args = append(args, "-A", cfg.V3AuthPass)
		}
	}
	if level == "authPriv" {
		proto := cfg.V3PrivProto
		if proto == "" {
			proto = "AES"
		}
		args = append(args, "-x", proto)
		if cfg.v3ConfPath == "" {
			args = append(args, "-X", cfg.V3PrivPass)
		}
	}
	return args, "v3/" + level
}

// writeV3ConfDir creates a directory under DATA_DIR (or the OS temp
// dir) containing a single snmp.conf (mode 0600) holding the v3
// passphrases. net-snmp picks the file up when SNMPCONFPATH is set
// on the child process. Returns the directory path so the caller can
// (a) point SNMPCONFPATH at it and (b) defer-remove it.
func writeV3ConfDir(cfg Config) (string, error) {
	base := os.Getenv("DATA_DIR")
	if base == "" {
		base = os.TempDir()
	}
	// Random suffix so concurrent scans never clash and the path is
	// not predictable to other local users.
	var rb [8]byte
	_, _ = rand.Read(rb[:])
	dir := filepath.Join(base, "snmp-v3-"+hex.EncodeToString(rb[:]))
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return "", err
	}
	path := filepath.Join(dir, "snmp.conf")
	f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0o600)
	if err != nil {
		os.RemoveAll(dir)
		return "", err
	}
	defer f.Close()
	var b strings.Builder
	if cfg.V3AuthPass != "" {
		b.WriteString("defAuthPassphrase ")
		b.WriteString(cfg.V3AuthPass)
		b.WriteString("\n")
	}
	if cfg.V3PrivPass != "" {
		b.WriteString("defPrivPassphrase ")
		b.WriteString(cfg.V3PrivPass)
		b.WriteString("\n")
	}
	if _, err := f.WriteString(b.String()); err != nil {
		os.RemoveAll(dir)
		return "", err
	}
	return dir, nil
}

// snmpCmd wraps shared.Command and, when the scan has a v3 snmp.conf
// directory prepared, attaches SNMPCONFPATH so net-snmp loads the
// passphrases from there instead of argv. The inherited environment
// is preserved so PATH/LD_LIBRARY_PATH still work.
func snmpCmd(ctx context.Context, cfg Config, name string, args ...string) *exec.Cmd {
	cmd := shared.Command(ctx, name, args...)
	if cfg.v3ConfPath != "" {
		env := cmd.Env
		if env == nil {
			env = os.Environ()
		}
		env = append(env, "SNMPCONFPATH="+cfg.v3ConfPath)
		cmd.Env = env
	}
	return cmd
}

func snmpget(ctx context.Context, target, community, oid string) string {
	return snmpgetCfg(ctx, Config{}, target, community, oid)
}

func snmpgetCfg(ctx context.Context, cfg Config, target, community, oid string) string {
	auth, _ := snmpAuthArgs(cfg, community)
	args := append([]string{}, auth...)
	// Audit fix (MEDIUM security): "--" separates flags from positional
	// arguments so a target that starts with "-" cannot be re-parsed by
	// net-snmp's GNU-getopt-style CLI as an option. shared.SafeTarget
	// already rejects such targets at handler entry; this is
	// defense-in-depth for the config-restore / DB-tamper path.
	args = append(args, "-Oqv", "-t", "2", "-r", "1", "--", target, oid)
	cmd := snmpCmd(ctx, cfg, "snmpget", args...)
	out, err := cmd.Output()
	if err != nil {
		return ""
	}
	return strings.TrimSpace(string(out))
}

// snmpgetMulti issues a single snmpget for multiple OIDs at once. net-snmp
// emits one value per line in input order when -Oqv is set, so the caller
// can map line[i] → oids[i]. The returned slice always has len == len(oids);
// missing/error lines are returned as "" so positional unpacking is safe.
// Audit fix (MEDIUM perf): replaces five fork/exec cycles per target for
// the system-identity probes with a single one.
func snmpgetMulti(ctx context.Context, cfg Config, target, community string, oids []string) []string {
	if len(oids) == 0 {
		return nil
	}
	auth, _ := snmpAuthArgs(cfg, community)
	args := append([]string{}, auth...)
	// See snmpgetCfg — "--" defense-in-depth against argv injection.
	args = append(args, "-Oqv", "-t", "2", "-r", "1", "--", target)
	args = append(args, oids...)
	cmd := snmpCmd(ctx, cfg, "snmpget", args...)
	out, err := cmd.Output()
	values := make([]string, len(oids))
	if err != nil {
		return values
	}
	lines := strings.Split(strings.TrimRight(string(out), "\n"), "\n")
	for i := 0; i < len(oids) && i < len(lines); i++ {
		v := strings.TrimSpace(lines[i])
		// net-snmp emits "No Such Object available on this agent at this OID"
		// (and similar) for missing OIDs — drop those so callers see "" the
		// same way they would for an outright error.
		if strings.HasPrefix(v, "No Such") || strings.HasPrefix(v, "No more") {
			v = ""
		}
		values[i] = v
	}
	return values
}

func snmpwalk(ctx context.Context, target, community, oid string) string {
	out, _ := snmpwalkCfg(ctx, Config{}, target, community, oid)
	return out
}

// snmpwalkMaxBytes caps the amount of stdout we read from a single
// snmpwalk invocation. Audit fix (MEDIUM perf): walks like
// 1.3.6.1.2.1.2.2 (interfaces) on a chassis switch or
// 1.3.6.1.2.1.25.6.3.1.2 (installed-software) on a Windows host can
// emit tens of MB. Anything beyond ~32 KB is wasted (the result column
// truncates at 24 KB anyway), so stream the read through a LimitReader
// instead of buffering the full output with CombinedOutput.
const snmpwalkMaxBytes = 32 * 1024

// snmpwalkCfg returns (output, failReason). failReason is set ONLY when
// the walk produced no stdout AND exited with a real error (a timeout,
// an auth failure) — never on a clean empty branch and never on the
// deliberate byte-cap kill below (which always leaves stdout non-empty).
// Callers use failReason to distinguish "branch empty" from "walk failed"
// (audit fix: silent tool degradation).
func snmpwalkCfg(ctx context.Context, cfg Config, target, community, oid string) (string, string) {
	auth, _ := snmpAuthArgs(cfg, community)
	args := append([]string{}, auth...)
	// See snmpgetCfg — "--" defense-in-depth against argv injection.
	args = append(args, "-Oqs", "-t", "2", "-r", "1", "--", target, oid)
	cmd := snmpCmd(ctx, cfg, "snmpwalk", args...)
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		return "", ""
	}
	// Capture stderr into a small bounded, memory-backed sink instead of
	// discarding it, so a walk that exits non-zero with no stdout can
	// report the real reason. capWriter is not the child's pipe, so a
	// chatty agent still can't block the child on a full pipe buffer
	// (net-snmp stderr is a line or two in practice anyway).
	errBuf := &capWriter{max: 4 * 1024}
	cmd.Stderr = errBuf
	if err := cmd.Start(); err != nil {
		return "", ""
	}
	// Read at most snmpwalkMaxBytes; if the walk exceeds that, kill
	// the child so it doesn't keep emitting on a pipe nobody reads.
	buf, _ := io.ReadAll(io.LimitReader(stdout, snmpwalkMaxBytes))
	if cmd.Process != nil {
		// Best-effort kill — if Wait already reaped the process, this
		// is a no-op. We don't care about the return code; the walk's
		// usefulness ends with the data we've already captured.
		_ = cmd.Process.Kill()
	}
	werr := cmd.Wait()
	res := string(buf)
	// Only report a failure when the walk yielded NOTHING and actually
	// errored. When we hit the byte cap the process is killed on purpose
	// (werr == "signal: killed") but res != "" so this is skipped — a
	// deliberate kill is never mistaken for a failure. Cancellation stays
	// quiet too.
	failReason := ""
	if res == "" && werr != nil && ctx.Err() == nil {
		failReason = strings.TrimSpace(errBuf.String())
	}
	return res, failReason
}

// snmpsetCfg sets a single OID via snmpset using whichever auth mode
// the cfg implies (v2c community or v3 USM). Returns (ok, reason): ok is
// true on a clean exit; on failure reason carries the tool's output/error
// (bounded) so the caller can tell an agent that actively refused the
// write (notWritable/noAccess → a *confirmed* read-only) from one that
// never answered (timeout/missing binary → an inconclusive RW probe).
func snmpsetCfg(ctx context.Context, cfg Config, target, community, oid, valueType, value string) (bool, string) {
	auth, _ := snmpAuthArgs(cfg, community)
	args := append([]string{}, auth...)
	// See snmpgetCfg — "--" defense-in-depth against argv injection.
	args = append(args, "-t", "2", "-r", "1", "--", target, oid, valueType, value)
	cmd := snmpCmd(ctx, cfg, "snmpset", args...)
	out, err := cmd.CombinedOutput()
	if err != nil {
		reason := strings.TrimSpace(string(out))
		if reason == "" {
			reason = err.Error()
		}
		return false, reason
	}
	return true, ""
}

// checkRWCommunity probes a community for write access by writing a
// random marker into sysContact.0, reading it back, and restoring the
// original value. snmpset is required (net-snmp); if it isn't in
// PATH we silently skip (the result just lacks the RW annotation).
//
// The probe is best-effort: any failure (snmpset missing, OID not
// writable on this device, network timeout) yields a non-RW
// classification rather than a hard error, because the goal is to
// surface RW as a positive signal, not to block enumeration.
func checkRWCommunity(ctx context.Context, cfg Config, target, community, origContact string, log func(string)) bool {
	if _, err := exec.LookPath("snmpset"); err != nil {
		return false
	}
	if ctx.Err() != nil {
		return false
	}
	// Random marker so a concurrent scanner running the same probe
	// can't confuse our round-trip.
	var rb [8]byte
	_, _ = rand.Read(rb[:])
	marker := "scanner-rw-" + hex.EncodeToString(rb[:])

	const sysContactOID = "1.3.6.1.2.1.1.4.0"
	if ok, reason := snmpsetCfg(ctx, cfg, target, community, sysContactOID, "s", marker); !ok {
		// Audit fix (silent tool degradation): a write that fails
		// because the agent answered notWritable/noAccess is a
		// *confirmed* read-only — expected, stay quiet. A write that
		// fails because the agent never responded (timeout) or snmpset
		// isn't installed leaves the RW verdict UNKNOWN, so log a crumb
		// telling the operator the RO classification is inconclusive.
		if log != nil && ctx.Err() == nil && setProbeInconclusive(reason) {
			log("$ snmpset RW probe inconclusive for community " + community + " (" + firstNonEmptyLine(reason, 180) + ") — RW status unknown, not a confirmed read-only")
		}
		return false
	}
	// Many devices accept the SET PDU silently without applying it
	// (e.g. when the community is RO and the agent is lenient about
	// errors); the GET round-trip is the actual test.
	got := snmpgetCfg(ctx, cfg, target, community, sysContactOID)
	rw := strings.Contains(got, marker)

	// Always attempt to restore the original sysContact, regardless
	// of whether the round-trip confirmed — if the write took effect
	// we don't want to leave our marker on the device.
	if origContact != "" {
		_, _ = snmpsetCfg(ctx, cfg, target, community, sysContactOID, "s", origContact)
	}
	if rw && log != nil {
		log("RW access confirmed for community: " + community)
	}
	return rw
}

func contains(slice []string, val string) bool {
	for _, s := range slice {
		if s == val {
			return true
		}
	}
	return false
}

func truncate(s string, max int) string {
	if len(s) <= max {
		return s
	}
	return s[:max] + "\n... [truncated]"
}

// firstNonEmptyLine returns the first non-blank line of s, trimmed to max
// characters, for use as a fallback failure reason when TranslateToolError
// doesn't recognize the raw tool output. Credential-safe: caps length and
// takes only the first line (tool stderr rarely carries secrets).
func firstNonEmptyLine(s string, max int) string {
	for _, ln := range strings.Split(s, "\n") {
		ln = strings.TrimSpace(ln)
		if ln == "" {
			continue
		}
		if max > 0 && len(ln) > max {
			ln = ln[:max] + "…"
		}
		return ln
	}
	return ""
}

// setProbeInconclusive reports whether an snmpset failure reason means the
// agent never rendered a read/write policy decision (a timeout, an
// unreachable host, or a missing snmpset binary) as opposed to actively
// refusing the write (notWritable / noAccess), which is a *confirmed*
// read-only and needs no warning.
func setProbeInconclusive(reason string) bool {
	low := strings.ToLower(reason)
	for _, s := range []string{
		"timeout", "no response", "executable file not found",
		"no such file", "unknown host", "cannot resolve", "not found in",
	} {
		if strings.Contains(low, s) {
			return true
		}
	}
	return false
}

// capWriter is a bounded, memory-backed sink for child stderr: it keeps at
// most max bytes and silently drops the rest, and always reports the full
// write as consumed so the exec copy goroutine never errors or blocks.
type capWriter struct {
	buf []byte
	max int
}

func (c *capWriter) Write(p []byte) (int, error) {
	if c.max > 0 && len(c.buf) < c.max {
		room := c.max - len(c.buf)
		if room > len(p) {
			room = len(p)
		}
		c.buf = append(c.buf, p[:room]...)
	}
	return len(p), nil
}

func (c *capWriter) String() string { return string(c.buf) }
