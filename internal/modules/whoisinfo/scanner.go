package whoisinfo

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"net"
	"regexp"
	"scanner/internal/modules/shared"
	"strings"
	"sync"
	"time"
)

type Record struct {
	Field string `json:"field"`
	Value string `json:"value"`
}

type ASNInfo struct {
	ASN          string   `json:"asn"`
	Organization string   `json:"organization,omitempty"`
	CountryCode  string   `json:"country_code,omitempty"`
	Registry     string   `json:"registry,omitempty"`
	Prefixes     []string `json:"prefixes,omitempty"`
}

type TargetResult struct {
	Target       string   `json:"target"`
	Kind         string   `json:"kind"` // "domain" or "ip"
	ResolvedIPs  []string `json:"resolved_ips,omitempty"`
	WHOISRecords []Record `json:"whois_records"` // parsed key:value lines
	WHOISRaw     string   `json:"whois_raw,omitempty"`
	ASN          *ASNInfo `json:"asn,omitempty"`
	Error        string   `json:"error,omitempty"`
}

type ScanResult struct {
	Results []TargetResult `json:"results"`
}

type Config struct {
	Targets       []string
	IncludePrefix bool // expand AS prefix list (slower, extra whois call)
	Concurrency   int
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

	// Audit S2: throttle per-target partials to 2s — was O(N²) marshal.
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

	// logCmd surfaces "$ <command>" crumbs (via the progress callback, using
	// the current done count) so the live console + "Commands run" panel show
	// exactly which whois invocations ran. Safe for concurrent use — progress
	// is already invoked from every worker goroutine.
	logCmd := func(msg string) {
		if progress == nil {
			return
		}
		mu.Lock()
		cur := done
		mu.Unlock()
		progress(cur, msg)
	}

	for _, t := range cfg.Targets {
		if ctx.Err() != nil {
			break
		}
		wg.Add(1)
		sem <- struct{}{}
		go func(target string) {
			defer wg.Done()
			defer func() { <-sem }()
			if progress != nil {
				mu.Lock()
				cur := done
				mu.Unlock()
				progress(cur, fmt.Sprintf("Looking up %s ...", target))
			}
			tr := lookupOne(ctx, target, cfg, logCmd)
			mu.Lock()
			done++
			out.Results = append(out.Results, *tr)
			cur := done
			mu.Unlock()
			if progress != nil {
				summary := fmt.Sprintf("[%d/%d] %s", cur, len(cfg.Targets), target)
				if tr.ASN != nil && tr.ASN.ASN != "" {
					summary += fmt.Sprintf(" — AS%s %s", tr.ASN.ASN, tr.ASN.Organization)
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

func lookupOne(ctx context.Context, target string, cfg Config, log func(string)) *TargetResult {
	target = strings.TrimSpace(target)
	tr := &TargetResult{Target: target}

	// Strip protocol/path if present
	clean := stripURL(target)
	tr.Target = clean

	// Audit MEDIUM: reject targets that would flag-inject into whois or
	// contain shell metachars. Surfaces the error per-target instead of
	// silently corrupting the whois command line.
	if _, ok := shared.SafeTarget(clean); !ok {
		tr.Error = "invalid target: rejected for flag-like or unsafe characters"
		return tr
	}

	// Decide if input is an IP or a domain
	if ip := net.ParseIP(clean); ip != nil {
		tr.Kind = "ip"
		tr.ResolvedIPs = []string{clean}
	} else {
		tr.Kind = "domain"
		// Audit MEDIUM: (a) net.LookupIP bypassed killswitch source-IP
		// binding; (b) no timeout — one slow resolver would park an
		// entire worker; (c) v6-only domains got no ASN. Use a resolver
		// whose Dial goes through shared.BoundDialer so it inherits the
		// killswitch binding, wrap ctx with 5s deadline, and keep both
		// v4 and v6 addresses.
		lctx, cancel := context.WithTimeout(ctx, 5*time.Second)
		res := &net.Resolver{
			PreferGo: true,
			Dial:     shared.BoundDialer(nil, 5*time.Second).DialContext,
		}
		if addrs, err := res.LookupIPAddr(lctx, clean); err == nil {
			for _, ipa := range addrs {
				tr.ResolvedIPs = append(tr.ResolvedIPs, ipa.IP.String())
			}
		}
		cancel()
	}

	// 1. Plain whois on the target itself
	whoisOut, whoisErr := runWhois(ctx, clean, "", log)
	// Audit MEDIUM: cap WHOISRaw at 4 KiB — bounded result blob avoids
	// approaching the 50 MB soft cap on multi-target scans, and 4 KiB
	// is more than enough for the parsed-display use case.
	tr.WHOISRaw = truncate(whoisOut, 4*1024)
	tr.WHOISRecords = parseWhois(whoisOut)
	if whoisErr != nil {
		if ctx.Err() != nil {
			tr.Error = "cancelled"
		} else {
			tr.Error = "whois failed: " + whoisErr.Error()
		}
	} else if whoisOut == "" {
		tr.Error = "whois returned no data"
	}

	// 2. ASN via Team Cymru. Cymru's " -v " query accepts both v4 and v6
	// literal forms; prefer v4 for the probe when available, otherwise
	// fall back to v6 (audit MEDIUM: v6-only assets used to get no ASN).
	var probeIP string
	if tr.Kind == "ip" {
		probeIP = clean
	} else {
		for _, s := range tr.ResolvedIPs {
			if ip := net.ParseIP(s); ip != nil && ip.To4() != nil {
				probeIP = s
				break
			}
		}
		if probeIP == "" && len(tr.ResolvedIPs) > 0 {
			probeIP = tr.ResolvedIPs[0]
		}
	}
	if probeIP != "" {
		if asn := lookupCymru(ctx, probeIP, log); asn != nil {
			tr.ASN = asn
			if cfg.IncludePrefix && asn.ASN != "" {
				asn.Prefixes = lookupASPrefixes(ctx, asn.ASN, log)
			}
		}
	}
	return tr
}

// whoisMaxOut caps stdout+stderr collected from a single whois subprocess.
// Audit MEDIUM: CombinedOutput() had no ceiling — a hostile or misbehaving
// server could stream unbounded bytes into the scanner's heap.
const whoisMaxOut = 2 * 1024 * 1024 // 2 MiB per invocation

// runWhoisTimeout is the per-invocation ceiling for a single whois call.
// Audit MEDIUM: without a deadline, a slow referral chain could park a
// worker for minutes; 20s covers even multi-hop registrar chases.
const runWhoisTimeout = 20 * time.Second

// runWhois invokes the system whois command. server is optional ("-h <server>").
// Audit MEDIUM: returns (output, error) so callers can distinguish
// exec failures (missing binary, timeouts) from genuinely empty output
// and from user cancellation.
func runWhois(ctx context.Context, query, server string, log func(string)) (string, error) {
	subctx, cancel := context.WithTimeout(ctx, runWhoisTimeout)
	defer cancel()
	args := []string{}
	if server != "" {
		args = append(args, "-h", server)
	}
	// Audit MEDIUM: "--" stops flag parsing so a target like "-V" or
	// "-hwhois.attacker.com" cannot inject flags into whois.
	args = append(args, "--", query)
	return runBoundedWhois(subctx, log, args...)
}

// runBoundedWhois runs `whois` with the given args, capping combined
// stdout+stderr at whoisMaxOut bytes. Excess bytes are silently dropped
// on the writer side — the subprocess keeps running so it can exit
// normally (kernel pipe buffer fills, but drops on our side prevent
// unbounded heap growth).
func runBoundedWhois(ctx context.Context, log func(string), args ...string) (string, error) {
	var buf bytes.Buffer
	lw := &limitWriter{w: &buf, remaining: whoisMaxOut}
	if log != nil {
		log("$ " + shared.FormatCommand("whois", args))
	}
	cmd := shared.Command(ctx, "whois", args...)
	cmd.Stdout = lw
	cmd.Stderr = lw
	err := cmd.Run()
	out := buf.Bytes()
	if lw.truncated {
		out = append(out, []byte("\n... [truncated by whoisMaxOut]")...)
	}
	return string(out), err
}

// limitWriter is an io.Writer that forwards up to `remaining` bytes to
// the wrapped writer, then drops the rest. Sets truncated=true when it
// overflows. Not safe for concurrent use, but exec.Cmd guarantees at
// most one Write goroutine when Stdout==Stderr (same comparable value).
type limitWriter struct {
	w         io.Writer
	remaining int
	truncated bool
}

func (l *limitWriter) Write(p []byte) (int, error) {
	if l.remaining <= 0 {
		l.truncated = true
		return len(p), nil
	}
	if len(p) > l.remaining {
		_, _ = l.w.Write(p[:l.remaining])
		l.remaining = 0
		l.truncated = true
		return len(p), nil
	}
	n, err := l.w.Write(p)
	l.remaining -= n
	return n, err
}

// kvLine matches "Key: Value" pairs. We keep only common, useful fields.
var kvLine = regexp.MustCompile(`^\s*([A-Za-z][A-Za-z0-9 _\-/]+?)\s*:\s*(.+?)\s*$`)

var keepFields = map[string]bool{}

func init() {
	for _, k := range []string{
		"domain name", "registrar", "registrar whois server", "registry domain id",
		"creation date", "registry expiry date", "expiration date", "updated date",
		"registrant", "registrant organization", "registrant country", "registrant email",
		"admin email", "tech email", "name server", "dnssec",
		"netname", "country", "org", "orgname", "organization", "cidr",
		"netrange", "originas", "owner", "ownerid",
	} {
		keepFields[k] = true
	}
}

// parseWhois scans whois output into a deduped, ordered list of useful fields.
func parseWhois(raw string) []Record {
	var out []Record
	seen := map[string]bool{}
	for _, line := range strings.Split(raw, "\n") {
		line = strings.TrimRight(line, "\r")
		if strings.HasPrefix(line, "%") || strings.HasPrefix(line, "#") {
			continue
		}
		m := kvLine.FindStringSubmatch(line)
		if m == nil {
			continue
		}
		k := strings.ToLower(strings.TrimSpace(m[1]))
		v := strings.TrimSpace(m[2])
		if v == "" || v == "REDACTED FOR PRIVACY" {
			continue
		}
		if !keepFields[k] {
			continue
		}
		key := k + "::" + v
		if seen[key] {
			continue
		}
		seen[key] = true
		out = append(out, Record{Field: m[1], Value: v})
	}
	return out
}

// lookupCymru queries whois.cymru.com for ASN/Org/CountryCode given an IP.
// Format: " -v <ip>" returns "AS | IP | BGP Prefix | CC | Registry | Allocated | AS Name"
func lookupCymru(ctx context.Context, ip string, log func(string)) *ASNInfo {
	subctx, cancel := context.WithTimeout(ctx, runWhoisTimeout)
	defer cancel()
	// Audit MEDIUM: bounded output + timeout + "--" flag stop.
	out, err := runBoundedWhois(subctx, log, "-h", "whois.cymru.com", "--", " -v "+ip)
	if err != nil && len(out) == 0 {
		return nil
	}
	for _, line := range strings.Split(out, "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "AS ") || strings.HasPrefix(line, "Bulk") {
			continue
		}
		parts := strings.Split(line, "|")
		if len(parts) < 5 {
			continue
		}
		asn := strings.TrimSpace(parts[0])
		if asn == "NA" || asn == "" {
			continue
		}
		info := &ASNInfo{
			ASN:         asn,
			CountryCode: strings.TrimSpace(parts[3]),
			Registry:    strings.TrimSpace(parts[4]),
		}
		// AS name is the last column
		if len(parts) >= 7 {
			info.Organization = strings.TrimSpace(parts[6])
		} else if len(parts) >= 6 {
			info.Organization = strings.TrimSpace(parts[5])
		}
		return info
	}
	return nil
}

// lookupASPrefixes asks RADB for the v4 prefixes announced by the AS.
func lookupASPrefixes(ctx context.Context, asn string, log func(string)) []string {
	asn = strings.TrimSpace(asn)
	asn = strings.TrimPrefix(asn, "AS")
	subctx, cancel := context.WithTimeout(ctx, runWhoisTimeout)
	defer cancel()
	// Audit MEDIUM: bounded output + timeout. Note that "--" already
	// separates whois's own flags from the query "-i origin AS<n>",
	// which is the whois query language passed through to the server.
	out, _ := runBoundedWhois(subctx, log, "-h", "whois.radb.net", "--", "-i origin AS"+asn)
	prefixes := map[string]bool{}
	for _, line := range strings.Split(out, "\n") {
		line = strings.TrimSpace(line)
		if !strings.HasPrefix(strings.ToLower(line), "route:") {
			continue
		}
		val := strings.TrimSpace(line[len("route:"):])
		if val != "" {
			prefixes[val] = true
		}
	}
	out2 := make([]string, 0, len(prefixes))
	for p := range prefixes {
		out2 = append(out2, p)
	}
	return out2
}

func stripURL(s string) string {
	s = strings.TrimSpace(s)
	if i := strings.Index(s, "://"); i >= 0 {
		s = s[i+3:]
	}
	if i := strings.Index(s, "/"); i >= 0 {
		s = s[:i]
	}
	// A bare IPv6 literal contains colons but no brackets and no port;
	// net.ParseIP catches it before we try to interpret a hextet as ":port".
	if ip := net.ParseIP(s); ip != nil {
		return s
	}
	// Handles "[ipv6]:port" and "host:port"; falls back to raw on error
	// (e.g. bare hostname, or malformed input).
	if host, _, err := net.SplitHostPort(s); err == nil {
		return host
	}
	return s
}

func truncate(s string, max int) string {
	if len(s) <= max {
		return s
	}
	return s[:max] + "\n... [truncated]"
}
