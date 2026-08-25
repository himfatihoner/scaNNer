package shared

import (
	"bufio"
	"bytes"
	"context"
	"encoding/xml"
	"fmt"
	"io"
	"regexp"
	"sort"
	"strconv"
	"strings"
)

// NmapXML is the subset of nmap's XML output we care about.
type NmapXML struct {
	XMLName  xml.Name     `xml:"nmaprun"`
	Hosts    []NmapHost   `xml:"host"`
	RunStats NmapRunStats `xml:"runstats"`
}

type NmapHost struct {
	Status    NmapStatus    `xml:"status"`
	Addresses []NmapAddress `xml:"address"`
	Hostnames NmapHostnames `xml:"hostnames"`
	Ports     NmapPorts     `xml:"ports"`
}

type NmapStatus struct {
	State  string `xml:"state,attr"`  // up | down
	Reason string `xml:"reason,attr"` // echo-reply, no-response, ...
}

type NmapAddress struct {
	Addr     string `xml:"addr,attr"`
	AddrType string `xml:"addrtype,attr"` // ipv4 | mac | ipv6
}

type NmapHostnames struct {
	Names []NmapName `xml:"hostname"`
}
type NmapName struct {
	Name string `xml:"name,attr"`
	Type string `xml:"type,attr"`
}

type NmapPorts struct {
	Ports []NmapPort `xml:"port"`
}

type NmapPort struct {
	Protocol string        `xml:"protocol,attr"`
	PortID   int           `xml:"portid,attr"`
	State    NmapPortState `xml:"state"`
	Service  NmapService   `xml:"service"`
	Scripts  []NmapScript  `xml:"script"`
}

type NmapPortState struct {
	State  string `xml:"state,attr"`
	Reason string `xml:"reason,attr"`
}

type NmapService struct {
	Name      string `xml:"name,attr"`
	Product   string `xml:"product,attr"`
	Version   string `xml:"version,attr"`
	ExtraInfo string `xml:"extrainfo,attr"`
	Tunnel    string `xml:"tunnel,attr"`
	Method    string `xml:"method,attr"`
	OSType    string `xml:"ostype,attr"`
}

type NmapScript struct {
	ID     string `xml:"id,attr"`
	Output string `xml:"output,attr"`
}

type NmapRunStats struct {
	Finished NmapFinished `xml:"finished"`
}
type NmapFinished struct {
	Elapsed string `xml:"elapsed,attr"`
	Summary string `xml:"summary,attr"`
}

// PrimaryAddress returns the first IPv4 address of the host (falls back to any).
func (h NmapHost) PrimaryAddress() string {
	for _, a := range h.Addresses {
		if a.AddrType == "ipv4" {
			return a.Addr
		}
	}
	if len(h.Addresses) > 0 {
		return h.Addresses[0].Addr
	}
	return ""
}

func (h NmapHost) PrimaryHostname() string {
	for _, n := range h.Hostnames.Names {
		if n.Type == "user" || n.Type == "PTR" {
			return n.Name
		}
	}
	if len(h.Hostnames.Names) > 0 {
		return h.Hostnames.Names[0].Name
	}
	return ""
}

// FormatCommand renders an executable + its argv as a roughly shell-paste-able
// string. Used by scanners to surface "what command did we just run" through
// the progress callback so the live console can display it.
func FormatCommand(prog string, args []string) string {
	parts := append([]string{prog}, args...)
	out := make([]string, 0, len(parts))
	for _, p := range parts {
		if strings.ContainsAny(p, " \t\"'") {
			out = append(out, "'"+strings.ReplaceAll(p, "'", "'\\''")+"'")
		} else {
			out = append(out, p)
		}
	}
	return strings.Join(out, " ")
}

// FormatNmap is a convenience wrapper for RunNmap callers that want to log
// the exact command line; mirrors the args RunNmap actually invokes.
func FormatNmap(args []string) string {
	full := append([]string{"-oX", "-"}, args...)
	return FormatCommand("nmap", full)
}

// nmapPctRe extracts the live completion percentage nmap prints to stderr when
// --stats-every is set, e.g. "SYN Stealth Scan Timing: About 45.34% done; ETC:".
var nmapPctRe = regexp.MustCompile(`About ([0-9.]+)% done`)

// ParseNmapProgress pulls the "About X% done" percentage out of one nmap
// stderr line, returning (pct, true) on a match.
func ParseNmapProgress(line string) (float64, bool) {
	m := nmapPctRe.FindStringSubmatch(line)
	if m == nil {
		return 0, false
	}
	v, err := strconv.ParseFloat(m[1], 64)
	if err != nil {
		return 0, false
	}
	return v, true
}

// RunNmap executes nmap with the given args and returns parsed XML.
// Args should NOT include -oX — the function adds it automatically with stdout target.
// stderr is captured but only returned on failure.
//
// When the namespace killswitch is engaged the resulting command is
// transparently wrapped via shared.Command so it spawns inside the
// isolated network namespace — no flag injection needed.
func RunNmap(ctx context.Context, args []string) (*NmapXML, []byte, error) {
	return RunNmapProgress(ctx, args, nil)
}

// RunNmapProgress is RunNmap with a live-progress callback. When onProgress is
// non-nil it adds `--stats-every 2s` and streams nmap's stderr, invoking
// onProgress(pct, line) on every "About X% done" timing line — so a long
// single-target scan reports live movement instead of sitting frozen until it
// finishes. XML is read from stdout (`-oX -`) separately from the stderr
// progress stream. With onProgress nil this behaves exactly like the old
// CombinedOutput path (no --stats-every, no streaming), so existing callers
// are unaffected.
func RunNmapProgress(ctx context.Context, args []string, onProgress func(pct float64, line string)) (*NmapXML, []byte, error) {
	full := append([]string{"-oX", "-"}, args...)
	if onProgress != nil {
		full = append([]string{"-oX", "-", "--stats-every", "2s"}, args...)
	}
	cmd := Command(ctx, "nmap", full...)

	stdoutPipe, err := cmd.StdoutPipe()
	if err != nil {
		return nil, nil, fmt.Errorf("nmap stdout pipe: %w", err)
	}
	stderrPipe, err := cmd.StderrPipe()
	if err != nil {
		return nil, nil, fmt.Errorf("nmap stderr pipe: %w", err)
	}
	if err := cmd.Start(); err != nil {
		return nil, nil, fmt.Errorf("nmap execution failed: %w", err)
	}

	// Drain stdout (the XML) fully in a goroutine so a large report can't
	// deadlock against a full stderr pipe.
	var outBuf bytes.Buffer
	stdoutDone := make(chan struct{})
	go func() {
		_, _ = io.Copy(&outBuf, stdoutPipe)
		close(stdoutDone)
	}()

	// Scan stderr line by line: forward timing lines to onProgress and keep a
	// capped copy so a failure can report what nmap complained about.
	var errBuf bytes.Buffer
	sc := bufio.NewScanner(stderrPipe)
	sc.Buffer(make([]byte, 0, 64*1024), 1024*1024)
	for sc.Scan() {
		line := sc.Text()
		if errBuf.Len() < 32*1024 {
			errBuf.WriteString(line)
			errBuf.WriteByte('\n')
		}
		if onProgress != nil {
			if pct, ok := ParseNmapProgress(line); ok {
				onProgress(pct, strings.TrimSpace(line))
			}
		}
	}
	<-stdoutDone
	waitErr := cmd.Wait()

	out := outBuf.Bytes()
	if waitErr != nil && len(out) == 0 {
		reason := strings.TrimSpace(errBuf.String())
		if reason != "" {
			return nil, errBuf.Bytes(), fmt.Errorf("nmap execution failed: %w: %s", waitErr, reason)
		}
		return nil, errBuf.Bytes(), fmt.Errorf("nmap execution failed: %w", waitErr)
	}
	// nmap exits non-zero on certain conditions while still producing useful XML.
	// Try to extract the XML even if exit was non-zero.
	xmlStart := bytes.Index(out, []byte("<?xml"))
	if xmlStart < 0 {
		xmlStart = bytes.Index(out, []byte("<nmaprun"))
	}
	if xmlStart < 0 {
		reason := strings.TrimSpace(errBuf.String())
		if reason == "" {
			reason = strings.TrimSpace(string(out))
		}
		return nil, out, fmt.Errorf("no XML in nmap output: %s", reason)
	}
	var parsed NmapXML
	if err := xml.Unmarshal(out[xmlStart:], &parsed); err != nil {
		return nil, out, fmt.Errorf("nmap XML parse: %w", err)
	}
	return &parsed, out, nil
}

// PortSpec converts a high-level scope (common|range|full|custom) plus
// optional custom value into the -p argument for nmap.
func PortSpec(scope, customValue string) string {
	switch strings.ToLower(scope) {
	case "common":
		// Top 1000 — nmap default behavior, but explicit for clarity.
		return "--top-ports 1000"
	case "range":
		// custom carries "1-1024" style range. Validate roughly.
		c := strings.TrimSpace(customValue)
		if c == "" {
			c = "1-1024"
		}
		return "-p " + c
	case "full":
		return "-p-"
	case "custom":
		c := strings.TrimSpace(customValue)
		if c == "" {
			c = "80,443"
		}
		return "-p " + c
	default:
		return "--top-ports 1000"
	}
}

// ExpandTargets walks a list of user-supplied target strings and returns the
// flat IP/host list, expanding CIDR blocks (≤/24 by default) and hyphen ranges.
// Single hosts and hostnames pass through untouched. The ipMax param caps how
// many IPs a single CIDR is allowed to expand to (255 = /24, 65535 = /16).
func ExpandTargets(in []string, ipMax int) []string {
	if ipMax <= 0 {
		ipMax = 255
	}
	out := []string{}
	seen := map[string]bool{}
	add := func(s string) {
		s = strings.TrimSpace(s)
		if s == "" || seen[s] {
			return
		}
		seen[s] = true
		out = append(out, s)
	}
	for _, raw := range in {
		raw = strings.TrimSpace(raw)
		if raw == "" {
			continue
		}
		// CIDR: "10.0.0.0/24"
		if strings.Contains(raw, "/") {
			ips := expandCIDR(raw, ipMax)
			if len(ips) == 0 {
				add(raw) // pass through if invalid/too big
				continue
			}
			for _, ip := range ips {
				add(ip)
			}
			continue
		}
		// Hyphen range: "10.0.0.1-50" (last octet) or "10.0.0.1-10.0.0.50"
		if ips := expandRange(raw, ipMax); len(ips) > 0 {
			for _, ip := range ips {
				add(ip)
			}
			continue
		}
		add(raw)
	}
	return out
}

func expandCIDR(cidr string, ipMax int) []string {
	parts := strings.SplitN(cidr, "/", 2)
	if len(parts) != 2 {
		return nil
	}
	ip := strings.Split(parts[0], ".")
	if len(ip) != 4 {
		return nil
	}
	var bits int
	if _, err := fmt.Sscanf(parts[1], "%d", &bits); err != nil || bits < 0 || bits > 32 {
		return nil
	}
	hostCount := 1 << uint(32-bits)
	if hostCount > ipMax {
		return nil
	}
	var base uint32
	for i := 0; i < 4; i++ {
		var n uint32
		if _, err := fmt.Sscanf(ip[i], "%d", &n); err != nil || n > 255 {
			return nil
		}
		base = base<<8 | n
	}
	mask := uint32(0xFFFFFFFF) << uint(32-bits)
	netStart := base & mask
	// Skip network address (first) and broadcast address (last) for any block
	// /30 or larger — those aren't host IPs. /31 (RFC 3021 point-to-point) and
	// /32 (single host) are returned unchanged.
	first, last := uint32(0), uint32(hostCount-1)
	if bits <= 30 {
		first = 1
		last = uint32(hostCount - 2)
	}
	out := make([]string, 0, last-first+1)
	for i := first; i <= last; i++ {
		v := netStart + i
		out = append(out, fmt.Sprintf("%d.%d.%d.%d", (v>>24)&0xff, (v>>16)&0xff, (v>>8)&0xff, v&0xff))
	}
	return out
}

func expandRange(s string, ipMax int) []string {
	// Only handle the "10.0.0.1-50" (last octet) variant — the more generic
	// nmap range form is broad enough to defer to nmap itself when we don't
	// match here.
	dash := strings.LastIndex(s, "-")
	if dash <= 0 {
		return nil
	}
	left := s[:dash]
	right := s[dash+1:]
	octets := strings.Split(left, ".")
	if len(octets) != 4 {
		return nil
	}
	var lo, hi int
	if _, err := fmt.Sscanf(octets[3], "%d", &lo); err != nil {
		return nil
	}
	if _, err := fmt.Sscanf(right, "%d", &hi); err != nil {
		return nil
	}
	if lo < 0 || hi > 255 || lo > hi {
		return nil
	}
	if hi-lo+1 > ipMax {
		return nil
	}
	out := []string{}
	for v := lo; v <= hi; v++ {
		out = append(out, fmt.Sprintf("%s.%s.%s.%d", octets[0], octets[1], octets[2], v))
	}
	return out
}

// ExpandPortSpec turns a comma/range port spec ("80,443,8000-8100")
// into a deduplicated, sorted []int. Invalid tokens are skipped
// silently; call ValidPortSpec first if you need strict validation.
// Ranges are capped at the input — no cap-from-1; "1-1024" expands to
// 1024 entries. The caller is responsible for limiting input size.
func ExpandPortSpec(s string) []int {
	seen := map[int]bool{}
	out := []int{}
	for _, tok := range strings.Split(s, ",") {
		tok = strings.TrimSpace(tok)
		if tok == "" {
			continue
		}
		if strings.Contains(tok, "-") {
			parts := strings.SplitN(tok, "-", 2)
			a, errA := strconv.Atoi(strings.TrimSpace(parts[0]))
			b, errB := strconv.Atoi(strings.TrimSpace(parts[1]))
			if errA != nil || errB != nil || a < 1 || b > 65535 || a > b {
				continue
			}
			for p := a; p <= b; p++ {
				if !seen[p] {
					seen[p] = true
					out = append(out, p)
				}
			}
			continue
		}
		n, err := strconv.Atoi(tok)
		if err != nil || n < 1 || n > 65535 {
			continue
		}
		if !seen[n] {
			seen[n] = true
			out = append(out, n)
		}
	}
	sort.Ints(out)
	return out
}

// ParsePortList performs minimal validation of a comma/range port spec.
// Returns true if every token is a number or num-num range in [1,65535].
func ValidPortSpec(s string) bool {
	if s == "" {
		return false
	}
	for _, tok := range strings.Split(s, ",") {
		tok = strings.TrimSpace(tok)
		if tok == "" {
			continue
		}
		if strings.Contains(tok, "-") {
			parts := strings.SplitN(tok, "-", 2)
			a, errA := strconv.Atoi(strings.TrimSpace(parts[0]))
			b, errB := strconv.Atoi(strings.TrimSpace(parts[1]))
			if errA != nil || errB != nil || a < 1 || b > 65535 || a > b {
				return false
			}
			continue
		}
		n, err := strconv.Atoi(tok)
		if err != nil || n < 1 || n > 65535 {
			return false
		}
	}
	return true
}
