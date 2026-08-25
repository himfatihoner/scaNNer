package sslscan

import (
	"context"
	"encoding/xml"
	"fmt"
	"os"
	"os/exec"
	"regexp"
	"strconv"
	"strings"
	"time"

	"scanner/internal/modules/shared"
)

// Tool-driven SSL/TLS engine. The module no longer relies on Go crypto/tls
// stdlib probing (fast but shallow — no SSLv2/v3, no weak ciphers Go omits, no
// Heartbleed/POODLE/DROWN/Logjam). Instead every host:port is examined with the
// real tools installed on the box and their outputs are merged into HostResult:
//
//   - sslscan --xml : protocol enable/disable (incl. SSLv2/SSLv3), cipher list
//                     with strength, Heartbleed, TLS compression (CRIME),
//                     insecure renegotiation.
//   - nmap NSE      : ssl-enum-ciphers (A–F cipher grades) + ssl-poodle,
//                     ssl-heartbleed, sslv2-drown, ssl-dh-params vuln scripts
//                     (POODLE / DROWN / Logjam CVE findings).
//   - openssl/Go    : certificate details (handled by the Go handshake in
//                     scanner.go, which populates the rich CertInfo fields).

// ToolAvailability reports which external tools are present.
type ToolAvailability struct {
	Nmap    bool
	Sslscan bool
	Openssl bool
}

func detectTools() ToolAvailability {
	has := func(bin string) bool { _, err := exec.LookPath(bin); return err == nil }
	return ToolAvailability{
		Nmap:    has("nmap"),
		Sslscan: has("sslscan"),
		Openssl: has("openssl"),
	}
}

// ---- sslscan --xml ----

type sslscanDoc struct {
	Tests []sslscanTest `xml:"ssltest"`
}
type sslscanTest struct {
	Host          string             `xml:"host,attr"`
	Port          string             `xml:"port,attr"`
	Protocols     []sslscanProto     `xml:"protocol"`
	Ciphers       []sslscanCipher    `xml:"cipher"`
	Heartbleeds   []sslscanHeartbleed `xml:"heartbleed"`
	Compression   *sslscanFlag       `xml:"compression"`
	Renegotiation *sslscanReneg      `xml:"renegotiation"`
}
type sslscanProto struct {
	Type    string `xml:"type,attr"`    // "ssl" | "tls"
	Version string `xml:"version,attr"` // "2","3","1.0",...
	Enabled string `xml:"enabled,attr"` // "0" | "1"
}
type sslscanCipher struct {
	Status     string `xml:"status,attr"`     // preferred | accepted
	SSLVersion string `xml:"sslversion,attr"` // TLSv1.2 ...
	Bits       string `xml:"bits,attr"`
	Cipher     string `xml:"cipher,attr"`   // OpenSSL name, e.g. ECDHE-RSA-AES256-GCM-SHA384
	Strength   string `xml:"strength,attr"` // strong | acceptable | weak | null
}
type sslscanHeartbleed struct {
	SSLVersion string `xml:"sslversion,attr"`
	Vulnerable string `xml:"vulnerable,attr"` // "0" | "1"
}
type sslscanFlag struct {
	Supported string `xml:"supported,attr"`
}
type sslscanReneg struct {
	Supported string `xml:"supported,attr"`
	Secure    string `xml:"secure,attr"`
}

// runSslscan runs sslscan against host:port and returns the parsed first test
// plus a ToolRun capturing the reproducible command and sslscan's real console
// output (for the PoC). It writes the XML we parse to a temp file so stdout
// carries the human-readable console output; if the temp file can't be created
// it falls back to the legacy `--xml=/dev/stdout` (XML on stdout, no console).
func runSslscan(ctx context.Context, host string, port int, toolTimeout time.Duration, startTLS string) (*sslscanTest, ToolRun, error) {
	target := fmt.Sprintf("%s:%d", host, port)
	stFlag := sslscanStartTLSFlag(startTLS)

	// Reproducible display command — what an operator would run by hand.
	disp := []string{"sslscan", "--no-colour"}
	if stFlag != "" {
		disp = append(disp, stFlag)
	}
	disp = append(disp, target)
	run := ToolRun{Tool: "sslscan", Command: strings.Join(disp, " ")}

	// Actual run: XML → temp file, so stdout is the readable console output.
	xmlPath := ""
	if tmp, err := os.CreateTemp("", "sslscan-*.xml"); err == nil {
		xmlPath = tmp.Name()
		tmp.Close()
		defer os.Remove(xmlPath)
	}
	args := []string{"--no-colour"}
	if stFlag != "" {
		args = append(args, stFlag)
	}
	if xmlPath != "" {
		args = append(args, "--xml="+xmlPath)
	} else {
		args = append(args, "--xml=/dev/stdout")
	}
	args = append(args, target)

	cctx, cancel := context.WithTimeout(ctx, toolTimeout)
	defer cancel()
	out, err := shared.Command(cctx, "sslscan", args...).Output()

	// XML source: prefer the temp file (stdout is then the console output).
	xmlSrc := ""
	if xmlPath != "" {
		if b, e := os.ReadFile(xmlPath); e == nil {
			xmlSrc = string(b)
		}
		if len(out) > 0 {
			run.Output = capOutput(string(out)) // stdout = readable console
		}
	}
	if strings.Index(xmlSrc, "<document") < 0 {
		// Fallback: XML came out on stdout (no temp file, or older sslscan).
		xmlSrc = string(out)
		run.Output = "" // stdout was XML, not human-readable console
	}
	var doc sslscanDoc
	if start := strings.Index(xmlSrc, "<document"); start >= 0 {
		_ = xml.Unmarshal([]byte(xmlSrc[start:]), &doc)
	}
	if len(doc.Tests) > 0 {
		return &doc.Tests[0], run, nil
	}
	// XML missing or truncated — sslscan can die mid-run (e.g. "TLSv1.3 dying"
	// during the Heartbleed probe), leaving unparseable XML. Salvage the
	// protocol enumeration from the readable console output so we don't lose it
	// (and don't later misreport a server that clearly speaks TLS 1.2/1.3 as
	// having "No Modern TLS").
	if t := parseSslscanConsoleTest(run.Output); t != nil {
		return t, run, nil
	}
	if err != nil {
		return nil, run, err
	}
	return nil, run, fmt.Errorf("sslscan: no usable output")
}

// parseSslscanConsoleTest recovers a partial sslscanTest from sslscan's
// human-readable console output when its XML is missing/truncated. It parses the
// "SSL/TLS Protocols:" block (the most important data, printed early) into
// protocol rows; other sections are left empty. Returns nil if no protocol block
// is present.
func parseSslscanConsoleTest(console string) *sslscanTest {
	if !strings.Contains(console, "SSL/TLS Protocols:") {
		return nil
	}
	t := &sslscanTest{}
	inProto := false
	for _, ln := range strings.Split(console, "\n") {
		s := strings.TrimSpace(ln)
		if strings.Contains(s, "SSL/TLS Protocols:") {
			inProto = true
			continue
		}
		if !inProto {
			continue
		}
		fields := strings.Fields(s)
		if len(fields) >= 2 {
			if typ, ver := sslscanConsoleProto(fields[0]); typ != "" {
				enabled := "0"
				if strings.EqualFold(fields[len(fields)-1], "enabled") {
					enabled = "1"
				}
				t.Protocols = append(t.Protocols, sslscanProto{Type: typ, Version: ver, Enabled: enabled})
				continue
			}
		}
		// A blank line or the next section header ("  TLS Fallback SCSV:") ends
		// the protocol block.
		if s == "" || strings.HasSuffix(s, ":") {
			break
		}
	}
	if len(t.Protocols) == 0 {
		return nil
	}
	return t
}

// sslscanConsoleProto maps a console protocol label to sslscan's XML type/version.
func sslscanConsoleProto(name string) (typ, ver string) {
	switch name {
	case "SSLv2":
		return "ssl", "2"
	case "SSLv3":
		return "ssl", "3"
	case "TLSv1.0":
		return "tls", "1.0"
	case "TLSv1.1":
		return "tls", "1.1"
	case "TLSv1.2":
		return "tls", "1.2"
	case "TLSv1.3":
		return "tls", "1.3"
	}
	return "", ""
}

func sslscanStartTLSFlag(mode string) string {
	switch strings.ToLower(strings.TrimSpace(mode)) {
	case "smtp":
		return "--starttls-smtp"
	case "imap":
		return "--starttls-imap"
	case "pop3":
		return "--starttls-pop3"
	case "ftp":
		return "--starttls-ftp"
	case "ldap":
		return "--starttls-ldap"
	case "postgres", "psql":
		return "--starttls-psql"
	}
	return ""
}

// ---- nmap (all SSL NSE scripts in one invocation) ----

type nmapRun struct {
	Hosts []nmapHost `xml:"host"`
}
type nmapHost struct {
	Ports []nmapPort `xml:"ports>port"`
}
type nmapPort struct {
	Scripts []nmapScript `xml:"script"`
}
type nmapScript struct {
	ID     string `xml:"id,attr"`
	Output string `xml:"output,attr"`
}

// nmapSSL bundles the parsed NSE results for a host:port.
type nmapSSL struct {
	Ciphers      []CipherResult    // IANA name + protocol versions it was offered on
	CipherGrades map[string]string // IANA cipher name -> A..F
	Protocols    map[string]bool   // canonical name ("TLS 1.2") -> offered
	Findings     []Finding         // POODLE / DROWN / Logjam / Heartbleed
	// ScriptOutput keeps each NSE script's real console text (nmap's XML
	// `output` attribute IS the human-readable output) so a finding's PoC can
	// show the exact evidence that produced it.
	ScriptOutput map[string]string
	Command      string // reproducible console command
}

func runNmapSSL(ctx context.Context, host string, port int, toolTimeout time.Duration) (*nmapSSL, ToolRun, error) {
	scripts := "ssl-enum-ciphers,ssl-poodle,ssl-heartbleed,sslv2-drown,ssl-dh-params"
	args := []string{
		"-Pn",
		"--script", scripts,
		"-p", strconv.Itoa(port),
		"-oX", "-",
		host,
	}
	// -sV (service/version detection) was removed: it probes the port with the
	// full version-detection handshake matrix — slow and pointless when we're
	// running SSL NSE scripts on a known TLS port. At scale (hundreds of hosts ×
	// 3 tools) it pushed nmap past its timeout, so it returned NOTHING and the
	// module missed protocols/ciphers (e.g. TLS 1.0) that `nmap --script
	// ssl-enum-ciphers` finds instantly by hand. The NSE scripts do their own
	// TLS negotiation and don't need -sV.
	//
	// Reproducible display command drops the -oX (XML) plumbing so it matches
	// what an operator would type to see the same output.
	tr := ToolRun{Tool: "nmap", Command: fmt.Sprintf("nmap -Pn --script %s -p %d %s", scripts, port, host)}

	cctx, cancel := context.WithTimeout(ctx, toolTimeout)
	defer cancel()
	out, err := shared.Command(cctx, "nmap", args...).Output()
	if err != nil && len(out) == 0 {
		return nil, tr, err
	}
	var run nmapRun
	start := strings.Index(string(out), "<nmaprun")
	if start < 0 {
		return nil, tr, fmt.Errorf("nmap: no XML")
	}
	if err := xml.Unmarshal(out[start:], &run); err != nil {
		return nil, tr, fmt.Errorf("nmap: parse: %w", err)
	}
	res := &nmapSSL{CipherGrades: map[string]string{}, Protocols: map[string]bool{}, ScriptOutput: map[string]string{}, Command: tr.Command}
	for _, h := range run.Hosts {
		for _, p := range h.Ports {
			for _, s := range p.Scripts {
				if strings.TrimSpace(s.Output) != "" {
					res.ScriptOutput[s.ID] = s.Output
				}
				switch s.ID {
				case "ssl-enum-ciphers":
					parseEnum(s.Output, res)
				case "ssl-poodle":
					if f := nmapVulnFinding(s.Output, SevMedium, "POODLE (SSLv3)", "protocol"); f != nil {
						res.Findings = append(res.Findings, *f)
					}
				case "ssl-heartbleed":
					if f := nmapVulnFinding(s.Output, SevCritical, "Heartbleed", "protocol"); f != nil {
						res.Findings = append(res.Findings, *f)
					}
				case "sslv2-drown":
					if f := nmapVulnFinding(s.Output, SevCritical, "DROWN (SSLv2)", "protocol"); f != nil {
						res.Findings = append(res.Findings, *f)
					}
				case "ssl-dh-params":
					if f := nmapVulnFinding(s.Output, SevMedium, "Weak Diffie-Hellman (Logjam)", "cipher"); f != nil {
						res.Findings = append(res.Findings, *f)
					}
				}
			}
		}
	}
	// A concatenated readable transcript for the per-host evidence panel.
	var sb strings.Builder
	for _, id := range []string{"ssl-enum-ciphers", "ssl-poodle", "ssl-heartbleed", "sslv2-drown", "ssl-dh-params"} {
		if o := res.ScriptOutput[id]; strings.TrimSpace(o) != "" {
			sb.WriteString("| " + id + ":\n" + strings.TrimRight(o, "\n") + "\n")
		}
	}
	tr.Output = capOutput(sb.String())
	return res, tr, nil
}

var (
	enumProtoLine  = regexp.MustCompile(`^\s{2,4}(SSLv2|SSLv3|TLSv1\.\d):\s*$`)
	enumCipherLine = regexp.MustCompile(`^\s+([A-Z][A-Za-z0-9_]+)\s+\(.*\)\s+-\s+([A-F])\s*$`)
)

// nmapProtoName maps nmap's protocol label to the canonical HostResult name.
var nmapProtoName = map[string]string{
	"SSLv2": "SSL 2.0", "SSLv3": "SSL 3.0",
	"TLSv1.0": "TLS 1.0", "TLSv1.1": "TLS 1.1",
	"TLSv1.2": "TLS 1.2", "TLSv1.3": "TLS 1.3",
}

// parseEnum walks ssl-enum-ciphers text output, tracking the current protocol
// section so each cipher records the versions it's offered on, plus its grade.
func parseEnum(output string, res *nmapSSL) {
	cur := ""                                  // canonical protocol of the current section
	idx := map[string]int{}                    // cipher name -> index in res.Ciphers
	for _, ln := range strings.Split(output, "\n") {
		if m := enumProtoLine.FindStringSubmatch(ln); m != nil {
			cur = nmapProtoName[m[1]]
			if cur != "" {
				res.Protocols[cur] = true
			}
			continue
		}
		if m := enumCipherLine.FindStringSubmatch(ln); m != nil && cur != "" {
			name, grade := m[1], m[2]
			res.CipherGrades[name] = grade
			if i, ok := idx[name]; ok {
				res.Ciphers[i].Versions = append(res.Ciphers[i].Versions, cur)
			} else {
				idx[name] = len(res.Ciphers)
				res.Ciphers = append(res.Ciphers, CipherResult{Name: name, Versions: []string{cur}})
			}
		}
	}
}

var cveRe = regexp.MustCompile(`CVE-\d{4}-\d{3,7}`)

// nmapVulnFinding turns a vuln NSE script's output into a Finding when the
// script reports the host VULNERABLE. Returns nil for not-vulnerable/absent.
func nmapVulnFinding(output string, sev Severity, title, component string) *Finding {
	if !strings.Contains(output, "State: VULNERABLE") {
		return nil
	}
	cves := cveRe.FindAllString(output, -1)
	// dedupe
	seen := map[string]bool{}
	var uniq []string
	for _, c := range cves {
		if !seen[c] {
			seen[c] = true
			uniq = append(uniq, c)
		}
	}
	if len(uniq) == 0 {
		uniq = []string{"N/A"}
	}
	desc := firstVulnDescLine(output)
	return &Finding{Severity: sev, Title: title, Description: desc, CVEs: uniq, Component: component, Count: 1}
}

// firstVulnDescLine grabs the human title line nmap prints under VULNERABLE.
func firstVulnDescLine(output string) string {
	lines := strings.Split(output, "\n")
	for i, ln := range lines {
		if strings.Contains(ln, "VULNERABLE:") && i+1 < len(lines) {
			if d := strings.TrimSpace(lines[i+1]); d != "" {
				return d
			}
		}
	}
	return "Confirmed vulnerable by nmap NSE script."
}

// protoVersionByName maps a canonical protocol name to the uint16 id that
// analyzeFindings / VulnerableProtocols match on.
var protoVersionByName = map[string]uint16{
	"SSL 2.0": 0x0002, "SSL 3.0": 0x0300,
	"TLS 1.0": 0x0301, "TLS 1.1": 0x0302,
	"TLS 1.2": 0x0303, "TLS 1.3": 0x0304,
}

var protoOrder = []string{"SSL 2.0", "SSL 3.0", "TLS 1.0", "TLS 1.1", "TLS 1.2", "TLS 1.3"}

// mergeToolResults assembles the HostResult protocols/ciphers/findings from the
// sslscan + nmap outputs (cert is filled separately by the Go handshake). It
// then reuses the existing analyzeFindings for protocol/cipher/cert/quality
// findings and appends the tool-only vulnerabilities.
func mergeToolResults(r *HostResult, ss *sslscanTest, nm *nmapSSL, goVersions map[uint16]bool) {
	// ---- Protocols: union of what either tool observed. ----
	ssEnabled := map[string]bool{}
	ssSeen := map[string]bool{}
	if ss != nil {
		for _, p := range ss.Protocols {
			name := sslscanProtoName(p.Type, p.Version)
			if name == "" {
				continue
			}
			ssSeen[name] = true
			if p.Enabled == "1" {
				ssEnabled[name] = true
			}
		}
	}
	// ---- Protocols: decide support per version by the RIGHT authority. ----
	// A protocol counts as supported only when a REAL handshake proves it:
	//   - Legacy (SSL2/3, TLS1.0/1.1): sslscan's explicit "enabled" (it did a
	//     per-cipher handshake) OR a completed native Go handshake (goVersions).
	//     nmap's ssl-enum is deliberately NOT trusted on its own here — it can
	//     print a phantom single-cipher legacy section against an inconsistent
	//     load-balancer (ftpsvc.example.com: nmap "TLSv1.0" with one cipher +
	//     "too few ciphers"/"indeterminate", while sslscan said disabled, openssl
	//     negotiated nothing, and a Go handshake was reset). A version nobody can
	//     actually handshake is not an exposure. Go can't speak SSL2/3, so those
	//     rest on sslscan alone.
	//   - Modern (TLS1.2/1.3): any of the three (all do real handshakes).
	// goVersions (the native Go sweep over every version) also guarantees a
	// TLS-serving host is never dropped as "No TLS" when the external tools fail.
	legacyProto := map[uint16]bool{
		protoVersionByName["SSL 2.0"]: true, protoVersionByName["SSL 3.0"]: true,
		protoVersionByName["TLS 1.0"]: true, protoVersionByName["TLS 1.1"]: true,
	}
	for _, name := range protoOrder {
		v := protoVersionByName[name]
		nmSaw := nm != nil && nm.Protocols[name]
		if !ssSeen[name] && !nmSaw && !goVersions[v] {
			continue // no tool examined this version
		}
		var supported bool
		if legacyProto[v] {
			supported = ssEnabled[name] || goVersions[v]
		} else {
			supported = ssEnabled[name] || nmSaw || goVersions[v]
		}
		r.Protocols = append(r.Protocols, ProtoResult{Version: v, Name: name, Supported: supported})
	}

	// ---- Ciphers: prefer nmap (IANA names → ClassifyCipher works); else sslscan. ----
	if nm != nil && len(nm.Ciphers) > 0 {
		r.Ciphers = nm.Ciphers
	} else if ss != nil {
		idx := map[string]int{}
		for _, c := range ss.Ciphers {
			ver := sslscanCipherVer(c.SSLVersion)
			if i, ok := idx[c.Cipher]; ok {
				r.Ciphers[i].Versions = append(r.Ciphers[i].Versions, ver)
			} else {
				idx[c.Cipher] = len(r.Ciphers)
				r.Ciphers = append(r.Ciphers, CipherResult{Name: c.Cipher, Versions: []string{ver}})
			}
		}
	}

	// (The native Go sweep is folded into the protocol loop above — goVersions is
	// authoritative for every version it handshakes, legacy included, and covers
	// the "never drop a live TLS host as No-TLS" guarantee.)

	// ---- Findings: existing analysis over the populated data, then tool-only. ----
	findings := analyzeFindings(r)
	findings = append(findings, toolOnlyFindings(ss, nm)...)
	findings = append(findings, sslscanStrengthFindings(ss)...)
	r.Findings = dedupeFindings(findings)
}

func sslscanProtoName(typ, ver string) string {
	if typ == "ssl" {
		switch ver {
		case "2":
			return "SSL 2.0"
		case "3":
			return "SSL 3.0"
		}
		return ""
	}
	switch ver {
	case "1.0":
		return "TLS 1.0"
	case "1.1":
		return "TLS 1.1"
	case "1.2":
		return "TLS 1.2"
	case "1.3":
		return "TLS 1.3"
	}
	return ""
}

func sslscanCipherVer(v string) string {
	switch v {
	case "SSLv2":
		return "SSL 2.0"
	case "SSLv3":
		return "SSL 3.0"
	case "TLSv1.0":
		return "TLS 1.0"
	case "TLSv1.1":
		return "TLS 1.1"
	case "TLSv1.2":
		return "TLS 1.2"
	case "TLSv1.3":
		return "TLS 1.3"
	}
	return v
}

// toolOnlyFindings covers vulns the protocol/cipher/cert analysis can't derive:
// Heartbleed, TLS compression (CRIME), insecure renegotiation, plus nmap's
// POODLE/DROWN/Logjam/Heartbleed NSE findings.
func toolOnlyFindings(ss *sslscanTest, nm *nmapSSL) []Finding {
	var out []Finding
	if ss != nil {
		for _, hb := range ss.Heartbleeds {
			if hb.Vulnerable == "1" {
				out = append(out, Finding{Severity: SevCritical, Title: "Heartbleed",
					Description: "Server is vulnerable to the Heartbleed memory-disclosure bug (" + hb.SSLVersion + ").",
					CVEs:        []string{"CVE-2014-0160"}, Component: "protocol", Count: 1})
				break
			}
		}
		if ss.Compression != nil && ss.Compression.Supported == "1" {
			out = append(out, Finding{Severity: SevMedium, Title: "TLS Compression Enabled (CRIME)",
				Description: "TLS-level compression is enabled, exposing the CRIME attack.",
				CVEs:        []string{"CVE-2012-4929"}, Component: "protocol", Count: 1})
		}
		if ss.Renegotiation != nil && ss.Renegotiation.Supported == "1" && ss.Renegotiation.Secure == "0" {
			out = append(out, Finding{Severity: SevMedium, Title: "Insecure Renegotiation",
				Description: "The server permits insecure (client-initiated / unauthenticated) TLS renegotiation.",
				CVEs:        []string{"CVE-2009-3555"}, Component: "protocol", Count: 1})
		}
	}
	if nm != nil {
		out = append(out, nm.Findings...)
	}
	return out
}

// sslscanStrengthFindings catches weak/null cipher suites via sslscan's own
// strength rating (more reliable than name matching across OpenSSL/IANA naming).
func sslscanStrengthFindings(ss *sslscanTest) []Finding {
	if ss == nil {
		return nil
	}
	// The generic "weak" rating is intentionally NOT emitted as its own finding:
	// analyzeFindings now reports weak ciphers grouped per TLS version (RC4 / DES
	// / EXPORT / 3DES / CBC-no-PFS / static-RSA are all classified there), so a
	// separate host-level "Weak Ciphers Supported" row would just duplicate them.
	// NULL (no encryption at all) is kept as its own unmissable critical row.
	var nullN int
	for _, c := range ss.Ciphers {
		if c.Strength == "null" {
			nullN++
		}
	}
	var out []Finding
	if nullN > 0 {
		out = append(out, Finding{Severity: SevCritical, Title: "NULL Ciphers Supported",
			Description: "The server accepts NULL cipher suites, which provide no encryption.",
			CVEs:        []string{"N/A"}, Component: "cipher", Count: nullN})
	}
	return out
}

// dedupeFindings collapses findings sharing a title, keeping the highest
// severity and summing cipher counts.
func dedupeFindings(in []Finding) []Finding {
	order := []string{}
	by := map[string]*Finding{}
	for i := range in {
		f := in[i]
		if e, ok := by[f.Title]; ok {
			if SeverityScore(f.Severity) > SeverityScore(e.Severity) {
				e.Severity = f.Severity
			}
			if f.Count > e.Count {
				e.Count = f.Count
			}
			if len(e.CVEs) == 0 || (len(e.CVEs) == 1 && e.CVEs[0] == "N/A") {
				if len(f.CVEs) > 0 && f.CVEs[0] != "N/A" {
					e.CVEs = f.CVEs
				}
			}
			continue
		}
		cp := f
		by[f.Title] = &cp
		order = append(order, f.Title)
	}
	out := make([]Finding, 0, len(order))
	for _, t := range order {
		out = append(out, *by[t])
	}
	return out
}

// sslToolTimeout gives external tools a generous ceiling — nmap's ssl-enum is
// deliberately thorough (the operator asked for completeness over speed). Used
// by the standalone SSL/TLS module (a handful of targets).
func sslToolTimeout(base time.Duration) time.Duration {
	// Generous enough for a thorough nmap ssl-enum + sslscan on a slow host
	// (observed ~40 s on rate-limiting gov infra) with margin, but bounded so a
	// large scan doesn't spend minutes per unresponsive/blocked host. Was 240 s
	// which made big scans crawl; 90 s comfortably covers the real tool time.
	t := base * 10
	if t < 60*time.Second {
		t = 60 * time.Second
	}
	if t > 90*time.Second {
		t = 90 * time.Second
	}
	return t
}

// sslBulkTimeout is the far tighter per-tool ceiling for advancedweb's bulk SSL
// stage (hundreds/thousands of hosts): one slow/filtered host must not drag the
// whole suite for minutes, while still leaving nmap's ssl-enum-ciphers room to
// finish on a responsive host. Trades a little completeness on pathologically
// slow hosts for stage-level stability.
func sslBulkTimeout(base time.Duration) time.Duration {
	t := base * 4
	if t < 15*time.Second {
		t = 15 * time.Second
	}
	if t > 30*time.Second {
		t = 30 * time.Second
	}
	return t
}
