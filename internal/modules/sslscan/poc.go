package sslscan

import (
	"context"
	"net"
	"strconv"
	"strings"
	"time"

	"scanner/internal/modules/shared"
)

// Real-evidence PoC capture. Each finding gets the exact (reproducible) command
// a tool was run with and that command's real console output, so the report /
// detail-drawer PoC shows genuine evidence instead of a synthesized description.

const pocOutputCap = 8 * 1024

// ToolRun is one tool invocation's reproducible command + real output.
type ToolRun struct {
	Tool    string `json:"tool"`
	Command string `json:"command"`
	Output  string `json:"output"`
}

// capOutput trims and size-bounds a captured output so the stored result stays
// small even when a tool prints hundreds of cipher lines.
func capOutput(s string) string {
	s = strings.TrimRight(s, "\n ")
	if len(s) <= pocOutputCap {
		return s
	}
	return strings.ToValidUTF8(s[:pocOutputCap], "") + "\n… (truncated)"
}

// opensslTimeout keeps the certificate handshake short — it is a single
// s_client dial, not a cipher sweep, so it must not inherit the minutes-long
// sslToolTimeout (a hung port would otherwise block the whole host).
func opensslTimeout(base time.Duration) time.Duration {
	t := base * 2
	if t < 8*time.Second {
		t = 8 * time.Second
	}
	if t > 15*time.Second {
		t = 15 * time.Second
	}
	return t
}

// runOpenSSLCert captures real certificate evidence via `openssl s_client`,
// whose output shows the served chain, protocol, cipher, validity and key —
// the reproducible evidence for certificate findings. Best-effort: returns a
// ToolRun with an empty Output when openssl is absent or the dial fails.
func runOpenSSLCert(ctx context.Context, host string, port int, timeout time.Duration, startTLS string) ToolRun {
	addr := net.JoinHostPort(host, strconv.Itoa(port))
	args := []string{"s_client", "-connect", addr, "-servername", host}
	if p := opensslStartTLS(startTLS); p != "" {
		args = append(args, "-starttls", p)
	}
	run := ToolRun{Tool: "openssl", Command: "openssl " + strings.Join(args, " ") + " </dev/null"}

	cctx, cancel := context.WithTimeout(ctx, opensslTimeout(timeout))
	defer cancel()
	cmd := shared.Command(cctx, "openssl", args...)
	cmd.Stdin = strings.NewReader("") // </dev/null — s_client sends close_notify on EOF and exits
	out, _ := cmd.Output()            // s_client often exits nonzero; keep whatever it printed
	if len(out) > 0 {
		run.Output = capOutput(string(out))
	}
	return run
}

// opensslStartTLS maps the resolved STARTTLS mode to openssl's -starttls value.
func opensslStartTLS(mode string) string {
	switch strings.ToLower(strings.TrimSpace(mode)) {
	case "smtp":
		return "smtp"
	case "imap":
		return "imap"
	case "pop3":
		return "pop3"
	case "ftp":
		return "ftp"
	case "ldap":
		return "ldap"
	case "postgres", "psql":
		return "postgres"
	}
	return ""
}

// nmapScriptForTitle maps a finding title to the NSE script whose output proves
// it, so the finding's PoC shows exactly the relevant nmap evidence.
var nmapScriptForTitle = map[string]string{
	"POODLE (SSLv3)":               "ssl-poodle",
	"DROWN (SSLv2)":                "sslv2-drown",
	"Weak Diffie-Hellman (Logjam)": "ssl-dh-params",
	"Heartbleed":                   "ssl-heartbleed",
}

// sslscanEvidenceTitles are findings only sslscan surfaces (nmap's enum doesn't
// show compression / renegotiation / strength ratings), so their PoC uses
// sslscan's console output.
var sslscanEvidenceTitles = map[string]bool{
	"TLS Compression Enabled (CRIME)": true,
	"Insecure Renegotiation":          true,
	"NULL Ciphers Supported":          true,
	"Weak Ciphers Supported":          true,
}

// attachPoC fills each finding's real command + output from the tool that
// produced its evidence: a specific nmap NSE script, nmap's ssl-enum-ciphers,
// sslscan's console, or openssl s_client for certificate findings. Findings
// with no available evidence are left blank (the report falls back to a
// synthesized command-based PoC).
func attachPoC(findings []Finding, ssRun, nmRun, opensslRun ToolRun, nm *nmapSSL) []Finding {
	enum := ""
	if nm != nil {
		enum = nm.ScriptOutput["ssl-enum-ciphers"]
	}
	for i := range findings {
		f := &findings[i]
		if script := nmapScriptForTitle[f.Title]; script != "" && nm != nil && nm.ScriptOutput[script] != "" {
			f.PoCCommand, f.PoCOutput = nmRun.Command, capOutput(nm.ScriptOutput[script])
			continue
		}
		if sslscanEvidenceTitles[f.Title] && ssRun.Output != "" {
			f.PoCCommand, f.PoCOutput = ssRun.Command, ssRun.Output
			continue
		}
		switch f.Component {
		case "protocol", "cipher":
			if enum != "" {
				f.PoCCommand, f.PoCOutput = nmRun.Command, capOutput(enum)
			} else if ssRun.Output != "" {
				f.PoCCommand, f.PoCOutput = ssRun.Command, ssRun.Output
			}
		case "certificate":
			if opensslRun.Output != "" {
				f.PoCCommand, f.PoCOutput = opensslRun.Command, opensslRun.Output
			}
		}
	}
	return findings
}

// nonEmptyRuns returns the tool runs that actually captured output, for the
// per-host evidence panel on the module results page.
func nonEmptyRuns(runs ...ToolRun) []ToolRun {
	var out []ToolRun
	for _, r := range runs {
		if strings.TrimSpace(r.Output) != "" {
			out = append(out, r)
		}
	}
	return out
}
