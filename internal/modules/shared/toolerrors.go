package shared

import (
	"regexp"
	"strings"
)

// toolerrors.go — a catalog that turns raw tool/stderr/exec errors into plain
// language a user can act on. Modules shell out to ~20 CLIs (nmap, nuclei,
// wpscan, hydra, impacket/nxc, subfinder, whois, snmp, …) plus Go-native
// HTTP/TLS; their raw failures ("KRB_AP_ERR_SKEW", "STATUS_LOGON_FAILURE",
// "no templates provided") are opaque. TranslateToolError maps the common
// ones (pre-researched per tool) to an explanation + fix.
//
// Usage: handlers call ExplainToolError(raw) when finalizing a failed scan so
// MarkScanError stores a human-readable reason (surfaced in the error banner),
// falling back to the raw text when no rule matches.

// errRule is one catalog entry. `sub` is a lowercased substring; if all the
// substrings in `all` are present (AND), the rule matches. First match wins,
// so order specific rules before generic ones.
type errRule struct {
	all      []string // every token (lowercased) must be present
	friendly string
}

// notFoundRe extracts the binary name from a Go exec "not found" error so the
// message can name the exact missing tool.
var notFoundRe = regexp.MustCompile(`(?i)exec: "([^"]+)": executable file not found`)

// toolErrorRules is ordered: tool-specific first, generic network last.
var toolErrorRules = []errRule{
	// ---- nmap ----
	{[]string{"requires root privileges"}, "nmap needs raw-socket privileges for this scan type (UDP -sU, SYN, or ICMP host discovery). Run scaNNer as root, or grant the capability once: sudo setcap cap_net_raw,cap_net_admin+eip $(which nmap)."},
	{[]string{"couldn't open a raw socket"}, "nmap could not open a raw socket (no privileges). Grant it: sudo setcap cap_net_raw,cap_net_admin+eip $(which nmap), or run as root."},
	{[]string{"failed to resolve"}, "nmap could not resolve the target hostname (DNS failure or typo). Use an IP address or fix the name / resolver."},
	{[]string{"host timeout"}, "nmap gave up on a slow or heavily filtered host at its --host-timeout, so results for that host are partial. Reduce the port range or raise the timeout."},

	// ---- nuclei ----
	{[]string{"no templates"}, "nuclei has no templates installed, so it can't test anything. Run: nuclei -update-templates (fetches the template store to ~/.local/nuclei-templates)."},
	{[]string{"could not find any templates"}, "nuclei has no templates installed. Run: nuclei -update-templates."},
	{[]string{"flag provided but not defined"}, "The installed nuclei version doesn't understand a flag scaNNer passes — update nuclei (v3+ recommended): nuclei -update, or reinstall from ProjectDiscovery."},

	// ---- wpscan ----
	{[]string{"no wpscan api token"}, "WPScan fingerprinted WordPress but couldn't report known CVEs — no WPVulnDB API token is set. Add one in Settings (free token at wpscan.com); results stay sparse without it."},
	{[]string{"api limit has been reached"}, "The WPScan/WPVulnDB API is rate-limited — the free token allows ~25 requests per 24h and the quota is exhausted. Wait for the reset or use a paid token."},
	{[]string{"does not seem to be running wordpress"}, "WPScan reached the site but it isn't WordPress, so there's nothing to enumerate. Check you targeted the right URL / path."},

	// ---- hydra ----
	{[]string{"all children were disabled"}, "hydra hit the target's rate-limiting / account-lockout / fail2ban and killed its workers. Lower the thread/task count and add a delay, or the account may already be locked."},
	{[]string{"compiled without libssh"}, "This hydra build lacks libssh, so the ssh module can't run. Install a full build: apt install hydra (thc-hydra with libssh)."},

	// ---- Active Directory: impacket / nxc / ldap / certipy / bloodhound ----
	{[]string{"krb_ap_err_skew"}, "Kerberos clock skew: your machine's clock is more than 5 minutes off the Domain Controller. Sync time before running: sudo ntpdate <dc-ip> (or chrony/rdate)."},
	{[]string{"clock skew too great"}, "Kerberos clock skew: sync your clock to the Domain Controller (sudo ntpdate <dc-ip>) — tickets outside a 5-minute window are rejected."},
	{[]string{"status_logon_failure"}, "The Domain Controller rejected the credentials (wrong username/password/NT hash, wrong domain/realm, or the account is locked/expired). Re-check the AD creds and domain."},
	{[]string{"unwilling to perform"}, "The Domain Controller refuses this LDAP bind — modern DCs disable anonymous binds and require LDAP signing/channel-binding. Supply valid credentials and/or use LDAPS."},
	{[]string{"could not connect to any ldap"}, "The BloodHound/LDAP collector couldn't reach a Domain Controller — it needs AD DNS (SRV/host records the DC serves). Point DNS at the DC and give the real domain FQDN."},

	// ---- subfinder / amass / puredns / massdns ----
	{[]string{"unable to find massdns"}, "puredns is a wrapper around massdns, which isn't installed — so the DNS brute-force / permutation phases produce nothing. Install massdns and put it on PATH."},
	{[]string{"no resolvers"}, "puredns/massdns needs a list of trusted DNS resolvers (data/resolvers.txt). Provide a resolvers file, or the brute-force phase resolves nothing."},
	{[]string{"missing/invalid keys"}, "subfinder is running without API keys, so it silently skips most passive sources (Censys/Shodan/SecurityTrails/VirusTotal/GitHub). Add keys to subfinder's config for fuller results."},

	// ---- SMB: smbclient / enum4linux ----
	{[]string{"nt_status_logon_failure"}, "SMB rejected the credentials (wrong username/password, or the account needs a DOMAIN\\ qualifier). Re-check the creds."},
	{[]string{"nt_status_access_denied"}, "The target refuses anonymous / null-session SMB enumeration — standard on hardened or modern Windows (RestrictAnonymous, SMB signing). Supply valid credentials to enumerate."},
	{[]string{"smb1"}, "The target disabled legacy SMB1 (used by smbclient's browse listing) — usually NOT a real failure; the host is reachable, just not via the old workgroup-listing protocol."},

	// ---- SNMP: net-snmp ----
	{[]string{"timeout: no response"}, "The SNMP agent didn't reply — the host is down, UDP/161 is filtered, or the community string is wrong. SNMP uses UDP so a filtered port looks identical to a wrong community."},
	{[]string{"usmstatswrongdigests"}, "SNMPv3 rejected the credentials (wrong auth or privacy passphrase, or mismatched security level). Re-check the v3 user and auth/priv settings."},
	{[]string{"no such object"}, "The device doesn't implement that SNMP MIB branch — common when walking Windows-only OIDs against a Linux/network device. Not a failure; just no data there."},

	// ---- whois ----
	{[]string{"maximum allowable number of queries"}, "The WHOIS registry rate-limited scaNNer for querying too fast (common when batching many targets). Lower the concurrency and retry later."},
	{[]string{"no whois server is known"}, "The system whois has no server mapping for that TLD/object type (many ccTLDs and new gTLDs). The lookup returns little or nothing."},

	// ---- theHarvester ----
	{[]string{"engines are not supported"}, "A selected theHarvester source was removed/renamed in v4.10+ (anubis, threatminer, bing, sitedossier no longer exist). Untick the offending source."},
	{[]string{"invalid source"}, "theHarvester rejected a selected source name (removed or renamed in a newer version). Untick it and re-run."},

	// ---- recon APIs: Shodan / Censys / GitHub ----
	{[]string{"invalid api key"}, "The API key (Shodan/Censys) is missing, mistyped, or revoked. Paste a valid key in Settings."},
	{[]string{"bad credentials"}, "The GitHub token in Settings is missing, malformed, or expired. Generate a fresh Personal Access Token and update Settings."},
	{[]string{"you have used your full quota"}, "You've exhausted the API's monthly quota / rate limit (Shodan ~1 req/s, Censys small free quota). Reduce queries or wait for the reset."},

	// ---- OOB collaborator ----
	{[]string{"address already in use"}, "The chosen OOB listen port is already held by another process. Pick a different port (or stop the process using it)."},

	// ---- Go-native HTTP/TLS + universal network (generic — keep LAST) ----
	{[]string{"no such host"}, "DNS couldn't resolve the target hostname — a typo, an internal-only name, or DNS not reachable via the pinned outbound/VPN interface. Use an IP, fix the name, or check DNS."},
	{[]string{"connection refused"}, "Nothing is listening on that host:port — the service is down, the port is wrong, or a firewall sent a RST. Confirm the service is up and try the other scheme (http/https)."},
	{[]string{"server gave http response to https client"}, "Scheme mismatch — an https:// URL was pointed at a plain-HTTP port (bare hostnames default to https://). Enter the target with an explicit http:// scheme or the correct port."},
	{[]string{"first record does not look like a tls handshake"}, "Scheme/port mismatch — a TLS handshake was attempted against a plaintext-HTTP service. Use http:// or the correct TLS port."},
	{[]string{"tls: handshake failure"}, "The TLS handshake was rejected — often a plain-HTTP port reached over https://, an unsupported protocol/cipher, or a WAF dropping the connection."},
	{[]string{"tls handshake timeout"}, "The TLS negotiation stalled — usually a WAF/firewall silently dropping packets, or an https:// URL aimed at a plain-HTTP port."},
	{[]string{"certificate signed by unknown authority"}, "The target serves a self-signed or internal-CA TLS certificate that Go rejects. Enable the insecure / skip-TLS-verify option to scan it."},
	{[]string{"certificate has expired"}, "The target's TLS certificate is expired or not yet valid, so the client refuses it. Enable skip-TLS-verify to scan anyway (and note the cert issue)."},
	{[]string{"cannot assign requested address"}, "Local ephemeral-port / file-descriptor exhaustion on the scanner host, or the killswitch is binding to a source IP that isn't on a live interface. Lower concurrency or fix the outbound interface."},
	{[]string{"i/o timeout"}, "The connection timed out with no response — the host is down, firewalled/filtered, or unreachable via the pinned outbound interface."},
	{[]string{"context deadline exceeded"}, "The target didn't respond within the configured timeout — it's slow, tarpitting, or a WAF/firewall is dropping packets. Raise the timeout or verify reachability."},
	{[]string{"client.timeout exceeded"}, "The request exceeded the per-request timeout — slow/unreachable target, or a WAF stalling the connection. Raise the timeout or check reachability."},
	{[]string{"network is unreachable"}, "No route to the target from this host — check the outbound interface / VPN / killswitch binding."},
	{[]string{"connection reset by peer"}, "The server or a WAF/rate-limiter actively reset the connection, often on a burst of probes. Lower concurrency / add a delay."},
}

// TranslateToolError returns a plain-language explanation of a raw tool error
// (stderr, an exec error, or a result Error field) and true if a catalog rule
// matched. Matching is case-insensitive; the first matching rule wins.
func TranslateToolError(raw string) (string, bool) {
	if strings.TrimSpace(raw) == "" {
		return "", false
	}
	if m := notFoundRe.FindStringSubmatch(raw); m != nil {
		return "The required tool \"" + m[1] + "\" is not installed or not on the scanner's PATH. Install it and make sure the account running scaNNer can execute it.", true
	}
	low := strings.ToLower(raw)
	for _, r := range toolErrorRules {
		matched := true
		for _, tok := range r.all {
			if !strings.Contains(low, tok) {
				matched = false
				break
			}
		}
		if matched {
			return r.friendly, true
		}
	}
	return "", false
}

// ExplainToolError returns the friendly explanation when one is known, else
// the trimmed raw error. Handlers use this so a failed scan always shows
// SOMETHING useful in the error banner. When a rule matches, the raw text is
// appended in parentheses so power users still see the original.
func ExplainToolError(raw string) string {
	raw = strings.TrimSpace(raw)
	if friendly, ok := TranslateToolError(raw); ok {
		short := raw
		if len(short) > 200 {
			short = short[:200] + "…"
		}
		return friendly + "\n\n(raw: " + short + ")"
	}
	return raw
}
