package modules

// ModuleDoc contains documentation about what a module does under the hood
type ModuleDoc struct {
	Summary    string         // 1-3 sentence narrative description
	Tools      []ToolRef      // external tools/libs used
	Phases     []string       // ordered list of what happens during a scan
	Notes      []string       // gotchas, tuning tips, edge cases
	References []ReferenceRef // external docs/links (RFCs, OWASP, CVE)
}

type ToolRef struct {
	Name string
	Desc string
}

type ReferenceRef struct {
	Label string
	URL   string
}

// VulnEmitters is the set of modules whose primary output is a
// vulnerability finding — either severity-tagged (sslscan, nuclei, jwt,
// secheaders, cvematch, all A-group except oob/assetdisc) or de-facto
// vulnerable signal (leakscan secret hit, brutef cracked credential,
// smbenum's smb-vuln-* NSE results, httpmethods dangerous-method flag).
// Used by the modules page to show a "⚠ Vuln Output" badge so a pentester
// can quickly see which tools feed the report directly.
var VulnEmitters = map[string]bool{
	// Severity-labeled findings
	"sslscan":      true,
	"nuclei":       true,
	"wpscan":       true,
	"secheaders":   true,
	"jwt":          true,
	"cvematch":     true,
	"takeover":     true,
	"corsscan":     true,
	"openredirect": true,
	"graphqlscan":  true,
	"authtest":     true,
	"sstiscan":     true,
	"cachepoison":  true,
	// De-facto vulnerability output (no explicit Severity field, but
	// every positive result IS a finding worth reporting).
	"leakscan":    true,
	"brutef":      true,
	"smbenum":     true,
	"httpmethods": true,
}

// IsVulnEmitter returns true when the module's primary output is a
// vulnerability finding ready for the pentest report.
func IsVulnEmitter(name string) bool { return VulnEmitters[name] }

// Infos provides detailed documentation for each registered module. The
// content is intentionally educational — a pentester opening the
// "How this module works" panel should come away knowing not only WHAT
// the scanner does but WHY each step matters, what gotchas to expect,
// and where to dig deeper.
var Infos = map[string]ModuleDoc{

	"hashcat": {
		Summary: "Cracks operator-submitted password hashes locally with hashcat — no network targets, the hashes are the input. The operator searches for the algorithm by name (the hash-mode list is parsed from `hashcat -hh`) or lets hashid auto-detect candidate modes, then runs either a dictionary attack with one or more famous rule sets or a brute-force mask built from a structured per-position UI. Each rule runs as its own hashcat pass (rules can't be safely chained), keyspace and ETA are aggregated across every pass, and live hashrate / utilisation / progress are streamed from hashcat's --status-json.",
		Tools: []ToolRef{
			{Name: "hashcat", Desc: "The cracking engine — one process per pass, driven with -a 0 (dictionary+rules) or -a 3 (mask), -m for the mode, -w for workload, and --status-json for live progress; `hashcat -hh` is also parsed to build the searchable hash-mode list"},
			{Name: "hashid", Desc: "Auto-detects candidate hashcat modes from a sample hash (`hashid -m`) when the operator doesn't pick an algorithm, in hashid's preference order"},
		},
		Phases: []string{
			"Writes every submitted hash to a temp input file (the module has no network targets — the hashes ARE the targets) and prepares a per-pass outfile for cracked results",
			"Mode selection — if no algorithm was chosen, shells out to `hashid -m <hash>` to auto-detect candidate hashcat modes in preference order (deduped, capped at 5 candidates); otherwise uses the single -m mode picked by name",
			"Keyspace planning — counts the wordlist once and expands the job into passes: a dictionary attack with N rules becomes N separate hashcat runs (rules are never chained), a mask attack is a single run; sums every pass's keyspace so the ETA reflects the whole job",
			"Per pass, runs one hashcat process (-a 0 dictionary+rules or -a 3 mask) with the chosen workload (-w), optional CPU-only (-D 1), core affinity (--cpu-affinity) and runtime cap (--runtime), writing hash:plain to the outfile with --potfile-disable --status-json --force",
			"Streams hashcat's --status-json every 2 seconds (--status-timer 2), folding live hashrate, device, CPU/GPU utilisation and aggregate progress + ETA into the summary and pushing throttled partial updates (~1/second)",
			"After each pass, reads the outfile and marks matching hashes as cracked with their plaintext; the first crack short-circuits all remaining rule passes and candidate modes",
			"Finalises status from the last pass's exit code (0=cracked, 1=exhausted, 2/3/4=aborted, other=error) and reports total cracked, duration and — in auto-detect mode — which mode ultimately matched",
		},
		Notes: []string{
			"No network traffic — the module cracks operator-submitted hashes entirely on the local CPU (or GPU); it's filed under the Network category only so it sits beside the other credential tooling",
			"Rules are NEVER stacked into one run: hashcat crashes on large chained rule sets ('Unsupported number of rules used in rule chaining'), so each selected rule file runs as its own pass and the results are the union",
			"--potfile-disable forces every hash to be re-attempted (hashcat won't silently skip ones it cracked before), and --force bypasses hashcat's device/driver warnings",
			"Progress % and ETA are aggregated across ALL passes (remaining keyspace ÷ current live hashrate), not just the pass currently running, so the estimate reflects the entire multi-rule/multi-mode job",
			"Auto-detect tries at most 5 candidate modes from hashid; if hashid finds no hashcat-mapped candidate it fails and asks the operator to pick the algorithm manually",
			"The picker enumerates wordlists from /usr/share/wordlists and SecLists (rockyou surfaced first) and rule files from the bundled data/hashcat-rules dir plus /usr/share/hashcat/rules (famous rules like OneRuleToRuleThemAll first); wordlist word counts are exact up to 25 MB and size-estimated above that",
			"Mask/brute-force mode is built from a structured per-position UI selection (or a length range) into a real hashcat mask plus up to 4 custom charsets (-1..-4), with --increment driven by the range bounds",
		},
		References: []ReferenceRef{
			{Label: "hashcat wiki", URL: "https://hashcat.net/wiki/"},
			{Label: "hashcat mask attack", URL: "https://hashcat.net/wiki/doku.php?id=mask_attack"},
			{Label: "hashcat rule-based attack", URL: "https://hashcat.net/wiki/doku.php?id=rule_based_attack"},
			{Label: "hashcat example hashes (mode reference)", URL: "https://hashcat.net/wiki/doku.php?id=example_hashes"},
			{Label: "hashID", URL: "https://github.com/psypanda/hashID"},
		},
	},

	"adpentest": {
		Summary: "Comprehensive Active Directory pentest pipeline against one target (CIDR, FQDN, DC IP, or domain name). Discovers domain controllers and topology, runs unauthenticated and authenticated enumeration (LDAP, SMB, RPC, SAMR), harvests AS-REP and Kerberoast hashes, collects BloodHound graph data, enumerates AD CS vulnerable templates (ESC IDs), probes for ZeroLogon/noPac/PrintNightmare/PetitPotam/DFSCoerce plus EternalBlue/SMBGhost, optionally coerces authentication (Responder/mitm6/coercer) and sprays passwords, then generates ready-to-paste lateral-movement commands from any captured credentials. Risk-tiered toggles (safe on by default / medium off by default) gate every noisy or modifying action.",
		Tools: []ToolRef{
			{Name: "dig", Desc: "SRV lookup of _ldap._tcp.dc._msdcs.<domain> to seed the DC list (hard tool, discovery)"},
			{Name: "nmap", Desc: "DC port sweep (88/389/445/636/3268/3269), NSE fingerprint (smb-os-discovery, ldap-rootdse, smb2-time) and SMB vuln NSE (smb-vuln-ms17-010 EternalBlue, smb2-vuln-cve-2020-0796 SMBGhost)"},
			{Name: "ldapsearch", Desc: "Anonymous rootDSE query for defaultNamingContext / dnsHostName / ldapServiceName / rootDomainNamingContext (domain DN, FQDN, forest)"},
			{Name: "nbtscan", Desc: "NetBIOS name metadata over the target range (soft; fills in names nmap NSE missed)"},
			{Name: "nxc (NetExec)", Desc: "SMB signing relay-list, auth modules --pass-pol/--laps/--gmsa/-M gpp_password, vuln modules zerologon/nopac/printnightmare/petitpotam/dfscoerce, and lockout-aware SMB password spray"},
			{Name: "ldapdomaindump", Desc: "LDAP object dump (users/groups/computers/trusts) — run anonymously in Phase 2 and again with creds in Phase 4"},
			{Name: "enum4linux-ng", Desc: "SMB/RPC enumeration + password policy; legacy enum4linux is the soft fallback"},
			{Name: "impacket-lookupsid", Desc: "SAMR RID cycling to recover usernames"},
			{Name: "impacket-samrdump", Desc: "SAMR user dump over the null-session pipe"},
			{Name: "impacket-GetNPUsers", Desc: "AS-REP roast of DONT_REQ_PREAUTH accounts (krb5asrep, hashcat mode 18200)"},
			{Name: "impacket-GetUserSPNs", Desc: "Kerberoast of SPN-bearing accounts (krb5tgs, hashcat mode 13100); supports password / -hashes / -k -no-pass ccache"},
			{Name: "kerbrute", Desc: "Kerberos pre-auth user-enumeration enrichment (soft)"},
			{Name: "bloodhound-python", Desc: "BloodHound -c All collection; zip kept under loot, JSON summarised for the UI"},
			{Name: "certipy-ad", Desc: "AD CS enumeration (find -vulnerable -json) against the single best-scored DC — CAs and vulnerable templates tagged with ESC IDs"},
			{Name: "responder", Desc: "LLMNR/NBT-NS/mDNS poisoning → NetNTLMv2 capture (hashcat mode 5600)"},
			{Name: "mitm6", Desc: "IPv6 RA spoof → rogue WPAD to coerce authentication (medium tier)"},
			{Name: "coercer", Desc: "PetitPotam/PrinterBug/DFSCoerce authentication coercion against a DC (medium tier)"},
			{Name: "hashcat", Desc: "Offline cracking of captured AS-REP/Kerberoast/NetNTLMv2 hashes (john is cataloged as a fallback but is not currently invoked)"},
		},
		Phases: []string{
			"Preflight tool check — walks the catalog with exec.LookPath (dig, ldapsearch, nmap, nbtscan, ldapdomaindump, enum4linux-ng/enum4linux, impacket-lookupsid/samrdump/GetNPUsers/GetUserSPNs, kerbrute, nxc, bloodhound-python, certipy-ad, responder, mitm6, coercer, hashcat/john); a hard-missing tool disables its phase and adds a top-level warning, a soft-missing tool just degrades to a fallback",
			"Phase 1 — DC discovery (safe): seed from an explicit DC IP, else dig SRV _ldap._tcp.dc._msdcs.<domain>, else nmap -p 88,389,445,636,3268,3269 sweep (a host counts as a DC when Kerberos 88 plus ANY LDAP port is open); resolve each DC's rootDSE over anonymous ldapsearch for domain DN/FQDN/forest; fingerprint with nmap NSE (smb-os-discovery, ldap-rootdse, smb2-time); optional nbtscan; nxc smb --gen-relay-list to list SMB-signing-off hosts",
			"Phase 2 — unauthenticated enum (safe): against the best-scored DC — anonymous ldapdomaindump (users/groups/computers/trusts), enum4linux-ng (legacy enum4linux fallback) for SMB/RPC + password policy, impacket-lookupsid RID cycling, impacket-samrdump SAMR dump; each step is independent and skips cleanly if its tool is missing",
			"Phase 2b — AS-REP roast (safe, no creds): impacket-GetNPUsers -no-pass across EVERY discovered DC for accounts with DONT_REQ_PREAUTH, storing krb5asrep hashes (hashcat mode 18200) de-duped by (account, hash); optional kerbrute userenum enrichment when present",
			"Phase 4 — authenticated enum (safe, needs creds): re-runs ldapdomaindump with creds (the richer dataset replaces the unauth one), then nxc --pass-pol / --laps / --gmsa / -M gpp_password; inventories unconstrained/constrained delegations from UAC flags and mines the description field for stashed passwords",
			"Phase 4b — BloodHound collection (safe, needs creds): bloodhound-python -c All --zip, parsed into a summary (Domain/Enterprise/Schema Admins, kerberoastable / AS-REP-roastable / unconstrained-delegation counts); the full zip is kept under loot for graph analysis",
			"Phase 4c — Kerberoast (safe, needs creds): impacket-GetUserSPNs -request across every DC, storing krb5tgs hashes (hashcat mode 13100) de-duped by (account, hash); supports password, NT hash (-hashes) or ccache (-k -no-pass) auth",
			"Phase 4d — targeted Kerberoast (medium, needs creds): CURRENTLY A NO-OP — the toggle is advertised with a 'modifies SPN attribute' warning but only emits a warning pointing the operator at the manual addspn → GetUserSPNs → delspn steps in the Lateral panel",
			"Phase 4e — AD CS enum (safe, needs creds): certipy-ad find -vulnerable -json against the single best-scored DC (bestDC), parsing every CA plus each vulnerable template tagged with its ESC IDs",
			"Phase 4f — password spray (medium, off by default): lockout-aware nxc smb spray that NEVER exceeds LockoutThreshold-1 attempts per account; candidates are common passwords plus seasonal passwords computed off the current and prior year; skipped entirely unless LockoutThreshold > 0",
			"Phase 5 — vulnerability probe (safe, detect-only): per DC runs nxc modules zerologon/nopac/printnightmare/petitpotam/dfscoerce (pre-auth, no creds passed so a detect never becomes an exploit) parsing the 'VULNERABLE' marker, plus nmap NSE smb-vuln-ms17-010 (EternalBlue) and smb2-vuln-cve-2020-0796 (SMBGhost); each nxc hit records a pre-filled exploit command that is never executed (the nmap NSE EternalBlue/SMBGhost hits record only a detect line)",
			"Phase 3 — hash harvest (medium, off by default): opens a listener window (HashHarvestSeconds, default 300s) and runs responder (LLMNR/NBT-NS/mDNS), mitm6 (IPv6 RA → WPAD) and coercer (PetitPotam/PrinterBug/DFSCoerce) in parallel on the killswitch veth scanner1; captured NetNTLMv2 hashes (hashcat mode 5600) are parsed back out of Responder's loot dir",
			"Phase 7 — auto-crack (medium, off by default): runs hashcat against every captured hash that carries a hashcat mode ID, using the first present wordlist (rockyou.txt and fallbacks) with a 10-minute per-hash cap; cracked secrets are written back and the lateral panel is regenerated",
			"Phase 6 — lateral-movement generation (safe): pure post-processing that walks the results for credential material and emits risk-tagged, paste-able commands (Pass-the-Hash SMB/WinRM, DCSync, constrained-delegation S4U, ADCS ESC1 abuse, ZeroLogon→DCSync chain, GPP-cleartext spray, LAPS local-admin, hash-crack hints); nothing is executed and real secrets are replaced with <PASSWORD>/<NTHASH> placeholders",
		},
		Notes: []string{
			"The 'Phase N' labels in the progress bar are semantic groupings, not execution order — the scanner actually runs discovery → unauth → AS-REP → auth → BloodHound → Kerberoast → targeted-Kerberoast → ADCS → spray → vuln-probe → hash-harvest → auto-crack → lateral-gen, so later phases can consume earlier output (e.g. Kerberoast needs the SPN list, lateral gen needs captured hashes)",
			"Creds-gated phases (auth enum, BloodHound, Kerberoast, targeted Kerberoast, ADCS) run only when a Username is set together with ANY of Password / NTLMHash / KerberosCC; without creds only the unauthenticated + AS-REP paths run",
			"Risk tiers are enforced by toggle: the safe tier defaults ON, every medium-tier action (LLMNR/NBT-NS poisoning, mitm6, coercion, targeted Kerberoast, password spray, auto-crack) defaults OFF and must be explicitly enabled",
			"Targeted Kerberoast is advertised in the UI but not implemented — checking it produces only a warning, never an SPN modification",
			"hashcat is the only cracker actually invoked; john is listed in the preflight catalog as a fallback but is not wired into the auto-crack phase. rockyou.txt.gz is not auto-decompressed — the phase warns you to gunzip it",
			"AS-REP roast and Kerberoast fan out across ALL discovered DCs (multi-DC forests, RODCs, GCs) and de-dupe results by (account, hash) so a pickup on several DCs is recorded once. ADCS enumeration, by contrast, runs against only the single best-scored DC (bestDC), not every DC",
			"Every subprocess routes through shared.Command, so when the Killswitch is armed the tools execute inside scanner-ns and obey the VPN egress path (no DNS leak). The poisoning listeners pin to the killswitch veth scanner1; if it is absent they fall back to eth0 / the first UP interface and warn that traffic may not be sandboxed",
			"Secrets never leak into the saved result: the visible command log redacts -p/-H/Impacket 'domain/user:password' arguments, and generated lateral commands substitute <PASSWORD>/<NTHASH> placeholders instead of the real values",
			"Password spray is hard-capped at LockoutThreshold-1 attempts per account so a single run can never trip the domain lockout policy; it is skipped entirely when LockoutThreshold is 0",
			"On an internet-drop pause adpentest is NOT auto-resumed — it is listed in noGenericResume because AD phases are a dependency chain holding half-populated ticket/hash/session state that cannot be safely reconstructed; the paused run keeps its partial result and must be Restarted from scratch",
		},
		References: []ReferenceRef{
			{Label: "The Hacker Recipes — Active Directory", URL: "https://www.thehacker.recipes/ad/"},
			{Label: "BloodHound documentation", URL: "https://bloodhound.readthedocs.io/"},
			{Label: "Certipy — AD CS enumeration & ESC abuse", URL: "https://github.com/ly4k/Certipy"},
			{Label: "Impacket", URL: "https://github.com/fortra/impacket"},
			{Label: "NetExec (nxc) wiki", URL: "https://www.netexec.wiki/"},
			{Label: "hashcat example hashes / mode IDs", URL: "https://hashcat.net/wiki/doku.php?id=example_hashes"},
			{Label: "ZeroLogon — CVE-2020-1472", URL: "https://nvd.nist.gov/vuln/detail/CVE-2020-1472"},
		},
	},

	// ========================================================================
	// SSL / TLS
	// ========================================================================
	"sslscan": {
		Summary: "Runs a thorough, tool-driven SSL/TLS audit of each host:port by combining sslscan --xml (protocols incl. SSLv2/SSLv3, cipher strength, Heartbleed, TLS compression/CRIME, insecure renegotiation), nmap NSE (ssl-enum-ciphers A–F grades plus the POODLE/DROWN/Logjam vuln scripts) and openssl s_client (certificate evidence), backed by an in-process Go crypto/tls handshake sweep that authoritatively proves protocol support so a live TLS host is never dropped when a tool fails. Findings cover vulnerable protocols (SSL 2.0/3.0 → DROWN/POODLE, TLS 1.0/1.1 → BEAST/FREAK), weak/anonymous/NULL cipher suites (RC4, 3DES → SWEET32, EXPORT, DES, Anonymous DH), tool-only vulnerabilities (Heartbleed, CRIME, Logjam, insecure renegotiation) and certificate problems (expired, self-signed, weak signature, hostname mismatch, missing intermediates, no OCSP stapling), each with CVE references and severity scoring. Because that in-process sweep offers every cipher suite Go implements (including the insecure RC4/3DES/CBC ones) with no SECLEVEL filtering, it still completes a handshake — and so proves the protocol version — even against servers that only accept deprecated suites which OpenSSL-policy-bound tools refuse to negotiate; the actual cipher naming is left to nmap/sslscan.",
		Tools: []ToolRef{
			{Name: "sslscan", Desc: "--xml run: protocol enable/disable incl. SSLv2/SSLv3, cipher list with strength ratings, Heartbleed, TLS compression (CRIME) and insecure renegotiation; STARTTLS via --starttls-* flags. The protocol block is salvaged from console output if the XML dies mid-run"},
			{Name: "nmap NSE", Desc: "One -Pn invocation runs ssl-enum-ciphers (A–F cipher grades) + ssl-poodle, ssl-heartbleed, sslv2-drown, ssl-dh-params, yielding POODLE/DROWN/Logjam/Heartbleed CVE findings"},
			{Name: "openssl s_client", Desc: "Reproducible certificate PoC (served chain, protocol, cipher, validity, key) — captured for the standalone module only, skipped on the bulk path"},
			{Name: "Go crypto/tls", Desc: "In-process handshake sweep (TLS 1.0–1.3) that authoritatively proves protocol support and is the backstop that stops a live TLS host being dropped when the external tools fail; offers every cipher suite Go implements (incl. the insecure RC4/3DES/CBC ones) with no SECLEVEL filtering so even a weak-cipher-only server still completes the handshake. It does NOT enumerate ciphers — cipher naming is left to nmap/sslscan"},
			{Name: "Go crypto/x509", Desc: "Certificate chain parsing + Verify() against the system root store (chain validity, missing intermediates, self-signed, hostname/SAN match)"},
		},
		Phases: []string{
			"TCP connectivity check — verifies the port even accepts a connection before wasting handshakes on dead hosts",
			"STARTTLS resolution — port 443 dials TLS directly, while the mail/FTP/LDAP/Postgres ports (25/587/143/110/21/389/5432) first run the plaintext AUTH-then-upgrade dance so STARTTLS-only services are audited instead of read as 'No TLS'",
			"sslscan --xml run — enumerates protocols (incl. SSLv2/SSLv3), cipher suites with strength ratings, Heartbleed, TLS compression (CRIME) and insecure renegotiation; if its XML dies mid-run the protocol block is salvaged from the console output",
			"nmap NSE run — a single -Pn invocation drives ssl-enum-ciphers (A–F cipher grades) plus ssl-poodle, ssl-heartbleed, sslv2-drown and ssl-dh-params, yielding the POODLE/DROWN/Logjam/Heartbleed findings",
			"Certificate extraction — subject, issuer, NotBefore/NotAfter, signature algorithm, public-key size, SANs, self-signed detection",
			"Chain validation — call cert.Verify() with the intermediates the server bundled; surfaces 'no intermediates served' which breaks older clients even when modern browsers cope via AIA fetch",
			"OCSP stapling check — state.OCSPResponse non-empty means the server pre-fetched a status response (revocation check works offline; missing OCSP = MITM with stolen cert may bypass revocation)",
			"Go crypto/tls protocol sweep — handshakes TLS 1.0–1.3 in-process (legacy TLS 1.0/1.1 require two confirming handshakes) as the authoritative protocol-presence backstop, so a live TLS host is never dropped as 'No TLS' just because sslscan/nmap failed or timed out; crypto/tls can't speak SSL 2.0/3.0, so those rest on sslscan",
			"Merge + finding classification — protocol support is decided per version by the right authority (legacy: sslscan 'enabled' or a Go handshake; modern: any tool), the cipher list is preferred from nmap's IANA names, then findings are analysed, the tool-only vulns (Heartbleed/CRIME/DROWN/Logjam/insecure-reneg) appended, and everything de-duplicated by title",
		},
		Notes: []string{
			"Reports weak cipher suites as ONE finding per TLS VERSION (e.g. 'Weak Cipher Suites (TLS 1.1)') summarising that version's categories (RC4 / 3DES / EXPORT / DES / CBC-no-PFS / static-RSA) — grouping per category produced too many rows per host. The 'Cipher Suites' tab shows the per-suite breakdown",
			"Hosts that don't speak TLS at all are skipped silently — this is desired behaviour because port scanners that include 443 will throw many false positives otherwise",
			"3DES on TLS 1.0 is the classic 'tool says no, server says yes' divergence — see the SSL/TLS doc notes for cross-verification via nmap or sslyze",
			"Cipher enumeration is taken from nmap's ssl-enum-ciphers (IANA names, so category classification works) and falls back to sslscan's list; TLS 1.3 suites aren't user-configurable in Go, so the in-process sweep only confirms protocol support and leaves cipher naming to the tools",
			"Self-signed leaves and expired certs are MEDIUM/HIGH severity respectively — they ARE valid pentest findings but won't trigger client-side TLS errors if the user pre-installed the cert as a trust anchor",
			"The engine treats nmap AND sslscan as required: a host errors out ('requires nmap and sslscan') only when BOTH are missing AND the in-process Go sweep also finds no TLS — if the Go sweep proves TLS, or either tool is present, the scan proceeds but carries a Limitations note whenever a tool is missing or fails for that host, so a thorough-looking 'no vulnerabilities' panel is never mistaken for a full audit (a missing sslscan silently drops SSLv2/SSLv3 + Heartbleed/CRIME/insecure-reneg; a missing nmap drops the POODLE/DROWN/Logjam vuln-NSE + A–F cipher grades)",
			"In the Go sweep, legacy TLS 1.0/1.1 is asserted only when TWO independent handshakes complete, so a stray success against a shared load-balancer IP can't manufacture a phantom legacy finding (sslscan's explicit 'enabled' is also trusted); modern TLS 1.2/1.3 needs just one",
			"The bulk path (advancedweb's SSL stage over 1000s of hosts) runs the same detection but skips the heavy per-host evidence (tool transcripts + PoC) and the openssl cert dump, with much tighter per-tool timeouts, to keep results small and stable",
		},
		References: []ReferenceRef{
			{Label: "RFC 8996 (TLS 1.0/1.1 deprecation, March 2021)", URL: "https://datatracker.ietf.org/doc/html/rfc8996"},
			{Label: "SWEET32 — 3DES birthday attacks (CVE-2016-2183)", URL: "https://sweet32.info/"},
			{Label: "Mozilla TLS configurator (modern/intermediate/old presets)", URL: "https://ssl-config.mozilla.org/"},
			{Label: "BEAST attack on TLS 1.0 CBC", URL: "https://www.openssl.org/~bodo/tls-cbc.txt"},
			{Label: "Heartbleed (CVE-2014-0160)", URL: "https://heartbleed.com/"},
			{Label: "DROWN attack (CVE-2016-0800)", URL: "https://drownattack.com/"},
			{Label: "Logjam / weak Diffie-Hellman", URL: "https://weakdh.org/"},
		},
	},

	// ========================================================================
	// HTTPX Finder
	// ========================================================================
	"httpxfind": {
		Summary: "Discovers HTTP/HTTPS services across a target list by probing ports and capturing per-service metadata (status, title, Server header, redirect target, response body, raw request/response bytes). This is the bread-and-butter first step of a web pentest: before you can hunt vulnerabilities you need to know WHERE the web apps live. The 'Full' mode TCP-scans all 65535 ports first so admin panels hidden on weird ports (e.g. Jenkins on 8082, Grafana on 3000) don't slip through.",
		Tools: []ToolRef{
			{Name: "Go net/http", Desc: "Custom client with InsecureSkipVerify and CheckRedirect = ErrUseLastResponse (don't follow redirects — we want the Location header)"},
			{Name: "Go net (TCP)", Desc: "Concurrent TCP connect port-open detection in Full mode — default 150 parallel connects (lowered from 500 to avoid saturating a home router's conntrack/NAT table), throttled by a token bucket to 500 new connections/sec"},
		},
		Phases: []string{
			"Mode selection — Common (4 ports: 80, 443, 8080, 8443) or Full (1–65535 TCP scan first, then HTTP probe open ports)",
			"Full mode — sweep every host's 65535 ports in a per-host randomised order, round-robin across hosts, to defeat the sequential-scan signature an IDS/firewall keys on; a shared token bucket caps new connections per second and unresolvable hostnames are dropped up front (fail-open on resolver errors)",
			"For each target × port, probe both schemes — HTTPS-first on most ports, HTTP-first on 80/8080; the first scheme that answers wins, otherwise fall back to the other — many legacy admin panels are still HTTP-only",
			"Send GET / with a recognisable User-Agent and capture the raw request bytes via httputil.DumpRequest (Burp replay material)",
			"Read response with a 256 KB body cap to keep memory bounded for huge pages",
			"Parse <title> via regex, snap the Server / Content-Type / Content-Length / Location headers",
			"Build a per-service row with all metadata + raw request + raw response for Burp Repeater",
			"Replay-hit via shared HTTP options — sends only the confirmed-alive URLs to Burp Proxy when the user has enabled 'send hits to proxy'",
		},
		Notes: []string{
			"Common mode finishes in seconds against a /24. Full mode against the same /24 takes minutes — use it ONLY when you suspect non-standard ports (e.g. a customer dev environment)",
			"Status filtering is not applied — even 404/500 are recorded because the response headers often disclose the framework / load-balancer behind",
			"Redirects are NOT followed — that's intentional. Following them would mask CDN/WAF edge nodes and double-count the same backend",
			"The 'Raw HTTP' panel in each result row carries the bytes Burp Repeater needs — no need to re-issue the request manually",
			"Title extraction uses a regex tolerant of leading whitespace inside <title> — caps to 200 chars",
			"Full mode has a 'direct HTTP/HTTPS' variant that skips the TCP connect pre-scan and fires HTTP straight at every port — only ports that actually answer HTTP are recorded, so a firewall that accepts or tarpits every connect can't inflate the result",
			"Results are memory-bounded: at most 20,000 services are retained, and once the retained response bodies/raw bytes pass ~128 MB the heavy body/raw fields are dropped (host/port/status/title still kept) and the result is flagged truncated — this stops an all-port sweep against a catch-all host that answers HTTP on every port from exhausting memory",
			"A dead port counts at most one error toward the per-scan error budget even though both HTTPS and HTTP are attempted, so probing closed ports doesn't trip the scan-abort threshold twice as fast as intended",
		},
		References: []ReferenceRef{
			{Label: "OWASP Web Server Fingerprint Cheat Sheet", URL: "https://owasp.org/www-community/attacks/Web_Server_Fingerprinting"},
			{Label: "ProjectDiscovery httpx (the inspiration)", URL: "https://github.com/projectdiscovery/httpx"},
		},
	},

	// ========================================================================
	// HTTP Method Tester
	// ========================================================================
	"httpmethods": {
		Summary: "Sends 9 HTTP methods (GET, HEAD, POST, PUT, PATCH, DELETE, OPTIONS, TRACE, CONNECT) plus 6 WebDAV methods (PROPFIND, MKCOL, COPY, MOVE, LOCK, UNLOCK) against each URL, with multiple Content-Type variants on the body-accepting ones (form, JSON, XML, multipart, binary, plain text). Catches misconfigured frameworks that respond 200 to PUT (file-upload RCE), DELETE (data destruction), TRACE (XST → cookie exfiltration when paired with HttpOnly bypass), or WebDAV (full filesystem on the wire).",
		Tools: []ToolRef{
			{Name: "Go net/http", Desc: "Raw method-driven requests; non-standard methods are sent verbatim — net/http does not block them"},
		},
		Phases: []string{
			"Build the method×content-type matrix — POST gets 6 variants (No Body, form-urlencoded, JSON, XML, multipart, text/plain), PUT gets 6 (No Body, form, JSON, XML, octet-stream binary, text/plain), PATCH 5 and DELETE 2 variants; TRACE gets a special X-XST-Marker request header",
			"Issue each request with httputil.DumpRequestOut/DumpResponse capturing the wire bytes (secret headers like Authorization/Cookie redacted before storage) and replay each reachable URL once to Burp",
			"Classify each response — Allowed (2xx), Redirect (3xx, not flagged dangerous), Not Allowed (405), Not Implemented (501), Forbidden (403), Unsupported Media Type (415), else the raw status code; a TRACE whose response echoes the injected X-XST-Marker header back is annotated 'XST confirmed' and flagged dangerous",
			"Dangerous-flag heuristic — PUT/DELETE/TRACE/CONNECT plus WebDAV methods marked dangerous when Status == Allowed",
			"Capture response Allow header — gives an authoritative server-side method list straight from the OPTIONS handshake",
			"Surface 'dangerous=YES' rows in a dedicated 'Dangerous Methods Only' export section so report writing is one click",
		},
		Notes: []string{
			"PUT returning 200/201 with the request body echoed = remote-file-write — classic Tomcat readonly=false RCE chain (CVE-2017-12617)",
			"TRACE that echoes Request headers + body = XST (Cross-Site Tracing) — combined with XSS, attacker can exfiltrate HttpOnly cookies",
			"WebDAV methods (PROPFIND etc.) allowed on production = forgotten test/staging exposure — usually full read+write access to the doc root",
			"Many WAFs block uncommon methods at the edge — getting 403 on PUT does NOT mean the origin server is safe, it means the WAF is doing its job",
			"30 probes per URL (15 methods × content-type variants) — use the workspace concurrency limit if scanning many endpoints",
		},
		References: []ReferenceRef{
			{Label: "OWASP HTTP Method Tampering", URL: "https://owasp.org/www-community/attacks/HTTP_Method_Tampering"},
			{Label: "CVE-2017-12617 (Apache Tomcat PUT RCE)", URL: "https://nvd.nist.gov/vuln/detail/CVE-2017-12617"},
			{Label: "XST (Cross-Site Tracing) — Jeremiah Grossman", URL: "https://www.whitehatsec.com/wp-content/uploads/2013/09/WHXSTPaper.pdf"},
		},
	},

	// ========================================================================
	// WAF Detector
	// ========================================================================
	"wafdetect": {
		Summary: "Identifies Web Application Firewalls in the path of a target through layered fingerprinting: header signatures (Cloudflare's CF-RAY, Akamai's X-Akamai-*), cookie names (Imperva's incap_ses_*, F5's TS01*), error-page body matching (custom block pages), and active payload probing (XSS/SQLi/LFI/RFI sent intentionally to provoke block responses). Knowing the WAF in advance shapes evasion strategy — Cloudflare's positive-security rule order differs sharply from AWS WAF's, and Akamai's Bot Manager fingerprints TLS client behaviour separately from request content.",
		Tools: []ToolRef{
			{Name: "Go net/http", Desc: "Baseline GET + 8 attack-payload probes (one carries an anomalous crawler User-Agent)"},
			{Name: "Signature DB (in-tree)", Desc: "20+ WAF vendors (Cloudflare, Akamai, AWS WAF, Imperva, F5, ModSecurity, Sucuri, Barracuda, Fortinet, etc.) matched against header/cookie/body fingerprints"},
		},
		Phases: []string{
			"Normal-traffic baseline — single GET to capture headers, cookies, body. This is the 'innocent client' fingerprint",
			"Match the baseline against 20+ vendor signatures, scoring each (header match = 25 points, cookie match = 20, body match = 30)",
			"Active payload phase (skipped when the launch form disables payload probing) — send 8 known-malicious requests (XSS <script>, SQLi OR 1=1, LFI ../etc/passwd, RFI http://evil.com/shell.txt, command injection, path traversal, protocol violation, suspicious User-Agent)",
			"For each payload, observe status code delta vs baseline. 403/406/429/503/999 on a baseline-200 endpoint = WAF block, +30 confidence",
			"Re-match the BLOCKED response body against signatures — the WAF's challenge page itself often leaks the vendor name",
			"Pick the highest-scoring vendor with confidence ≥ 15; below that, report 'Unknown WAF' but include the evidence that one is present",
		},
		Notes: []string{
			"The User-Agent Anomaly probe uses a real-world cloud-system-networks bot string — many WAFs rate-limit suspicious crawlers, so this surfaces edge defenses even when content-based payloads aren't blocked",
			"CDN ≠ WAF — Fastly fronts many sites without active filtering. Look for Fastly headers PLUS payload-block evidence before claiming 'WAF detected'",
			"WAFs deliberately add latency to suspicious probes — back-to-back requests against the same target may trigger temporary IP blocks. Run from rotating egress IPs for repeatable testing",
			"This module does NOT bypass the WAF — for that, use the OWASP CRS bypass cheat sheet or the dedicated paramdisc / corsscan / sstiscan modules with payload encoding tricks",
			"Payload probing is optional — when the launch form disables it, only the baseline signature/header/cookie/body analysis runs and the WAF verdict is derived from those signature scores alone (no active malicious requests are sent)",
			"Targets are scanned concurrently (default 5 in flight, configurable up to 50) with a default per-request timeout of 10 s (configurable up to 60 s); an optional reachability preflight skips TLS-dead hosts up front, recording them as explicit 'unreachable' rows",
		},
		References: []ReferenceRef{
			{Label: "OWASP WAF Bypass Techniques", URL: "https://owasp.org/www-community/attacks/Web_Application_Firewall_Bypassing"},
			{Label: "wafw00f — the open-source reference fingerprinter", URL: "https://github.com/EnableSecurity/wafw00f"},
		},
	},

	// ========================================================================
	// Tech Detector
	// ========================================================================
	"techdetect": {
		Summary: "Identifies the technology stack of a target by fusing two detection layers: 290+ built-in fingerprints (HTTP headers, cookies, HTML body, meta/script/link tags) and WhatWeb's plugin set (passive -a 1 by default; -a 3 when the Aggressive toggle is on). Categorises results into CMS, Framework, Web Server, Language, JS Library, CDN, Analytics, UI, Security — and crucially CAPTURES VERSIONS where possible so cvematch can chain into CVE lookups. The favicon MurmurHash3 mode mirrors Shodan's http.favicon.hash technique: pivot from one hash to every other host on the internet serving the same icon (mass-asset discovery for the same SaaS deployment).",
		Tools: []ToolRef{
			{Name: "Built-in fingerprints", Desc: "290+ rules (WordPress generator meta, X-Powered-By, React data-reactroot markers, Next.js __NEXT_DATA__, jQuery script-src, nginx Server header, etc.)"},
			{Name: "whatweb", Desc: "External Ruby CLI — adds 1800+ plugins (must be on $PATH). Runs passive (-a 1) by default; the Aggressive toggle switches it to -a 3 for deeper, slower plugin probing"},
			{Name: "MurmurHash3", Desc: "Hashes the favicon (declared <link rel=icon> first, then /favicon.ico) for Shodan-style pivoting"},
		},
		Phases: []string{
			"Fetch target URL with captured raw req/resp for Burp; allow up to 3 redirects so canonical homes resolve",
			"Extract response headers, cookies, HTML body, meta tags — these are the inputs all fingerprinters consume",
			"Built-in pattern match against 290+ rules — fast (single-file, no spawn) and catches the high-signal cases (X-Generator: WordPress 6.4.3)",
			"Fetch up to 2 first-party .js bundles referenced in the HTML (<=128 KB each, exact-host only) and re-run the body fingerprints over them — SPA framework names + versions (React/Vue/Next/lodash/axios/sentry) live inside the bundle, not the root HTML",
			"Run whatweb per target after the built-in pass — passive -a 1 (25s budget) by default, -a 3 (60s budget) only when the Aggressive toggle is on; it runs even if the Go GET failed, and up to ~20 targets are processed concurrently (capacity-driven)",
			"Merge results — WhatWeb fills in versions for fingerprints the built-in rules matched without one",
			"Enrich versions from response headers (Server, X-Powered-By, X-AspNet-Version, X-Generator, Via/X-Varnish, CF-Ray) and body signals (meta generator, JS asset paths, WordPress core markers), then collapse same-product duplicates into one entry so CVE matching sees a single versioned detection",
			"Categorise — CMS (WordPress/Drupal/Joomla), Framework (Django/Rails/Spring), Server (nginx/Apache/IIS), Language (PHP/Python/Java/Node), JS (React/Vue/jQuery), CDN (Cloudflare/Fastly), Analytics (GTM/Mixpanel), Security (CSP/HSTS markers), UI (Bootstrap/Tailwind)",
			"Favicon fetch — try <link rel='icon'> first, fall back to /favicon.ico. Hash the bytes, base64-wrap-76 to match Shodan's canonical form",
		},
		Notes: []string{
			"whatweb is optional but recommended — without it the module still catches most stacks via the built-in rules. If whatweb is missing or exits with no output the scan still succeeds: a non-fatal amber warning banner flags that whatweb didn't run while the Go-side fingerprint results are kept",
			"FaviconMMH3 is the killer feature for asset discovery — paste the int32 into Shodan's http.favicon.hash:<value> filter and you'll find every other deployment in the wild (think SaaS clones)",
			"Version detection is best-effort. Where multiple sources disagree (header says 'nginx/1.18', X-Powered-By says 'nginx/1.20'), the FIRST version detected wins — later sources only backfill a version onto a detection that has none, they never overwrite one",
			"Feeds cvematch directly — once you have (Apache, 2.4.49) the CVE matcher returns CVE-2021-41773 in one click",
			"In the advancedweb suite, techdetect runs a network-free path that reuses HTTPX's already-fetched responses (ScanFromPrefetched) — whatweb and all fresh fetches are skipped, only the built-in fingerprints, header parsing and version mining run, sized to one worker per CPU core",
		},
		References: []ReferenceRef{
			{Label: "WhatWeb plugin reference", URL: "https://github.com/urbanadventurer/WhatWeb/wiki"},
			{Label: "Shodan favicon hash technique (writeup)", URL: "https://medium.com/@Behrouz_Sadeghipour/favicon-hash-trick-66c4dc09b75e"},
			{Label: "Wappalyzer fingerprints (community reference)", URL: "https://github.com/wappalyzer/wappalyzer"},
		},
	},

	// ========================================================================
	// Web Spider
	// ========================================================================
	"spider": {
		Summary: "Crawls a web application from a seed URL, extracting links from every parseable source (HTML href / src / action / srcset / form, CSS url(), JS string-literal paths, .js bundle scanning with API regex extractors) and classifying each discovery as directory, file, or endpoint. Seeds discovery from robots.txt and sitemap.xml before the seed URL, and mines every HTML page for high-signal recon artifacts — emails, HTML comments, forms (action / method / field names), external links, and image / video / audio / JS references. Stays in-scope by matching same-host (optionally widening to the whole eTLD+1 when Include Subdomains is on), respects Max Depth + Max Pages limits, and runs a configurable worker pool (10 by default) with a visited-set guard. A connectivity pause checkpoints the crawl frontier for lossless resume. Output feeds direnum (discovered paths seed its probes) and openredirect (discovered URLs retain candidate redirect parameters).",
		Tools: []ToolRef{
			{Name: "Go net/http + regexp", Desc: "Concurrent worker pool, HTML attribute regex, CSS url() regex, JS endpoint regex"},
			{Name: "Same-host filter", Desc: "Strips off-scope hosts so a single rogue <a href='facebook.com'> doesn't drag the crawler off-target"},
		},
		Phases: []string{
			"Optional reachability preflight drops unreachable seeds up front; a resumed scan instead reloads its saved checkpoint — visited-set, page count, prior finds, and pending frontier",
			"Seed discovery from /robots.txt (Allow / Disallow paths plus declared Sitemap:) and /sitemap.xml + /sitemap_index.xml (<loc> entries, nested indexes followed), then enqueue the seed URL and mark visited",
			"A dispatcher spawns up to Concurrency (default 10) worker goroutines that pop URLs, apply the optional per-request delay, fetch with the shared HTTP client, and capture raw req/resp — operator Cookie / Authorization / API-key headers redacted before storage",
			"Branch on Content-Type: HTML → harvest recon artifacts (emails, HTML comments, forms, external links, image/video/audio/JS refs) and extract links (href/src/action/srcset attrs, CSS url(), conservative JS path literals); JavaScript body or .js URL → extractJSEndpoints() runs 3 regex patterns (api/v\\d+/..., fetch/axios calls, url=/path= assignments), capped at 200/file",
			"Resolve all extracted links against the current page URL (relative→absolute), filter to in-scope host (same-host, or same eTLD+1 when Include Subdomains is on), drop fragments, and skip logout / exclude-regex paths so operator cookies aren't killed",
			"Classify the path — trailing slash → directory; known extension → file; /api/, /v1/, GraphQL marker → endpoint",
			"Track depth (distance from seed) and 'found-on' (parent page) for each resource — essential for vulnerability reports",
			"Stop conditions: visited count ≥ MaxPages OR all queue depths exhausted OR ctx cancelled by user Stop button",
		},
		Notes: []string{
			"JS endpoint extraction is the secret weapon for SPA-heavy targets — modern React/Vue apps reveal more API surface in bundle.js than in any rendered HTML",
			"Crawler is intentionally simple (no JS execution). For full SPA rendering use Burp Suite's embedded Chromium or write a Playwright recorder",
			"Max Depth = 0 means 'seeds only' (useful as a sanity probe before a long crawl). Max Depth = 5+ with permissive Max Pages is reckless on production",
			"Resources discovered here flow into the asset_findings dashboard, where direnum / paramdisc / cvematch can cross-reference",
			"Forms are recorded with action + method + field names — useful manual review for CSRF / authentication endpoints",
			"robots.txt (Allow / Disallow paths plus Sitemap: declarations) and sitemap.xml are consumed before the crawl proper — the two highest-yield 'free' discovery sources, and missing them is why users otherwise reach for katana / gospider mid-engagement",
			"Beyond the path tree, every HTML page is mined for emails, HTML comments (a frequent leak of internal notes / credentials), external links and image / video / audio / JS references — all deduped and capped so a huge site can't blow the result blob",
			"Logout / session-terminating URLs are never followed, and an optional per-path exclude-regex skips destructive links (delete / unsubscribe) so a crawl running with operator cookies can't log itself out or fire dangerous actions",
			"A connectivity pause (Stop button or a dropped VPN) snapshots the exact crawl frontier — visited-set, page count, and pending URLs — so the scan resumes losslessly instead of restarting from the seed",
		},
		References: []ReferenceRef{
			{Label: "Hakrawler (similar tool, the JS path-regex inspiration)", URL: "https://github.com/hakluke/hakrawler"},
			{Label: "OWASP Spider methodology", URL: "https://owasp.org/www-project-web-security-testing-guide/v42/4-Web_Application_Security_Testing/01-Information_Gathering/06-Identify_Application_Entry_Points"},
		},
	},

	// ========================================================================
	// Directory Enumerator
	// ========================================================================
	"direnum": {
		Summary: "Technology-aware directory and file brute-forcing with smart false-positive detection. Combines SecLists wordlists, per-tech extension lists (PHP, ASP.NET, Java, Node, WordPress paths), and a ~2304-probe-per-extension baseline matrix that catches 'soft 404' servers (sites that return 200 or a stable error page for nonexistent paths): it learns each extension's not-found (status code, body size) fingerprint and filters live results against it, so status-code-200 false positives don't drown out the real hits.",
		Tools: []ToolRef{
			{Name: "SecLists wordlists", Desc: "common.txt (low), raft-medium / raft-large (normal/aggressive), DirBuster mediums, tech-specific files (PHP/ASP/Java/Node/WP/API); loaded via loadWordlist with a missing/empty-file embedded fallback"},
			{Name: "Go net/http", Desc: "Concurrent requests with workspace-driven concurrency cap (capacity.Recommend)"},
		},
		Phases: []string{
			"User selects technology profiles (PHP, ASP.NET, Java, Python, Node, WordPress, Drupal, Joomla, ColdFusion, Apache, API, General) — drives the wordlist + extension matrix",
			"Scan level (Light=common.txt, Normal=raft-medium, Aggressive=raft-large) determines wordlist size",
			"Smart Scan baseline — sweep ~2304 random nonexistent paths PER extension (6 charsets × 8 lengths × 6 shapes × 8 samples) to learn the server's false-positive shape: any (status code, body size) pair recurring ≥5× becomes an FP signature, and the status code is locked in only when it dominates ⅔+ of the matrix",
			"Build the full request list — words × tech extensions × profiles, dedup + skip user-blocked paths",
			"Concurrent probe loop with workspace-defined parallelism (default 30 in-flight)",
			"For each response, compare against the FP baseline matrix. Drop matches → these are soft-404s, not real discoveries",
			"Classify each surviving response — trailing slash → directory; with extension → file; capture redirect target if 3xx",
			"Backup-file enrichment — every bare word is also probed with common backup / editor-swap suffixes (.bak, .swp, .old, .orig, .tmp, .~, .back) stacked on top of the profile extensions, catching leftovers like /config.bak or /admin.swp",
			"Optional Exclude Paths — skip /admin, /logout, etc. (prefix matching, BFS-aware so recursive sub-levels are also excluded)",
			"Recursive BFS levels (optional) — each directory (and each 403-forbidden directory) discovered at depth N is re-brute-forced at depth N+1 up to Max Depth, skipping any subtree the operator excluded or marked skip mid-scan",
		},
		Notes: []string{
			"Smart Scan filters live results against the calibrated baseline FP signature — matching (status code, body size), not trusting status codes blindly — so 'soft 404' servers that answer 200 for everything don't bury the real hits",
			"Recursive mode (Max Depth 2-3) is where real magic happens — /admin/ found at depth 0 triggers a Depth-1 enum on /admin/users, /admin/settings, etc.",
			"Aggressive level can hit 200k+ requests per target — use workspace concurrency caps + Burp Replay-Hit toggle to keep the proxy log manageable",
			"The 'Skip Path' feature holds an in-memory per-scan skip set keyed by scan ID — consulted live by the recursive BFS, so marking a directory mid-scan drops its whole subtree from in-flight and queued requests immediately. The set is discarded when the scan ends (it is not persisted across scans)",
			"There is no automatic 'general' profile — select only 'wordpress' and you get ONLY the WordPress words + extensions, not generic basics like /backup or /test. The 'general' fallback kicks in only when your selection resolves to zero known profiles (and the launcher defaults to 'general' when you pick nothing)",
			"Logout-related paths are stripped from every wordlist (shared.IsLogoutPath) before probing, so the brute-force can't log the operator out of an authenticated session mid-scan",
			"403 responses are kept as real signal (the resource exists but access is denied): they bypass smart-scan FP filtering and their directories are still walked recursively, while an adaptive guard bans any (status code, body size) pair seen 8+ times mid-scan and retroactively removes earlier matches",
			"Operators can supply extra wordlists through the launch form (capped at 16); any wordlist — profile or custom — that points at a missing /usr/share/seclists path falls back to a small embedded 30-entry list, so a broken SecLists install degrades to a smoke-pass instead of a silent zero-result scan",
			"Root-level scans are losslessly resumable — a connectivity pause snapshots a watermark of completed requests and reuses the calibrated FP signatures, so Resume continues without re-probing the wordlist or re-running the multi-minute calibration; a scan paused after recursion started is not checkpointed and restarts",
		},
		References: []ReferenceRef{
			{Label: "SecLists project (the source of truth for wordlists)", URL: "https://github.com/danielmiessler/SecLists"},
			{Label: "OWASP Forced Browsing", URL: "https://owasp.org/www-community/attacks/Forced_browsing"},
			{Label: "Feroxbuster soft-404 detection (similar approach)", URL: "https://github.com/epi052/feroxbuster"},
		},
	},

	// ========================================================================
	// Security Headers
	// ========================================================================
	"secheaders": {
		Summary: "Audits HTTP security headers across multiple method/content-type variants, grades each URL A+ through F, and flags inconsistencies where the same header differs between methods (a common reverse-proxy misconfiguration). Checks 14 critical headers: Strict-Transport-Security, Content-Security-Policy, X-Frame-Options, X-Content-Type-Options, Referrer-Policy, Permissions-Policy, Cross-Origin-* triad, Cache-Control, plus information-leak headers (Server, X-Powered-By, X-AspNet-Version). Cookie audit catches HttpOnly/Secure/SameSite omissions and overly broad Domain=, plus a passive CORS audit of Access-Control-Allow-Origin/Access-Control-Allow-Credentials that flags wildcard, null, reflected-looking, and credentialed origins.",
		Tools: []ToolRef{
			{Name: "Go net/http", Desc: "Same probe mechanism as HTTP Method Tester — up to 11 method/content-type probe variants per URL across 7 HTTP methods (GET, HEAD, POST, PUT, PATCH, DELETE, OPTIONS)"},
		},
		Phases: []string{
			"Build the 11-variant probe matrix — GET, HEAD, POST (no body/form/JSON/XML), PUT (no body/JSON), PATCH (JSON), DELETE, OPTIONS — filtered to the user-selected methods (GET only by default); capture per-variant raw req/resp",
			"Filter to responses returning 200 OK — headers on a 405 are meaningless for end-user security",
			"Per-probe analysis — evaluate every header check (and the per-cookie audit) against THIS probe's response. Lets the UI show 'GET passes HSTS but POST is missing it' instead of hiding behind a worst-case aggregate",
			"Worst-case aggregation — for the score card, take the WEAKEST value of each header across probes (a single misconfigured method ruins the grade — correct behaviour)",
			"Cookie audit — split joined Set-Cookie header into individual cookies, check HttpOnly/Secure/SameSite, flag overly broad Domain=, check __Host- / __Secure- prefix usage",
			"CORS header audit — inspect Access-Control-Allow-Origin (flag wildcard, null, or a single reflected-looking origin) and Access-Control-Allow-Credentials (flag credentialed CORS); passive only — it does not send an Origin header, but advises manual reflection testing",
			"Information-leak header check — Server/X-Powered-By/X-AspNet-Version disclose versions usable by attackers",
			"Cross-method inconsistency check — for each required header, compare its value across all 200 OK probes and flag a MEDIUM finding when a method/content-type returns a different value",
			"Score → grade — HIGH severity -20pts, MEDIUM -10, LOW -5, PASS 0. Grade A+ ≥95, A ≥85, B ≥75, C ≥60, D ≥40, F otherwise",
		},
		Notes: []string{
			"The 'cross-method inconsistency' finding is unique to this tool — most scanners only check GET. CSRF/auth endpoints often forget to set CSP on POST responses (fires only when the user selects more than one method, since it needs >1 probe)",
			"CSP audit looks for unsafe-inline / unsafe-eval / wildcard — does NOT execute the policy or validate report-uri targets",
			"HSTS audit flags a missing header (HIGH), a missing max-age directive (MEDIUM), max-age=0 (HIGH, effectively disabled), and a missing includeSubDomains directive (LOW) — it does not parse the numeric max-age duration",
			"Permissions-Policy is opt-in; a missing header is only a LOW finding since most sites don't need to disable geolocation/camera APIs",
			"The cookie audit fires per-cookie — a single response with 5 cookies missing HttpOnly produces 5 findings",
		},
		References: []ReferenceRef{
			{Label: "OWASP Secure Headers Project", URL: "https://owasp.org/www-project-secure-headers/"},
			{Label: "MDN — Content-Security-Policy reference", URL: "https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Content-Security-Policy"},
			{Label: "scotthelme.co.uk grading rubric (the basis for our A+/A/B/C/D/F)", URL: "https://scotthelme.co.uk/hardening-your-http-response-headers/"},
		},
	},

	// ========================================================================
	// WPScan
	// ========================================================================
	"wpscan": {
		Summary: "WordPress vulnerability scanner powered by the wpscan CLI and the WPScan API vulnerability database (CVE lookups for core / themes / plugins). Detects WordPress version, active theme + its CVEs, all enumerable plugins + their CVEs, exposed config backups, database dumps, and user accounts. An optional WPScan API token — supplied via Settings, not bundled — unlocks the full vulnerability data and per-CVE descriptions; without it the scan still runs, just with limited or no vulnerability lookups.",
		Tools: []ToolRef{
			{Name: "wpscan", Desc: "External Ruby tool — must be installed and on $PATH"},
			{Name: "WPScan API token", Desc: "Optional WPScan vulnerability-database token — set in Settings (wpscan_api_key), passed to wpscan via the WPSCAN_API_TOKEN env var; enables CVE lookups and per-vuln descriptions"},
		},
		Phases: []string{
			"Reachability preflight — when enabled, TLS-dead / unresolvable targets are filtered out (shared.FilterReachable) and marked 'unreachable' before any wpscan process is spawned",
			"Concurrency — up to 2 wpscan processes run at once (MaxConcurrent, overridable), each invoked with --max-threads 30, --request-timeout 30, --connect-timeout 10 and --disable-tls-checks (scan targets routinely have bad certs)",
			"Per-target command build — bare hostnames default to https://; base args add --format json --no-banner; per-scan HTTP knobs are appended: random or custom user-agent, proxy, cookie-string, http-auth and custom headers (http-auth / cookie values are redacted from the console crumb)",
			"Speed profile selects the enumeration: Fast = --enumerate ap,cb,u + --plugins-detection passive (~15-60s); Normal = ap,at,cb,dbe,u + mixed detection (~5-15min); Aggressive = ap,at,cb,dbe,u,tt,m + aggressive plugin and version detection (~30-60min+)",
			"Vulnerability DB freshness — if wpscan reports a stale local database the module runs `wpscan --update` (serialised, success cached 24h) and retries the target; an HTTP 429 API rate-limit triggers a single 60s back-off then one retry",
			"Reachability / WordPress verdict — scan_aborted / stop_reason / text markers in wpscan output map the target to 'not_wordpress', 'unreachable' or 'error' and stop before parsing findings",
			"Parse JSON output into findings — core version (insecure core flagged HIGH), main theme, every plugin, top-level vulns and interesting_findings — bucketed into core / theme / plugin / info",
			"Severity is computed in-module, not taken from wpscan: patched vuln = MEDIUM, unpatched = HIGH, unpatched high-impact class (RCE / SQLi / auth-bypass / priv-esc / file-upload / deserialization / command-injection with no fix) = CRITICAL, interesting findings = INFO",
		},
		Notes: []string{
			"Plugin enumeration is the bulk of runtime — large sites with 50+ plugins can push Normal and Aggressive runs to 15-60 minutes. Use the Fast profile for triage",
			"Hosted WordPress (WordPress.com, managed providers) often returns 403 to /wp-admin probes — the scan still works because passive detection (RSS, OPML, JSON-REST API) succeeds",
			"INFO-severity findings are filtered out of the default exports — they're enumeration data, not vulnerabilities. The 'Site Info' export section shows them when needed",
			"WPScan's vulnerability DB is the gold standard for WordPress — even Nuclei references it indirectly through the wordpress-* template tags",
			"No API token is bundled — set your own in Settings (wpscan_api_key); it's passed to wpscan via the WPSCAN_API_TOKEN env, never argv. Without a token the scan runs unauthenticated with limited/no CVE data; wpscan.com free tokens are rate-limited (~25 requests / 24h)",
		},
		References: []ReferenceRef{
			{Label: "WPScan official site + API docs", URL: "https://wpscan.com/"},
			{Label: "WordPress vulnerability DB", URL: "https://wpscan.com/wordpresses/"},
			{Label: "OWASP WordPress Security Implementation Guideline", URL: "https://owasp.org/www-pdf-archive/OWASP_Wordpress_Security_Implementation_Guideline.pdf"},
		},
	},

	// ========================================================================
	// DNS Enumerator
	// ========================================================================
	"dnsenum": {
		Summary: "Multi-source subdomain enumeration combining passive sources (subfinder + amass + crt.sh + recon-ng + VirusTotal + Shodan + Censys), active brute strategies (puredns/massdns against 18 global resolvers, per-authoritative-NS focused brute, and an opt-in gobuster DNS brute against each nameserver), and altdns-style permutation of every discovered host. Three speed profiles: Fast (~2-5 min, passive + basic brute), Normal (~10-20 min, adds recon-ng + NS brute + permutations), Deep (~30-60+ min, exhaustive). Optional AXFR zone-transfer and reverse-DNS sweep add-ons. Detects wildcard DNS to suppress false positives.",
		Tools: []ToolRef{
			{Name: "puredns + massdns", Desc: "High-speed DNS brute-force with resolver validation; 18 hand-picked global resolvers for redundancy"},
			{Name: "subfinder", Desc: "ProjectDiscovery's passive enumeration run with -all (every configured data source; key-gated ones skip gracefully when unconfigured)"},
			{Name: "amass", Desc: "OWASP's passive enumeration (DNS data aggregators, certificate transparency, WHOIS)"},
			{Name: "crt.sh", Desc: "Certificate Transparency log query — finds every host that has ever been issued a TLS cert for the apex"},
			{Name: "VirusTotal API", Desc: "Optional — pulls the domains/<d>/subdomains list when Settings has a VT key (fires at any speed)"},
			{Name: "Shodan / Censys", Desc: "Optional passive sources — add hostnames from internet-wide scans when keys are configured (fire at any speed)"},
			{Name: "recon-ng", Desc: "hackertarget and threatminer modules (Normal/Deep speed only); each recon-ng run is capped at 3 minutes"},
			{Name: "gobuster", Desc: "Opt-in `gobuster dns` brute-force run directly against each authoritative nameserver; honours a per-request --delay to evade rate limits"},
			{Name: "dig", Desc: "Used for optional AXFR zone-transfer attempts (`dig axfr @ns`) against each authoritative nameserver"},
		},
		Phases: []string{
			"Authoritative nameserver discovery — pull NS records for the apex. These are the canonical sources of truth for the zone",
			"Passive phase (parallel) — subfinder + amass + crt.sh always run; recon-ng joins in Normal/Deep; VT + Shodan + Censys join in any speed when their API keys are configured",
			"Active brute phase — puredns + massdns against 18 resolvers using the user's wordlist (per-speed SecLists default: bitquark-top100k for Fast, namelist for Normal, dns-Jhaddix for Deep)",
			"NS-specific brute (Normal/Deep only) — query each authoritative NS DIRECTLY via a Go resolver, using a focused wordlist built from the passive hits plus a small built-in list (bypasses caching middleboxes; catches names that exist only on the target's own resolvers)",
			"NS gobuster brute (opt-in, any speed) — when enabled, run `gobuster dns` directly against each authoritative NS using the full per-speed wordlist, with an optional --delay to go gentle",
			"Permutation generation (B8, Normal/Deep only) — for every passive+brute hit, derive altdns-style variants (label-staging, label-dev, dev-label, label2, label-v2, ...), capped at 20 000, then re-brute them via puredns against the same resolver set",
			"Resolution + wildcard detection — every survivor gets resolved to IPs; the resolver responses are cross-checked against a wildcard baseline (random.example.com) to mark wildcard responders",
			"AXFR zone transfer (opt-in) — attempt `dig axfr` against each authoritative NS; successful A/AAAA/CNAME records are merged into the subdomain list",
			"Reverse-DNS sweep (opt-in) — PTR-lookup every resolved IP (or a user-supplied CIDR/IP list) to surface additional hostnames",
			"Depth filter (opt-in) — after all sources run unrestricted, drop rows deeper than the user's max-depth so brute/passive caches still see everything but output stays scoped",
			"Output dedup — each hostname collapses to ONE row attributed to the source that discovered it FIRST (allSubs keeps first-source only); the Sources histogram counts unique first-sightings per source, not raw emitted lines",
		},
		Notes: []string{
			"Custom resolver list lives at data/resolvers.txt — bring your own corporate resolvers to discover internal-only names",
			"Wildcard DNS detection is essential — sites using *.example.com → some-cdn-host will otherwise produce hundreds of false positives",
			"Deep mode uses the largest wordlist (dns-Jhaddix) with a 20-minute puredns brute cap plus NS-brute and permutations, so a single domain can run 30-60+ minutes — only use it when you have time AND the target is in-scope. recon-ng runs on Normal and Deep and is itself capped at 3 minutes, so it is not what drives Deep's runtime",
			"VirusTotal API key is shared with the rate-limited free tier (500 lookups/day) — pace yourself across multiple domains",
			"crt.sh is frequently overloaded / rate-limited (502/503/timeout); the scanner issues one query per domain and retries up to 3x with incremental backoff, flagging the source as failed if every attempt comes back empty",
			"AXFR, reverse-DNS sweep, gobuster NS-brute, custom wordlist, and max-depth are all opt-in form toggles — the core passive + brute + permutation flow runs without them",
			"Resolve/PTR/brute concurrency are operator-tunable (resolve fan-out default 50, PTR default 16) to dial down DNS load on monitored or corporate resolvers",
		},
		References: []ReferenceRef{
			{Label: "Certificate Transparency (RFC 6962)", URL: "https://datatracker.ietf.org/doc/html/rfc6962"},
			{Label: "altdns (the permutation strategy)", URL: "https://github.com/infosec-au/altdns"},
			{Label: "OWASP Subdomain Enumeration", URL: "https://owasp.org/www-project-amass/"},
			{Label: "subfinder source list", URL: "https://github.com/projectdiscovery/subfinder/blob/main/v2/pkg/subscraping/sources/sources.go"},
		},
	},

	// ========================================================================
	// Nuclei
	// ========================================================================
	"nuclei": {
		Summary: "Runs ProjectDiscovery's Nuclei templates against URLs to find CVEs, default credentials, exposed admin panels, misconfigurations, and information disclosure. Streams results LIVE — findings appear in the UI as templates fire, so you can stop a long scan once you've seen what you need. Each finding includes raw request + response bytes (via -include-rr flag), curl-command for replay, mapped CVEs/CWEs, and references to upstream advisory pages.",
		Tools: []ToolRef{
			{Name: "nuclei", Desc: "ProjectDiscovery's template engine — must be installed and on $PATH"},
			{Name: "Nuclei template repo", Desc: "9000+ community templates auto-updated daily; -update-templates flag pulls latest"},
		},
		Phases: []string{
			"Reachability preflight (when enabled) — drops TLS-dead targets before nuclei runs so a host that resets TLS can't dominate the run with errors; skipped hosts become explicit 'unreachable' rows in the result",
			"Optional template update — runs `nuclei -update-templates -silent` BEFORE the scan to pull the latest templates (only on the first batch). Skip for repeat runs to save time",
			"Batch large URL sets — sets larger than the batch size (default 10) are split into chunks and run as one nuclei process per chunk; every chunk runs to completion so finished hosts get COMPLETE results and stream in as partials, and a per-chunk 45-minute safety cap skips just one stuck chunk without stopping the run",
			"Compose CLI invocation — -l urlfile -jsonl -silent -disable-update-check -no-color -stats -include-rr -timeout 5 -retries 1, plus user-selected -severity / -tags / -t|-id (templates), -rl / -c / -bulk-size throughput, -exclude-tags / -exclude-templates, -dast, -as, and HTTP-auth knobs (-H headers/cookies/User-Agent, -proxy, -fr, -sni)",
			"Emit the exact command line into the scan's 'Commands run' panel — matches the convention used by nmap modules so the user can reproduce in their own terminal",
			"Enforce a hard wall-clock cap — nuclei's own -timeout only bounds a single HTTP call, so a 90-minute default cap (overridable per scan) guards the whole run; if it fires the result is flagged INCOMPLETE with an operator-facing reason instead of a false 'done'",
			"Stream stdout JSONL — every line is one finding; the stderr pipe is drained concurrently to prevent the well-known Go-exec deadlock when nuclei emits verbose stderr",
			"Per-finding: parse the rawFinding struct, convert to our Finding shape, attach to the matching input URL via host/MatchedAt longest-prefix match",
			"Live UI update — the partial result is rewritten on a 2-second throttle while nuclei's -stats 'Requests: N/M' stderr line drives the progress bar, so the user sees activity without waiting for the full scan",
			"On exit, distinguish a clean finish from an INCOMPLETE run — a wall-clock-cap kill, an output-stream buffer overflow, an OS/OOM signal kill, or a non-zero nuclei exit each flag the result Truncated with nuclei's own stderr reason, so a killed or errored run is never reported as a clean 'done'",
		},
		Notes: []string{
			"Severity defaults to critical/high/medium — broaden via the form to include low/info for compliance scans (slower, noisier)",
			"Tags (cve, xss, rce, lfi, ssrf, panel, exposure) are MUCH faster than severity — a 'tags: cve,rce' scan completes in 10x less time than 'severity: critical,high'",
			"Specific template paths take precedence over severity/tags — perfect for re-running a single CVE check (`-t cves/2023/CVE-2023-...yaml`)",
			"Nuclei's -include-rr captures the raw exchange in each JSONL line — feeds directly into our raw_exchange UI partial",
			"On large target sets, nuclei's concurrency (-c, default 25) blows past most rate limits — drop to -c 5 for production targets you don't own",
			"Templates referencing extractors (cve-id, cwe-id, references) populate the Finding's CVEs / CWEs / References columns automatically",
		},
		References: []ReferenceRef{
			{Label: "Nuclei docs", URL: "https://docs.projectdiscovery.io/tools/nuclei"},
			{Label: "Template repository (9000+ templates)", URL: "https://github.com/projectdiscovery/nuclei-templates"},
			{Label: "Writing custom templates guide", URL: "https://docs.projectdiscovery.io/templates/introduction"},
			{Label: "Cloud-native security templates", URL: "https://github.com/projectdiscovery/nuclei-templates/tree/main/cloud"},
		},
	},

	// ========================================================================
	// Host Discovery
	// ========================================================================
	"hostdiscovery": {
		Summary: "Two-pass nmap host discovery designed to surface BOTH responsive hosts AND ICMP-filtered hosts (the ones firewalls hide). Pass 1 uses default discovery (ICMP echo + TCP-ACK 80/443 + ICMP timestamp). Pass 2 forces -Pn (skip host discovery) so hosts that filter ICMP but still serve ports are flagged. Comparing the two passes reveals the firewall posture: hosts in pass-2-only = ICMP-filtered, hosts in both = standard, hosts in neither = down or fully blocked.",
		Tools: []ToolRef{
			{Name: "nmap", Desc: "Industry-standard network mapper. Must be on $PATH. Recommended ≥7.9 for up-to-date default host-discovery probes and nmap-services port naming — the module runs no -O and no -sV of its own"},
		},
		Phases: []string{
			"Parse target input — accepts single IP, CIDR (10.0.0.0/24), range (10.0.0.1-50), or hostname",
			"Pass 1 (with discovery) — nmap with default -PE -PA80,443 host discovery + selected port set (Common/Custom/Range/Full)",
			"For each host in Pass 1: record host_up, ping_reachable, and open ports (state open or open|filtered)",
			"Pass 2 (-Pn) — skips host discovery and jumps straight to the port scan. For a single target it ALWAYS runs (to catch ICMP-filtered hosts even when ping already succeeded); for a CIDR/range it runs when Pass 1 found no reachable hosts or left any host marked down",
			"Mark host as icmp_filtered when the -Pn pass finds at least one open port (state open) on a host that ping did not reach — under -Pn every host is assumed up, so the open ports (not a bare -Pn reply) are what set the flag. Pentest-worthy because the firewall config is leaking information about target presence",
			"Firewall-reflection guard — when nmap reports more than 100 open ports for one host, flag it as a suspected stateful firewall (suspected_firewall + firewalled_count) and drop the spurious port list instead of trusting it",
			"Aggregate — per-host row with host_up, ping_reachable, icmp_filtered, open_count, list of open ports + their state",
		},
		Notes: []string{
			"-Pn is slower than default discovery on dead hosts — that's why we run it only for the no-response cases. A /24 with mostly-down hosts: Pass 1 = 30s, Pass 2 = 5 min",
			"Common = top 1000 ports (nmap's default), Range/Custom let you target known service ports, Full = 1-65535 (slow but exhaustive)",
			"CIDR /16 (65k hosts) is supported but takes hours — use only when authorized and time-permitting",
			"icmp_filtered is the #1 signal of 'serious target' — proper firewall config drops ICMP but allows specific TCP, which means there IS something worth protecting behind",
			"Output feeds portservice (deep scan with -sV + NSE) — discovery first, deep scan second is the classic recon flow",
			"Every pass runs -T4 with -n (no DNS resolution), --max-retries 2, and a scope-scaled --host-timeout (5m default, 10m Range/Custom, 30m Full) so one silent host with many filtered ports can't stall the whole sweep",
			"Targets are scanned concurrently — default 4 parallel nmap invocations — and any CIDR/range wider than 256 hosts is sliced into 256-IP chunks so progress and partial results land every few minutes instead of only when the goroutine finishes",
			"Firewall-reflection guard: a host reported with more than 100 open ports is badged 'suspected firewall, +N ports' and its port list is cleared. hostdiscovery runs no -sV, so re-run portservice against that host to confirm which ports are genuinely open",
		},
		References: []ReferenceRef{
			{Label: "Nmap reference guide (host discovery)", URL: "https://nmap.org/book/host-discovery.html"},
			{Label: "Firewall evasion techniques", URL: "https://nmap.org/book/firewall-subversion.html"},
		},
	},

	// ========================================================================
	// Port + Service Scanner (portservice)
	// ========================================================================
	"portservice": {
		Summary: "Multi-phase nmap scan: two-pass host discovery (ping + -Pn) → version detection (-sV) → curated NSE vuln scripts → follow-up script pass on newly-detected services → HTTP/TCP banner enrichment → Nuclei vulnerability scan against open HTTP/HTTPS services. Optional UDP scan (-sU) catches DNS/SNMP/NTP/NetBIOS that TCP misses. Optional 'Deep' script depth adds the intrusive/fuzzer/exploit NSE categories. Optional brute-force wordlists activate the brute/auth NSE categories. EXTERNAL and DOS categories are hard-excluded (OPSEC + crash risk). Per-scan concurrency slider (1-50 hosts in parallel; banner enrichment is fixed at 64 probes and Nuclei at 50).",
		Tools: []ToolRef{
			{Name: "nmap -sV", Desc: "Version detection probes — matches banners against nmap's 2500+ service signatures"},
			{Name: "nmap NSE", Desc: "Nmap Scripting Engine — 600+ scripts across 14 categories. scaNNer runs a vetted subset (see 'NSE Category Coverage' below)"},
			{Name: "nmap -sU (optional)", Desc: "UDP scan pass for DNS/SNMP/NTP/DHCP/NetBIOS services — off by default (RFC 1812 rate-limits make UDP scans dramatically slower)"},
			{Name: "nuclei", Desc: "Phase 4 vulnerability scan against every open HTTP/HTTPS service across all hosts — severities critical→info, tags cve/vulnerability/exposure/default-login/misconfig, concurrency 50. Findings are attached per host"},
		},
		Phases: []string{
			"Phase 1 — Discovery: two parallel nmap passes per host (with ping + -Pn). The -Pn pass surfaces ICMP-filtered hosts that the ping pass thought were down. Optional third UDP (-sU) pass when the user enables it",
			"Phase 1.5 — Union: merge results from ping/-Pn/UDP. UDP ports merge with proto='udp' marker so renderers can group by protocol",
			"Firewall heuristic — a host that returns more than 100 'open' ports in Phase 1 is flagged as a suspected firewall (reflective replies). Its Phase 2 is narrowed to the top-100 common ports within the user's range and runs -sV only; banner enrichment is skipped for that host",
			"Phase 2 — Version detection + curated NSE scripts: -sV --version-intensity 5 + service-specific NSE scripts (ssl-heartbleed for SSL/TLS, http-shellshock for HTTP, smb-vuln-ms17-010 for SMB, etc.). Default 'Safe' depth = curated list only; 'Deep' depth adds intrusive+fuzzer+exploit categories",
			"Phase 2 — Brute/auth: ONLY when user supplies both username AND password wordlists. Adds brute,auth categories + --script-args userdb=<tmp>,passdb=<tmp>,brute.firstonly=true. Stops at first valid cred per service",
			"Phase 3 — Follow-up: for services that Phase 2 newly identified (e.g. Phase 1 saw 8080/tcp but Phase 2 confirmed it's http), run any extra scripts that weren't run for that service yet",
			"Phase 3.5 — Banner enrichment: connect to every open port on non-firewalled hosts and capture Shodan-style data — a real HTTP GET / (status, headers, Server, title, body preview) for web ports and a raw TCP banner (SSH/FTP/SMTP/POP3/IMAP/Redis/Memcached/…) for the rest. Runs in-process (Go, no external tool), bounded to 64 concurrent probes, honouring killswitch source-IP + proxy. The HTTP probe sends a fixed scaNNer/1.0 User-Agent — Settings' custom UA/headers/cookies are NOT applied to this stage (they ARE applied to the Nuclei phase)",
			"Phase 4 — Nuclei: every open HTTP/HTTPS service across all hosts is fed to nuclei (severities critical→info; tags cve/vulnerability/exposure/default-login/misconfig; concurrency 50; honours Settings proxy + custom UA/headers). Findings are stitched back onto each host's result",
			"Per-port output capture: state (open / open|filtered), service name, product, version, extra info, tunnel (ssl/raw), full NSE script output verbatim",
			"HTTPS auto-detection — nmap-reported tunnel=ssl (e.g. 443 / 8443) drives an https:// scheme for the banner-enrichment probe and the Nuclei URL",
		},
		Notes: []string{
			"NSE Category Coverage — what runs by default vs. what's behind the 'Deep' toggle vs. what's NEVER enabled:",
			"  ✗ default / -sC (NOT run) — the nmap 'default' NSE category is deliberately NOT invoked (-A/-sC/-O were dropped for speed). Scripts like http-title, http-headers, ssh-hostkey, smb-os-discovery therefore do NOT fire; HTTP title/Server/headers and raw service banners are recovered instead by the in-process banner-enrichment phase (Phase 3.5)",
			"  ✓ version (always) — service version probing via -sV (intensity 5)",
			"  ✓ safe (always) — curated subset, no risk of crashing services",
			"  ✓ discovery (selective, always) — hand-picked: snmp-info, ldap-rootdse, dns-recursion, etc.",
			"  ✓ vuln (selective, always) — curated vuln-detection scripts: ssl-heartbleed, http-shellshock, smb-vuln-ms17-010, http-vuln-cve-*. Detect only, no exploitation",
			"  ✓ intrusive (Deep only) — may crash fragile services. Examples: mssql-query, memcached-info, oracle-sid-brute",
			"  ✓ fuzzer (Deep only) — malformed-packet probes for buffer-overflow / parser-confusion detection",
			"  ✓ exploit (Deep only) — actually attempts exploitation to confirm vulnerability. Pentest engagement scope required",
			"  ✓ brute (only with wordlists) — ftp-brute, ssh-brute, http-brute, smb-brute, mysql-brute, etc. Empty wordlist = silent skip",
			"  ✓ auth (only with wordlists) — paired with brute; default-credential checks etc.",
			"  ✗ external (NEVER) — sends recon data to 3rd-party APIs (Shodan/Censys) — OPSEC leak. Hard-excluded",
			"  ✗ dos (NEVER) — denial-of-service scripts. Will crash target services. Hard-excluded",
			"  ✗ malware (skip) — checks for known backdoor signatures; niche use case, not enabled in either preset",
			"  ✗ broadcast (skip) — local-network broadcast probes; would spam in multi-host scans",
			"Brute/auth lockout note — 'brute.firstonly=true' is set so brute stops at the first valid cred per service (nmap is also passed unpwdb.timelimit=5m). Still: against tightly-configured AD, three wrong attempts can lock out the account. Use service-account creds, not user creds",
			"Concurrency slider (1-50, default 10) controls hosts-in-parallel for the nmap phases only. Each host = 2-3 nmap subprocesses depending on UDP toggle. Banner enrichment (64 probes) and Nuclei (50) have their own fixed concurrency. Above 25 needs `ulimit -n 65535` and dedicated VPS",
			"Service version detection occasionally returns wrong versions for heavily-customised services (nginx behind WAF, modified Apache modules) — verify before mapping to CVEs",
			"Output is large — a /24 with -sV + Deep + brute can produce 50-200 MB of nmap + banner + Nuclei data. The whole per-scan result blob is soft-capped at 50 MB (operator-overridable via the max_result_mb setting; 0 = unlimited); an over-cap result is not written and the user gets a truncation banner. NSE script output itself is stored verbatim, not per-port truncated",
		},
		References: []ReferenceRef{
			{Label: "Nmap NSE category reference", URL: "https://nmap.org/book/nse-usage.html#nse-categories"},
			{Label: "Vulnerability scripts list", URL: "https://nmap.org/nsedoc/categories/vuln.html"},
			{Label: "Service detection internals", URL: "https://nmap.org/book/vscan.html"},
			{Label: "Brute scripts + --script-args", URL: "https://nmap.org/nsedoc/lib/brute.html"},
			{Label: "Nuclei templates", URL: "https://github.com/projectdiscovery/nuclei-templates"},
		},
	},

	// ========================================================================
	// SMB Enum
	// ========================================================================
	"smbenum": {
		Summary: "SMB enumeration triple-stack — nmap's smb-* NSE scripts (shares, OS, MS17-010, signing), smbclient anonymous listing (or authenticated), and enum4linux for user/group/RID/password-policy extraction. Optional 'share content walk' phase lists the top-level contents of every readable share, filtered for interesting filenames (.env, .ssh, .bak, .sql, .kdbx, config, *backup*). Catches the classic Windows pentest wins: anonymous share access, MS17-010 unpatched hosts, default credentials, exposed user lists for password spraying.",
		Tools: []ToolRef{
			{Name: "nmap (smb-* NSE)", Desc: "Runs smb-os-discovery, smb-enum-shares, smb-enum-users, smb-enum-sessions, smb-enum-domains, smb-protocols, smb-security-mode, smb-vuln-ms17-010, smb2-security-mode"},
			{Name: "smbclient", Desc: "Anonymous / authenticated share listing (-L -g); content walk via -c \"ls\" (root directory only, 200-entry cap)"},
			{Name: "enum4linux", Desc: "Veteran tool (Perl) — users, groups, RIDs, password policy, share permissions"},
		},
		Phases: []string{
			"TCP/445 reachability — nmap -p 445 -Pn. If closed, the host is skipped entirely (no point in NSE/smbclient)",
			"nmap smb-* NSE bundle — runs the entire SMB script set in one invocation, captures structured per-script output",
			"smbclient -L (or -L -U user%pass) — anonymous or authenticated share listing, parsed from -g grep-friendly output and merged with the nmap pass without duplicates",
			"Share content walk (optional, off by default) — for each readable share except IPC$/ADMIN$/print$: `smbclient //h/s -c \"ls\" -N` lists the top-level (root) directory only, capped at 200 entries",
			"Interesting-file filter on the walk output — patterns: password, .env, config, .ssh, id_rsa, .pem, .key, .bak, .sql, .kdbx, keepass, unattend.xml, groups.xml",
			"enum4linux -a — full enumeration including pwInfo (password policy), RID cycling, group/user lists",
		},
		Notes: []string{
			"Anonymous null-session is the default — provides only public info but no credentials needed. Authenticated mode unlocks user lists and full share content",
			"MS17-010 (EternalBlue) detection is the killer NSE script — patches dated >2017 should have closed it, but unpatched 2016-vintage Windows boxes are still surprisingly common in enterprise networks",
			"Share-walk can produce thousands of file paths on chatty file servers — the interesting-file filter cuts ~99% of noise",
			"enum4linux only works on Samba/Windows SMB1; on SMB2/SMB3-only hosts it produces partial output. Use rpcclient + nmap fallback when enum4linux blanks out",
			"Authentication caveat: failed-login lockouts apply — three wrong attempts can trigger account lockout on tightly-configured AD. Use known-good service-account creds, NOT user creds",
			"Credentials never leak to the UI — enum4linux's `-p <password>` and smbclient's `-U user%pass` values are redacted to *** in the commands panel and progress feed, while the plaintext still reaches the subprocess itself",
			"enum4linux exits 0 even when every null-session sub-query is denied — the module scans its raw output for access-denied / logon-failure markers and surfaces them, so a blocked anonymous session isn't reported as an empty host",
		},
		References: []ReferenceRef{
			{Label: "MS17-010 EternalBlue details", URL: "https://docs.microsoft.com/en-us/security-updates/SecurityBulletins/2017/ms17-010"},
			{Label: "enum4linux source", URL: "https://github.com/CiscoCXSecurity/enum4linux"},
			{Label: "nmap NSE smb-enum-shares script", URL: "https://nmap.org/nsedoc/scripts/smb-enum-shares.html"},
		},
	},

	// ========================================================================
	// Service Brute Forcer
	// ========================================================================
	"brutef": {
		Summary: "Hydra-powered credential brute-force across ten common services (SSH, FTP, RDP, SMB, MSSQL, MySQL, PostgreSQL, VNC, LDAP, Telnet). Streams successful logins as they're discovered (live UI updates), includes a built-in default-credentials list per service (admin:admin, root:toor, sa/postgres/mysql, vendor-specific pairs), and supports single-username mode (hydra -l: one user tried against the full password list). Stop-on-first-hit is on by default so a scan terminates the moment a credential lands.",
		Tools: []ToolRef{
			{Name: "hydra", Desc: "THC Hydra — the classic login-cracker. Must be on $PATH"},
			{Name: "Built-in default-cred lists (B12)", Desc: "Per-service vendor defaults for all ten protocols: SSH (17 pairs), FTP (9), RDP (8), SMB (8), MSSQL (7), MySQL (7), PostgreSQL (5), VNC (5), LDAP (3), Telnet (8). Auto-prepended when 'Include defaults' is on"},
		},
		Phases: []string{
			"Optional: prepend default-credential pairs to the wordlists when 'Include defaults' toggle is on",
			"Materialize username + password lists into hydra-format temp files",
			"Spawn hydra per (target, protocol) tuple with concurrency capped via workspace settings",
			"Parse hydra's stdout line-by-line — extract [port][service] login: pass format for hits",
			"Track attempt counter via hydra's -V verbose output — gives the user live 'X of Y attempted' progress",
			"Stream successful login findings to the UI immediately (don't wait for hydra to finish)",
			"On finish, write the full result with all discovered credentials",
		},
		Notes: []string{
			"ALWAYS confirm authorization in writing before brute-forcing live systems. Account lockouts can trigger DoS-class outages on production AD",
			"Stop-on-first-hit (-f) is on by default — usually you want to stop and pivot once you have credentials. Disable when running compliance audits that need every weak account flagged",
			"Single Username mode runs hydra -l against one account with the full password list — useful when you already know the username. Note this hammers a single account and will trip lockout policies fast; the module has no built-in per-account rate-limiting, and Threads (hydra -t) defaults to 16 parallel logins, so lower it against lockout-protected targets",
			"Hydra's RDP module is fragile against modern Windows (NLA enabled) — for hardened targets use Crackmapexec or NetExec's rdp scanner instead",
			"Default-cred mode is the FIRST thing to try — every router/IoT/legacy device has a documented default that admins forget to change. Vendors with known defaults: D-Link, TP-Link, Cisco, Huawei, Hikvision",
			"Targets and single-username values are validated before they reach hydra's argv — shared.SafeTarget rejects shell metacharacters and leading-dash values, and a '--' option terminator stops a target from being reparsed as a hydra flag (argument-injection hardening)",
		},
		References: []ReferenceRef{
			{Label: "THC Hydra GitHub", URL: "https://github.com/vanhauser-thc/thc-hydra"},
			{Label: "Default Credentials cheatsheet (CIRT)", URL: "https://cirt.net/passwords"},
			{Label: "NIST 800-63B — credential management", URL: "https://pages.nist.gov/800-63-3/sp800-63b.html"},
		},
	},

	// ========================================================================
	// SNMP Enum
	// ========================================================================
	"snmpenum": {
		Summary: "Community-string brute (v1/v2c) or USM-based v3 enumeration of an SNMP agent. v2c phase tries 14 default communities (public, private, manager, admin, router, etc.) via onesixtyone (fast UDP burst) with snmpget fallback. v3 mode skips brute entirely — connects with -v3 -u USER -l LEVEL -a SHA -x AES for User-based Security Model authentication, with auth/priv passphrases loaded from a per-scan snmp.conf via SNMPCONFPATH (kept out of argv/procfs; -A/-X are only a fallback). Each valid v1/v2c community is then probed for read/write (RW) access via an snmpset round-trip on sysContact. Once a valid auth is found, walks system identity OIDs (descr, uptime, contact, name, location) plus user-selected branches (interfaces, processes, software, users, tcp, udp, installed-services, arp, routes, ipaddrs, shares, win32-services, cdp).",
		Tools: []ToolRef{
			{Name: "onesixtyone", Desc: "High-speed UDP community brute (preferred, falls back to snmpget per-string if absent)"},
			{Name: "snmpget / snmpwalk", Desc: "Net-SNMP CLI tools. Must be on $PATH. snmpget pulls the system-identity OIDs in one multi-OID call; snmpwalk streams each selected branch table (32 KB read cap). v3 USM is invoked via -v3 -u/-l/-a/-x flags with auth/priv passphrases loaded from a per-scan snmp.conf (SNMPCONFPATH), not argv"},
			{Name: "snmpset", Desc: "Net-SNMP write tool. Probes each valid v1/v2c community for RW access by round-tripping a random marker through sysContact.0 (1.3.6.1.2.1.1.4.0) and restoring the original value. If absent, RW detection is skipped (result just lacks the RW annotation)"},
		},
		Phases: []string{
			"Decide auth mode — V3User set → v3 USM (skip community brute); ForcedCommunity set → use as-is; SkipBrute set → single 'public' probe; otherwise → brute the community list",
			"v2c brute — onesixtyone batched UDP probe against the target with the candidate community list; if onesixtyone is absent or errors, falls back to parallel per-community snmpget probes (8-wide worker pool)",
			"Pull system identity OIDs always — 1.3.6.1.2.1.1.1.0 (sysDescr), 1.3.6.1.2.1.1.3.0 (sysUpTime), 1.3.6.1.2.1.1.4.0 (sysContact), 1.3.6.1.2.1.1.5.0 (sysName), 1.3.6.1.2.1.1.6.0 (sysLocation)",
			"Probe RW access (v1/v2c only) — for each valid community, snmpset writes a random marker into sysContact.0 (1.3.6.1.2.1.1.4.0), reads it back, and restores the original; a confirmed round-trip flags the community as read/write",
			"Walk selected branches — interfaces (1.3.6.1.2.1.2.2), processes (1.3.6.1.2.1.25.4.2), software (1.3.6.1.2.1.25.6.3.1.2), users (1.3.6.1.4.1.77.1.2.25), tcp (1.3.6.1.2.1.6.13), udp (1.3.6.1.2.1.7.5), installed-services (1.3.6.1.2.1.25.6.3), plus lateral-movement branches arp (1.3.6.1.2.1.4.22.1.2), routes (1.3.6.1.2.1.4.21.1), ipaddrs (1.3.6.1.2.1.4.20), shares (1.3.6.1.4.1.77.1.2.27), win32-services (1.3.6.1.4.1.77.1.2.3.1.1), cdp (1.3.6.1.4.1.9.9.23.1.2.1.1.6)",
			"Truncate each walk to 24 KB to keep DB rows manageable on chatty agents (large process tables can hit megabytes)",
		},
		Notes: []string{
			"Default communities 'public' and 'private' are STILL surprisingly common in 2026 — every embedded device, every printer, every legacy switch",
			"Windows hosts running SNMP often expose the full process list via 1.3.6.1.2.1.25.4.2 — a goldmine for lateral-movement targeting",
			"v3 noAuthNoPriv mode is essentially v2c with extra steps — flag it as a finding even when the rest of the policy is solid",
			"snmpwalk against a populated table can DoS slow management agents — use SkipBrute mode (single 'public' probe) for sensitive targets",
			"User-account enumeration via 1.3.6.1.4.1.77.1.2.25 is a Windows-specific OID — Linux/BSD SNMP daemons return empty here",
			"A community that grants RW (write) access is a near-instant escalation path — running-config write, OS image upload, route-table rewrite — and is surfaced separately from read-only communities",
			"If snmpget/snmpwalk/snmpset aren't on $PATH the scan emits an amber warning instead of silently returning empty — a locked-down host and a missing binary no longer look identical",
		},
		References: []ReferenceRef{
			{Label: "RFC 3414 — SNMPv3 USM", URL: "https://datatracker.ietf.org/doc/html/rfc3414"},
			{Label: "Default SNMP community wordlist", URL: "https://wiki.skullsecurity.org/index.php/Passwords"},
			{Label: "Net-SNMP project", URL: "http://www.net-snmp.org/"},
		},
	},

	// ========================================================================
	// WHOIS / ASN Lookup
	// ========================================================================
	"whoisinfo": {
		Summary: "Multi-source WHOIS + ASN intelligence. For domains: resolves the host to IPs, then runs whois on the domain against the registrar/registry database, extracting registrant org, registrar, name servers, and creation/expiration dates. For a directly-given IP: runs whois on the address itself. In either case it then queries Team Cymru — on the IP given directly, or the first address resolved from the domain — for AS number, AS owner, country, and registry (ARIN/RIPE/APNIC/AfriNIC/LACNIC). When prefix expansion is enabled, it pulls the AS's advertised v4 prefixes from RADB — the asset-discovery foundation: once you have the ASN, you have the IP blocks owned by that org.",
		Tools: []ToolRef{
			{Name: "whois", Desc: "Classic UNIX whois client. Must be on $PATH"},
			{Name: "Team Cymru WHOIS (whois.cymru.com)", Desc: "IP -> ASN / AS owner / country / registry mapping, queried through the whois client with ' -v <ip>'"},
			{Name: "RADB WHOIS (whois.radb.net)", Desc: "AS -> advertised IPv4 'route:' prefix list, queried only when prefix expansion (IncludePrefix) is enabled"},
		},
		Phases: []string{
			"Classify input — net.ParseIP decides IP vs domain; strip any scheme/path and host:port wrapper first, and reject targets with flag-like or shell-unsafe characters",
			"Domain path — resolve the host through the killswitch-bound resolver (5s timeout, keeps both v4 and v6), then run whois on the domain",
			"WHOIS query — run the system whois with '--' flag-stop and a 20s per-call timeout; keep the raw output (capped at 4 KiB in results) and parse it into a deduped list of whitelisted key:value fields (registrar, name servers, dates, netname, org, CIDR, etc.)",
			"ASN lookup — query Team Cymru (whois.cymru.com, ' -v <ip>') for a probe IP (prefer v4, fall back to v6) to get AS number, org, country, and registry",
			"Optional prefix expansion — when IncludePrefix is set, query RADB (whois.radb.net, '-i origin AS<n>') for the AS's advertised v4 'route:' prefixes",
			"Structured output — per target: WHOIS records (whitelisted key:value), a truncated raw WHOIS blob, resolved IPs, and ASN info (with prefixes when expanded); targets run concurrently (default 4 workers)",
		},
		Notes: []string{
			"Registrar privacy redaction (Whois Privacy Service, Domains By Proxy, etc.) blanks the registrant fields — that's expected. Pivot via certificate transparency (dnsenum) instead",
			"GDPR-related redactions hide EU domain registrants since 2018 — only the registrar is publicly visible. Same workaround applies",
			"ASN-driven asset discovery is the 'big map' for engagement planning — feed the prefixes back into dnsenum / hostdiscovery for the full surface",
			"WHOIS query rate limits are strict (1 query/3s typical) — bulk lookups can burst-fail. The scanner runs up to 4 lookups concurrently with a 20s per-call timeout and does no retry/back-off, so heavy runs may hit server-side throttling",
			"Some country TLDs (.fr, .ar) use non-standard WHOIS formats the whitelist parser won't recognize — but the raw WHOIS blob is always retained (capped at 4 KiB in results), so those registries stay readable there even when structured parsing extracts nothing",
			"AS prefix expansion is off by default and covers only IPv4 (RADB 'route:' objects) — enable IncludePrefix to populate the prefix list; it costs one extra whois call per target",
			"Domain DNS resolution goes through the killswitch-bound dialer so lookups honor the scanner's source-IP binding, with a 5s timeout so one slow resolver can't park a worker; each whois subprocess is also capped at 2 MiB of output",
		},
		References: []ReferenceRef{
			{Label: "RFC 3912 — WHOIS protocol", URL: "https://datatracker.ietf.org/doc/html/rfc3912"},
			{Label: "RFC 7480 — RDAP (modern replacement)", URL: "https://datatracker.ietf.org/doc/html/rfc7480"},
			{Label: "Hurricane Electric BGP toolkit", URL: "https://bgp.he.net/"},
			{Label: "Team Cymru IP-to-ASN mapping", URL: "https://team-cymru.com/community-services/ip-asn-mapping/"},
			{Label: "RADB — Routing Assets Database", URL: "https://www.radb.net/"},
		},
	},

	// ========================================================================
	// Email Harvester
	// ========================================================================
	"emailharvest": {
		Summary: "Wraps the theHarvester CLI to collect emails, hostnames, and IPs for one or more target domains from public OSINT sources (crtsh, hackertarget, rapiddns, urlscan, duckduckgo, otx, certspotter, and more — no API keys required). Optional enrichment resolves email-authentication DNS records (MX/SPF/DMARC/DKIM) and queries Have I Been Pwned's domain breach list. Feeds phishing-simulation planning and password-spray targeting (authtest module).",
		Tools: []ToolRef{
			{Name: "theHarvester", Desc: "The wrapped OSINT CLI — driven with -d <domain> -b <sources> -l <limit> -f <json>; emits structured JSON of emails, hosts, and IPs. Preflighted on PATH (probes both theHarvester and theharvester) with a 5-minute per-domain timeout."},
			{Name: "Have I Been Pwned API (optional)", Desc: "Domain-level breach lookup via /api/v3/breaches?domain=<domain>, issued once per domain — lists breaches involving the domain. No key required; an optional hibp-api-key header is sent when configured, but the endpoint does not change."},
			{Name: "DNS resolver (optional)", Desc: "Killswitch-bound Go resolver enrichment — resolves MX, analyzes SPF/DMARC policy strength, probes common DKIM selectors in parallel, and guesses the mail provider from MX hostnames."},
		},
		Phases: []string{
			"For each target domain (default concurrency 2), preflight the theHarvester binary on PATH — a missing tool becomes a named hard error, not a silent empty result",
			"Run theHarvester with the selected sources (default: crtsh, hackertarget, duckduckgo, otx, rapiddns), capped at the result limit (default 200), writing structured JSON to a temp file",
			"Parse emails, hosts, and IPs from the JSON output; if a field is empty, fall back to regex extraction over the tool's stdout (domain-scoped for emails/hosts), then dedupe",
			"Classify the run — a rejected/unsupported source or a non-zero exit with zero parsed results becomes a fatal per-domain error; a non-zero exit that still yielded data becomes a non-fatal amber warning",
			"Optional DNS-auth enrichment — resolve MX and analyze SPF/DMARC policy strength, probe common DKIM selectors in parallel, and best-effort guess the mail provider from MX hostnames",
			"Optional HIBP enrichment — query the domain breach list once per domain (429 is surfaced as rate-limited, 404 as no breaches)",
			"Aggregate per-domain results and emit throttled partial snapshots (every ~2s) as each domain completes",
		},
		Notes: []string{
			"theHarvester has NO API-key sources wired here — the default set (crtsh, hackertarget, duckduckgo, otx, rapiddns) works key-free; older sources like anubis/threatminer/bing/sitedossier were removed upstream and will be rejected as unsupported",
			"The HIBP breach check is domain-level (/breaches?domain=), issued once per domain and needs no API key; an optional key is sent but does NOT switch to per-account lookups (the free-tier 1-request/6s limit would stall multi-email scans)",
			"Each theHarvester run is capped at 5 minutes so a dead source API cannot pin a goroutine; a missing binary or an all-sources-rejected run surfaces as a red per-domain error, while a non-zero exit that still parsed data is downgraded to an amber warning",
			"Public emails on a corporate domain → use the password spray module sparingly (lockout policies will trigger)",
			"GDPR/data-protection compliance — emails returned MAY be personal data depending on jurisdiction. Treat as sensitive even though discovered via public sources",
			"Combine with the leakscan module — emails harvested here can be cross-referenced against secrets leakage on GitHub/Pastebin",
		},
		References: []ReferenceRef{
			{Label: "Have I Been Pwned API docs", URL: "https://haveibeenpwned.com/API/v3"},
			{Label: "theHarvester — the wrapped CLI", URL: "https://github.com/laramies/theHarvester"},
			{Label: "RFC 7208 — Sender Policy Framework (SPF)", URL: "https://datatracker.ietf.org/doc/html/rfc7208"},
			{Label: "RFC 7489 — DMARC", URL: "https://datatracker.ietf.org/doc/html/rfc7489"},
			{Label: "RFC 6376 — DomainKeys Identified Mail (DKIM)", URL: "https://datatracker.ietf.org/doc/html/rfc6376"},
		},
	},

	// ========================================================================
	// GitHub Leak Scanner
	// ========================================================================
	"leakscan": {
		Summary: "Searches GitHub Code Search + Pastebin (psbdmp.ws) + Wayback Machine for query strings, then runs each retrieved file through 15 secret-pattern regexes (AWS keys, GitHub tokens, GitLab PAT, Slack tokens, Stripe live keys, Google API keys, private keys, JWT, generic password assignments). Every hit is a high-severity finding — leaked secrets are typically game-over for the account/service involved.",
		Tools: []ToolRef{
			{Name: "GitHub Code Search API", Desc: "Authenticated when token provided (4x rate limit); unauth fallback hits 422 on broad queries"},
			{Name: "psbdmp.ws API (B13)", Desc: "Pastebin public-search proxy — adds historical paste content"},
			{Name: "Wayback CDX API (B13)", Desc: "Internet Archive's URL index — finds historic copies of pages that once leaked secrets"},
			{Name: "Built-in regex DB", Desc: "15 high-signal patterns; precision-tuned to reduce false positives"},
		},
		Phases: []string{
			"For each user-supplied query, hit GitHub /search/code?q=<query> with API token if available",
			"Parse up to MaxFiles results (default 30), construct raw.githubusercontent.com URLs from the html_url",
			"When the B13 widening toggles are on (IncludePastebin / IncludeWayback), ALSO query the Pastebin scrape API (psbdmp.ws) + Wayback CDX for the same query and append their hits to the query's result set — this runs before the download step, so those hits get fetched and scanned too",
			"Optionally download each file (FetchSnippets toggle) — up to 256 KB body per file, fetched concurrently with up to 5 requests in flight",
			"Run secretPatterns regex set against each downloaded body — extract matches with ±40-char context for the Sample field",
			"Per-query result: query string + hit list + match count, ready for the export's 'Leak Hits' section",
		},
		Notes: []string{
			"GitHub Code Search REQUIRES authentication for unscoped queries (422 otherwise) — drop in a personal access token via Settings for production use",
			"Common queries: organization name, internal hostname, product code, customer ID. Avoid queries that match too broadly (e.g. 'AKIA' alone returns 100k+ results that aren't yours)",
			"Every secret hit IS the finding — there is no severity gradation. Treat all as CRITICAL until you've manually checked the file age and validity",
			"Pastebin paste IDs are unguessable, but psbdmp.ws indexes public listings — newer pastes (last 30 days) skew the results",
			"Wayback Machine CDX is the slowest source — many CDX queries time out on broad terms. Use specific subdomain queries (e.g. 'admin.example.com') for best signal",
			"On a 403 with X-RateLimit-Remaining:0 the scan sleeps until X-RateLimit-Reset (capped at 90s); a 429/403 with Retry-After sleeps that long (capped at 60s) so later queries in the same scan don't all fail",
			"All outbound HTTP (GitHub, Pastebin, Wayback, and raw-file fetches) dials through shared.BoundDialer, so queries honor the global Killswitch source-IP binding instead of leaking over the host's default route",
		},
		References: []ReferenceRef{
			{Label: "GitHub Code Search API", URL: "https://docs.github.com/en/rest/search/search#search-code"},
			{Label: "TruffleHog / GitLeaks (similar tools)", URL: "https://github.com/trufflesecurity/trufflehog"},
			{Label: "GitGuardian secret detection benchmarks", URL: "https://www.gitguardian.com/"},
		},
	},

	// ========================================================================
	// JWT Analyzer
	// ========================================================================
	"jwt": {
		Summary: "Analyses JSON Web Tokens for cryptographic and configuration weaknesses, then generates forged attack tokens the user can paste back at the target to confirm exploitation — and, when a target URL is supplied, actively replays each forged token at the verifier to flag which the server accepts. Detects: alg=none acceptance, weak HMAC secret (cracks HS256/HS384/HS512 via dictionary + optional streamed wordlist file), kid header injection, jku/x5u/x5c header poisoning, RS256→HS256 confusion attacks, missing/expired exp claims, overly-long lifetimes, missing iss claim, alg smuggled into the payload, and sensitive fields embedded in the payload. Attack-token generation plus optional live replay is the difference vs other JWT tools — you get ready-to-paste payloads and immediate accept/reject signal, not just findings.",
		Tools: []ToolRef{
			{Name: "Go crypto/hmac + crypto/sha256+sha512", Desc: "HMAC-SHA256/384/512 secret cracking — multi-core dictionary attack over the in-memory list plus an optional streamed wordlist file"},
			{Name: "Built-in secret list", Desc: "~30 common HMAC secrets bundled (secret, password, your-256-bit-secret, changeme, qwerty, etc.); supply a rockyou-class wordlist file to go bigger"},
			{Name: "Go net/http (replay engine)", Desc: "Optional active replay — fires the original + each forged token at the target verifier, honours workspace proxy/UA and Killswitch source-IP binding, records status + body length"},
		},
		Phases: []string{
			"Parse the token — split into 2–3 dot-separated segments; base64url-decode the header and payload and JSON-parse both into maps; pull the alg value out of the header. The signature segment is kept for the HMAC crack step; malformed input or a bad segment count aborts that token with an Error.",
			"Algorithm audit (auditAlgorithm) — classify the header alg: none → CRITICAL (verifier may honor it); missing alg → MEDIUM; HS256/HS384/HS512 → INFO (symmetric, crackable, algorithm-confusion hint); RS/ES/PS* → INFO (algorithm-confusion candidate). Flags only — no forging happens here.",
			"Claim audit (auditPayload) — exp missing → MEDIUM (replayable indefinitely), exp in the past → MEDIUM (expired), exp >90 days out → LOW (long-lived); iss missing → LOW; alg present in the payload → MEDIUM; sensitive fields in the payload (password/secret/api_key/private_key) → HIGH.",
			"Header-attack audit (auditHeaderAttacks) — kid present → INFO, or HIGH when the kid value contains / \\ or .. (path-traversal / SQLi surface); jku header → HIGH; x5u header → HIGH; x5c header → MEDIUM.",
			"HMAC secret crack (crackHmac) — only for HS256/HS384/HS512 three-part tokens when a wordlist or wordlist file is supplied. Fan candidates across runtime.NumCPU() workers (min 2), testing the in-memory list (custom + optional built-ins) first, then optionally streaming a rockyou-class wordlist file line-by-line; stop on first match, progress every 50k attempts. A hit prepends a CRITICAL 'HMAC secret cracked' finding.",
			"Attack token generation (buildAttackTokens, when enabled) — always emits alg=none, alg=None case-variant, and empty-signature tokens; adds an RS→HS256 confusion stub for asymmetric tokens, three kid probes (kid→/dev/null signed with an empty key, kid SQLi UNION SELECT 'secret', empty-kid default-key) when a kid is present, a jku-poisoning template (attacker JWKS URL) when jku is present or the alg is asymmetric, and — when the secret was cracked — a fully-valid re-signed token (plus an HS256 downgrade variant for HS384/512).",
			"Active replay (optional, replayTokenSet) — when a target URL is set, GET the target with the original token as a baseline, then each forged attack token, inserting it into the Authorization header (Bearer prefix by default, unless header=Cookie), following no redirects and skipping TLS verification; record each response's status + body length and flag which forgeries the server accepts.",
			"Output — per-token TokenResult: decoded header/payload JSON, severity-labeled Findings, the cracked secret + attempt count, and the paste-ready AttackTokens list (with replay status/body length when replay ran).",
		},
		Notes: []string{
			"alg=none is the CRITICAL bug — surprisingly common in homegrown JWT libraries. Test the forged token against the server; if accepted, full auth bypass",
			"HMAC cracking runs in-process across all CPU cores and can stream a rockyou-class wordlist file directly (line-by-line, no memory blow-up) — no need to export first; for GPU-speed cracking, hashcat -m 16500 against the token remains an option",
			"kid injection works when the server uses the kid value as a file path or DB key without sanitization — generates 'kid: ../../etc/passwd' style payloads",
			"RS256→HS256 confusion exploits servers that accept algorithm parameter from the token header instead of enforcing server-side: attacker signs with the public key as if it were an HMAC secret",
			"jku/x5u/x5c header attacks are dangerous when present — server fetches a remote JWKS URL the attacker controls. Test with a controlled OOB collaborator URL (A9 module)",
			"Supply a target URL to have the module fire every forged token at the verifier itself and mark which are accepted — no copying each into curl by hand. Replay honours the workspace proxy/UA and Killswitch source-IP binding, follows no redirects, and ignores TLS cert errors.",
		},
		References: []ReferenceRef{
			{Label: "RFC 7519 — JWT spec", URL: "https://datatracker.ietf.org/doc/html/rfc7519"},
			{Label: "OWASP JWT Cheat Sheet", URL: "https://cheatsheetseries.owasp.org/cheatsheets/JSON_Web_Token_for_Java_Cheat_Sheet.html"},
			{Label: "JWT.IO debugger / library list", URL: "https://jwt.io/"},
			{Label: "Critical vulnerabilities in JSON Web Token (Auth0 research)", URL: "https://auth0.com/blog/critical-vulnerabilities-in-json-web-token-libraries/"},
		},
	},

	// ========================================================================
	// Parameter Discovery
	// ========================================================================
	"paramdisc": {
		Summary: "Arjun-style discovery of hidden query parameters and form fields. Sends a curated ~600-name default wordlist (or a user-supplied list) one parameter at a time per URL over GET, POST, or both, and flags names that change the response: status-code deltas, body-length deltas beyond a per-target noise threshold, and reflection (parameter value echoed in the response body). Detects parameters that influence server behaviour but aren't documented — these are pure XSS / SSRF / open-redirect / SQLi attack surface that other crawlers miss because they only walk visible HTML.",
		Tools: []ToolRef{
			{Name: "Go net/http", Desc: "High-concurrency probe loop, one request per candidate parameter (default 30 workers via a semaphore)"},
			{Name: "Built-in param wordlist", Desc: "Curated ~600-name list inspired by Arjun / ParamSpider, deduped before probing; user-supplied lists override"},
		},
		Phases: []string{
			"Baseline probe — request the URL with NO extra param and record its status code and body size as the calibration baseline",
			"Noise calibration — send 4 probes with random parameter names/values, take the largest body-size delta, apply a 1.5x margin and a 32-byte floor; if every noise probe fails widen to a 128-byte fallback and disable status-diff, and trust status-diff only when all noise probes returned the same status as baseline",
			"Parameter probing — send each wordlist name as a single GET query param or POST form field with a random value, concurrently (default 30 workers), one request per parameter — no batching or bisection",
			"Length-delta check — a probe whose body size differs from baseline by more than the calibrated noise threshold + 8 bytes is flagged as interesting",
			"Reflection check — does the test value appear in the response body? Reflected param = XSS/HTML-injection candidate",
			"Status-code-change check — 200→302, 200→500, 200→403 transitions are high-signal (param triggered server-side logic)",
			"Per-finding output — URL, parameter name, method, status delta, length delta, reflected y/n, note, plus a redacted raw request/response that is re-issued and captured only for confirmed hits",
		},
		Notes: []string{
			"Pure Go — despite the Arjun-style name it ships no external binary and drives only the built-in net/http probe loop; nothing to install",
			"Reflection detection is XSS pre-work — any reflected param is the next thing to fuzz with payloads (manually or with sqlmap/dalfox)",
			"Status-code transitions to 5xx may indicate the param triggered an unhandled exception — query the server logs (if you have access) for the stack trace",
			"Length deltas are judged against a per-target noise threshold — the scanner sends 4 random-name probes, takes the biggest body-size swing, applies a 1.5x margin and a 32-byte floor, then only flags probes exceeding that + 8 bytes. Reflection and status-delta are the other trustworthy signals",
			"Concurrency defaults to 30 workers per target (configurable); on rate-limited targets drop it to 5-10 concurrent for slow-burn discovery",
			"Raw request/response are captured only for confirmed hits (the hot loop skips the dumps), truncated to 4 KB / 16 KB, and secret headers (Authorization, Cookie, X-Api-Key) are redacted before results are stored",
		},
		References: []ReferenceRef{
			{Label: "Arjun (the project this borrows from)", URL: "https://github.com/s0md3v/Arjun"},
			{Label: "PortSwigger param miner extension", URL: "https://portswigger.net/bappstore/17d2949a985c4b7ca092728dba871943"},
			{Label: "OWASP API Security Top 10 — Mass Assignment", URL: "https://owasp.org/API-Security/editions/2023/en/0xa6-unrestricted-access-to-sensitive-business-flows/"},
		},
	},

	// ========================================================================
	// Concurrency Tester
	// ========================================================================
	"concurtest": {
		Summary: "Probes a target's concurrency tolerance to find the practical request-rate ceiling before timeouts, throttling, or rate-limit responses kick in. Per target it takes a 5-request median baseline, then runs three scenarios: a ramp test that steps concurrency through a geometric ladder (1, 2, 5, 10, 25, 50, 100, 200 … up to MaxConcurrency, default 200), firing ReqsPerLevel requests per level (default 30) and flagging the highest 'healthy' level — ≥98% success and p95 within 2× baseline — as the practical max; a sustained-load test held at the detected knee (or 25) for a fixed window (default 30s); and a burst test (default 50 requests × 5 bursts with a 3s idle gap) that surfaces anti-burst defenses. Each bucket records p50/p95/p99/avg latency, throughput, status-code and error-class histograms; response bodies are read then discarded rather than inspected.",
		Tools: []ToolRef{
			{Name: "Go net/http + goroutines", Desc: "Native Go HTTP with goroutine worker pools for the ramp, sustained, and burst scenarios; each target gets a dedicated client with the connection pool sized to the test ceiling and HTTP/1.1 forced by default so concurrency maps 1:1 to TCP connections. Honors the Settings proxy (Burp/upstream) and killswitch L2 source-IP binding. No external CLI tools are driven."},
		},
		Phases: []string{
			"Normalize each target — trim, prepend https:// when no scheme is given, and require a host; invalid targets are recorded as errors but still counted toward the progress bar.",
			"Build a per-target dedicated HTTP client — connection pool sized to the test ceiling, HTTP/1.1 forced by default (ForceHTTP1) so each in-flight request holds its own TCP/TLS connection; honors the Settings proxy and killswitch source-IP binding.",
			"Baseline — fire 5 sequential warm-up requests and take the median latency as the reference for the 'p95 within 2× baseline' health test.",
			"Ramp test — step concurrency through the geometric ladder up to MaxConcurrency, firing ReqsPerLevel requests per level; classify each level healthy at ≥98% success and p95 ≤ 2× baseline (429/503 count as failures) and record the highest healthy level as the practical max / knee.",
			"Sustained test (if enabled) — hold SustainedConcurrency, or the detected knee (falling back to 25), firing continuously for SustainedDurationSec while watching for throttling (429/503), timeouts, and refused/reset connections.",
			"Burst test (if enabled) — fire BurstSize requests in parallel, idle for BurstIdleMs, and repeat BurstCount times to expose anti-burst defenses that cap rapid surges but let sustained traffic through.",
			"Summarize each bucket — p50/p95/p99/avg latency, throughput in RPS, and status-code / error-class histograms; response bodies are read and discarded (capped at 1 MiB), never hashed or diffed.",
		},
		Notes: []string{
			"Measures concurrency capacity and rate-limit ceilings, not business-logic race conditions — response bodies are read then discarded (capped at 1 MiB), never hashed or compared, so it cannot detect duplicate-winner races on its own.",
			"HTTP/1.1 is forced by default (ForceHTTP1) so each in-flight request holds its own TCP connection and concurrency reflects the server's real socket ceiling; disable it to let ALPN negotiate HTTP/2 and measure multiplexed throughput or reach h2-only origins.",
			"The default config stays under ~3000 total requests across all scenarios (MaxConcurrency 200, 30 requests per level, 30s sustained, 50×5 burst); raising MaxConcurrency extends the ramp ladder up to 10000 concurrent.",
			"ProbeMode 'varied' (default) appends a random path segment per request to mimic a direnum-style 404-heavy load profile; 'single' hammers one endpoint with a cache-buster query when measuring a specific page's capacity. Set Method/Body/ContentType to profile POST, login, or GraphQL endpoints.",
			"NEVER test rate-limit thresholds against production without WRITTEN AUTHORIZATION — accidentally tripping anti-DDoS systems can trigger billing or legal alerts",
			"If responses cluster bimodally (some 200s, some 429s within a single burst), you've hit the rate limit MIDWAY through the burst — note this in the report as a partial finding",
		},
		References: []ReferenceRef{
			{Label: "MDN HTTP 429 Too Many Requests", URL: "https://developer.mozilla.org/en-US/docs/Web/HTTP/Status/429"},
			{Label: "Go net/http Transport", URL: "https://pkg.go.dev/net/http#Transport"},
			{Label: "k6 load testing docs", URL: "https://grafana.com/docs/k6/latest/"},
		},
	},

	// ========================================================================
	// Advanced Web Application Scanner Suite
	// ========================================================================
	"advancedweb": {
		Summary: "Orchestrates 12 web-focused modules in a single chained pipeline against one or more targets. Stages 1-3 (whois → dns → httpx) build the asset map, stage 6 (techdetect) drives stage 10's wordlist selection (PHP target → PHP wordlist) and also feeds stage 7 (CVE Matcher) and stage 8 (WPScan, gated on WordPress detection), stage 10 (direnum ↔ spider) cross-feeds discoveries (direnum finds /admin → spider crawls it → direnum re-probes spider's findings — up to 3 iterations), stages 11-12 (httpmethods, secheaders) test only the URLs that earlier stages confirmed alive. Result: one consolidated report across the target set, with each stage informed by the previous.",
		Tools: []ToolRef{
			{Name: "Internal orchestrator", Desc: "Sequential loop that calls each module's native Scan() function in stage order (worker goroutines are spawned only inside individual stages)"},
			{Name: "TechDetect → DirEnum profile map", Desc: "Auto-selects WordPress / Drupal / Joomla / Apache / IIS / PHP / Java / Python / Node / ColdFusion profiles (plus a baseline 'general') based on stage 6 findings"},
		},
		Phases: []string{
			"Stage 1 (WHOIS/ASN) — only runs for domain targets, skipped for URLs",
			"Stage 2 (DNS Enum) — passive + brute; provides subdomain list to feed httpx",
			"Stage 3 (HTTPX) — probe every supplied host + discovered subdomain on common ports (full/custom modes optional); surfaces alive services",
			"Stage 4 (SSL/TLS) — independent of HTTPX: probes every DNS-discovered host (or the raw targets) on a configured port set (default 443,8443) with nmap ssl-enum + sslscan; finds cipher/protocol/vuln issues across the asset map",
			"Stage 5 (WAF) — fingerprint each alive URL's edge defenses",
			"Stage 6 (TechDetect) — fingerprint the stack of every alive URL; feeds profile selection downstream",
			"Stage 7 (CVE Matcher) — maps stage 6's (product, version) pairs onto the CVE database; requires Tech Detection and a DB lookup, else skipped",
			"Stage 8 (WPScan) — runs wpscan only on URLs where Tech Detection identified WordPress (core markers or a WordPress-exclusive plugin/theme); skipped when none found",
			"Stage 9 (Nuclei) — CVE / misconfig scan against the alive URL set",
			"Stage 10 (DirEnum ↔ Spider iterative cross-feed) — direnum runs with profiles from stage 6, finds dirs; spider crawls those dirs (depth 1); direnum re-probes spider's new dirs; loop up to 3 times or until no new dirs",
			"Stage 11 (HTTP Methods) — fires against the union of stage 3 alive URLs + stage 10 directory discoveries (2xx-3xx entries)",
			"Stage 12 (Security Headers) — same URL source as stage 11; methods auto-derived from the HTTP Methods stage's successful GET/POST/PUT responses (user can override)",
		},
		Notes: []string{
			"paramdisc is intentionally excluded from the suite — per spec it's not production-ready for an unattended chain run. Run it separately on URLs of interest",
			"URL inputs skip stages 1-3 with a 'skipped: input is URL' annotation; IP-only input is rejected (web suite needs hostnames)",
			"Iterative cross-feed terminates early when spider finds nothing new — keeps reasonable bounds on runtime for site maps without many sub-dirs",
			"Per-stage results embed the native module's results template inline — no special UI for the suite, just stacked module views",
			"Suite is intentionally NOT modifiable mid-flight — stop button cancels the whole chain. For granular control, run modules individually",
			"Accepts multiple targets at once (manual list or an imported target list); WHOIS/DNS/HTTPX (stages 1-3) are skipped only when EVERY target is a URL — a single domain in the mix still triggers full recon, and plain-IP entries are dropped",
			"CVE Matcher and WPScan both hard-require Tech Detection — with it disabled they are force-disabled regardless of the checkbox; WPScan additionally only runs when WordPress is detected",
			"Supports stage-level resume — stages that completed before a connectivity pause are seeded back and skipped on the resume run, while the data-producing stages (DNS/HTTPX/TechDetect) are reconstructed so later stages still get their input",
			"A Nuclei run can be reported INCOMPLETE (marked as an error state and the whole suite flagged incomplete) when it hits its time cap or exits abnormally; a 'low'/'info' severity sweep over 50+ hosts is warned up-front as a multi-hour job",
			"The DirEnum ↔ Spider cross-feed has a 72-hour wall-clock deadline; if it fires, the stage returns partial results and the suite is flagged incomplete rather than being pinned as 'running' forever",
		},
		References: []ReferenceRef{
			{Label: "OWASP Testing Guide v4.2", URL: "https://owasp.org/www-project-web-security-testing-guide/v42/"},
		},
	},

	// ========================================================================
	// Subdomain Takeover (A1)
	// ========================================================================
	"takeover": {
		Summary: "Detects dangling subdomain CNAMEs pointing at deprovisioned third-party services (S3, GitHub Pages, Heroku, Azure, Vercel, Netlify, Fastly, Shopify, Tumblr, Squarespace, etc.). Resolves each candidate subdomain's CNAME, matches the tail against 26 provider signatures, then HTTP-probes both schemes and looks for service-specific error messages ('NoSuchBucket', \"There isn't a GitHub Pages site here\", 'No such app' for Heroku, etc.). A hit means the attacker can register the upstream service name and claim the dangling subdomain.",
		Tools: []ToolRef{
			{Name: "Go net (LookupCNAME)", Desc: "Native CNAME resolution"},
			{Name: "Built-in provider signature DB", Desc: "26 provider fingerprints with CNAME tails, body markers, HTTP statuses, severity ratings"},
			{Name: "Go net/http", Desc: "HTTPS-then-HTTP probe of each candidate subdomain; reads up to 128 KB of the response body to fingerprint provider error pages"},
		},
		Phases: []string{
			"For each input subdomain, query CNAME record via Go resolver. If empty/equal-to-self → record 'no_cname' and skip",
			"Resolve to IPs as well — provides context (alive IPs = service still up; no IPs = likely candidate)",
			"Match CNAME tail against signature DB (S3 bucket suffix patterns, github.io, herokuapp.com, azurewebsites.net, etc.)",
			"If no signature match → status 'resolved_normal' (CNAME points to something we don't recognize)",
			"If the CNAME matches a provider but the CNAME target itself doesn't resolve (NXDOMAIN/unresolved) → immediately flag 'vulnerable' (pattern 'cname-target-nxdomain') with no HTTP body needed — the dangling name can be claimed on the provider",
			"HTTP probe — try HTTPS then HTTP. Status + body capture",
			"Body marker check — substring-search for provider's specific 'not found' message",
			"Mark as 'vulnerable' when status matches signature filter AND body marker found. Mark 'candidate' if CNAME matches but probe fails (manual verification needed)",
			"Optional dnsenum import — pull subdomains directly from a previous DNS Enumerator scan with one click",
		},
		Notes: []string{
			"S3 takeovers are the #1 hit — every dev team prototypes with a bucket then deletes it without removing the CNAME. CRITICAL severity, easy to verify (register the bucket name in your AWS account)",
			"GitHub Pages takeovers require both: a CNAME pointing at github.io AND no claimed repository serving that custom domain. Severity HIGH because attacker needs a GH account",
			"Statuspage requires email verification on takeover — flagged LOW because exploitation isn't automatic. Netlify validates domain ownership and takeover requires DNS poisoning — flagged MEDIUM, still a misconfiguration",
			"Some 'unreachable' candidates are still findings — the CNAME points at a dead provider but probe failed for network reasons. Mark for manual review, don't dismiss",
			"Re-run weekly on stable target lists — providers refresh their unclaimed inventory daily, hits appear and disappear",
		},
		References: []ReferenceRef{
			{Label: "can-i-take-over-xyz (community signature DB)", URL: "https://github.com/EdOverflow/can-i-take-over-xyz"},
			{Label: "Hackerone subdomain takeover writeups", URL: "https://www.hackerone.com/application-security/guide-subdomain-takeovers"},
			{Label: "Detectify Labs research", URL: "https://labs.detectify.com/2014/10/21/hostile-subdomain-takeover-using-herokugithubdesk-more/"},
		},
	},

	// ========================================================================
	// CORS Misconfig (A2)
	// ========================================================================
	"corsscan": {
		Summary: "Probes CORS handling for 9 misconfiguration patterns: arbitrary origin reflection (server echoes any Origin into ACAO), wildcard subdomain trust (any *.victim.com works), regex bypass via suffix/prefix attach (victim.com.attacker.tld), null origin trust (sandboxed iframes get full access), scheme downgrade (http origin trusted on https endpoint), comma injection, trailing-dot bypass, look-alike domain trust. Each Origin is probed with a simple GET and again as an OPTIONS preflight. Arbitrary origin reflection + Access-Control-Allow-Credentials: true = CRITICAL — any site can read authenticated responses; wildcard ACAO + credentials is flagged HIGH.",
		Tools: []ToolRef{
			{Name: "Go net/http", Desc: "Each test Origin is fired as a separate GET and again as an OPTIONS preflight; no external binaries"},
		},
		Phases: []string{
			"Optional reachability preflight (when enabled): drop TLS-dead / unreachable targets up front via a fast connect check, recording each skipped target as 'unreachable — <reason>'",
			"For each URL, fire 9 probes with different Origin headers and capture the response ACAO + Access-Control-Allow-Credentials headers",
			"Probe 1 (reflection): Origin: https://attacker-evil-<timestamp>.example — any reflection at all = misconfig",
			"Probe 2 (subdomain attach): Origin: https://evil.<victim-host> — server trusting any subdomain leaks access via XSS on a single subdomain",
			"Probe 3 (suffix): Origin: https://<victim-host>.attacker.example — catches unanchored regex like 'endsWith(host)'",
			"Probe 4 (prefix): Origin: https://<victim-host>attacker.example — catches 'startsWith(host)' regex",
			"Probe 5 (null): Origin: null — exploitable from sandboxed iframes / data: URIs / file:// pages",
			"Probe 6 (scheme swap): http origin on https endpoint — MITM on insecure network bypasses TLS",
			"Probe 7 (comma injection): comma in Origin — some proxies parse this leniently",
			"Probe 8 (trailing dot): https://victim.com. — host parser canonicalizes the dot away, regex doesn't",
			"Probe 9 (unicode look-alike): swap o→0, l→1 — catches naive substring checks",
			"Preflight pass: re-fire all 9 Origin probes as OPTIONS requests carrying Access-Control-Request-Method: PUT and Access-Control-Request-Headers: Authorization, Content-Type, and also capture Access-Control-Allow-Methods / Access-Control-Allow-Headers; matching findings are tagged [preflight] to expose simple-GET vs preflight divergence",
		},
		Notes: []string{
			"ACAO: * with credentials is FORBIDDEN by spec — browsers reject. But many reverse-proxies still emit the header and the server's CORS preflight logic doesn't enforce. Catch it because legacy clients/SDKs may use it",
			"Reflection + ACAC: true (credentials enabled) is the killer combo — any site fetch()s your authenticated user's data cross-origin",
			"Null-origin trust often comes from misunderstanding sandboxed iframes — attackers craft a sandboxed page with the API call and host it anywhere",
			"Suffix-attach (victim.com.attacker.tld) requires attacker to register that exact subdomain on a tld they own — costs ~$10. Severity HIGH because feasibility is trivial",
			"Many WAFs strip the Origin header before reaching the app — preflight may succeed even when actual fetch is blocked. Verify with browser DevTools before reporting",
		},
		References: []ReferenceRef{
			{Label: "PortSwigger CORS labs", URL: "https://portswigger.net/web-security/cors"},
			{Label: "OWASP CORS Cheat Sheet", URL: "https://cheatsheetseries.owasp.org/cheatsheets/HTML5_Security_Cheat_Sheet.html#cross-origin-resource-sharing"},
			{Label: "MDN — Cross-Origin Resource Sharing", URL: "https://developer.mozilla.org/en-US/docs/Web/HTTP/CORS"},
		},
	},

	// ========================================================================
	// Open Redirect (A3)
	// ========================================================================
	"openredirect": {
		Summary: "Fuzzes 26 redirect-candidate query parameters (next, url, return, redirect, redirect_uri, goto, dest, callback, etc.) with 10 bypass payload variants per param. Variants exercise parser quirks: protocol-relative (//evil.com), backslash variants (\\evil.com), userinfo@host (https://example.com@evil.com), URL-encoded (%2F%2Fevil.com), scheme-only no-slash (https:evil.com). Detects open-redirect-to-external — a CVE-class issue used for phishing and OAuth-flow hijacking.",
		Tools: []ToolRef{
			{Name: "Go net/http", Desc: "Custom client with CheckRedirect = ErrUseLastResponse (don't follow — we need the Location header)"},
		},
		Phases: []string{
			"For each input URL, iterate the candidate parameter list (default 26 names, or a user-supplied override list)",
			"For each (param, payload) combo, inject ?param=<payload> while preserving the URL's existing query",
			"Issue GET, capture raw req/resp, check status (must be 301/302/303/307/308 for a redirect)",
			"Inspect the Location header — does it point at the evil sentinel host? Match strict prefix (scheme://host), protocol-relative (//host), backslash variants, or userinfo (@host) bypass",
			"For 200 OK responses, read up to 64 KiB of the body and scan for meta-refresh (<meta http-equiv=refresh>) and client-side JS location redirects (window.location / document.location) that point at the evil host",
			"On match, emit a Finding with severity HIGH, the exact payload that landed, and how the Location matched (label for the bypass technique)",
			"Optional stop-on-hit per parameter — saves time on noisy targets where every variant works for one param",
		},
		Notes: []string{
			"Modern frameworks (Django, Rails, Spring) validate redirect targets against an allow-list by default — open redirect there usually means a deliberate-but-broken implementation. Read the source",
			"OAuth redirect_uri parameter is the #1 hit — attackers steal authorization codes by redirecting to attacker-controlled hosts during the OAuth dance",
			"Wildcard 'open redirects' that only allow same-origin are NOT findings — verify by testing with an obviously-external host first",
			"Some redirects are intentional (login → after-login destination). Confirm with the dev team before reporting, especially on customer-facing apps",
			"Stop-on-hit per parameter is on by default in many tools; here it's a toggle so audit-mode users can enumerate every variant",
		},
		References: []ReferenceRef{
			{Label: "OWASP Open Redirect Cheat Sheet", URL: "https://cheatsheetseries.owasp.org/cheatsheets/Unvalidated_Redirects_and_Forwards_Cheat_Sheet.html"},
			{Label: "CWE-601 — URL Redirection to Untrusted Site", URL: "https://cwe.mitre.org/data/definitions/601.html"},
			{Label: "PortSwigger redirect labs", URL: "https://portswigger.net/kb/issues/00500100_open-redirection-reflected"},
		},
	},

	// ========================================================================
	// CVE Matcher (A4)
	// ========================================================================
	"cvematch": {
		Summary: "Maps detected technologies + versions onto a SQLite CVE cache that is SEEDED at startup with 35 curated high-impact CVEs spanning Apache HTTPD, nginx, PHP, OpenSSL, OpenSSH, Tomcat, Spring, IIS, WordPress, Drupal, Jenkins, GitLab, Confluence, Log4j, Exchange, VMware Workspace ONE, MOVEit, ManageEngine, Citrix ADC, Fortinet FortiOS, etc. — and can be expanded to hundreds of thousands of CVEs by syncing NVD's JSON 2.0 feeds / REST API plus CVE.org (MITRE) CNA records for brand-new CVEs NVD hasn't analyzed yet. Handles dotted-numeric version ranges with inclusive or exclusive [lo, hi] bounds and case-insensitive, token-based product aliasing (apache → 'apache http server', etc.), with a bare-name fallback so detections beyond the ~25 curated products still match. Feeds direct from techdetect's output with one click, or from manual product@version entries.",
		Tools: []ToolRef{
			{Name: "In-tree curated CVE database", Desc: "35 pentest-relevant landmark CVEs; product aliases map techdetect's wording onto canonical product names"},
			{Name: "SQLite cve_records cache", Desc: "The single match source of truth — queried by CPE-style vendor:product keys; holds the built-in seed plus synced NVD + CNA rows, with cache rows overriding built-ins on the same CVE ID"},
			{Name: "NVD JSON 2.0 feeds + REST API", Desc: "DownloadFeedWithProgress pulls annual/'modified' gz feeds and FetchModifiedSince pulls the incremental modified-since REST API; both parse CPE version ranges into source='nvd' rows"},
			{Name: "CVE.org / MITRE CNA records", Desc: "FetchCNARows enriches NVD-unanalyzed (no-CPE) CVEs from cveawg.mitre.org into source='cna' rows so brand-new CVEs match before NVD's analysis lag"},
		},
		Phases: []string{
			"Gather inputs — one or more manual 'product@version' or 'product@version@url' lines (Source=manual), optionally combined with a techdetect import",
			"For each input (product, version, source URL), call canonicalProduct() to normalize 'apache' / 'httpd' onto canonical 'apache http server'",
			"No curated alias? Fall back to the normalized bare product name (fallbackProduct, ≥4 chars) so detections beyond the ~25 curated products can still match synced NVD/CNA rows",
			"Look up the SQLite cve_records cache by CPE-style candidate keys (candidateCacheKeys → 'vendor:product'); built-in + NVD + CNA rows are merged and a cache hit overrides a built-in with the same CVE ID. With no cache wired (offline/tests) it falls back to iterating the in-tree CVEDatabase slice",
			"Version range check — parse dotted-numeric (2.4.49 → [2,4,49]), strip non-numeric suffixes (p1, -rc1), compare element-wise",
			"If version is empty → skip CVE matching entirely (no version = can't bound-check = a guess). Record the input in SkippedNoVersion when the product has CVEs so the UI can show 'detected, version unknown — not CVE-checked'",
			"Emit a Match record per CVE hit with severity, CVSS, description, NVD reference URL",
			"Dedup matches by CVE ID (cache row wins over built-in), flush partial results to the DB every 2s, and honor the Stop button — ScanContext checks ctx cancellation between inputs",
			"Bucket matches by severity for the summary view (CRITICAL count, HIGH count, etc.)",
			"Import-from-techdetect dropdown — one-click pulls every (Name, Version) pair from a previous techdetect scan as inputs",
		},
		Notes: []string{
			"The curated DB is intentionally small (35 entries) — focused on pentest-relevant CVEs, not 1000+ low-severity bugs",
			"Version parsing is conservative — '2.4.49' and '2.4.49-Debian' both reduce to [2,4,49]. Distro suffixes don't break matching",
			"Products in the curated productAliases table match via token-based aliasing (word-boundary, so 'ssh' no longer matches inside 'openssh'); products NOT in the table fall back to a normalized bare name (≥4 chars) matched against synced NVD/CNA rows — so matching is no longer strictly limited to the ~25 curated products",
			"Broader coverage is live: a CVE-DB sync (Settings) downloads NVD's JSON 2.0 annual/'modified' feeds or the incremental modified-since REST API, parses CPE version ranges, and enriches NVD-unanalyzed (no-CPE) CVEs from CVE.org (MITRE) CNA records — upserting everything into the same cve_records table the matcher reads",
			"Source URL (where the tech was detected) flows through to the Match record — pentesters can click straight to the affected endpoint for proof",
			"The cache self-maintains: a daily auto-refresh pulls the NVD modified delta once the DB is >7 days old, backfills sparse recent years, and prunes NVD rows unseen upstream for 2 years; the built-in 35-CVE seed is preserved so offline matching always works",
		},
		References: []ReferenceRef{
			{Label: "NVD (National Vulnerability Database)", URL: "https://nvd.nist.gov/"},
			{Label: "CVE Details — searchable view of NVD", URL: "https://www.cvedetails.com/"},
			{Label: "CPE 2.3 product naming standard", URL: "https://csrc.nist.gov/projects/security-content-automation-protocol/specifications/cpe"},
			{Label: "NVD CVE API 2.0", URL: "https://nvd.nist.gov/developers/vulnerabilities"},
			{Label: "CVE.org / MITRE CVE Services", URL: "https://www.cve.org/"},
		},
	},

	// ========================================================================
	// GraphQL Scanner (A5)
	// ========================================================================
	"graphqlscan": {
		Summary: "Discovers GraphQL endpoints via 11 well-known paths (/graphql, /graphiql, /v1/graphql, /api/graphql, /query, /playground, etc.), confirms each is GraphQL by issuing a {__typename} probe, then runs 5 abuse tests on confirmed endpoints: introspection (full schema dump), GET-method acceptance (CSRF + cache poisoning), field-name suggestions (schema leak even when introspection is disabled), query batching (rate-limit bypass), alias overload (multi-mutation in one request — auth brute-force amplification). GraphiQL / Playground pages exposed = HIGH finding by itself.",
		Tools: []ToolRef{
			{Name: "Go net/http", Desc: "Per-endpoint POST+GET probe loop"},
		},
		Phases: []string{
			"Build candidate endpoint list — user-supplied base URLs × 11 default GraphQL paths (or user's custom override list)",
			"Per candidate: GET first (detects GraphiQL / Playground browser IDEs)",
			"POST {__typename} — confirms endpoint speaks GraphQL by presence of 'data' or 'errors' in response",
			"If confirmed: fire introspection query IntrospectionQuery — schema returned = HIGH finding (disable introspection in prod!)",
			"Parse schema if returned — extract Query / Mutation / Subscription fields for the report",
			"Fire GET-form query — /endpoint?query={__typename}. Server accepting this enables CSRF (no Content-Type required → no preflight)",
			"Fire bad-field query { thisFieldDoesNotExist } — error response with 'Did you mean...' suggestions leaks schema even with introspection off",
			"Fire batch query [{__typename},{__typename}] — server processing arrays bypasses per-request rate limits",
			"Fire alias-overload query {a:__typename b:__typename ...} — many aliases in one request amplifies brute-force / auth-burst attacks",
		},
		Notes: []string{
			"Introspection enabled is the #1 GraphQL misconfiguration — Apollo/Hasura/Sangria all ship with introspection ON by default in dev mode and developers forget to flip it for prod",
			"Field suggestions ('Did you mean...') leak the schema brute-forceable — disable in apollo-server config or set production: true",
			"Batched queries are the auth-brute force technique — wrap 100 login attempts in one HTTP request to bypass per-IP rate limits",
			"Alias overload is the same idea — 1000 mutation aliases in 1 request = 1000 mutation invocations × 1 rate-limit token",
			"GraphiQL exposed on production is a giveaway that introspection is also on — usually go together. Check both",
		},
		References: []ReferenceRef{
			{Label: "OWASP GraphQL Cheat Sheet", URL: "https://cheatsheetseries.owasp.org/cheatsheets/GraphQL_Cheat_Sheet.html"},
			{Label: "GraphQL Security best-practices (Apollo)", URL: "https://www.apollographql.com/docs/apollo-server/security/cors/"},
			{Label: "GraphQL Threat Matrix (community)", URL: "https://github.com/nicholasaleks/graphql-threat-matrix"},
		},
	},

	// ========================================================================
	// Auth Tester (A7)
	// ========================================================================
	"authtest": {
		Summary: "Probes login flows for 4 classes of auth weakness: weak credentials (small user×pass lists driven through 5 Burp-Intruder-style attack modes — sniper, battering ram, pitchfork, cluster bomb and password spray — with auto-detection of failed-login response shape), username enumeration (same wrong password against multiple users — different response sizes/status codes signal which usernames are valid), session fixation (session cookie should rotate on auth success), and password-reset token entropy (tokens shorter than 10 chars or with shared common prefix = predictable / brute-forceable). Auto-infers the 'invalid login' marker from baseline response — works without user configuration in most cases. Supports both form-encoded and JSON login bodies for SPA/API/SSO endpoints.",
		Tools: []ToolRef{
			{Name: "Go net/http", Desc: "Form/JSON-POST + cookie tracking + body diffing"},
		},
		Phases: []string{
			"Baseline failed-login probe — send 'definitely-nonexistent-user' + 'wrong-pass' to learn the failure response shape (status, body length, body content)",
			"Failure-marker inference — if no FailMarker supplied, search baseline body for common strings ('invalid credentials', 'login failed', 'hatalı', 'incorrect password', etc.). Save as auto-detected marker",
			"User-enumeration probes — for each candidate user, send (user, fixed-wrong-password). Cluster responses by (status, body length / 64-byte bucket). ≥2 clusters = enumeration oracle",
			"Brute-force phase — build the (user, pass) attempt sequence per the selected Burp-Intruder attack mode (sniper, battering ram, pitchfork, cluster bomb = cartesian, password spray), capped by MaxAttempts. Cluster bomb fires concurrently (default 3 workers); every other mode runs serially so DelayPerUser (anti-lockout) and DelayPerPass (rate-limit) actually pace it. Each attempt classified via heuristic: success marker present? failure marker absent? status changed (302/303 from 200 baseline, or 200 from 401/403 baseline)? body length delta >20%?",
			"Session fixation probe (optional) — GET login URL pre-auth, capture session cookie. Log in with the first configured user/pass (runs only if that login looks successful). GET again. If cookie didn't rotate → session fixation finding",
			"Password reset entropy probe (optional) — POST password-reset for up to 3 users, capture emitted tokens (from the Location header and response body). Tokens averaging <10 chars OR sharing ≥50% common prefix → weak token finding",
		},
		Notes: []string{
			"User-enumeration is THE most common login finding — 'invalid username' vs 'invalid password' messaging gives it away. Even response size deltas as small as 50 bytes (different error template) leak the signal",
			"Auto-detected failure markers cover Turkish ('hatalı', 'geçersiz') and English ('invalid credentials', 'login failed') — extend the inferFailMarker() list for other languages",
			"Session fixation is RARE on modern frameworks (Spring Security, Django Auth, Rails Devise all rotate by default). Found mainly in custom-built auth or legacy PHP / classic ASP apps",
			"Password reset entropy weakness leads directly to account takeover — short tokens or sequential tokens (containing timestamp) are brute-forceable",
			"NEVER run against production with real-user passwords without WRITTEN AUTHORIZATION and a documented rollback plan for lockouts",
			"Five Burp-Intruder-style attack modes shape the attempt order: sniper (one field varies, the other fixed), battering ram (same value in both fields — catches user==pass defaults), pitchfork (zips leaked user:pass pairs for credential stuffing), cluster bomb (full cartesian — loudest, concurrent), and password spray (each password against every user before the next — evades per-account lockout; pair with DelayPerUser ≥30s)",
			"Login bodies can be form-encoded (default) or JSON (BodyEncoding='json' with a JSONTemplate using {USER}/{PASS} placeholders) — needed for SPA/API/SSO stacks (Okta/Auth0/Cognito) that answer 400/415 to a form POST",
			"Cracked passwords are masked in findings and Attempt rows, and the plaintext is scrubbed from captured raw request bodies (both form and JSON) before it reaches scan-result JSON / CSV exports / the UI",
		},
		References: []ReferenceRef{
			{Label: "OWASP Authentication Cheat Sheet", URL: "https://cheatsheetseries.owasp.org/cheatsheets/Authentication_Cheat_Sheet.html"},
			{Label: "CWE-307 — Improper Restriction of Excessive Authentication Attempts", URL: "https://cwe.mitre.org/data/definitions/307.html"},
			{Label: "NIST 800-63B (digital identity guidelines)", URL: "https://pages.nist.gov/800-63-3/sp800-63b.html"},
		},
	},

	// ========================================================================
	// Asset Discovery (A8)
	// ========================================================================
	"assetdisc": {
		Summary: "Queries Shodan and Censys for org/ASN/SSL-cert-scoped internet-facing assets, enriching local discovery (dnsenum) with internet-wide passive data. Returns per-host (IP, port, hostname, OS, ASN, org, country, product banner, all domain names the provider associates with this IP). Massively expands the attack surface map — a target org's main domain often hides hundreds of forgotten dev/staging/IoT hosts that only Shodan/Censys see.",
		Tools: []ToolRef{
			{Name: "Shodan API", Desc: "/shodan/host/search — full text + filters (org:, ssl:, hostname:, port:, country:)"},
			{Name: "Censys API", Desc: "/api/v2/hosts/search — modern endpoint with full service data per IP. Uses HTTP Basic auth"},
		},
		Phases: []string{
			"For each user query, fan out to selected providers (Shodan and/or Censys)",
			"Shodan: GET /shodan/host/search?key=K&query=Q&minify=true — paginated to MaxPerQuery (default 100)",
			"Censys: POST /api/v2/hosts/search with {q, per_page} body, Basic auth (id:secret)",
			"Per response: extract IP, port, hostname, OS, ASN+org, country, product+banner, all known DNS names for the host",
			"Censys returns ONE host with N services — expand to one Asset row per service for unified handling with Shodan's flat rows",
			"Aggregate per-query: total reported by API + actual assets fetched (capped at MaxPerQuery)",
			"Graceful empty-key handling — if API key missing in Settings, emit a Query result with the error message instead of crashing",
		},
		Notes: []string{
			"Shodan free tier: 100 results/query, 5 queries/day. Paid tier 1000-100k. Set the key via Settings",
			"Censys offers more structured per-service data but more restrictive rate limits — start with Shodan, fill gaps with Censys",
			"Filter syntax: org:'Acme Corp' (Shodan) vs services.tls.certificates.leaf_data.subject.organization:'Acme' (Censys) — different DSLs, same intent",
			"Don't query both providers for every project — pick one based on which has better coverage in your target's region",
			"Output feeds asset_findings dashboard — Shodan/Censys IPs become first-class assets just like dnsenum hits",
			"Pagination is capped by MaxPages (default 1) — Shodan follows &page=N, Censys follows the result.links.next cursor, stopping at MaxPerQuery, an empty page, or the API-reported total. Each extra Shodan page can cost a query credit on paid plans.",
		},
		References: []ReferenceRef{
			{Label: "Shodan filter reference", URL: "https://help.shodan.io/the-basics/search-query-fundamentals"},
			{Label: "Censys search filters", URL: "https://search.censys.io/search/language?resource=hosts"},
		},
	},

	// ========================================================================
	// OOB Collaborator (A9) — LOCAL LISTENER, NOT A FULL OOB SERVICE
	// ========================================================================
	"oob": {
		Summary: "LOCAL HTTP callback listener — opens a port on scaNNer's host and waits for inbound requests. WORKS ONLY when the target server can reach scaNNer (internal pentest LAN, CTF, VPN tunnel, or public-IP self-hosted deployment). DOES NOT have a DNS authority (no XXE-via-subdomain detection) and DOES NOT serve HTTPS (some targets refuse). For public-internet targets, use Interactsh (oast.fun) or Burp Collaborator — they solve reachability, DNS, HTTPS and persistence. This module is best used as a learning/CTF aid or for inside-network engagements where you control routing.",
		Tools: []ToolRef{
			{Name: "Go net/http", Desc: "Listener on configurable port (default :0 = OS-assigned). NO TLS termination, NO DNS server"},
		},
		Phases: []string{
			"Mint a session — random hex session_id + N tokens (each 10-hex-char). Tokens are how scaNNer attributes captured requests to a specific probe",
			"Open the listener — bind to the validated listen address (default ':0' = OS-assigned wildcard port; the user may instead pin an explicit loopback or wildcard host:port). This is a SEPARATE field from 'Public host' (base_domain), which is only composed into the callback URL and is NOT necessarily the bind interface — so a loopback bind with a blank public host is the #1 silent failure, which the console explicitly warns about",
			"Compose callback URLs — http://<public-host>/<token>. The user pastes these into vulnerable targets' inputs (SSRF payloads, blind-XSS hooks, SSTI ${fetch()} probes)",
			"Listener handler captures: timestamp, remote IP, method, path, Host header, User-Agent, ALL request headers, body snippet (first 600 bytes)",
			"Token matching from the request path (and Host) → links the interaction back to its originating probe",
			"Respond with a tiny JSON ACK ({ok:true, token, received_at}) — useful when the user's payload reads back the HTTP response (some SSTI echo HTTP into rendered output)",
			"Persistence — last 500 interactions per session held in memory; a background flusher snapshots them to the DB every 5s (only when the interaction count grows), plus a final snapshot on Stop, so captured hits survive a server restart. The results page itself is a pure read",
		},
		Notes: []string{
			"Fixed Phase 7 (stale DB-on-every-results-hit -> background flusher + Stop snapshot; results page is pure read).",
			"Added a note documenting oobMaxTokens=64 clamp and validateOOBListen port/host restrictions.",
			"Corrected Phase 2: dropped the false 'listener binds to 0.0.0.0 regardless' claim — startHTTP binds the validated listen_addr, which may be an explicit 127.0.0.1 loopback bind; 'Public host' (base_domain) is a separate URL-only field. Translation added for the rewritten phase.",
			"descriptionFix empty: module.go Description() is consistent with the code.",
			"Module drives no external CLI tools; sole tool entry 'Go net/http' is accurate.",
		},
		References: []ReferenceRef{
			{Label: "Interactsh (the right tool for public-internet OOB)", URL: "https://github.com/projectdiscovery/interactsh"},
			{Label: "Interactsh public service — paste 'interactsh-client' in terminal", URL: "https://app.interactsh.com/"},
			{Label: "PortSwigger Burp Collaborator (the reference design)", URL: "https://portswigger.net/burp/documentation/collaborator"},
			{Label: "OWASP SSRF Prevention Cheat Sheet", URL: "https://cheatsheetseries.owasp.org/cheatsheets/Server_Side_Request_Forgery_Prevention_Cheat_Sheet.html"},
		},
	},

	// ========================================================================
	// SSTI Probe (A10)
	// ========================================================================
	"sstiscan": {
		Summary: "Detects server-side template injection across 10 template engines (Jinja2, Twig, Mako, Smarty, ERB, Velocity, FreeMarker, Mustache/Handlebars, Pug, EJS) using engine-specific arithmetic markers. Each engine has a probe payload that evaluates to a recognisable result (e.g. Jinja2 {{7*'7'}} → '7777777', while Twig coerces the same expression to '49'). To confirm, it strips every literal occurrence of the payload out of the response body and then checks whether the marker substring still appears — so a page that merely reflects the payload verbatim (reflected XSS) is stripped away and does NOT match, but a page that both echoes the payload and renders the marker elsewhere still counts. Note the literal payload is not required to be absent from the original body, and because no marker ('49'/'7777777') is a substring of its payload the strip is effectively inert for the current engine set. Each finding includes an engine-specific exploitation hint chaining toward RCE.",
		Tools: []ToolRef{
			{Name: "Go net/http", Desc: "Per (injection point × engine) probe over a single shared HTTP client"},
		},
		Phases: []string{
			"Build injection points — if the URL contains a FUZZ placeholder, inject only there (GET query). Otherwise, for each candidate param (default: name, q, search, input, id, page, data, template) add a GET ?param=PAYLOAD point when Method is GET/both and a POST body-field point when Method is POST/both; additionally, regardless of Method, inject the payload into the User-Agent, Referer and X-Forwarded-For request headers (each issued as a GET request)",
			"For each injection point × each engine, fire the engine's signature payload",
			"Response handling — read up to 256 KB of the response body, then strip every literal occurrence of the payload out of it",
			"Confirm evaluation — the marker substring must still be present in the payload-stripped body; a page that merely reflects the payload verbatim is removed by the strip and does not match, but a page that both echoes the payload and renders the marker elsewhere still counts (the literal payload is NOT required to be absent from the original body)",
			"Emit a finding — severity is tiered per engine: CRITICAL for engine-unique markers (Jinja2 '7777777', the Handlebars constructor chain) and HIGH for the arithmetic-only '49' markers shared by any 7*7-evaluating engine — recording engine name, parameter/location, method, payload, marker, raw request/response, and the engine-specific note (e.g. for Jinja2: 'Try {{config.items()}} or {{_self}} for further escalation')",
			"Continue testing other engines on the same parameter — same param may be evaluated by multiple engines in chained renderers",
		},
		Notes: []string{
			"Jinja2 vs Twig discrimination is the {{7*'7'}} test — Jinja2 returns '7777777' (string * int = repeated string), Twig returns '49' (string coerced to int). Same syntax, different outputs",
			"SSTI → RCE chain is well-known per engine — see PortSwigger's SSTI labs for engine-specific escape sequences. The 'Note' field has a one-line tip per finding",
			"Mustache logic-less variant doesn't have a clean SSTI primitive — only Handlebars-style with helpers. The Mustache probe payload uses the Handlebars-only constructor escape",
			"False-positive risk: '49' is a common number — if the target page already contains '49' for unrelated reasons (e.g. a product count), the probe triggers. The literal-payload strip only removes echoed copies of the payload (preventing false negatives when the page both reflects and renders it); it does NOT remove an unrelated marker occurrence, so short markers like '49' keep a real false-positive risk — which is why they are rated HIGH rather than CRITICAL",
			"Targets behind a CDN may not evaluate templates server-side — confirm by sending different markers from each engine and comparing which actually evaluate",
		},
		References: []ReferenceRef{
			{Label: "PortSwigger SSTI labs", URL: "https://portswigger.net/web-security/server-side-template-injection"},
			{Label: "OWASP SSTI cheat sheet", URL: "https://owasp.org/www-project-web-security-testing-guide/v42/4-Web_Application_Security_Testing/07-Input_Validation_Testing/18-Testing_for_Server_Side_Template_Injection"},
			{Label: "James Kettle's SSTI research (the original)", URL: "https://portswigger.net/research/server-side-template-injection"},
		},
	},

	// ========================================================================
	// Cache Poisoning + HTTP Smuggling (A11)
	// ========================================================================
	"cachepoison": {
		Summary: "Two-in-one module probing web cache poisoning (23 host-override, URL-override and IP-spoofing headers like X-Forwarded-Host / X-Original-URL / X-Custom-IP-Authorization) AND HTTP request smuggling (CL.TE, TE.CL, TE.TE — front-end vs back-end Content-Length / Transfer-Encoding parser disagreements). Cache poisoning checks for header reflection on cacheable endpoints (CDN-served, Age/X-Cache present), then re-fetches with a clean GET to confirm the poison persisted into a request that never sent the malicious header. Smuggling uses raw TCP sockets to send malformed requests and detects back-end socket parking via response timeout OR positive signals (two HTTP responses on one socket, or the smuggled /poison / GPOST artifacts echoed back).",
		Tools: []ToolRef{
			{Name: "Go net/http", Desc: "Cache poisoning header reflection tests"},
			{Name: "Go net (raw TCP)", Desc: "Smuggling probes need raw byte control — Go's net/http won't let you send CL.TE-conflicting headers"},
		},
		Phases: []string{
			"Cache poisoning baseline — issue a clean GET, capture response. Check Cache-Control, Age, X-Cache, X-Cache-Hits headers to assess cacheability",
			"Baseline sentinel check — if the target's normal response already contains the evilHost string (in a header or the body), emit an INFO finding and skip all header probes for that URL, since coincidental matches would false-positive every probe",
			"Per-header probe — for each of 23 host-override / URL-override / IP-spoofing headers, send GET with that header set to evilHost",
			"Reflection detection — does a response header (e.g. Location, Link) or the body contain evilHost? Reflection on a non-cacheable response = MEDIUM; reflection on a cacheable response starts at HIGH",
			"Poison-persistence confirmation — on a cacheable reflection, sleep 250ms then issue a clean GET with no malicious headers. If the poison is served back = CRITICAL (confirmed exploit primitive); if the clean follow-up is clean = downgrade to LOW (cache key likely includes the header or TTL too short)",
			"Cacheable-but-clean — if the URL is cacheable but no header reflected, emit an INFO finding flagging it for manual review with custom probe headers",
			"Smuggling baseline — none; smuggling probes are direct CL.TE / TE.CL / TE.TE attempts",
			"CL.TE probe — send POST with Content-Length AND Transfer-Encoding: chunked. Front-end may honor CL, back-end TE → smuggled bytes get parked, response times out",
			"TE.CL probe — reverse (chunked body with conflicting smaller CL value)",
			"TE.TE probe — obfuscated Transfer-Encoding header (mixed case, extra header) — one parser strips/normalizes, the other doesn't",
			"Read raw socket response with deadline. Fire on a timeout/deadline (back-end parked) OR on positive signals — two HTTP/1.x status lines on one socket, or the smuggled /poison / GPOST artifacts echoed back — while early-rejecting a clean 400/501 as a plain front-end rejection",
		},
		Notes: []string{
			"Cache poisoning is the deadliest 'visible' finding — a single successful poison persists for the cache TTL (hours to days) and serves attacker content to all visitors",
			"Smuggling is harder to confirm — the response-time signal is suggestive, not conclusive. PortSwigger's published methodology requires multiple confirmation requests; this module emits POSSIBLE smuggling flags, not certain ones",
			"DO NOT run smuggling probes against production without explicit authorization — even unsuccessful CL.TE attempts can crash the front-end / back-end pairing temporarily",
			"CDN-fronted sites: cache poisoning is at the CDN layer, but the X-Forwarded-Host reflection happens at the origin. Confirm by checking the Cache-Control / Age headers came from the CDN edge",
			"This module is intentionally noisy — false positives on benign reflection (header echo for debugging) are tolerated to maximize sensitivity",
			"The evilHost sentinel defaults to scanner-evil.example; if the target organically reflects your chosen sentinel the baseline check skips all probes and tells you to pick a different evil_host",
		},
		References: []ReferenceRef{
			{Label: "PortSwigger cache poisoning labs", URL: "https://portswigger.net/web-security/web-cache-poisoning"},
			{Label: "PortSwigger HTTP request smuggling labs", URL: "https://portswigger.net/web-security/request-smuggling"},
			{Label: "James Kettle's request smuggling whitepaper", URL: "https://portswigger.net/research/http-desync-attacks-request-smuggling-reborn"},
			{Label: "RFC 7230 — HTTP/1.1 message syntax", URL: "https://datatracker.ietf.org/doc/html/rfc7230"},
		},
	},
}
