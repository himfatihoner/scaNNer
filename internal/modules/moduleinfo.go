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

	// ========================================================================
	// SSL / TLS
	// ========================================================================
	"sslscan": {
		Summary: "Probes a host:port with every TLS version (SSL 3.0 → TLS 1.3) AND every cipher suite Go knows about, then classifies the negotiated set into pentest-relevant categories: protocol-level weaknesses (SSL 3.0 → POODLE, TLS 1.0/1.1 → BEAST/Lucky13), cryptographic weaknesses (RC4 biases, 3DES → SWEET32, NULL ciphers, Anonymous DH), and certificate problems (expired, self-signed, weak signature algorithm, missing intermediates, no OCSP stapling). Unlike OpenSSL-based tools that enforce SECLEVEL≥1 and refuse to even offer deprecated ciphers, this module bypasses that policy and tests what the server's policy actually permits — surfacing real misconfigurations that other scanners miss.",
		Tools: []ToolRef{
			{Name: "Go crypto/tls", Desc: "Native TLS handshake with no SECLEVEL filtering — lets the client offer any cipher, including 3DES/RC4/NULL"},
			{Name: "Go crypto/x509", Desc: "Certificate chain parsing + Verify() against system root store"},
		},
		Phases: []string{
			"TCP connectivity check — verifies the port even accepts a connection before wasting handshakes on dead hosts",
			"Bare TLS handshake probe — if the port doesn't speak TLS at all (e.g. HTTP on 443) the host is short-circuited with HasTLS=false",
			"For each TLS version (SSL 3.0, TLS 1.0/1.1/1.2/1.3), force MinVersion = MaxVersion to that exact version and try the full cipher list",
			"Defensive: assert state.Version equals the requested version, drop the result if Go ever silently accepts a downgrade",
			"Per-cipher individual probes — connect with CipherSuites=[csID] one at a time; the server's selection reveals the EXACT set of suites enabled for that version (not just the strongest one)",
			"Certificate extraction — subject, issuer, NotBefore/NotAfter, signature algorithm, public-key size, SANs, self-signed detection",
			"Chain validation — call cert.Verify() with the intermediates the server bundled; surfaces 'no intermediates served' which breaks older clients even when modern browsers cope via AIA fetch",
			"OCSP stapling check — state.OCSPResponse non-empty means the server pre-fetched a status response (revocation check works offline; missing OCSP = MITM with stolen cert may bypass revocation)",
			"Finding classification — group similar weaknesses into categories (one '3DES suites supported' finding instead of 7 cipher rows) with CVE references where applicable",
		},
		Notes: []string{
			"Reports one finding PER CATEGORY (e.g. '3DES ciphers') not per cipher — keeps the report concise. The 'Cipher Suites' tab shows the per-suite breakdown",
			"Hosts that don't speak TLS at all are skipped silently — this is desired behaviour because port scanners that include 443 will throw many false positives otherwise",
			"3DES on TLS 1.0 is the classic 'tool says no, server says yes' divergence — see the SSL/TLS doc notes for cross-verification via nmap or sslyze",
			"TLS 1.3 cipher suites aren't user-configurable in Go; we still report the single negotiated AEAD cipher for completeness",
			"Self-signed leaves and expired certs are LOW/HIGH severity respectively — they ARE valid pentest findings but won't trigger client-side TLS errors if the user pre-installed the cert as a trust anchor",
		},
		References: []ReferenceRef{
			{Label: "RFC 8996 (TLS 1.0/1.1 deprecation, March 2021)", URL: "https://datatracker.ietf.org/doc/html/rfc8996"},
			{Label: "SWEET32 — 3DES birthday attacks (CVE-2016-2183)", URL: "https://sweet32.info/"},
			{Label: "Mozilla TLS configurator (modern/intermediate/old presets)", URL: "https://ssl-config.mozilla.org/"},
			{Label: "BEAST attack on TLS 1.0 CBC", URL: "https://www.openssl.org/~bodo/tls-cbc.txt"},
		},
	},

	// ========================================================================
	// HTTPX Finder
	// ========================================================================
	"httpxfind": {
		Summary: "Discovers HTTP/HTTPS services across a target list by probing ports and capturing per-service metadata (status, title, Server header, redirect target, response body, raw request/response bytes). This is the bread-and-butter first step of a web pentest: before you can hunt vulnerabilities you need to know WHERE the web apps live. The 'Full' mode TCP-scans all 65535 ports first so admin panels hidden on weird ports (e.g. Jenkins on 8082, Grafana on 3000) don't slip through.",
		Tools: []ToolRef{
			{Name: "Go net/http", Desc: "Custom client with InsecureSkipVerify and CheckRedirect = ErrUseLastResponse (don't follow redirects — we want the Location header)"},
			{Name: "Go net (TCP)", Desc: "Concurrent port-open detection at 500 parallel connections in Full mode"},
		},
		Phases: []string{
			"Mode selection — Common (4 ports: 80, 443, 8080, 8443) or Full (1–65535 TCP scan first, then HTTP probe open ports)",
			"For each target × port, try HTTPS first. On TLS handshake failure fall back to plain HTTP — many legacy admin panels are still HTTP-only",
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
			"Build the method×content-type matrix — POST gets 6 CT variants (form-urlencoded, JSON, XML, multipart, text/plain, binary), PUT/PATCH/DELETE similar combinations, TRACE gets a special X-XST-Marker header",
			"Issue each request with httputil.DumpRequest capturing the wire bytes for Burp replay",
			"Classify each response — Allowed (2xx-3xx), Method Not Allowed (405), Forbidden (403), Unauthorized (401), TRACE-Echo (TRACE returns request body verbatim → XST candidate)",
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
			{Name: "Go net/http", Desc: "Baseline GET + 8 attack-payload probes with anomalous User-Agent variants"},
			{Name: "Signature DB (in-tree)", Desc: "20+ WAF vendors (Cloudflare, Akamai, AWS WAF, Imperva, F5, ModSecurity, Sucuri, Barracuda, Fortinet, etc.) matched against header/cookie/body fingerprints"},
		},
		Phases: []string{
			"Normal-traffic baseline — single GET to capture headers, cookies, body. This is the 'innocent client' fingerprint",
			"Match the baseline against 20+ vendor signatures, scoring each (header match = 25 points, cookie match = 20, body match = 30)",
			"Active payload phase — send 8 known-malicious requests (XSS <script>, SQLi UNION, LFI ../etc/passwd, RFI http://evil.com/shell, command injection, path traversal, protocol violation, suspicious User-Agent)",
			"For each payload, observe status code delta vs baseline. 403/406/429/503/999 on a baseline-200 endpoint = WAF block, +30 confidence",
			"Re-match the BLOCKED response body against signatures — the WAF's challenge page itself often leaks the vendor name",
			"Pick the highest-scoring vendor with confidence ≥ 15; below that, report 'Unknown WAF' but include the evidence that one is present",
		},
		Notes: []string{
			"The User-Agent Anomaly probe uses a real-world cloud-system-networks bot string — many WAFs rate-limit suspicious crawlers, so this surfaces edge defenses even when content-based payloads aren't blocked",
			"CDN ≠ WAF — Fastly fronts many sites without active filtering. Look for Fastly headers PLUS payload-block evidence before claiming 'WAF detected'",
			"WAFs deliberately add latency to suspicious probes — back-to-back requests against the same target may trigger temporary IP blocks. Run from rotating egress IPs for repeatable testing",
			"This module does NOT bypass the WAF — for that, use the OWASP CRS bypass cheat sheet or the dedicated paramdisc / corsscan / sstiscan modules with payload encoding tricks",
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
		Summary: "Identifies the technology stack of a target by fusing two detection layers: 70+ built-in fingerprints (HTTP headers, cookies, HTML body, meta tags, favicon hash) and WhatWeb's plugin set (passive -a 1 by default; -a 3 when the Aggressive toggle is on). Categorises results into CMS, Framework, Web Server, Language, JS Library, CDN, Analytics, UI, Security — and crucially CAPTURES VERSIONS where possible so cvematch can chain into CVE lookups. The favicon MurmurHash3 mode mirrors Shodan's http.favicon.hash technique: pivot from one hash to every other host on the internet serving the same icon (mass-asset discovery for the same SaaS deployment).",
		Tools: []ToolRef{
			{Name: "Built-in fingerprints", Desc: "70+ rules (WordPress generator meta, X-Powered-By, React DevTools globals, Next.js __NEXT_DATA__, jQuery version regex, nginx default page, etc.)"},
			{Name: "whatweb", Desc: "External Ruby CLI — adds 1800+ plugins (must be on $PATH). Runs passive (-a 1) by default; the Aggressive toggle switches it to -a 3 for deeper, slower plugin probing"},
			{Name: "MurmurHash3", Desc: "Hashes /favicon.ico for Shodan-style pivoting"},
		},
		Phases: []string{
			"Fetch target URL with captured raw req/resp for Burp; allow up to 3 redirects so canonical homes resolve",
			"Extract response headers, cookies, HTML body, meta tags — these are the inputs all fingerprinters consume",
			"Built-in pattern match against 70+ rules — fast (single-file, no spawn) and catches the high-signal cases (X-Generator: WordPress 6.4.3)",
			"Spawn whatweb -a 3 in parallel — slower (1-5s) but covers obscure plugins and admin panel fingerprints",
			"Merge results — WhatWeb fills in versions for fingerprints the built-in rules matched without one",
			"Categorise — CMS (WordPress/Drupal/Joomla), Framework (Django/Rails/Spring), Server (nginx/Apache/IIS), Language (PHP/Python/Java/Node), JS (React/Vue/jQuery), CDN (Cloudflare/Fastly), Analytics (GTM/Mixpanel), Security (CSP/HSTS markers), UI (Bootstrap/Tailwind)",
			"Favicon fetch — try <link rel='icon'> first, fall back to /favicon.ico. Hash the bytes, base64-wrap-76 to match Shodan's canonical form",
		},
		Notes: []string{
			"whatweb is optional but recommended — without it the module still catches 60-70% of stacks via the built-in rules. Skip via env var if you can't install Ruby",
			"FaviconMMH3 is the killer feature for asset discovery — paste the int32 into Shodan's http.favicon.hash:<value> filter and you'll find every other deployment in the wild (think SaaS clones)",
			"Version detection is best-effort. Where multiple sources disagree (header says 'nginx/1.18', X-Powered-By says 'nginx/1.20'), the LAST one wins — usually the most accurate",
			"Feeds cvematch directly — once you have (Apache, 2.4.49) the CVE matcher returns CVE-2021-41773 in one click",
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
		Summary: "Crawls a web application from a seed URL, extracting links from every parseable source (HTML href / src / action / srcset / form, CSS url(), JS string-literal paths, .js bundle scanning with API regex extractors) and classifying each discovery as directory, file, or endpoint. Stays in-scope by matching same-host, respects Max Depth + Max Pages limits, and runs 10 concurrent workers with a visited-set guard. Output feeds direnum (seed URLs), cvematch (discovered tech), and openredirect (potential redirect parameters).",
		Tools: []ToolRef{
			{Name: "Go net/http + regexp", Desc: "Concurrent worker pool, HTML attribute regex, CSS url() regex, JS endpoint regex"},
			{Name: "Same-host filter", Desc: "Strips off-scope hosts so a single rogue <a href='facebook.com'> doesn't drag the crawler off-target"},
		},
		Phases: []string{
			"Enqueue the seed URL(s) into the work channel; mark visited",
			"10 concurrent workers pop URLs, fetch with the shared HTTP client, capture raw req/resp",
			"Branch on Content-Type: HTML → extract href/src/action/srcset attrs + form fields + meta refresh; CSS → extract url() refs; JS → extractJSEndpoints() runs 3 regex patterns (api/v\\d+/..., fetch/axios calls, url=/path= assignments). Caps JS endpoints at 200/file",
			"Resolve all extracted links against the current page URL (relative→absolute), filter to same-host, drop fragments",
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
		Summary: "Technology-aware directory and file brute-forcing with smart false-positive detection. Combines SecLists wordlists, per-tech extension lists (PHP, ASP.NET, Java, Node, WordPress paths), and a 2304-probe baseline matrix that catches 'soft 404' servers (sites returning 200 for nonexistent paths). The smart-scan baseline is the differentiator vs gobuster/ffuf — pentest tools have been historically blind to status-code 200 false positives, and this module's per-extension baseline matrix beats them.",
		Tools: []ToolRef{
			{Name: "SecLists wordlists", Desc: "common.txt (low), raft-medium / raft-large (normal/aggressive), DirBuster mediums, tech-specific files (PHP/ASP/Java/Node/WP/API)"},
			{Name: "Go net/http", Desc: "Concurrent requests with workspace-driven concurrency cap"},
		},
		Phases: []string{
			"User selects technology profiles (PHP, ASP, Java, Python, Node, WordPress, API, General) — drives the wordlist + extension matrix",
			"Scan level (Light=common.txt, Normal=raft-medium, Aggressive=raft-large) determines wordlist size",
			"Smart Scan baseline — send 50 random nonexistent paths PER extension to learn the server's false-positive shape (status code, body length, Location header)",
			"Build the full request list — words × tech extensions × profiles, dedup + skip user-blocked paths",
			"Concurrent probe loop with workspace-defined parallelism (default 20 in-flight)",
			"For each response, compare against the FP baseline matrix. Drop matches → these are soft-404s, not real discoveries",
			"Classify each surviving response — trailing slash → directory; with extension → file; capture redirect target if 3xx",
			"Backup-file enrichment — for each .ext discovery, queue probes for .ext.bak, .ext.swp, .ext.old, .ext.~, .ext.orig (B4 enhancement)",
			"Optional Exclude Paths — skip /admin, /logout, etc. (prefix matching, BFS-aware so recursive sub-levels are also excluded)",
		},
		Notes: []string{
			"Smart Scan finds ~30% more REAL hits than gobuster/ffuf on noisy sites because it filters the baseline FP signature instead of trusting status codes blindly",
			"Recursive mode (Max Depth 2-3) is where real magic happens — /admin/ found at depth 0 triggers a Depth-1 enum on /admin/users, /admin/settings, etc.",
			"Aggressive level can hit 200k+ requests per target — use workspace concurrency caps + Burp Replay-Hit toggle to keep the proxy log manageable",
			"The 'Skip Path' feature stores user choices in SQLite per-workspace — next time the same path appears in any scan, it's auto-excluded",
			"Tech profiles automatically include 'general' — you never miss the basics like /admin /backup /test even when you've selected only 'wordpress'",
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
		Summary: "Audits HTTP security headers across multiple method/content-type variants, grades each URL A+ through F, and flags inconsistencies where the same header differs between methods (a common reverse-proxy misconfiguration). Checks 12 critical headers: Strict-Transport-Security, Content-Security-Policy, X-Frame-Options, X-Content-Type-Options, Referrer-Policy, Permissions-Policy, Cross-Origin-* triad, Cache-Control on sensitive endpoints, plus information-leak headers (Server, X-Powered-By, X-AspNet-Version). Cookie audit catches HttpOnly/Secure/SameSite omissions and overly broad Domain=, plus CORS reflection probes via the Origin header.",
		Tools: []ToolRef{
			{Name: "Go net/http", Desc: "Same probe mechanism as HTTP Method Tester — 30 probes per URL across 15 HTTP methods"},
		},
		Phases: []string{
			"Build the 11-variant probe matrix — GET, HEAD, POST (form/JSON/XML), PUT (form/JSON), PATCH (JSON), DELETE, OPTIONS — capture per-variant raw req/resp",
			"Filter to responses returning 200 OK — headers on a 405 are meaningless for end-user security",
			"Per-probe analysis — evaluate every header check against THIS probe's response. Lets the UI show 'GET passes HSTS but POST is missing it' instead of hiding behind a worst-case aggregate",
			"Worst-case aggregation — for the score card, take the WEAKEST value of each header across probes (a single misconfigured method ruins the grade — correct behaviour)",
			"Cookie audit — split joined Set-Cookie header into individual cookies, check HttpOnly/Secure/SameSite, flag overly broad Domain=, check __Host- / __Secure- prefix usage",
			"CORS reflection probe — send Origin: https://evil.example and observe Access-Control-Allow-Origin reflection",
			"Information-leak header check — Server/X-Powered-By/X-AspNet-Version disclose versions usable by attackers",
			"Score → grade — HIGH severity -20pts, MEDIUM -10, LOW -5, PASS 0. Grade A+ ≥95, A ≥85, B ≥75, C ≥60, D ≥40, F otherwise",
		},
		Notes: []string{
			"The 'cross-method inconsistency' finding is unique to this tool — most scanners only check GET. CSRF/auth endpoints often forget to set CSP on POST responses",
			"CSP audit looks for unsafe-inline / unsafe-eval / wildcard — does NOT execute the policy or validate report-uri targets",
			"HSTS detection includes max-age threshold checks — <6 months is LOW finding, <1 month is HIGH (browser cache won't last between visits)",
			"Permissions-Policy is opt-in; missing it is INFO not LOW since most sites don't need to disable geolocation/camera APIs",
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
		Summary: "Authenticated WordPress vulnerability scanner powered by the wpscan CLI and the WPScan API vulnerability database (CVE lookups for core / themes / plugins). Detects WordPress version, active theme + its CVEs, all enumerable plugins + their CVEs, exposed config backups, database dumps, and user accounts. The API token is bundled in-tree — no user configuration required — and you get the full commercial vulnerability data without subscribing yourself.",
		Tools: []ToolRef{
			{Name: "wpscan", Desc: "External Ruby tool — must be installed and on $PATH"},
			{Name: "WPScan API token", Desc: "Embedded authenticated access to the WPScan vulnerability database (40k+ CVEs)"},
		},
		Phases: []string{
			"Run wpscan with --enumerate vp,vt,cb,dbe (vulnerable plugins, vulnerable themes, config backups, db exports) and --plugins-detection mixed for max coverage",
			"WordPress fingerprint — version from generator meta, readme.html, login page, RSS feed",
			"Theme detection — readme.txt + style.css scrape; CVE lookup against the API DB",
			"Plugin enumeration — passive (manifest scan + bundle.js inspection) + aggressive (probe well-known plugin paths). Each plugin gets a version + CVE list",
			"Config backup probe — wp-config.php.bak, wp-config.txt, .wp-config.php.swp etc.",
			"Database export probe — *.sql, *.sql.gz in document root and common locations",
			"Parse JSON output and split findings into core / theme / plugin / info buckets with severity inherited from each CVE record",
		},
		Notes: []string{
			"Plugin enumeration is the bulk of runtime — large sites with 50+ plugins can take 5-10 minutes. Use Light scan for triage",
			"Hosted WordPress (WordPress.com, managed providers) often returns 403 to /wp-admin probes — the scan still works because passive detection (RSS, OPML, JSON-REST API) succeeds",
			"INFO-severity findings are filtered out of the default exports — they're enumeration data, not vulnerabilities. The 'Site Info' export section shows them when needed",
			"WPScan's vulnerability DB is the gold standard for WordPress — even Nuclei references it indirectly through the wordpress-* template tags",
			"The bundled API token is rate-limited shared across all scaNNer users — for heavy use, register a free token at wpscan.com and override via Settings (planned C-group)",
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
		Summary: "Multi-source subdomain enumeration combining 3 passive APIs (subfinder + amass + crt.sh + VirusTotal + Shodan + Censys), 2 active brute strategies (puredns/massdns against 18 global resolvers, then per-authoritative-NS focused brute), and altdns-style permutation of every discovered host. Three speed profiles: Fast (~2-5 min, passive + basic brute), Normal (~10-20 min, adds recon-ng + crt.sh deep), Deep (~30-60+ min, exhaustive). Detects wildcard DNS to suppress false positives.",
		Tools: []ToolRef{
			{Name: "puredns + massdns", Desc: "High-speed DNS brute-force with resolver validation; 18 hand-picked global resolvers for redundancy"},
			{Name: "subfinder", Desc: "ProjectDiscovery's passive enumeration (Censys, VirusTotal, ThreatCrowd, AnubisDB, etc.) — 30+ sources by default"},
			{Name: "amass", Desc: "OWASP's enumeration (DNS data aggregators, certificate transparency, WHOIS)"},
			{Name: "crt.sh", Desc: "Certificate Transparency log query — finds every host that has ever been issued a TLS cert for the apex"},
			{Name: "VirusTotal API", Desc: "Optional — pulls passive DNS from VT's resolutions endpoint when Settings has a key"},
			{Name: "Shodan / Censys", Desc: "Optional passive sources — adds hostnames from internet-wide scans when keys are configured"},
			{Name: "recon-ng", Desc: "Hackertarget and ThreatMiner modules (Normal/Deep speed only)"},
		},
		Phases: []string{
			"Authoritative nameserver discovery — pull NS records for the apex. These are the canonical sources of truth for the zone",
			"Passive phase (parallel) — subfinder + amass + crt.sh always run; recon-ng + VT + Shodan + Censys join in Normal/Deep when configured",
			"Active brute phase — puredns + massdns against 18 resolvers using the user's wordlist (defaults to SecLists DNS-medium)",
			"NS-specific brute — query each authoritative NS DIRECTLY (bypasses caching middleboxes; catches names that exist only on the target's own resolvers)",
			"Permutation generation (B8) — for every passive+brute hit, derive variants: -staging, -dev, -test, -prod, 1-9 suffix, common-word injection. Re-probe each against the same resolver set",
			"Resolution + wildcard detection — every survivor gets resolved to IPs; the resolver responses are cross-checked against a wildcard baseline (random.example.com) to mark wildcard-cn responders",
			"Output dedup — same hostname seen from multiple sources gets ONE row with all sources concatenated",
		},
		Notes: []string{
			"Custom resolver list lives at data/resolvers.txt — bring your own corporate resolvers to discover internal-only names",
			"Wildcard DNS detection is essential — sites using *.example.com → some-cdn-host will otherwise produce hundreds of false positives",
			"Deep mode does a recon-ng tour that can take 30+ minutes alone — only use it when you have time AND the target is in-scope",
			"VirusTotal API key is shared with the rate-limited free tier (500 lookups/day) — pace yourself across multiple domains",
			"crt.sh is rate-limited via Cloudflare — bursts of >5 parallel queries trigger 503s; the scanner retries with exponential backoff",
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
			{Name: "Nuclei template repo", Desc: "9000+ community templates auto-updated daily; -ut flag pulls latest"},
		},
		Phases: []string{
			"Optional template update — runs `nuclei -ut` BEFORE the scan to pull the latest templates. Skip for repeat runs to save 30 seconds",
			"Compose CLI invocation — -l urlfile -jsonl -silent -include-rr -timeout 5 -retries 1, plus user-selected -severity / -tags / -t (specific templates)",
			"Emit the exact command line into the scan's 'Commands run' panel — matches the convention used by nmap modules so the user can reproduce in their own terminal",
			"Stream stdout JSONL — every line is one finding; the stderr pipe is drained concurrently to prevent the well-known Go-exec deadlock when nuclei emits verbose stderr",
			"Per-finding: parse the rawFinding struct, convert to our Finding shape, attach to the matching input URL via host/MatchedAt longest-prefix match",
			"Live UI update — partial result is rewritten every 5 findings so the user sees activity without waiting for the full scan",
			"On exit, non-zero return is normal when no findings; only surface ExitInfo when ctx.Err() is nil AND zero findings (indicates real misconfiguration)",
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
			{Name: "nmap", Desc: "Industry-standard network mapper. Must be on $PATH. Recommended ≥7.9 for modern OS detection"},
		},
		Phases: []string{
			"Parse target input — accepts single IP, CIDR (10.0.0.0/24), range (10.0.0.1-50), or hostname",
			"Pass 1 (with discovery) — nmap with default -PE -PA80,443 host discovery + selected port set (Common/Custom/Range/Full)",
			"For each host in Pass 1: record host_up, ping_reachable, open ports (with state filtered/closed/open)",
			"If host responded and has ≥1 open port → stop. We have all the info we need",
			"Pass 2 (-Pn) — only for hosts that did NOT respond to ping in Pass 1. Skips host discovery, jumps straight to port scan. Detects firewalls dropping ICMP",
			"Mark host as icmp_filtered when it answers on -Pn but not on ping — pentest-worthy because the firewall config is leaking information about target presence",
			"Aggregate — per-host row with host_up, ping_reachable, icmp_filtered, open_count, list of open ports + their state",
		},
		Notes: []string{
			"-Pn is slower than default discovery on dead hosts — that's why we run it only for the no-response cases. A /24 with mostly-down hosts: Pass 1 = 30s, Pass 2 = 5 min",
			"Common = top 1000 ports (nmap's default), Range/Custom let you target known service ports, Full = 1-65535 (slow but exhaustive)",
			"CIDR /16 (65k hosts) is supported but takes hours — use only when authorized and time-permitting",
			"icmp_filtered is the #1 signal of 'serious target' — proper firewall config drops ICMP but allows specific TCP, which means there IS something worth protecting behind",
			"Output feeds portservice (deep scan with -sV + NSE) — discovery first, deep scan second is the classic recon flow",
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
		Summary: "Multi-phase nmap scan: two-pass host discovery (ping + -Pn) → version detection (-sV) → curated NSE vuln scripts → follow-up script pass on newly-detected services. Optional UDP scan (-sU) catches DNS/SNMP/NTP/NetBIOS that TCP misses. Optional 'Deep' script depth adds the intrusive/fuzzer/exploit NSE categories. Optional brute-force wordlists activate the brute/auth NSE categories. EXTERNAL and DOS categories are hard-excluded (OPSEC + crash risk). Per-stage concurrency slider (1-50 hosts in parallel).",
		Tools: []ToolRef{
			{Name: "nmap -sV", Desc: "Version detection probes — matches banners against nmap's 2500+ service signatures"},
			{Name: "nmap NSE", Desc: "Nmap Scripting Engine — 600+ scripts across 14 categories. scaNNer runs a vetted subset (see 'NSE Category Coverage' below)"},
			{Name: "nmap -sU (optional)", Desc: "UDP scan pass for DNS/SNMP/NTP/DHCP/NetBIOS services — off by default (RFC 1812 rate-limits make UDP scans dramatically slower)"},
		},
		Phases: []string{
			"Phase 1 — Discovery: two parallel nmap passes per host (with ping + -Pn). The -Pn pass surfaces ICMP-filtered hosts that the ping pass thought were down. Optional third UDP (-sU) pass when the user enables it",
			"Phase 1.5 — Union: merge results from ping/-Pn/UDP. UDP ports merge with proto='udp' marker so renderers can group by protocol",
			"Phase 2 — Version detection + curated NSE scripts: -sV --version-intensity 5 + service-specific NSE scripts (ssl-heartbleed for SSL/TLS, http-shellshock for HTTP, smb-vuln-ms17-010 for SMB, etc.). Default 'Safe' depth = curated list only; 'Deep' depth adds intrusive+fuzzer+exploit categories",
			"Phase 2 — Brute/auth: ONLY when user supplies both username AND password wordlists. Adds brute,auth categories + --script-args userdb=<tmp>,passdb=<tmp>,brute.firstonly=true. Stops at first valid cred per service",
			"Phase 3 — Follow-up: for services that Phase 2 newly identified (e.g. Phase 1 saw 8080/tcp but Phase 2 confirmed it's http), run any extra scripts that weren't run for that service yet",
			"Per-port output capture: state (open/filtered/closed), service name, product, version, extra info, tunnel (ssl/raw), CPE, full NSE script output verbatim",
			"HTTPS auto-detection — port 443 / 8443 with nmap-reported tunnel=ssl → marked as TLS in result",
			"Per-script structured extraction — `smb-vuln-ms17-010` reports VULNERABLE/NOT VULNERABLE → parsed into structured findings, not raw text",
		},
		Notes: []string{
			"NSE Category Coverage — what runs by default vs. what's behind the 'Deep' toggle vs. what's NEVER enabled:",
			"  ✓ default (always) — http-title, http-headers, ssh-hostkey, smb-os-discovery, ssl-cert, dns-recursion, etc. Fingerprint/banner data",
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
			"Brute/auth lockout note — 'brute.firstonly=true' is set so brute stops at the first valid cred per service. Still: against tightly-configured AD, three wrong attempts can lock out the account. Use service-account creds, not user creds",
			"Concurrency slider (1-50, default 10) controls hosts-in-parallel. Each host = 2-3 nmap subprocesses depending on UDP toggle. Above 25 needs `ulimit -n 65535` and dedicated VPS",
			"Service version detection occasionally returns wrong versions for heavily-customised services (nginx behind WAF, modified Apache modules) — verify before mapping to CVEs",
			"Output is large — a /24 with -sV + Deep + brute can produce 50-200 MB of nmap output. The scanner truncates per-port script output to 24 KB to keep the DB manageable",
		},
		References: []ReferenceRef{
			{Label: "Nmap NSE category reference", URL: "https://nmap.org/book/nse-usage.html#nse-categories"},
			{Label: "Vulnerability scripts list", URL: "https://nmap.org/nsedoc/categories/vuln.html"},
			{Label: "Service detection internals", URL: "https://nmap.org/book/vscan.html"},
			{Label: "Brute scripts + --script-args", URL: "https://nmap.org/nsedoc/lib/brute.html"},
		},
	},

	// ========================================================================
	// SMB Enum
	// ========================================================================
	"smbenum": {
		Summary: "SMB enumeration triple-stack — nmap's smb-* NSE scripts (shares, OS, MS17-010, signing), smbclient anonymous listing (or authenticated), and enum4linux for user/group/RID/password-policy extraction. Optional 'share content walk' phase recursively lists every readable share, filtered for interesting filenames (.env, .ssh, .bak, .sql, .kdbx, .pst, *backup*). Catches the classic Windows pentest wins: anonymous share access, MS17-010 unpatched hosts, default credentials, exposed user lists for password spraying.",
		Tools: []ToolRef{
			{Name: "nmap (smb-* NSE)", Desc: "Runs smb-os-discovery, smb-enum-shares, smb-enum-users, smb-enum-sessions, smb-enum-domains, smb-protocols, smb-security-mode, smb-vuln-ms17-010, smb2-security-mode"},
			{Name: "smbclient", Desc: "Anonymous / authenticated share listing (-L); content walk via -c \"recurse;ls\""},
			{Name: "enum4linux", Desc: "Veteran tool (Perl) — users, groups, RIDs, password policy, share permissions"},
		},
		Phases: []string{
			"TCP/445 reachability — nmap -p 445 -Pn. If closed, the host is skipped entirely (no point in NSE/smbclient)",
			"nmap smb-* NSE bundle — runs the entire SMB script set in one invocation, captures structured per-script output",
			"smbclient -L (or -L -U user%pass) — share listing. With ENUMERATION-FRIENDLY share names (FILES$, BACKUP$, IT, USERS) → flag as 'interesting'",
			"enum4linux -a — full enumeration including pwInfo (password policy), RID cycling, group/user lists",
			"Share content walk (optional, B14 enhancement) — for each readable share except IPC$/ADMIN$/print$: `smbclient //h/s -c \"recurse;ls\"`",
			"Interesting-file filter on the walk output — patterns: .env, .ssh/, .bak, .sql, *backup*, .kdbx, .pst, *password*, *cred*",
			"Per-share permission summary — read/write detection via attempted ls + create-temp test",
		},
		Notes: []string{
			"Anonymous null-session is the default — provides only public info but no credentials needed. Authenticated mode unlocks user lists and full share content",
			"MS17-010 (EternalBlue) detection is the killer NSE script — patches dated >2017 should have closed it, but unpatched 2016-vintage Windows boxes are still surprisingly common in enterprise networks",
			"Share-walk can produce thousands of file paths on chatty file servers — the interesting-file filter cuts ~99% of noise",
			"enum4linux only works on Samba/Windows SMB1; on SMB2/SMB3-only hosts it produces partial output. Use rpcclient + nmap fallback when enum4linux blanks out",
			"Authentication caveat: failed-login lockouts apply — three wrong attempts can trigger account lockout on tightly-configured AD. Use known-good service-account creds, NOT user creds",
		},
		References: []ReferenceRef{
			{Label: "MS17-010 EternalBlue details", URL: "https://docs.microsoft.com/en-us/security-updates/SecurityBulletins/2017/ms17-010"},
			{Label: "enum4linux source", URL: "https://github.com/CiscoCXSecurity/enum4linux"},
			{Label: "OWASP SMB testing", URL: "https://owasp.org/www-project-web-security-testing-guide/v42/4-Web_Application_Security_Testing/01-Information_Gathering/02-Fingerprint_Web_Server"},
		},
	},

	// ========================================================================
	// Service Brute Forcer
	// ========================================================================
	"brutef": {
		Summary: "Hydra-powered credential brute-force across ten common services (SSH, FTP, RDP, SMB, MSSQL, MySQL, PostgreSQL, VNC, LDAP, Telnet). Streams successful logins as they're discovered (live UI updates), includes built-in default-credentials list per service (admin:admin, root:toor, sa/postgres/mysql, vendor-specific pairs), supports username-only spray attacks (one user × big password list — bypass account lockout via low velocity). Stop-on-first-hit by default so dictionary scans terminate the moment a credential lands.",
		Tools: []ToolRef{
			{Name: "hydra", Desc: "THC Hydra — the classic login-cracker. Must be on $PATH"},
			{Name: "Built-in default-cred lists (B12)", Desc: "Per-service vendor defaults: SSH (17 pairs), FTP (9 pairs), RDP (8 pairs). Auto-prepended when 'Include defaults' is on"},
		},
		Phases: []string{
			"Materialize username + password lists into hydra-format temp files",
			"Optional: prepend default-credential pairs to the wordlists when 'Include defaults' toggle is on",
			"Spawn hydra per (target, protocol) tuple with concurrency capped via workspace settings",
			"Parse hydra's stdout line-by-line — extract [port][service] login: pass format for hits",
			"Track attempt counter via hydra's -V verbose output — gives the user live 'X of Y attempted' progress",
			"Stream successful login findings to the UI immediately (don't wait for hydra to finish)",
			"On finish, write the full result with all discovered credentials",
		},
		Notes: []string{
			"ALWAYS confirm authorization in writing before brute-forcing live systems. Account lockouts can trigger DoS-class outages on production AD",
			"Stop-on-first-hit (-f) is on by default — usually you want to stop and pivot once you have credentials. Disable when running compliance audits that need every weak account flagged",
			"Single Username mode (one user × full password list) is the safest attack against lockout-policy targets — spray slowly: 5 attempts/account/hour stays under typical lockout thresholds",
			"Hydra's RDP module is fragile against modern Windows (NLA enabled) — for hardened targets use Crackmapexec or NetExec's rdp scanner instead",
			"Default-cred mode is the FIRST thing to try — every router/IoT/legacy device has a documented default that admins forget to change. Vendors with known defaults: D-Link, TP-Link, Cisco, Huawei, Hikvision",
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
		Summary: "Community-string brute (v1/v2c) or USM-based v3 enumeration of an SNMP agent. v2c phase tries 14 default communities (public, private, manager, admin, router, etc.) via onesixtyone (fast UDP burst) with snmpget fallback. v3 mode skips brute entirely — connects via -u USER -l LEVEL -a SHA -A PASS -x AES -X PASS for User-based Security Model authentication. Once a valid auth is found, walks system identity OIDs (descr, uptime, contact, name, location) plus user-selected branches (interfaces, processes, software, users, tcp, udp, installed-services).",
		Tools: []ToolRef{
			{Name: "onesixtyone", Desc: "High-speed UDP community brute (preferred, falls back to snmpget per-string if absent)"},
			{Name: "snmpget / snmpwalk", Desc: "Net-SNMP CLI tools. Must be on $PATH. v3 USM is invoked via -v3 -u/-l/-a/-A/-x/-X flags"},
		},
		Phases: []string{
			"Decide auth mode — V3User set → v3 USM (skip community brute); ForcedCommunity set → use as-is; otherwise → brute the community list",
			"v2c brute — onesixtyone batched UDP probe with the candidate community list (covers 14 defaults in <2 seconds against a /24)",
			"Pull system identity OIDs always — 1.3.6.1.2.1.1.1.0 (sysDescr), 1.3.6.1.2.1.1.3.0 (sysUpTime), 1.3.6.1.2.1.1.4.0 (sysContact), 1.3.6.1.2.1.1.5.0 (sysName), 1.3.6.1.2.1.1.6.0 (sysLocation)",
			"Walk selected branches — interfaces (1.3.6.1.2.1.2.2), processes (1.3.6.1.2.1.25.4.2), software (1.3.6.1.2.1.25.6.3.1.2), users (1.3.6.1.4.1.77.1.2.25), tcp (1.3.6.1.2.1.6.13), udp (1.3.6.1.2.1.7.5), installed-services",
			"Truncate each walk to 24 KB to keep DB rows manageable on chatty agents (large process tables can hit megabytes)",
		},
		Notes: []string{
			"Default communities 'public' and 'private' are STILL surprisingly common in 2026 — every embedded device, every printer, every legacy switch",
			"Windows hosts running SNMP often expose the full process list via 1.3.6.1.2.1.25.4.2 — a goldmine for lateral-movement targeting",
			"v3 noAuthNoPriv mode is essentially v2c with extra steps — flag it as a finding even when the rest of the policy is solid",
			"snmpwalk against a populated table can DoS slow management agents — use SkipBrute mode (single 'public' probe) for sensitive targets",
			"User-account enumeration via 1.3.6.1.4.1.77.1.2.25 is a Windows-specific OID — Linux/BSD SNMP daemons return empty here",
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
		Summary: "Multi-source WHOIS + ASN intelligence. For domains: runs whois against the registrar's database, extracts registrant org, registrar, name servers, creation/expiration dates. For IPs: pulls AS owner, AS number, AS prefixes (full v4/v6 routing scope), country, registry (ARIN/RIPE/APNIC/AfriNIC/LACNIC). The 'AS prefixes' output is the asset-discovery foundation — once you have the ASN, you have every IP block owned by that org.",
		Tools: []ToolRef{
			{Name: "whois", Desc: "Classic UNIX whois client. Must be on $PATH"},
			{Name: "ipinfo.io / RIPEstat APIs", Desc: "ASN-to-prefix lookups when whois output is incomplete"},
		},
		Phases: []string{
			"Classify input — domain (has TLD) → registrar WHOIS; IP → registry RDAP/WHOIS",
			"Domain path — run whois <domain>, parse registrant fields, name servers, expiry. Some TLDs (e.g. .io, .co.uk) require thin/thick lookup chains",
			"IP path — registry detection from first octet, then RDAP query if available (better structured), whois fallback otherwise",
			"ASN extraction — pull ASN from whois output. Then query the AS prefix list (every CIDR the ASN advertises)",
			"Organization correlation — same org may own multiple ASNs (Cloudflare AS13335 + AS209242 + AS395747, etc.) — surface them all",
			"Structured output — Summary (org/asn/country), Records (every key:value from whois), Prefixes (CIDR list for AS-scoped asset enum)",
		},
		Notes: []string{
			"Registrar privacy redaction (Whois Privacy Service, Domains By Proxy, etc.) blanks the registrant fields — that's expected. Pivot via certificate transparency (dnsenum) instead",
			"GDPR-related redactions hide EU domain registrants since 2018 — only the registrar is publicly visible. Same workaround applies",
			"ASN-driven asset discovery is the 'big map' for engagement planning — feed the prefixes back into dnsenum / hostdiscovery for the full surface",
			"WHOIS query rate limits are strict (1 query/3s typical) — bulk lookups burst-fail. The scanner respects retry-after where the server gives one",
			"Some country TLDs (.fr, .ar) have non-standard WHOIS formats — the parser falls back to raw output dump when structured parsing fails",
		},
		References: []ReferenceRef{
			{Label: "RFC 3912 — WHOIS protocol", URL: "https://datatracker.ietf.org/doc/html/rfc3912"},
			{Label: "RFC 7480 — RDAP (modern replacement)", URL: "https://datatracker.ietf.org/doc/html/rfc7480"},
			{Label: "Hurricane Electric BGP toolkit", URL: "https://bgp.he.net/"},
		},
	},

	// ========================================================================
	// Email Harvester
	// ========================================================================
	"emailharvest": {
		Summary: "OSINT email enumeration via multiple sources — Hunter.io (when key set), HIBP (Have I Been Pwned breach lookup), bing/google site: dorks, and public-page scraping. Outputs per-domain email list + host correlation + breach data. Feeds password-spray attacks (authtest module) and phishing simulation planning.",
		Tools: []ToolRef{
			{Name: "Google/Bing dork queries", Desc: "site:<domain> '@<domain>' searches — bulk-recover emails leaked in public web pages"},
			{Name: "HIBP API (optional)", Desc: "Per-email breach lookup — reveals which leaks the address has appeared in"},
		},
		Phases: []string{
			"Per-domain search via Bing — site:<domain> intext:@<domain>; paginate through 10 pages of results",
			"Scrape email regex from each result snippet, dedup against running set",
			"For each discovered email, optionally hit HIBP /breachedaccount/{email} (rate-limited 1/1.5s) to enumerate past breaches",
			"Track per-email: source (which dork found it first), first-seen URL, breach count, breach names + data classes",
			"Aggregate hosts mentioned alongside emails — often reveals corporate subdomains via signature blocks ('Acme Corp · sales@acme.com · https://portal.acme.com')",
		},
		Notes: []string{
			"Bing rate-limits aggressive scraping — large enumerations slow to 1 query/3s. The scanner respects retry-after headers",
			"HIBP requires a paid API key for high-volume use; without it, fall back to k-anonymity password endpoint (no PII)",
			"Public emails on a corporate domain → use the password spray module sparingly (lockout policies will trigger)",
			"GDPR/data-protection compliance — emails returned MAY be personal data depending on jurisdiction. Treat as sensitive even though discovered via public sources",
			"Combine with the leakscan module — emails harvested here can be cross-referenced against secrets leakage on GitHub/Pastebin",
		},
		References: []ReferenceRef{
			{Label: "Have I Been Pwned API docs", URL: "https://haveibeenpwned.com/API/v3"},
			{Label: "theHarvester (the reference tool)", URL: "https://github.com/laramies/theHarvester"},
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
			"Parse up to MaxFiles results (default 50), construct raw.githubusercontent.com URLs from the html_url",
			"Optionally download each file (FetchSnippets toggle) — up to 256 KB body per file",
			"Run secretPatterns regex set against each downloaded body — extract matches with ±40-char context for the Sample field",
			"In B13 widened mode, ALSO query Pastebin scrape API + Wayback CDX for the same query — additional context not on GitHub",
			"Per-source result: query string + hit list + match count, ready for the export's 'Leak Hits' section",
		},
		Notes: []string{
			"GitHub Code Search REQUIRES authentication for unscoped queries (422 otherwise) — drop in a personal access token via Settings for production use",
			"Common queries: organization name, internal hostname, product code, customer ID. Avoid queries that match too broadly (e.g. 'AKIA' alone returns 100k+ results that aren't yours)",
			"Every secret hit IS the finding — there is no severity gradation. Treat all as CRITICAL until you've manually checked the file age and validity",
			"Pastebin paste IDs are unguessable, but psbdmp.ws indexes public listings — newer pastes (last 30 days) skew the results",
			"Wayback Machine CDX is the slowest source — many CDX queries time out on broad terms. Use specific subdomain queries (e.g. 'admin.example.com') for best signal",
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
		Summary: "Analyses JSON Web Tokens for cryptographic and configuration weaknesses, then generates forged attack tokens the user can paste back at the target to confirm exploitation. Detects: alg=none acceptance, weak HMAC secret (cracks via HS256 dictionary), kid header injection, jku header poisoning, RS256→HS256 confusion attacks, missing exp/iat claims, overly-long lifetimes, weak issuers, unsigned tokens, and 'unverified-on-server' signs. Attack-token generation is the difference vs other JWT tools — you get ready-to-paste payloads, not just findings.",
		Tools: []ToolRef{
			{Name: "Go crypto/hmac + crypto/sha256+sha512", Desc: "HMAC-SHA256/384/512 secret cracking (dictionary attack on HS256)"},
			{Name: "Built-in secret list", Desc: "Top-10k common secrets bundled — JWT_SECRET, secret123, key, your-256-bit-secret, etc."},
		},
		Phases: []string{
			"Parse the token — base64url-decode header + payload + signature. Extract alg, kid, jku, typ, iss, exp, iat, sub claims",
			"Algorithm audit — alg=none → CRITICAL (server may accept). alg=HS256 with kid header reflecting input → kid injection. alg=RS256 → attempt HS256 confusion forge",
			"HMAC secret crack (HS256/HS384/HS512) — try each candidate secret against the token's signature. Stops on first match",
			"Claim audit — exp missing or >>future → finding; iat skew >24h → finding; iss empty or 'test' → finding",
			"Attack token generation — for every detected weakness, mint a forged token: alg=none variant, alg confusion variant, kid-injection variant pointing at attacker-controlled file, jku poison variant with attacker JWKS URL",
			"Output — per-token Findings list (severity-labeled) + AttackTokens list (paste-ready)",
		},
		Notes: []string{
			"alg=none is the CRITICAL bug — surprisingly common in homegrown JWT libraries. Test the forged token against the server; if accepted, full auth bypass",
			"HS256 secret cracking is dictionary-only here — for longer dictionaries / actual brute, export the token and use hashcat -m 16500 with rockyou.txt",
			"kid injection works when the server uses the kid value as a file path or DB key without sanitization — generates 'kid: ../../etc/passwd' style payloads",
			"RS256→HS256 confusion exploits servers that accept algorithm parameter from the token header instead of enforcing server-side: attacker signs with the public key as if it were an HMAC secret",
			"jku/x5u/x5c header attacks are dangerous when present — server fetches a remote JWKS URL the attacker controls. Test with a controlled OOB collaborator URL (A9 module)",
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
		Summary: "Brute-force discovery of hidden query parameters and form fields. Sends 6000+ candidate parameter names per URL (Arjun-style + custom wordlists), watches for status-code deltas, body-length deltas, response-time deltas, and reflection (parameter value echoed in response body). Detects parameters that influence server behaviour but aren't documented — these are pure XSS / SSRF / open-redirect / SQLi attack surface that other crawlers miss because they only walk visible HTML.",
		Tools: []ToolRef{
			{Name: "Go net/http", Desc: "High-concurrency probe loop with timing instrumentation"},
			{Name: "Built-in param wordlist", Desc: "Arjun + ParamMiner + custom merged list, 6000+ names tuned for web app frameworks"},
		},
		Phases: []string{
			"Baseline probe — request the URL with NO extra params. Record status, body len, response time, headers, body content (for reflection diffs)",
			"Batch probe — send chunks of 50-100 candidate params at a time as ?param1=test&param2=test&... (mass-probing reduces request count vs one-at-a-time)",
			"Status delta check — any chunk whose response differs from baseline gets bisected to identify the specific param that caused the change",
			"Length delta check — body length difference ≥ 30 bytes flags an interesting candidate (param made the page render differently)",
			"Reflection check — does the test value appear in the response body? Reflected param = XSS/HTML-injection candidate",
			"Status-code-change check — 200→302, 200→500, 200→403 transitions are high-signal (param triggered server-side logic)",
			"Per-finding output — URL, parameter name, method, status delta, length delta, reflected y/n, response-time delta, note",
		},
		Notes: []string{
			"Bisection is what makes this scale — 6000 params per URL would be 6000 requests; chunking to 100 + bisecting on signal cuts that to ~120 requests in the typical case",
			"Reflection detection is XSS pre-work — any reflected param is the next thing to fuzz with payloads (manually or with sqlmap/dalfox)",
			"Status-code transitions to 5xx may indicate the param triggered an unhandled exception — query the server logs (if you have access) for the stack trace",
			"Body-length deltas <30 bytes are noise — server timestamps / nonces shift output between requests. Reflection + status-delta are the trustworthy signals",
			"Concurrency-aware: respects workspace caps. On rate-limited targets, drop to 5-10 concurrent for slow-burn discovery",
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
		Summary: "Stress-tests an endpoint with N parallel requests to detect race conditions (e.g. coupon redemption, balance transfer, voting), rate-limit thresholds, and back-end stability. Fires the same request M-times-N (M = burst size, N = number of bursts) and records every response — duplicate winning responses across requests in a single burst usually means race conditions exist. Pair with a target that has side-effects (purchase, vote, redeem-once) to confirm exploitation.",
		Tools: []ToolRef{
			{Name: "Go net/http + goroutines", Desc: "Spawns N goroutines that each fire M requests; uses sync barriers to align burst start times to within microseconds"},
		},
		Phases: []string{
			"Build a single canonical request — method, URL, headers, body (often with a CSRF or auth token captured from the user's session)",
			"Spawn N goroutines that pre-build their identical clones of the request",
			"Synchronize start — all goroutines wait at a sync barrier; the controller releases them at exactly the same moment",
			"Each goroutine fires its M requests, captures response status, body, headers, request duration",
			"Aggregate — group responses by (status, body hash) — identical responses across N concurrent requests for a single-use endpoint is the race finding",
			"Per-response timing histogram — surfaces rate-limit thresholds (response time spikes from 50ms baseline to 5000ms when the rate limit kicks in)",
		},
		Notes: []string{
			"Race conditions in business logic (coupon use, voucher redemption, voting, balance transfer, account creation) are the #1 use case — N=20 to 100 reveals most race issues",
			"NOT a load-test tool — for capacity benchmarking use k6 or wrk. This tool is precision-targeted at race conditions",
			"NEVER test rate-limit thresholds against production without WRITTEN AUTHORIZATION — accidentally tripping anti-DDoS systems can trigger billing or legal alerts",
			"Side-effect endpoints (purchase, vote, file-upload) need to be tested with rollback ability — your authorized engagement scope must cover any state changes",
			"If responses cluster bimodally (some 200s, some 429s within a single burst), you've hit the rate limit MIDWAY through the burst — note this in the report as a partial finding",
		},
		References: []ReferenceRef{
			{Label: "OWASP Race Condition Cheat Sheet", URL: "https://owasp.org/www-community/vulnerabilities/Race_Condition_Vulnerability"},
			{Label: "Portswigger race condition labs", URL: "https://portswigger.net/web-security/race-conditions"},
		},
	},

	// ========================================================================
	// Advanced Web Application Scanner Suite
	// ========================================================================
	"advancedweb": {
		Summary: "Orchestrates 10+ web-focused modules in a single chained pipeline against one target. Stages 1-3 (whois → dns → httpx) build the asset map, stage 6 (techdetect) drives stage 8's wordlist selection (PHP target → PHP wordlist), stage 8 (direnum ↔ spider) cross-feeds discoveries (direnum finds /admin → spider crawls it → direnum re-probes spider's findings — up to 3 iterations), stages 10-11 (httpmethods, secheaders) test only the URLs that earlier stages confirmed alive. Result: one consolidated report for one target, with each stage informed by the previous.",
		Tools: []ToolRef{
			{Name: "Internal orchestrator", Desc: "Sequential goroutine that calls each module's native Scan() function in order"},
			{Name: "TechDetect → DirEnum profile map", Desc: "Auto-selects WordPress / Drupal / Joomla / Apache / IIS / PHP / Java / Python / Node profiles based on stage 6 findings"},
		},
		Phases: []string{
			"Stage 1 (WHOIS/ASN) — only runs for domain targets, skipped for URLs",
			"Stage 2 (DNS Enum) — passive + brute; provides subdomain list to feed httpx",
			"Stage 3 (HTTPX) — probe every discovered subdomain on common ports; surfaces alive services",
			"Stage 4 (SSL/TLS) — TLS audit per alive Service; finds cipher/protocol issues across the asset map",
			"Stage 5 (WAF) — fingerprint each alive URL's edge defenses",
			"Stage 6 (TechDetect) — fingerprint the stack of every alive URL; feeds profile selection downstream",
			"Stage 7 (Nuclei) — CVE / misconfig scan against the alive URL set",
			"Stage 8 (DirEnum ↔ Spider iterative cross-feed) — direnum runs with profiles from stage 6, finds dirs; spider crawls those dirs (depth 1); direnum re-probes spider's new dirs; loop up to 3 times or until no new dirs",
			"Stage 10 (HTTP Methods) — fires against the union of stage 3 alive URLs + stage 8 directory discoveries",
			"Stage 11 (Security Headers) — same URL source as stage 10; user picks GET/POST/PUT method variants",
		},
		Notes: []string{
			"Stage 9 (paramdisc) was excluded — it produces too much noise for an unattended suite. Run it separately on URLs of interest",
			"URL inputs skip stages 1-3 with a 'skipped: input is URL' annotation; IP-only inputs are REJECTED at submit (web suite needs hostnames)",
			"Iterative cross-feed terminates early when spider finds nothing new — keeps reasonable bounds on runtime for site maps without many sub-dirs",
			"Per-stage results embed the native module's results template inline — no special UI for the suite, just stacked module views",
			"Suite is intentionally NOT modifiable mid-flight — stop button cancels the whole chain. For granular control, run modules individually",
		},
		References: []ReferenceRef{
			{Label: "OWASP Testing Guide v4.2", URL: "https://owasp.org/www-project-web-security-testing-guide/v42/"},
		},
	},

	// ========================================================================
	// Subdomain Takeover (A1)
	// ========================================================================
	"takeover": {
		Summary: "Detects dangling subdomain CNAMEs pointing at deprovisioned third-party services (S3, GitHub Pages, Heroku, Azure, Vercel, Netlify, Fastly, Shopify, Tumblr, Squarespace, etc.). Resolves each candidate subdomain's CNAME, matches the tail against 27 provider signatures, then HTTP-probes both schemes and looks for service-specific error messages ('NoSuchBucket', \"There isn't a GitHub Pages site here\", 'No such app' for Heroku, etc.). A hit means the attacker can register the upstream service name and claim the dangling subdomain.",
		Tools: []ToolRef{
			{Name: "Go net (LookupCNAME)", Desc: "Native CNAME resolution"},
			{Name: "Built-in provider signature DB", Desc: "27 provider fingerprints with CNAME tails, body markers, HTTP statuses, severity ratings"},
		},
		Phases: []string{
			"For each input subdomain, query CNAME record via Go resolver. If empty/equal-to-self → record 'no_cname' and skip",
			"Resolve to IPs as well — provides context (alive IPs = service still up; no IPs = likely candidate)",
			"Match CNAME tail against signature DB (S3 bucket suffix patterns, github.io, herokuapp.com, azurewebsites.net, etc.)",
			"If no signature match → status 'resolved_normal' (CNAME points to something we don't recognize)",
			"HTTP probe — try HTTPS then HTTP. Status + body capture",
			"Body marker check — substring-search for provider's specific 'not found' message",
			"Mark as 'vulnerable' when status matches signature filter AND body marker found. Mark 'candidate' if CNAME matches but probe fails (manual verification needed)",
			"Optional dnsenum import — pull subdomains directly from a previous DNS Enumerator scan with one click",
		},
		Notes: []string{
			"S3 takeovers are the #1 hit — every dev team prototypes with a bucket then deletes it without removing the CNAME. CRITICAL severity, easy to verify (register the bucket name in your AWS account)",
			"GitHub Pages takeovers require both: a CNAME pointing at github.io AND no claimed repository serving that custom domain. Severity HIGH because attacker needs a GH account",
			"Statuspage / Netlify require email verification on takeover — flagged LOW because exploitation isn't automatic",
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
		Summary: "Probes CORS handling for 9 misconfiguration patterns: arbitrary origin reflection (server echoes any Origin into ACAO), wildcard subdomain trust (any *.victim.com works), regex bypass via suffix/prefix attach (victim.com.attacker.tld), null origin trust (sandboxed iframes get full access), scheme downgrade (http origin trusted on https endpoint), comma injection, trailing-dot bypass, look-alike domain trust. Wildcard ACAO + credentials = CRITICAL — any site can read authenticated responses.",
		Tools: []ToolRef{
			{Name: "Go net/http", Desc: "Each test fires a separate GET with a different Origin header value"},
		},
		Phases: []string{
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
		Summary: "Fuzzes 26 redirect-candidate query parameters (next, url, return, redirect, redirect_uri, goto, dest, callback, etc.) with 10 bypass payload variants per param. Variants exercise parser quirks: protocol-relative (//evil.com), backslash variants (\\\\evil.com), userinfo@host (https://example.com@evil.com), URL-encoded (%2F%2Fevil.com), comma/space injection. Detects open-redirect-to-external — a CVE-class issue used for phishing and OAuth-flow hijacking.",
		Tools: []ToolRef{
			{Name: "Go net/http", Desc: "Custom client with CheckRedirect = ErrUseLastResponse (don't follow — we need the Location header)"},
		},
		Phases: []string{
			"For each input URL, iterate the candidate parameter list (default 26 names + user-supplied additions)",
			"For each (param, payload) combo, inject ?param=<payload> while preserving the URL's existing query",
			"Issue GET, capture raw req/resp, check status (must be 301/302/303/307/308 for a redirect)",
			"Inspect the Location header — does it point at the evil sentinel host? Match strict prefix (scheme://host), protocol-relative (//host), backslash variants, or userinfo (@host) bypass",
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
		Summary: "Maps detected technologies + versions onto a curated database of 35 high-impact CVEs spanning Apache HTTPD, nginx, PHP, OpenSSL, OpenSSH, Tomcat, Spring, IIS, WordPress, Drupal, Jenkins, GitLab, Confluence, Log4j, Exchange, VMware Workspace ONE, MOVEit, ManageEngine, Citrix ADC, Fortinet FortiOS, etc. Handles dotted-numeric version ranges with [lo, hi] inclusive bounds and case-insensitive product aliasing (apache → 'apache http server', etc.). Feeds direct from techdetect's output with one click.",
		Tools: []ToolRef{
			{Name: "In-tree curated CVE database", Desc: "35 pentest-relevant landmark CVEs; product aliases map techdetect's wording onto canonical product names"},
		},
		Phases: []string{
			"For each input (product, version, source URL), call canonicalProduct() to normalize 'apache' / 'httpd' onto canonical 'apache http server'",
			"Iterate the CVE database — for each record matching the canonical product name, evaluate the [AffectedLo, AffectedHi] version range",
			"Version range check — parse dotted-numeric (2.4.49 → [2,4,49]), strip non-numeric suffixes (p1, -rc1), compare element-wise",
			"If version is empty (techdetect didn't capture one) → skip the CVE silently (don't false-positive). UI shows 'no version' badge for that input",
			"Emit a Match record per CVE hit with severity, CVSS, description, NVD reference URL",
			"Bucket matches by severity for the summary view (CRITICAL count, HIGH count, etc.)",
			"Import-from-techdetect dropdown — one-click pulls every (Name, Version) pair from a previous techdetect scan as inputs",
		},
		Notes: []string{
			"The curated DB is intentionally small (35 entries) — focused on pentest-relevant CVEs, not 1000+ low-severity bugs",
			"Version parsing is conservative — '2.4.49' and '2.4.49-Debian' both reduce to [2,4,49]. Distro suffixes don't break matching",
			"If a CVE applies to a product not yet in productAliases, add an alias (or open an issue) — the matching is purely table-driven",
			"For broader coverage, the planned successor will pull from NVD's JSON feed (~250k CVEs) — present implementation favors precision over recall",
			"Source URL (where the tech was detected) flows through to the Match record — pentesters can click straight to the affected endpoint for proof",
		},
		References: []ReferenceRef{
			{Label: "NVD (National Vulnerability Database)", URL: "https://nvd.nist.gov/"},
			{Label: "CVE Details — searchable view of NVD", URL: "https://www.cvedetails.com/"},
			{Label: "CPE 2.3 product naming standard", URL: "https://csrc.nist.gov/projects/security-content-automation-protocol/specifications/cpe"},
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
		Summary: "Probes login flows for 4 classes of auth weakness: weak credentials (cartesian brute of small user×pass lists, with auto-detection of failed-login response shape), username enumeration (same wrong password against multiple users — different response sizes/status codes signal which usernames are valid), session fixation (session cookie should rotate on auth success), and password-reset token entropy (tokens shorter than 10 chars or with shared common prefix = predictable / brute-forceable). Auto-infers the 'invalid login' marker from baseline response — works without user configuration in most cases.",
		Tools: []ToolRef{
			{Name: "Go net/http", Desc: "Form-POST + cookie tracking + body diffing"},
		},
		Phases: []string{
			"Baseline failed-login probe — send 'definitely-nonexistent-user' + 'wrong-pass' to learn the failure response shape (status, body length, body content)",
			"Failure-marker inference — if no FailMarker supplied, search baseline body for common strings ('invalid credentials', 'login failed', 'hatalı', 'incorrect password', etc.). Save as auto-detected marker",
			"User-enumeration probes — for each candidate user, send (user, fixed-wrong-password). Cluster responses by (status, body length / 64-byte bucket). ≥2 clusters = enumeration oracle",
			"Brute-force phase — cartesian user × password. Each attempt classified via heuristic: success marker present? failure marker absent? status changed (302/303 from 200 baseline)? body length delta >20%?",
			"Session fixation probe (optional) — GET login URL pre-auth, capture session cookie. Log in with discovered creds. GET again. If cookie didn't rotate → session fixation finding",
			"Password reset entropy probe (optional) — POST password-reset for 3 users, capture emitted tokens (via Location/body/Set-Cookie). Tokens <10 chars OR sharing ≥50% common prefix → weak token finding",
		},
		Notes: []string{
			"User-enumeration is THE most common login finding — 'invalid username' vs 'invalid password' messaging gives it away. Even response size deltas as small as 50 bytes (different error template) leak the signal",
			"Auto-detected failure markers cover Turkish ('hatalı', 'geçersiz') and English ('invalid credentials', 'login failed') — extend the inferFailMarker() list for other languages",
			"Session fixation is RARE on modern frameworks (Spring Security, Django Auth, Rails Devise all rotate by default). Found mainly in custom-built auth or legacy PHP / classic ASP apps",
			"Password reset entropy weakness leads directly to account takeover — short tokens or sequential tokens (containing timestamp) are brute-forceable",
			"NEVER run against production with real-user passwords without WRITTEN AUTHORIZATION and a documented rollback plan for lockouts",
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
		Summary: "Queries Shodan and Censys for org/ASN/SSL-cert-scoped internet-facing assets, enriching local discovery (dnsenum) with internet-wide passive data. Returns per-host (IP, port, hostname, OS, ASN, org, country, product banner, all domain names CT logs have associated with this IP). Massively expands the attack surface map — a target org's main domain often hides hundreds of forgotten dev/staging/IoT hosts that only Shodan/Censys see.",
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
			"Open the listener — bind to the user-supplied :port (or :0 for auto-port). The 'Public host' form field is what appears in the URL; the listener binds to 0.0.0.0 regardless",
			"Compose callback URLs — http://<public-host>/<token>. The user pastes these into vulnerable targets' inputs (SSRF payloads, blind-XSS hooks, SSTI ${fetch()} probes)",
			"Listener handler captures: timestamp, remote IP, method, path, Host header, User-Agent, ALL request headers, body snippet (first 600 bytes)",
			"Token matching from the request path → links the interaction back to its originating probe",
			"Respond with a tiny JSON ACK ({ok:true, token, received_at}) — useful when the user's payload reads back the HTTP response (some SSTI echo HTTP into rendered output)",
			"Persistence — last 500 interactions per session held in memory; snapshot to DB on every results-page hit so they survive shutdown",
		},
		Notes: []string{
			"⚠ The biggest gotcha: if scaNNer is on your laptop behind residential NAT, the target CAN'T REACH YOU. The listener will accept connections, but no public packet will ever arrive. This module is fundamentally a 'lab/internal/public-VPS' tool",
			"⚠ NO DNS authority — XXE via 'http://attacker.com/x' triggers an HTTP fetch; 'http://nonexistent.attacker.com' relies on DNS lookups that go to the target's resolver, never to you. Interactsh has a real DNS server; this module does not",
			"⚠ NO HTTPS — modern Java / .NET targets refuse plaintext HTTP outbound calls. You'd need to front this listener with nginx + Let's Encrypt yourself",
			"For real engagements, deploy via: (a) Tailscale/WireGuard tunnel between target and scaNNer, (b) ngrok HTTP forwarding, (c) self-hosted VPS with stable hostname + reverse proxy. Or just use Interactsh's public oast.fun (no infrastructure needed)",
			"Each interaction shows the source IP — useful to confirm the request came from INSIDE the target's network (different external IP than the user's browser proves SSRF)",
			"Long-running sessions accumulate memory — use the explicit 'Stop' button to clean up listeners when done",
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
		Summary: "Detects server-side template injection in 10 template engines (Jinja2, Twig, Mako, Smarty, ERB, Velocity, FreeMarker, Mustache/Handlebars, Pug, EJS) using engine-specific arithmetic markers. Each engine has a probe payload that evaluates to a recognisable result (e.g. Jinja2 {{7*'7'}} → '7777777' but Twig {{7*'7'}} → '49'). Confirms injection ONLY when the marker appears AND the literal payload does NOT — avoiding false positives from reflected XSS. Each finding includes an engine-specific exploitation hint chaining toward RCE.",
		Tools: []ToolRef{
			{Name: "Go net/http", Desc: "Per (URL, parameter, engine) probe"},
		},
		Phases: []string{
			"Build injection points — if URL has FUZZ placeholder, use it. Otherwise inject as ?param=PAYLOAD against the candidate param list",
			"For each injection point × each engine, fire the engine's signature payload",
			"Response handling — read up to 256 KB body, check for the marker substring AND the absence of the literal payload",
			"Both conditions must match — marker present AND payload NOT present = TEMPLATE evaluated the payload",
			"Emit a CRITICAL finding with engine name, parameter, payload, marker, and the engine-specific note (e.g. for Jinja2: 'Try {{config.items()}} or {{_self}} for further escalation')",
			"Continue testing other engines on the same parameter — same param may be evaluated by multiple engines in chained renderers",
		},
		Notes: []string{
			"Jinja2 vs Twig discrimination is the {{7*'7'}} test — Jinja2 returns '7777777' (string * int = repeated string), Twig returns '49' (string coerced to int). Same syntax, different outputs",
			"SSTI → RCE chain is well-known per engine — see PortSwigger's SSTI labs for engine-specific escape sequences. The 'Note' field has a one-line tip per finding",
			"Mustache logic-less variant doesn't have a clean SSTI primitive — only Handlebars-style with helpers. The Mustache probe payload uses the Handlebars-only constructor escape",
			"False-positive risk: 49 is a common number — if the target page already contains '49' for unrelated reasons (e.g. product count), the probe could trigger. The 'literal payload not present' check mitigates but doesn't eliminate this",
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
		Summary: "Two-in-one module probing web cache poisoning (12 host-override headers like X-Forwarded-Host / X-Original-URL / X-Custom-IP-Authorization) AND HTTP request smuggling (CL.TE, TE.CL, TE.TE — front-end vs back-end Content-Length / Transfer-Encoding parser disagreements). Cache poisoning checks for header reflection on cacheable endpoints (CDN-served, Age/X-Cache present). Smuggling uses raw TCP sockets to send malformed requests and detects back-end socket parking via response timeout — a behavioural signal that the front-end parsed differently than the back-end.",
		Tools: []ToolRef{
			{Name: "Go net/http", Desc: "Cache poisoning header reflection tests"},
			{Name: "Go net (raw TCP)", Desc: "Smuggling probes need raw byte control — Go's net/http won't let you send CL.TE-conflicting headers"},
		},
		Phases: []string{
			"Cache poisoning baseline — issue a clean GET, capture response. Check Cache-Control, Age, X-Cache, X-Cache-Hits headers to assess cacheability",
			"Per-header probe — for each of 12 host-override headers, send GET with that header set to evilHost",
			"Reflection detection — does the response's Location, Link, or body contain evilHost? If yes + endpoint cacheable = HIGH finding (cache poisons every future visitor); if no cache evidence = MEDIUM",
			"Smuggling baseline — none; smuggling probes are direct CL.TE / TE.CL / TE.TE attempts",
			"CL.TE probe — send POST with Content-Length AND Transfer-Encoding: chunked. Front-end may honor CL, back-end TE → smuggled bytes get parked, response times out",
			"TE.CL probe — reverse (chunked body with conflicting smaller CL value)",
			"TE.TE probe — obfuscated Transfer-Encoding header (mixed case, extra header) — one parser strips/normalizes, the other doesn't",
			"Read raw socket response with deadline. Timeout or fast-fail patterns become the smuggling fingerprint",
		},
		Notes: []string{
			"Cache poisoning is the deadliest 'visible' finding — a single successful poison persists for the cache TTL (hours to days) and serves attacker content to all visitors",
			"Smuggling is harder to confirm — the response-time signal is suggestive, not conclusive. PortSwigger's published methodology requires multiple confirmation requests; this module emits POSSIBLE smuggling flags, not certain ones",
			"DO NOT run smuggling probes against production without explicit authorization — even unsuccessful CL.TE attempts can crash the front-end / back-end pairing temporarily",
			"CDN-fronted sites: cache poisoning is at the CDN layer, but the X-Forwarded-Host reflection happens at the origin. Confirm by checking the Cache-Control / Age headers came from the CDN edge",
			"This module is intentionally noisy — false positives on benign reflection (header echo for debugging) are tolerated to maximize sensitivity",
		},
		References: []ReferenceRef{
			{Label: "PortSwigger cache poisoning labs", URL: "https://portswigger.net/web-security/web-cache-poisoning"},
			{Label: "PortSwigger HTTP request smuggling labs", URL: "https://portswigger.net/web-security/request-smuggling"},
			{Label: "James Kettle's request smuggling whitepaper", URL: "https://portswigger.net/research/http-desync-attacks-request-smuggling-reborn"},
			{Label: "RFC 7230 — HTTP/1.1 message syntax", URL: "https://datatracker.ietf.org/doc/html/rfc7230"},
		},
	},
}
