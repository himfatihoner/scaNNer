package cvematch

// CVERecord describes one CVE with the product/version range it applies to.
// "AffectedRange" uses inclusive [lo, hi] semantics; either bound may be
// empty to mean "open-ended" (e.g. lo="" hi="2.4.49" → anything ≤ 2.4.49).
type CVERecord struct {
	CVE         string
	Product     string // canonical lowercase: "apache http server", "nginx", "openssh"
	AffectedLo  string // inclusive lower bound (empty = -inf)
	AffectedHi  string // inclusive upper bound (empty = +inf)
	FixedIn     string // first version that contains the fix (informational)
	Severity    string // CRITICAL | HIGH | MEDIUM | LOW
	CVSS        string // e.g. "9.8"
	Description string
	Remediation string // actionable hint for the pentest report
	Reference   string
}

// CVEDatabase is a curated set of high-impact known CVEs across common
// web technologies. Not exhaustive — pentest-relevant landmark issues.
// Each record carries a Remediation hint suitable for the pentest report.
var CVEDatabase = []CVERecord{
	// Apache HTTPD
	{CVE: "CVE-2021-41773", Product: "apache http server", AffectedLo: "2.4.49", AffectedHi: "2.4.49", FixedIn: "2.4.50", Severity: "HIGH", CVSS: "7.5",
		Description: "Path traversal & RCE via crafted URLs when mod_cgi enabled.",
		Remediation: "Upgrade Apache to 2.4.51 or later (2.4.50 was incomplete — see CVE-2021-42013). Disable mod_cgi if unused. Audit Require directives in <Directory> blocks.",
		Reference:   "https://nvd.nist.gov/vuln/detail/CVE-2021-41773"},
	{CVE: "CVE-2021-42013", Product: "apache http server", AffectedLo: "2.4.49", AffectedHi: "2.4.50", FixedIn: "2.4.51", Severity: "CRITICAL", CVSS: "9.8",
		Description: "Path traversal + RCE — incomplete fix of CVE-2021-41773.",
		Remediation: "Upgrade to Apache 2.4.51 or later. The fix in 2.4.50 missed encoding-based variants — only 2.4.51+ is safe.",
		Reference:   "https://nvd.nist.gov/vuln/detail/CVE-2021-42013"},
	{CVE: "CVE-2017-15715", Product: "apache http server", AffectedLo: "2.4.0", AffectedHi: "2.4.29", FixedIn: "2.4.30", Severity: "HIGH", CVSS: "8.1",
		Description: "Apache mod_rewrite trailing-newline regex bypass.",
		Remediation: "Upgrade Apache to 2.4.30 or later. Audit any RewriteRule patterns that anchor with $ for newline-injection bypass.",
		Reference:   "https://nvd.nist.gov/vuln/detail/CVE-2017-15715"},

	// Nginx
	{CVE: "CVE-2017-7529", Product: "nginx", AffectedLo: "0.5.6", AffectedHi: "1.13.2", FixedIn: "1.13.3", Severity: "HIGH", CVSS: "7.5",
		Description: "Integer overflow in range filter — information disclosure.",
		Remediation: "Upgrade nginx to 1.13.3+ (1.12.1 LTS branch also patched). If upgrade impossible, set max_ranges 1 in nginx.conf.",
		Reference:   "https://nvd.nist.gov/vuln/detail/CVE-2017-7529"},
	{CVE: "CVE-2019-9511", Product: "nginx", AffectedLo: "", AffectedHi: "1.16.0", FixedIn: "1.16.1", Severity: "HIGH", CVSS: "7.5",
		Description: "HTTP/2 \"Data Dribble\" denial-of-service.",
		Remediation: "Upgrade nginx to 1.16.1 / 1.17.3 or later. If upgrade impossible, disable HTTP/2 (listen 443 ssl; — drop http2) until patched.",
		Reference:   "https://nvd.nist.gov/vuln/detail/CVE-2019-9511"},

	// PHP
	{CVE: "CVE-2019-11043", Product: "php", AffectedLo: "7.1.0", AffectedHi: "7.3.11", FixedIn: "7.3.11", Severity: "CRITICAL", CVSS: "9.8",
		Description: "PHP-FPM + Nginx underflow → remote code execution.",
		Remediation: "Upgrade PHP to 7.1.33 / 7.2.24 / 7.3.11 or later. If you run nginx + PHP-FPM with try_files, the specific config in PHP's advisory is exploitable. Remove the problematic location ~ \\.php$ fallback or hard-code resolved scripts.",
		Reference:   "https://nvd.nist.gov/vuln/detail/CVE-2019-11043"},
	{CVE: "CVE-2018-19518", Product: "php", AffectedLo: "", AffectedHi: "7.2.12", FixedIn: "7.2.13", Severity: "HIGH", CVSS: "8.8",
		Description: "imap_open() argument injection enables command exec.",
		Remediation: "Upgrade PHP to 7.2.13 / 7.1.25 / 7.0.33 or later. As a hardening: disable imap_open in php.ini disable_functions if not used.",
		Reference:   "https://nvd.nist.gov/vuln/detail/CVE-2018-19518"},
	{CVE: "CVE-2024-4577", Product: "php", AffectedLo: "8.0.0", AffectedHi: "8.3.7", FixedIn: "8.3.8", Severity: "CRITICAL", CVSS: "9.8",
		Description: "PHP-CGI argument injection on Windows leading to RCE.",
		Remediation: "Upgrade PHP to 8.1.29 / 8.2.20 / 8.3.8 or later. Windows-only impact when using PHP-CGI with certain locales (Chinese/Japanese). Migrate from PHP-CGI to PHP-FPM for Windows hosts.",
		Reference:   "https://nvd.nist.gov/vuln/detail/CVE-2024-4577"},

	// OpenSSL
	{CVE: "CVE-2014-0160", Product: "openssl", AffectedLo: "1.0.1", AffectedHi: "1.0.1f", FixedIn: "1.0.1g", Severity: "CRITICAL", CVSS: "7.5",
		Description: "Heartbleed — server memory disclosure.",
		Remediation: "Upgrade OpenSSL to 1.0.1g or later. ROTATE ALL SSL certificates AND any secrets that touched server memory (session keys, passwords). Recompile statically-linked binaries.",
		Reference:   "https://nvd.nist.gov/vuln/detail/CVE-2014-0160"},
	{CVE: "CVE-2022-0778", Product: "openssl", AffectedLo: "", AffectedHi: "3.0.1", FixedIn: "3.0.2", Severity: "HIGH", CVSS: "7.5",
		Description: "Infinite loop in BN_mod_sqrt() — DoS via crafted cert.",
		Remediation: "Upgrade OpenSSL to 3.0.2 / 1.1.1n / 1.0.2zd or later. Affects any code path that parses certificates with explicit curves (e.g. CRL verification).",
		Reference:   "https://nvd.nist.gov/vuln/detail/CVE-2022-0778"},

	// OpenSSH
	{CVE: "CVE-2024-6387", Product: "openssh", AffectedLo: "8.5", AffectedHi: "9.7", FixedIn: "9.8", Severity: "CRITICAL", CVSS: "8.1",
		Description: "regreSSHion — unauthenticated RCE via signal handler race.",
		Remediation: "Upgrade OpenSSH server to 9.8p1 or later. Mitigation if upgrade not possible: set LoginGraceTime 0 in sshd_config (disables the timeout but blocks this attack). Restrict SSH access to known IPs via firewall.",
		Reference:   "https://nvd.nist.gov/vuln/detail/CVE-2024-6387"},
	{CVE: "CVE-2023-38408", Product: "openssh", AffectedLo: "", AffectedHi: "9.3p1", FixedIn: "9.3p2", Severity: "HIGH", CVSS: "9.8",
		Description: "ssh-agent forwarding PKCS#11 RCE.",
		Remediation: "Upgrade OpenSSH to 9.3p2 or later. Disable agent forwarding (ForwardAgent no) on untrusted hosts. Restrict PKCS#11 provider whitelist via ssh-agent's -P flag.",
		Reference:   "https://nvd.nist.gov/vuln/detail/CVE-2023-38408"},

	// Tomcat
	{CVE: "CVE-2020-1938", Product: "apache tomcat", AffectedLo: "6.0.0", AffectedHi: "9.0.30", FixedIn: "9.0.31", Severity: "CRITICAL", CVSS: "9.8",
		Description: "Ghostcat — AJP file read / RCE.",
		Remediation: "Upgrade Tomcat to 7.0.100 / 8.5.51 / 9.0.31 or later. If upgrade not possible: disable the AJP connector (port 8009) in server.xml, OR require a secret via the secret attribute on the Connector.",
		Reference:   "https://nvd.nist.gov/vuln/detail/CVE-2020-1938"},
	{CVE: "CVE-2017-12617", Product: "apache tomcat", AffectedLo: "", AffectedHi: "9.0.0", FixedIn: "9.0.1", Severity: "HIGH", CVSS: "8.1",
		Description: "PUT-method JSP upload → RCE when readonly=false.",
		Remediation: "Upgrade Tomcat to 7.0.82 / 8.0.47 / 8.5.23 / 9.0.1 or later. Ensure readonly is TRUE (default) on the DefaultServlet in web.xml. PUT method should be denied on production unless explicitly required.",
		Reference:   "https://nvd.nist.gov/vuln/detail/CVE-2017-12617"},

	// Spring
	{CVE: "CVE-2022-22965", Product: "spring framework", AffectedLo: "5.2.0", AffectedHi: "5.3.17", FixedIn: "5.3.18", Severity: "CRITICAL", CVSS: "9.8",
		Description: "Spring4Shell — RCE via ClassLoader manipulation.",
		Remediation: "Upgrade Spring Framework to 5.3.18 / 5.2.20 or later. Mitigation: subclass ServletRequestDataBinder and block class.module.classLoader prefix via setDisallowedFields. Requires JDK 9+ to be exploitable.",
		Reference:   "https://nvd.nist.gov/vuln/detail/CVE-2022-22965"},
	{CVE: "CVE-2022-22963", Product: "spring cloud function", AffectedLo: "3.1.6", AffectedHi: "3.2.2", FixedIn: "3.2.3", Severity: "CRITICAL", CVSS: "9.8",
		Description: "SpEL injection → RCE via Spring Cloud Function.",
		Remediation: "Upgrade Spring Cloud Function to 3.1.7 / 3.2.3 or later. If header routing is not required, set spring.cloud.function.routing-expression=false.",
		Reference:   "https://nvd.nist.gov/vuln/detail/CVE-2022-22963"},

	// IIS
	{CVE: "CVE-2017-7269", Product: "iis", AffectedLo: "6.0", AffectedHi: "6.0", FixedIn: "(EOL — upgrade host OS)", Severity: "CRITICAL", CVSS: "9.8",
		Description: "Buffer overflow in WebDAV ScStoragePathFromUrl.",
		Remediation: "IIS 6.0 (Windows Server 2003) is end-of-life. Migrate to a supported Windows Server version. If migration is delayed, disable WebDAV in IIS Manager and apply Microsoft's out-of-band patch (KB5012688 timeframe).",
		Reference:   "https://nvd.nist.gov/vuln/detail/CVE-2017-7269"},

	// WordPress
	{CVE: "CVE-2022-21661", Product: "wordpress", AffectedLo: "", AffectedHi: "5.8.2", FixedIn: "5.8.3", Severity: "HIGH", CVSS: "8.0",
		Description: "WP_Query SQLi.",
		Remediation: "Upgrade WordPress core to 5.8.3 or later. Audit any custom plugins that build WP_Query from user input without prepared statements.",
		Reference:   "https://nvd.nist.gov/vuln/detail/CVE-2022-21661"},

	// Drupal
	{CVE: "CVE-2018-7600", Product: "drupal", AffectedLo: "7.0", AffectedHi: "8.5.0", FixedIn: "8.5.1", Severity: "CRITICAL", CVSS: "9.8",
		Description: "Drupalgeddon2 — unauthenticated RCE via form rendering.",
		Remediation: "Upgrade Drupal to 7.58 / 8.3.9 / 8.4.6 / 8.5.1 or later. Block /user/register, /user/password, /node/add endpoints at the WAF until patched.",
		Reference:   "https://nvd.nist.gov/vuln/detail/CVE-2018-7600"},

	// Jenkins
	{CVE: "CVE-2024-23897", Product: "jenkins", AffectedLo: "", AffectedHi: "2.441", FixedIn: "2.442", Severity: "CRITICAL", CVSS: "9.8",
		Description: "args4j arbitrary file read → leads to RCE.",
		Remediation: "Upgrade Jenkins to 2.442 / LTS 2.426.3 or later. Mitigation: disable the CLI altogether via -Djenkins.CLI.disabled=true JVM arg, OR remove network access to the Jenkins HTTP listener for untrusted users.",
		Reference:   "https://nvd.nist.gov/vuln/detail/CVE-2024-23897"},

	// GitLab
	{CVE: "CVE-2021-22205", Product: "gitlab", AffectedLo: "11.9.0", AffectedHi: "13.10.2", FixedIn: "13.10.3", Severity: "CRITICAL", CVSS: "10.0",
		Description: "ExifTool image upload → unauthenticated RCE.",
		Remediation: "Upgrade GitLab to 13.10.3 / 13.9.6 / 13.8.8 or later. If immediate upgrade not possible, restrict unauthenticated POST to issue/MR image endpoints at the load balancer.",
		Reference:   "https://nvd.nist.gov/vuln/detail/CVE-2021-22205"},

	// Atlassian Confluence
	{CVE: "CVE-2022-26134", Product: "confluence", AffectedLo: "1.3.0", AffectedHi: "7.18.0", FixedIn: "7.18.1", Severity: "CRITICAL", CVSS: "9.8",
		Description: "OGNL injection → unauthenticated RCE.",
		Remediation: "Upgrade Confluence Server/Data Center to 7.4.17 / 7.13.7 / 7.14.3 / 7.15.2 / 7.16.4 / 7.17.4 / 7.18.1 or later. Mitigation: WAF block any URI containing ${ pattern.",
		Reference:   "https://nvd.nist.gov/vuln/detail/CVE-2022-26134"},
	{CVE: "CVE-2023-22515", Product: "confluence", AffectedLo: "8.0.0", AffectedHi: "8.5.1", FixedIn: "8.5.2", Severity: "CRITICAL", CVSS: "10.0",
		Description: "Privilege escalation — unauthenticated admin account creation.",
		Remediation: "Upgrade Confluence Server/Data Center to 8.3.3 / 8.4.3 / 8.5.2 or later. Block /setup/* paths at the perimeter; setup wizard should never be reachable on a live install.",
		Reference:   "https://nvd.nist.gov/vuln/detail/CVE-2023-22515"},

	// Log4j
	{CVE: "CVE-2021-44228", Product: "log4j", AffectedLo: "2.0", AffectedHi: "2.14.1", FixedIn: "2.17.0", Severity: "CRITICAL", CVSS: "10.0",
		Description: "Log4Shell — JNDI lookup RCE.",
		Remediation: "Upgrade log4j2 to 2.17.1+ (NOT 2.15 or 2.16 — both have follow-up CVEs). If upgrade is impossible: set log4j2.formatMsgNoLookups=true JVM arg AND remove JndiLookup.class from the log4j-core jar.",
		Reference:   "https://nvd.nist.gov/vuln/detail/CVE-2021-44228"},

	// Exchange
	{CVE: "CVE-2021-26855", Product: "exchange", AffectedLo: "2013", AffectedHi: "2019", FixedIn: "(see KB5000871)", Severity: "CRITICAL", CVSS: "9.8",
		Description: "ProxyLogon SSRF as first step of RCE chain.",
		Remediation: "Apply Microsoft's emergency March 2021 security update for Exchange (KB5000871 + cumulative updates). Block external access to /ecp and /owa virtual directories until patched. Run Microsoft's Exchange On-Premises Mitigation Tool (EOMT).",
		Reference:   "https://nvd.nist.gov/vuln/detail/CVE-2021-26855"},
	{CVE: "CVE-2022-41040", Product: "exchange", AffectedLo: "2013", AffectedHi: "2019", FixedIn: "(see Nov 2022 SU)", Severity: "HIGH", CVSS: "8.8",
		Description: "ProxyNotShell — SSRF chained with RCE.",
		Remediation: "Apply Microsoft's November 2022 Exchange Security Update. Mitigation rule (until patched): URL Rewrite to block .*autodiscover\\.json.*\\@.*Powershell.* on the FrontEnd/Autodiscover virtual directory.",
		Reference:   "https://nvd.nist.gov/vuln/detail/CVE-2022-41040"},

	// VMware
	{CVE: "CVE-2022-22954", Product: "vmware workspace one access", AffectedLo: "", AffectedHi: "21.08.0.1", FixedIn: "21.08.0.2", Severity: "CRITICAL", CVSS: "9.8",
		Description: "Server-side template injection → RCE.",
		Remediation: "Apply VMware's emergency patch (KB88098). Workaround: run /usr/local/horizon/scripts/hw-template-fix.py if upgrade not yet possible. Restrict admin console to bastion network.",
		Reference:   "https://nvd.nist.gov/vuln/detail/CVE-2022-22954"},

	// PHPMyAdmin
	{CVE: "CVE-2016-5734", Product: "phpmyadmin", AffectedLo: "4.0", AffectedHi: "4.6.3", FixedIn: "4.6.4", Severity: "HIGH", CVSS: "8.8",
		Description: "create_function() argument injection → RCE.",
		Remediation: "Upgrade phpMyAdmin to 4.4.15.8 / 4.6.4 or later. Never expose phpMyAdmin to the public internet — restrict to localhost / bastion via firewall.",
		Reference:   "https://nvd.nist.gov/vuln/detail/CVE-2016-5734"},

	// vBulletin
	{CVE: "CVE-2019-16759", Product: "vbulletin", AffectedLo: "5.0.0", AffectedHi: "5.5.4", FixedIn: "5.5.4 Patch Level 1", Severity: "CRITICAL", CVSS: "9.8",
		Description: "PHP module template RCE — pre-auth.",
		Remediation: "Upgrade vBulletin to 5.5.4 Patch Level 1, 5.5.3 PL1, or 5.5.2 PL1. Disable the widget_php widget if upgrade is delayed: edit includes/vb5/frontend/controller/widget.php to throw on widgetType=php.",
		Reference:   "https://nvd.nist.gov/vuln/detail/CVE-2019-16759"},

	// Citrix
	{CVE: "CVE-2019-19781", Product: "citrix adc", AffectedLo: "", AffectedHi: "13.0", FixedIn: "13.0 build 47.24", Severity: "CRITICAL", CVSS: "9.8",
		Description: "Citrix ADC/Gateway path traversal → RCE.",
		Remediation: "Apply Citrix's firmware update (build 47.24+ on 13.0, 51.x on 12.1, 70.12+ on 12.0, 71.20+ on 11.1). Workaround: load the responder policy from CTX267679 article.",
		Reference:   "https://nvd.nist.gov/vuln/detail/CVE-2019-19781"},

	// Fortinet
	{CVE: "CVE-2022-40684", Product: "fortinet fortios", AffectedLo: "7.0.0", AffectedHi: "7.2.1", FixedIn: "7.2.2", Severity: "CRITICAL", CVSS: "9.8",
		Description: "Authentication bypass on admin interface.",
		Remediation: "Upgrade FortiOS to 7.0.7 / 7.2.2 or later. Mitigation: restrict access to the admin GUI via trusted-host configuration; disable HTTP/HTTPS admin entirely if SSH suffices.",
		Reference:   "https://nvd.nist.gov/vuln/detail/CVE-2022-40684"},

	// Microsoft SharePoint
	{CVE: "CVE-2019-0604", Product: "sharepoint", AffectedLo: "", AffectedHi: "2019", FixedIn: "(see MS19-Mar)", Severity: "CRITICAL", CVSS: "9.8",
		Description: "Deserialization → unauthenticated RCE.",
		Remediation: "Apply Microsoft's March 2019 SharePoint Security Update (KB4462184/KB4462199/KB4462202 depending on version). Audit /BusinessDataMetadataCatalog/* requests for unusual payload sizes.",
		Reference:   "https://nvd.nist.gov/vuln/detail/CVE-2019-0604"},

	// Joomla
	{CVE: "CVE-2015-8562", Product: "joomla", AffectedLo: "1.5", AffectedHi: "3.4.5", FixedIn: "3.4.6", Severity: "HIGH", CVSS: "7.5",
		Description: "Unauthenticated RCE via PHP deserialization in User-Agent.",
		Remediation: "Upgrade Joomla to 3.4.6 or later (1.5 and 2.5 received hotfixes via the original advisory). WAF block User-Agent / X-Forwarded-For containing serialized PHP objects.",
		Reference:   "https://nvd.nist.gov/vuln/detail/CVE-2015-8562"},

	// MOVEit
	{CVE: "CVE-2023-34362", Product: "moveit transfer", AffectedLo: "", AffectedHi: "2023.0.1", FixedIn: "2023.0.2", Severity: "CRITICAL", CVSS: "9.8",
		Description: "SQL injection → unauthenticated RCE.",
		Remediation: "Apply Progress Software's emergency patch immediately (2021.0.6 / 2021.1.4 / 2022.0.4 / 2022.1.5 / 2023.0.1 or later). Indicators-of-compromise: check for human2.aspx, _human2.aspx, /human2.aspx in IIS logs.",
		Reference:   "https://nvd.nist.gov/vuln/detail/CVE-2023-34362"},

	// ManageEngine
	{CVE: "CVE-2022-47966", Product: "manageengine", AffectedLo: "", AffectedHi: "", FixedIn: "(see ME advisory)", Severity: "CRITICAL", CVSS: "9.8",
		Description: "SAML SSO unauthenticated RCE across multiple ME products.",
		Remediation: "Apply Zoho ManageEngine's January 2023 hotfix for affected products (ADSelfService Plus, ServiceDesk Plus, etc.). Mitigation: disable SAML SSO until patched; isolate ManageEngine consoles from internet.",
		Reference:   "https://nvd.nist.gov/vuln/detail/CVE-2022-47966"},
}

// productAliases lets us normalize techdetect's wording onto our canonical
// Product name. For each canonical Product, list aliases (lowercase) that
// might appear in the source. Substring matched.
var productAliases = map[string][]string{
	"apache http server":         {"apache", "httpd"},
	"nginx":                      {"nginx"},
	"php":                        {"php"},
	"openssl":                    {"openssl"},
	"openssh":                    {"openssh", "ssh"},
	"apache tomcat":              {"tomcat"},
	"spring framework":           {"spring framework", "spring boot", "spring-mvc"},
	"spring cloud function":      {"spring cloud function"},
	"iis":                        {"iis", "microsoft-iis"},
	"wordpress":                  {"wordpress", "wp"},
	"drupal":                     {"drupal"},
	"jenkins":                    {"jenkins"},
	"gitlab":                     {"gitlab"},
	"confluence":                 {"confluence"},
	"log4j":                      {"log4j"},
	"exchange":                   {"exchange server", "owa"},
	"vmware workspace one access": {"workspace one", "vidm"},
	"phpmyadmin":                 {"phpmyadmin"},
	"vbulletin":                  {"vbulletin"},
	"citrix adc":                 {"citrix", "netscaler"},
	"fortinet fortios":           {"fortinet", "fortigate", "fortios"},
	"sharepoint":                 {"sharepoint"},
	"joomla":                     {"joomla"},
	"moveit transfer":            {"moveit"},
	"manageengine":               {"manageengine", "servicedesk plus", "adselfservice"},
}
