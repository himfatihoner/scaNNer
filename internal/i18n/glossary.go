package i18n

// DoNotTranslate lists technical terms that MUST stay verbatim in both the
// English source and every translation — security terms, tool names, protocols,
// and acronyms. Translate the prose around them, never the term itself
// ("SQL injection" stays "SQL injection", never "SQL enjeksiyonu"; "NVD" stays
// "NVD", never "UZV").
//
// This is a review/lint aid (the offline catalog linter flags any translation
// that altered a protected term); it is NOT applied at runtime.
var DoNotTranslate = []string{
	// Vulnerability classes
	"SQL injection", "SQLi", "XSS", "CSRF", "SSRF", "RCE", "LFI", "RFI", "XXE",
	"IDOR", "SSTI", "CRLF", "open redirect", "clickjacking", "path traversal",
	// Vuln data / scoring
	"NVD", "CVE", "CVSS", "CWE", "CPE", "OWASP", "KEV", "EPSS", "PoC",
	// Protocols / tech
	"DNS", "SMB", "LDAP", "Kerberos", "NTLM", "SNMP", "TLS", "SSL", "mTLS",
	"HTTP", "HTTPS", "TCP", "UDP", "IP", "IPv4", "IPv6", "CIDR", "URL", "URI",
	"JWT", "ViewState", "WAF", "API", "CORS", "HSTS", "MAC", "HMAC", "OOB",
	"WebSocket", "GraphQL", "SAML", "OAuth", "TOTP", "2FA", "RBAC",
	// Tools
	"nmap", "nuclei", "subfinder", "amass", "puredns", "massdns", "hydra",
	"wpscan", "httpx", "netexec", "nxc", "impacket", "responder", "mitm6",
	"certipy", "bloodhound", "kerbrute", "hashcat", "CyberChef", "whatweb",
	"theHarvester", "recon-ng", "ffuf", "gobuster", "onesixtyone", "snmpwalk",
	"smbclient", "enum4linux", "ldapsearch", "coercer", "BloodHound",
	// Product / brand
	"scaNNer", "Burp Suite", "Active Directory", "Kerberoasting", "AS-REP",
}
