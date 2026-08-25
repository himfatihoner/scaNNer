package handlers

import (
	"encoding/json"

	"scanner/internal/models"
)

// ExportColumn is a single column the user can toggle on or off in the export
// modal. The ID is used both in the form and to look up the row value.
type ExportColumn struct {
	ID      string `json:"id"`
	Label   string `json:"label"`
	Default bool   `json:"default"`
}

// ExportSection is a logical group of rows in the result (e.g. "Findings" vs
// "Cipher Suites") plus the columns that section can emit.
type ExportSection struct {
	ID      string         `json:"id"`
	Label   string         `json:"label"`
	Default bool           `json:"default"`
	Columns []ExportColumn `json:"columns"`
	// HasSeverity signals the modal that rows in this section carry a
	// severity attribute, so a "Severity Filter" checkbox group should
	// be rendered alongside. Honored by sslscan/findings,
	// wpscan/vulnerabilities, secheaders/findings, nuclei/findings,
	// jwt/issues — anything with a per-finding severity.
	HasSeverity bool `json:"has_severity,omitempty"`
}

// AllSeverities is the canonical CRITICAL → INFO ordering. Modules emit
// severities in different conventions (`HIGH` vs `high`); the filter
// matches case-insensitively so all five accepted forms work.
var AllSeverities = []string{"CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"}

// advancedwebEnabledStages reads a scan's stored Config JSON and returns
// the set of stage IDs the user enabled at launch (as the writers use
// them — "whois", "dnsenum", "httpxfind", ...). Returns nil when the
// scan is not advancedweb or the config can't be parsed, in which case
// callers should fall through to "show everything" (legacy behaviour).
func advancedwebEnabledStages(scan *models.Scan) map[string]bool {
	if scan == nil || scan.Module != "advancedweb" || scan.Config == "" || scan.Config == "{}" {
		return nil
	}
	var cfg struct {
		EnableWhois       bool `json:"enable_whois"`
		EnableDNSEnum     bool `json:"enable_dnsenum"`
		EnableHTTPXFind   bool `json:"enable_httpxfind"`
		EnableSSLScan     bool `json:"enable_sslscan"`
		EnableWAFDetect   bool `json:"enable_wafdetect"`
		EnableTechDetect  bool `json:"enable_techdetect"`
		EnableCVEMatch    bool `json:"enable_cvematch"`
		EnableWPScan      bool `json:"enable_wpscan"`
		EnableNuclei      bool `json:"enable_nuclei"`
		EnableDirSpider   bool `json:"enable_dirspider"`
		EnableHTTPMethods bool `json:"enable_httpmethods"`
		EnableSecHeaders  bool `json:"enable_secheaders"`
	}
	if err := json.Unmarshal([]byte(scan.Config), &cfg); err != nil {
		return nil
	}
	return map[string]bool{
		"whois":       cfg.EnableWhois,
		"dnsenum":     cfg.EnableDNSEnum,
		"httpxfind":   cfg.EnableHTTPXFind,
		"sslscan":     cfg.EnableSSLScan,
		"wafdetect":   cfg.EnableWAFDetect,
		"techdetect":  cfg.EnableTechDetect,
		"cvematch":    cfg.EnableCVEMatch,
		"wpscan":      cfg.EnableWPScan,
		"nuclei":      cfg.EnableNuclei,
		"dirspider":   cfg.EnableDirSpider,
		"httpmethods": cfg.EnableHTTPMethods,
		"secheaders":  cfg.EnableSecHeaders,
	}
}

// ExportSchemaFor returns the export schema tailored to a specific scan.
// For most modules this is identical to ExportSchema(scan.Module). For
// the advancedweb suite it consults the scan's stored Config JSON and
// drops sections for stages the user disabled at launch time — so the
// export modal never shows "Tech / CVEs / Nuclei" for a scan that only
// ran "DNS / HTTPX". Falls back to the full schema on missing or
// unparseable config.
func ExportSchemaFor(scan *models.Scan) []ExportSection {
	full := ExportSchema(scan.Module)
	if scan.Module != "advancedweb" || scan.Config == "" || scan.Config == "{}" {
		return full
	}
	var cfg struct {
		EnableWhois       bool `json:"enable_whois"`
		EnableDNSEnum     bool `json:"enable_dnsenum"`
		EnableHTTPXFind   bool `json:"enable_httpxfind"`
		EnableSSLScan     bool `json:"enable_sslscan"`
		EnableWAFDetect   bool `json:"enable_wafdetect"`
		EnableTechDetect  bool `json:"enable_techdetect"`
		EnableCVEMatch    bool `json:"enable_cvematch"`
		EnableWPScan      bool `json:"enable_wpscan"`
		EnableNuclei      bool `json:"enable_nuclei"`
		EnableDirSpider   bool `json:"enable_dirspider"`
		EnableHTTPMethods bool `json:"enable_httpmethods"`
		EnableSecHeaders  bool `json:"enable_secheaders"`
	}
	if err := json.Unmarshal([]byte(scan.Config), &cfg); err != nil {
		return full
	}
	// Map section ID → "is enabled in this scan's config". Sections not
	// in the map are always kept (e.g. "summary" — always meaningful).
	// Commit 4: 7 new stage sections added — whois/sslscan/wafdetect/
	// wpscan/dirspider/httpmethods/secheaders. Trimmed when the scan's
	// stored config has the corresponding Enable* flag false.
	enabled := map[string]bool{
		"whois":       cfg.EnableWhois,
		"dnsenum":     cfg.EnableDNSEnum,
		"httpxfind":   cfg.EnableHTTPXFind,
		"sslscan":     cfg.EnableSSLScan,
		"wafdetect":   cfg.EnableWAFDetect,
		"techdetect":  cfg.EnableTechDetect,
		// CVE / Nuclei depend on their own toggle. Don't gate CVE on
		// TechDetect here — the user toggled CVE intentionally and the
		// CSV writer already handles the empty-data case cleanly.
		"cvematch":    cfg.EnableCVEMatch,
		"wpscan":      cfg.EnableWPScan,
		"nuclei":      cfg.EnableNuclei,
		"dirspider":   cfg.EnableDirSpider,
		"httpmethods": cfg.EnableHTTPMethods,
		"secheaders":  cfg.EnableSecHeaders,
	}
	out := make([]ExportSection, 0, len(full))
	for _, s := range full {
		if want, has := enabled[s.ID]; has && !want {
			continue
		}
		out = append(out, s)
	}
	return out
}

// ExportSchema returns the full export schema for a module. This is the single
// source of truth used by the modal, the CSV writer, and the JSON writer.
// Callers that have a scan in hand should prefer ExportSchemaFor, which
// trims advancedweb sections for stages the scan didn't actually run.
func ExportSchema(module string) []ExportSection {
	switch module {
	case "sslscan":
		return []ExportSection{
			{ID: "findings", Label: "Findings (Vulnerabilities)", Default: true, HasSeverity: true, Columns: []ExportColumn{
				{ID: "host", Label: "Host", Default: true},
				{ID: "port", Label: "Port", Default: true},
				{ID: "severity", Label: "Severity", Default: true},
				{ID: "title", Label: "Finding", Default: true},
				{ID: "description", Label: "Description", Default: true},
				{ID: "cves", Label: "CVEs", Default: true},
				{ID: "component", Label: "Component", Default: false},
			}},
			{ID: "protocols", Label: "Protocol Support", Default: false, Columns: []ExportColumn{
				{ID: "host", Label: "Host", Default: true},
				{ID: "port", Label: "Port", Default: true},
				{ID: "version", Label: "Protocol", Default: true},
				{ID: "supported", Label: "Supported", Default: true},
			}},
			{ID: "ciphers", Label: "Cipher Suites", Default: false, Columns: []ExportColumn{
				{ID: "host", Label: "Host", Default: true},
				{ID: "port", Label: "Port", Default: true},
				{ID: "name", Label: "Cipher", Default: true},
				{ID: "versions", Label: "Protocols", Default: true},
			}},
			{ID: "certificates", Label: "Certificate Info", Default: false, Columns: []ExportColumn{
				{ID: "host", Label: "Host", Default: true},
				{ID: "port", Label: "Port", Default: true},
				{ID: "subject", Label: "Subject", Default: true},
				{ID: "issuer", Label: "Issuer", Default: true},
				{ID: "not_before", Label: "Valid From", Default: false},
				{ID: "not_after", Label: "Valid Until", Default: true},
				{ID: "sig_alg", Label: "Signature Algorithm", Default: false},
				{ID: "expired", Label: "Expired", Default: true},
			}},
		}
	case "httpxfind":
		return []ExportSection{
			{ID: "services", Label: "Discovered Services", Default: true, Columns: []ExportColumn{
				{ID: "url", Label: "URL", Default: true},
				{ID: "host", Label: "Host", Default: false},
				{ID: "port", Label: "Port", Default: false},
				{ID: "scheme", Label: "Scheme", Default: false},
				{ID: "status", Label: "Status", Default: true},
				{ID: "title", Label: "Title", Default: true},
				{ID: "server", Label: "Server", Default: true},
				{ID: "content_type", Label: "Content-Type", Default: false},
				{ID: "redirect", Label: "Redirect", Default: false},
				{ID: "content_length", Label: "Length", Default: false},
			}},
			{ID: "headers", Label: "Response Headers", Default: false, Columns: []ExportColumn{
				{ID: "url", Label: "URL", Default: true},
				{ID: "headers", Label: "Headers", Default: true},
			}},
		}
	case "httpmethods":
		return []ExportSection{
			{ID: "methods", Label: "Method Test Results", Default: true, Columns: []ExportColumn{
				{ID: "url", Label: "URL", Default: true},
				{ID: "method", Label: "Method", Default: true},
				{ID: "variant", Label: "Variant", Default: false},
				{ID: "content_type", Label: "Request CT", Default: false},
				{ID: "status_code", Label: "Status", Default: true},
				{ID: "result", Label: "Result", Default: true},
				{ID: "size", Label: "Size", Default: false},
				{ID: "resp_ct", Label: "Response CT", Default: false},
				{ID: "allow", Label: "Allow", Default: false},
				{ID: "dangerous", Label: "Dangerous", Default: true},
			}},
			{ID: "dangerous", Label: "Dangerous Methods Only", Default: false, Columns: []ExportColumn{
				{ID: "url", Label: "URL", Default: true},
				{ID: "method", Label: "Method", Default: true},
				{ID: "status_code", Label: "Status", Default: true},
				{ID: "variant", Label: "Variant", Default: true},
			}},
		}
	case "wafdetect":
		return []ExportSection{
			{ID: "results", Label: "WAF Detection Results", Default: true, Columns: []ExportColumn{
				{ID: "url", Label: "URL", Default: true},
				{ID: "reachable", Label: "Reachable", Default: true},
				{ID: "waf_detected", Label: "WAF Detected", Default: true},
				{ID: "waf_name", Label: "WAF Name", Default: true},
				{ID: "vendor", Label: "Vendor", Default: true},
				{ID: "confidence", Label: "Confidence %", Default: true},
				{ID: "server", Label: "Server", Default: false},
			}},
			{ID: "evidence", Label: "Detection Evidence", Default: false, Columns: []ExportColumn{
				{ID: "url", Label: "URL", Default: true},
				{ID: "method", Label: "Method", Default: true},
				{ID: "detail", Label: "Detail", Default: true},
				{ID: "confidence", Label: "Confidence", Default: true},
			}},
		}
	case "wpscan":
		return []ExportSection{
			{ID: "vulnerabilities", Label: "Vulnerabilities", Default: true, HasSeverity: true, Columns: []ExportColumn{
				{ID: "url", Label: "URL", Default: true},
				{ID: "severity", Label: "Severity", Default: true},
				{ID: "category", Label: "Category", Default: true},
				{ID: "title", Label: "Title", Default: true},
				{ID: "description", Label: "Description", Default: false},
				{ID: "cves", Label: "CVEs", Default: true},
				{ID: "fixed_in", Label: "Fixed In", Default: true},
				{ID: "references", Label: "References", Default: false},
			}},
			{ID: "info", Label: "Site Info", Default: true, Columns: []ExportColumn{
				{ID: "url", Label: "URL", Default: true},
				{ID: "wp_version", Label: "WP Version", Default: true},
				{ID: "wp_status", Label: "Status", Default: true},
				{ID: "theme", Label: "Theme", Default: true},
				{ID: "plugin_count", Label: "Plugins", Default: true},
				{ID: "is_wordpress", Label: "Is WordPress", Default: false},
			}},
		}
	case "dnsenum":
		return []ExportSection{
			{ID: "subdomains", Label: "Subdomains", Default: true, Columns: []ExportColumn{
				{ID: "domain", Label: "Domain", Default: true},
				{ID: "subdomain", Label: "Subdomain", Default: true},
				{ID: "ips", Label: "IPs", Default: true},
				{ID: "source", Label: "Source", Default: true},
				{ID: "wildcard", Label: "Wildcard", Default: false},
			}},
			{ID: "axfr", Label: "Zone Transfer Records", Default: false, Columns: []ExportColumn{
				{ID: "domain", Label: "Domain", Default: true},
				{ID: "ns", Label: "NS", Default: true},
				{ID: "name", Label: "Record", Default: true},
				{ID: "type", Label: "Type", Default: true},
				{ID: "value", Label: "Value", Default: true},
			}},
			{ID: "reverse_dns", Label: "Reverse DNS", Default: false, Columns: []ExportColumn{
				{ID: "domain", Label: "Domain", Default: true},
				{ID: "ip", Label: "IP", Default: true},
				{ID: "hostname", Label: "Hostname", Default: true},
			}},
			{ID: "crtsh", Label: "crt.sh Certificates", Default: false, Columns: []ExportColumn{
				{ID: "domain", Label: "Domain", Default: true},
				{ID: "name_value", Label: "Hostname", Default: true},
				{ID: "issuer", Label: "Issuer", Default: false},
				{ID: "not_before", Label: "Valid From", Default: false},
				{ID: "not_after", Label: "Valid Until", Default: false},
			}},
		}
	case "techdetect":
		return []ExportSection{
			{ID: "technologies", Label: "Technologies", Default: true, Columns: []ExportColumn{
				{ID: "url", Label: "URL", Default: true},
				{ID: "name", Label: "Technology", Default: true},
				{ID: "version", Label: "Version", Default: true},
				{ID: "category", Label: "Category", Default: true},
				{ID: "source", Label: "Source", Default: false},
				{ID: "evidence", Label: "Evidence", Default: false},
			}},
			// Embedded CVE Matcher chain (populated only when auto_cvematch
			// was ticked on the form — empty section otherwise).
			{ID: "matches", Label: "CVE Matches (chained)", Default: true, Columns: []ExportColumn{
				{ID: "target_url", Label: "Target URL", Default: true},
				{ID: "product", Label: "Product", Default: true},
				{ID: "version", Label: "Version", Default: true},
				{ID: "cve", Label: "CVE", Default: true},
				{ID: "severity", Label: "Severity", Default: true},
				{ID: "cvss", Label: "CVSS", Default: true},
				{ID: "fixed_in", Label: "Fixed In", Default: true},
				{ID: "description", Label: "Description", Default: false},
				{ID: "remediation", Label: "Remediation", Default: false},
				{ID: "reference", Label: "Reference", Default: false},
			}},
		}
	case "spider":
		return []ExportSection{
			{ID: "all", Label: "All Resources", Default: true, Columns: []ExportColumn{
				{ID: "url", Label: "URL", Default: true},
				{ID: "path", Label: "Path", Default: true},
				{ID: "type", Label: "Type", Default: true},
				{ID: "status", Label: "Status", Default: true},
				{ID: "content_type", Label: "Content-Type", Default: false},
				{ID: "found_on", Label: "Found On", Default: true},
				{ID: "depth", Label: "Depth", Default: false},
			}},
			{ID: "directories", Label: "Directories Only", Default: false, Columns: []ExportColumn{
				{ID: "url", Label: "URL", Default: true},
				{ID: "path", Label: "Path", Default: true},
				{ID: "status", Label: "Status", Default: true},
				{ID: "found_on", Label: "Found On", Default: true},
			}},
			{ID: "files", Label: "Files Only", Default: false, Columns: []ExportColumn{
				{ID: "url", Label: "URL", Default: true},
				{ID: "path", Label: "Path", Default: true},
				{ID: "status", Label: "Status", Default: true},
				{ID: "content_type", Label: "Content-Type", Default: true},
			}},
		}
	case "direnum":
		return []ExportSection{
			{ID: "all", Label: "All Discoveries", Default: true, Columns: []ExportColumn{
				{ID: "url", Label: "URL", Default: true},
				{ID: "path", Label: "Path", Default: true},
				{ID: "type", Label: "Type", Default: true},
				{ID: "status", Label: "Status", Default: true},
				{ID: "size", Label: "Size", Default: true},
				{ID: "content_type", Label: "Content-Type", Default: false},
				{ID: "redirect", Label: "Redirect", Default: false},
			}},
			{ID: "dirs", Label: "Directories Only", Default: false, Columns: []ExportColumn{
				{ID: "url", Label: "URL", Default: true},
				{ID: "path", Label: "Path", Default: true},
				{ID: "status", Label: "Status", Default: true},
			}},
			{ID: "files", Label: "Files Only", Default: false, Columns: []ExportColumn{
				{ID: "url", Label: "URL", Default: true},
				{ID: "path", Label: "Path", Default: true},
				{ID: "status", Label: "Status", Default: true},
				{ID: "content_type", Label: "Content-Type", Default: true},
			}},
		}
	case "secheaders":
		return []ExportSection{
			{ID: "findings", Label: "Header Findings", Default: true, HasSeverity: true, Columns: []ExportColumn{
				{ID: "url", Label: "URL", Default: true},
				{ID: "grade", Label: "Grade", Default: true},
				{ID: "score", Label: "Score", Default: true},
				{ID: "header", Label: "Header", Default: true},
				{ID: "severity", Label: "Severity", Default: true},
				{ID: "status", Label: "Status", Default: true},
				{ID: "value", Label: "Value", Default: false},
				{ID: "description", Label: "Description", Default: false},
				{ID: "recommend", Label: "Recommendation", Default: false},
			}},
			{ID: "probes", Label: "Probe Details (200 OK methods)", Default: false, Columns: []ExportColumn{
				{ID: "url", Label: "URL", Default: true},
				{ID: "method", Label: "Method", Default: true},
				{ID: "variant", Label: "Variant", Default: true},
				{ID: "content_type", Label: "Content-Type", Default: false},
				{ID: "status_code", Label: "Status", Default: true},
			}},
		}
	case "nuclei":
		return []ExportSection{
			{ID: "findings", Label: "Vulnerabilities", Default: true, HasSeverity: true, Columns: []ExportColumn{
				{ID: "url", Label: "URL", Default: true},
				{ID: "template_id", Label: "Template ID", Default: true},
				{ID: "name", Label: "Name", Default: true},
				{ID: "severity", Label: "Severity", Default: true},
				{ID: "type", Label: "Type", Default: false},
				{ID: "matched_at", Label: "Matched At", Default: true},
				{ID: "description", Label: "Description", Default: false},
				{ID: "cves", Label: "CVEs", Default: true},
				{ID: "cwes", Label: "CWEs", Default: false},
				{ID: "tags", Label: "Tags", Default: false},
				{ID: "references", Label: "References", Default: false},
			}},
		}
	case "hostdiscovery":
		return []ExportSection{
			{ID: "hosts", Label: "Hosts", Default: true, Columns: []ExportColumn{
				{ID: "target", Label: "Target", Default: true},
				{ID: "ip", Label: "IP", Default: true},
				{ID: "host", Label: "Hostname", Default: false},
				{ID: "host_up", Label: "Up", Default: true},
				{ID: "ping_reachable", Label: "Ping OK", Default: true},
				{ID: "icmp_filtered", Label: "ICMP Filtered", Default: true},
				{ID: "open_count", Label: "Open Ports", Default: true},
			}},
			{ID: "ports", Label: "Open Ports", Default: false, Columns: []ExportColumn{
				{ID: "target", Label: "Target", Default: true},
				{ID: "ip", Label: "IP", Default: true},
				{ID: "port", Label: "Port", Default: true},
				{ID: "protocol", Label: "Protocol", Default: true},
				{ID: "state", Label: "State", Default: true},
				{ID: "service", Label: "Service", Default: true},
			}},
		}
	case "portservice":
		return []ExportSection{
			{ID: "ports", Label: "Ports + Service Versions", Default: true, Columns: []ExportColumn{
				{ID: "target", Label: "Target", Default: true},
				{ID: "ip", Label: "IP", Default: true},
				{ID: "port", Label: "Port", Default: true},
				{ID: "protocol", Label: "Protocol", Default: true},
				{ID: "state", Label: "State", Default: true},
				{ID: "service", Label: "Service", Default: true},
				{ID: "product", Label: "Product", Default: true},
				{ID: "version", Label: "Version", Default: true},
				{ID: "extra_info", Label: "Extra Info", Default: false},
				{ID: "tunnel", Label: "Tunnel", Default: false},
			}},
			{ID: "scripts", Label: "NSE Script Outputs", Default: false, Columns: []ExportColumn{
				{ID: "target", Label: "Target", Default: true},
				{ID: "port", Label: "Port", Default: true},
				{ID: "script_id", Label: "Script", Default: true},
				{ID: "output", Label: "Output", Default: true},
			}},
			// Audit MED fix: the module spends Phase 3.5 grabbing HTTP
			// banners + response metadata and Phase 4 running Nuclei —
			// none of which were previously exportable. Report writers
			// had to either dig JSON out of the DB or switch to the host
			// detail page. These three sections surface that data
			// alongside the nmap-derived rows.
			{ID: "banners", Label: "Service Banners", Default: false, Columns: []ExportColumn{
				{ID: "target", Label: "Target", Default: true},
				{ID: "ip", Label: "IP", Default: true},
				{ID: "port", Label: "Port", Default: true},
				{ID: "protocol", Label: "Protocol", Default: true},
				{ID: "service", Label: "Service", Default: true},
				{ID: "banner", Label: "Banner", Default: true},
			}},
			{ID: "http", Label: "HTTP Responses", Default: false, Columns: []ExportColumn{
				{ID: "target", Label: "Target", Default: true},
				{ID: "ip", Label: "IP", Default: true},
				{ID: "port", Label: "Port", Default: true},
				{ID: "url", Label: "URL", Default: true},
				{ID: "status", Label: "Status", Default: true},
				{ID: "server", Label: "Server", Default: true},
				{ID: "title", Label: "Title", Default: true},
				{ID: "content_type", Label: "Content-Type", Default: false},
				{ID: "body_length", Label: "Body Length", Default: false},
			}},
			{ID: "vulns", Label: "Nuclei Findings", Default: false, Columns: []ExportColumn{
				{ID: "target", Label: "Target", Default: true},
				{ID: "template_id", Label: "Template ID", Default: true},
				{ID: "name", Label: "Name", Default: true},
				{ID: "severity", Label: "Severity", Default: true},
				{ID: "cves", Label: "CVEs", Default: true},
				{ID: "matched_at", Label: "Matched At", Default: true},
				{ID: "description", Label: "Description", Default: false},
			}},
		}
	case "smbenum":
		return []ExportSection{
			{ID: "shares", Label: "SMB Shares", Default: true, Columns: []ExportColumn{
				{ID: "target", Label: "Target", Default: true},
				{ID: "name", Label: "Share", Default: true},
				{ID: "type", Label: "Type", Default: true},
				{ID: "comment", Label: "Comment", Default: false},
				{ID: "access", Label: "Access", Default: false},
			}},
			{ID: "users", Label: "Users / Groups", Default: false, Columns: []ExportColumn{
				{ID: "target", Label: "Target", Default: true},
				{ID: "kind", Label: "Kind", Default: true},
				{ID: "name", Label: "Name", Default: true},
			}},
			{ID: "info", Label: "Host Info", Default: false, Columns: []ExportColumn{
				{ID: "target", Label: "Target", Default: true},
				{ID: "ip", Label: "IP", Default: true},
				{ID: "os", Label: "OS", Default: true},
				{ID: "domain", Label: "Domain", Default: true},
				{ID: "workgroup", Label: "Workgroup", Default: false},
				{ID: "netbios_name", Label: "NetBIOS Name", Default: false},
				{ID: "smb_port_open", Label: "445 Open", Default: true},
			}},
		}
	case "brutef":
		return []ExportSection{
			{ID: "credentials", Label: "Cracked Credentials", Default: true, Columns: []ExportColumn{
				{ID: "host", Label: "Host", Default: true},
				{ID: "port", Label: "Port", Default: true},
				{ID: "protocol", Label: "Protocol", Default: true},
				{ID: "username", Label: "Username", Default: true},
				{ID: "password", Label: "Password", Default: true},
			}},
		}
	case "whoisinfo":
		return []ExportSection{
			{ID: "summary", Label: "Lookup Summary", Default: true, Columns: []ExportColumn{
				{ID: "target", Label: "Target", Default: true},
				{ID: "kind", Label: "Kind", Default: true},
				{ID: "ip", Label: "IP", Default: true},
				{ID: "asn", Label: "ASN", Default: true},
				{ID: "organization", Label: "Organization", Default: true},
				{ID: "country", Label: "Country", Default: false},
				{ID: "registry", Label: "Registry", Default: false},
			}},
			{ID: "records", Label: "WHOIS Records", Default: false, Columns: []ExportColumn{
				{ID: "target", Label: "Target", Default: true},
				{ID: "field", Label: "Field", Default: true},
				{ID: "value", Label: "Value", Default: true},
			}},
			{ID: "prefixes", Label: "AS Prefixes", Default: false, Columns: []ExportColumn{
				{ID: "asn", Label: "ASN", Default: true},
				{ID: "prefix", Label: "Prefix", Default: true},
			}},
		}
	case "emailharvest":
		return []ExportSection{
			{ID: "emails", Label: "Emails", Default: true, Columns: []ExportColumn{
				{ID: "domain", Label: "Domain", Default: true},
				{ID: "email", Label: "Email", Default: true},
			}},
			{ID: "hosts", Label: "Hosts", Default: false, Columns: []ExportColumn{
				{ID: "domain", Label: "Domain", Default: true},
				{ID: "host", Label: "Host", Default: true},
			}},
			{ID: "ips", Label: "IPs", Default: false, Columns: []ExportColumn{
				{ID: "domain", Label: "Domain", Default: true},
				{ID: "ip", Label: "IP", Default: true},
			}},
			{ID: "breaches", Label: "HIBP Breaches", Default: false, Columns: []ExportColumn{
				{ID: "domain", Label: "Domain", Default: true},
				{ID: "name", Label: "Breach", Default: true},
				{ID: "title", Label: "Title", Default: true},
				{ID: "date", Label: "Date", Default: true},
				{ID: "pwn_count", Label: "Accounts", Default: true},
				{ID: "data_classes", Label: "Data Classes", Default: false},
			}},
		}
	case "leakscan":
		return []ExportSection{
			{ID: "hits", Label: "Leak Hits", Default: true, Columns: []ExportColumn{
				{ID: "query", Label: "Query", Default: true},
				{ID: "repo", Label: "Repository", Default: true},
				{ID: "path", Label: "File Path", Default: true},
				{ID: "url", Label: "URL", Default: true},
				{ID: "secret_type", Label: "Secret Type", Default: true},
				{ID: "snippet", Label: "Snippet", Default: false},
			}},
		}
	case "snmpenum":
		return []ExportSection{
			{ID: "communities", Label: "Community Strings", Default: true, Columns: []ExportColumn{
				{ID: "target", Label: "Target", Default: true},
				{ID: "community", Label: "Community", Default: true},
				{ID: "access", Label: "Access", Default: true},
			}},
			{ID: "info", Label: "System / OID Info", Default: false, Columns: []ExportColumn{
				{ID: "target", Label: "Target", Default: true},
				{ID: "oid", Label: "OID", Default: true},
				{ID: "value", Label: "Value", Default: true},
			}},
		}
	case "jwt":
		return []ExportSection{
			{ID: "summary", Label: "Token Summary", Default: true, Columns: []ExportColumn{
				{ID: "token_idx", Label: "#", Default: true},
				{ID: "alg", Label: "Algorithm", Default: true},
				{ID: "issuer", Label: "Issuer", Default: false},
				{ID: "subject", Label: "Subject", Default: false},
				{ID: "exp", Label: "Expires", Default: true},
				{ID: "expired", Label: "Expired", Default: true},
				{ID: "secret", Label: "Cracked Secret", Default: true},
			}},
			{ID: "issues", Label: "Audit Issues", Default: true, HasSeverity: true, Columns: []ExportColumn{
				{ID: "token_idx", Label: "#", Default: true},
				{ID: "severity", Label: "Severity", Default: true},
				{ID: "title", Label: "Issue", Default: true},
				{ID: "detail", Label: "Detail", Default: false},
			}},
		}
	case "paramdisc":
		return []ExportSection{
			{ID: "hits", Label: "Discovered Parameters", Default: true, Columns: []ExportColumn{
				{ID: "url", Label: "URL", Default: true},
				{ID: "method", Label: "Method", Default: true},
				{ID: "name", Label: "Parameter", Default: true},
				{ID: "status_code", Label: "Status", Default: true},
				{ID: "status_diff", Label: "Status Δ", Default: true},
				{ID: "length_diff", Label: "Length Δ", Default: true},
				{ID: "reflected", Label: "Reflected", Default: true},
				{ID: "note", Label: "Note", Default: false},
			}},
		}

	// === Commit 2: schemas for modules that previously had NO export
	// catalogue. Most of these are "vuln scanner" shape — `Results []
	// URLResult { URL, Findings []Finding }` — so they share the same
	// {findings, targets} pair. Per-module Finding struct shape varies;
	// each `case` enumerates only the columns actually present in that
	// module's Finding type (verified against scanner.go). ===

	case "takeover":
		// takeover.ScanResult has both top-level Findings and per-host
		// Results. Two sections: the high-signal Findings list +
		// per-host outcome table for the audit trail.
		return []ExportSection{
			{ID: "findings", Label: "Takeover Findings", Default: true, HasSeverity: true, Columns: []ExportColumn{
				{ID: "subdomain", Label: "Subdomain", Default: true},
				{ID: "cname", Label: "CNAME", Default: true},
				{ID: "ips", Label: "IPs", Default: false},
				{ID: "service", Label: "Service", Default: true},
				{ID: "severity", Label: "Severity", Default: true},
				{ID: "http_status", Label: "HTTP", Default: true},
				{ID: "matched_pattern", Label: "Matched Pattern", Default: true},
				{ID: "note", Label: "Note", Default: false},
				{ID: "body_snippet", Label: "Body Snippet", Default: false},
			}},
			{ID: "hosts", Label: "Per-host Outcome", Default: false, Columns: []ExportColumn{
				{ID: "subdomain", Label: "Subdomain", Default: true},
				{ID: "cname", Label: "CNAME", Default: true},
				{ID: "ips", Label: "IPs", Default: false},
				{ID: "status", Label: "Status", Default: true},
				{ID: "note", Label: "Note", Default: false},
			}},
		}

	case "corsscan":
		return []ExportSection{
			{ID: "findings", Label: "CORS Findings", Default: true, HasSeverity: true, Columns: []ExportColumn{
				{ID: "url", Label: "URL", Default: true},
				{ID: "severity", Label: "Severity", Default: true},
				{ID: "title", Label: "Title", Default: true},
				{ID: "request_origin", Label: "Request Origin", Default: true},
				{ID: "response_acao", Label: "ACAO", Default: true},
				{ID: "response_acac", Label: "ACAC", Default: false},
				{ID: "detail", Label: "Detail", Default: false},
			}},
		}

	case "openredirect":
		return []ExportSection{
			{ID: "findings", Label: "Open Redirect Hits", Default: true, HasSeverity: true, Columns: []ExportColumn{
				{ID: "url", Label: "URL", Default: true},
				{ID: "parameter", Label: "Parameter", Default: true},
				{ID: "payload", Label: "Payload", Default: true},
				{ID: "status_code", Label: "HTTP", Default: true},
				{ID: "location", Label: "Location", Default: true},
				{ID: "how_matched", Label: "Match Method", Default: false},
				{ID: "severity", Label: "Severity", Default: true},
			}},
		}

	case "graphqlscan":
		return []ExportSection{
			{ID: "endpoints", Label: "Endpoints", Default: true, Columns: []ExportColumn{
				{ID: "url", Label: "URL", Default: true},
				{ID: "status", Label: "HTTP", Default: true},
				{ID: "is_graphql", Label: "GraphQL?", Default: true},
				{ID: "introspection_on", Label: "Introspection", Default: true},
				{ID: "schema_type_count", Label: "Schema Types", Default: true},
				{ID: "query_fields", Label: "Query Fields", Default: false},
				{ID: "mutation_fields", Label: "Mutation Fields", Default: false},
			}},
			{ID: "findings", Label: "GraphQL Findings", Default: true, HasSeverity: true, Columns: []ExportColumn{
				{ID: "url", Label: "URL", Default: true},
				{ID: "severity", Label: "Severity", Default: true},
				{ID: "title", Label: "Title", Default: true},
				{ID: "detail", Label: "Detail", Default: false},
				{ID: "evidence", Label: "Evidence", Default: false},
			}},
		}

	case "authtest":
		return []ExportSection{
			{ID: "findings", Label: "Auth Findings", Default: true, HasSeverity: true, Columns: []ExportColumn{
				{ID: "login_url", Label: "Login URL", Default: true},
				{ID: "method", Label: "Method", Default: true},
				{ID: "severity", Label: "Severity", Default: true},
				{ID: "title", Label: "Title", Default: true},
				{ID: "detail", Label: "Detail", Default: false},
				{ID: "evidence", Label: "Evidence", Default: false},
			}},
			{ID: "attempts", Label: "Auth Attempts", Default: false, Columns: []ExportColumn{
				{ID: "login_url", Label: "Login URL", Default: true},
				{ID: "username", Label: "Username", Default: true},
				{ID: "password", Label: "Password", Default: true},
				{ID: "status_code", Label: "HTTP", Default: true},
				{ID: "body_len", Label: "Body Len", Default: false},
				{ID: "outcome", Label: "Outcome", Default: true},
			}},
		}

	case "sstiscan":
		return []ExportSection{
			{ID: "findings", Label: "SSTI Findings", Default: true, HasSeverity: true, Columns: []ExportColumn{
				{ID: "url", Label: "URL", Default: true},
				{ID: "engine", Label: "Engine", Default: true},
				{ID: "parameter", Label: "Parameter", Default: true},
				{ID: "payload", Label: "Payload", Default: true},
				{ID: "marker", Label: "Marker", Default: false},
				{ID: "severity", Label: "Severity", Default: true},
				{ID: "note", Label: "Note", Default: false},
			}},
		}

	case "cachepoison":
		return []ExportSection{
			{ID: "findings", Label: "Cache/Smuggling Findings", Default: true, HasSeverity: true, Columns: []ExportColumn{
				{ID: "url", Label: "URL", Default: true},
				{ID: "class", Label: "Class", Default: true},
				{ID: "header", Label: "Header", Default: true},
				{ID: "payload", Label: "Payload", Default: true},
				{ID: "severity", Label: "Severity", Default: true},
				{ID: "title", Label: "Title", Default: true},
				{ID: "detail", Label: "Detail", Default: false},
				{ID: "evidence", Label: "Evidence", Default: false},
			}},
		}

	// === Commit 3: big multi-section schemas — adpentest, concurtest, oob. ===

	case "adpentest":
		// AD pentest produces multiple parallel inventories. Cherry-pick
		// the high-signal sections; raw BloodHound zip + raw nbtscan/etc
		// blobs are deliberately omitted (they belong in the loot folder,
		// not a CSV row). Severity gates are wired only where the data
		// has a Severity field (vulns, hashes via type label).
		return []ExportSection{
			{ID: "discovery", Label: "Discovery — DCs", Default: true, Columns: []ExportColumn{
				{ID: "ip", Label: "IP", Default: true},
				{ID: "fqdn", Label: "FQDN", Default: true},
				{ID: "netbios_name", Label: "NetBIOS", Default: true},
				{ID: "os", Label: "OS", Default: true},
				{ID: "open_ports", Label: "Open Ports", Default: false},
				{ID: "roles", Label: "Roles", Default: false},
			}},
			{ID: "users", Label: "AD Users", Default: false, Columns: []ExportColumn{
				{ID: "username", Label: "Username", Default: true},
				{ID: "dn", Label: "DN", Default: false},
				{ID: "sid", Label: "SID", Default: false},
				{ID: "enabled", Label: "Enabled", Default: true},
				{ID: "admin_count", Label: "AdminCount", Default: true},
				{ID: "description", Label: "Description", Default: false},
				{ID: "last_logon", Label: "Last Logon", Default: false},
				{ID: "uac_flags", Label: "UAC Flags", Default: false},
				{ID: "spn", Label: "SPN", Default: false},
			}},
			{ID: "groups", Label: "AD Groups", Default: false, Columns: []ExportColumn{
				{ID: "name", Label: "Name", Default: true},
				{ID: "sid", Label: "SID", Default: false},
				{ID: "members", Label: "Members", Default: false},
				{ID: "description", Label: "Description", Default: false},
			}},
			{ID: "computers", Label: "AD Computers", Default: false, Columns: []ExportColumn{
				{ID: "name", Label: "Name", Default: true},
				{ID: "os", Label: "OS", Default: true},
				{ID: "dns_hostname", Label: "DNS Host", Default: true},
				{ID: "enabled", Label: "Enabled", Default: true},
				{ID: "uac_flags", Label: "UAC Flags", Default: false},
				{ID: "spn", Label: "SPN", Default: false},
			}},
			{ID: "shares", Label: "Shares", Default: false, Columns: []ExportColumn{
				{ID: "host", Label: "Host", Default: true},
				{ID: "name", Label: "Share", Default: true},
				{ID: "type", Label: "Type", Default: false},
				{ID: "comment", Label: "Comment", Default: false},
				{ID: "readable", Label: "Readable", Default: true},
				{ID: "writable", Label: "Writable", Default: true},
			}},
			{ID: "acl_findings", Label: "ACL Findings", Default: false, Columns: []ExportColumn{
				{ID: "source", Label: "Source", Default: true},
				{ID: "target", Label: "Target", Default: true},
				{ID: "right", Label: "Right", Default: true},
				{ID: "path", Label: "Path", Default: false},
				{ID: "actionable", Label: "Actionable", Default: true},
			}},
			{ID: "kerberoast", Label: "Kerberoastable", Default: true, Columns: []ExportColumn{
				{ID: "username", Label: "Username", Default: true},
				{ID: "spn", Label: "SPN", Default: true},
				{ID: "hash_file", Label: "Hash File", Default: false},
			}},
			{ID: "hashes", Label: "Captured Hashes", Default: true, Columns: []ExportColumn{
				{ID: "type", Label: "Type", Default: true},
				{ID: "account", Label: "Account", Default: true},
				{ID: "realm", Label: "Realm", Default: false},
				{ID: "source", Label: "Captured Via", Default: true},
				{ID: "cracked_secret", Label: "Cracked", Default: true},
				{ID: "captured_at", Label: "Captured At", Default: false},
			}},
			{ID: "vulns", Label: "Vulnerabilities", Default: true, HasSeverity: true, Columns: []ExportColumn{
				{ID: "cve", Label: "CVE", Default: true},
				{ID: "name", Label: "Name", Default: true},
				{ID: "host", Label: "Host", Default: true},
				{ID: "severity", Label: "Severity", Default: true},
				{ID: "detail", Label: "Detail", Default: false},
				{ID: "exploit_cmd", Label: "Exploit", Default: false},
			}},
			{ID: "lateral", Label: "Lateral Movement", Default: false, Columns: []ExportColumn{
				{ID: "title", Label: "Title", Default: true},
				{ID: "tool", Label: "Tool", Default: true},
				{ID: "risk", Label: "Risk", Default: true},
				{ID: "command", Label: "Command", Default: true},
				{ID: "notes", Label: "Notes", Default: false},
			}},
		}

	case "concurtest":
		return []ExportSection{
			{ID: "summary", Label: "Per-Target Summary", Default: true, Columns: []ExportColumn{
				{ID: "url", Label: "URL", Default: true},
				{ID: "baseline_ms", Label: "Baseline (ms)", Default: true},
				{ID: "practical_max", Label: "Practical Max", Default: true},
				{ID: "notes", Label: "Notes", Default: false},
				{ID: "error", Label: "Error", Default: false},
			}},
			{ID: "ramp", Label: "Ramp Buckets", Default: false, Columns: []ExportColumn{
				{ID: "url", Label: "URL", Default: true},
				{ID: "label", Label: "Bucket", Default: true},
				{ID: "concurrency", Label: "Concurrency", Default: true},
				{ID: "requests", Label: "Requests", Default: true},
				{ID: "successes", Label: "Successes", Default: true},
				{ID: "errors", Label: "Errors", Default: true},
				{ID: "p50_ms", Label: "P50 (ms)", Default: true},
				{ID: "p95_ms", Label: "P95 (ms)", Default: true},
				{ID: "p99_ms", Label: "P99 (ms)", Default: false},
				{ID: "throughput_rps", Label: "RPS", Default: true},
				{ID: "healthy", Label: "Healthy", Default: true},
			}},
			{ID: "sustained", Label: "Sustained Bucket", Default: false, Columns: []ExportColumn{
				{ID: "url", Label: "URL", Default: true},
				{ID: "concurrency", Label: "Concurrency", Default: true},
				{ID: "requests", Label: "Requests", Default: true},
				{ID: "successes", Label: "Successes", Default: true},
				{ID: "errors", Label: "Errors", Default: true},
				{ID: "p50_ms", Label: "P50 (ms)", Default: true},
				{ID: "p95_ms", Label: "P95 (ms)", Default: true},
				{ID: "duration_ms", Label: "Duration (ms)", Default: true},
			}},
			{ID: "burst", Label: "Burst Bucket", Default: false, Columns: []ExportColumn{
				{ID: "url", Label: "URL", Default: true},
				{ID: "concurrency", Label: "Concurrency", Default: true},
				{ID: "requests", Label: "Requests", Default: true},
				{ID: "successes", Label: "Successes", Default: true},
				{ID: "errors", Label: "Errors", Default: true},
				{ID: "p50_ms", Label: "P50 (ms)", Default: true},
				{ID: "p95_ms", Label: "P95 (ms)", Default: true},
				{ID: "duration_ms", Label: "Duration (ms)", Default: true},
			}},
		}

	case "oob":
		return []ExportSection{
			{ID: "interactions", Label: "OOB Interactions", Default: true, Columns: []ExportColumn{
				{ID: "kind", Label: "Kind", Default: true},
				{ID: "token", Label: "Token", Default: true},
				{ID: "at", Label: "Timestamp", Default: true},
				{ID: "remote_addr", Label: "Source IP", Default: true},
				{ID: "host", Label: "Host", Default: true},
				{ID: "method", Label: "HTTP Method", Default: true},
				{ID: "path", Label: "Path", Default: true},
				{ID: "user_agent", Label: "User-Agent", Default: false},
				{ID: "subdomain", Label: "Subdomain", Default: false},
				{ID: "query_type", Label: "DNS Type", Default: false},
				{ID: "body_snippet", Label: "Body Snippet", Default: false},
			}},
		}

	case "assetdisc":
		return []ExportSection{
			{ID: "assets", Label: "Discovered Assets", Default: true, Columns: []ExportColumn{
				{ID: "source", Label: "Source", Default: true},
				{ID: "ip", Label: "IP", Default: true},
				{ID: "port", Label: "Port", Default: true},
				{ID: "hostname", Label: "Hostname", Default: true},
				{ID: "asn", Label: "ASN", Default: false},
				{ID: "org", Label: "Org", Default: true},
				{ID: "country", Label: "Country", Default: false},
				{ID: "product", Label: "Product", Default: true},
				{ID: "os", Label: "OS", Default: false},
				{ID: "banner", Label: "Banner", Default: false},
				{ID: "domains", Label: "Domains", Default: false},
			}},
			{ID: "queries", Label: "Per-Query Summary", Default: false, Columns: []ExportColumn{
				{ID: "source", Label: "Source", Default: true},
				{ID: "query", Label: "Query", Default: true},
				{ID: "total", Label: "Total Hits", Default: true},
				{ID: "error", Label: "Error", Default: false},
			}},
		}

	case "cvematch":
		// Per-match row plus the underlying inputs in a separate section
		// so analysts can join the two via (product, version) outside.
		return []ExportSection{
			{ID: "matches", Label: "CVE Matches", Default: true, Columns: []ExportColumn{
				{ID: "target_url", Label: "Target URL", Default: true},
				{ID: "product", Label: "Product", Default: true},
				{ID: "version", Label: "Version", Default: true},
				{ID: "cve", Label: "CVE", Default: true},
				{ID: "severity", Label: "Severity", Default: true},
				{ID: "cvss", Label: "CVSS", Default: true},
				{ID: "fixed_in", Label: "Fixed In", Default: true},
				{ID: "description", Label: "Description", Default: true},
				{ID: "remediation", Label: "Remediation", Default: true},
				{ID: "reference", Label: "Reference", Default: true},
				{ID: "source", Label: "Match Source", Default: false},
			}},
			{ID: "inputs", Label: "Inputs", Default: false, Columns: []ExportColumn{
				{ID: "product", Label: "Product", Default: true},
				{ID: "version", Label: "Version", Default: true},
				{ID: "url", Label: "Target URL", Default: true},
				{ID: "source", Label: "Source", Default: false},
			}},
		}
	case "advancedweb":
		// Suite export — one section per stage that produced data. The
		// CSV writer flattens each stage's native shape into the same
		// columns its standalone export uses.
		return []ExportSection{
			{ID: "summary", Label: "Suite Summary", Default: true, Columns: []ExportColumn{
				{ID: "stage", Label: "Stage", Default: true},
				{ID: "status", Label: "Status", Default: true},
				{ID: "message", Label: "Message", Default: true},
				{ID: "started_at", Label: "Started", Default: false},
				{ID: "finished_at", Label: "Finished", Default: false},
				{ID: "duration", Label: "Duration", Default: true},
			}},
			{ID: "dnsenum", Label: "DNS Subdomains", Default: true, Columns: []ExportColumn{
				{ID: "subdomain", Label: "Subdomain", Default: true},
				{ID: "ips", Label: "IPs", Default: true},
				{ID: "source", Label: "Source", Default: false},
			}},
			{ID: "httpxfind", Label: "HTTP Services", Default: true, Columns: []ExportColumn{
				{ID: "url", Label: "URL", Default: true},
				{ID: "status_code", Label: "Status", Default: true},
				{ID: "title", Label: "Title", Default: true},
				{ID: "server", Label: "Server", Default: true},
			}},
			{ID: "techdetect", Label: "Technologies", Default: true, Columns: []ExportColumn{
				{ID: "url", Label: "URL", Default: true},
				{ID: "name", Label: "Tech", Default: true},
				{ID: "version", Label: "Version", Default: true},
				{ID: "category", Label: "Category", Default: false},
			}},
			{ID: "cvematch", Label: "CVE Matches", Default: true, Columns: []ExportColumn{
				{ID: "target_url", Label: "Target URL", Default: true},
				{ID: "product", Label: "Product", Default: true},
				{ID: "version", Label: "Version", Default: true},
				{ID: "cve", Label: "CVE", Default: true},
				{ID: "severity", Label: "Severity", Default: true},
				{ID: "fixed_in", Label: "Fixed In", Default: true},
			}},
			{ID: "nuclei", Label: "Nuclei Findings", Default: true, Columns: []ExportColumn{
				{ID: "url", Label: "URL", Default: true},
				{ID: "template", Label: "Template", Default: true},
				{ID: "severity", Label: "Severity", Default: true},
				{ID: "name", Label: "Name", Default: true},
			}},

			// Commit 4: 7 additional stage sections. Column lists mirror
			// the primary section of each standalone module so the suite
			// view and the per-module view stay aligned.

			{ID: "whois", Label: "WHOIS Summary", Default: true, Columns: []ExportColumn{
				{ID: "target", Label: "Target", Default: true},
				{ID: "kind", Label: "Kind", Default: true},
				{ID: "ip", Label: "IP", Default: true},
				{ID: "asn", Label: "ASN", Default: true},
				{ID: "organization", Label: "Organization", Default: true},
				{ID: "country", Label: "Country", Default: false},
			}},
			{ID: "sslscan", Label: "SSL/TLS Findings", Default: true, HasSeverity: true, Columns: []ExportColumn{
				{ID: "host", Label: "Host", Default: true},
				{ID: "title", Label: "Title", Default: true},
				{ID: "description", Label: "Description", Default: false},
				{ID: "severity", Label: "Severity", Default: true},
				{ID: "category", Label: "Category", Default: false},
			}},
			{ID: "wafdetect", Label: "WAF Detection", Default: true, Columns: []ExportColumn{
				{ID: "url", Label: "URL", Default: true},
				{ID: "waf_detected", Label: "WAF?", Default: true},
				{ID: "waf_name", Label: "WAF Name", Default: true},
				{ID: "confidence", Label: "Confidence", Default: true},
			}},
			{ID: "wpscan", Label: "WordPress Findings", Default: true, HasSeverity: true, Columns: []ExportColumn{
				{ID: "url", Label: "URL", Default: true},
				{ID: "title", Label: "Title", Default: true},
				{ID: "severity", Label: "Severity", Default: true},
				{ID: "category", Label: "Category", Default: true},
				{ID: "description", Label: "Description", Default: false},
			}},
			{ID: "dirspider", Label: "Discovered Paths", Default: true, Columns: []ExportColumn{
				{ID: "url", Label: "URL", Default: true},
				{ID: "status_code", Label: "Status", Default: true},
				{ID: "size", Label: "Size", Default: true},
				{ID: "source", Label: "Source", Default: false},
			}},
			{ID: "httpmethods", Label: "HTTP Methods", Default: true, Columns: []ExportColumn{
				{ID: "url", Label: "URL", Default: true},
				{ID: "method", Label: "Method", Default: true},
				{ID: "status_code", Label: "Status", Default: true},
				{ID: "is_dangerous", Label: "Dangerous", Default: true},
			}},
			{ID: "secheaders", Label: "Security Headers", Default: true, HasSeverity: true, Columns: []ExportColumn{
				{ID: "url", Label: "URL", Default: true},
				{ID: "header", Label: "Header", Default: true},
				{ID: "severity", Label: "Severity", Default: true},
				{ID: "status", Label: "Status", Default: true},
				{ID: "recommend", Label: "Recommendation", Default: false},
			}},
		}
	}
	return nil
}

// ExportColumnSelected returns true if the column is checked. The selected
// map's keys are "<sectionID>.<columnID>". When the selected map is empty for
// a given section, fall back to the column's Default flag.
func ExportColumnSelected(sectionID, columnID string, selected map[string]bool, columns []ExportColumn) bool {
	if len(selected) == 0 {
		for _, c := range columns {
			if c.ID == columnID {
				return c.Default
			}
		}
		return false
	}
	// If user touched THIS section's checkboxes, only honor the explicit set.
	hasAny := false
	for k := range selected {
		if len(k) > len(sectionID)+1 && k[:len(sectionID)+1] == sectionID+"." {
			hasAny = true
			break
		}
	}
	if !hasAny {
		// Section selected but no per-column choices made → use defaults
		for _, c := range columns {
			if c.ID == columnID {
				return c.Default
			}
		}
		return false
	}
	return selected[sectionID+"."+columnID]
}

// ExportFilteredHeaders returns the labels (in declared order) of the columns
// the user has selected for this section.
func ExportFilteredHeaders(sectionID string, columns []ExportColumn, selected map[string]bool) []string {
	out := []string{}
	for _, c := range columns {
		if ExportColumnSelected(sectionID, c.ID, selected, columns) {
			out = append(out, c.Label)
		}
	}
	return out
}

// ExportFilteredRow extracts the values for the selected columns of a row in
// declared order. Pass row keyed by column ID.
func ExportFilteredRow(sectionID string, columns []ExportColumn, selected map[string]bool, row map[string]string) []string {
	out := []string{}
	for _, c := range columns {
		if ExportColumnSelected(sectionID, c.ID, selected, columns) {
			out = append(out, row[c.ID])
		}
	}
	return out
}

// ParseSeveritiesParam decodes the ?severities=CRITICAL,HIGH,... query into a
// set of upper-cased severity tokens. Empty input means "all severities pass"
// — the writer should treat the filter as a no-op.
func ParseSeveritiesParam(s string) map[string]bool {
	out := map[string]bool{}
	if s == "" {
		return out
	}
	for _, p := range splitCSV(s) {
		p = upperTrim(p)
		if p != "" {
			out[p] = true
		}
	}
	return out
}

// SeverityAllowed returns true when no filter is set, or the severity (in any
// casing) matches one of the selected entries.
func SeverityAllowed(sev string, filter map[string]bool) bool {
	if len(filter) == 0 {
		return true
	}
	return filter[upperTrim(sev)]
}

// HasAnySeveritySection returns true if the module has at least one
// HasSeverity-bearing section, used to decide whether the modal should show
// the severity filter group.
func HasAnySeveritySection(module string) bool {
	for _, s := range ExportSchema(module) {
		if s.HasSeverity {
			return true
		}
	}
	return false
}

func splitCSV(s string) []string {
	var out []string
	cur := ""
	for _, r := range s {
		if r == ',' {
			out = append(out, cur)
			cur = ""
			continue
		}
		cur += string(r)
	}
	if cur != "" {
		out = append(out, cur)
	}
	return out
}

func upperTrim(s string) string {
	// Strict upper-case + strip whitespace; severities are short ASCII.
	out := make([]byte, 0, len(s))
	for i := 0; i < len(s); i++ {
		c := s[i]
		if c == ' ' || c == '\t' || c == '\n' || c == '\r' {
			continue
		}
		if c >= 'a' && c <= 'z' {
			c -= 32
		}
		out = append(out, c)
	}
	return string(out)
}

// SectionInSchema checks if a section ID exists in the module's schema and is
// either explicitly enabled in the selected set OR was the default when the
// user submitted no section choices at all.
func SectionInSchema(module, sectionID string, sectionsSelected map[string]bool) bool {
	schema := ExportSchema(module)
	if len(sectionsSelected) == 0 {
		for _, s := range schema {
			if s.ID == sectionID {
				return s.Default
			}
		}
		return false
	}
	return sectionsSelected[sectionID]
}
