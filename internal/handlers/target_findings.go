package handlers

import (
	"sort"
	"strings"
	"time"

	"scanner/internal/models"
)

// target_findings.go — the date-aware, per-target findings engine that powers
// the asset/target detail page (/assets/{value}, reached by clicking a target).
//
// It replaces the older dateless extractAssetFindings summary. Where the old
// engine merged every scan's output into one flat AssetFindings struct of
// []string + int counters (losing which scan — and which DATE — each finding
// came from), this one produces one TargetFinding per distinct discovery,
// carrying FirstSeen / LastSeen dates aggregated across every scan that saw it.
//
// Data flow:
//   extractTargetFindings(target, scans)
//     └─ for each scan: dispatchTargetParser(module, result, target, date, id, emit)
//          └─ per-module parseXxxTarget(...) unmarshals result, filters to the
//             target host, and calls emit(targetRaw, when) once per finding.
//     └─ emit dedupes on module|category|title|locus, folding first/last seen.
//
// Adding a module = write one parseXxxTarget in tf_<module>.go against the
// contract documented on targetRaw below, then add its case to
// dispatchTargetParser.

// Category names double as the section titles on the detail page. CatVuln is
// special: those findings render in the top severity-sorted table; every other
// category renders as an informational box (chips, each date-badged).
const (
	CatVuln       = "Vulnerabilities"
	CatCreds      = "Credentials & Secrets"
	CatHostStatus = "Host Status"
	CatPorts      = "Ports"
	CatServices   = "Services"
	CatTech       = "Technologies"
	CatWAF        = "WAF"
	CatSubdomains = "Subdomains"
	CatWebContent = "Web Content"
	CatTLS        = "TLS / SSL"
	CatHeaders    = "Headers / Web-Misconfig"
	CatSMBAD      = "SMB / AD"
	CatEmailRecon = "Email / Recon"
	CatWhois      = "WHOIS / ASN"
	CatOOB        = "OOB Interactions"
)

// categoryOrder fixes the render order + icon of the informational boxes.
// CatVuln is intentionally absent (it drives the top table, not a box).
var categoryOrder = []struct{ Name, Icon string }{
	{CatCreds, "🔓"},
	{CatHostStatus, "🖥️"},
	{CatPorts, "📡"},
	{CatServices, "🛰️"},
	{CatTech, "🧬"},
	{CatWAF, "🛡️"},
	{CatSubdomains, "🔎"},
	{CatWebContent, "📂"},
	{CatTLS, "🔐"},
	{CatHeaders, "🧱"},
	{CatSMBAD, "🗄️"},
	{CatEmailRecon, "📧"},
	{CatWhois, "🌐"},
	{CatOOB, "🕸️"},
}

// TargetFinding is one distinct discovery for a target, aggregated across every
// scan that observed it.
type TargetFinding struct {
	SevRank   int       // 4=critical … 1=low, 0=info, -1=no severity (recon fact)
	Severity  string    // "CRITICAL"… or "" for recon facts
	Category  string    // one of the Cat* constants
	Module    string    // provenance label ("nuclei", "sslscan", "nuclei via advancedweb")
	Title     string    // one-line summary
	Detail    string    // longer text / evidence (optional)
	Locus     string    // where: "443/tcp", "https://x/admin", "svc_sql@CORP", ""
	ScanID    string    // owning scan of the most-recent sighting (for the link)
	ScanURL   string    // "/modules/<mod>/results/<id>" of that scan
	FirstSeen time.Time
	LastSeen  time.Time
	Count     int // how many scans saw it
	// Typed enrichment (Task 4) — optional; rendered in the finding's detail
	// drawer when present.
	CVEs        []string
	References  []string
	Evidence    string
	Remediation string
	RawRequest  string
	RawResponse string
}

// HasDetailDrawer reports whether a finding carries any typed enrichment worth
// an expandable drawer (beyond the always-shown Title/Detail/Locus).
func (f TargetFinding) HasDetailDrawer() bool {
	return len(f.CVEs) > 0 || len(f.References) > 0 || f.Evidence != "" ||
		f.Remediation != "" || f.RawRequest != "" || f.RawResponse != ""
}

// FindingCategory is one informational box on the page.
type FindingCategory struct {
	Name  string
	Icon  string
	Items []TargetFinding
}

// TargetFindingSet is the full page payload.
type TargetFindingSet struct {
	Vulns      []TargetFinding   // CatVuln, sorted SevRank↓ then LastSeen↓
	Categories []FindingCategory // informational boxes, fixed order, non-empty only
	CritCount  int
	HighCount  int
	MedCount   int
	LowCount   int
	InfoCount  int
	HasAny     bool
}

// targetRaw is what a per-module parser emits — one pre-dedup, pre-date finding.
//
// Parser contract (tf_<module>.go):
//
//	func parseXxxTarget(resJSON, target string, scanDate time.Time, scanID string, emit func(targetRaw, time.Time))
//
//   - resJSON  = the scan's Result column (module's own ScanResult JSON).
//   - target   = the normalized asset key (normalizeAsset output) to filter to.
//   - scanDate = default detection time; pass it to emit unless the result
//     carries a better per-item timestamp (assetdisc, oob).
//   - scanID   = owning scan id (used by emit for the link; parser ignores it).
//   - emit     = call once per finding: emit(targetRaw{...}, scanDate).
//
// Set Module on every raw. Use CatVuln only for confirmed issues that carry a
// severity; put configuration weaknesses in CatHeaders and recon facts in their
// category with SevRank -1.
type targetRaw struct {
	SevRank  int
	Severity string
	Category string
	Module   string
	Title    string
	Detail   string
	Locus    string
	// Optional typed enrichment (Task 4). Any parser that has these promotes
	// them out of free-text Detail so the unified findings view can render a
	// structured drawer (CVE links, evidence, the request/response that proved
	// it, remediation). All optional — absent fields just don't render.
	CVEs        []string
	References  []string
	Evidence    string
	Remediation string
	RawRequest  string
	RawResponse string
}

// extractTargetFindings inspects every scan that touched `target` and returns a
// date-aware, deduped, categorized finding set. `target` is the normalized
// asset key (same form as normalizeAsset produces). Each scan's own module
// parser filters to the target internally.
func (h *Handler) extractTargetFindings(target string, scans []models.Scan) TargetFindingSet {
	agg := map[string]*TargetFinding{}
	order := make([]string, 0, 64)

	for _, s := range scans {
		scanID := s.ID
		scanDate := s.CreatedAt
		scanURL := "/modules/" + s.Module + "/results/" + s.ID

		emit := func(r targetRaw, when time.Time) {
			if strings.TrimSpace(r.Title) == "" {
				return
			}
			if when.IsZero() {
				when = scanDate
			}
			key := r.Module + "|" + r.Category + "|" + r.Title + "|" + r.Locus
			f := agg[key]
			if f == nil {
				nf := TargetFinding{
					SevRank:     r.SevRank,
					Severity:    r.Severity,
					Category:    r.Category,
					Module:      r.Module,
					Title:       r.Title,
					Detail:      r.Detail,
					Locus:       r.Locus,
					ScanID:      scanID,
					ScanURL:     scanURL,
					FirstSeen:   when,
					LastSeen:    when,
					Count:       1,
					CVEs:        r.CVEs,
					References:  r.References,
					Evidence:    r.Evidence,
					Remediation: r.Remediation,
					RawRequest:  r.RawRequest,
					RawResponse: r.RawResponse,
				}
				agg[key] = &nf
				order = append(order, key)
				return
			}
			f.Count++
			if when.Before(f.FirstSeen) {
				f.FirstSeen = when
			}
			if !when.Before(f.LastSeen) {
				f.LastSeen = when
				f.ScanID = scanID
				f.ScanURL = scanURL
			}
			if f.Detail == "" && r.Detail != "" {
				f.Detail = r.Detail
			}
			// Backfill any typed enrichment a later sighting carries.
			if len(f.CVEs) == 0 {
				f.CVEs = r.CVEs
			}
			if len(f.References) == 0 {
				f.References = r.References
			}
			if f.Evidence == "" {
				f.Evidence = r.Evidence
			}
			if f.Remediation == "" {
				f.Remediation = r.Remediation
			}
			if f.RawRequest == "" {
				f.RawRequest = r.RawRequest
			}
			if f.RawResponse == "" {
				f.RawResponse = r.RawResponse
			}
		}

		dispatchTargetParser(s.Module, s.Result, target, scanDate, scanID, emit)
	}

	set := TargetFindingSet{}
	catMap := map[string][]TargetFinding{}
	for _, key := range order {
		f := *agg[key]
		if f.Category == CatVuln {
			set.Vulns = append(set.Vulns, f)
			switch f.SevRank {
			case 4:
				set.CritCount++
			case 3:
				set.HighCount++
			case 2:
				set.MedCount++
			case 1:
				set.LowCount++
			default:
				set.InfoCount++
			}
		} else {
			catMap[f.Category] = append(catMap[f.Category], f)
		}
	}

	sort.SliceStable(set.Vulns, func(i, j int) bool {
		if set.Vulns[i].SevRank != set.Vulns[j].SevRank {
			return set.Vulns[i].SevRank > set.Vulns[j].SevRank
		}
		return set.Vulns[i].LastSeen.After(set.Vulns[j].LastSeen)
	})

	for _, c := range categoryOrder {
		items := catMap[c.Name]
		if len(items) == 0 {
			continue
		}
		sort.SliceStable(items, func(i, j int) bool {
			if items[i].SevRank != items[j].SevRank {
				return items[i].SevRank > items[j].SevRank
			}
			return items[i].Title < items[j].Title
		})
		set.Categories = append(set.Categories, FindingCategory{Name: c.Name, Icon: c.Icon, Items: items})
	}

	set.HasAny = len(set.Vulns) > 0 || len(set.Categories) > 0
	return set
}

// dispatchTargetParser routes a scan's result JSON to its module parser.
// One case per module; unknown modules contribute nothing.
func dispatchTargetParser(module, resJSON, target string, scanDate time.Time, scanID string, emit func(targetRaw, time.Time)) {
	switch module {
	case "adpentest":
		parseAdpentestTarget(resJSON, target, scanDate, scanID, emit)
	case "advancedweb":
		parseAdvancedWebTarget(resJSON, target, scanDate, scanID, emit)
	case "assetdisc":
		parseAssetDiscTarget(resJSON, target, scanDate, scanID, emit)
	case "authtest":
		parseAuthTestTarget(resJSON, target, scanDate, scanID, emit)
	case "brutef":
		parseBruteFTarget(resJSON, target, scanDate, scanID, emit)
	case "cachepoison":
		parseCachePoisonTarget(resJSON, target, scanDate, scanID, emit)
	case "concurtest":
		parseConcurTestTarget(resJSON, target, scanDate, scanID, emit)
	case "corsscan":
		parseCORSTarget(resJSON, target, scanDate, scanID, emit)
	case "cvematch":
		parseCVEMatchTarget(resJSON, target, scanDate, scanID, emit)
	case "direnum":
		parseDirEnumTarget(resJSON, target, scanDate, scanID, emit)
	case "dnsenum":
		parseDNSEnumTarget(resJSON, target, scanDate, scanID, emit)
	case "emailharvest":
		parseEmailHarvestTarget(resJSON, target, scanDate, scanID, emit)
	case "graphqlscan":
		parseGraphQLTarget(resJSON, target, scanDate, scanID, emit)
	case "hostdiscovery":
		parseHostDiscoveryTarget(resJSON, target, scanDate, scanID, emit)
	case "httpmethods":
		parseHTTPMethodsTarget(resJSON, target, scanDate, scanID, emit)
	case "httpxfind":
		parseHTTPXFindTarget(resJSON, target, scanDate, scanID, emit)
	case "jwt":
		parseJWTTarget(resJSON, target, scanDate, scanID, emit)
	case "leakscan":
		parseLeakScanTarget(resJSON, target, scanDate, scanID, emit)
	case "nuclei":
		parseNucleiTarget(resJSON, target, scanDate, scanID, emit)
	case "oob":
		parseOobTarget(resJSON, target, scanDate, scanID, emit)
	case "openredirect":
		parseOpenRedirectTarget(resJSON, target, scanDate, scanID, emit)
	case "paramdisc":
		parseParamDiscTarget(resJSON, target, scanDate, scanID, emit)
	case "portservice":
		parsePortServiceTarget(resJSON, target, scanDate, scanID, emit)
	case "secheaders":
		parseSecHeadersTarget(resJSON, target, scanDate, scanID, emit)
	case "smbenum":
		parseSMBEnumTarget(resJSON, target, scanDate, scanID, emit)
	case "snmpenum":
		parseSNMPEnumTarget(resJSON, target, scanDate, scanID, emit)
	case "spider":
		parseSpiderTarget(resJSON, target, scanDate, scanID, emit)
	case "sslscan":
		parseSSLScanTarget(resJSON, target, scanDate, scanID, emit)
	case "sstiscan":
		parseSSTITarget(resJSON, target, scanDate, scanID, emit)
	case "takeover":
		parseTakeoverTarget(resJSON, target, scanDate, scanID, emit)
	case "techdetect":
		parseTechDetectTarget(resJSON, target, scanDate, scanID, emit)
	case "wafdetect":
		parseWAFDetectTarget(resJSON, target, scanDate, scanID, emit)
	case "whoisinfo":
		parseWhoisTarget(resJSON, target, scanDate, scanID, emit)
	case "wpscan":
		parseWPScanTarget(resJSON, target, scanDate, scanID, emit)
	}
}

// --- shared helpers (moved here from the retired asset_findings.go) ---

// severityRank converts a textual severity into a sortable integer.
// Critical=4 down to Info=0. Unknown strings sort below info (-1).
func severityRank(s string) int {
	switch strings.ToUpper(strings.TrimSpace(s)) {
	case "CRITICAL":
		return 4
	case "HIGH":
		return 3
	case "MEDIUM":
		return 2
	case "LOW":
		return 1
	case "INFO", "INFORMATIONAL", "NONE":
		return 0
	}
	return -1
}

// urlMatchesAsset tests whether a probed URL belongs to the asset/target key.
// Exact-host match only: the URL's normalized host must equal the target.
// A subdomain (dev.example.com) therefore does NOT match its parent
// (example.com) — each host's findings live on its own asset page.
func urlMatchesAsset(rawURL, asset string) bool {
	if rawURL == "" {
		return false
	}
	return normalizeAsset(rawURL) == asset
}

// appendUnique appends s to slice unless empty or already present.
func appendUnique(slice []string, s string) []string {
	if s == "" {
		return slice
	}
	for _, x := range slice {
		if x == s {
			return slice
		}
	}
	return append(slice, s)
}
