package handlers

import (
	"encoding/csv"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"time"

	"scanner/internal/modules/adpentest"
	"scanner/internal/modules/advancedweb"
	"scanner/internal/modules/assetdisc"
	"scanner/internal/modules/authtest"
	"scanner/internal/modules/brutef"
	"scanner/internal/modules/cachepoison"
	"scanner/internal/modules/concurtest"
	"scanner/internal/modules/corsscan"
	"scanner/internal/modules/cvematch"
	"scanner/internal/modules/direnum"
	"scanner/internal/modules/dnsenum"
	"scanner/internal/modules/emailharvest"
	"scanner/internal/modules/graphqlscan"
	"scanner/internal/modules/hostdiscovery"
	"scanner/internal/modules/httpmethods"
	"scanner/internal/modules/httpxfind"
	"scanner/internal/modules/jwt"
	"scanner/internal/modules/leakscan"
	"scanner/internal/modules/nuclei"
	"scanner/internal/modules/oob"
	"scanner/internal/modules/openredirect"
	"scanner/internal/modules/paramdisc"
	"scanner/internal/modules/portservice"
	"scanner/internal/modules/secheaders"
	"scanner/internal/modules/smbenum"
	"scanner/internal/modules/snmpenum"
	"scanner/internal/modules/spider"
	"scanner/internal/modules/sslscan"
	"scanner/internal/modules/sstiscan"
	"scanner/internal/modules/takeover"
	"scanner/internal/modules/techdetect"
	"scanner/internal/modules/wafdetect"
	"scanner/internal/modules/whoisinfo"
	"scanner/internal/modules/wpscan"

	"github.com/go-pdf/fpdf"
)

// ExportScan handles CSV/JSON/PDF export for any module's scan results.
// Query params: format=csv|json|pdf, sections=comma-separated list of sections
func (h *Handler) ExportScan(w http.ResponseWriter, r *http.Request) {
	scanID := strings.TrimPrefix(r.URL.Path, "/export/")
	if scanID == "" {
		http.NotFound(w, r)
		return
	}

	scan, err := h.db.GetScan(scanID)
	if err != nil {
		http.NotFound(w, r)
		return
	}

	format := r.URL.Query().Get("format")
	sectionsParam := r.URL.Query().Get("sections")
	sections := map[string]bool{}
	if sectionsParam != "" {
		for _, s := range strings.Split(sectionsParam, ",") {
			sections[strings.TrimSpace(s)] = true
		}
	}
	// Belt-and-braces: even when the URL declares sections the scan
	// didn't run (advancedweb suite with TechDetect off, e.g.), drop
	// them here. The modal already filters via ExportSchemaFor, but a
	// hand-crafted URL would still trigger empty writer sections.
	if allowed := ExportSchemaFor(scan); len(allowed) > 0 {
		valid := map[string]bool{}
		for _, s := range allowed {
			valid[s.ID] = true
		}
		for id := range sections {
			if !valid[id] {
				delete(sections, id)
			}
		}
	}
	columns := parseColumnsParam(r.URL.Query().Get("columns"))
	severities := ParseSeveritiesParam(r.URL.Query().Get("severities"))

	shortID := scanID
	if len(shortID) > 8 {
		shortID = shortID[:8]
	}

	switch format {
	case "json":
		h.exportJSON(w, scan.Module, scan.Result, shortID, sections, severities)
	case "pdf":
		h.exportPDF(w, scan.Module, scan.Result, shortID, sections, columns, severities)
	default:
		h.exportCSV(w, scan.Module, scan.Result, shortID, sections, columns, severities, r)
	}
}

// ExportSectionsAPI returns available export sections (with their per-column
// schema) for a scan as JSON. Powers the modal column checkboxes.
func (h *Handler) ExportSectionsAPI(w http.ResponseWriter, r *http.Request) {
	scanID := strings.TrimPrefix(r.URL.Path, "/export/sections/")
	scan, err := h.db.GetScan(scanID)
	if err != nil {
		http.NotFound(w, r)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(ExportSchemaFor(scan))
}

// parseColumnsParam parses the ?columns= query into a selected map keyed by
// "section.column".
func parseColumnsParam(s string) map[string]bool {
	out := map[string]bool{}
	if s == "" {
		return out
	}
	for _, k := range strings.Split(s, ",") {
		k = strings.TrimSpace(k)
		if k != "" {
			out[k] = true
		}
	}
	return out
}

// sectionColumns returns the column list for one section in a module's schema.
func sectionColumns(module, sectionID string) []ExportColumn {
	for _, s := range ExportSchema(module) {
		if s.ID == sectionID {
			return s.Columns
		}
	}
	return nil
}

// writeFilteredCSV emits a header row + one or more value rows honoring the
// column selection. `row` is keyed by column ID.
func writeFilteredCSVHeader(w *csv.Writer, module, sectionID string, columns map[string]bool) {
	cols := sectionColumns(module, sectionID)
	w.Write(ExportFilteredHeaders(sectionID, cols, columns))
}
func writeFilteredCSVRow(w *csv.Writer, module, sectionID string, columns map[string]bool, row map[string]string) {
	cols := sectionColumns(module, sectionID)
	w.Write(ExportFilteredRow(sectionID, cols, columns, row))
}

// --- CSV ---

func (h *Handler) exportCSV(w http.ResponseWriter, module, result, shortID string, sections map[string]bool, columns map[string]bool, severities map[string]bool, r *http.Request) {
	w.Header().Set("Content-Type", "text/csv; charset=utf-8")
	w.Header().Set("Content-Disposition", fmt.Sprintf("attachment; filename=%s_%s.csv", module, shortID))
	writer := csv.NewWriter(w)
	defer writer.Flush()

	// If no sections specified, use defaults
	if len(sections) == 0 {
		switch module {
		case "sslscan":
			sections["findings"] = true
		case "httpxfind":
			sections["services"] = true
		case "httpmethods":
			sections["methods"] = true
		case "wafdetect":
			sections["results"] = true
		case "wpscan":
			sections["vulnerabilities"] = true
		case "dnsenum":
			sections["subdomains"] = true
		case "techdetect":
			sections["technologies"] = true
		case "spider":
			sections["all"] = true
		case "direnum":
			sections["all"] = true
		case "secheaders":
			sections["findings"] = true
		// Commit 1: defaults for modules whose schema already declared
		// columns but whose writer was missing — pick the most useful
		// "primary" section so a no-tick export still produces something.
		case "nuclei":
			sections["findings"] = true
		case "hostdiscovery":
			sections["hosts"] = true
		case "portservice":
			sections["ports"] = true
		case "smbenum":
			sections["shares"] = true
		case "brutef":
			sections["credentials"] = true
		case "whoisinfo":
			sections["summary"] = true
		case "emailharvest":
			sections["emails"] = true
		case "leakscan":
			sections["hits"] = true
		case "snmpenum":
			sections["communities"] = true
		case "jwt":
			sections["summary"] = true
			sections["issues"] = true
		case "paramdisc":
			sections["hits"] = true
		// Commit 2 defaults — schema brand-new for these modules.
		case "takeover":
			sections["findings"] = true
		case "corsscan":
			sections["findings"] = true
		case "openredirect":
			sections["findings"] = true
		case "graphqlscan":
			sections["endpoints"] = true
			sections["findings"] = true
		case "authtest":
			sections["findings"] = true
		case "sstiscan":
			sections["findings"] = true
		case "cachepoison":
			sections["findings"] = true
		case "assetdisc":
			sections["assets"] = true
		// Commit 3 defaults.
		case "adpentest":
			sections["discovery"] = true
			sections["vulns"] = true
			sections["hashes"] = true
			sections["kerberoast"] = true
		case "concurtest":
			sections["summary"] = true
		case "oob":
			sections["interactions"] = true
		}
	}

	switch module {
	case "sslscan":
		var results []*sslscan.HostResult
		json.Unmarshal([]byte(result), &results)
		sortMode := r.URL.Query().Get("sort")
		if sortMode == "" {
			sortMode = "severity"
		}
		sortSSLResults(results, sortMode)

		if sections["findings"] {
			writeFilteredCSVHeader(writer, "sslscan", "findings", columns)
			for _, hr := range results {
				if !hr.Reachable || len(hr.Findings) == 0 {
					continue
				}
				for _, f := range hr.Findings {
					if !SeverityAllowed(string(f.Severity), severities) {
						continue
					}
					writeFilteredCSVRow(writer, "sslscan", "findings", columns, map[string]string{
						"host":        hr.Host,
						"port":        fmt.Sprintf("%d", hr.Port),
						"severity":    string(f.Severity),
						"title":       f.Title,
						"description": f.Description,
						"cves":        strings.Join(f.CVEs, "; "),
						"component":   f.Component,
					})
				}
			}
		}
		if sections["protocols"] {
			if sections["findings"] {
				writer.Write([]string{})
			}
			writeFilteredCSVHeader(writer, "sslscan", "protocols", columns)
			for _, hr := range results {
				for _, p := range hr.Protocols {
					sup := "No"
					if p.Supported {
						sup = "Yes"
					}
					writeFilteredCSVRow(writer, "sslscan", "protocols", columns, map[string]string{
						"host":      hr.Host,
						"port":      fmt.Sprintf("%d", hr.Port),
						"version":   p.Name,
						"supported": sup,
					})
				}
			}
		}
		if sections["ciphers"] {
			writer.Write([]string{})
			writeFilteredCSVHeader(writer, "sslscan", "ciphers", columns)
			for _, hr := range results {
				for _, c := range hr.Ciphers {
					writeFilteredCSVRow(writer, "sslscan", "ciphers", columns, map[string]string{
						"host":     hr.Host,
						"port":     fmt.Sprintf("%d", hr.Port),
						"name":     c.Name,
						"versions": strings.Join(c.Versions, ", "),
					})
				}
			}
		}
		if sections["certificates"] {
			writer.Write([]string{})
			writeFilteredCSVHeader(writer, "sslscan", "certificates", columns)
			for _, hr := range results {
				if hr.CertInfo == nil {
					continue
				}
				exp := "No"
				if hr.CertInfo.DaysLeft < 0 {
					exp = "Yes"
				}
				writeFilteredCSVRow(writer, "sslscan", "certificates", columns, map[string]string{
					"host":       hr.Host,
					"port":       fmt.Sprintf("%d", hr.Port),
					"subject":    hr.CertInfo.Subject,
					"issuer":     hr.CertInfo.Issuer,
					"not_before": hr.CertInfo.NotBefore.Format("2006-01-02"),
					"not_after":  hr.CertInfo.NotAfter.Format("2006-01-02"),
					"sig_alg":    hr.CertInfo.SigAlg,
					"expired":    exp,
				})
			}
		}

	case "httpxfind":
		var sr httpxfind.ScanResult
		json.Unmarshal([]byte(result), &sr)
		if sections["services"] {
			writeFilteredCSVHeader(writer, "httpxfind", "services", columns)
			for _, s := range sr.Services {
				u, _ := url.Parse(s.URL)
				host, port, scheme := "", "", ""
				if u != nil {
					host = u.Hostname()
					port = u.Port()
					scheme = u.Scheme
				}
				writeFilteredCSVRow(writer, "httpxfind", "services", columns, map[string]string{
					"url":            s.URL,
					"host":           host,
					"port":           port,
					"scheme":         scheme,
					"status":         fmt.Sprintf("%d", s.StatusCode),
					"title":          s.Title,
					"server":         s.Server,
					"content_type":   s.ContentType,
					"redirect":       s.RedirectURL,
					"content_length": fmt.Sprintf("%d", s.ContentLength),
				})
			}
		}
		if sections["headers"] {
			writer.Write([]string{})
			writeFilteredCSVHeader(writer, "httpxfind", "headers", columns)
			for _, s := range sr.Services {
				writeFilteredCSVRow(writer, "httpxfind", "headers", columns, map[string]string{
					"url":     s.URL,
					"headers": s.ResponseHeaders,
				})
			}
		}

	case "httpmethods":
		var sr httpmethods.ScanResult
		json.Unmarshal([]byte(result), &sr)
		if sections["methods"] {
			writeFilteredCSVHeader(writer, "httpmethods", "methods", columns)
			for _, ur := range sr.Results {
				for _, m := range ur.Methods {
					danger := ""
					if m.Dangerous && m.Status == "Allowed" {
						danger = "YES"
					}
					writeFilteredCSVRow(writer, "httpmethods", "methods", columns, map[string]string{
						"url":          ur.URL,
						"method":       m.Method,
						"variant":      m.Variant,
						"content_type": m.ContentType,
						"status_code":  fmt.Sprintf("%d", m.StatusCode),
						"result":       m.Status,
						"size":         fmt.Sprintf("%d", m.Size),
						"resp_ct":      m.RespCT,
						"allow":        m.Allow,
						"dangerous":    danger,
					})
				}
			}
		}
		if sections["dangerous"] {
			writer.Write([]string{})
			writeFilteredCSVHeader(writer, "httpmethods", "dangerous", columns)
			for _, ur := range sr.Results {
				for _, m := range ur.Methods {
					if m.Dangerous && m.Status == "Allowed" {
						writeFilteredCSVRow(writer, "httpmethods", "dangerous", columns, map[string]string{
							"url":         ur.URL,
							"method":      m.Method,
							"status_code": fmt.Sprintf("%d", m.StatusCode),
							"variant":     m.Variant,
						})
					}
				}
			}
		}

	case "wafdetect":
		var sr wafdetect.ScanResult
		json.Unmarshal([]byte(result), &sr)
		if sections["results"] {
			writeFilteredCSVHeader(writer, "wafdetect", "results", columns)
			for _, tr := range sr.Results {
				reach := "No"
				if tr.Reachable {
					reach = "Yes"
				}
				detected := "No"
				if tr.WAFDetected {
					detected = "Yes"
				}
				writeFilteredCSVRow(writer, "wafdetect", "results", columns, map[string]string{
					"url":          tr.URL,
					"reachable":    reach,
					"waf_detected": detected,
					"waf_name":     tr.WAFName,
					"vendor":       tr.WAFVendor,
					"confidence":   fmt.Sprintf("%d", tr.Confidence),
					"server":       tr.Server,
				})
			}
		}
		if sections["evidence"] {
			writer.Write([]string{})
			writeFilteredCSVHeader(writer, "wafdetect", "evidence", columns)
			for _, tr := range sr.Results {
				for _, d := range tr.Detections {
					writeFilteredCSVRow(writer, "wafdetect", "evidence", columns, map[string]string{
						"url":        tr.URL,
						"method":     d.Method,
						"detail":     d.Detail,
						"confidence": fmt.Sprintf("%d", d.Confidence),
					})
				}
			}
		}

	case "wpscan":
		var sr wpscan.ScanResult
		json.Unmarshal([]byte(result), &sr)
		if sections["vulnerabilities"] {
			writeFilteredCSVHeader(writer, "wpscan", "vulnerabilities", columns)
			for _, tr := range sr.Results {
				for _, f := range tr.Findings {
					if f.Severity == "INFO" {
						continue
					}
					if !SeverityAllowed(f.Severity, severities) {
						continue
					}
					writeFilteredCSVRow(writer, "wpscan", "vulnerabilities", columns, map[string]string{
						"url":         tr.URL,
						"severity":    f.Severity,
						"category":    f.Category,
						"title":       f.Title,
						"description": f.Description,
						"cves":        strings.Join(f.CVEs, "; "),
						"fixed_in":    f.FixedIn,
						"references":  strings.Join(f.References, "; "),
					})
				}
			}
		}
		if sections["info"] {
			if sections["vulnerabilities"] {
				writer.Write([]string{})
			}
			writeFilteredCSVHeader(writer, "wpscan", "info", columns)
			for _, tr := range sr.Results {
				isWP := "No"
				if tr.IsWordPress {
					isWP = "Yes"
				}
				writeFilteredCSVRow(writer, "wpscan", "info", columns, map[string]string{
					"url":          tr.URL,
					"wp_version":   tr.WPVersion,
					"wp_status":    tr.Status,
					"theme":        tr.Theme,
					"plugin_count": fmt.Sprintf("%d", tr.PluginCount),
					"is_wordpress": isWP,
				})
			}
		}

	case "dnsenum":
		var sr dnsenum.ScanResult
		json.Unmarshal([]byte(result), &sr)
		if sections["subdomains"] {
			writeFilteredCSVHeader(writer, "dnsenum", "subdomains", columns)
			for _, dr := range sr.Results {
				for _, s := range dr.Subdomains {
					wild := ""
					if s.IsWild {
						wild = "yes"
					}
					writeFilteredCSVRow(writer, "dnsenum", "subdomains", columns, map[string]string{
						"domain":    dr.Domain,
						"subdomain": s.Subdomain,
						"ips":       strings.Join(s.IPs, " "),
						"source":    s.Source,
						"wildcard":  wild,
					})
				}
			}
		}
		// Commit 5: the three previously-ghost sections now have real
		// writers — AXFRRecords / ReverseDNS / CrtShCerts are populated
		// when the user enables those passes in the launch form.
		if sections["axfr"] {
			if sections["subdomains"] {
				writer.Write([]string{})
			}
			writeFilteredCSVHeader(writer, "dnsenum", "axfr", columns)
			for _, dr := range sr.Results {
				for _, a := range dr.AXFRRecords {
					writeFilteredCSVRow(writer, "dnsenum", "axfr", columns, map[string]string{
						"domain": dr.Domain,
						"ns":     a.NS,
						"name":   a.Name,
						"type":   a.Type,
						"value":  a.Value,
					})
				}
			}
		}
		if sections["reverse_dns"] {
			if sections["subdomains"] || sections["axfr"] {
				writer.Write([]string{})
			}
			writeFilteredCSVHeader(writer, "dnsenum", "reverse_dns", columns)
			for _, dr := range sr.Results {
				for _, p := range dr.ReverseDNS {
					writeFilteredCSVRow(writer, "dnsenum", "reverse_dns", columns, map[string]string{
						"domain":   dr.Domain,
						"ip":       p.IP,
						"hostname": p.Hostname,
					})
				}
			}
		}
		if sections["crtsh"] {
			if sections["subdomains"] || sections["axfr"] || sections["reverse_dns"] {
				writer.Write([]string{})
			}
			writeFilteredCSVHeader(writer, "dnsenum", "crtsh", columns)
			for _, dr := range sr.Results {
				for _, c := range dr.CrtShCerts {
					writeFilteredCSVRow(writer, "dnsenum", "crtsh", columns, map[string]string{
						"domain":     dr.Domain,
						"name_value": c.NameValue,
						"issuer":     c.Issuer,
						"not_before": c.NotBefore,
						"not_after":  c.NotAfter,
					})
				}
			}
		}

	case "techdetect":
		// chainedResult shape — same JSON keys as techdetect.ScanResult
		// plus optional cve_matches / cve_inputs for the auto-CVE chain.
		var sr struct {
			techdetect.ScanResult
			CVEInputs  []cvematch.Input `json:"cve_inputs,omitempty"`
			CVEMatches []cvematch.Match `json:"cve_matches,omitempty"`
		}
		json.Unmarshal([]byte(result), &sr)
		if sections["technologies"] {
			writeFilteredCSVHeader(writer, "techdetect", "technologies", columns)
			for _, tr := range sr.Results {
				for _, t := range tr.Technologies {
					writeFilteredCSVRow(writer, "techdetect", "technologies", columns, map[string]string{
						"url":      tr.URL,
						"name":     t.Name,
						"version":  t.Version,
						"category": string(t.Category),
						"source":   t.Source,
						"evidence": t.Evidence,
					})
				}
			}
		}
		if sections["matches"] && len(sr.CVEMatches) > 0 {
			if sections["technologies"] {
				writer.Write([]string{})
			}
			writeFilteredCSVHeader(writer, "techdetect", "matches", columns)
			for _, m := range sr.CVEMatches {
				if !SeverityAllowed(m.Severity, severities) {
					continue
				}
				writeFilteredCSVRow(writer, "techdetect", "matches", columns, map[string]string{
					"target_url":  m.URL,
					"product":     m.Product,
					"version":     m.Version,
					"cve":         m.CVE,
					"severity":    m.Severity,
					"cvss":        m.CVSS,
					"fixed_in":    m.FixedIn,
					"description": m.Description,
					"remediation": m.Remediation,
					"reference":   m.Reference,
				})
			}
		}

	case "spider":
		var sr spider.ScanResult
		json.Unmarshal([]byte(result), &sr)
		writeSpider := func(sectionID, filter string) {
			writeFilteredCSVHeader(writer, "spider", sectionID, columns)
			for _, tr := range sr.Results {
				for _, r := range tr.Resources {
					if filter != "" && string(r.Type) != filter {
						continue
					}
					writeFilteredCSVRow(writer, "spider", sectionID, columns, map[string]string{
						"url":          tr.URL,
						"path":         r.Path,
						"type":         string(r.Type),
						"status":       fmt.Sprintf("%d", r.StatusCode),
						"content_type": r.ContentType,
						"found_on":     r.FoundOn,
						"depth":        fmt.Sprintf("%d", r.Depth),
					})
				}
			}
		}
		if sections["all"] {
			writeSpider("all", "")
		}
		if sections["directories"] {
			if sections["all"] {
				writer.Write([]string{})
			}
			writeSpider("directories", "directory")
		}
		if sections["files"] {
			if sections["all"] || sections["directories"] {
				writer.Write([]string{})
			}
			writeSpider("files", "file")
		}

	case "direnum":
		var sr direnum.ScanResult
		json.Unmarshal([]byte(result), &sr)
		writeDirEnum := func(sectionID, filter string) {
			writeFilteredCSVHeader(writer, "direnum", sectionID, columns)
			for _, tr := range sr.Results {
				for _, e := range tr.Entries {
					if filter == "dirs" && !e.IsDir {
						continue
					}
					if filter == "files" && e.IsDir {
						continue
					}
					tp := "file"
					if e.IsDir {
						tp = "directory"
					}
					writeFilteredCSVRow(writer, "direnum", sectionID, columns, map[string]string{
						"url":          tr.URL,
						"path":         e.Path,
						"type":         tp,
						"status":       fmt.Sprintf("%d", e.StatusCode),
						"size":         fmt.Sprintf("%d", e.Size),
						"content_type": e.ContentType,
						"redirect":     e.RedirectTo,
					})
				}
			}
		}
		if sections["all"] {
			writeDirEnum("all", "")
		}
		if sections["dirs"] {
			if sections["all"] {
				writer.Write([]string{})
			}
			writeDirEnum("dirs", "dirs")
		}
		if sections["files"] {
			if sections["all"] || sections["dirs"] {
				writer.Write([]string{})
			}
			writeDirEnum("files", "files")
		}

	case "secheaders":
		var sr secheaders.ScanResult
		json.Unmarshal([]byte(result), &sr)
		if sections["findings"] {
			writeFilteredCSVHeader(writer, "secheaders", "findings", columns)
			for _, tr := range sr.Results {
				for _, f := range tr.Findings {
					if !SeverityAllowed(string(f.Severity), severities) {
						continue
					}
					writeFilteredCSVRow(writer, "secheaders", "findings", columns, map[string]string{
						"url":         tr.URL,
						"grade":       tr.Grade,
						"score":       fmt.Sprintf("%d", tr.Score),
						"header":      f.Header,
						"severity":    string(f.Severity),
						"status":      f.Status,
						"value":       f.Value,
						"description": f.Description,
						"recommend":   f.Recommend,
					})
				}
			}
		}
		if sections["probes"] {
			if sections["findings"] {
				writer.Write([]string{})
			}
			writeFilteredCSVHeader(writer, "secheaders", "probes", columns)
			for _, tr := range sr.Results {
				for _, p := range tr.Probes {
					writeFilteredCSVRow(writer, "secheaders", "probes", columns, map[string]string{
						"url":          tr.URL,
						"method":       p.Method,
						"variant":      p.Variant,
						"content_type": "",
						"status_code":  fmt.Sprintf("%d", p.StatusCode),
					})
				}
			}
		}

	case "cvematch":
		var sr cvematch.ScanResult
		json.Unmarshal([]byte(result), &sr)
		if sections["matches"] {
			writeFilteredCSVHeader(writer, "cvematch", "matches", columns)
			for _, m := range sr.Matches {
				if !SeverityAllowed(m.Severity, severities) {
					continue
				}
				writeFilteredCSVRow(writer, "cvematch", "matches", columns, map[string]string{
					"target_url":  m.URL,
					"product":     m.Product,
					"version":     m.Version,
					"cve":         m.CVE,
					"severity":    m.Severity,
					"cvss":        m.CVSS,
					"fixed_in":    m.FixedIn,
					"description": m.Description,
					"remediation": m.Remediation,
					"reference":   m.Reference,
					// Match.Source was renamed to MatchSource to stop
					// shadowing the embedded Input.Source. The "source"
					// schema column historically meant match origin
					// (builtin/cache), so keep emitting MatchSource.
					"source": m.MatchSource,
				})
			}
		}
		if sections["inputs"] {
			if sections["matches"] {
				writer.Write([]string{})
			}
			writeFilteredCSVHeader(writer, "cvematch", "inputs", columns)
			for _, in := range sr.Inputs {
				writeFilteredCSVRow(writer, "cvematch", "inputs", columns, map[string]string{
					"product": in.Product,
					"version": in.Version,
					"url":     in.URL,
					"source":  in.Source,
				})
			}
		}

	// === Commit 1: writer arms for the 11 modules whose ExportSchema
	// already declared column catalogues. Each follows the same shape
	// as the secheaders case above — for every selected section, write
	// header, iterate the typed result, emit one filtered row per item,
	// drop a blank-line separator between sections. ===

	case "nuclei":
		var sr nuclei.ScanResult
		json.Unmarshal([]byte(result), &sr)
		if sections["findings"] {
			writeFilteredCSVHeader(writer, "nuclei", "findings", columns)
			for _, tr := range sr.Results {
				for _, f := range tr.Findings {
					if !SeverityAllowed(f.Severity, severities) {
						continue
					}
					writeFilteredCSVRow(writer, "nuclei", "findings", columns, map[string]string{
						"url":         tr.URL,
						"template_id": f.TemplateID,
						"name":        f.Name,
						"severity":    f.Severity,
						"type":        f.Type,
						"matched_at":  f.MatchedAt,
						"description": f.Description,
						"cves":        strings.Join(f.CVEs, ","),
						"cwes":        strings.Join(f.CWEs, ","),
						"tags":        strings.Join(f.Tags, ","),
						"references":  strings.Join(f.References, ","),
					})
				}
			}
		}

	case "hostdiscovery":
		var sr hostdiscovery.ScanResult
		json.Unmarshal([]byte(result), &sr)
		boolStr := func(b bool) string {
			if b {
				return "yes"
			}
			return "no"
		}
		if sections["hosts"] {
			writeFilteredCSVHeader(writer, "hostdiscovery", "hosts", columns)
			for _, tr := range sr.Results {
				writeFilteredCSVRow(writer, "hostdiscovery", "hosts", columns, map[string]string{
					"target":         tr.Target,
					"ip":             tr.IP,
					"host":           tr.Host,
					"host_up":        boolStr(tr.HostUp),
					"ping_reachable": boolStr(tr.PingReachable),
					"icmp_filtered":  boolStr(tr.IcmpFiltered),
					"open_count":     fmt.Sprintf("%d", tr.OpenCount),
				})
			}
		}
		if sections["ports"] {
			if sections["hosts"] {
				writer.Write([]string{})
			}
			writeFilteredCSVHeader(writer, "hostdiscovery", "ports", columns)
			for _, tr := range sr.Results {
				for _, p := range tr.Ports {
					writeFilteredCSVRow(writer, "hostdiscovery", "ports", columns, map[string]string{
						"target":   tr.Target,
						"ip":       tr.IP,
						"port":     fmt.Sprintf("%d", p.Port),
						"protocol": p.Protocol,
						"state":    p.State,
						"service":  p.Service,
					})
				}
			}
		}

	case "portservice":
		var sr portservice.ScanResult
		json.Unmarshal([]byte(result), &sr)
		if sections["ports"] {
			writeFilteredCSVHeader(writer, "portservice", "ports", columns)
			for _, tr := range sr.Results {
				for _, p := range tr.Ports {
					writeFilteredCSVRow(writer, "portservice", "ports", columns, map[string]string{
						"target":     tr.Target,
						"ip":         tr.IP,
						"port":       fmt.Sprintf("%d", p.Port),
						"protocol":   p.Protocol,
						"state":      p.State,
						"service":    p.Service,
						"product":    p.Product,
						"version":    p.Version,
						"extra_info": p.ExtraInfo,
						"tunnel":     p.Tunnel,
					})
				}
			}
		}
		if sections["scripts"] {
			if sections["ports"] {
				writer.Write([]string{})
			}
			writeFilteredCSVHeader(writer, "portservice", "scripts", columns)
			for _, tr := range sr.Results {
				for _, p := range tr.Ports {
					for _, sc := range p.Scripts {
						writeFilteredCSVRow(writer, "portservice", "scripts", columns, map[string]string{
							"target":    tr.Target,
							"port":      fmt.Sprintf("%d", p.Port),
							"script_id": sc.ID,
							"output":    sc.Output,
						})
					}
				}
			}
		}
		// Audit MED fix: banners / HTTP / Nuclei findings are gathered by
		// Phase 3.5 + Phase 4 but had no export path — now they do.
		if sections["banners"] {
			if sections["ports"] || sections["scripts"] {
				writer.Write([]string{})
			}
			writeFilteredCSVHeader(writer, "portservice", "banners", columns)
			for _, tr := range sr.Results {
				for _, p := range tr.Ports {
					if p.Banner == "" {
						continue
					}
					writeFilteredCSVRow(writer, "portservice", "banners", columns, map[string]string{
						"target":   tr.Target,
						"ip":       tr.IP,
						"port":     fmt.Sprintf("%d", p.Port),
						"protocol": p.Protocol,
						"service":  p.Service,
						"banner":   p.Banner,
					})
				}
			}
		}
		if sections["http"] {
			if sections["ports"] || sections["scripts"] || sections["banners"] {
				writer.Write([]string{})
			}
			writeFilteredCSVHeader(writer, "portservice", "http", columns)
			for _, tr := range sr.Results {
				for _, p := range tr.Ports {
					if p.HTTPResp == nil {
						continue
					}
					writeFilteredCSVRow(writer, "portservice", "http", columns, map[string]string{
						"target":       tr.Target,
						"ip":           tr.IP,
						"port":         fmt.Sprintf("%d", p.Port),
						"url":          p.HTTPResp.URL,
						"status":       fmt.Sprintf("%d", p.HTTPResp.Status),
						"server":       p.HTTPResp.Server,
						"title":        p.HTTPResp.Title,
						"content_type": p.HTTPResp.ContentType,
						"body_length":  fmt.Sprintf("%d", p.HTTPResp.BodyLength),
					})
				}
			}
		}
		if sections["vulns"] {
			if sections["ports"] || sections["scripts"] || sections["banners"] || sections["http"] {
				writer.Write([]string{})
			}
			writeFilteredCSVHeader(writer, "portservice", "vulns", columns)
			for _, tr := range sr.Results {
				for _, f := range tr.NucleiFindings {
					writeFilteredCSVRow(writer, "portservice", "vulns", columns, map[string]string{
						"target":      tr.Target,
						"template_id": f.TemplateID,
						"name":        f.Name,
						"severity":    f.Severity,
						"cves":        strings.Join(f.CVEs, ","),
						"matched_at":  f.MatchedAt,
						"description": f.Description,
					})
				}
			}
		}

	case "smbenum":
		var sr smbenum.ScanResult
		json.Unmarshal([]byte(result), &sr)
		boolStr := func(b bool) string {
			if b {
				return "yes"
			}
			return "no"
		}
		if sections["shares"] {
			writeFilteredCSVHeader(writer, "smbenum", "shares", columns)
			for _, tr := range sr.Results {
				for _, sh := range tr.Shares {
					writeFilteredCSVRow(writer, "smbenum", "shares", columns, map[string]string{
						"target":  tr.Target,
						"name":    sh.Name,
						"type":    sh.Type,
						"comment": sh.Comment,
						"access":  sh.Access,
					})
				}
			}
		}
		if sections["users"] {
			if sections["shares"] {
				writer.Write([]string{})
			}
			writeFilteredCSVHeader(writer, "smbenum", "users", columns)
			for _, tr := range sr.Results {
				for _, u := range tr.Users {
					writeFilteredCSVRow(writer, "smbenum", "users", columns, map[string]string{
						"target": tr.Target,
						"kind":   "user",
						"name":   u,
					})
				}
				for _, g := range tr.Groups {
					writeFilteredCSVRow(writer, "smbenum", "users", columns, map[string]string{
						"target": tr.Target,
						"kind":   "group",
						"name":   g,
					})
				}
			}
		}
		if sections["info"] {
			if sections["shares"] || sections["users"] {
				writer.Write([]string{})
			}
			writeFilteredCSVHeader(writer, "smbenum", "info", columns)
			for _, tr := range sr.Results {
				writeFilteredCSVRow(writer, "smbenum", "info", columns, map[string]string{
					"target":        tr.Target,
					"ip":            tr.IP,
					"os":            tr.OS,
					"domain":        tr.Domain,
					"workgroup":     tr.Workgroup,
					"netbios_name":  tr.NetbiosName,
					"smb_port_open": boolStr(tr.SMBPortOpen),
				})
			}
		}

	case "brutef":
		var sr brutef.ScanResult
		json.Unmarshal([]byte(result), &sr)
		if sections["credentials"] {
			writeFilteredCSVHeader(writer, "brutef", "credentials", columns)
			for _, tr := range sr.Results {
				for _, c := range tr.Found {
					writeFilteredCSVRow(writer, "brutef", "credentials", columns, map[string]string{
						"host":     c.Host,
						"port":     fmt.Sprintf("%d", c.Port),
						"protocol": string(tr.Protocol),
						"username": c.Username,
						"password": c.Password,
					})
				}
			}
		}

	case "whoisinfo":
		var sr whoisinfo.ScanResult
		json.Unmarshal([]byte(result), &sr)
		if sections["summary"] {
			writeFilteredCSVHeader(writer, "whoisinfo", "summary", columns)
			for _, tr := range sr.Results {
				asn, org, country, registry := "", "", "", ""
				ip := strings.Join(tr.ResolvedIPs, ",")
				if tr.ASN != nil {
					asn = tr.ASN.ASN
					org = tr.ASN.Organization
					country = tr.ASN.CountryCode
					registry = tr.ASN.Registry
				}
				writeFilteredCSVRow(writer, "whoisinfo", "summary", columns, map[string]string{
					"target":       tr.Target,
					"kind":         tr.Kind,
					"ip":           ip,
					"asn":          asn,
					"organization": org,
					"country":      country,
					"registry":     registry,
				})
			}
		}
		if sections["records"] {
			if sections["summary"] {
				writer.Write([]string{})
			}
			writeFilteredCSVHeader(writer, "whoisinfo", "records", columns)
			for _, tr := range sr.Results {
				for _, rec := range tr.WHOISRecords {
					writeFilteredCSVRow(writer, "whoisinfo", "records", columns, map[string]string{
						"target": tr.Target,
						"field":  rec.Field,
						"value":  rec.Value,
					})
				}
			}
		}
		if sections["prefixes"] {
			if sections["summary"] || sections["records"] {
				writer.Write([]string{})
			}
			writeFilteredCSVHeader(writer, "whoisinfo", "prefixes", columns)
			for _, tr := range sr.Results {
				if tr.ASN == nil {
					continue
				}
				for _, p := range tr.ASN.Prefixes {
					writeFilteredCSVRow(writer, "whoisinfo", "prefixes", columns, map[string]string{
						"asn":    tr.ASN.ASN,
						"prefix": p,
					})
				}
			}
		}

	case "emailharvest":
		var sr emailharvest.ScanResult
		json.Unmarshal([]byte(result), &sr)
		if sections["emails"] {
			writeFilteredCSVHeader(writer, "emailharvest", "emails", columns)
			for _, d := range sr.Results {
				for _, e := range d.Emails {
					writeFilteredCSVRow(writer, "emailharvest", "emails", columns, map[string]string{
						"domain": d.Domain,
						"email":  e,
					})
				}
			}
		}
		if sections["hosts"] {
			if sections["emails"] {
				writer.Write([]string{})
			}
			writeFilteredCSVHeader(writer, "emailharvest", "hosts", columns)
			for _, d := range sr.Results {
				for _, h := range d.Hosts {
					writeFilteredCSVRow(writer, "emailharvest", "hosts", columns, map[string]string{
						"domain": d.Domain,
						"host":   h,
					})
				}
			}
		}
		if sections["ips"] {
			if sections["emails"] || sections["hosts"] {
				writer.Write([]string{})
			}
			writeFilteredCSVHeader(writer, "emailharvest", "ips", columns)
			for _, d := range sr.Results {
				for _, ip := range d.IPs {
					writeFilteredCSVRow(writer, "emailharvest", "ips", columns, map[string]string{
						"domain": d.Domain,
						"ip":     ip,
					})
				}
			}
		}
		if sections["breaches"] {
			if sections["emails"] || sections["hosts"] || sections["ips"] {
				writer.Write([]string{})
			}
			writeFilteredCSVHeader(writer, "emailharvest", "breaches", columns)
			for _, d := range sr.Results {
				for _, b := range d.Breaches {
					writeFilteredCSVRow(writer, "emailharvest", "breaches", columns, map[string]string{
						"domain":       d.Domain,
						"name":         b.Name,
						"title":        b.Title,
						"date":         b.BreachDate,
						"pwn_count":    fmt.Sprintf("%d", b.PwnCount),
						"data_classes": strings.Join(b.DataClasses, ","),
					})
				}
			}
		}

	case "leakscan":
		var sr leakscan.ScanResult
		json.Unmarshal([]byte(result), &sr)
		if sections["hits"] {
			writeFilteredCSVHeader(writer, "leakscan", "hits", columns)
			for _, q := range sr.Results {
				for _, h := range q.Hits {
					// Pick the most-readable URL (HTML > Raw) so the
					// "url" column always points to something openable.
					purl := h.HTMLURL
					if purl == "" {
						purl = h.RawURL
					}
					// secret_type joins the pattern names of every match —
					// leakscan.Match has no Type field; Pattern is the
					// closest human label (e.g. "AWS key", "GitHub token").
					stypes := []string{}
					for _, m := range h.Matches {
						stypes = append(stypes, m.Pattern)
					}
					writeFilteredCSVRow(writer, "leakscan", "hits", columns, map[string]string{
						"query":       q.Query,
						"repo":        h.Repo,
						"path":        h.Path,
						"url":         purl,
						"secret_type": strings.Join(stypes, ","),
						"snippet":     h.Snippet,
					})
				}
			}
		}

	case "snmpenum":
		var sr snmpenum.ScanResult
		json.Unmarshal([]byte(result), &sr)
		if sections["communities"] {
			writeFilteredCSVHeader(writer, "snmpenum", "communities", columns)
			for _, tr := range sr.Results {
				// Build a set of confirmed-RW communities so the
				// "access" column reflects the snmpset round-trip
				// rather than the historical hard-coded "read".
				rwSet := map[string]bool{}
				for _, w := range tr.WriteCommunities {
					rwSet[w] = true
				}
				for _, c := range tr.ValidCommunities {
					access := "read"
					if rwSet[c] {
						access = "write"
					}
					writeFilteredCSVRow(writer, "snmpenum", "communities", columns, map[string]string{
						"target":    tr.Target,
						"community": c,
						"access":    access,
					})
				}
			}
		}
		if sections["info"] {
			if sections["communities"] {
				writer.Write([]string{})
			}
			writeFilteredCSVHeader(writer, "snmpenum", "info", columns)
			// Flatten system-level fields as OID rows so the "oid"/"value"
			// pair is honest — analysts can pivot off this in spreadsheets
			// without parsing wide columns.
			sysFields := func(tr snmpenum.TargetResult) [][2]string {
				return [][2]string{
					{"1.3.6.1.2.1.1.1.0 sysDescr", tr.SystemDescr},
					{"1.3.6.1.2.1.1.3.0 sysUpTime", tr.SystemUptime},
					{"1.3.6.1.2.1.1.4.0 sysContact", tr.SystemContact},
					{"1.3.6.1.2.1.1.5.0 sysName", tr.SystemName},
					{"1.3.6.1.2.1.1.6.0 sysLocation", tr.SystemLocation},
				}
			}
			for _, tr := range sr.Results {
				for _, pair := range sysFields(tr) {
					if pair[1] == "" {
						continue
					}
					writeFilteredCSVRow(writer, "snmpenum", "info", columns, map[string]string{
						"target": tr.Target,
						"oid":    pair[0],
						"value":  pair[1],
					})
				}
				// snmpenum.Walk holds the whole walk output as a single
				// multi-line string — there's no per-OID breakdown on
				// the result struct. Emit one row per walk so the CSV
				// stays grep-able; the "value" cell may contain newlines
				// which Go's CSV writer quotes correctly.
				for _, walk := range tr.Walks {
					writeFilteredCSVRow(writer, "snmpenum", "info", columns, map[string]string{
						"target": tr.Target,
						"oid":    walk.Label + " (" + walk.OID + ")",
						"value":  walk.Output,
					})
				}
			}
		}

	case "jwt":
		var sr jwt.ScanResult
		json.Unmarshal([]byte(result), &sr)
		boolStr := func(b bool) string {
			if b {
				return "yes"
			}
			return "no"
		}
		// Pull standard claims out of the payload without forcing a typed
		// schema on it. Falls back to empty string when missing.
		claim := func(p map[string]interface{}, key string) string {
			if p == nil {
				return ""
			}
			if v, ok := p[key]; ok {
				return fmt.Sprintf("%v", v)
			}
			return ""
		}
		if sections["summary"] {
			writeFilteredCSVHeader(writer, "jwt", "summary", columns)
			for i, t := range sr.Results {
				expVal := claim(t.Payload, "exp")
				// Mark expired when exp is in the past — best-effort
				// numeric compare.
				expired := "no"
				if expVal != "" {
					if epoch, perr := fmt.Sscanf(expVal, "%d", new(int64)); perr == nil && epoch > 0 {
						var ts int64
						fmt.Sscanf(expVal, "%d", &ts)
						if ts > 0 && time.Unix(ts, 0).Before(time.Now()) {
							expired = "yes"
						}
					}
				}
				writeFilteredCSVRow(writer, "jwt", "summary", columns, map[string]string{
					"token_idx": fmt.Sprintf("%d", i+1),
					"alg":       t.Algorithm,
					"issuer":    claim(t.Payload, "iss"),
					"subject":   claim(t.Payload, "sub"),
					"exp":       expVal,
					"expired":   expired,
					"secret":    t.CrackedSecret,
				})
				_ = boolStr // silence unused in this branch
			}
		}
		if sections["issues"] {
			if sections["summary"] {
				writer.Write([]string{})
			}
			writeFilteredCSVHeader(writer, "jwt", "issues", columns)
			for i, t := range sr.Results {
				for _, f := range t.Findings {
					if !SeverityAllowed(f.Severity, severities) {
						continue
					}
					writeFilteredCSVRow(writer, "jwt", "issues", columns, map[string]string{
						"token_idx": fmt.Sprintf("%d", i+1),
						"severity":  f.Severity,
						"title":     f.Title,
						"detail":    f.Detail,
					})
				}
			}
		}

	case "paramdisc":
		var sr paramdisc.ScanResult
		json.Unmarshal([]byte(result), &sr)
		boolStr := func(b bool) string {
			if b {
				return "yes"
			}
			return "no"
		}
		if sections["hits"] {
			writeFilteredCSVHeader(writer, "paramdisc", "hits", columns)
			for _, tr := range sr.Results {
				for _, h := range tr.Hits {
					writeFilteredCSVRow(writer, "paramdisc", "hits", columns, map[string]string{
						"url":         tr.URL,
						"method":      h.Method,
						"name":        h.Name,
						"status_code": fmt.Sprintf("%d", h.StatusCode),
						"status_diff": boolStr(h.StatusDiff),
						"length_diff": fmt.Sprintf("%d", h.LengthDiff),
						"reflected":   boolStr(h.Reflected),
						"note":        h.Note,
					})
				}
			}
		}

	// === Commit 2: CSV writers for the 8 modules whose schema was
	// brand-new. Most follow the {findings, optional secondary} shape. ===

	case "takeover":
		var sr takeover.ScanResult
		json.Unmarshal([]byte(result), &sr)
		if sections["findings"] {
			writeFilteredCSVHeader(writer, "takeover", "findings", columns)
			for _, f := range sr.Findings {
				if !SeverityAllowed(f.Severity, severities) {
					continue
				}
				writeFilteredCSVRow(writer, "takeover", "findings", columns, map[string]string{
					"subdomain":       f.Subdomain,
					"cname":           f.CNAME,
					"ips":             strings.Join(f.IPs, ","),
					"service":         f.Service,
					"severity":        f.Severity,
					"http_status":     fmt.Sprintf("%d", f.HTTPStatus),
					"matched_pattern": f.MatchedPattern,
					"note":            f.Note,
					"body_snippet":    f.BodySnippet,
				})
			}
		}
		if sections["hosts"] {
			if sections["findings"] {
				writer.Write([]string{})
			}
			writeFilteredCSVHeader(writer, "takeover", "hosts", columns)
			for _, h := range sr.Results {
				writeFilteredCSVRow(writer, "takeover", "hosts", columns, map[string]string{
					"subdomain": h.Subdomain,
					"cname":     h.CNAME,
					"ips":       strings.Join(h.IPs, ","),
					"status":    h.Status,
					"note":      h.Note,
				})
			}
		}

	case "corsscan":
		var sr corsscan.ScanResult
		json.Unmarshal([]byte(result), &sr)
		if sections["findings"] {
			writeFilteredCSVHeader(writer, "corsscan", "findings", columns)
			for _, tr := range sr.Results {
				for _, f := range tr.Findings {
					if !SeverityAllowed(f.Severity, severities) {
						continue
					}
					writeFilteredCSVRow(writer, "corsscan", "findings", columns, map[string]string{
						"url":            tr.URL,
						"severity":       f.Severity,
						"title":          f.Title,
						"request_origin": f.RequestOrigin,
						"response_acao":  f.ResponseACAO,
						"response_acac":  f.ResponseACAC,
						"detail":         f.Detail,
					})
				}
			}
		}

	case "openredirect":
		var sr openredirect.ScanResult
		json.Unmarshal([]byte(result), &sr)
		if sections["findings"] {
			writeFilteredCSVHeader(writer, "openredirect", "findings", columns)
			for _, tr := range sr.Results {
				for _, f := range tr.Findings {
					if !SeverityAllowed(f.Severity, severities) {
						continue
					}
					writeFilteredCSVRow(writer, "openredirect", "findings", columns, map[string]string{
						"url":         f.URL,
						"parameter":   f.Parameter,
						"payload":     f.Payload,
						"status_code": fmt.Sprintf("%d", f.StatusCode),
						"location":    f.Location,
						"how_matched": f.HowMatched,
						"severity":    f.Severity,
					})
				}
				_ = tr
			}
		}

	case "graphqlscan":
		var sr graphqlscan.ScanResult
		json.Unmarshal([]byte(result), &sr)
		boolStr := func(b bool) string {
			if b {
				return "yes"
			}
			return "no"
		}
		if sections["endpoints"] {
			writeFilteredCSVHeader(writer, "graphqlscan", "endpoints", columns)
			for _, e := range sr.Endpoints {
				writeFilteredCSVRow(writer, "graphqlscan", "endpoints", columns, map[string]string{
					"url":               e.URL,
					"status":            fmt.Sprintf("%d", e.Status),
					"is_graphql":        boolStr(e.IsGraphQL),
					"introspection_on":  boolStr(e.IntrospectionOn),
					"schema_type_count": fmt.Sprintf("%d", e.SchemaTypeCount),
					"query_fields":      strings.Join(e.QueryFields, ","),
					"mutation_fields":   strings.Join(e.MutationFields, ","),
				})
			}
		}
		if sections["findings"] {
			if sections["endpoints"] {
				writer.Write([]string{})
			}
			writeFilteredCSVHeader(writer, "graphqlscan", "findings", columns)
			for _, e := range sr.Endpoints {
				for _, f := range e.Findings {
					if !SeverityAllowed(f.Severity, severities) {
						continue
					}
					writeFilteredCSVRow(writer, "graphqlscan", "findings", columns, map[string]string{
						"url":      e.URL,
						"severity": f.Severity,
						"title":    f.Title,
						"detail":   f.Detail,
						"evidence": f.Evidence,
					})
				}
			}
		}

	case "authtest":
		var sr authtest.ScanResult
		json.Unmarshal([]byte(result), &sr)
		if sections["findings"] {
			writeFilteredCSVHeader(writer, "authtest", "findings", columns)
			for _, tr := range sr.Results {
				for _, f := range tr.Findings {
					if !SeverityAllowed(f.Severity, severities) {
						continue
					}
					writeFilteredCSVRow(writer, "authtest", "findings", columns, map[string]string{
						"login_url": tr.LoginURL,
						"method":    tr.Method,
						"severity":  f.Severity,
						"title":     f.Title,
						"detail":    f.Detail,
						"evidence":  f.Evidence,
					})
				}
			}
		}
		if sections["attempts"] {
			if sections["findings"] {
				writer.Write([]string{})
			}
			writeFilteredCSVHeader(writer, "authtest", "attempts", columns)
			for _, tr := range sr.Results {
				for _, a := range tr.Attempts {
					writeFilteredCSVRow(writer, "authtest", "attempts", columns, map[string]string{
						"login_url":   tr.LoginURL,
						"username":    a.Username,
						"password":    a.Password,
						"status_code": fmt.Sprintf("%d", a.StatusCode),
						"body_len":    fmt.Sprintf("%d", a.BodyLen),
						"outcome":     a.Outcome,
					})
				}
			}
		}

	case "sstiscan":
		var sr sstiscan.ScanResult
		json.Unmarshal([]byte(result), &sr)
		if sections["findings"] {
			writeFilteredCSVHeader(writer, "sstiscan", "findings", columns)
			for _, tr := range sr.Results {
				for _, f := range tr.Findings {
					if !SeverityAllowed(f.Severity, severities) {
						continue
					}
					writeFilteredCSVRow(writer, "sstiscan", "findings", columns, map[string]string{
						"url":       f.URL,
						"engine":    f.Engine,
						"parameter": f.Parameter,
						"payload":   f.Payload,
						"marker":    f.Marker,
						"severity":  f.Severity,
						"note":      f.Note,
					})
				}
				_ = tr
			}
		}

	case "cachepoison":
		var sr cachepoison.ScanResult
		json.Unmarshal([]byte(result), &sr)
		if sections["findings"] {
			writeFilteredCSVHeader(writer, "cachepoison", "findings", columns)
			for _, tr := range sr.Results {
				for _, f := range tr.Findings {
					if !SeverityAllowed(f.Severity, severities) {
						continue
					}
					writeFilteredCSVRow(writer, "cachepoison", "findings", columns, map[string]string{
						"url":      f.URL,
						"class":    f.Class,
						"header":   f.Header,
						"payload":  f.Payload,
						"severity": f.Severity,
						"title":    f.Title,
						"detail":   f.Detail,
						"evidence": f.Evidence,
					})
				}
				_ = tr
			}
		}

	case "assetdisc":
		var sr assetdisc.ScanResult
		json.Unmarshal([]byte(result), &sr)
		if sections["assets"] {
			writeFilteredCSVHeader(writer, "assetdisc", "assets", columns)
			for _, q := range sr.Queries {
				for _, a := range q.Assets {
					writeFilteredCSVRow(writer, "assetdisc", "assets", columns, map[string]string{
						"source":   a.Source,
						"ip":       a.IP,
						"port":     fmt.Sprintf("%d", a.Port),
						"hostname": a.Hostname,
						"asn":      a.ASN,
						"org":      a.Org,
						"country":  a.Country,
						"product":  a.Product,
						"os":       a.OS,
						"banner":   a.Banner,
						"domains":  strings.Join(a.Domains, ","),
					})
				}
			}
		}
		if sections["queries"] {
			if sections["assets"] {
				writer.Write([]string{})
			}
			writeFilteredCSVHeader(writer, "assetdisc", "queries", columns)
			for _, q := range sr.Queries {
				writeFilteredCSVRow(writer, "assetdisc", "queries", columns, map[string]string{
					"source": q.Source,
					"query":  q.Query,
					"total":  fmt.Sprintf("%d", q.Total),
					"error":  q.Error,
				})
			}
		}

	// === Commit 3: big multi-section CSV writers. ===

	case "adpentest":
		var sr adpentest.ScanResult
		json.Unmarshal([]byte(result), &sr)
		boolStr := func(b bool) string {
			if b {
				return "yes"
			}
			return "no"
		}
		sep := func(secs ...string) {
			for _, s := range secs {
				if sections[s] {
					writer.Write([]string{})
					return
				}
			}
		}
		if sections["discovery"] && sr.Discovered != nil {
			writeFilteredCSVHeader(writer, "adpentest", "discovery", columns)
			for _, dc := range sr.Discovered.DCs {
				ports := []string{}
				for _, p := range dc.OpenPorts {
					ports = append(ports, fmt.Sprintf("%d", p))
				}
				writeFilteredCSVRow(writer, "adpentest", "discovery", columns, map[string]string{
					"ip":           dc.IP,
					"fqdn":         dc.FQDN,
					"netbios_name": dc.NetBIOSName,
					"os":           dc.OS,
					"open_ports":   strings.Join(ports, ","),
					"roles":        strings.Join(dc.Roles, ","),
				})
			}
		}
		if sections["users"] && sr.UnauthEnum != nil {
			sep("discovery")
			writeFilteredCSVHeader(writer, "adpentest", "users", columns)
			for _, u := range sr.UnauthEnum.Users {
				writeFilteredCSVRow(writer, "adpentest", "users", columns, map[string]string{
					"username":    u.Username,
					"dn":          u.DistinguishedName,
					"sid":         u.SID,
					"enabled":     boolStr(u.Enabled),
					"admin_count": boolStr(u.AdminCount),
					"description": u.Description,
					"last_logon":  u.LastLogon,
					"uac_flags":   strings.Join(u.UACFlags, ","),
					"spn":         strings.Join(u.SPN, ","),
				})
			}
		}
		if sections["groups"] && sr.UnauthEnum != nil {
			sep("discovery", "users")
			writeFilteredCSVHeader(writer, "adpentest", "groups", columns)
			for _, g := range sr.UnauthEnum.Groups {
				writeFilteredCSVRow(writer, "adpentest", "groups", columns, map[string]string{
					"name":        g.Name,
					"sid":         g.SID,
					"members":     strings.Join(g.Members, ","),
					"description": g.Description,
				})
			}
		}
		if sections["computers"] && sr.UnauthEnum != nil {
			sep("discovery", "users", "groups")
			writeFilteredCSVHeader(writer, "adpentest", "computers", columns)
			for _, c := range sr.UnauthEnum.Computers {
				writeFilteredCSVRow(writer, "adpentest", "computers", columns, map[string]string{
					"name":         c.Name,
					"os":           c.OS,
					"dns_hostname": c.DNSHostName,
					"enabled":      boolStr(c.Enabled),
					"uac_flags":    strings.Join(c.UACFlags, ","),
					"spn":          strings.Join(c.SPN, ","),
				})
			}
		}
		if sections["shares"] && sr.UnauthEnum != nil {
			sep("discovery", "users", "groups", "computers")
			writeFilteredCSVHeader(writer, "adpentest", "shares", columns)
			for _, sh := range sr.UnauthEnum.Shares {
				writeFilteredCSVRow(writer, "adpentest", "shares", columns, map[string]string{
					"host":     sh.Host,
					"name":     sh.Name,
					"type":     sh.Type,
					"comment":  sh.Comment,
					"readable": boolStr(sh.Readable),
					"writable": boolStr(sh.Writable),
				})
			}
		}
		if sections["acl_findings"] && sr.AuthEnum != nil {
			sep("discovery", "users", "groups", "computers", "shares")
			writeFilteredCSVHeader(writer, "adpentest", "acl_findings", columns)
			for _, a := range sr.AuthEnum.ACLFindings {
				writeFilteredCSVRow(writer, "adpentest", "acl_findings", columns, map[string]string{
					"source":     a.Source,
					"target":     a.Target,
					"right":      a.Right,
					"path":       a.Path,
					"actionable": boolStr(a.Actionable),
				})
			}
		}
		if sections["kerberoast"] && sr.AuthEnum != nil {
			sep("discovery", "users", "groups", "computers", "shares", "acl_findings")
			writeFilteredCSVHeader(writer, "adpentest", "kerberoast", columns)
			for _, k := range sr.AuthEnum.Kerberoastable {
				writeFilteredCSVRow(writer, "adpentest", "kerberoast", columns, map[string]string{
					"username":  k.Username,
					"spn":       k.SPN,
					"hash_file": k.HashFile,
				})
			}
		}
		if sections["hashes"] {
			sep("discovery", "users", "groups", "computers", "shares", "acl_findings", "kerberoast")
			writeFilteredCSVHeader(writer, "adpentest", "hashes", columns)
			for _, h := range sr.Hashes {
				writeFilteredCSVRow(writer, "adpentest", "hashes", columns, map[string]string{
					"type":           h.Type,
					"account":        h.Account,
					"realm":          h.Realm,
					"source":         h.Source,
					"cracked_secret": h.CrackedSecret,
					"captured_at":    h.CapturedAt.Format(time.RFC3339),
				})
			}
		}
		if sections["vulns"] {
			sep("discovery", "users", "groups", "computers", "shares", "acl_findings", "kerberoast", "hashes")
			writeFilteredCSVHeader(writer, "adpentest", "vulns", columns)
			for _, v := range sr.Vulns {
				if !SeverityAllowed(v.Severity, severities) {
					continue
				}
				writeFilteredCSVRow(writer, "adpentest", "vulns", columns, map[string]string{
					"cve":         v.CVE,
					"name":        v.Name,
					"host":        v.Host,
					"severity":    v.Severity,
					"detail":      v.Detail,
					"exploit_cmd": v.ExploitCmd,
				})
			}
		}
		if sections["lateral"] {
			sep("discovery", "users", "groups", "computers", "shares", "acl_findings", "kerberoast", "hashes", "vulns")
			writeFilteredCSVHeader(writer, "adpentest", "lateral", columns)
			for _, l := range sr.Lateral {
				writeFilteredCSVRow(writer, "adpentest", "lateral", columns, map[string]string{
					"title":   l.Title,
					"tool":    l.Tool,
					"risk":    l.Risk,
					"command": l.Command,
					"notes":   l.Notes,
				})
			}
		}

	case "concurtest":
		var sr concurtest.ScanResult
		json.Unmarshal([]byte(result), &sr)
		boolStr := func(b bool) string {
			if b {
				return "yes"
			}
			return "no"
		}
		if sections["summary"] {
			writeFilteredCSVHeader(writer, "concurtest", "summary", columns)
			for _, tr := range sr.Targets {
				writeFilteredCSVRow(writer, "concurtest", "summary", columns, map[string]string{
					"url":           tr.URL,
					"baseline_ms":   fmt.Sprintf("%d", tr.BaselineMs),
					"practical_max": fmt.Sprintf("%d", tr.PracticalMax),
					"notes":         strings.Join(tr.Notes, "; "),
					"error":         tr.Error,
				})
			}
		}
		if sections["ramp"] {
			if sections["summary"] {
				writer.Write([]string{})
			}
			writeFilteredCSVHeader(writer, "concurtest", "ramp", columns)
			for _, tr := range sr.Targets {
				for _, b := range tr.Ramp {
					if b == nil {
						continue
					}
					writeFilteredCSVRow(writer, "concurtest", "ramp", columns, map[string]string{
						"url":            tr.URL,
						"label":          b.Label,
						"concurrency":    fmt.Sprintf("%d", b.Concurrency),
						"requests":       fmt.Sprintf("%d", b.Requests),
						"successes":      fmt.Sprintf("%d", b.Successes),
						"errors":         fmt.Sprintf("%d", b.Errors),
						"p50_ms":         fmt.Sprintf("%d", b.P50Ms),
						"p95_ms":         fmt.Sprintf("%d", b.P95Ms),
						"p99_ms":         fmt.Sprintf("%d", b.P99Ms),
						"throughput_rps": fmt.Sprintf("%.2f", b.ThroughputRPS),
						"healthy":        boolStr(b.Healthy),
					})
				}
			}
		}
		writeConcurBucket := func(sectionID string, pick func(*concurtest.TargetResult) *concurtest.Bucket, preceded ...string) {
			if !sections[sectionID] {
				return
			}
			for _, p := range preceded {
				if sections[p] {
					writer.Write([]string{})
					break
				}
			}
			writeFilteredCSVHeader(writer, "concurtest", sectionID, columns)
			for _, tr := range sr.Targets {
				b := pick(tr)
				if b == nil {
					continue
				}
				writeFilteredCSVRow(writer, "concurtest", sectionID, columns, map[string]string{
					"url":         tr.URL,
					"concurrency": fmt.Sprintf("%d", b.Concurrency),
					"requests":    fmt.Sprintf("%d", b.Requests),
					"successes":   fmt.Sprintf("%d", b.Successes),
					"errors":      fmt.Sprintf("%d", b.Errors),
					"p50_ms":      fmt.Sprintf("%d", b.P50Ms),
					"p95_ms":      fmt.Sprintf("%d", b.P95Ms),
					"duration_ms": fmt.Sprintf("%d", b.DurationMs),
				})
			}
		}
		writeConcurBucket("sustained", func(tr *concurtest.TargetResult) *concurtest.Bucket { return tr.Sustained }, "summary", "ramp")
		writeConcurBucket("burst", func(tr *concurtest.TargetResult) *concurtest.Bucket { return tr.Burst }, "summary", "ramp", "sustained")

	case "oob":
		// oob result is a flat {"interactions": [...]} envelope.
		var sr struct {
			Interactions []oob.Interaction `json:"interactions"`
		}
		json.Unmarshal([]byte(result), &sr)
		if sections["interactions"] {
			writeFilteredCSVHeader(writer, "oob", "interactions", columns)
			for _, i := range sr.Interactions {
				writeFilteredCSVRow(writer, "oob", "interactions", columns, map[string]string{
					"kind":         i.Kind,
					"token":        i.Token,
					"at":           i.At.Format(time.RFC3339),
					"remote_addr":  i.RemoteAddr,
					"host":         i.Host,
					"method":       i.Method,
					"path":         i.Path,
					"user_agent":   i.UserAgent,
					"subdomain":    i.Subdomain,
					"query_type":   i.QueryType,
					"body_snippet": i.BodySnippet,
				})
			}
		}

	case "advancedweb":
		var sr advancedweb.ScanResult
		json.Unmarshal([]byte(result), &sr)
		// Per-stage summary first.
		if sections["summary"] {
			writeFilteredCSVHeader(writer, "advancedweb", "summary", columns)
			for _, st := range advancedweb.StageOrder {
				stage := sr.Stages[st]
				if stage == nil {
					continue
				}
				dur := ""
				if !stage.StartedAt.IsZero() && !stage.FinishedAt.IsZero() {
					dur = stage.FinishedAt.Sub(stage.StartedAt).String()
				}
				writeFilteredCSVRow(writer, "advancedweb", "summary", columns, map[string]string{
					"stage":       string(st),
					"status":      string(stage.Status),
					"message":     stage.Message,
					"started_at":  stage.StartedAt.Format("2006-01-02 15:04:05"),
					"finished_at": stage.FinishedAt.Format("2006-01-02 15:04:05"),
					"duration":    dur,
				})
			}
		}
		// DNS subdomains.
		if sections["dnsenum"] {
			if stage := sr.Stages["dnsenum"]; stage != nil && len(stage.Result) > 0 {
				var dns dnsenum.ScanResult
				if json.Unmarshal(stage.Result, &dns) == nil {
					writer.Write([]string{})
					writeFilteredCSVHeader(writer, "advancedweb", "dnsenum", columns)
					for _, tr := range dns.Results {
						for _, s := range tr.Subdomains {
							writeFilteredCSVRow(writer, "advancedweb", "dnsenum", columns, map[string]string{
								"subdomain": s.Subdomain,
								"ips":       strings.Join(s.IPs, ","),
								"source":    s.Source,
							})
						}
					}
				}
			}
		}
		// HTTPX services.
		if sections["httpxfind"] {
			if stage := sr.Stages["httpxfind"]; stage != nil && len(stage.Result) > 0 {
				var hpx httpxfind.ScanResult
				if json.Unmarshal(stage.Result, &hpx) == nil {
					writer.Write([]string{})
					writeFilteredCSVHeader(writer, "advancedweb", "httpxfind", columns)
					for _, s := range hpx.Services {
						writeFilteredCSVRow(writer, "advancedweb", "httpxfind", columns, map[string]string{
							"url":         s.URL,
							"status_code": fmt.Sprintf("%d", s.StatusCode),
							"title":       s.Title,
							"server":      s.Server,
						})
					}
				}
			}
		}
		// TechDetect technologies.
		if sections["techdetect"] {
			if stage := sr.Stages["techdetect"]; stage != nil && len(stage.Result) > 0 {
				var td techdetect.ScanResult
				if json.Unmarshal(stage.Result, &td) == nil {
					writer.Write([]string{})
					writeFilteredCSVHeader(writer, "advancedweb", "techdetect", columns)
					for _, tr := range td.Results {
						for _, t := range tr.Technologies {
							writeFilteredCSVRow(writer, "advancedweb", "techdetect", columns, map[string]string{
								"url":      tr.URL,
								"name":     t.Name,
								"version":  t.Version,
								"category": string(t.Category),
							})
						}
					}
				}
			}
		}
		// CVE matches (suite's own cvematch stage).
		if sections["cvematch"] {
			if stage := sr.Stages["cvematch"]; stage != nil && len(stage.Result) > 0 {
				var cm cvematch.ScanResult
				if json.Unmarshal(stage.Result, &cm) == nil {
					writer.Write([]string{})
					writeFilteredCSVHeader(writer, "advancedweb", "cvematch", columns)
					for _, m := range cm.Matches {
						if !SeverityAllowed(m.Severity, severities) {
							continue
						}
						writeFilteredCSVRow(writer, "advancedweb", "cvematch", columns, map[string]string{
							"target_url": m.URL,
							"product":    m.Product,
							"version":    m.Version,
							"cve":        m.CVE,
							"severity":   m.Severity,
							"fixed_in":   m.FixedIn,
						})
					}
				}
			}
		}
		// Nuclei findings.
		if sections["nuclei"] {
			if stage := sr.Stages["nuclei"]; stage != nil && len(stage.Result) > 0 {
				var nu nuclei.ScanResult
				if json.Unmarshal(stage.Result, &nu) == nil {
					writer.Write([]string{})
					writeFilteredCSVHeader(writer, "advancedweb", "nuclei", columns)
					for _, tr := range nu.Results {
						for _, f := range tr.Findings {
							if !SeverityAllowed(f.Severity, severities) {
								continue
							}
							writeFilteredCSVRow(writer, "advancedweb", "nuclei", columns, map[string]string{
								"url":      tr.URL,
								"template": f.TemplateID,
								"severity": f.Severity,
								"name":     f.Name,
							})
						}
					}
				}
			}
		}

		// === Commit 4: 7 additional stage blocks. Same pattern as
		// dnsenum/httpxfind/etc above — pull the stage's native shape
		// out of sr.Stages[<id>].Result, iterate, emit filtered rows. ===

		if sections["whois"] {
			if stage := sr.Stages["whois"]; stage != nil && len(stage.Result) > 0 {
				var wh whoisinfo.ScanResult
				if json.Unmarshal(stage.Result, &wh) == nil {
					writer.Write([]string{})
					writeFilteredCSVHeader(writer, "advancedweb", "whois", columns)
					for _, tr := range wh.Results {
						asn, org, country := "", "", ""
						if tr.ASN != nil {
							asn = tr.ASN.ASN
							org = tr.ASN.Organization
							country = tr.ASN.CountryCode
						}
						writeFilteredCSVRow(writer, "advancedweb", "whois", columns, map[string]string{
							"target":       tr.Target,
							"kind":         tr.Kind,
							"ip":           strings.Join(tr.ResolvedIPs, ","),
							"asn":          asn,
							"organization": org,
							"country":      country,
						})
					}
				}
			}
		}

		if sections["sslscan"] {
			if stage := sr.Stages["sslscan"]; stage != nil && len(stage.Result) > 0 {
				// sslscan suite stage stores []*HostResult directly.
				var hosts []*sslscan.HostResult
				if json.Unmarshal(stage.Result, &hosts) == nil {
					writer.Write([]string{})
					writeFilteredCSVHeader(writer, "advancedweb", "sslscan", columns)
					for _, h := range hosts {
						if h == nil {
							continue
						}
						for _, f := range h.Findings {
							if !SeverityAllowed(string(f.Severity), severities) {
								continue
							}
							writeFilteredCSVRow(writer, "advancedweb", "sslscan", columns, map[string]string{
								"host":        h.Host,
								"title":       f.Title,
								"description": f.Description,
								"severity":    string(f.Severity),
								"category":    f.Component,
							})
						}
					}
				}
			}
		}

		if sections["wafdetect"] {
			if stage := sr.Stages["wafdetect"]; stage != nil && len(stage.Result) > 0 {
				var wf wafdetect.ScanResult
				if json.Unmarshal(stage.Result, &wf) == nil {
					writer.Write([]string{})
					writeFilteredCSVHeader(writer, "advancedweb", "wafdetect", columns)
					boolStr := func(b bool) string {
						if b {
							return "yes"
						}
						return "no"
					}
					for _, tr := range wf.Results {
						writeFilteredCSVRow(writer, "advancedweb", "wafdetect", columns, map[string]string{
							"url":          tr.URL,
							"waf_detected": boolStr(tr.WAFDetected),
							"waf_name":     tr.WAFName,
							"confidence":   fmt.Sprintf("%d", tr.Confidence),
						})
					}
				}
			}
		}

		if sections["wpscan"] {
			if stage := sr.Stages["wpscan"]; stage != nil && len(stage.Result) > 0 {
				var wp wpscan.ScanResult
				if json.Unmarshal(stage.Result, &wp) == nil {
					writer.Write([]string{})
					writeFilteredCSVHeader(writer, "advancedweb", "wpscan", columns)
					for _, tr := range wp.Results {
						for _, f := range tr.Findings {
							if !SeverityAllowed(f.Severity, severities) {
								continue
							}
							writeFilteredCSVRow(writer, "advancedweb", "wpscan", columns, map[string]string{
								"url":         tr.URL,
								"title":       f.Title,
								"severity":    f.Severity,
								"category":    f.Category,
								"description": f.Description,
							})
						}
					}
				}
			}
		}

		if sections["dirspider"] {
			// dirspider stage holds direnum + spider merged output.
			// Try direnum shape first (more common), fall back to spider.
			if stage := sr.Stages["dirspider"]; stage != nil && len(stage.Result) > 0 {
				writer.Write([]string{})
				writeFilteredCSVHeader(writer, "advancedweb", "dirspider", columns)
				var de direnum.ScanResult
				if json.Unmarshal(stage.Result, &de) == nil && len(de.Results) > 0 {
					for _, tr := range de.Results {
						for _, e := range tr.Entries {
							writeFilteredCSVRow(writer, "advancedweb", "dirspider", columns, map[string]string{
								"url":         e.URL,
								"status_code": fmt.Sprintf("%d", e.StatusCode),
								"size":        fmt.Sprintf("%d", e.Size),
								"source":      "direnum",
							})
						}
					}
				}
				var sp spider.ScanResult
				if json.Unmarshal(stage.Result, &sp) == nil && len(sp.Results) > 0 {
					for _, tr := range sp.Results {
						for _, r := range tr.Resources {
							writeFilteredCSVRow(writer, "advancedweb", "dirspider", columns, map[string]string{
								"url":         r.URL,
								"status_code": fmt.Sprintf("%d", r.StatusCode),
								"size":        fmt.Sprintf("%d", r.Size),
								"source":      "spider",
							})
						}
					}
				}
			}
		}

		if sections["httpmethods"] {
			if stage := sr.Stages["httpmethods"]; stage != nil && len(stage.Result) > 0 {
				var hm httpmethods.ScanResult
				if json.Unmarshal(stage.Result, &hm) == nil {
					writer.Write([]string{})
					writeFilteredCSVHeader(writer, "advancedweb", "httpmethods", columns)
					boolStr := func(b bool) string {
						if b {
							return "yes"
						}
						return "no"
					}
					for _, tr := range hm.Results {
						for _, m := range tr.Methods {
							writeFilteredCSVRow(writer, "advancedweb", "httpmethods", columns, map[string]string{
								"url":          tr.URL,
								"method":       m.Method,
								"status_code":  fmt.Sprintf("%d", m.StatusCode),
								"is_dangerous": boolStr(m.Dangerous),
							})
						}
					}
				}
			}
		}

		if sections["secheaders"] {
			if stage := sr.Stages["secheaders"]; stage != nil && len(stage.Result) > 0 {
				var sh secheaders.ScanResult
				if json.Unmarshal(stage.Result, &sh) == nil {
					writer.Write([]string{})
					writeFilteredCSVHeader(writer, "advancedweb", "secheaders", columns)
					for _, tr := range sh.Results {
						for _, f := range tr.Findings {
							if !SeverityAllowed(string(f.Severity), severities) {
								continue
							}
							writeFilteredCSVRow(writer, "advancedweb", "secheaders", columns, map[string]string{
								"url":       tr.URL,
								"header":    f.Header,
								"severity":  string(f.Severity),
								"status":    f.Status,
								"recommend": f.Recommend,
							})
						}
					}
				}
			}
		}
	}
}

// --- JSON ---

func (h *Handler) exportJSON(w http.ResponseWriter, module, result, shortID string, sections map[string]bool, severities map[string]bool) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.Header().Set("Content-Disposition", fmt.Sprintf("attachment; filename=%s_%s.json", module, shortID))

	// For JSON, just return raw scan result (already JSON)
	// If sections are specified, filter
	if len(sections) == 0 {
		w.Write([]byte(result))
		return
	}

	// Parse and filter based on module
	var data interface{}
	json.Unmarshal([]byte(result), &data)

	out := map[string]interface{}{"module": module}

	switch module {
	case "sslscan":
		var results []*sslscan.HostResult
		json.Unmarshal([]byte(result), &results)
		if sections["findings"] {
			findings := []map[string]interface{}{}
			for _, hr := range results {
				for _, f := range hr.Findings {
					if !SeverityAllowed(string(f.Severity), severities) {
						continue
					}
					findings = append(findings, map[string]interface{}{
						"host": fmt.Sprintf("%s:%d", hr.Host, hr.Port), "severity": f.Severity,
						"title": f.Title, "description": f.Description, "cves": f.CVEs,
					})
				}
			}
			out["findings"] = findings
		}
		if sections["protocols"] {
			out["protocols"] = results
		}
		if sections["ciphers"] {
			out["ciphers"] = results
		}
		if sections["certificates"] {
			certs := []interface{}{}
			for _, hr := range results {
				if hr.CertInfo != nil {
					certs = append(certs, map[string]interface{}{"host": fmt.Sprintf("%s:%d", hr.Host, hr.Port), "cert": hr.CertInfo})
				}
			}
			out["certificates"] = certs
		}
	case "cvematch":
		var sr cvematch.ScanResult
		json.Unmarshal([]byte(result), &sr)
		if sections["matches"] {
			matches := []map[string]interface{}{}
			for _, m := range sr.Matches {
				if !SeverityAllowed(m.Severity, severities) {
					continue
				}
				matches = append(matches, map[string]interface{}{
					"target_url":  m.URL,
					"product":     m.Product,
					"version":     m.Version,
					"cve":         m.CVE,
					"severity":    m.Severity,
					"cvss":        m.CVSS,
					"fixed_in":    m.FixedIn,
					"description": m.Description,
					"remediation": m.Remediation,
					"reference":   m.Reference,
					// Match.Source → MatchSource rename (see CSV writer
					// above). Wire schema "source" still encodes the
					// match origin (builtin/cache/nvd).
					"source": m.MatchSource,
				})
			}
			out["matches"] = matches
		}
		if sections["inputs"] {
			out["inputs"] = sr.Inputs
		}

	// === Commit 1: JSON writer arms paired with the CSV arms above.
	// Each emits a typed-map per row so downstream tools get clean
	// JSON instead of the raw blob that the default branch produces.
	// Severity-gated modules (nuclei, jwt) honor `severities`. ===

	case "nuclei":
		var sr nuclei.ScanResult
		json.Unmarshal([]byte(result), &sr)
		if sections["findings"] {
			rows := []map[string]interface{}{}
			for _, tr := range sr.Results {
				for _, f := range tr.Findings {
					if !SeverityAllowed(f.Severity, severities) {
						continue
					}
					rows = append(rows, map[string]interface{}{
						"url":         tr.URL,
						"template_id": f.TemplateID,
						"name":        f.Name,
						"severity":    f.Severity,
						"type":        f.Type,
						"matched_at":  f.MatchedAt,
						"description": f.Description,
						"cves":        f.CVEs,
						"cwes":        f.CWEs,
						"tags":        f.Tags,
						"references":  f.References,
					})
				}
			}
			out["findings"] = rows
		}

	case "hostdiscovery":
		var sr hostdiscovery.ScanResult
		json.Unmarshal([]byte(result), &sr)
		if sections["hosts"] {
			rows := []map[string]interface{}{}
			for _, tr := range sr.Results {
				rows = append(rows, map[string]interface{}{
					"target":         tr.Target,
					"ip":             tr.IP,
					"host":           tr.Host,
					"host_up":        tr.HostUp,
					"ping_reachable": tr.PingReachable,
					"icmp_filtered":  tr.IcmpFiltered,
					"open_count":     tr.OpenCount,
				})
			}
			out["hosts"] = rows
		}
		if sections["ports"] {
			rows := []map[string]interface{}{}
			for _, tr := range sr.Results {
				for _, p := range tr.Ports {
					rows = append(rows, map[string]interface{}{
						"target":   tr.Target,
						"ip":       tr.IP,
						"port":     p.Port,
						"protocol": p.Protocol,
						"state":    p.State,
						"service":  p.Service,
					})
				}
			}
			out["ports"] = rows
		}

	case "portservice":
		var sr portservice.ScanResult
		json.Unmarshal([]byte(result), &sr)
		if sections["ports"] {
			rows := []map[string]interface{}{}
			for _, tr := range sr.Results {
				for _, p := range tr.Ports {
					rows = append(rows, map[string]interface{}{
						"target":     tr.Target,
						"ip":         tr.IP,
						"port":       p.Port,
						"protocol":   p.Protocol,
						"state":      p.State,
						"service":    p.Service,
						"product":    p.Product,
						"version":    p.Version,
						"extra_info": p.ExtraInfo,
						"tunnel":     p.Tunnel,
					})
				}
			}
			out["ports"] = rows
		}
		if sections["scripts"] {
			rows := []map[string]interface{}{}
			for _, tr := range sr.Results {
				for _, p := range tr.Ports {
					for _, sc := range p.Scripts {
						rows = append(rows, map[string]interface{}{
							"target":    tr.Target,
							"port":      p.Port,
							"script_id": sc.ID,
							"output":    sc.Output,
						})
					}
				}
			}
			out["scripts"] = rows
		}

	case "smbenum":
		var sr smbenum.ScanResult
		json.Unmarshal([]byte(result), &sr)
		if sections["shares"] {
			rows := []map[string]interface{}{}
			for _, tr := range sr.Results {
				for _, sh := range tr.Shares {
					rows = append(rows, map[string]interface{}{
						"target":  tr.Target,
						"name":    sh.Name,
						"type":    sh.Type,
						"comment": sh.Comment,
						"access":  sh.Access,
					})
				}
			}
			out["shares"] = rows
		}
		if sections["users"] {
			rows := []map[string]interface{}{}
			for _, tr := range sr.Results {
				for _, u := range tr.Users {
					rows = append(rows, map[string]interface{}{"target": tr.Target, "kind": "user", "name": u})
				}
				for _, g := range tr.Groups {
					rows = append(rows, map[string]interface{}{"target": tr.Target, "kind": "group", "name": g})
				}
			}
			out["users"] = rows
		}
		if sections["info"] {
			rows := []map[string]interface{}{}
			for _, tr := range sr.Results {
				rows = append(rows, map[string]interface{}{
					"target":        tr.Target,
					"ip":            tr.IP,
					"os":            tr.OS,
					"domain":        tr.Domain,
					"workgroup":     tr.Workgroup,
					"netbios_name":  tr.NetbiosName,
					"smb_port_open": tr.SMBPortOpen,
				})
			}
			out["info"] = rows
		}

	case "brutef":
		var sr brutef.ScanResult
		json.Unmarshal([]byte(result), &sr)
		if sections["credentials"] {
			rows := []map[string]interface{}{}
			for _, tr := range sr.Results {
				for _, c := range tr.Found {
					rows = append(rows, map[string]interface{}{
						"host":     c.Host,
						"port":     c.Port,
						"protocol": string(tr.Protocol),
						"username": c.Username,
						"password": c.Password,
					})
				}
			}
			out["credentials"] = rows
		}

	case "whoisinfo":
		var sr whoisinfo.ScanResult
		json.Unmarshal([]byte(result), &sr)
		if sections["summary"] {
			rows := []map[string]interface{}{}
			for _, tr := range sr.Results {
				row := map[string]interface{}{
					"target": tr.Target,
					"kind":   tr.Kind,
					"ip":     tr.ResolvedIPs,
				}
				if tr.ASN != nil {
					row["asn"] = tr.ASN.ASN
					row["organization"] = tr.ASN.Organization
					row["country"] = tr.ASN.CountryCode
					row["registry"] = tr.ASN.Registry
				}
				rows = append(rows, row)
			}
			out["summary"] = rows
		}
		if sections["records"] {
			rows := []map[string]interface{}{}
			for _, tr := range sr.Results {
				for _, rec := range tr.WHOISRecords {
					rows = append(rows, map[string]interface{}{
						"target": tr.Target,
						"field":  rec.Field,
						"value":  rec.Value,
					})
				}
			}
			out["records"] = rows
		}
		if sections["prefixes"] {
			rows := []map[string]interface{}{}
			for _, tr := range sr.Results {
				if tr.ASN == nil {
					continue
				}
				for _, p := range tr.ASN.Prefixes {
					rows = append(rows, map[string]interface{}{
						"asn":    tr.ASN.ASN,
						"prefix": p,
					})
				}
			}
			out["prefixes"] = rows
		}

	case "emailharvest":
		var sr emailharvest.ScanResult
		json.Unmarshal([]byte(result), &sr)
		if sections["emails"] {
			rows := []map[string]interface{}{}
			for _, d := range sr.Results {
				for _, e := range d.Emails {
					rows = append(rows, map[string]interface{}{"domain": d.Domain, "email": e})
				}
			}
			out["emails"] = rows
		}
		if sections["hosts"] {
			rows := []map[string]interface{}{}
			for _, d := range sr.Results {
				for _, h := range d.Hosts {
					rows = append(rows, map[string]interface{}{"domain": d.Domain, "host": h})
				}
			}
			out["hosts"] = rows
		}
		if sections["ips"] {
			rows := []map[string]interface{}{}
			for _, d := range sr.Results {
				for _, ip := range d.IPs {
					rows = append(rows, map[string]interface{}{"domain": d.Domain, "ip": ip})
				}
			}
			out["ips"] = rows
		}
		if sections["breaches"] {
			rows := []map[string]interface{}{}
			for _, d := range sr.Results {
				for _, b := range d.Breaches {
					rows = append(rows, map[string]interface{}{
						"domain":       d.Domain,
						"name":         b.Name,
						"title":        b.Title,
						"date":         b.BreachDate,
						"pwn_count":    b.PwnCount,
						"data_classes": b.DataClasses,
					})
				}
			}
			out["breaches"] = rows
		}

	case "leakscan":
		var sr leakscan.ScanResult
		json.Unmarshal([]byte(result), &sr)
		if sections["hits"] {
			rows := []map[string]interface{}{}
			for _, q := range sr.Results {
				for _, h := range q.Hits {
					purl := h.HTMLURL
					if purl == "" {
						purl = h.RawURL
					}
					patterns := []string{}
					for _, m := range h.Matches {
						patterns = append(patterns, m.Pattern)
					}
					rows = append(rows, map[string]interface{}{
						"query":       q.Query,
						"repo":        h.Repo,
						"path":        h.Path,
						"url":         purl,
						"secret_type": patterns,
						"snippet":     h.Snippet,
					})
				}
			}
			out["hits"] = rows
		}

	case "snmpenum":
		var sr snmpenum.ScanResult
		json.Unmarshal([]byte(result), &sr)
		if sections["communities"] {
			rows := []map[string]interface{}{}
			for _, tr := range sr.Results {
				for _, c := range tr.ValidCommunities {
					rows = append(rows, map[string]interface{}{
						"target":    tr.Target,
						"community": c,
						"access":    "read",
					})
				}
			}
			out["communities"] = rows
		}
		if sections["info"] {
			rows := []map[string]interface{}{}
			for _, tr := range sr.Results {
				sysFields := map[string]string{
					"sysDescr":    tr.SystemDescr,
					"sysUpTime":   tr.SystemUptime,
					"sysContact":  tr.SystemContact,
					"sysName":     tr.SystemName,
					"sysLocation": tr.SystemLocation,
				}
				for label, val := range sysFields {
					if val == "" {
						continue
					}
					rows = append(rows, map[string]interface{}{
						"target": tr.Target,
						"oid":    label,
						"value":  val,
					})
				}
				for _, walk := range tr.Walks {
					rows = append(rows, map[string]interface{}{
						"target": tr.Target,
						"oid":    walk.Label + " (" + walk.OID + ")",
						"value":  walk.Output,
					})
				}
			}
			out["info"] = rows
		}

	case "jwt":
		var sr jwt.ScanResult
		json.Unmarshal([]byte(result), &sr)
		claim := func(p map[string]interface{}, key string) interface{} {
			if p == nil {
				return nil
			}
			return p[key]
		}
		if sections["summary"] {
			rows := []map[string]interface{}{}
			for i, t := range sr.Results {
				rows = append(rows, map[string]interface{}{
					"token_idx": i + 1,
					"alg":       t.Algorithm,
					"issuer":    claim(t.Payload, "iss"),
					"subject":   claim(t.Payload, "sub"),
					"exp":       claim(t.Payload, "exp"),
					"secret":    t.CrackedSecret,
				})
			}
			out["summary"] = rows
		}
		if sections["issues"] {
			rows := []map[string]interface{}{}
			for i, t := range sr.Results {
				for _, f := range t.Findings {
					if !SeverityAllowed(f.Severity, severities) {
						continue
					}
					rows = append(rows, map[string]interface{}{
						"token_idx": i + 1,
						"severity":  f.Severity,
						"title":     f.Title,
						"detail":    f.Detail,
					})
				}
			}
			out["issues"] = rows
		}

	case "paramdisc":
		var sr paramdisc.ScanResult
		json.Unmarshal([]byte(result), &sr)
		if sections["hits"] {
			rows := []map[string]interface{}{}
			for _, tr := range sr.Results {
				for _, h := range tr.Hits {
					rows = append(rows, map[string]interface{}{
						"url":         tr.URL,
						"method":      h.Method,
						"name":        h.Name,
						"status_code": h.StatusCode,
						"status_diff": h.StatusDiff,
						"length_diff": h.LengthDiff,
						"reflected":   h.Reflected,
						"note":        h.Note,
					})
				}
			}
			out["hits"] = rows
		}

	// === Commit 2: JSON writers for the 8 modules. ===

	case "takeover":
		var sr takeover.ScanResult
		json.Unmarshal([]byte(result), &sr)
		if sections["findings"] {
			rows := []map[string]interface{}{}
			for _, f := range sr.Findings {
				if !SeverityAllowed(f.Severity, severities) {
					continue
				}
				rows = append(rows, map[string]interface{}{
					"subdomain":       f.Subdomain,
					"cname":           f.CNAME,
					"ips":             f.IPs,
					"service":         f.Service,
					"severity":        f.Severity,
					"http_status":     f.HTTPStatus,
					"matched_pattern": f.MatchedPattern,
					"note":            f.Note,
					"body_snippet":    f.BodySnippet,
				})
			}
			out["findings"] = rows
		}
		if sections["hosts"] {
			rows := []map[string]interface{}{}
			for _, h := range sr.Results {
				rows = append(rows, map[string]interface{}{
					"subdomain": h.Subdomain,
					"cname":     h.CNAME,
					"ips":       h.IPs,
					"status":    h.Status,
					"note":      h.Note,
				})
			}
			out["hosts"] = rows
		}

	case "corsscan":
		var sr corsscan.ScanResult
		json.Unmarshal([]byte(result), &sr)
		if sections["findings"] {
			rows := []map[string]interface{}{}
			for _, tr := range sr.Results {
				for _, f := range tr.Findings {
					if !SeverityAllowed(f.Severity, severities) {
						continue
					}
					rows = append(rows, map[string]interface{}{
						"url":            tr.URL,
						"severity":       f.Severity,
						"title":          f.Title,
						"request_origin": f.RequestOrigin,
						"response_acao":  f.ResponseACAO,
						"response_acac":  f.ResponseACAC,
						"detail":         f.Detail,
					})
				}
			}
			out["findings"] = rows
		}

	case "openredirect":
		var sr openredirect.ScanResult
		json.Unmarshal([]byte(result), &sr)
		if sections["findings"] {
			rows := []map[string]interface{}{}
			for _, tr := range sr.Results {
				for _, f := range tr.Findings {
					if !SeverityAllowed(f.Severity, severities) {
						continue
					}
					rows = append(rows, map[string]interface{}{
						"url":         f.URL,
						"parameter":   f.Parameter,
						"payload":     f.Payload,
						"status_code": f.StatusCode,
						"location":    f.Location,
						"how_matched": f.HowMatched,
						"severity":    f.Severity,
					})
				}
				_ = tr
			}
			out["findings"] = rows
		}

	case "graphqlscan":
		var sr graphqlscan.ScanResult
		json.Unmarshal([]byte(result), &sr)
		if sections["endpoints"] {
			rows := []map[string]interface{}{}
			for _, e := range sr.Endpoints {
				rows = append(rows, map[string]interface{}{
					"url":               e.URL,
					"status":            e.Status,
					"is_graphql":        e.IsGraphQL,
					"introspection_on":  e.IntrospectionOn,
					"schema_type_count": e.SchemaTypeCount,
					"query_fields":      e.QueryFields,
					"mutation_fields":   e.MutationFields,
				})
			}
			out["endpoints"] = rows
		}
		if sections["findings"] {
			rows := []map[string]interface{}{}
			for _, e := range sr.Endpoints {
				for _, f := range e.Findings {
					if !SeverityAllowed(f.Severity, severities) {
						continue
					}
					rows = append(rows, map[string]interface{}{
						"url":      e.URL,
						"severity": f.Severity,
						"title":    f.Title,
						"detail":   f.Detail,
						"evidence": f.Evidence,
					})
				}
			}
			out["findings"] = rows
		}

	case "authtest":
		var sr authtest.ScanResult
		json.Unmarshal([]byte(result), &sr)
		if sections["findings"] {
			rows := []map[string]interface{}{}
			for _, tr := range sr.Results {
				for _, f := range tr.Findings {
					if !SeverityAllowed(f.Severity, severities) {
						continue
					}
					rows = append(rows, map[string]interface{}{
						"login_url": tr.LoginURL,
						"method":    tr.Method,
						"severity":  f.Severity,
						"title":     f.Title,
						"detail":    f.Detail,
						"evidence":  f.Evidence,
					})
				}
			}
			out["findings"] = rows
		}
		if sections["attempts"] {
			rows := []map[string]interface{}{}
			for _, tr := range sr.Results {
				for _, a := range tr.Attempts {
					rows = append(rows, map[string]interface{}{
						"login_url":   tr.LoginURL,
						"username":    a.Username,
						"password":    a.Password,
						"status_code": a.StatusCode,
						"body_len":    a.BodyLen,
						"outcome":     a.Outcome,
					})
				}
			}
			out["attempts"] = rows
		}

	case "sstiscan":
		var sr sstiscan.ScanResult
		json.Unmarshal([]byte(result), &sr)
		if sections["findings"] {
			rows := []map[string]interface{}{}
			for _, tr := range sr.Results {
				for _, f := range tr.Findings {
					if !SeverityAllowed(f.Severity, severities) {
						continue
					}
					rows = append(rows, map[string]interface{}{
						"url":       f.URL,
						"engine":    f.Engine,
						"parameter": f.Parameter,
						"payload":   f.Payload,
						"marker":    f.Marker,
						"severity":  f.Severity,
						"note":      f.Note,
					})
				}
				_ = tr
			}
			out["findings"] = rows
		}

	case "cachepoison":
		var sr cachepoison.ScanResult
		json.Unmarshal([]byte(result), &sr)
		if sections["findings"] {
			rows := []map[string]interface{}{}
			for _, tr := range sr.Results {
				for _, f := range tr.Findings {
					if !SeverityAllowed(f.Severity, severities) {
						continue
					}
					rows = append(rows, map[string]interface{}{
						"url":      f.URL,
						"class":    f.Class,
						"header":   f.Header,
						"payload":  f.Payload,
						"severity": f.Severity,
						"title":    f.Title,
						"detail":   f.Detail,
						"evidence": f.Evidence,
					})
				}
				_ = tr
			}
			out["findings"] = rows
		}

	case "assetdisc":
		var sr assetdisc.ScanResult
		json.Unmarshal([]byte(result), &sr)
		if sections["assets"] {
			rows := []map[string]interface{}{}
			for _, q := range sr.Queries {
				for _, a := range q.Assets {
					rows = append(rows, map[string]interface{}{
						"source":   a.Source,
						"ip":       a.IP,
						"port":     a.Port,
						"hostname": a.Hostname,
						"asn":      a.ASN,
						"org":      a.Org,
						"country":  a.Country,
						"product":  a.Product,
						"os":       a.OS,
						"banner":   a.Banner,
						"domains":  a.Domains,
					})
				}
			}
			out["assets"] = rows
		}
		if sections["queries"] {
			rows := []map[string]interface{}{}
			for _, q := range sr.Queries {
				rows = append(rows, map[string]interface{}{
					"source": q.Source,
					"query":  q.Query,
					"total":  q.Total,
					"error":  q.Error,
				})
			}
			out["queries"] = rows
		}

	// === Commit 3 JSON writers. ===

	case "adpentest":
		var sr adpentest.ScanResult
		json.Unmarshal([]byte(result), &sr)
		if sections["discovery"] && sr.Discovered != nil {
			rows := []map[string]interface{}{}
			for _, dc := range sr.Discovered.DCs {
				rows = append(rows, map[string]interface{}{
					"ip": dc.IP, "fqdn": dc.FQDN, "netbios_name": dc.NetBIOSName,
					"os": dc.OS, "open_ports": dc.OpenPorts, "roles": dc.Roles,
				})
			}
			out["discovery"] = rows
		}
		if sections["users"] && sr.UnauthEnum != nil {
			out["users"] = sr.UnauthEnum.Users
		}
		if sections["groups"] && sr.UnauthEnum != nil {
			out["groups"] = sr.UnauthEnum.Groups
		}
		if sections["computers"] && sr.UnauthEnum != nil {
			out["computers"] = sr.UnauthEnum.Computers
		}
		if sections["shares"] && sr.UnauthEnum != nil {
			out["shares"] = sr.UnauthEnum.Shares
		}
		if sections["acl_findings"] && sr.AuthEnum != nil {
			out["acl_findings"] = sr.AuthEnum.ACLFindings
		}
		if sections["kerberoast"] && sr.AuthEnum != nil {
			out["kerberoast"] = sr.AuthEnum.Kerberoastable
		}
		if sections["hashes"] {
			out["hashes"] = sr.Hashes
		}
		if sections["vulns"] {
			vrows := []adpentest.VulnFinding{}
			for _, v := range sr.Vulns {
				if !SeverityAllowed(v.Severity, severities) {
					continue
				}
				vrows = append(vrows, v)
			}
			out["vulns"] = vrows
		}
		if sections["lateral"] {
			out["lateral"] = sr.Lateral
		}

	case "concurtest":
		var sr concurtest.ScanResult
		json.Unmarshal([]byte(result), &sr)
		if sections["summary"] {
			rows := []map[string]interface{}{}
			for _, tr := range sr.Targets {
				rows = append(rows, map[string]interface{}{
					"url":           tr.URL,
					"baseline_ms":   tr.BaselineMs,
					"practical_max": tr.PracticalMax,
					"notes":         tr.Notes,
					"error":         tr.Error,
				})
			}
			out["summary"] = rows
		}
		if sections["ramp"] {
			rows := []map[string]interface{}{}
			for _, tr := range sr.Targets {
				for _, b := range tr.Ramp {
					if b == nil {
						continue
					}
					rows = append(rows, map[string]interface{}{
						"url": tr.URL, "label": b.Label, "concurrency": b.Concurrency,
						"requests": b.Requests, "successes": b.Successes, "errors": b.Errors,
						"p50_ms": b.P50Ms, "p95_ms": b.P95Ms, "p99_ms": b.P99Ms,
						"throughput_rps": b.ThroughputRPS, "healthy": b.Healthy,
					})
				}
			}
			out["ramp"] = rows
		}
		// Sustained + Burst: same shape, one bucket per target (may be nil).
		writeBuckets := func(sectionID string, pick func(*concurtest.TargetResult) *concurtest.Bucket) {
			if !sections[sectionID] {
				return
			}
			rows := []map[string]interface{}{}
			for _, tr := range sr.Targets {
				b := pick(tr)
				if b == nil {
					continue
				}
				rows = append(rows, map[string]interface{}{
					"url": tr.URL, "concurrency": b.Concurrency,
					"requests": b.Requests, "successes": b.Successes, "errors": b.Errors,
					"p50_ms": b.P50Ms, "p95_ms": b.P95Ms, "duration_ms": b.DurationMs,
				})
			}
			out[sectionID] = rows
		}
		writeBuckets("sustained", func(tr *concurtest.TargetResult) *concurtest.Bucket { return tr.Sustained })
		writeBuckets("burst", func(tr *concurtest.TargetResult) *concurtest.Bucket { return tr.Burst })

	case "oob":
		var sr struct {
			Interactions []oob.Interaction `json:"interactions"`
		}
		json.Unmarshal([]byte(result), &sr)
		if sections["interactions"] {
			out["interactions"] = sr.Interactions
		}

	case "advancedweb":
		// Suite — dump every requested stage's native result blob under
		// stages.{stage_name} so downstream tooling can pick the parts
		// it needs without re-parsing the wrapper envelope.
		var sr advancedweb.ScanResult
		json.Unmarshal([]byte(result), &sr)
		out["target"] = sr.Target
		out["kind"] = sr.Kind
		stages := map[string]interface{}{}
		for _, stID := range advancedweb.StageOrder {
			st := sr.Stages[stID]
			if st == nil || !sections[string(stID)] && !sections["summary"] {
				continue
			}
			entry := map[string]interface{}{
				"status":  st.Status,
				"message": st.Message,
			}
			if sections[string(stID)] && len(st.Result) > 0 {
				var raw interface{}
				json.Unmarshal(st.Result, &raw)
				entry["result"] = raw
			}
			stages[string(stID)] = entry
		}
		out["stages"] = stages
	default:
		out["data"] = data
	}

	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	enc.Encode(out)
}

// --- PDF ---

// exportPDF emits a landscape A4 PDF. Commit 6 added the `columns`
// parameter so per-module PDF cases that opt in (currently sslscan
// findings) can route through the schema-aware pdfFilteredTable
// helper. Non-opted PDF cases still hard-code their headers/widths
// and ignore `columns` — that's intentional, opt-in by module.
func (h *Handler) exportPDF(w http.ResponseWriter, module, result, shortID string, sections map[string]bool, columns map[string]bool, severities map[string]bool) {
	w.Header().Set("Content-Type", "application/pdf")
	w.Header().Set("Content-Disposition", fmt.Sprintf("attachment; filename=%s_%s.pdf", module, shortID))

	pdf := fpdf.New("L", "mm", "A4", "")
	pdf.SetAutoPageBreak(true, 15)
	pdf.AddPage()

	// Title — explicit black text so it's readable regardless of any
	// stray color state from later sections that share the document.
	pdf.SetTextColor(0, 0, 0)
	pdf.SetFont("Helvetica", "B", 16)
	pdf.CellFormat(0, 10, "scaNNer Report: "+module, "", 1, "L", false, 0, "")
	pdf.SetTextColor(60, 60, 60)
	pdf.SetFont("Helvetica", "", 9)
	pdf.CellFormat(0, 6, "Scan ID: "+shortID, "", 1, "L", false, 0, "")
	pdf.Ln(4)

	if len(sections) == 0 {
		switch module {
		case "sslscan":
			sections["findings"] = true
		case "httpxfind":
			sections["services"] = true
		case "httpmethods":
			sections["methods"] = true
		case "wafdetect":
			sections["results"] = true
		case "wpscan":
			sections["vulnerabilities"] = true
		case "dnsenum":
			sections["subdomains"] = true
		case "techdetect":
			sections["technologies"] = true
		case "spider":
			sections["all"] = true
		case "direnum":
			sections["all"] = true
		case "secheaders":
			sections["findings"] = true
		// Commit 1: defaults for modules whose schema already declared
		// columns but whose writer was missing — pick the most useful
		// "primary" section so a no-tick export still produces something.
		case "nuclei":
			sections["findings"] = true
		case "hostdiscovery":
			sections["hosts"] = true
		case "portservice":
			sections["ports"] = true
		case "smbenum":
			sections["shares"] = true
		case "brutef":
			sections["credentials"] = true
		case "whoisinfo":
			sections["summary"] = true
		case "emailharvest":
			sections["emails"] = true
		case "leakscan":
			sections["hits"] = true
		case "snmpenum":
			sections["communities"] = true
		case "jwt":
			sections["summary"] = true
			sections["issues"] = true
		case "paramdisc":
			sections["hits"] = true
		// Commit 2 defaults — schema brand-new for these modules.
		case "takeover":
			sections["findings"] = true
		case "corsscan":
			sections["findings"] = true
		case "openredirect":
			sections["findings"] = true
		case "graphqlscan":
			sections["endpoints"] = true
			sections["findings"] = true
		case "authtest":
			sections["findings"] = true
		case "sstiscan":
			sections["findings"] = true
		case "cachepoison":
			sections["findings"] = true
		case "assetdisc":
			sections["assets"] = true
		// Commit 3 defaults.
		case "adpentest":
			sections["discovery"] = true
			sections["vulns"] = true
			sections["hashes"] = true
			sections["kerberoast"] = true
		case "concurtest":
			sections["summary"] = true
		case "oob":
			sections["interactions"] = true
		}
	}

	switch module {
	case "sslscan":
		var results []*sslscan.HostResult
		json.Unmarshal([]byte(result), &results)

		if sections["findings"] {
			// Commit 6: first opt-in to schema-driven PDF tables.
			// Helper reads the sslscan/findings catalog from
			// export_schema.go, intersects with the user's `columns`
			// map, and produces a proportional-width table. When the
			// user ticked none of the columns ExportColumnSelected
			// falls back to each column's Default flag — same logic
			// CSV/JSON already use, so a default export keeps the
			// "all useful columns" feel.
			pdfSection(pdf, "Findings")
			tbl := pdfFilteredTable(pdf, "sslscan", "findings", columns)
			for _, hr := range results {
				for _, f := range hr.Findings {
					if !SeverityAllowed(string(f.Severity), severities) {
						continue
					}
					tbl.filteredRow("sslscan", "findings", columns, map[string]string{
						"host":        hr.Host,
						"port":        fmt.Sprintf("%d", hr.Port),
						"severity":    string(f.Severity),
						"title":       f.Title,
						"description": f.Description,
						"cves":        strings.Join(f.CVEs, ", "),
						"component":   f.Component,
					})
				}
			}
			tbl.flush()
		}
		if sections["protocols"] {
			pdfSection(pdf, "Protocol Support")
			tbl := newPDFTable(pdf,
				[]string{"Host", "Port", "Protocol", "Supported"},
				[]float64{60, 20, 30, 25})
			for _, hr := range results {
				for _, p := range hr.Protocols {
					sup := "No"
					if p.Supported {
						sup = "Yes"
					}
					tbl.row([]string{hr.Host, fmt.Sprintf("%d", hr.Port), p.Name, sup})
				}
			}
			tbl.flush()
		}
		if sections["ciphers"] {
			pdfSection(pdf, "Cipher Suites")
			tbl := newPDFTable(pdf,
				[]string{"Host", "Port", "Cipher", "Protocols"},
				[]float64{50, 15, 120, 50})
			for _, hr := range results {
				for _, c := range hr.Ciphers {
					tbl.row([]string{hr.Host, fmt.Sprintf("%d", hr.Port), c.Name, strings.Join(c.Versions, ", ")})
				}
			}
			tbl.flush()
		}

	case "httpxfind":
		var sr httpxfind.ScanResult
		json.Unmarshal([]byte(result), &sr)
		if sections["services"] {
			pdfSection(pdf, "Discovered Services")
			tbl := newPDFTable(pdf,
				[]string{"URL", "Status", "Title", "Server", "Redirect"},
				[]float64{70, 18, 70, 50, 70})
			for _, s := range sr.Services {
				tbl.row([]string{s.URL, fmt.Sprintf("%d", s.StatusCode), s.Title, s.Server, s.RedirectURL})
			}
			tbl.flush()
		}

	case "httpmethods":
		var sr httpmethods.ScanResult
		json.Unmarshal([]byte(result), &sr)
		if sections["methods"] {
			pdfSection(pdf, "HTTP Method Test Results")
			tbl := newPDFTable(pdf,
				[]string{"URL", "Method", "Variant", "Status", "Result", "Dangerous"},
				[]float64{65, 22, 30, 18, 35, 22})
			for _, ur := range sr.Results {
				for _, m := range ur.Methods {
					danger := ""
					if m.Dangerous && m.Status == "Allowed" {
						danger = "YES"
					}
					tbl.row([]string{ur.URL, m.Method, m.Variant, fmt.Sprintf("%d", m.StatusCode), m.Status, danger})
				}
			}
			tbl.flush()
		}

	case "wafdetect":
		var sr wafdetect.ScanResult
		json.Unmarshal([]byte(result), &sr)
		if sections["results"] {
			pdfSection(pdf, "WAF Detection Results")
			tbl := newPDFTable(pdf,
				[]string{"URL", "WAF Detected", "WAF Name", "Vendor", "Confidence"},
				[]float64{80, 25, 50, 50, 25})
			for _, tr := range sr.Results {
				det := "No"
				if tr.WAFDetected {
					det = "Yes"
				}
				tbl.row([]string{tr.URL, det, tr.WAFName, tr.WAFVendor, fmt.Sprintf("%d%%", tr.Confidence)})
			}
			tbl.flush()
		}
		if sections["evidence"] {
			pdfSection(pdf, "Detection Evidence")
			tbl := newPDFTable(pdf,
				[]string{"URL", "Method", "Detail"},
				[]float64{70, 25, 180})
			for _, tr := range sr.Results {
				for _, d := range tr.Detections {
					tbl.row([]string{tr.URL, d.Method, d.Detail})
				}
			}
			tbl.flush()
		}

	case "wpscan":
		var sr wpscan.ScanResult
		json.Unmarshal([]byte(result), &sr)
		if sections["vulnerabilities"] {
			pdfSection(pdf, "Vulnerabilities")
			tbl := newPDFTable(pdf,
				[]string{"URL", "Severity", "Category", "Title", "CVEs", "Fixed In"},
				[]float64{55, 20, 20, 90, 50, 30})
			for _, tr := range sr.Results {
				for _, f := range tr.Findings {
					if f.Severity == "INFO" {
						continue
					}
					if !SeverityAllowed(f.Severity, severities) {
						continue
					}
					tbl.row([]string{tr.URL, f.Severity, f.Category, f.Title, strings.Join(f.CVEs, ", "), f.FixedIn})
				}
			}
			tbl.flush()
		}
		if sections["info"] {
			pdfSection(pdf, "Informational Findings")
			tbl := newPDFTable(pdf,
				[]string{"URL", "Title", "Description"},
				[]float64{60, 110, 100})
			for _, tr := range sr.Results {
				for _, f := range tr.Findings {
					if f.Severity != "INFO" {
						continue
					}
					tbl.row([]string{tr.URL, f.Title, f.Description})
				}
			}
			tbl.flush()
		}

	case "dnsenum":
		var sr dnsenum.ScanResult
		json.Unmarshal([]byte(result), &sr)
		if sections["subdomains"] {
			pdfSection(pdf, "Subdomains")
			tbl := newPDFTable(pdf,
				[]string{"Subdomain", "IP", "Source"},
				[]float64{110, 80, 50})
			for _, dr := range sr.Results {
				for _, s := range dr.Subdomains {
					tbl.row([]string{s.Subdomain, strings.Join(s.IPs, " "), s.Source})
				}
			}
			tbl.flush()
		}

	case "techdetect":
		var sr techdetect.ScanResult
		json.Unmarshal([]byte(result), &sr)
		if sections["technologies"] {
			pdfSection(pdf, "Technologies")
			tbl := newPDFTable(pdf,
				[]string{"URL", "Technology", "Version", "Category"},
				[]float64{80, 70, 40, 40})
			for _, tr := range sr.Results {
				for _, t := range tr.Technologies {
					tbl.row([]string{tr.URL, t.Name, t.Version, string(t.Category)})
				}
			}
			tbl.flush()
		}

	case "spider":
		var sr spider.ScanResult
		json.Unmarshal([]byte(result), &sr)
		if sections["all"] || sections["directories"] || sections["files"] {
			pdfSection(pdf, "Discovered Resources")
			tbl := newPDFTable(pdf,
				[]string{"Path", "Type", "Status", "Found On", "Depth"},
				[]float64{110, 25, 20, 80, 15})
			for _, tr := range sr.Results {
				for _, r := range tr.Resources {
					if sections["directories"] && string(r.Type) != "directory" {
						continue
					}
					if sections["files"] && string(r.Type) != "file" {
						continue
					}
					tbl.row([]string{r.Path, string(r.Type), fmt.Sprintf("%d", r.StatusCode), r.FoundOn, fmt.Sprintf("%d", r.Depth)})
				}
			}
			tbl.flush()
		}

	case "direnum":
		var sr direnum.ScanResult
		json.Unmarshal([]byte(result), &sr)
		pdfSection(pdf, "Directory Enumeration Results")
		tbl := newPDFTable(pdf,
			[]string{"Path", "Type", "Status", "Size", "Redirect"},
			[]float64{100, 25, 20, 25, 80})
		for _, tr := range sr.Results {
			for _, e := range tr.Entries {
				tp := "file"
				if e.IsDir {
					tp = "dir"
				}
				tbl.row([]string{e.Path, tp, fmt.Sprintf("%d", e.StatusCode), fmt.Sprintf("%d", e.Size), e.RedirectTo})
			}
		}
		tbl.flush()

	case "secheaders":
		var sr secheaders.ScanResult
		json.Unmarshal([]byte(result), &sr)
		if sections["findings"] {
			for _, tr := range sr.Results {
				pdfSection(pdf, fmt.Sprintf("%s — Grade: %s (%d/100)", tr.URL, tr.Grade, tr.Score))
				tbl := newPDFTable(pdf,
					[]string{"Header", "Status", "Severity", "Description"},
					[]float64{60, 25, 22, 160})
				for _, f := range tr.Findings {
					if !SeverityAllowed(string(f.Severity), severities) {
						continue
					}
					tbl.row([]string{f.Header, f.Status, string(f.Severity), f.Description})
				}
				tbl.flush()
			}
		}

	case "cvematch":
		var sr cvematch.ScanResult
		json.Unmarshal([]byte(result), &sr)
		// Default the section when caller didn't specify.
		if len(sections) == 0 || !sections["matches"] && !sections["inputs"] {
			sections["matches"] = true
		}
		if sections["matches"] {
			pdfSection(pdf, fmt.Sprintf("CVE Matches (%d)", len(sr.Matches)))
			tbl := newPDFTable(pdf,
				[]string{"CVE", "Severity", "CVSS", "Target", "Product", "Version", "Fixed In", "Remediation"},
				[]float64{30, 18, 12, 50, 28, 18, 20, 95})
			for _, m := range sr.Matches {
				if !SeverityAllowed(m.Severity, severities) {
					continue
				}
				tbl.row([]string{
					m.CVE,
					m.Severity,
					m.CVSS,
					m.URL,
					m.Product,
					m.Version,
					m.FixedIn,
					m.Remediation,
				})
			}
			tbl.flush()
		}
		if sections["inputs"] {
			pdfSection(pdf, fmt.Sprintf("Inputs (%d)", len(sr.Inputs)))
			tbl := newPDFTable(pdf,
				[]string{"Product", "Version", "Target URL", "Source"},
				[]float64{60, 30, 130, 40})
			for _, in := range sr.Inputs {
				tbl.row([]string{in.Product, in.Version, in.URL, in.Source})
			}
			tbl.flush()
		}

	case "advancedweb":
		// Multi-stage suite report. One section per stage that produced
		// data; each section calls the stage's native printer in a
		// table-row shape (compact enough to fit on landscape A4).
		var sr advancedweb.ScanResult
		json.Unmarshal([]byte(result), &sr)
		pdfSection(pdf, fmt.Sprintf("Target: %s · Kind: %s", sr.Target, sr.Kind))

		// Stage summary up top.
		if sections["summary"] || len(sections) == 0 {
			pdfSection(pdf, "Suite summary")
			tbl := newPDFTable(pdf,
				[]string{"Stage", "Status", "Message", "Duration"},
				[]float64{40, 22, 165, 35})
			for _, stID := range advancedweb.StageOrder {
				st := sr.Stages[stID]
				if st == nil {
					continue
				}
				dur := ""
				if !st.StartedAt.IsZero() && !st.FinishedAt.IsZero() {
					dur = st.FinishedAt.Sub(st.StartedAt).Truncate(time.Millisecond).String()
				}
				tbl.row([]string{string(stID), string(st.Status), st.Message, dur})
			}
			tbl.flush()
		}

		// Each per-stage section walks the native ScanResult and renders
		// a compact subset. Sections are opt-in (CSV writer uses the same
		// keys), but if none were specified we surface all available.
		want := func(id string) bool {
			if len(sections) == 0 {
				return true
			}
			return sections[id]
		}

		if st := sr.Stages["dnsenum"]; st != nil && len(st.Result) > 0 && want("dnsenum") {
			var dns dnsenum.ScanResult
			if json.Unmarshal(st.Result, &dns) == nil {
				pdfSection(pdf, "DNS Subdomains")
				tbl := newPDFTable(pdf,
					[]string{"Subdomain", "IPs", "Source"},
					[]float64{110, 100, 45})
				for _, tr := range dns.Results {
					for _, s := range tr.Subdomains {
						tbl.row([]string{s.Subdomain, strings.Join(s.IPs, ", "), s.Source})
					}
				}
				tbl.flush()
			}
		}
		if st := sr.Stages["httpxfind"]; st != nil && len(st.Result) > 0 && want("httpxfind") {
			var hpx httpxfind.ScanResult
			if json.Unmarshal(st.Result, &hpx) == nil {
				pdfSection(pdf, "HTTP Services")
				tbl := newPDFTable(pdf,
					[]string{"URL", "Status", "Title", "Server"},
					[]float64{120, 20, 70, 50})
				for _, s := range hpx.Services {
					tbl.row([]string{s.URL, fmt.Sprintf("%d", s.StatusCode), s.Title, s.Server})
				}
				tbl.flush()
			}
		}
		if st := sr.Stages["techdetect"]; st != nil && len(st.Result) > 0 && want("techdetect") {
			var td techdetect.ScanResult
			if json.Unmarshal(st.Result, &td) == nil {
				pdfSection(pdf, "Technologies")
				tbl := newPDFTable(pdf,
					[]string{"URL", "Tech", "Version", "Category"},
					[]float64{100, 60, 40, 45})
				for _, tr := range td.Results {
					for _, t := range tr.Technologies {
						tbl.row([]string{tr.URL, t.Name, t.Version, string(t.Category)})
					}
				}
				tbl.flush()
			}
		}
		if st := sr.Stages["cvematch"]; st != nil && len(st.Result) > 0 && want("cvematch") {
			var cm cvematch.ScanResult
			if json.Unmarshal(st.Result, &cm) == nil {
				pdfSection(pdf, "CVE Matches")
				tbl := newPDFTable(pdf,
					[]string{"CVE", "Severity", "Target", "Product", "Version", "Fixed In"},
					[]float64{30, 18, 60, 40, 22, 25})
				for _, m := range cm.Matches {
					if !SeverityAllowed(m.Severity, severities) {
						continue
					}
					tbl.row([]string{m.CVE, m.Severity, m.URL, m.Product, m.Version, m.FixedIn})
				}
				tbl.flush()
			}
		}
		if st := sr.Stages["nuclei"]; st != nil && len(st.Result) > 0 && want("nuclei") {
			var nu nuclei.ScanResult
			if json.Unmarshal(st.Result, &nu) == nil {
				pdfSection(pdf, "Nuclei Findings")
				tbl := newPDFTable(pdf,
					[]string{"URL", "Template", "Severity", "Name"},
					[]float64{90, 60, 22, 90})
				for _, tr := range nu.Results {
					for _, f := range tr.Findings {
						if !SeverityAllowed(f.Severity, severities) {
							continue
						}
						tbl.row([]string{tr.URL, f.TemplateID, f.Severity, f.Name})
					}
				}
				tbl.flush()
			}
		}
	}

	pdf.Output(w)
}

// toCP1252 re-encodes a UTF-8 string into the bytes fpdf's default
// Helvetica expects (Windows-1252 / WinAnsi). Without this, multi-byte
// UTF-8 sequences like em-dash "—" (0xE2 0x80 0x94) get rendered as three
// Latin-1 glyphs (e.g. "â€\""). CP1252 natively has em-dash at 0x97,
// en-dash at 0x96, smart quotes at 0x91-0x94, etc., so we map the common
// Unicode typographic chars to their CP1252 byte equivalents; anything
// outside CP1252 is replaced with "?" so the PDF stays well-formed.
func toCP1252(s string) string {
	var b strings.Builder
	b.Grow(len(s))
	for _, r := range s {
		switch {
		case r < 0x80:
			b.WriteByte(byte(r))
		case r >= 0xA0 && r <= 0xFF:
			// ISO-8859-1 supplement — CP1252 byte values match here.
			b.WriteByte(byte(r))
		case r == '€':
			b.WriteByte(0x80) // €
		case r == '‚':
			b.WriteByte(0x82) // ‚
		case r == 'ƒ':
			b.WriteByte(0x83) // ƒ
		case r == '„':
			b.WriteByte(0x84) // „
		case r == '…':
			b.WriteByte(0x85) // …
		case r == '†':
			b.WriteByte(0x86) // †
		case r == '‡':
			b.WriteByte(0x87) // ‡
		case r == 'ˆ':
			b.WriteByte(0x88) // ˆ
		case r == '‰':
			b.WriteByte(0x89) // ‰
		case r == 'Š':
			b.WriteByte(0x8A) // Š
		case r == '‹':
			b.WriteByte(0x8B) // ‹
		case r == 'Œ':
			b.WriteByte(0x8C) // Œ
		case r == 'Ž':
			b.WriteByte(0x8E) // Ž
		case r == '‘':
			b.WriteByte(0x91) // ‘
		case r == '’':
			b.WriteByte(0x92) // ’
		case r == '“':
			b.WriteByte(0x93) // “
		case r == '”':
			b.WriteByte(0x94) // ”
		case r == '•':
			b.WriteByte(0x95) // •
		case r == '–':
			b.WriteByte(0x96) // – en dash
		case r == '—':
			b.WriteByte(0x97) // — em dash
		case r == '˜':
			b.WriteByte(0x98) // ˜
		case r == '™':
			b.WriteByte(0x99) // ™
		case r == 'š':
			b.WriteByte(0x9A) // š
		case r == '›':
			b.WriteByte(0x9B) // ›
		case r == 'œ':
			b.WriteByte(0x9C) // œ
		case r == 'ž':
			b.WriteByte(0x9E) // ž
		case r == 'Ÿ':
			b.WriteByte(0x9F) // Ÿ
		default:
			b.WriteByte('?')
		}
	}
	return b.String()
}

func pdfSection(pdf *fpdf.Fpdf, title string) {
	pdf.Ln(6)
	pdf.SetTextColor(0, 0, 0)
	pdf.SetFont("Helvetica", "B", 11)
	pdf.CellFormat(0, 8, toCP1252(title), "", 1, "L", false, 0, "")
	pdf.Ln(1)
}

// pdfTable buffers a tabular section so the "#" column's width can be
// sized to the actual row count — a 4-digit row number needs more
// space than a 1-digit one and was previously wrapping to a second
// line. Use newPDFTable(...) → .row(cells) per data row → .flush()
// at the end to actually paint header + rows.
type pdfTable struct {
	pdf     *fpdf.Fpdf
	headers []string
	widths  []float64 // data-column widths (without the # column)
	rows    [][]string
}

// newPDFTable buffers the column definitions. Nothing is drawn until
// flush() — we need the total row count first to size the # column.
func newPDFTable(pdf *fpdf.Fpdf, headers []string, widths []float64) *pdfTable {
	return &pdfTable{pdf: pdf, headers: headers, widths: widths}
}

// pdfFilteredTable is the schema-aware counterpart to newPDFTable. It
// reads the export schema for `(module, sectionID)`, intersects the
// schema's declared column list with the user's selection map, then
// derives proportional widths so the surviving columns share the
// landscape A4 page (≈277mm usable). Label-length is the heuristic for
// the proportional split — wider labels get more pixels.
//
// Commit 6: until this helper existed, PDF tables had hard-coded
// widths/headers and the user's column selection was silently ignored.
// To opt a module's PDF section into column honoring, swap its
// `newPDFTable(pdf, [hard-coded headers], [hard-coded widths])` for
// `pdfFilteredTable(pdf, "module", "sectionID", columns)`. Per-row
// values must then be fed via `tbl.filteredRow(module, sectionID,
// columns, map[string]string{...})` so the column key set stays in
// sync with the header set.
func pdfFilteredTable(pdf *fpdf.Fpdf, module, sectionID string, columns map[string]bool) *pdfTable {
	cols := sectionColumns(module, sectionID)
	headers := []string{}
	weights := []float64{}
	totalWeight := 0.0
	for _, c := range cols {
		if !ExportColumnSelected(sectionID, c.ID, columns, cols) {
			continue
		}
		headers = append(headers, c.Label)
		// Weight is the label-width-in-characters with a floor so a
		// 1-char header doesn't collapse to a sliver.
		w := float64(len(c.Label))
		if w < 6 {
			w = 6
		}
		weights = append(weights, w)
		totalWeight += w
	}
	// Distribute ≈277mm landscape width across selected columns
	// proportionally. pdfTable's flush() will donate some of this back
	// to the # column it auto-prepends — but the proportional split is
	// preserved.
	const usableWidth = 277.0
	widths := make([]float64, len(weights))
	for i, w := range weights {
		widths[i] = (w / totalWeight) * usableWidth
	}
	return &pdfTable{pdf: pdf, headers: headers, widths: widths}
}

// filteredRow is the row-add complement of pdfFilteredTable. The
// `values` map carries every available column value for one row; only
// the columns the user selected get pushed into the table buffer (and
// the order matches the header set produced by pdfFilteredTable).
func (t *pdfTable) filteredRow(module, sectionID string, columns map[string]bool, values map[string]string) {
	cols := sectionColumns(module, sectionID)
	cells := []string{}
	for _, c := range cols {
		if !ExportColumnSelected(sectionID, c.ID, columns, cols) {
			continue
		}
		cells = append(cells, values[c.ID])
	}
	t.row(cells)
}

// row buffers one body row. Cells exclude the # column (auto-prepended
// on flush).
func (t *pdfTable) row(cells []string) {
	dup := make([]string, len(cells))
	copy(dup, cells)
	t.rows = append(t.rows, dup)
}

// flush renders the header + every buffered row. The # column width is
// measured from the widest row-number string at the body font size, and
// the widest data column donates that width so total page width is
// unchanged.
func (t *pdfTable) flush() {
	if len(t.rows) == 0 {
		return
	}
	// Switch to the body font so GetStringWidth measures with the same
	// metrics that pdfTableRowWrap will later render with.
	t.pdf.SetFont("Helvetica", "", 7)
	maxLabel := fmt.Sprintf("%d", len(t.rows))
	// 4mm cushion (~2mm padding per side + slack for fpdf's SplitLines
	// width comparison which can split mid-string when the measurement
	// is razor-close to the cell width). Minimum 7mm so the "#" header
	// glyph itself never wraps.
	numW := t.pdf.GetStringWidth(maxLabel) + 4.0
	if numW < 7 {
		numW = 7
	}

	// Donate numW from the widest data column.
	adj := make([]float64, len(t.widths))
	copy(adj, t.widths)
	if len(adj) > 0 {
		maxIdx := 0
		for i := 1; i < len(adj); i++ {
			if adj[i] > adj[maxIdx] {
				maxIdx = i
			}
		}
		adj[maxIdx] -= numW
		if adj[maxIdx] < 10 {
			adj[maxIdx] = 10
		}
	}
	finalWidths := append([]float64{numW}, adj...)
	finalHeaders := append([]string{"#"}, t.headers...)

	pdfTableHeaderLegacy(t.pdf, finalHeaders, finalWidths)
	for i, cells := range t.rows {
		full := append([]string{fmt.Sprintf("%d", i+1)}, cells...)
		pdfTableRowWrap(t.pdf, full, finalWidths)
	}
}

// pdfTableHeaderLegacy renders the header bar — dark fill, white text.
// Body rows below render on the white page background, so pdfTableRowWrap
// switches the text color back to near-black.
func pdfTableHeaderLegacy(pdf *fpdf.Fpdf, headers []string, widths []float64) {
	pdf.SetFont("Helvetica", "B", 8)
	pdf.SetFillColor(40, 40, 45)
	pdf.SetDrawColor(80, 80, 90)
	pdf.SetTextColor(255, 255, 255)
	for i, h := range headers {
		if i >= len(widths) {
			break
		}
		pdf.CellFormat(widths[i], 7, toCP1252(h), "1", 0, "L", true, 0, "")
	}
	pdf.Ln(-1)
	pdf.SetTextColor(20, 20, 20)
}

// pdfTableRowWrap renders a row whose cell heights flex with content.
// Each cell's text is wrapped to its column width via fpdf.SplitLines;
// the row height is set to the tallest cell's line count so cells stay
// aligned and borders close cleanly. Triggers an explicit page break if
// the row wouldn't fit on the remaining page space (Rect calls don't
// trigger the auto-pagebreak that CellFormat does).
func pdfTableRowWrap(pdf *fpdf.Fpdf, cells []string, widths []float64) {
	pdf.SetFont("Helvetica", "", 7)
	pdf.SetDrawColor(160, 160, 170)
	pdf.SetTextColor(20, 20, 20)

	const (
		lineH = 3.6  // mm per wrapped line
		padX  = 1.0  // horizontal padding inside each cell
		padY  = 0.6  // vertical padding above the first line
	)

	// Wrap each cell. SplitLines uses the currently-set font (7pt
	// Helvetica/CP1252). We must hand it CP1252-encoded bytes so the
	// width math and the rendered glyphs agree — passing UTF-8 directly
	// causes both garbled output and wrong per-line width calculations.
	wrapped := make([][][]byte, len(cells))
	maxLines := 1
	for i := 0; i < len(cells) && i < len(widths); i++ {
		w := widths[i] - padX*2
		if w < 1 {
			w = 1
		}
		// Normalize embedded newlines so SplitLines sees them as breaks.
		txt := strings.ReplaceAll(cells[i], "\r\n", "\n")
		var lines [][]byte
		for _, segment := range strings.Split(txt, "\n") {
			ls := pdf.SplitLines([]byte(toCP1252(segment)), w)
			if len(ls) == 0 {
				ls = [][]byte{[]byte("")}
			}
			lines = append(lines, ls...)
		}
		wrapped[i] = lines
		if len(lines) > maxLines {
			maxLines = len(lines)
		}
	}
	rowH := padY*2 + lineH*float64(maxLines)

	// Manual page-break: Rect() does NOT trigger fpdf's auto-pagebreak.
	_, pageH := pdf.GetPageSize()
	_, _, _, marginB := pdf.GetMargins()
	if pdf.GetY()+rowH > pageH-marginB {
		pdf.AddPage()
	}

	startX := pdf.GetX()
	startY := pdf.GetY()
	x := startX
	for i, w := range widths {
		if i >= len(cells) {
			break
		}
		// Cell border that hugs the wrapped height.
		pdf.Rect(x, startY, w, rowH, "D")
		// Stack lines vertically inside the cell.
		for j, line := range wrapped[i] {
			pdf.SetXY(x+padX, startY+padY+float64(j)*lineH)
			pdf.CellFormat(w-padX*2, lineH, string(line), "", 0, "L", false, 0, "")
		}
		x += w
	}
	pdf.SetXY(startX, startY+rowH)
}

func trunc(s string, max int) string {
	if len(s) > max {
		return s[:max] + "..."
	}
	return s
}
