package handlers

import (
	"encoding/json"
	"fmt"
	"strings"
	"time"
)

// parseSecHeadersTarget extracts per-target findings from a secheaders scan
// result. Shape: {"results":[{url,grade,score,findings:[{header,severity,
// status,value,description,recommend}],probes:[...]}]}. Each URLResult is
// matched to the normalized target via its url.
//
// Mapping:
//   - findings[] with Status Missing/Weak/Insecure -> CatHeaders, one raw each
//     (Title = header + " " + status, Severity/SevRank from the finding).
//   - Exposed Server / X-Powered-By (and the AspNet version variants, all of
//     which only ever carry Status "Exposed") -> CatTech recon facts.
//   - grade -> a single CatHeaders info fact "Header grade: <grade>" (SevRank -1).
//
// scanID is part of the contract but ignored here (the engine wires the link).
func parseSecHeadersTarget(resJSON, target string, scanDate time.Time, scanID string, emit func(targetRaw, time.Time)) {
	var res struct {
		Results []struct {
			URL      string `json:"url"`
			Score    int    `json:"score"`
			Grade    string `json:"grade"`
			Findings []struct {
				Header      string `json:"header"`
				Severity    string `json:"severity"`
				Status      string `json:"status"`
				Value       string `json:"value"`
				Description string `json:"description"`
				Recommend   string `json:"recommend"`
			} `json:"findings"`
		} `json:"results"`
	}
	if err := json.Unmarshal([]byte(resJSON), &res); err != nil {
		return
	}

	const maxFindings = 200
	emitted := 0

	for _, ur := range res.Results {
		if !urlMatchesAsset(ur.URL, target) {
			continue
		}
		locus := strings.TrimSpace(ur.URL)

		// grade -> CatHeaders info recon fact (skip the "N/A" no-data marker).
		if g := strings.TrimSpace(ur.Grade); g != "" && !strings.EqualFold(g, "N/A") {
			if emitted >= maxFindings {
				return
			}
			detail := ""
			if ur.Score > 0 {
				detail = fmt.Sprintf("Security header score: %d/100", ur.Score)
			}
			emit(targetRaw{
				SevRank:  -1,
				Severity: "",
				Category: CatHeaders,
				Module:   "secheaders",
				Title:    "Header grade: " + g,
				Detail:   detail,
				Locus:    locus,
			}, scanDate)
			emitted++
		}

		for _, f := range ur.Findings {
			if emitted >= maxFindings {
				return
			}
			header := strings.TrimSpace(f.Header)
			status := strings.TrimSpace(f.Status)
			if header == "" {
				continue
			}

			// "Present" = header correctly set; not a finding.
			if status == "" || status == "Present" {
				continue
			}

			if status == "Exposed" {
				// Information-leak headers (Server, X-Powered-By, AspNet
				// versions) — technology recon facts, not vulns.
				v := strings.TrimSpace(f.Value)
				if v == "" {
					continue
				}
				emit(targetRaw{
					SevRank:  -1,
					Severity: "",
					Category: CatTech,
					Module:   "secheaders",
					Title:    header + ": " + v,
					Detail:   strings.TrimSpace(f.Description),
					Locus:    locus,
				}, scanDate)
				emitted++
				continue
			}

			// Every other problem status is a header/config weakness:
			// Missing/Weak/Insecure/Absent, the cookie-audit statuses
			// (Missing HttpOnly/Secure/SameSite, No security prefix,
			// SameSite=None without Secure, Broad Domain), and the CORS
			// statuses (Wildcard, Enabled) + Inconsistent. High/Critical
			// ones surface in the top Vulnerabilities table; the rest sit
			// in the Headers / Web-Misconfig box.
			sev := strings.ToUpper(strings.TrimSpace(f.Severity))
			rank := severityRank(sev)
			value := strings.TrimSpace(f.Value)
			recommend := strings.TrimSpace(f.Recommend)
			detail := strings.TrimSpace(f.Description)
			if value != "" {
				detail = appendEvidence(detail, "Value: "+value)
			}
			if recommend != "" {
				detail = appendEvidence(detail, "Recommend: "+recommend)
			}
			cat := CatHeaders
			// Typed enrichment is attached only to the CatVuln findings that
			// surface in the top Vulnerabilities table: the matched header
			// value is the concrete proof, and Recommend is the module's fix
			// text. The module carries no CVE / reference IDs, and its raw
			// request/response live on the probe (ProbeResult), not on the
			// per-header finding parsed here, so those fields stay unset.
			var evidence, remediation string
			if rank >= 3 {
				cat = CatVuln
				evidence = value
				remediation = recommend
			}
			emit(targetRaw{
				SevRank:     rank,
				Severity:    sev,
				Category:    cat,
				Module:      "secheaders",
				Title:       header + " " + status,
				Detail:      detail,
				Locus:       locus,
				Evidence:    evidence,
				Remediation: remediation,
			}, scanDate)
			emitted++
		}
	}
}
