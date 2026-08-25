package handlers

import (
	"encoding/json"
	"strings"
	"time"
)

// parseWPScanTarget extracts per-target findings from a wpscan scan result.
// Shape: {"results":[{url,effective_url,is_wordpress,wp_version,wp_status,
// theme,plugin_count,status,reachable,findings:[{title,category,severity,
// description,cves,fixed_in}]}]}. Each TargetResult is matched to the
// normalized target via its url OR effective_url.
//
// Mapping:
//   - findings[] with a real severity (CRITICAL/HIGH/MEDIUM/LOW) -> CatVuln
//     (Title = finding title, Detail = description + " fixed_in " + fixed_in,
//     Severity = UPPERCASED severity, SevRank from severityRank, Locus = url).
//     INFO / unknown-severity findings are recon noise and are skipped.
//   - wp_version -> a CatTech recon fact ("WordPress <ver>", SevRank -1).
//   - theme -> a CatTech recon fact (theme string, SevRank -1).
//
// scanID is part of the contract but ignored here (the engine wires the link).
func parseWPScanTarget(resJSON, target string, scanDate time.Time, scanID string, emit func(targetRaw, time.Time)) {
	var res struct {
		Results []struct {
			URL          string `json:"url"`
			EffectiveURL string `json:"effective_url"`
			IsWordPress  bool   `json:"is_wordpress"`
			WPVersion    string `json:"wp_version"`
			WPStatus     string `json:"wp_status"`
			Theme        string `json:"theme"`
			PluginCount  int    `json:"plugin_count"`
			Status       string `json:"status"`
			Reachable    bool   `json:"reachable"`
			Findings     []struct {
				Title       string   `json:"title"`
				Category    string   `json:"category"`
				Severity    string   `json:"severity"`
				Description string   `json:"description"`
				CVEs        []string `json:"cves"`
				References  []string `json:"references"`
				FixedIn     string   `json:"fixed_in"`
			} `json:"findings"`
		} `json:"results"`
	}
	if err := json.Unmarshal([]byte(resJSON), &res); err != nil {
		return
	}

	const maxFindings = 500
	emitted := 0

	for _, r := range res.Results {
		if !urlMatchesAsset(r.URL, target) && !urlMatchesAsset(r.EffectiveURL, target) {
			continue
		}

		locus := strings.TrimSpace(r.URL)
		if locus == "" {
			locus = strings.TrimSpace(r.EffectiveURL)
		}

		// wp_version -> CatTech recon fact.
		if ver := strings.TrimSpace(r.WPVersion); ver != "" {
			if emitted >= maxFindings {
				return
			}
			emit(targetRaw{
				SevRank:  -1,
				Severity: "",
				Category: CatTech,
				Module:   "wpscan",
				Title:    "WordPress " + ver,
				Detail:   strings.TrimSpace(r.WPStatus),
				Locus:    locus,
			}, scanDate)
			emitted++
		}

		// theme -> CatTech recon fact.
		if theme := strings.TrimSpace(r.Theme); theme != "" {
			if emitted >= maxFindings {
				return
			}
			emit(targetRaw{
				SevRank:  -1,
				Severity: "",
				Category: CatTech,
				Module:   "wpscan",
				Title:    theme,
				Detail:   "",
				Locus:    locus,
			}, scanDate)
			emitted++
		}

		// findings[] -> CatVuln (real severities only; INFO/unknown skipped).
		for _, f := range r.Findings {
			if emitted >= maxFindings {
				return
			}
			title := strings.TrimSpace(f.Title)
			if title == "" {
				continue
			}
			sev := strings.ToUpper(strings.TrimSpace(f.Severity))
			rank := severityRank(sev)
			if rank < 1 {
				// INFO (0) / unknown (-1) — not a vuln.
				continue
			}

			fixed := strings.TrimSpace(f.FixedIn)
			detail := strings.TrimSpace(f.Description)
			if fixed != "" {
				if detail != "" {
					detail += " "
				}
				detail += "fixed_in " + fixed
			}

			// Typed enrichment: carry the CVE ids, reference URLs and
			// the fixed-in version through as structured fields instead
			// of leaving them flattened into Detail only.
			var remediation string
			if fixed != "" {
				remediation = "Update to version " + fixed + " or later."
			}

			emit(targetRaw{
				SevRank:     rank,
				Severity:    sev,
				Category:    CatVuln,
				Module:      "wpscan",
				Title:       title,
				Detail:      detail,
				Locus:       locus,
				CVEs:        f.CVEs,
				References:  f.References,
				Remediation: remediation,
			}, scanDate)
			emitted++
		}
	}
}
