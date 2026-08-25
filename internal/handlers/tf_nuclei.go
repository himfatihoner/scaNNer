package handlers

import (
	"encoding/json"
	"strings"
	"time"
)

// parseNucleiTarget extracts per-target findings from a nuclei scan result.
// Shape: {"results":[{url,findings:[{template_id,name,severity,type,host,
// matched_at,description,cves[],tags[]}]}]}. Each TargetResult is the per-URL
// bucket; a finding is emitted when the bucket url OR the finding's own host /
// matched_at resolves to the (already-normalized) target — nuclei normalizes
// hosts in its output, so the bucket key can differ from the input. Every
// finding becomes a CatVuln raw (Title=name or template_id, Detail=description,
// Severity/SevRank from the finding severity, Locus=matched_at or bucket url).
//
// scanID is part of the contract but ignored here (the engine wires the link).
func parseNucleiTarget(resJSON, target string, scanDate time.Time, scanID string, emit func(targetRaw, time.Time)) {
	var res struct {
		Results []struct {
			URL      string `json:"url"`
			Findings []struct {
				TemplateID  string   `json:"template_id"`
				Name        string   `json:"name"`
				Severity    string   `json:"severity"`
				Type        string   `json:"type"`
				Host        string   `json:"host"`
				MatchedAt   string   `json:"matched_at"`
				Description string   `json:"description"`
				CVEs        []string `json:"cves"`
				References  []string `json:"references"`
				Extracted   []string `json:"extracted"`
				RawRequest  string   `json:"raw_request"`
				RawResponse string   `json:"raw_response"`
			} `json:"findings"`
		} `json:"results"`
	}
	if err := json.Unmarshal([]byte(resJSON), &res); err != nil {
		return
	}

	const maxFindings = 500
	emitted := 0

	for _, tr := range res.Results {
		bucketMatches := urlMatchesAsset(tr.URL, target)
		for _, f := range tr.Findings {
			if emitted >= maxFindings {
				return
			}

			// Host-key: accept the finding if the bucket url, or the
			// finding's own host / matched_at resolve to this target.
			if !bucketMatches &&
				!urlMatchesAsset(f.Host, target) &&
				!urlMatchesAsset(f.MatchedAt, target) {
				continue
			}

			title := strings.TrimSpace(f.Name)
			if title == "" {
				title = strings.TrimSpace(f.TemplateID)
			}
			if title == "" {
				continue
			}

			locus := strings.TrimSpace(f.MatchedAt)
			if locus == "" {
				locus = strings.TrimSpace(tr.URL)
			}

			sev := strings.ToUpper(strings.TrimSpace(f.Severity))

			// Typed enrichment: nuclei carries the CVE id(s), reference URLs,
			// the extracted proof value(s), and (with -include-rr) the raw
			// request/response that proved the finding. Promote them out of
			// free-text into the structured drawer fields.
			var evidence string
			if len(f.Extracted) > 0 {
				var parts []string
				for _, e := range f.Extracted {
					if e = strings.TrimSpace(e); e != "" {
						parts = append(parts, e)
					}
				}
				evidence = strings.Join(parts, ", ")
			}

			emit(targetRaw{
				SevRank:     severityRank(sev),
				Severity:    sev,
				Category:    CatVuln,
				Module:      "nuclei",
				Title:       title,
				Detail:      strings.TrimSpace(f.Description),
				Locus:       locus,
				CVEs:        f.CVEs,
				References:  f.References,
				Evidence:    evidence,
				RawRequest:  strings.TrimSpace(f.RawRequest),
				RawResponse: strings.TrimSpace(f.RawResponse),
			}, scanDate)
			emitted++
		}
	}
}
