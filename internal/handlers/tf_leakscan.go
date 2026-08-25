package handlers

import (
	"encoding/json"
	"strings"
	"time"
)

// tf_leakscan.go — per-target finding parser for the "leakscan" module.
//
// Result shape (from internal/modules/leakscan/scanner.go —
// ScanResult/QueryResult/Hit/Match):
//
//	{"results":[{
//	    "query":"org:acme filename:.env",
//	    "hits":[{
//	        "repo":"acme/config",
//	        "path":"deploy/.env",
//	        "html_url":"https://github.com/acme/config/blob/main/deploy/.env",
//	        "snippet":"AWS_SECRET=...",
//	        "matches":[{"pattern":"AWS Access Key","sample":"...AKIA... "}]
//	    }],
//	    "match_count":1,
//	    "error":""
//	}]}
//
// This is a GitHub/paste/archive code-search module — there is NO per-host
// field on any result entry. The scan config already targeted the host/domain,
// so every leaked-secret match belongs to `target` and we emit all of them
// (no host filtering possible or needed).
//
// Category mapping:
//   - results[].hits[].matches[] -> CatCreds (HIGH, SevRank 3)
//       Title  = "<pattern> leaked"
//       Detail = match sample + surrounding file snippet
//       Locus  = hit html_url (fall back to repo)
//
// Capped at maxLeakScanFindings emitted rows so a pathological search can't
// spawn thousands of findings.

const maxLeakScanFindings = 100

func parseLeakScanTarget(resJSON, target string, scanDate time.Time, scanID string, emit func(targetRaw, time.Time)) {
	_ = scanID // engine owns the scan link; parser ignores scanID by contract.
	_ = target // GitHub search has no host field; scan config already scoped this host.

	var res struct {
		Results []struct {
			Query string `json:"query"`
			Hits  []struct {
				Repo    string `json:"repo"`
				Path    string `json:"path"`
				HTMLURL string `json:"html_url"`
				Snippet string `json:"snippet"`
				Matches []struct {
					Pattern string `json:"pattern"`
					Sample  string `json:"sample"`
				} `json:"matches"`
			} `json:"hits"`
			MatchCount int    `json:"match_count"`
			Error      string `json:"error"`
		} `json:"results"`
	}
	if err := json.Unmarshal([]byte(resJSON), &res); err != nil {
		return
	}

	emitted := 0
	for _, qr := range res.Results {
		for _, hit := range qr.Hits {
			locus := strings.TrimSpace(hit.HTMLURL)
			if locus == "" {
				locus = strings.TrimSpace(hit.Repo)
			}
			for _, m := range hit.Matches {
				pattern := strings.TrimSpace(m.Pattern)
				if pattern == "" {
					continue // skip empty titles
				}
				if emitted >= maxLeakScanFindings {
					return
				}

				var parts []string
				if s := strings.TrimSpace(m.Sample); s != "" {
					parts = append(parts, "match: "+s)
				}
				if s := strings.TrimSpace(hit.Snippet); s != "" {
					parts = append(parts, "context: "+s)
				}

				emit(targetRaw{
					Module:   "leakscan",
					Category: CatCreds,
					Title:    pattern + " leaked",
					Detail:   strings.Join(parts, " | "),
					Locus:    locus,
					Severity: "HIGH",
					SevRank:  severityRank("HIGH"),
				}, scanDate)
				emitted++
			}
		}
	}
}
