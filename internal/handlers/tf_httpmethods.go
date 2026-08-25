package handlers

import (
	"encoding/json"
	"strings"
	"time"
)

// parseHTTPMethodsTarget extracts per-target findings from an httpmethods scan
// result. Shape: {"results":[{url,methods:[{method,status,dangerous,note,allow,
// status_code}]}]}. Each URLResult is matched to the normalized target via its
// url. A method that is dangerous AND actually Allowed becomes a CatVuln MEDIUM
// finding; any other method that carries a note becomes an informational
// CatHeaders fact. scanID is part of the contract but ignored here (the engine
// wires the link).
func parseHTTPMethodsTarget(resJSON, target string, scanDate time.Time, scanID string, emit func(targetRaw, time.Time)) {
	var res struct {
		Results []struct {
			URL     string `json:"url"`
			Methods []struct {
				Method     string `json:"method"`
				Status     string `json:"status"`
				Dangerous  bool   `json:"dangerous"`
				Note       string `json:"note"`
				Allow      string `json:"allow"`
				StatusCode int    `json:"status_code"`
			} `json:"methods"`
		} `json:"results"`
	}
	if err := json.Unmarshal([]byte(resJSON), &res); err != nil {
		return
	}

	const maxFindings = 200
	medRank := severityRank("MEDIUM")
	emitted := 0

	for _, ur := range res.Results {
		if !urlMatchesAsset(ur.URL, target) {
			continue
		}
		locus := strings.TrimSpace(ur.URL)
		for _, m := range ur.Methods {
			if emitted >= maxFindings {
				return
			}
			method := strings.TrimSpace(m.Method)
			if method == "" {
				continue
			}
			note := strings.TrimSpace(m.Note)

			if m.Dangerous && m.Status == "Allowed" {
				// Dangerous method that actually executed — real vuln.
				emit(targetRaw{
					SevRank:  medRank,
					Severity: "MEDIUM",
					Category: CatVuln,
					Module:   "httpmethods",
					Title:    method + " allowed",
					Detail:   note,
					Locus:    locus,
				}, scanDate)
				emitted++
				continue
			}

			// Any other method carrying an annotation is an informational fact.
			if note != "" {
				emit(targetRaw{
					SevRank:  -1,
					Severity: "",
					Category: CatHeaders,
					Module:   "httpmethods",
					Title:    method + " method note",
					Detail:   note,
					Locus:    locus,
				}, scanDate)
				emitted++
			}
		}
	}
}
