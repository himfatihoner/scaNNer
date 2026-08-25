package handlers

import (
	"encoding/json"
	"strings"
	"time"
)

// parseTechDetectTarget extracts per-target findings from a techdetect scan
// result. Shape: {"results":[{url,status_code,title,server,
// technologies:[{name,version,category}],headers,error}]}. Each TargetResult
// is matched to the normalized target via its url.
//
// Mapping:
//   - technologies[] -> CatTech recon facts, one raw each
//     (Title = "<name> <version>", Detail = category, SevRank -1, Locus = url).
//   - server -> a single CatServices recon fact (Title = server, SevRank -1).
//
// scanID is part of the contract but ignored here (the engine wires the link).
func parseTechDetectTarget(resJSON, target string, scanDate time.Time, scanID string, emit func(targetRaw, time.Time)) {
	var res struct {
		Results []struct {
			URL          string `json:"url"`
			StatusCode   int    `json:"status_code"`
			Title        string `json:"title"`
			Server       string `json:"server"`
			Technologies []struct {
				Name     string `json:"name"`
				Version  string `json:"version"`
				Category string `json:"category"`
			} `json:"technologies"`
			Headers string `json:"headers"`
			Error   string `json:"error"`
		} `json:"results"`
	}
	if err := json.Unmarshal([]byte(resJSON), &res); err != nil {
		return
	}

	const maxFindings = 500
	emitted := 0

	for _, ur := range res.Results {
		if !urlMatchesAsset(ur.URL, target) {
			continue
		}
		locus := strings.TrimSpace(ur.URL)

		// server -> CatServices recon fact.
		if srv := strings.TrimSpace(ur.Server); srv != "" {
			if emitted >= maxFindings {
				return
			}
			emit(targetRaw{
				SevRank:  -1,
				Severity: "",
				Category: CatServices,
				Module:   "techdetect",
				Title:    srv,
				Detail:   "",
				Locus:    locus,
			}, scanDate)
			emitted++
		}

		// technologies[] -> CatTech recon facts.
		for _, t := range ur.Technologies {
			if emitted >= maxFindings {
				return
			}
			name := strings.TrimSpace(t.Name)
			if name == "" {
				continue
			}
			title := name
			if ver := strings.TrimSpace(t.Version); ver != "" {
				title = name + " " + ver
			}
			emit(targetRaw{
				SevRank:  -1,
				Severity: "",
				Category: CatTech,
				Module:   "techdetect",
				Title:    title,
				Detail:   strings.TrimSpace(t.Category),
				Locus:    locus,
			}, scanDate)
			emitted++
		}
	}
}
