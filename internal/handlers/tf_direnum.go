package handlers

import (
	"encoding/json"
	"fmt"
	"strings"
	"time"
)

// parseDirEnumTarget extracts per-target findings from a direnum scan result.
// Shape: {"results":[{url,entries:[{path,url,status_code,is_dir,redirect_to,
// content_type,size}],total_found,error}]}. Each TargetResult is matched to the
// normalized target via its url; every discovered entry becomes a CatWebContent
// recon fact (Title "<path> (<status_code>)", Detail from redirect_to /
// content_type, Locus the entry's absolute url). Recon facts carry SevRank -1
// and an empty Severity. Emission is capped at 100 entries per scan to keep the
// findings table bounded. scanID is part of the contract but ignored here (the
// engine wires the link).
func parseDirEnumTarget(resJSON, target string, scanDate time.Time, scanID string, emit func(targetRaw, time.Time)) {
	var res struct {
		Results []struct {
			URL     string `json:"url"`
			Entries []struct {
				Path        string `json:"path"`
				URL         string `json:"url"`
				StatusCode  int    `json:"status_code"`
				IsDir       bool   `json:"is_dir"`
				RedirectTo  string `json:"redirect_to"`
				ContentType string `json:"content_type"`
				Size        int64  `json:"size"`
			} `json:"entries"`
			TotalFound int    `json:"total_found"`
			Error      string `json:"error"`
		} `json:"results"`
	}
	if err := json.Unmarshal([]byte(resJSON), &res); err != nil {
		return
	}

	const maxEntries = 100
	emitted := 0

	for _, tr := range res.Results {
		if !urlMatchesAsset(tr.URL, target) {
			continue
		}
		for _, e := range tr.Entries {
			if emitted >= maxEntries {
				return
			}
			path := strings.TrimSpace(e.Path)
			if path == "" {
				continue
			}

			title := fmt.Sprintf("%s (%d)", path, e.StatusCode)

			var parts []string
			if rt := strings.TrimSpace(e.RedirectTo); rt != "" {
				parts = append(parts, "→ "+rt)
			}
			if ct := strings.TrimSpace(e.ContentType); ct != "" {
				parts = append(parts, ct)
			}
			detail := strings.Join(parts, " · ")

			locus := strings.TrimSpace(e.URL)

			emit(targetRaw{
				SevRank:  -1,
				Severity: "",
				Category: CatWebContent,
				Module:   "direnum",
				Title:    title,
				Detail:   detail,
				Locus:    locus,
			}, scanDate)
			emitted++
		}
	}
}
