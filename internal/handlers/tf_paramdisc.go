package handlers

import (
	"encoding/json"
	"strings"
	"time"
)

// parseParamDiscTarget extracts per-target findings from a paramdisc scan
// result. Shape: {"results":[{url,method,hits:[{name,reflected,status_code,
// status_diff,length_diff,note}],tested,error}]}. Each result is matched to the
// normalized target via its url; every discovered parameter hit becomes a
// CatWebContent recon fact (SevRank -1, no severity). NOTE: the scanner emits
// hits[].name — the old parser read hits[].param and silently dropped every
// hit. scanID is part of the contract but ignored here (the engine wires the
// link).
func parseParamDiscTarget(resJSON, target string, scanDate time.Time, scanID string, emit func(targetRaw, time.Time)) {
	var res struct {
		Results []struct {
			URL    string `json:"url"`
			Method string `json:"method"`
			Hits   []struct {
				Name      string `json:"name"`
				Reflected bool   `json:"reflected"`
				Note      string `json:"note"`
			} `json:"hits"`
		} `json:"results"`
	}
	if err := json.Unmarshal([]byte(resJSON), &res); err != nil {
		return
	}

	const maxHits = 100
	emitted := 0

	for _, r := range res.Results {
		if !urlMatchesAsset(r.URL, target) {
			continue
		}
		locus := strings.TrimSpace(r.URL)
		method := strings.TrimSpace(r.Method)
		for _, h := range r.Hits {
			if emitted >= maxHits {
				return
			}
			name := strings.TrimSpace(h.Name)
			if name == "" {
				continue
			}

			title := "?" + name
			if method != "" {
				title = method + " ?" + name
			}
			if h.Reflected {
				title += " (reflected)"
			}

			emit(targetRaw{
				SevRank:  -1,
				Severity: "",
				Category: CatWebContent,
				Module:   "paramdisc",
				Title:    title,
				Detail:   strings.TrimSpace(h.Note),
				Locus:    locus,
			}, scanDate)
			emitted++
		}
	}
}
