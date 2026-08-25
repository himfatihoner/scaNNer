package handlers

import (
	"encoding/json"
	"fmt"
	"time"
)

// parseConcurTestTarget parses a concurtest scan result (a per-target
// concurrency/capacity metric module) and emits at most a couple of recon
// facts per matching target under CatHeaders. It never invents vulns.
//
// Shape (see internal/modules/concurtest/scanner.go):
//
//	{"targets":[{url,baseline_ms,practical_max,notes[],ramp[],...,error}]}
//
// scanID is part of the signature for engine wiring but is ignored here.
func parseConcurTestTarget(resJSON, target string, scanDate time.Time, scanID string, emit func(targetRaw, time.Time)) {
	_ = scanID

	var res struct {
		Targets []struct {
			URL          string `json:"url"`
			BaselineMs   int64  `json:"baseline_ms"`
			PracticalMax int    `json:"practical_max"`
			Ramp         []struct {
				Concurrency int  `json:"concurrency"`
				Healthy     bool `json:"healthy"`
			} `json:"ramp"`
			Error string `json:"error,omitempty"`
		} `json:"targets"`
	}
	if err := json.Unmarshal([]byte(resJSON), &res); err != nil {
		return
	}

	for _, t := range res.Targets {
		if t.URL == "" || !urlMatchesAsset(t.URL, target) {
			continue
		}

		// Recon fact 1: where rate limiting / throttling kicks in — the
		// first ramp level that stopped being healthy.
		for _, b := range t.Ramp {
			if !b.Healthy && b.Concurrency > 0 {
				title := fmt.Sprintf("Rate limiting kicks in at %d concurrency", b.Concurrency)
				detail := fmt.Sprintf("First unhealthy ramp level: %d concurrent requests (baseline %dms).", b.Concurrency, t.BaselineMs)
				emit(targetRaw{
					Module:   "concurtest",
					Category: CatHeaders,
					Title:    title,
					Detail:   detail,
					Locus:    t.URL,
					Severity: "",
					SevRank:  -1,
				}, scanDate)
				break
			}
		}

		// Recon fact 2: the detected practical-max concurrency (highest
		// healthy ramp level).
		var pmTitle, pmDetail string
		if t.PracticalMax > 0 {
			pmTitle = fmt.Sprintf("Practical max concurrency: %d", t.PracticalMax)
			pmDetail = fmt.Sprintf("Highest healthy concurrency level (baseline %dms).", t.BaselineMs)
		} else {
			pmTitle = "Practical max concurrency: none (saturated at 1 concurrent)"
			pmDetail = "No ramp level cleared the health threshold."
		}
		emit(targetRaw{
			Module:   "concurtest",
			Category: CatHeaders,
			Title:    pmTitle,
			Detail:   pmDetail,
			Locus:    t.URL,
			Severity: "",
			SevRank:  -1,
		}, scanDate)
	}
}
