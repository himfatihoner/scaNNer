package handlers

import (
	"encoding/json"
	"fmt"
	"strings"
	"time"
)

// parseWAFDetectTarget extracts per-target findings from a wafdetect scan
// result. Shape: {"results":[{url,waf_detected,waf_name,waf_vendor,confidence,
// server,detections:[{method,detail}],error}]}. Each TargetResult is matched to
// the normalized target via its url; a positive WAF verdict becomes a CatWAF
// recon fact (SevRank -1). scanID is part of the contract but ignored here (the
// engine wires the link).
func parseWAFDetectTarget(resJSON, target string, scanDate time.Time, scanID string, emit func(targetRaw, time.Time)) {
	var res struct {
		Results []struct {
			URL         string `json:"url"`
			WAFDetected bool   `json:"waf_detected"`
			WAFName     string `json:"waf_name"`
			WAFVendor   string `json:"waf_vendor"`
			Confidence  int    `json:"confidence"`
			Server      string `json:"server"`
			Detections  []struct {
				Method string `json:"method"`
				Detail string `json:"detail"`
			} `json:"detections"`
			Error string `json:"error"`
		} `json:"results"`
	}
	if err := json.Unmarshal([]byte(resJSON), &res); err != nil {
		return
	}

	const maxFindings = 200
	emitted := 0

	for _, tr := range res.Results {
		if emitted >= maxFindings {
			return
		}
		if !urlMatchesAsset(tr.URL, target) {
			continue
		}

		wafName := strings.TrimSpace(tr.WAFName)
		if !tr.WAFDetected || wafName == "" {
			continue
		}

		title := fmt.Sprintf("%s (%d%% confidence)", wafName, tr.Confidence)

		emit(targetRaw{
			SevRank:  -1,
			Severity: "",
			Category: CatWAF,
			Module:   "wafdetect",
			Title:    title,
			Detail:   strings.TrimSpace(tr.WAFVendor),
			Locus:    strings.TrimSpace(tr.URL),
		}, scanDate)
		emitted++
	}
}
