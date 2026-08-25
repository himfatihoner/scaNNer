package handlers

import (
	"encoding/json"
	"strings"
	"time"
)

// parseSSTITarget extracts per-target findings from an sstiscan scan result.
// Shape: {"results":[{url,findings:[{engine,severity,parameter,payload,marker,
// note,method,location,url}],tested,error}]}. Each URLResult is matched to the
// normalized target via its url; every matching finding becomes a CatVuln raw
// ("SSTI: <engine> engine"). scanID is part of the contract but ignored here
// (the engine wires the link).
func parseSSTITarget(resJSON, target string, scanDate time.Time, scanID string, emit func(targetRaw, time.Time)) {
	var res struct {
		Results []struct {
			URL      string `json:"url"`
			Findings []struct {
				URL         string `json:"url"`
				Engine      string `json:"engine"`
				Parameter   string `json:"parameter"`
				Payload     string `json:"payload"`
				Marker      string `json:"marker"`
				Severity    string `json:"severity"`
				Note        string `json:"note"`
				Method      string `json:"method"`
				Location    string `json:"location"`
				RawRequest  string `json:"raw_request"`
				RawResponse string `json:"raw_response"`
			} `json:"findings"`
			Tested int    `json:"tested"`
			Error  string `json:"error"`
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
		for _, f := range ur.Findings {
			if emitted >= maxFindings {
				return
			}

			engine := strings.TrimSpace(f.Engine)
			title := "SSTI: " + engine + " engine"
			if engine == "" {
				continue
			}

			sev := strings.ToUpper(strings.TrimSpace(f.Severity))
			rank := severityRank(sev)

			detail := "param " + strings.TrimSpace(f.Parameter) + " payload " + strings.TrimSpace(f.Payload)

			// Concrete proof of evaluation: the payload that was sent,
			// the marker it rendered into (matched string), and the
			// exact injection point (param / location / method).
			var evParts []string
			if p := strings.TrimSpace(f.Payload); p != "" {
				evParts = append(evParts, "payload "+p)
			}
			if m := strings.TrimSpace(f.Marker); m != "" {
				evParts = append(evParts, "evaluated marker "+m)
			}
			if param := strings.TrimSpace(f.Parameter); param != "" {
				evParts = append(evParts, "param "+param)
			}
			if loc := strings.TrimSpace(f.Location); loc != "" {
				evParts = append(evParts, "location "+loc)
			}
			if meth := strings.TrimSpace(f.Method); meth != "" {
				evParts = append(evParts, "method "+meth)
			}

			emit(targetRaw{
				SevRank:     rank,
				Severity:    sev,
				Category:    CatVuln,
				Module:      "sstiscan",
				Title:       title,
				Detail:      detail,
				Locus:       strings.TrimSpace(f.URL),
				Evidence:    strings.Join(evParts, "; "),
				RawRequest:  strings.TrimSpace(f.RawRequest),
				RawResponse: strings.TrimSpace(f.RawResponse),
			}, scanDate)
			emitted++
		}
	}
}
