package handlers

import (
	"encoding/json"
	"strings"
	"time"
)

// parseCachePoisonTarget extracts per-target findings from a cachepoison scan
// result. Shape: {"results":[{url,findings:[{url,class,header,payload,severity,
// title,detail,evidence}],tested,error}]}. Each URLResult is matched to the
// normalized target via its url; every matching finding becomes a CatVuln raw.
// scanID is part of the contract but ignored here (the engine wires the link).
func parseCachePoisonTarget(resJSON, target string, scanDate time.Time, scanID string, emit func(targetRaw, time.Time)) {
	var res struct {
		Results []struct {
			URL      string `json:"url"`
			Findings []struct {
				URL         string `json:"url"`
				Class       string `json:"class"`
				Header      string `json:"header"`
				Payload     string `json:"payload"`
				Severity    string `json:"severity"`
				Title       string `json:"title"`
				Detail      string `json:"detail"`
				Evidence    string `json:"evidence"`
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
			if strings.TrimSpace(f.Title) == "" {
				continue
			}

			detail := strings.TrimSpace(f.Detail)
			if ev := strings.TrimSpace(f.Evidence); ev != "" {
				if detail != "" {
					detail += " — evidence: " + ev
				} else {
					detail = "evidence: " + ev
				}
			}

			locus := strings.TrimSpace(f.URL)
			if locus == "" {
				locus = strings.TrimSpace(f.Class)
			}

			sev := strings.ToUpper(strings.TrimSpace(f.Severity))

			// Typed enrichment: promote the concrete proof out of free-text.
			// The most proof-like string is the reflection/response evidence;
			// prefix the poison header and payload that produced it so the
			// structured drawer shows the full "header X → reflected Y" chain.
			var evParts []string
			if h := strings.TrimSpace(f.Header); h != "" {
				evParts = append(evParts, "header: "+h)
			}
			if p := strings.TrimSpace(f.Payload); p != "" {
				evParts = append(evParts, "payload: "+p)
			}
			if ev := strings.TrimSpace(f.Evidence); ev != "" {
				evParts = append(evParts, ev)
			}
			evidence := strings.Join(evParts, " | ")

			emit(targetRaw{
				SevRank:     severityRank(sev),
				Severity:    sev,
				Category:    CatVuln,
				Module:      "cachepoison",
				Title:       f.Title,
				Detail:      detail,
				Locus:       locus,
				Evidence:    evidence,
				RawRequest:  strings.TrimSpace(f.RawRequest),
				RawResponse: strings.TrimSpace(f.RawResponse),
			}, scanDate)
			emitted++
		}
	}
}
