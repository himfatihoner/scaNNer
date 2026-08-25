package handlers

import (
	"encoding/json"
	"strconv"
	"strings"
	"time"
)

// parseOpenRedirectTarget extracts per-target findings from an openredirect
// scan result. Shape: {"results":[{url,findings:[{url,parameter,payload,
// location,how_matched,severity,status_code}],tested,error}]}. Each URLResult
// is matched to the normalized target via its url; every matching finding
// becomes a CatVuln raw ("Open redirect via ?<parameter>"). scanID is part of
// the contract but ignored here (the engine wires the link).
func parseOpenRedirectTarget(resJSON, target string, scanDate time.Time, scanID string, emit func(targetRaw, time.Time)) {
	var res struct {
		Results []struct {
			URL      string `json:"url"`
			Findings []struct {
				URL         string `json:"url"`
				Parameter   string `json:"parameter"`
				Payload     string `json:"payload"`
				Location    string `json:"location"`
				HowMatched  string `json:"how_matched"`
				Severity    string `json:"severity"`
				StatusCode  int    `json:"status_code"`
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

			param := strings.TrimSpace(f.Parameter)
			title := "Open redirect via ?" + param
			if strings.TrimSpace(title) == "" {
				continue
			}

			sev := strings.ToUpper(strings.TrimSpace(f.Severity))
			rank := severityRank(sev)

			location := strings.TrimSpace(f.Location)
			how := strings.TrimSpace(f.HowMatched)
			detail := "-> " + location + " (" + how + ")"

			// Evidence: the concrete proof that the redirect landed — the
			// injected payload, the param it rode in on, where the server
			// redirected to, and how the match was recognised.
			var ev []string
			if param != "" {
				ev = append(ev, "param="+param)
			}
			if p := strings.TrimSpace(f.Payload); p != "" {
				ev = append(ev, "payload="+p)
			}
			if location != "" {
				loc := "-> " + location
				if f.StatusCode != 0 {
					loc = "[HTTP " + strconv.Itoa(f.StatusCode) + "] " + loc
				}
				ev = append(ev, loc)
			}
			if how != "" {
				ev = append(ev, "match: "+how)
			}
			evidence := strings.Join(ev, " ")

			emit(targetRaw{
				SevRank:     rank,
				Severity:    sev,
				Category:    CatVuln,
				Module:      "openredirect",
				Title:       title,
				Detail:      detail,
				Locus:       strings.TrimSpace(f.URL),
				Evidence:    evidence,
				RawRequest:  strings.TrimSpace(f.RawRequest),
				RawResponse: strings.TrimSpace(f.RawResponse),
			}, scanDate)
			emitted++
		}
	}
}
