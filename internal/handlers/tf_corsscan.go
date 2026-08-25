package handlers

import (
	"encoding/json"
	"strings"
	"time"
)

// parseCORSTarget extracts per-target findings from a corsscan scan result.
// Shape: {"results":[{url,findings:[{severity,title,detail,request_origin,
// response_acao,response_acac,...}],error}]}. Each URLResult is matched to the
// normalized target via its url; every matching finding becomes a raw —
// CatVuln when its severity is HIGH or above, otherwise CatHeaders. scanID is
// part of the contract but ignored here (the engine wires the link).
func parseCORSTarget(resJSON, target string, scanDate time.Time, scanID string, emit func(targetRaw, time.Time)) {
	var res struct {
		Results []struct {
			URL      string `json:"url"`
			Findings []struct {
				Severity       string `json:"severity"`
				Title          string `json:"title"`
				Detail         string `json:"detail"`
				RequestOrigin  string `json:"request_origin"`
				RequestMethod  string `json:"request_method"`
				ResponseACAO   string `json:"response_acao"`
				ResponseACAC   string `json:"response_acac"`
				AllowedMethods string `json:"allowed_methods"`
				AllowedHeaders string `json:"allowed_headers"`
				RawRequest     string `json:"raw_request"`
				RawResponse    string `json:"raw_response"`
			} `json:"findings"`
			Error string `json:"error"`
		} `json:"results"`
	}
	if err := json.Unmarshal([]byte(resJSON), &res); err != nil {
		return
	}

	const maxFindings = 200
	highRank := severityRank("HIGH")
	emitted := 0

	for _, ur := range res.Results {
		if !urlMatchesAsset(ur.URL, target) {
			continue
		}
		locus := strings.TrimSpace(ur.URL)
		for _, f := range ur.Findings {
			if emitted >= maxFindings {
				return
			}
			if strings.TrimSpace(f.Title) == "" {
				continue
			}

			sev := strings.ToUpper(strings.TrimSpace(f.Severity))
			rank := severityRank(sev)

			category := CatHeaders
			if rank >= highRank {
				category = CatVuln
			}

			detail := strings.TrimSpace(f.Detail)
			if o := strings.TrimSpace(f.RequestOrigin); o != "" {
				detail = appendEvidence(detail, "Origin: "+o)
			}
			if acao := strings.TrimSpace(f.ResponseACAO); acao != "" {
				detail = appendEvidence(detail, "ACAO: "+acao)
			}
			if acac := strings.TrimSpace(f.ResponseACAC); acac != "" {
				detail = appendEvidence(detail, "ACAC: "+acac)
			}

			raw := targetRaw{
				SevRank:  rank,
				Severity: sev,
				Category: category,
				Module:   "corsscan",
				Title:    f.Title,
				Detail:   detail,
				Locus:    locus,
			}

			// Promote the concrete CORS proof into typed enrichment for
			// confirmed (CatVuln) findings: the exact Origin sent and the
			// ACAO/ACAC (plus preflight Allow-Methods/-Headers) the server
			// reflected back, alongside the raw request/response that
			// captured it. corsscan carries no CVE/reference/remediation.
			if category == CatVuln {
				var ev []string
				if o := strings.TrimSpace(f.RequestOrigin); o != "" {
					ev = append(ev, "Origin: "+o)
				}
				if acao := strings.TrimSpace(f.ResponseACAO); acao != "" {
					ev = append(ev, "ACAO: "+acao)
				}
				if acac := strings.TrimSpace(f.ResponseACAC); acac != "" {
					ev = append(ev, "ACAC: "+acac)
				}
				if am := strings.TrimSpace(f.AllowedMethods); am != "" {
					ev = append(ev, "Allow-Methods: "+am)
				}
				if ah := strings.TrimSpace(f.AllowedHeaders); ah != "" {
					ev = append(ev, "Allow-Headers: "+ah)
				}
				raw.Evidence = strings.Join(ev, " | ")
				raw.RawRequest = strings.TrimSpace(f.RawRequest)
				raw.RawResponse = strings.TrimSpace(f.RawResponse)
			}

			emit(raw, scanDate)
			emitted++
		}
	}
}

// appendEvidence joins an evidence crumb onto an existing detail string.
func appendEvidence(detail, crumb string) string {
	if detail == "" {
		return crumb
	}
	return detail + " — " + crumb
}
