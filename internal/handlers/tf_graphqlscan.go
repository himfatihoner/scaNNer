package handlers

import (
	"encoding/json"
	"strings"
	"time"
)

// parseGraphQLTarget extracts per-target findings from a graphqlscan scan
// result. Shape: {"endpoints":[{url,is_graphql,introspection_on,findings:
// [{title,severity,detail,evidence}],...}]}. Each EndpointResult is matched to
// the normalized target via its url. Every finding becomes a CatVuln raw
// (severity from the finding); when introspection_on is set an additional
// CatHeaders observation is emitted. scanID is part of the contract but ignored
// here (the engine wires the link).
func parseGraphQLTarget(resJSON, target string, scanDate time.Time, scanID string, emit func(targetRaw, time.Time)) {
	var res struct {
		Endpoints []struct {
			URL             string `json:"url"`
			IsGraphQL       bool   `json:"is_graphql"`
			IntrospectionOn bool   `json:"introspection_on"`
			Findings        []struct {
				Title       string `json:"title"`
				Severity    string `json:"severity"`
				Detail      string `json:"detail"`
				Evidence    string `json:"evidence"`
				RawRequest  string `json:"raw_request"`
				RawResponse string `json:"raw_response"`
			} `json:"findings"`
		} `json:"endpoints"`
	}
	if err := json.Unmarshal([]byte(resJSON), &res); err != nil {
		return
	}

	const maxFindings = 200
	emitted := 0

	for _, ep := range res.Endpoints {
		if !urlMatchesAsset(ep.URL, target) {
			continue
		}
		locus := strings.TrimSpace(ep.URL)

		for _, f := range ep.Findings {
			if emitted >= maxFindings {
				return
			}
			if strings.TrimSpace(f.Title) == "" {
				continue
			}

			sev := strings.ToUpper(strings.TrimSpace(f.Severity))
			rank := severityRank(sev)

			ev := strings.TrimSpace(f.Evidence)
			detail := strings.TrimSpace(f.Detail)
			if ev != "" {
				if detail == "" {
					detail = ev
				} else {
					detail = detail + " — " + ev
				}
			}

			emit(targetRaw{
				SevRank:     rank,
				Severity:    sev,
				Category:    CatVuln,
				Module:      "graphqlscan",
				Title:       f.Title,
				Detail:      detail,
				Locus:       locus,
				Evidence:    ev,
				RawRequest:  strings.TrimSpace(f.RawRequest),
				RawResponse: strings.TrimSpace(f.RawResponse),
			}, scanDate)
			emitted++
		}

		if ep.IntrospectionOn {
			if emitted >= maxFindings {
				return
			}
			emit(targetRaw{
				SevRank:  -1,
				Severity: "",
				Category: CatHeaders,
				Module:   "graphqlscan",
				Title:    "GraphQL introspection enabled",
				Detail:   "Introspection is enabled on this GraphQL endpoint, exposing the full schema.",
				Locus:    locus,
			}, scanDate)
			emitted++
		}
	}
}
