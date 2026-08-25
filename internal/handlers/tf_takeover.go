package handlers

import (
	"encoding/json"
	"strconv"
	"strings"
	"time"
)

// tf_takeover.go — per-target finding parser for the "takeover" module.
//
// Result shape (module ScanResult):
//
//	{"results":[{
//	   subdomain, cname, ips[], status, note,
//	   finding:{subdomain, cname, ips[], service, severity, http_status,
//	            body_snippet, matched_pattern, note}
//	 }],
//	 "findings":[{subdomain, cname, ips[], service, severity, http_status,
//	              body_snippet, matched_pattern, note}]}
//
// Host key: results[].subdomain and findings[].subdomain (normalizeAsset). An
// entry matches the target when its subdomain normalizes to the target key.
//
// Category mapping:
//
//	findings[]                       -> CatVuln       "Subdomain takeover: <service>"
//	results[].finding (service set)  -> CatVuln       "Subdomain takeover: <service>"
//	results[].cname                  -> CatSubdomains (recon fact, SevRank -1)
//
// findings[] duplicates results[].finding by design (the module appends each
// HostResult.Finding into the top-level Findings slice); the aggregation engine
// dedups by Module|Category|Title|Locus, so both emits collapse to one finding.
//
// scanID is part of the signature but ignored here — the engine wires the link.
func parseTakeoverTarget(resJSON, target string, scanDate time.Time, scanID string, emit func(targetRaw, time.Time)) {
	if target == "" {
		return
	}

	type finding struct {
		Subdomain      string   `json:"subdomain"`
		CNAME          string   `json:"cname"`
		IPs            []string `json:"ips,omitempty"`
		Service        string   `json:"service"`
		Severity       string   `json:"severity"`
		HTTPStatus     int      `json:"http_status"`
		BodySnippet    string   `json:"body_snippet,omitempty"`
		MatchedPattern string   `json:"matched_pattern,omitempty"`
		Note           string   `json:"note,omitempty"`
	}

	var res struct {
		Results []struct {
			Subdomain string   `json:"subdomain"`
			CNAME     string   `json:"cname"`
			IPs       []string `json:"ips,omitempty"`
			Status    string   `json:"status"`
			Note      string   `json:"note,omitempty"`
			Finding   *finding `json:"finding,omitempty"`
		} `json:"results"`
		Findings []finding `json:"findings"`
	}
	if err := json.Unmarshal([]byte(resJSON), &res); err != nil {
		return
	}

	const maxVulns = 200
	emitted := 0

	// emitVuln maps a takeover finding to a CatVuln raw, filtered to the target
	// subdomain. Skips entries with no service (nothing to title) and respects
	// the per-list cap.
	emitVuln := func(f finding) {
		if emitted >= maxVulns {
			return
		}
		service := strings.TrimSpace(f.Service)
		if service == "" {
			return
		}
		if normalizeAsset(f.Subdomain) != target {
			return
		}
		sev := strings.ToUpper(strings.TrimSpace(f.Severity))
		cname := strings.TrimSpace(f.CNAME)
		matched := strings.TrimSpace(f.MatchedPattern)
		var parts []string
		if matched != "" {
			parts = append(parts, "matched: "+matched)
		}
		if n := strings.TrimSpace(f.Note); n != "" {
			parts = append(parts, n)
		}
		if cname != "" {
			parts = append(parts, "CNAME: "+cname)
		}

		// Typed enrichment: the concrete proof of a dangling-CNAME takeover is
		// the CNAME → provider pointer plus the pattern that matched (either a
		// signal like "cname-target-nxdomain" or the literal body fingerprint)
		// and the response body snippet the module captured.
		var evParts []string
		if cname != "" {
			evParts = append(evParts, "CNAME "+cname+" → "+service)
		} else {
			evParts = append(evParts, "service: "+service)
		}
		if matched != "" {
			evParts = append(evParts, "matched: "+matched)
		}
		if f.HTTPStatus > 0 {
			evParts = append(evParts, "HTTP "+strconv.Itoa(f.HTTPStatus))
		}
		if bs := strings.TrimSpace(f.BodySnippet); bs != "" {
			evParts = append(evParts, "body: "+bs)
		}
		evidence := strings.Join(evParts, " | ")

		// f.Note carries the signature's remediation hint (see Signature.Note /
		// matched.Note in the module), so surface it as structured remediation.
		remediation := strings.TrimSpace(f.Note)

		emit(targetRaw{
			SevRank:     severityRank(sev),
			Severity:    sev,
			Category:    CatVuln,
			Module:      "takeover",
			Title:       "Subdomain takeover: " + service,
			Detail:      strings.Join(parts, " — "),
			Locus:       strings.TrimSpace(f.Subdomain),
			Evidence:    evidence,
			Remediation: remediation,
		}, scanDate)
		emitted++
	}

	// Top-level findings[] — confirmed/candidate takeovers.
	for _, f := range res.Findings {
		emitVuln(f)
	}

	// Per-host results — the embedded finding (CatVuln) plus the CNAME fact.
	for _, r := range res.Results {
		if normalizeAsset(r.Subdomain) != target {
			continue
		}
		if r.Finding != nil {
			emitVuln(*r.Finding)
		}

		// results[].cname -> CatSubdomains recon fact (SevRank -1).
		cname := strings.TrimSpace(r.CNAME)
		if cname == "" {
			continue
		}
		var parts []string
		if len(r.IPs) > 0 {
			parts = append(parts, "ips: "+strings.Join(r.IPs, ", "))
		}
		if st := strings.TrimSpace(r.Status); st != "" {
			parts = append(parts, "status: "+st)
		}
		if n := strings.TrimSpace(r.Note); n != "" {
			parts = append(parts, n)
		}
		emit(targetRaw{
			Module:   "takeover",
			Category: CatSubdomains,
			Title:    "CNAME: " + cname,
			Detail:   strings.Join(parts, " | "),
			Locus:    strings.TrimSpace(r.Subdomain),
			Severity: "",
			SevRank:  -1,
		}, scanDate)
	}
}
