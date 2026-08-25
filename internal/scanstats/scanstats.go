// Package scanstats produces compact denormalized counters from a scan's
// raw JSON result, decoupling the dashboard's chart aggregator from the
// per-module result types.
//
// Why a separate package: the database layer needs to write these counts
// alongside the result blob (so dashboard queries can read them without
// re-parsing megabytes of JSON), and the handlers package is too heavy a
// dependency for the database package. This package is pure functions —
// no imports beyond stdlib — so both DB and handlers can use it freely.
package scanstats

import (
	"encoding/json"
	"strings"
)

// Compute is the single entry point. Returns (severityHits, openConnections)
// for the given module + result JSON. Either or both may be 0 for modules
// that don't emit findings or port data.
//
// The function tolerates malformed JSON: any unmarshal error is silently
// treated as "no findings". This matches the prior behaviour of the
// handler-side helpers — chart data should never crash a page render.
func Compute(module, resultJSON string) (severity, openConnections int) {
	return SeverityHits(module, resultJSON), OpenConnections(module, resultJSON)
}

// SeverityHits walks a scan's stored result JSON and returns the number
// of critical+high+medium findings (or just findings, depending on module).
// We use anonymous struct unmarshal to keep this orthogonal to the per-module
// types — adding a new module later doesn't break this aggregator.
func SeverityHits(module, resultJSON string) int {
	if resultJSON == "" || resultJSON == "{}" {
		return 0
	}
	severe := func(s string) bool {
		ls := strings.ToLower(s)
		return ls == "critical" || ls == "high" || ls == "medium"
	}
	switch module {
	case "nuclei":
		var r struct {
			Results []struct {
				Findings []struct {
					Severity string `json:"severity"`
				} `json:"findings"`
			} `json:"results"`
		}
		if json.Unmarshal([]byte(resultJSON), &r) != nil {
			return 0
		}
		n := 0
		for _, tr := range r.Results {
			for _, f := range tr.Findings {
				if severe(f.Severity) {
					n++
				}
			}
		}
		return n
	case "sslscan":
		var hosts []struct {
			Findings []struct {
				Severity string `json:"severity"`
			} `json:"findings"`
		}
		if json.Unmarshal([]byte(resultJSON), &hosts) != nil {
			return 0
		}
		n := 0
		for _, h := range hosts {
			for _, f := range h.Findings {
				if severe(f.Severity) {
					n++
				}
			}
		}
		return n
	case "wpscan":
		var r struct {
			Results []struct {
				Findings []struct {
					Severity string `json:"severity"`
				} `json:"findings"`
			} `json:"results"`
		}
		if json.Unmarshal([]byte(resultJSON), &r) != nil {
			return 0
		}
		n := 0
		for _, tr := range r.Results {
			for _, f := range tr.Findings {
				if severe(f.Severity) {
					n++
				}
			}
		}
		return n
	case "secheaders":
		var r struct {
			Results []struct {
				Findings []struct {
					Severity string `json:"severity"`
				} `json:"findings"`
			} `json:"results"`
		}
		if json.Unmarshal([]byte(resultJSON), &r) != nil {
			return 0
		}
		n := 0
		for _, tr := range r.Results {
			for _, f := range tr.Findings {
				if severe(f.Severity) {
					n++
				}
			}
		}
		return n
	case "wafdetect":
		var r struct {
			Results []struct {
				WAFDetected bool `json:"waf_detected"`
			} `json:"results"`
		}
		if json.Unmarshal([]byte(resultJSON), &r) != nil {
			return 0
		}
		n := 0
		for _, tr := range r.Results {
			if tr.WAFDetected {
				n++
			}
		}
		return n
	case "brutef":
		// Each cracked credential is its own finding.
		var r struct {
			Results []struct {
				Found []struct{} `json:"found"`
			} `json:"results"`
		}
		if json.Unmarshal([]byte(resultJSON), &r) != nil {
			return 0
		}
		n := 0
		for _, tr := range r.Results {
			n += len(tr.Found)
		}
		return n
	case "smbenum":
		// Vuln nmap-script outputs are the high-signal events.
		var r struct {
			Results []struct {
				NmapScripts []struct {
					ID     string `json:"id"`
					Output string `json:"output"`
				} `json:"nmap_scripts"`
			} `json:"results"`
		}
		if json.Unmarshal([]byte(resultJSON), &r) != nil {
			return 0
		}
		n := 0
		for _, tr := range r.Results {
			for _, s := range tr.NmapScripts {
				low := strings.ToLower(s.ID)
				if strings.Contains(low, "vuln") && strings.Contains(strings.ToLower(s.Output), "vulnerable") {
					n++
				}
			}
		}
		return n
	case "corsscan":
		// Audit MEDIUM fix: corsscan emits {results:[{findings:[{severity}]}]}
		// — mirrors the nuclei/wpscan shape. Counts CRITICAL/HIGH/MEDIUM
		// across all URLResults so the Dashboard severity chart reflects
		// CORS misconfig hits.
		var r struct {
			Results []struct {
				Findings []struct {
					Severity string `json:"severity"`
				} `json:"findings"`
			} `json:"results"`
		}
		if json.Unmarshal([]byte(resultJSON), &r) != nil {
			return 0
		}
		n := 0
		for _, tr := range r.Results {
			for _, f := range tr.Findings {
				if severe(f.Severity) {
					n++
				}
			}
		}
		return n
	case "takeover":
		// takeover.ScanResult.Findings are the confirmed dangling-CNAME hits
		// (CRITICAL S3, HIGH GitHub Pages / Heroku / Azure, etc).
		var r struct {
			Findings []struct {
				Severity string `json:"severity"`
			} `json:"findings"`
		}
		if json.Unmarshal([]byte(resultJSON), &r) != nil {
			return 0
		}
		n := 0
		for _, f := range r.Findings {
			if severe(f.Severity) {
				n++
			}
		}
		return n
	case "graphqlscan":
		// graphqlscan emits {endpoints:[{findings:[{severity:"HIGH"|"MEDIUM"|"LOW"}]}]}
		// — the generic fallback only walks `results[]`/`findings[]`/bare-array
		// shapes, so this module needs its own case for Dashboard severity
		// counts to reflect introspection/GraphiQL/CSRF-over-GET hits.
		var r struct {
			Endpoints []struct {
				Findings []struct {
					Severity string `json:"severity"`
				} `json:"findings"`
			} `json:"endpoints"`
		}
		if json.Unmarshal([]byte(resultJSON), &r) != nil {
			return 0
		}
		n := 0
		for _, e := range r.Endpoints {
			for _, f := range e.Findings {
				if severe(f.Severity) {
					n++
				}
			}
		}
		return n
	case "leakscan":
		// leakscan emits {results:[{hits:[{matches:[{pattern,sample}]}],match_count}]}
		// — no per-finding severity field, but every regex match is a
		// credential/secret leak (AWS key, GitHub token, private key,
		// JWT, etc.) which is unambiguously HIGH-severity by any normal
		// pentest definition. Sum MatchCount across all queries so the
		// Dashboard severity chart reflects the module's highest-value
		// output. Audit MEDIUM fix — leakscan matches previously rolled
		// up as 0 because the generic fallback only walks
		// results[].findings[].severity, which this module doesn't emit.
		var r struct {
			Results []struct {
				MatchCount int `json:"match_count"`
			} `json:"results"`
		}
		if json.Unmarshal([]byte(resultJSON), &r) != nil {
			return 0
		}
		n := 0
		for _, tr := range r.Results {
			n += tr.MatchCount
		}
		return n
	case "openredirect":
		// openredirect emits {results:[{findings:[{severity:"HIGH"}]}]}
		// — every finding is HIGH-severity by construction (scanner.go
		// hardcodes Severity:"HIGH"). Explicit case pins the count so the
		// Dashboard severity chart reflects open-redirect hits even if the
		// generic fallback changes shape.
		var r struct {
			Results []struct {
				Findings []struct {
					Severity string `json:"severity"`
				} `json:"findings"`
			} `json:"results"`
		}
		if json.Unmarshal([]byte(resultJSON), &r) != nil {
			return 0
		}
		n := 0
		for _, tr := range r.Results {
			for _, f := range tr.Findings {
				if severe(f.Severity) {
					n++
				}
			}
		}
		return n
	case "sstiscan":
		// sstiscan emits {results:[{findings:[{severity:"CRITICAL"|"HIGH"}]}]}
		// where CRITICAL covers engine-unique markers (7777777 Jinja2, the
		// Handlebars chain) and HIGH covers the arithmetic-only "49"
		// confirmations that overlap across evaluating engines. Mirrors the
		// nuclei/wpscan shape; `severe` lowercases so both uppercase values
		// are counted. Audit MEDIUM fix: pin the count to the module's exact
		// shape so the Dashboard severity chart reflects SSTI hits even if
		// the generic fallback shape ever changes.
		var r struct {
			Results []struct {
				Findings []struct {
					Severity string `json:"severity"`
				} `json:"findings"`
			} `json:"results"`
		}
		if json.Unmarshal([]byte(resultJSON), &r) != nil {
			return 0
		}
		n := 0
		for _, tr := range r.Results {
			for _, f := range tr.Findings {
				if severe(f.Severity) {
					n++
				}
			}
		}
		return n
	case "jwt":
		// jwt emits {results:[{findings:[{severity:"CRITICAL"|"HIGH"|...}]}]}
		// where CRITICAL covers cracked HMAC secret + alg=none, HIGH covers
		// jku/x5u/path-like-kid/sensitive payload field, MEDIUM covers
		// expired/no-exp/missing-alg/x5c. Mirrors the nuclei/wpscan shape;
		// `severe` already lowercases so the uppercase severities work.
		// Audit MEDIUM fix: previously fell through to genericSeverityHits,
		// which DID still count results[].findings[], so this case is
		// effectively a no-op for correctness — but explicit > implicit
		// keeps the dashboard counts pinned to the module's exact shape
		// even if the generic fallback ever changes.
		var r struct {
			Results []struct {
				Findings []struct {
					Severity string `json:"severity"`
				} `json:"findings"`
			} `json:"results"`
		}
		if json.Unmarshal([]byte(resultJSON), &r) != nil {
			return 0
		}
		n := 0
		for _, tr := range r.Results {
			for _, f := range tr.Findings {
				if severe(f.Severity) {
					n++
				}
			}
		}
		return n
	}
	// Audit S8: every new module that emits {results[].findings[].severity}
	// previously had to be hand-added to this switch — 18 modules silently
	// skipped Dashboard severity counts. Generic fallback walks the same
	// shape any module-shaped scan result would have, so adpentest,
	// takeover, openredirect, graphqlscan, corsscan, authtest, sstiscan,
	// cachepoison, assetdisc, advancedweb, oob, concurtest, leakscan,
	// paramdisc, jwt, snmpenum, whoisinfo, emailharvest, direnum,
	// dnsenum, spider, takeover etc. all start counting without code edits.
	return genericSeverityHits(resultJSON, severe)
}

// genericSeverityHits unmarshals against the shape every scaNNer module
// converged on for its result JSON, in three variants — top-level findings,
// nested under results[], or nested under a single 'result' object.
// Whichever shape matches contributes; the others quietly return 0.
func genericSeverityHits(resultJSON string, severe func(string) bool) int {
	type finding struct {
		Severity string `json:"severity"`
	}
	count := func(fs []finding) int {
		n := 0
		for _, f := range fs {
			if severe(f.Severity) {
				n++
			}
		}
		return n
	}
	// Shape A: top-level {findings: [...]}
	var topLevel struct {
		Findings []finding `json:"findings"`
	}
	if json.Unmarshal([]byte(resultJSON), &topLevel) == nil && len(topLevel.Findings) > 0 {
		return count(topLevel.Findings)
	}
	// Shape B: {results: [{findings: [...]}, ...]}
	var nested struct {
		Results []struct {
			Findings []finding `json:"findings"`
		} `json:"results"`
	}
	if json.Unmarshal([]byte(resultJSON), &nested) == nil {
		n := 0
		for _, r := range nested.Results {
			n += count(r.Findings)
		}
		if n > 0 {
			return n
		}
	}
	// Shape C: bare array of {findings: [...]} (sslscan style — already handled
	// above but if a module emits this without its case, catch it here).
	var bare []struct {
		Findings []finding `json:"findings"`
	}
	if json.Unmarshal([]byte(resultJSON), &bare) == nil {
		n := 0
		for _, h := range bare {
			n += count(h.Findings)
		}
		if n > 0 {
			return n
		}
	}
	return 0
}

// OpenConnections returns the number of distinct open ports in a single
// network-scan's result. Used by the dashboard's Network Connections chart.
// Only hostdiscovery + portservice produce port data; everything else is 0.
func OpenConnections(module, resultJSON string) int {
	if resultJSON == "" || resultJSON == "{}" {
		return 0
	}
	if module != "hostdiscovery" && module != "portservice" {
		return 0
	}
	var r struct {
		Results []struct {
			OpenCount         int  `json:"open_count"`
			SuspectedFirewall bool `json:"suspected_firewall"`
		} `json:"results"`
	}
	if json.Unmarshal([]byte(resultJSON), &r) != nil {
		return 0
	}
	total := 0
	for _, tr := range r.Results {
		if tr.SuspectedFirewall {
			continue
		}
		total += tr.OpenCount
	}
	return total
}
