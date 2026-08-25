package handlers

import (
	"encoding/json"
	"strings"
	"time"
)

// tf_whoisinfo.go — per-target finding parser for the "whoisinfo" module.
//
// Result shape (module ScanResult):
//
//	{"results":[{
//	   target,
//	   kind,                          // "domain" | "ip"
//	   resolved_ips[],
//	   whois_records:[{field, value}],
//	   whois_raw,
//	   asn:{asn, organization, country_code, registry, prefixes[]},
//	   error
//	}]}
//
// NOTE: the whois_records elements use json tags "field"/"value" (not
// "key"/"value") — verified against internal/modules/whoisinfo/scanner.go.
//
// Host key: results[].target (normalizeAsset). A result matches the target when
// its target normalizes to the target key.
//
// Category mapping:
//
//	whois_records[] (registrar/dates/nameservers) -> CatWhois     Title="field: value"
//	whois_records[] with email-looking value      -> CatEmailRecon Title="field: value"
//	asn.asn / asn.organization                    -> CatWhois     Title="ASN <asn> <org>"
//
// All entries are recon facts: Severity "" and SevRank -1. whois_records capped at 40.
//
// scanID is part of the signature but ignored here — the engine links findings.
func parseWhoisTarget(resJSON, target string, scanDate time.Time, scanID string, emit func(targetRaw, time.Time)) {
	if target == "" {
		return
	}

	var res struct {
		Results []struct {
			Target       string `json:"target"`
			Kind         string `json:"kind"`
			WHOISRecords []struct {
				Field string `json:"field"`
				Value string `json:"value"`
			} `json:"whois_records"`
			ASN *struct {
				ASN          string `json:"asn"`
				Organization string `json:"organization,omitempty"`
				CountryCode  string `json:"country_code,omitempty"`
				Registry     string `json:"registry,omitempty"`
			} `json:"asn,omitempty"`
			Error string `json:"error,omitempty"`
		} `json:"results"`
	}
	if err := json.Unmarshal([]byte(resJSON), &res); err != nil {
		return
	}

	// looksLikeEmail reports whether v is a plausible email address:
	// one '@' with non-empty local + dotted domain, and no whitespace.
	looksLikeEmail := func(v string) bool {
		at := strings.IndexByte(v, '@')
		if at <= 0 || at >= len(v)-1 {
			return false
		}
		if strings.ContainsAny(v, " \t\r\n") {
			return false
		}
		if strings.IndexByte(v, '@') != strings.LastIndexByte(v, '@') {
			return false
		}
		return strings.Contains(v[at+1:], ".")
	}

	push := func(cat, title, detail, locus string) {
		title = strings.TrimSpace(title)
		if title == "" {
			return
		}
		emit(targetRaw{
			Module:   "whoisinfo",
			Category: cat,
			Title:    title,
			Detail:   detail,
			Locus:    locus,
			Severity: "",
			SevRank:  -1,
		}, scanDate)
	}

	for _, r := range res.Results {
		if normalizeAsset(r.Target) != target {
			continue
		}
		locus := strings.TrimSpace(r.Target)

		// whois records -> CatWhois, or CatEmailRecon when the value is an email.
		const maxRecords = 40
		for i, rec := range r.WHOISRecords {
			if i >= maxRecords {
				break
			}
			field := strings.TrimSpace(rec.Field)
			value := strings.TrimSpace(rec.Value)
			if field == "" || value == "" {
				continue
			}
			cat := CatWhois
			if looksLikeEmail(value) {
				cat = CatEmailRecon
			}
			push(cat, field+": "+value, "", locus)
		}

		// ASN -> CatWhois.
		if r.ASN != nil {
			asn := strings.TrimSpace(r.ASN.ASN)
			org := strings.TrimSpace(r.ASN.Organization)
			if asn != "" || org != "" {
				title := "ASN"
				if asn != "" {
					title += " " + asn
				}
				if org != "" {
					title += " " + org
				}
				var parts []string
				if cc := strings.TrimSpace(r.ASN.CountryCode); cc != "" {
					parts = append(parts, "country: "+cc)
				}
				if reg := strings.TrimSpace(r.ASN.Registry); reg != "" {
					parts = append(parts, "registry: "+reg)
				}
				push(CatWhois, title, strings.Join(parts, " | "), locus)
			}
		}
	}
}
