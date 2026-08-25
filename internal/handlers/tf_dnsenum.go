package handlers

import (
	"encoding/json"
	"fmt"
	"strings"
	"time"
)

// tf_dnsenum.go — per-target finding parser for the "dnsenum" module.
//
// Result shape (module ScanResult):
//
//	{"results":[{
//	   domain,
//	   nameservers[],
//	   subdomains:[{subdomain, ips[], source, is_wild}],
//	   total_found,
//	   reverse_dns:[{ip, hostname}],
//	   axfr_records:[{ns, name, type, value}],
//	   crtsh_certs:[{name_value, issuer, not_before, not_after}],
//	   error
//	}]}
//
// Host key: results[].domain (normalizeAsset). A result matches the target when
// its domain normalizes to the target key.
//
// Category mapping:
//
//	subdomains[].subdomain        -> CatSubdomains  (recon, SevRank -1, cap 150)
//	nameservers[]                 -> CatEmailRecon  (recon, SevRank -1)
//	reverse_dns[]                 -> CatEmailRecon  (recon, SevRank -1)
//	axfr_records (if non-empty)   -> CatHeaders     "Zone transfer (AXFR) allowed" MEDIUM SevRank 2
//	crtsh_certs[]                 -> CatTLS         (recon, SevRank -1)
//
// scanID is part of the signature but ignored here — the engine links findings.
func parseDNSEnumTarget(resJSON, target string, scanDate time.Time, scanID string, emit func(targetRaw, time.Time)) {
	if target == "" {
		return
	}

	var res struct {
		Results []struct {
			Domain      string   `json:"domain"`
			Nameservers []string `json:"nameservers"`
			Subdomains  []struct {
				Subdomain string   `json:"subdomain"`
				IPs       []string `json:"ips,omitempty"`
				Source    string   `json:"source"`
				IsWild    bool     `json:"is_wild,omitempty"`
			} `json:"subdomains"`
			TotalFound  int `json:"total_found"`
			AXFRRecords []struct {
				NS    string `json:"ns"`
				Name  string `json:"name"`
				Type  string `json:"type"`
				Value string `json:"value"`
			} `json:"axfr_records,omitempty"`
			ReverseDNS []struct {
				IP       string `json:"ip"`
				Hostname string `json:"hostname"`
			} `json:"reverse_dns,omitempty"`
			CrtShCerts []struct {
				NameValue string `json:"name_value"`
				Issuer    string `json:"issuer,omitempty"`
				NotBefore string `json:"not_before,omitempty"`
				NotAfter  string `json:"not_after,omitempty"`
			} `json:"crtsh_certs,omitempty"`
			Error string `json:"error,omitempty"`
		} `json:"results"`
	}
	if err := json.Unmarshal([]byte(resJSON), &res); err != nil {
		return
	}

	push := func(cat, title, detail, locus, severity string, sevRank int) {
		title = strings.TrimSpace(title)
		if title == "" {
			return
		}
		emit(targetRaw{
			Module:   "dnsenum",
			Category: cat,
			Title:    title,
			Detail:   detail,
			Locus:    locus,
			Severity: severity,
			SevRank:  sevRank,
		}, scanDate)
	}

	for _, r := range res.Results {
		if normalizeAsset(r.Domain) != target {
			continue
		}
		domain := strings.TrimSpace(r.Domain)

		// Nameservers -> CatEmailRecon (recon fact).
		for _, ns := range r.Nameservers {
			push(CatEmailRecon, "Nameserver: "+strings.TrimSpace(ns), "", domain, "", -1)
		}

		// Subdomains -> CatSubdomains (recon fact), capped at 150.
		const maxSubs = 150
		for i, s := range r.Subdomains {
			if i >= maxSubs {
				break
			}
			sub := strings.TrimSpace(s.Subdomain)
			if sub == "" {
				continue
			}
			var parts []string
			if len(s.IPs) > 0 {
				parts = append(parts, "ips: "+strings.Join(s.IPs, ", "))
			}
			if src := strings.TrimSpace(s.Source); src != "" {
				parts = append(parts, "source: "+src)
			}
			if s.IsWild {
				parts = append(parts, "wildcard")
			}
			push(CatSubdomains, sub, strings.Join(parts, " | "), sub, "", -1)
		}

		// Reverse DNS -> CatEmailRecon (recon fact).
		for _, p := range r.ReverseDNS {
			host := strings.TrimSpace(p.Hostname)
			if host == "" {
				continue
			}
			ip := strings.TrimSpace(p.IP)
			push(CatEmailRecon, host, "PTR for "+ip, ip, "", -1)
		}

		// AXFR records (if any) -> single CatHeaders MEDIUM finding.
		if len(r.AXFRRecords) > 0 {
			nsSet := []string{}
			for _, a := range r.AXFRRecords {
				if ns := strings.TrimSpace(a.NS); ns != "" {
					nsSet = appendUnique(nsSet, ns)
				}
			}
			detail := fmt.Sprintf("%d record(s) exposed via zone transfer", len(r.AXFRRecords))
			if len(nsSet) > 0 {
				detail += " from " + strings.Join(nsSet, ", ")
			}
			push(CatHeaders, "Zone transfer (AXFR) allowed", detail, domain, "MEDIUM", 2)
		}

		// crt.sh certificates -> CatTLS (recon fact).
		for _, c := range r.CrtShCerts {
			name := strings.TrimSpace(c.NameValue)
			if name == "" {
				continue
			}
			var parts []string
			if iss := strings.TrimSpace(c.Issuer); iss != "" {
				parts = append(parts, "issuer: "+iss)
			}
			if nb := strings.TrimSpace(c.NotBefore); nb != "" {
				parts = append(parts, "not_before: "+nb)
			}
			if na := strings.TrimSpace(c.NotAfter); na != "" {
				parts = append(parts, "not_after: "+na)
			}
			push(CatTLS, name, strings.Join(parts, " | "), domain, "", -1)
		}
	}
}
