package handlers

import (
	"encoding/json"
	"fmt"
	"strings"
	"time"
)

// tf_assetdisc.go — per-target finding parser for the "assetdisc" module.
//
// Result shape (module ScanResult): {"queries":[{"assets":[...]}]}. Each asset
// is an external-intel host record (Shodan / Censys) carrying ip / port /
// hostname / product / banner / asn / org / country / domains and a per-item
// `discovered` timestamp. An asset matches the target when its ip, hostname, or
// any of its domains normalize to the target key.
//
// Category mapping (all assetdisc findings are recon facts — SevRank -1):
//
//	port           -> CatPorts     (locus = ip)
//	product/banner -> CatServices  (locus = ip[:port])
//	hostname/domain-> CatSubdomains
//	asn/org/country-> CatWhois
//
// Timestamp: the per-asset `discovered` (RFC3339, unmarshalled into time.Time)
// is preferred when non-zero; otherwise scanDate is used.
func parseAssetDiscTarget(resJSON, target string, scanDate time.Time, scanID string, emit func(targetRaw, time.Time)) {
	if target == "" {
		return
	}

	var res struct {
		Queries []struct {
			Assets []struct {
				IP         string    `json:"ip"`
				Port       int       `json:"port,omitempty"`
				Hostname   string    `json:"hostname,omitempty"`
				OS         string    `json:"os,omitempty"`
				ASN        string    `json:"asn,omitempty"`
				Org        string    `json:"org,omitempty"`
				Country    string    `json:"country,omitempty"`
				Product    string    `json:"product,omitempty"`
				Banner     string    `json:"banner,omitempty"`
				Domains    []string  `json:"domains,omitempty"`
				Discovered time.Time `json:"discovered"`
			} `json:"assets"`
		} `json:"queries"`
	}
	if err := json.Unmarshal([]byte(resJSON), &res); err != nil {
		return
	}

	const maxEmit = 2000
	emitted := 0
	// Local dedup so repeated Censys service rows for the same host don't emit
	// the same subdomain / whois fact hundreds of times (the engine dedups too,
	// but this bounds work and honours the per-list cap).
	seen := map[string]bool{}

	push := func(cat, title, detail, locus string, when time.Time) {
		title = strings.TrimSpace(title)
		if title == "" || emitted >= maxEmit {
			return
		}
		k := cat + "|" + title + "|" + locus
		if seen[k] {
			return
		}
		seen[k] = true
		emitted++
		emit(targetRaw{
			Module:   "assetdisc",
			Category: cat,
			Title:    title,
			Detail:   detail,
			Locus:    locus,
			Severity: "",
			SevRank:  -1,
		}, when)
	}

	for _, q := range res.Queries {
		for _, a := range q.Assets {
			// Match this asset to the target on ip / hostname / any domain.
			matched := normalizeAsset(a.IP) == target || normalizeAsset(a.Hostname) == target
			if !matched {
				for _, d := range a.Domains {
					if normalizeAsset(d) == target {
						matched = true
						break
					}
				}
			}
			if !matched {
				continue
			}

			when := scanDate
			if !a.Discovered.IsZero() {
				when = a.Discovered
			}
			ip := strings.TrimSpace(a.IP)

			// Ports — locus is the IP.
			if a.Port != 0 {
				push(CatPorts, fmt.Sprintf("%d/tcp", a.Port), "", ip, when)
			}

			// Services — product, falling back to banner.
			svc := strings.TrimSpace(a.Product)
			if svc == "" {
				svc = strings.TrimSpace(a.Banner)
			}
			if svc != "" {
				locus := ip
				if a.Port != 0 {
					locus = fmt.Sprintf("%s:%d", ip, a.Port)
				}
				detail := ""
				if b := strings.TrimSpace(a.Banner); b != "" && b != svc {
					detail = b
				}
				push(CatServices, svc, detail, locus, when)
			}

			// Subdomains — hostname + domains.
			push(CatSubdomains, a.Hostname, "", ip, when)
			for _, d := range a.Domains {
				push(CatSubdomains, d, "", ip, when)
			}

			// WHOIS / ASN — asn / org / country.
			if s := strings.TrimSpace(a.ASN); s != "" {
				push(CatWhois, "ASN: "+s, "", ip, when)
			}
			if s := strings.TrimSpace(a.Org); s != "" {
				push(CatWhois, "Org: "+s, "", ip, when)
			}
			if s := strings.TrimSpace(a.Country); s != "" {
				push(CatWhois, "Country: "+s, "", ip, when)
			}
		}
	}
}
