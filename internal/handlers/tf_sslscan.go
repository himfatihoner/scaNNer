package handlers

import (
	"encoding/json"
	"fmt"
	"strings"
	"time"
)

// tf_sslscan.go — per-target finding parser for the "sslscan" module.
//
// Result shape (bare array of *sslscan.HostResult, verbatim json tags from
// internal/modules/sslscan/scanner.go — NOT wrapped in {"results":...}):
//
//	[ {host,port,reachable,has_tls,
//	   findings:[{title,severity,description,cves,component}],
//	   protocols:[{name,supported}],
//	   ciphers:[{name}],
//	   cert_info:{subject,issuer,not_before,not_after,sans[]}} ]
//
// A host entry matches when normalizeAsset(host) equals the (already
// normalized) target key.
//
// Category mapping:
//
//	findings[] severity HIGH/CRITICAL          -> CatVuln  (Severity + SevRank)
//	findings[] LOW/MED/INFO                     -> CatTLS   (keeps its severity)
//	protocols[] supported & weak (SSLv2/3,TLS1.0/1.1) -> CatTLS (recon fact)
//	cert_info issuer/expiry                     -> CatTLS   (recon fact,
//	                                              Title "Cert expires <not_after>")
//	cert_info.sans[]                            -> CatSubdomains (recon fact)
//
// scanID is part of the contract but ignored here — the engine wires the link.
func parseSSLScanTarget(resJSON, target string, scanDate time.Time, scanID string, emit func(targetRaw, time.Time)) {
	_ = scanID // engine owns the scan link; parser ignores it

	if target == "" {
		return
	}

	var hosts []struct {
		Host      string `json:"host"`
		Port      int    `json:"port"`
		Reachable bool   `json:"reachable"`
		HasTLS    bool   `json:"has_tls"`
		Findings  []struct {
			Title       string   `json:"title"`
			Severity    string   `json:"severity"`
			Description string   `json:"description"`
			CVEs        []string `json:"cves"`
			Component   string   `json:"component"`
		} `json:"findings"`
		Protocols []struct {
			Name      string `json:"name"`
			Supported bool   `json:"supported"`
		} `json:"protocols"`
		Ciphers []struct {
			Name string `json:"name"`
		} `json:"ciphers"`
		CertInfo *struct {
			Subject     string    `json:"subject"`
			Issuer      string    `json:"issuer"`
			NotBefore   time.Time `json:"not_before"`
			NotAfter    time.Time `json:"not_after"`
			IsExpired   bool      `json:"is_expired"`
			SigAlg      string    `json:"sig_alg"`
			KeySize     int       `json:"key_size"`
			SelfSigned  bool      `json:"self_signed"`
			ChainErr    string    `json:"chain_err"`
			HostnameErr string    `json:"hostname_err"`
			SANs        []string  `json:"sans"`
		} `json:"cert_info"`
	}
	if err := json.Unmarshal([]byte(resJSON), &hosts); err != nil {
		return
	}

	const (
		maxFindings = 200
		maxSANs     = 200
	)
	highRank := severityRank("HIGH")

	// recon fact — SevRank -1, no severity.
	fact := func(cat, title, detail, locus string) {
		title = strings.TrimSpace(title)
		if title == "" {
			return
		}
		emit(targetRaw{
			Module:   "sslscan",
			Category: cat,
			Title:    title,
			Detail:   detail,
			Locus:    locus,
			Severity: "",
			SevRank:  -1,
		}, scanDate)
	}

	for _, h := range hosts {
		if normalizeAsset(h.Host) != target {
			continue
		}

		locus := strings.TrimSpace(h.Host)
		if locus != "" && h.Port > 0 {
			locus = fmt.Sprintf("%s:%d", locus, h.Port)
		}

		// Certificate facts — reused as Evidence for certificate-component
		// CatVuln findings (Expired / Weak Key / Weak Signature / Hostname
		// Mismatch), whose Description is generic advice; the CertInfo carries
		// the concrete proof the finding was derived from.
		certFacts := ""
		if h.CertInfo != nil {
			ci := h.CertInfo
			var cf []string
			if s := strings.TrimSpace(ci.Subject); s != "" {
				cf = append(cf, "Subject: "+s)
			}
			if s := strings.TrimSpace(ci.Issuer); s != "" {
				cf = append(cf, "Issuer: "+s)
			}
			if s := strings.TrimSpace(ci.SigAlg); s != "" {
				cf = append(cf, "SigAlg: "+s)
			}
			if ci.KeySize > 0 {
				cf = append(cf, fmt.Sprintf("Key: %d-bit", ci.KeySize))
			}
			if !ci.NotAfter.IsZero() {
				exp := "NotAfter: " + ci.NotAfter.Format("2006-01-02")
				if ci.IsExpired {
					exp += " (expired)"
				}
				cf = append(cf, exp)
			}
			if ci.SelfSigned {
				cf = append(cf, "self-signed")
			}
			if s := strings.TrimSpace(ci.HostnameErr); s != "" {
				cf = append(cf, "HostnameErr: "+s)
			}
			if s := strings.TrimSpace(ci.ChainErr); s != "" {
				cf = append(cf, "ChainErr: "+s)
			}
			certFacts = strings.Join(cf, " · ")
		}

		// --- Findings: HIGH/CRITICAL -> CatVuln, rest -> CatTLS ---
		emitted := 0
		for _, f := range h.Findings {
			if emitted >= maxFindings {
				break
			}
			title := strings.TrimSpace(f.Title)
			if title == "" {
				continue
			}

			sev := strings.ToUpper(strings.TrimSpace(f.Severity))
			rank := severityRank(sev)

			category := CatTLS
			if rank >= highRank {
				category = CatVuln
			}

			detail := strings.TrimSpace(f.Description)
			var cves []string
			for _, c := range f.CVEs {
				c = strings.TrimSpace(c)
				if c == "" || strings.EqualFold(c, "N/A") {
					continue
				}
				cves = appendUnique(cves, c)
			}
			if len(cves) > 0 {
				detail = strings.TrimSpace(detail + " (" + strings.Join(cves, ", ") + ")")
			}

			raw := targetRaw{
				Module:   "sslscan",
				Category: category,
				Title:    title,
				Detail:   detail,
				Locus:    locus,
				Severity: sev,
				SevRank:  rank,
			}
			// Enrich CatVuln findings with typed fields: pull the CVE ids out
			// of the flattened Detail text into the structured slice, and set
			// Evidence to the concrete proof — cert facts for certificate
			// findings (whose Description is generic), otherwise the matched
			// cipher/protocol Description which names the affected suites.
			if category == CatVuln {
				raw.CVEs = cves
				if f.Component == "certificate" && certFacts != "" {
					raw.Evidence = certFacts
				} else if d := strings.TrimSpace(f.Description); d != "" {
					raw.Evidence = d
				}
			}
			emit(raw, scanDate)
			emitted++
		}

		// --- Protocols: supported & weak -> CatTLS recon fact ---
		for _, p := range h.Protocols {
			if !p.Supported {
				continue
			}
			name := strings.TrimSpace(p.Name)
			switch name {
			case "SSL 2.0", "SSL 3.0", "TLS 1.0", "TLS 1.1":
				fact(CatTLS, name+" supported", "weak/deprecated protocol version negotiated", locus)
			}
		}

		// --- Certificate issuer / expiry -> CatTLS recon fact ---
		if h.CertInfo != nil {
			var certDetail []string
			if iss := strings.TrimSpace(h.CertInfo.Issuer); iss != "" {
				certDetail = append(certDetail, "Issuer: "+iss)
			}
			if subj := strings.TrimSpace(h.CertInfo.Subject); subj != "" {
				certDetail = append(certDetail, "Subject: "+subj)
			}
			if !h.CertInfo.NotAfter.IsZero() {
				fact(CatTLS,
					"Cert expires "+h.CertInfo.NotAfter.Format("2006-01-02"),
					strings.Join(certDetail, " · "),
					locus)
			} else if len(certDetail) > 0 {
				fact(CatTLS, "Certificate", strings.Join(certDetail, " · "), locus)
			}

			// --- SANs -> CatSubdomains recon facts ---
			sansEmitted := 0
			for _, s := range h.CertInfo.SANs {
				if sansEmitted >= maxSANs {
					break
				}
				s = strings.TrimSpace(s)
				if s == "" {
					continue
				}
				fact(CatSubdomains, s, "SAN on certificate for "+locus, locus)
				sansEmitted++
			}
		}
	}
}
