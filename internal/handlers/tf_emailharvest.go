package handlers

import (
	"encoding/json"
	"fmt"
	"strings"
	"time"
)

// tf_emailharvest.go — per-target finding parser for the "emailharvest" module.
//
// Result shape (from internal/modules/emailharvest/scanner.go —
// ScanResult/DomainResult/DNSAuthInfo/MXRecord/DKIMRecord/BreachInfo):
//
//	{"results":[{
//	    "domain":"example.com",
//	    "emails":["a@example.com"],
//	    "hosts":["mail.example.com"],
//	    "ips":["1.2.3.4"],
//	    "dns_auth":{
//	        "mx":[{"host":"mx1.example.com"}],
//	        "spf_finding":"missing — domain accepts mail from anyone",
//	        "dmarc_finding":"p=none — monitoring only, no enforcement",
//	        "dkim_selectors":[{"selector":"default"}],
//	        "mail_provider":"Google Workspace"
//	    },
//	    "breaches":[{"name":"Adobe","title":"Adobe","breach_date":"2013-10-04",
//	                 "pwn_count":152445165,"data_classes":["Email addresses"]}],
//	    "error":""
//	}]}
//
// Host key is results[].domain (normalizeAsset). Each result entry belongs to a
// single domain, so we filter on that.
//
// Category mapping:
//   - emails[]                    -> CatEmailRecon (recon fact, SevRank -1)
//   - hosts[]                     -> CatSubdomains (recon fact, SevRank -1)
//   - breaches[]                  -> CatCreds      (HIGH, SevRank 3)
//   - dns_auth.spf_finding  (weak)-> CatHeaders    (MEDIUM, SevRank 2)
//   - dns_auth.dmarc_finding(weak)-> CatHeaders    (MEDIUM, SevRank 2)
//   - dns_auth.mail_provider      -> CatTech       (recon fact, SevRank -1)

// Per-list caps so a pathological harvest can't spawn thousands of rows.
const (
	maxEmailHarvestEmails   = 500
	maxEmailHarvestHosts    = 500
	maxEmailHarvestBreaches = 200
)

func parseEmailHarvestTarget(resJSON, target string, scanDate time.Time, scanID string, emit func(targetRaw, time.Time)) {
	_ = scanID // engine owns the scan link; parser ignores scanID by contract.

	var res struct {
		Results []struct {
			Domain  string   `json:"domain"`
			Emails  []string `json:"emails"`
			Hosts   []string `json:"hosts"`
			IPs     []string `json:"ips"`
			Error   string   `json:"error"`
			DNSAuth *struct {
				MX []struct {
					Host string `json:"host"`
				} `json:"mx"`
				SPFFinding    string `json:"spf_finding"`
				DMARCFinding  string `json:"dmarc_finding"`
				DKIMSelectors []struct {
					Selector string `json:"selector"`
				} `json:"dkim_selectors"`
				MailProvider string `json:"mail_provider"`
			} `json:"dns_auth"`
			Breaches []struct {
				Name        string   `json:"name"`
				Title       string   `json:"title"`
				BreachDate  string   `json:"breach_date"`
				PwnCount    int      `json:"pwn_count"`
				DataClasses []string `json:"data_classes"`
			} `json:"breaches"`
		} `json:"results"`
	}
	if err := json.Unmarshal([]byte(resJSON), &res); err != nil {
		return
	}

	for _, dr := range res.Results {
		if normalizeAsset(dr.Domain) != target {
			continue
		}
		domain := strings.TrimSpace(dr.Domain)

		// Emails — recon facts.
		for i, e := range dr.Emails {
			if i >= maxEmailHarvestEmails {
				break
			}
			e = strings.TrimSpace(e)
			if e == "" {
				continue
			}
			emit(targetRaw{
				Module:   "emailharvest",
				Category: CatEmailRecon,
				Title:    e,
				Locus:    domain,
				Severity: "",
				SevRank:  -1,
			}, scanDate)
		}

		// Hosts — subdomains, recon facts.
		for i, h := range dr.Hosts {
			if i >= maxEmailHarvestHosts {
				break
			}
			h = strings.TrimSpace(h)
			if h == "" {
				continue
			}
			emit(targetRaw{
				Module:   "emailharvest",
				Category: CatSubdomains,
				Title:    h,
				Locus:    domain,
				Severity: "",
				SevRank:  -1,
			}, scanDate)
		}

		// Breaches — one HIGH credential-exposure finding each.
		for i, b := range dr.Breaches {
			if i >= maxEmailHarvestBreaches {
				break
			}
			name := strings.TrimSpace(b.Title)
			if name == "" {
				name = strings.TrimSpace(b.Name)
			}
			if name == "" {
				continue
			}
			detail := "Domain appears in a known breach (Have I Been Pwned)"
			var parts []string
			if d := strings.TrimSpace(b.BreachDate); d != "" {
				parts = append(parts, "breached "+d)
			}
			if b.PwnCount > 0 {
				parts = append(parts, fmt.Sprintf("%d accounts", b.PwnCount))
			}
			if len(b.DataClasses) > 0 {
				parts = append(parts, "exposed: "+strings.Join(b.DataClasses, ", "))
			}
			if len(parts) > 0 {
				detail += " — " + strings.Join(parts, "; ")
			}
			emit(targetRaw{
				Module:   "emailharvest",
				Category: CatCreds,
				Title:    "Breach: " + name,
				Detail:   detail,
				Locus:    domain,
				Severity: "HIGH",
				SevRank:  severityRank("HIGH"),
			}, scanDate)
		}

		// DNS email-authentication weaknesses + mail provider.
		if dr.DNSAuth != nil {
			if f := strings.TrimSpace(dr.DNSAuth.SPFFinding); isEmailAuthWeak(f) {
				emit(targetRaw{
					Module:   "emailharvest",
					Category: CatHeaders,
					Title:    "Weak SPF policy",
					Detail:   "SPF: " + f,
					Locus:    domain,
					Severity: "MEDIUM",
					SevRank:  severityRank("MEDIUM"),
				}, scanDate)
			}
			if f := strings.TrimSpace(dr.DNSAuth.DMARCFinding); isEmailAuthWeak(f) {
				emit(targetRaw{
					Module:   "emailharvest",
					Category: CatHeaders,
					Title:    "Weak DMARC policy",
					Detail:   "DMARC: " + f,
					Locus:    domain,
					Severity: "MEDIUM",
					SevRank:  severityRank("MEDIUM"),
				}, scanDate)
			}
			if p := strings.TrimSpace(dr.DNSAuth.MailProvider); p != "" {
				emit(targetRaw{
					Module:   "emailharvest",
					Category: CatTech,
					Title:    "Mail provider: " + p,
					Locus:    domain,
					Severity: "",
					SevRank:  -1,
				}, scanDate)
			}
		}
	}
}

// isEmailAuthWeak reports whether an SPF/DMARC finding string describes a weak
// or missing policy. The scanner tags strict, recommended postures (SPF "-all"
// hard fail, DMARC "p=reject") with the word "recommended"; every other finding
// — missing, soft-fail, neutral, permissive, quarantine, unparseable — is a
// weakness worth a MEDIUM heads-up.
func isEmailAuthWeak(finding string) bool {
	if finding == "" {
		return false
	}
	return !strings.Contains(strings.ToLower(finding), "recommended")
}
