package handlers

import (
	"encoding/json"
	"fmt"
	"strings"
	"time"
)

// tf_portservice.go — per-target finding parser for the "portservice" module.
//
// Result shape (module ScanResult, verbatim json tags from
// internal/modules/portservice/scanner.go):
//
//	{"results":[{target,ip,host,host_up,ping_reachable,icmp_filtered,
//	             suspected_firewall,firewalled_count,error,open_count,
//	             ports:[{port,protocol,state,service,product,version,
//	                     extra_info,tunnel,banner,
//	                     scripts:[{id,output}],
//	                     http_resp:{status,server}}]}]}
//
// A result row matches the target when its target / ip / host normalizes to the
// (already-normalized) target key.
//
// Category mapping:
//
//	host_up / icmp_filtered / suspected_firewall / error -> CatHostStatus (recon)
//	ports[] (state == "open")                            -> CatPorts     (recon, Title "<port>/<proto> <service>")
//	product / version / banner                           -> CatServices  (recon)
//	ports[].tunnel (ssl/tls)                             -> CatTLS       (recon)
//	ports[].scripts[] (id~"vuln" && output~"vulnerable") -> CatVuln HIGH SevRank 3 (Title "NSE <id>", Detail output)
//	http_resp.server                                     -> CatTech      (recon)
func parsePortServiceTarget(resJSON, target string, scanDate time.Time, scanID string, emit func(targetRaw, time.Time)) {
	_ = scanID // engine owns the scan link; parser ignores it

	if target == "" {
		return
	}

	var res struct {
		Results []struct {
			Target            string `json:"target"`
			IP                string `json:"ip,omitempty"`
			Host              string `json:"host,omitempty"`
			PingReachable     bool   `json:"ping_reachable"`
			HostUp            bool   `json:"host_up"`
			IcmpFiltered      bool   `json:"icmp_filtered,omitempty"`
			SuspectedFirewall bool   `json:"suspected_firewall,omitempty"`
			FirewalledCount   int    `json:"firewalled_count,omitempty"`
			OpenCount         int    `json:"open_count"`
			Error             string `json:"error,omitempty"`
			NucleiFindings    []struct {
				TemplateID  string `json:"template_id"`
				Name        string `json:"name"`
				Severity    string `json:"severity"`
				Host        string `json:"host"`
				MatchedAt   string `json:"matched_at"`
				Description string `json:"description,omitempty"`
			} `json:"nuclei_findings,omitempty"`
			Ports []struct {
				Port      int    `json:"port"`
				Protocol  string `json:"protocol"`
				State     string `json:"state"`
				Service   string `json:"service,omitempty"`
				Product   string `json:"product,omitempty"`
				Version   string `json:"version,omitempty"`
				ExtraInfo string `json:"extra_info,omitempty"`
				Tunnel    string `json:"tunnel,omitempty"`
				Banner    string `json:"banner,omitempty"`
				Scripts   []struct {
					ID     string `json:"id"`
					Output string `json:"output"`
				} `json:"scripts,omitempty"`
				HTTPResp *struct {
					Status int    `json:"status"`
					Server string `json:"server,omitempty"`
				} `json:"http_resp,omitempty"`
			} `json:"ports"`
		} `json:"results"`
	}
	if err := json.Unmarshal([]byte(resJSON), &res); err != nil {
		return
	}

	const maxPorts = 500

	// recon fact — SevRank -1, no severity.
	fact := func(cat, title, detail, locus string) {
		title = strings.TrimSpace(title)
		if title == "" {
			return
		}
		emit(targetRaw{
			Module:   "portservice",
			Category: cat,
			Title:    title,
			Detail:   detail,
			Locus:    locus,
			Severity: "",
			SevRank:  -1,
		}, scanDate)
	}

	// vuln finding — severity HIGH, ranked via severityRank.
	vuln := func(title, detail, locus string) {
		title = strings.TrimSpace(title)
		if title == "" {
			return
		}
		sev := "HIGH"
		emit(targetRaw{
			Module:   "portservice",
			Category: CatVuln,
			Title:    title,
			Detail:   detail,
			Locus:    locus,
			Severity: sev,
			SevRank:  severityRank(sev),
		}, scanDate)
	}

	for _, r := range res.Results {
		if normalizeAsset(r.Target) != target &&
			normalizeAsset(r.IP) != target &&
			normalizeAsset(r.Host) != target {
			continue
		}

		// Base locus: prefer IP, then host, then the row's target label.
		base := strings.TrimSpace(r.IP)
		if base == "" {
			base = strings.TrimSpace(r.Host)
		}
		if base == "" {
			base = strings.TrimSpace(r.Target)
		}

		// --- Host status facts ---
		if r.HostUp {
			if r.PingReachable {
				fact(CatHostStatus, "Host up (ping)", "", base)
			} else {
				fact(CatHostStatus, "Host up", "", base)
			}
		}
		if r.IcmpFiltered {
			fact(CatHostStatus, "ICMP filtered (up via -Pn)", "responded to port probe but not to ping", base)
		}
		if r.SuspectedFirewall {
			detail := "nmap reported an implausible number of open ports; likely a stateful firewall reflecting probes"
			if r.FirewalledCount > 0 {
				detail = fmt.Sprintf("%d reflected ports; %s", r.FirewalledCount, detail)
			}
			fact(CatHostStatus, "Suspected firewall", detail, base)
		}
		if e := strings.TrimSpace(r.Error); e != "" {
			fact(CatHostStatus, "Error: "+e, "", base)
		}

		// --- Nuclei findings (optional post-nmap web pass) — real severities ---
		for _, nf := range r.NucleiFindings {
			title := strings.TrimSpace(nf.Name)
			if title == "" {
				title = strings.TrimSpace(nf.TemplateID)
			}
			if title == "" {
				continue
			}
			sev := strings.ToUpper(strings.TrimSpace(nf.Severity))
			locus := strings.TrimSpace(nf.MatchedAt)
			if locus == "" {
				locus = strings.TrimSpace(nf.Host)
			}
			emit(targetRaw{
				Module:   "portservice",
				Category: CatVuln,
				Title:    title,
				Detail:   strings.TrimSpace(nf.Description),
				Locus:    locus,
				Severity: sev,
				SevRank:  severityRank(sev),
			}, scanDate)
		}

		// --- Ports, services, TLS, vuln scripts, tech ---
		n := 0
		for _, p := range r.Ports {
			if !strings.EqualFold(p.State, "open") {
				continue
			}
			if n >= maxPorts {
				break
			}
			n++

			proto := strings.TrimSpace(p.Protocol)
			if proto == "" {
				proto = "tcp"
			}
			svc := strings.TrimSpace(p.Service)
			portLocus := fmt.Sprintf("%s:%d", base, p.Port)

			// Open port fact.
			title := fmt.Sprintf("%d/%s", p.Port, proto)
			if svc != "" {
				title += " " + svc
			}
			fact(CatPorts, title, "", portLocus)

			// Service detail (product / version / banner).
			product := strings.TrimSpace(p.Product)
			version := strings.TrimSpace(p.Version)
			extra := strings.TrimSpace(p.ExtraInfo)
			banner := strings.TrimSpace(p.Banner)
			if product != "" || version != "" || banner != "" {
				svcTitle := strings.TrimSpace(product + " " + version)
				if svcTitle == "" {
					svcTitle = svc
				}
				if svcTitle == "" {
					svcTitle = "Service banner"
				}
				var detailParts []string
				if extra != "" {
					detailParts = append(detailParts, extra)
				}
				if banner != "" {
					detailParts = append(detailParts, banner)
				}
				fact(CatServices, svcTitle, strings.Join(detailParts, " · "), portLocus)
			}

			// TLS/SSL tunnel.
			if tun := strings.ToLower(strings.TrimSpace(p.Tunnel)); tun == "ssl" || tun == "tls" {
				fact(CatTLS, fmt.Sprintf("TLS/SSL on %d/%s", p.Port, proto), "tunnel: "+tun, portLocus)
			}

			// NSE vuln scripts.
			for _, s := range p.Scripts {
				id := strings.TrimSpace(s.ID)
				if id == "" || !strings.Contains(strings.ToLower(id), "vuln") {
					continue
				}
				if !strings.Contains(strings.ToLower(s.Output), "vulnerable") {
					continue
				}
				vuln("NSE "+id, strings.TrimSpace(s.Output), portLocus)
			}

			// HTTP server banner -> tech.
			if p.HTTPResp != nil {
				if server := strings.TrimSpace(p.HTTPResp.Server); server != "" {
					fact(CatTech, "Server: "+server, "", portLocus)
				}
			}
		}
	}
}
