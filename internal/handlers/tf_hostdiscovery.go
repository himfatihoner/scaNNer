package handlers

import (
	"encoding/json"
	"fmt"
	"strings"
	"time"
)

// tf_hostdiscovery.go — per-target finding parser for the "hostdiscovery" module.
//
// Result shape (module ScanResult):
//
//	{"results":[{target,ip,host,host_up,ping_reachable,icmp_filtered,
//	             ping_reason,suspected_firewall,firewalled_count,
//	             ports:[{port,protocol,state,service}],open_count,error}]}
//
// A result row matches the target when its target / ip / host normalizes to the
// (already-normalized) target key.
//
// Category mapping (all hostdiscovery findings are recon facts — SevRank -1,
// Severity ""):
//
//	host_up / icmp_filtered / suspected_firewall / error -> CatHostStatus
//	ports[] (state == "open")                            -> CatPorts    (Title "<port>/<proto> <service>")
//	ports[].service                                      -> CatServices (Title service, locus ip:port)
func parseHostDiscoveryTarget(resJSON, target string, scanDate time.Time, scanID string, emit func(targetRaw, time.Time)) {
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
			PingReason        string `json:"ping_reason,omitempty"`
			HostUp            bool   `json:"host_up"`
			IcmpFiltered      bool   `json:"icmp_filtered,omitempty"`
			SuspectedFirewall bool   `json:"suspected_firewall,omitempty"`
			FirewalledCount   int    `json:"firewalled_count,omitempty"`
			Ports             []struct {
				Port     int    `json:"port"`
				Protocol string `json:"protocol"`
				State    string `json:"state"`
				Service  string `json:"service,omitempty"`
			} `json:"ports"`
			OpenCount int    `json:"open_count"`
			Error     string `json:"error,omitempty"`
		} `json:"results"`
	}
	if err := json.Unmarshal([]byte(resJSON), &res); err != nil {
		return
	}

	const maxPorts = 500

	push := func(cat, title, detail, locus string, when time.Time) {
		title = strings.TrimSpace(title)
		if title == "" {
			return
		}
		emit(targetRaw{
			Module:   "hostdiscovery",
			Category: cat,
			Title:    title,
			Detail:   detail,
			Locus:    locus,
			Severity: "",
			SevRank:  -1,
		}, when)
	}

	for _, r := range res.Results {
		if normalizeAsset(r.Target) != target &&
			normalizeAsset(r.IP) != target &&
			normalizeAsset(r.Host) != target {
			continue
		}

		// Locus: prefer IP, then host, then the row's target label.
		locus := strings.TrimSpace(r.IP)
		if locus == "" {
			locus = strings.TrimSpace(r.Host)
		}
		if locus == "" {
			locus = strings.TrimSpace(r.Target)
		}

		// --- Host status facts ---
		if r.HostUp {
			detail := ""
			if reason := strings.TrimSpace(r.PingReason); reason != "" {
				detail = "reason: " + reason
			}
			if r.PingReachable {
				push(CatHostStatus, "Host up (ping)", detail, locus, scanDate)
			} else {
				push(CatHostStatus, "Host up", detail, locus, scanDate)
			}
		}
		if r.IcmpFiltered {
			push(CatHostStatus, "ICMP filtered (up via -Pn)", "responded to port probe but not to ping", locus, scanDate)
		}
		if r.SuspectedFirewall {
			detail := "nmap reported an implausible number of open ports; likely a stateful firewall reflecting probes"
			if r.FirewalledCount > 0 {
				detail = fmt.Sprintf("%d reflected ports; %s", r.FirewalledCount, detail)
			}
			push(CatHostStatus, "Suspected firewall", detail, locus, scanDate)
		}
		if e := strings.TrimSpace(r.Error); e != "" {
			push(CatHostStatus, "Error: "+e, "", locus, scanDate)
		}

		// --- Ports & services ---
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

			title := fmt.Sprintf("%d/%s", p.Port, proto)
			if svc != "" {
				title += " " + svc
			}
			push(CatPorts, title, "", locus, scanDate)

			if svc != "" {
				svcLocus := fmt.Sprintf("%s:%d", locus, p.Port)
				push(CatServices, svc, "", svcLocus, scanDate)
			}
		}
	}
}
