package handlers

import (
	"encoding/json"
	"strings"
	"time"
)

// tf_smbenum.go — per-target finding parser for the "smbenum" module.
//
// Result shape (module ScanResult, tags verified against
// internal/modules/smbenum/scanner.go):
//
//	{"results":[{target,ip,os,domain,workgroup,netbios_name,
//	             shares:[{name,type,comment,access,interesting_hits}],
//	             users[],groups[],sessions[],
//	             nmap_scripts:[{id,output}]}]}
//
// A result row matches the (already-normalized) target when its target / ip
// normalizes to the target key.
//
// Category mapping:
//
//	shares[]                 -> CatSMBAD   (Title "share: <name>", Detail comment+access)
//	users[] / groups[]       -> CatSMBAD
//	os                       -> CatServices
//	shares[].interesting_hits-> CatCreds
//	nmap_scripts[] where id contains "vuln" and output mentions "vulnerable"
//	                         -> CatVuln HIGH (SevRank 3, Title id, Detail output)
func parseSMBEnumTarget(resJSON, target string, scanDate time.Time, scanID string, emit func(targetRaw, time.Time)) {
	_ = scanID // engine owns the scan link; parser ignores it

	if target == "" {
		return
	}

	var res struct {
		Results []struct {
			Target      string `json:"target"`
			IP          string `json:"ip,omitempty"`
			OS          string `json:"os,omitempty"`
			Domain      string `json:"domain,omitempty"`
			Workgroup   string `json:"workgroup,omitempty"`
			NetbiosName string `json:"netbios_name,omitempty"`
			Shares      []struct {
				Name            string   `json:"name"`
				Type            string   `json:"type,omitempty"`
				Comment         string   `json:"comment,omitempty"`
				Access          string   `json:"access,omitempty"`
				InterestingHits []string `json:"interesting_hits,omitempty"`
			} `json:"shares"`
			Users       []string `json:"users"`
			Groups      []string `json:"groups"`
			Sessions    []string `json:"sessions"`
			NmapScripts []struct {
				ID     string `json:"id"`
				Output string `json:"output"`
			} `json:"nmap_scripts"`
		} `json:"results"`
	}
	if err := json.Unmarshal([]byte(resJSON), &res); err != nil {
		return
	}

	const maxItems = 200

	// fact emits a recon/enumeration finding: no severity, SevRank -1.
	fact := func(cat, title, detail, locus string) {
		title = strings.TrimSpace(title)
		if title == "" {
			return
		}
		emit(targetRaw{
			Module:   "smbenum",
			Category: cat,
			Title:    title,
			Detail:   detail,
			Locus:    locus,
			Severity: "",
			SevRank:  -1,
		}, scanDate)
	}

	for _, r := range res.Results {
		if normalizeAsset(r.Target) != target && normalizeAsset(r.IP) != target {
			continue
		}

		// Locus: prefer IP, then the row's target label.
		locus := strings.TrimSpace(r.IP)
		if locus == "" {
			locus = strings.TrimSpace(r.Target)
		}

		// --- OS -> CatServices ---
		if os := strings.TrimSpace(r.OS); os != "" {
			fact(CatServices, os, "", locus)
		}

		// --- Shares -> CatSMBAD; interesting hits -> CatCreds ---
		for i := range r.Shares {
			if i >= maxItems {
				break
			}
			sh := r.Shares[i]
			name := strings.TrimSpace(sh.Name)
			if name == "" {
				continue
			}
			detail := strings.TrimSpace(strings.TrimSpace(sh.Comment) + " " + strings.TrimSpace(sh.Access))
			fact(CatSMBAD, "share: "+name, detail, locus)

			for j, hit := range sh.InterestingHits {
				if j >= maxItems {
					break
				}
				hit = strings.TrimSpace(hit)
				if hit == "" {
					continue
				}
				fact(CatCreds, "Interesting file in "+name+": "+hit, "share: "+name, locus)
			}
		}

		// --- Users -> CatSMBAD ---
		for i, u := range r.Users {
			if i >= maxItems {
				break
			}
			u = strings.TrimSpace(u)
			if u == "" {
				continue
			}
			fact(CatSMBAD, "User: "+u, "", locus)
		}

		// --- Groups -> CatSMBAD ---
		for i, g := range r.Groups {
			if i >= maxItems {
				break
			}
			g = strings.TrimSpace(g)
			if g == "" {
				continue
			}
			fact(CatSMBAD, "Group: "+g, "", locus)
		}

		// --- nmap vuln scripts -> CatVuln HIGH ---
		for _, sc := range r.NmapScripts {
			id := strings.TrimSpace(sc.ID)
			if id == "" {
				continue
			}
			if !strings.Contains(strings.ToLower(id), "vuln") {
				continue
			}
			if !strings.Contains(strings.ToLower(sc.Output), "vulnerable") {
				continue
			}
			sev := "HIGH"
			emit(targetRaw{
				Module:   "smbenum",
				Category: CatVuln,
				Title:    id,
				Detail:   strings.TrimSpace(sc.Output),
				Locus:    locus,
				Severity: sev,
				SevRank:  severityRank(sev),
			}, scanDate)
		}
	}
}
