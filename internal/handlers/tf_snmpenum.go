package handlers

import (
	"encoding/json"
	"fmt"
	"strings"
	"time"
)

// tf_snmpenum.go — per-target finding parser for the "snmpenum" module.
//
// Result shape (verified against internal/modules/snmpenum/scanner.go —
// ScanResult / TargetResult / Walk). NOTE: the walk entry carries an
// "output" string, not a "lines[]" array:
//
//	{"results":[{
//	    "target":"10.0.0.1",
//	    "valid_communities":["public"],
//	    "write_communities":["private"],
//	    "system_descr":"Linux fw 5.10 ...",
//	    "system_uptime":"12 days",
//	    "system_contact":"noc@example.com",
//	    "system_name":"fw01",
//	    "system_location":"rack 3",
//	    "walks":[{"label":"users","oid":"1.3.6.1.4.1.77.1.2.25",
//	              "line_count":42,"output":"..."}],
//	    "error":""
//	}]}
//
// Host key: results[].target (normalizeAsset). A result matches when its
// target normalizes to the target key.
//
// Category mapping:
//   - valid_communities[]  -> CatCreds       MEDIUM SevRank 2 ("SNMP community: <c>")
//   - write_communities[]  -> CatCreds       HIGH   SevRank 3 ("SNMP WRITE community: <c>")
//   - system_descr         -> CatServices    (recon fact, SevRank -1)
//   - system_contact       -> CatEmailRecon  (recon fact, SevRank -1)
//   - walks[]              -> CatSMBAD / CatTech / CatServices by label
//     (recon fact, SevRank -1, "<label> (<n> entries)")
//
// scanID is part of the signature but ignored here — the engine links findings.
func parseSNMPEnumTarget(resJSON, target string, scanDate time.Time, scanID string, emit func(targetRaw, time.Time)) {
	_ = scanID // engine owns the scan link; parser ignores scanID by contract.
	if target == "" {
		return
	}

	var res struct {
		Results []struct {
			Target           string   `json:"target"`
			ValidCommunities []string `json:"valid_communities"`
			WriteCommunities []string `json:"write_communities,omitempty"`
			SystemDescr      string   `json:"system_descr,omitempty"`
			SystemContact    string   `json:"system_contact,omitempty"`
			Walks            []struct {
				Label     string `json:"label"`
				OID       string `json:"oid"`
				LineCount int    `json:"line_count"`
			} `json:"walks"`
			Error string `json:"error,omitempty"`
		} `json:"results"`
	}
	if err := json.Unmarshal([]byte(resJSON), &res); err != nil {
		return
	}

	// Per-list caps so a pathological host can't spawn thousands of rows.
	const (
		maxSNMPCommunities = 100
		maxSNMPWalks       = 100
	)

	for _, r := range res.Results {
		if normalizeAsset(r.Target) != target {
			continue
		}
		host := strings.TrimSpace(r.Target)
		if host == "" {
			host = target
		}

		// Write communities carry RW access — a near-instant escalation
		// path — so surface them as HIGH, distinct from the RO MEDIUM
		// entry the valid-communities pass emits below.
		for i, c := range r.WriteCommunities {
			if i >= maxSNMPCommunities {
				break
			}
			c = strings.TrimSpace(c)
			if c == "" {
				continue
			}
			emit(targetRaw{
				Module:   "snmpenum",
				Category: CatCreds,
				Title:    "SNMP WRITE community: " + c,
				Detail:   "Confirmed read-write (RW) SNMP access — enables config write, route/table rewrite, image upload",
				Locus:    host,
				Severity: "HIGH",
				SevRank:  severityRank("HIGH"),
			}, scanDate)
		}

		// Valid (read) communities — MEDIUM credential exposure.
		for i, c := range r.ValidCommunities {
			if i >= maxSNMPCommunities {
				break
			}
			c = strings.TrimSpace(c)
			if c == "" {
				continue
			}
			emit(targetRaw{
				Module:   "snmpenum",
				Category: CatCreds,
				Title:    "SNMP community: " + c,
				Detail:   "Valid SNMP community string grants read access to the agent",
				Locus:    host,
				Severity: "MEDIUM",
				SevRank:  severityRank("MEDIUM"),
			}, scanDate)
		}

		// System description — services/tech recon fact.
		if d := strings.TrimSpace(r.SystemDescr); d != "" {
			emit(targetRaw{
				Module:   "snmpenum",
				Category: CatServices,
				Title:    "System: " + d,
				Detail:   "SNMP sysDescr (1.3.6.1.2.1.1.1.0)",
				Locus:    host,
				Severity: "",
				SevRank:  -1,
			}, scanDate)
		}

		// System contact — email/recon fact.
		if c := strings.TrimSpace(r.SystemContact); c != "" {
			emit(targetRaw{
				Module:   "snmpenum",
				Category: CatEmailRecon,
				Title:    "SNMP contact: " + c,
				Detail:   "SNMP sysContact (1.3.6.1.2.1.1.4.0)",
				Locus:    host,
				Severity: "",
				SevRank:  -1,
			}, scanDate)
		}

		// Walked OID branches — recon facts, categorised by label.
		for i, w := range r.Walks {
			if i >= maxSNMPWalks {
				break
			}
			label := strings.TrimSpace(w.Label)
			if label == "" {
				continue
			}
			detail := "SNMP walk"
			if oid := strings.TrimSpace(w.OID); oid != "" {
				detail += " of " + oid
			}
			emit(targetRaw{
				Module:   "snmpenum",
				Category: snmpWalkCategory(label),
				Title:    fmt.Sprintf("%s (%d entries)", label, w.LineCount),
				Detail:   detail,
				Locus:    host,
				Severity: "",
				SevRank:  -1,
			}, scanDate)
		}
	}
}

// snmpWalkCategory maps a walked OID-branch label to a finding category.
// User/share enumeration is AD/SMB-flavoured recon; installed software is
// tech fingerprinting; everything else (interfaces, processes, routes,
// services, tables) is service/host recon.
func snmpWalkCategory(label string) string {
	switch strings.ToLower(strings.TrimSpace(label)) {
	case "users", "shares":
		return CatSMBAD
	case "software", "installed-services":
		return CatTech
	default:
		return CatServices
	}
}
