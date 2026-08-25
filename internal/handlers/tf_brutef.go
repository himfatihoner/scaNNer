package handlers

import (
	"encoding/json"
	"fmt"
	"time"
)

// tf_brutef.go — per-target finding parser for the "brutef" (hydra) module.
//
// Shape (from internal/modules/brutef/scanner.go — ScanResult/TargetResult/Credential):
//
//	{"results":[{
//	    "target":"1.2.3.4","port":22,"protocol":"ssh",
//	    "found":[{"username":"root","password":"toor","host":"1.2.3.4"}],
//	    "attempts":42,"error":""
//	}]}
//
// Host key is results[].target (normalizeAsset). Each result entry already
// belongs to a single target host, so we filter on that.
//
// Category mapping:
//   - results[].found[]        -> CatCreds     (HIGH, SevRank 3) — a valid login
//   - results[].protocol/port  -> CatServices  (SevRank -1)      — service probed

// bruteFCredRaw mirrors brutef.Credential (only the fields we consume).
type bruteFCredRaw struct {
	Username string `json:"username"`
	Password string `json:"password"`
	Host     string `json:"host"`
}

// bruteFTargetRaw mirrors brutef.TargetResult (subset).
type bruteFTargetRaw struct {
	Target   string          `json:"target"`
	Port     int             `json:"port"`
	Protocol string          `json:"protocol"`
	Found    []bruteFCredRaw `json:"found"`
	Attempts int             `json:"attempts"`
	Error    string          `json:"error"`
}

// bruteFResultRaw mirrors brutef.ScanResult.
type bruteFResultRaw struct {
	Results []bruteFTargetRaw `json:"results"`
}

// maxBruteFCredsPerTarget caps how many credential findings we emit per target
// result so a pathological hydra run can't spawn thousands of rows.
const maxBruteFCredsPerTarget = 100

func parseBruteFTarget(resJSON, target string, scanDate time.Time, scanID string, emit func(targetRaw, time.Time)) {
	_ = scanID // engine owns the scan link; parser ignores scanID by contract.

	var res bruteFResultRaw
	if err := json.Unmarshal([]byte(resJSON), &res); err != nil {
		return
	}

	for _, tr := range res.Results {
		if normalizeAsset(tr.Target) != target {
			continue
		}

		proto := tr.Protocol
		if proto == "" {
			continue
		}
		locus := fmt.Sprintf("%d/%s", tr.Port, proto)

		// Service fact: this protocol/port was brute-forced (recon, no severity).
		svc := targetRaw{
			SevRank:  -1,
			Severity: "",
			Category: CatServices,
			Module:   "brutef",
			Title:    fmt.Sprintf("%s/%d", proto, tr.Port),
			Locus:    locus,
		}
		if tr.Attempts > 0 {
			svc.Detail = fmt.Sprintf("%d login attempts", tr.Attempts)
		}
		emit(svc, scanDate)

		// Valid credentials: one HIGH finding per (user, pass) pair.
		for i, c := range tr.Found {
			if i >= maxBruteFCredsPerTarget {
				break
			}
			emit(targetRaw{
				SevRank:  3,
				Severity: "HIGH",
				Category: CatCreds,
				Module:   "brutef",
				Title:    fmt.Sprintf("%s/%d %s:%s", proto, tr.Port, c.Username, c.Password),
				Detail:   fmt.Sprintf("Valid credentials recovered via hydra (%s)", proto),
				Locus:    locus,
			}, scanDate)
		}
	}
}
