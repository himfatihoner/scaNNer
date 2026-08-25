package handlers

import (
	"encoding/json"
	"strings"
	"time"
)

// tf_jwt.go — per-target finding parser for the "jwt" module.
//
// Shape (mirrors internal/modules/jwt/scanner.go, DO NOT import it):
//
//	{"results":[{
//	    "algorithm":"",
//	    "findings":[{"severity":"","title":"","detail":""}],
//	    "cracked_secret":"",
//	    "attack_tokens":[{"name":"","replay_accepted":false,"replay_status":0}]}]}
//
// Host key: NONE. TokenResult carries no host field, so the scan config already
// guaranteed this host — every result is emitted (no per-host filtering).
//
// Mapping:
//   - results[].findings[]     -> CatVuln  (Title/Severity/SevRank from the finding;
//                                 Evidence = token alg + cracked secret when present)
//   - results[].cracked_secret -> CatCreds (HIGH, SevRank 3)
//   - results[].algorithm      -> CatTech  (recon fact, SevRank -1)

// jwt per-list caps so a token batch can't emit thousands of rows.
const (
	jwtFindingCap = 500
	jwtAlgoCap    = 50
)

type jwtFindingRaw struct {
	Severity string `json:"severity"`
	Title    string `json:"title"`
	Detail   string `json:"detail,omitempty"`
}

type jwtTokenResult struct {
	Algorithm     string          `json:"algorithm,omitempty"`
	Findings      []jwtFindingRaw `json:"findings"`
	CrackedSecret string          `json:"cracked_secret,omitempty"`
}

type jwtResult struct {
	Results []jwtTokenResult `json:"results"`
}

// parseJWTTarget unmarshals a jwt scan result and emits one raw per finding,
// per cracked secret, and per distinct observed algorithm. TokenResult has no
// host field, so (the scan config already targeting this host) every result is
// emitted. scanID is part of the signature but intentionally unused (the engine
// wires the scan link).
func parseJWTTarget(resJSON, target string, scanDate time.Time, scanID string, emit func(targetRaw, time.Time)) {
	_ = scanID

	var res jwtResult
	if err := json.Unmarshal([]byte(resJSON), &res); err != nil {
		return
	}

	findingsEmitted := 0
	var algos []string

	for _, tr := range res.Results {
		// Token-level proof shared by every finding under this token: the
		// signing algorithm and, when brute-force succeeded, the recovered
		// secret. Joined into Evidence so each CatVuln row carries concrete
		// proof instead of only free-text Title/Detail.
		var evParts []string
		if alg := strings.TrimSpace(tr.Algorithm); alg != "" {
			evParts = append(evParts, "alg="+alg)
		}
		if secret := strings.TrimSpace(tr.CrackedSecret); secret != "" {
			evParts = append(evParts, "cracked secret="+secret)
		}
		evidence := strings.Join(evParts, "; ")

		// findings[] -> CatVuln.
		for _, f := range tr.Findings {
			if findingsEmitted >= jwtFindingCap {
				break
			}
			title := strings.TrimSpace(f.Title)
			if title == "" {
				continue
			}
			emit(targetRaw{
				SevRank:  severityRank(f.Severity),
				Severity: strings.ToUpper(strings.TrimSpace(f.Severity)),
				Category: CatVuln,
				Module:   "jwt",
				Title:    title,
				Detail:   strings.TrimSpace(f.Detail),
				Evidence: evidence,
				Locus:    target,
			}, scanDate)
			findingsEmitted++
		}

		// cracked_secret -> CatCreds (HIGH).
		if secret := strings.TrimSpace(tr.CrackedSecret); secret != "" {
			emit(targetRaw{
				SevRank:  3,
				Severity: "HIGH",
				Category: CatCreds,
				Module:   "jwt",
				Title:    "JWT secret cracked: " + secret,
				Detail:   "The JWT signing secret was recovered by brute force; tokens can be forged with a valid signature.",
				Locus:    target,
			}, scanDate)
		}

		// algorithm -> CatTech recon fact (deduped across tokens).
		if alg := strings.TrimSpace(tr.Algorithm); alg != "" {
			algos = appendUnique(algos, alg)
		}
	}

	for i, alg := range algos {
		if i >= jwtAlgoCap {
			break
		}
		emit(targetRaw{
			SevRank:  -1,
			Severity: "",
			Category: CatTech,
			Module:   "jwt",
			Title:    "JWT algorithm: " + alg,
			Locus:    target,
		}, scanDate)
	}
}
