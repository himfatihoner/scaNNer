package handlers

import (
	"encoding/json"
	"fmt"
	"strings"
	"time"
)

// tf_authtest.go — per-target finding parser for the "authtest" module.
//
// Shape (mirrors internal/modules/authtest/scanner.go, DO NOT import it):
//
//	{"results":[{"login_url":"","method":"","findings":[
//	    {"severity":"","title":"","detail":"","evidence":""}],
//	  "attempts":[
//	    {"username":"","password":"","status_code":0,"body_len":0,"outcome":""}]}]}
//
// Host key: results[].login_url (URL match against the target asset).
//
// Mapping:
//   - findings[] with severity >= HIGH  -> CatVuln
//   - findings[] with severity <  HIGH  -> CatHeaders (web-misconfig)
//     Title/Detail/Severity/SevRank all come from the finding.
//   - attempts[] with a success outcome -> CatCreds (weak credential accepted).

// authtest per-list caps so a ClusterBomb result can't emit thousands of rows.
const (
	authTestFindingCap = 500
	authTestCredCap    = 200
)

type authTestFindingRaw struct {
	Severity    string `json:"severity"`
	Title       string `json:"title"`
	Detail      string `json:"detail"`
	Evidence    string `json:"evidence"`
	RawRequest  string `json:"raw_request"`
	RawResponse string `json:"raw_response"`
}

type authTestAttemptRaw struct {
	Username   string `json:"username"`
	Password   string `json:"password"`
	StatusCode int    `json:"status_code"`
	BodyLen    int    `json:"body_len"`
	Outcome    string `json:"outcome"`
}

type authTestURLResult struct {
	LoginURL string               `json:"login_url"`
	Method   string               `json:"method"`
	Findings []authTestFindingRaw `json:"findings"`
	Attempts []authTestAttemptRaw `json:"attempts"`
}

type authTestResult struct {
	Results []authTestURLResult `json:"results"`
}

// parseAuthTestTarget unmarshals an authtest scan result, filters to the URL
// results that belong to `target`, and emits one raw per finding / successful
// credential. scanID is part of the signature but intentionally unused (the
// engine wires the scan link).
func parseAuthTestTarget(resJSON, target string, scanDate time.Time, scanID string, emit func(targetRaw, time.Time)) {
	_ = scanID

	var res authTestResult
	if err := json.Unmarshal([]byte(resJSON), &res); err != nil {
		return
	}

	for _, lr := range res.Results {
		// login_url is the host field. When present it must match the
		// target; when empty the scan config already guaranteed this host.
		if lr.LoginURL != "" && !urlMatchesAsset(lr.LoginURL, target) {
			continue
		}

		locus := lr.LoginURL

		// findings[] -> CatVuln (>=HIGH) or CatHeaders.
		findingsEmitted := 0
		for _, f := range lr.Findings {
			if findingsEmitted >= authTestFindingCap {
				break
			}
			title := strings.TrimSpace(f.Title)
			if title == "" {
				continue
			}

			sev := strings.ToUpper(strings.TrimSpace(f.Severity))
			rank := severityRank(f.Severity)
			cat := CatHeaders
			if rank >= 3 { // HIGH or CRITICAL
				cat = CatVuln
			}

			detail := strings.TrimSpace(f.Detail)
			if ev := strings.TrimSpace(f.Evidence); ev != "" {
				if detail != "" {
					detail += " — Evidence: " + ev
				} else {
					detail = ev
				}
			}

			tr := targetRaw{
				SevRank:  rank,
				Severity: sev,
				Category: cat,
				Module:   "authtest",
				Title:    title,
				Detail:   detail,
				Locus:    locus,
			}
			// For CatVuln findings, carry the module's proof fields as typed
			// data (not just flattened into Detail). The module's Finding
			// exposes evidence + captured raw request/response; it has no
			// CVE / reference / remediation fields.
			if cat == CatVuln {
				if ev := strings.TrimSpace(f.Evidence); ev != "" {
					tr.Evidence = ev
				}
				tr.RawRequest = f.RawRequest
				tr.RawResponse = f.RawResponse
			}

			emit(tr, scanDate)
			findingsEmitted++
		}

		// attempts[] with a success outcome -> CatCreds.
		credsEmitted := 0
		for _, a := range lr.Attempts {
			if credsEmitted >= authTestCredCap {
				break
			}
			if !strings.Contains(strings.ToLower(a.Outcome), "success") {
				continue
			}
			user := strings.TrimSpace(a.Username)
			title := "Weak credentials accepted"
			if user != "" {
				title += ": " + user
			}
			detail := fmt.Sprintf("Login succeeded as %s / %s (HTTP %d, body %d bytes).",
				valueOrDash(user), valueOrDash(strings.TrimSpace(a.Password)), a.StatusCode, a.BodyLen)

			emit(targetRaw{
				SevRank:  4,
				Severity: "CRITICAL",
				Category: CatCreds,
				Module:   "authtest",
				Title:    title,
				Detail:   detail,
				Locus:    locus,
			}, scanDate)
			credsEmitted++
		}
	}
}

func valueOrDash(s string) string {
	if s == "" {
		return "-"
	}
	return s
}
