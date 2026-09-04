package handlers

import (
	"encoding/json"
	"log"
	"net/http"
	"strings"
	"time"

	"scanner/internal/capacity"
	"scanner/internal/models"
	"scanner/internal/modules/cvematch"
	"scanner/internal/modules/shared"
	"scanner/internal/modules/techdetect"
	"scanner/internal/sysmon"
)

func (h *Handler) TechDetectPage(w http.ResponseWriter, r *http.Request) {
	data := h.baseData(r, "Tech Detector - scaNNer", "techdetect")
	ws := data["ActiveWorkspace"].(*models.Workspace)
	data["WSTargetGroups"] = h.groupTargetsByList(ws.ID)
	scans, _ := h.db.ListScansLite(ws.ID, "techdetect")
	data["Scans"] = scans
	h.render(w, "layout", data)
}

func (h *Handler) TechDetectRun(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Redirect(w, r, "/modules/techdetect", http.StatusSeeOther)
		return
	}
	ws := h.activeWorkspace(r)

	var urls []string
	for _, line := range strings.Split(r.FormValue("urls"), "\n") {
		line = strings.TrimSpace(line)
		if line != "" {
			urls = append(urls, line)
		}
	}
	if selected := r.Form["targets"]; len(selected) > 0 {
		urls = append(urls, selected...)
	}
	if len(urls) == 0 {
		http.Redirect(w, r, "/modules/techdetect?error=no_urls", http.StatusSeeOther)
		return
	}

	opts := h.BuildHTTPOptions(r)
	autoCVE := r.FormValue("auto_cvematch") == "on"
	aggressive := r.FormValue("aggressive_whatweb") == "on"

	// Audit fix: persist the per-scan HTTP overrides (Headers, Cookies, UA,
	// Proxy shape) into the config JSON so Restart can replay the same
	// authenticated probe. Previously Restart hardcoded nil opts + built
	// only from Settings, so a scan launched with a custom auth cookie or
	// Burp proxy silently degraded to unauthenticated / direct-fetch mode.
	cfgMap := map[string]interface{}{
		"urls":          urls,
		"auto_cvematch": autoCVE,
		"aggressive":    aggressive,
	}
	if opts != nil {
		if len(opts.Headers) > 0 {
			cfgMap["headers"] = opts.Headers
		}
		if len(opts.Cookies) > 0 {
			cfgMap["cookies"] = opts.Cookies
		}
		if opts.UserAgent != "" {
			cfgMap["user_agent"] = opts.UserAgent
		}
	}
	cfgJSON, _ := json.Marshal(cfgMap)
	scan, _ := h.db.CreateScan(ws.ID, "techdetect", string(cfgJSON), len(urls))

	if h.queueIfSequential(w, r, scan) {
		return
	}
	go h.runTechDetect(scan.ID, ws.ID, urls, opts, autoCVE, aggressive)
	http.Redirect(w, r, "/modules/techdetect/results/"+scan.ID, http.StatusSeeOther)
}

func (h *Handler) TechDetectResults(w http.ResponseWriter, r *http.Request) {
	scanID := strings.TrimPrefix(r.URL.Path, "/modules/techdetect/results/")
	scan, err := h.db.GetScan(scanID)
	if err != nil {
		http.NotFound(w, r)
		return
	}
	data := h.baseData(r, "Tech Results - scaNNer", "techdetect_results")

	// The result blob is a chainedResult — techdetect.ScanResult plus an
	// optional embedded CVE Match section. Older scans (before the
	// inline chain landed) won't have the CVE fields; the unmarshal still
	// works because they're tagged omitempty.
	var result chainedResult
	json.Unmarshal([]byte(scan.Result), &result)

	totalTech := 0
	for _, tr := range result.Results {
		totalTech += len(tr.Technologies)
	}

	var cfg struct {
		AutoCVEMatch bool `json:"auto_cvematch"`
	}
	json.Unmarshal([]byte(scan.Config), &cfg)

	// Severity bucket counts for the cvematch_results_inner template.
	cveSev := map[string]int{"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0}
	for _, m := range result.CVEMatches {
		cveSev[m.Severity]++
	}

	data["Scan"] = scan
	data["Results"] = result.Results
	// Non-fatal whatweb tool-degradation notes (missing binary / broken exit),
	// rendered as an amber banner so a silently-absent whatweb is visible even
	// when the Go-side fingerprints still produced results.
	data["Warnings"] = result.Warnings
	data["TotalTech"] = totalTech
	data["AutoCVEMatch"] = cfg.AutoCVEMatch
	data["CVEMatches"] = result.CVEMatches
	data["CVEInputs"] = result.CVEInputs
	data["CVESeverityCounts"] = cveSev
	h.renderResults(w, r, "techdetect_results_inner", data)
}

func (h *Handler) TechDetectStatus(w http.ResponseWriter, r *http.Request) {
	scanID := strings.TrimPrefix(r.URL.Path, "/modules/techdetect/status/")
	scan, err := h.db.GetScan(scanID)
	if err != nil {
		http.NotFound(w, r)
		return
	}
	h.writeScanStatus(w, scan)
}

// chainedResult is what we persist in the scan's result column when the
// user ticks auto_cvematch. It embeds techdetect's native shape so older
// readers (and the standalone Tech Detect → CVE Matcher CSV export)
// continue to work; the two extra fields are zero-value omitempty when
// the chain wasn't requested.
type chainedResult struct {
	techdetect.ScanResult
	CVEInputs  []cvematch.Input `json:"cve_inputs,omitempty"`
	CVEMatches []cvematch.Match `json:"cve_matches,omitempty"`
}

// capPoCRaw truncates a captured raw request/response to the same bound the vuln
// index enrichment applies (vulnRawCap), so the persisted chained result doesn't
// carry a full 256 KB response copy on every per-tech CVE match for a URL.
func capPoCRaw(s string) string {
	if len(s) <= vulnRawCap {
		return s
	}
	return s[:vulnRawCap] + "\n... [truncated]"
}

func (h *Handler) runTechDetect(scanID, workspaceID string, urls []string, opts *shared.HTTPOptions, autoCVE, aggressive bool) {
	if !h.db.MarkRunning(scanID) {
		return
	}
	opts = h.BeginScan(scanID, opts)
	defer h.FinishScan(scanID)
	// Audit fix: stream per-target snapshots so a 50+ URL scan doesn't
	// blank the results page for minutes. Throttled at 2s inside the
	// scanner so this callback only fires at most that often.
	partialFn := func(snap *techdetect.ScanResult) {
		// Wrap into the chainedResult shell so the results page (which
		// always reads chainedResult) can render mid-scan.
		ch := chainedResult{ScanResult: *snap}
		if js, err := json.Marshal(ch); err == nil {
			h.db.UpdateScanResult(scanID, string(js))
		}
	}
	tdResult := techdetect.ScanWithConfig(techdetect.Config{
		URLs:        urls,
		Aggressive:  aggressive,
		Concurrency: capacity.Recommend("techdetect", sysmon.ReadLimits()),
	}, opts, func(done int, msg string) {
		h.db.UpdateScanProgress(scanID, done, msg)
	}, partialFn)

	chained := chainedResult{ScanResult: *tdResult}

	// Auto-chain CVE matching — runs INLINE within the same scan goroutine
	// so the user sees both tech tags and CVE matches on a single results
	// page. No separate scan record, no separate pending state, no extra
	// click. Previously this spawned a sibling cvematch scan, which the
	// user (correctly) found surprising — the two modules feel like one
	// operation conceptually.
	if autoCVE {
		var inputs []cvematch.Input
		for _, tr := range tdResult.Results {
			for _, t := range tr.Technologies {
				if strings.TrimSpace(t.Name) == "" {
					continue
				}
				inputs = append(inputs, cvematch.Input{
					Product: t.Name,
					Version: t.Version,
					URL:     tr.URL,
					Source:  "techdetect",
					// Carry the request/response that fingerprinted this tech so a
					// resulting CVE shows the evidencing exchange in its PoC. Bounded
					// so N techs on one URL don't each persist a full 256 KB response.
					RawRequest:  capPoCRaw(tr.RawRequest),
					RawResponse: capPoCRaw(tr.RawResponse),
				})
			}
		}
		chained.CVEInputs = inputs
		if len(inputs) > 0 {
			// Reuse the same DB-backed lookup the standalone cvematch
			// runner uses — keeps fixed_in, remediation, severity etc.
			// behaviour identical.
			lookup := func(productKey string) []cvematch.CacheCVE {
				recs, err := h.db.CVELookup(productKey)
				if err != nil || len(recs) == 0 {
					return nil
				}
				out := make([]cvematch.CacheCVE, 0, len(recs))
				for _, r := range recs {
					out = append(out, cvematch.CacheCVE{
						CVEID:       r.CVEID,
						ProductKey:  r.ProductKey,
						ProductName: r.ProductName,
						VersionLo:   r.VersionLo,
						VersionHi:   r.VersionHi,
						LoInc:       r.LoInc == 1,
						HiInc:       r.HiInc == 1,
						FixedIn:     r.FixedIn,
						Severity:    r.Severity,
						CVSS:        r.CVSS,
						Description: r.Description,
						Remediation: r.Remediation,
						Reference:   r.Reference,
					})
				}
				return out
			}
			var lastCVEFlush time.Time
			cveRes := cvematch.ScanContext(opts.Ctx, cvematch.Config{Inputs: inputs},
				func(done int, msg string) {
					// Surface CVE phase progress alongside techdetect's so
					// the running banner shows "Matching CVEs (X/Y)" not
					// just "100% done" while we're still working. Pin
					// progress_done at the tech-detect total (len(urls)) — the
					// CVE phase has its OWN counter (up to len(inputs), which
					// can far exceed len(urls)); writing it as progress_done
					// against progress_total=len(urls) drove the bar past 100%
					// (e.g. 129%). The live count stays visible in the message.
					h.db.UpdateScanProgress(scanID, len(urls), "CVE match: "+msg)
				},
				func(snap *cvematch.ScanResult) {
					// Flush partial CVE matches into the chained result so
					// techdetect's CVE findings land on the Vulnerabilities page
					// LIVE (they were previously written only at completion, line
					// below). Safe: the main goroutine is blocked in ScanContext,
					// so this is the sole writer of `chained` here. Throttled ~2s.
					if snap == nil || time.Since(lastCVEFlush) < 2*time.Second {
						return
					}
					lastCVEFlush = time.Now()
					chained.CVEMatches = snap.Matches
					if b, err := json.Marshal(chained); err == nil {
						h.db.UpdateScanResult(scanID, string(b))
					}
				}, lookup)
			if cveRes != nil {
				chained.CVEMatches = cveRes.Matches
			}
			log.Printf("[techdetect+cvematch] %s: %d inputs → %d matches", scanID, len(inputs), len(chained.CVEMatches))
		}
	}

	if b, err := json.Marshal(chained); err == nil {
		h.db.UpdateScanResult(scanID, string(b))
	}

	// Hard-failure surfacing: if every unit errored, mark the scan failed
	// with a translated reason rather than a silent "done" with zero findings.
	if opts.Ctx.Err() == nil {
		var errs []string
		for _, u := range chained.Results {
			if u.Error != "" {
				errs = append(errs, u.Error)
			}
		}
		h.markHardFailure(scanID, errs, len(urls))
	}
}
