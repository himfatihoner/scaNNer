package handlers

import (
	"encoding/json"
	"log"
	"net/http"
	"strings"
	"sync"
	"time"

	"scanner/internal/models"
	"scanner/internal/modules/cvematch"
	"scanner/internal/modules/techdetect"
)

func (h *Handler) CVEMatchPage(w http.ResponseWriter, r *http.Request) {
	data := h.baseData(r, "CVE Matcher - scaNNer", "cvematch")
	ws := data["ActiveWorkspace"].(*models.Workspace)
	scans, _ := h.db.ListScansLite(ws.ID, "cvematch")
	data["Scans"] = scans
	techScans, _ := h.db.ListScansLite(ws.ID, "techdetect")
	data["TechScans"] = techScans

	// Surface DB freshness — show a banner when the cache hasn't been
	// refreshed within the last 8 days (NVD's "modified" feed window).
	// Anything older than that risks missing recent CVEs entirely.
	lr := h.db.CVECacheLastRefresh()
	if lr.IsZero() {
		data["CVEDBNeverRefreshed"] = true
	} else {
		ageDays := int(time.Since(lr).Hours() / 24)
		data["CVEDBAgeDays"] = ageDays
		data["CVEDBStale"] = ageDays >= 8
		data["CVEDBLastRefresh"] = lr.Format("2006-01-02 15:04 MST")
	}
	data["CVEDBCount"] = h.db.CVECacheCount()
	data["CVEDBSourceCounts"] = h.db.CVECacheCountsBySource()
	h.render(w, "layout", data)
}

func (h *Handler) CVEMatchRun(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Redirect(w, r, "/modules/cvematch", http.StatusSeeOther)
		return
	}
	r.ParseForm()
	ws := h.activeWorkspace(r)

	var inputs []cvematch.Input
	// Manual entries: each line "product@version" or "product@version@url".
	for _, line := range strings.Split(r.FormValue("manual"), "\n") {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		parts := strings.SplitN(line, "@", 3)
		in := cvematch.Input{Source: "manual"}
		in.Product = strings.TrimSpace(parts[0])
		if len(parts) > 1 {
			in.Version = strings.TrimSpace(parts[1])
		}
		if len(parts) > 2 {
			in.URL = strings.TrimSpace(parts[2])
		}
		if in.Product == "" {
			continue
		}
		inputs = append(inputs, in)
	}

	// Import from a techdetect scan if selected.
	if src := strings.TrimSpace(r.FormValue("import_techdetect")); src != "" {
		if scan, err := h.db.GetScan(src); err == nil {
			var tdResult techdetect.ScanResult
			if json.Unmarshal([]byte(scan.Result), &tdResult) == nil {
				for _, tr := range tdResult.Results {
					for _, t := range tr.Technologies {
						inputs = append(inputs, cvematch.Input{
							Product: t.Name,
							Version: t.Version,
							URL:     tr.URL,
							Source:  "techdetect",
						})
					}
				}
			}
		}
	}

	if len(inputs) == 0 {
		http.Redirect(w, r, "/modules/cvematch?error=no_inputs", http.StatusSeeOther)
		return
	}

	cfg := cvematch.Config{Inputs: inputs}
	cfgJSON, _ := json.Marshal(cfg)
	scan, err := h.db.CreateScan(ws.ID, "cvematch", string(cfgJSON), len(inputs))
	if err != nil {
		http.Redirect(w, r, "/modules/cvematch?error=db_error", http.StatusSeeOther)
		return
	}
	if h.queueIfSequential(w, r, scan) {
		return
	}
	go h.runCVEMatch(scan.ID, cfg)
	http.Redirect(w, r, "/modules/cvematch/results/"+scan.ID, http.StatusSeeOther)
}

func (h *Handler) CVEMatchResults(w http.ResponseWriter, r *http.Request) {
	scanID := strings.TrimPrefix(r.URL.Path, "/modules/cvematch/results/")
	scan, err := h.db.GetScan(scanID)
	if err != nil {
		http.NotFound(w, r)
		return
	}
	data := h.baseData(r, "CVE Match Results - scaNNer", "cvematch_results")
	var result cvematch.ScanResult
	json.Unmarshal([]byte(scan.Result), &result)

	// Bucket matches by severity for the summary view. UNKNOWN is now
	// explicitly counted so NVD entries without CVSS metrics
	// (reserved/rejected/newer-than-feed) aren't silently dropped from
	// the totals — pickSeverity() in nvd.go returns "UNKNOWN" for those.
	bySev := map[string]int{"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0, "UNKNOWN": 0}
	unverified := 0
	for _, m := range result.Matches {
		sev := strings.ToUpper(strings.TrimSpace(m.Severity))
		if sev == "" {
			sev = "UNKNOWN"
		}
		if _, ok := bySev[sev]; !ok {
			// Any unexpected severity label is folded into UNKNOWN so
			// the dashboard total still matches len(result.Matches).
			sev = "UNKNOWN"
		}
		bySev[sev]++
		if m.UnverifiedVersion {
			unverified++
		}
	}
	data["Scan"] = scan
	data["Inputs"] = result.Inputs
	data["Matches"] = result.Matches
	data["SeverityCounts"] = bySev
	data["UnverifiedCount"] = unverified
	// Products detected without a resolvable version: per user directive
	// these are NOT CVE-matched (a version-less match is a guess). We still
	// surface them so the operator knows to determine the version manually.
	// Dedup by product+source for a clean list.
	seenSkip := map[string]bool{}
	var skipped []cvematch.Input
	for _, in := range result.SkippedNoVersion {
		k := strings.ToLower(in.Product) + "|" + in.Source
		if seenSkip[k] {
			continue
		}
		seenSkip[k] = true
		skipped = append(skipped, in)
	}
	data["SkippedNoVersion"] = skipped
	h.renderResults(w, r, "cvematch_results_inner", data)
}

func (h *Handler) CVEMatchStatus(w http.ResponseWriter, r *http.Request) {
	scanID := strings.TrimPrefix(r.URL.Path, "/modules/cvematch/status/")
	scan, err := h.db.GetScan(scanID)
	if err != nil {
		http.NotFound(w, r)
		return
	}
	h.writeScanStatus(w, scan)
}

func (h *Handler) runCVEMatch(scanID string, cfg cvematch.Config) {
	if !h.db.MarkRunning(scanID) {
		log.Printf("[cvematch] MarkRunning failed for %s — scan not in pending state", scanID)
		return
	}
	log.Printf("[cvematch] running scan %s with %d inputs", scanID, len(cfg.Inputs))
	ctx := h.scanMgr.Register(scanID)
	defer h.FinishScan(scanID)

	// Wrap db.CVELookup so the cvematch package doesn't have to import
	// the database package directly (clean module boundary).
	//
	// Audit fix: memoize lookups per-scan. The matcher calls this for
	// up to 3 candidate keys per input; a techdetect import of 200
	// "Apache" tech findings previously fired 600 identical SELECTs.
	// A plain map is enough — inputs are processed sequentially by
	// ScanContext, so no locking is needed. Cache lives only for the
	// duration of this scan goroutine and dies when it returns.
	lookupCache := make(map[string][]cvematch.CacheCVE)
	lookup := func(productKey string) []cvematch.CacheCVE {
		if cached, ok := lookupCache[productKey]; ok {
			return cached
		}
		recs, err := h.db.CVELookup(productKey)
		if err != nil || len(recs) == 0 {
			lookupCache[productKey] = nil
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
		lookupCache[productKey] = out
		return out
	}

	// Canonical 2-second partial-flush pattern (see smbenum.runSMBEnum):
	// the cvematch module now emits a PartialFunc snapshot per input,
	// the ticker flushes the most recent marshalled blob to the DB so
	// the htmx-polled results page sees progress instead of waiting
	// until completion. doneCh is closed via defer for panic safety
	// (audit B20).
	var latest []byte
	var mu sync.Mutex
	doneCh := make(chan struct{})
	defer close(doneCh)
	go func() {
		t := time.NewTicker(2 * time.Second)
		defer t.Stop()
		for {
			select {
			case <-doneCh:
				return
			case <-t.C:
				mu.Lock()
				b := latest
				mu.Unlock()
				if b != nil {
					h.db.UpdateScanResult(scanID, string(b))
				}
			}
		}
	}()

	result := cvematch.ScanContext(ctx, cfg,
		func(done int, msg string) { h.db.UpdateScanProgress(scanID, done, msg) },
		func(p *cvematch.ScanResult) {
			b, err := json.Marshal(p)
			if err == nil {
				mu.Lock()
				latest = b
				mu.Unlock()
			}
		},
		lookup)
	resultJSON, _ := json.Marshal(result)
	h.db.UpdateScanResult(scanID, string(resultJSON))
}
