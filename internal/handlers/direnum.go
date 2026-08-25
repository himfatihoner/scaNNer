package handlers

import (
	"encoding/json"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"time"

	"scanner/internal/models"
	"scanner/internal/modules/direnum"
	"scanner/internal/modules/shared"
)

func (h *Handler) DirEnumPage(w http.ResponseWriter, r *http.Request) {
	data := h.baseData(r, "Directory Enumerator - scaNNer", "direnum")
	ws := data["ActiveWorkspace"].(*models.Workspace)
	scans, _ := h.db.ListScansLite(ws.ID, "direnum")
	data["Scans"] = scans
	data["TechProfiles"] = direnum.AllTechProfiles
	data["WSTargetGroups"] = h.groupTargetsByList(ws.ID)
	h.render(w, "layout", data)
}

func (h *Handler) DirEnumRun(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Redirect(w, r, "/modules/direnum", http.StatusSeeOther)
		return
	}
	// Audit fix: cap incoming form body so a single drive-by POST can't
	// shovel a multi-MB url= field through the parser. 1 MiB easily fits
	// ~500 URLs + every other form input even with maximal padding.
	r.Body = http.MaxBytesReader(w, r.Body, 1<<20)
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
		http.Redirect(w, r, "/modules/direnum?error=no_urls", http.StatusSeeOther)
		return
	}
	// Audit fix: cap URL count so a single submission cannot queue
	// billions of requests. 500 matches the documented Settings ceiling
	// for web modules and is well above any realistic engagement.
	if len(urls) > 500 {
		http.Redirect(w, r, "/modules/direnum?error=too_many_urls", http.StatusSeeOther)
		return
	}

	techs := r.Form["techs"]
	if len(techs) == 0 {
		techs = []string{"general"}
	}
	if len(techs) > 12 {
		// Twelve is the number of baked-in TechProfiles; ticking more
		// than that means the form was tampered with. Truncate so the
		// scan still runs but doesn't fan out beyond the UI's intent.
		techs = techs[:12]
	}

	level := direnum.LevelNormal
	switch r.FormValue("level") {
	case "light":
		level = direnum.LevelLight
	case "aggressive":
		level = direnum.LevelAggressive
	}

	smartScan := r.FormValue("smart_scan") == "on"

	var filterCodes []int
	for _, cStr := range r.Form["filter_codes"] {
		if c, err := strconv.Atoi(cStr); err == nil {
			filterCodes = append(filterCodes, c)
		}
	}
	// Custom comma/space-separated codes (e.g. "302, 418 451")
	customRaw := r.FormValue("filter_codes_custom")
	for _, tok := range strings.FieldsFunc(customRaw, func(r rune) bool {
		return r == ',' || r == ' ' || r == ';' || r == '\n' || r == '\t'
	}) {
		if c, err := strconv.Atoi(strings.TrimSpace(tok)); err == nil && c > 0 && c < 1000 {
			// dedupe
			seen := false
			for _, x := range filterCodes {
				if x == c {
					seen = true
					break
				}
			}
			if !seen {
				filterCodes = append(filterCodes, c)
			}
		}
	}

	recursive := r.FormValue("recursive") == "on"
	maxDepth := 0
	if recursive {
		if md, err := strconv.Atoi(r.FormValue("max_depth")); err == nil && md >= 1 && md <= 5 {
			maxDepth = md
		} else {
			maxDepth = 2
		}
	}

	// Parse the user's exclude-paths list (one path per line, also
	// accepts comma- and semicolon-separated as a convenience). The
	// scanner does its own normalisation, but we filter out obvious
	// noise here so the config JSON stays clean.
	var excludePaths []string
	for _, tok := range strings.FieldsFunc(r.FormValue("exclude_paths"), func(r rune) bool {
		return r == '\n' || r == '\r' || r == ',' || r == ';'
	}) {
		p := strings.TrimSpace(tok)
		if p != "" && p != "/" {
			excludePaths = append(excludePaths, p)
		}
	}

	// Custom wordlist paths the operator typed in (one per line, also
	// accepts comma / semicolon separators). Path existence is checked
	// inside loadWordlist — missing files fall through to the embedded
	// fallback with a log line, so a typo doesn't silently zero out the
	// scan. Capped at 16 entries to bound fan-out.
	var customWordlists []string
	for _, tok := range strings.FieldsFunc(r.FormValue("custom_wordlists"), func(r rune) bool {
		return r == '\n' || r == '\r' || r == ',' || r == ';'
	}) {
		p := strings.TrimSpace(tok)
		if p != "" {
			customWordlists = append(customWordlists, p)
		}
		if len(customWordlists) >= 16 {
			break
		}
	}

	opts := h.BuildHTTPOptions(r)
	// applyHTTPTuning reads the http_tuning partial (req_timeout /
	// max_concurrent), sets opts.Timeout to the override-or-global value,
	// and returns the effective concurrency. direnum's HTTP client reads
	// cfg.Timeout (scanner.go), so mirror opts.Timeout into it.
	conc, _ := h.applyHTTPTuning(r, opts)
	cfg := direnum.ScanConfig{
		Techs:           techs,
		Level:           level,
		SmartScan:       smartScan,
		FilterCodes:     filterCodes,
		Concurrency:     conc,
		Timeout:         opts.Timeout,
		Recursive:       recursive,
		MaxDepth:        maxDepth,
		ExcludePaths:    excludePaths,
		CustomWordlists: customWordlists,
	}

	// Audit fix: previous cfgJSON dropped filter_codes / recursive /
	// max_depth / exclude_paths, so Restart silently ran a stripped-
	// down scan with the wrong knobs. Persist every form input the
	// scanner reads so replay produces the same scan the operator just
	// ran.
	cfgJSON, _ := json.Marshal(map[string]interface{}{
		"urls":             urls,
		"techs":            techs,
		"level":            level,
		"smart_scan":       smartScan,
		"filter_codes":     filterCodes,
		"recursive":        recursive,
		"max_depth":        maxDepth,
		"exclude_paths":    excludePaths,
		"custom_wordlists": customWordlists,
	})
	scan, _ := h.db.CreateScan(ws.ID, "direnum", string(cfgJSON), len(urls))
	// Sequential scanning: if the operator ticked "start after the current
	// scan finishes" and this workspace is busy, park this run as queued.
	if h.queueIfSequential(w, r, scan) {
		return
	}

	// Bind the per-scan skip set (populated by DirEnumSkip) into the
	// scanner so the BFS recursion drops user-cancelled subtrees on
	// the fly. The closure resolves IsSkipped against the live set
	// at every check, so adds during the scan take effect immediately.
	cfg.IsSkipped = func(absURL string) bool {
		return h.scanMgr.IsSkipped(scan.ID, absURL)
	}

	go h.runDirEnum(scan.ID, urls, cfg, opts)
	http.Redirect(w, r, "/modules/direnum/results/"+scan.ID, http.StatusSeeOther)
}

// DirEnumSkip records a directory the user no longer wants the scanner
// to walk into. The skip is consulted live by the BFS recursion in the
// scanner — already-fired requests aren't aborted, but queued ones
// under this prefix get dropped before they go out, and the dir's
// subtree is excluded from deeper levels.
//
// Audit fix: the previous implementation took an arbitrary scanID +
// URL prefix and shoveled them into ScanManager without checking that
// the scan exists, that it belongs to the active workspace, or that
// it's even still running. That let an unauthenticated cross-origin
// attacker grow the in-memory skip map without bound and grief any
// known scanID. We now require the scan to exist, to belong to the
// active workspace, and to be in `running` state — everything else
// is rejected without touching ScanManager.
func (h *Handler) DirEnumSkip(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	// Bound the form body — `url=` is the only field expected and a
	// kilobyte is already 4x more than the largest realistic URL.
	r.Body = http.MaxBytesReader(w, r.Body, 4<<10)
	scanID := strings.TrimPrefix(r.URL.Path, "/modules/direnum/skip/")
	if scanID == "" {
		http.Error(w, "missing scan id", http.StatusBadRequest)
		return
	}
	scan, err := h.db.GetScan(scanID)
	if err != nil {
		http.NotFound(w, r)
		return
	}
	ws := h.activeWorkspace(r)
	if ws == nil || scan.WorkspaceID != ws.ID {
		http.NotFound(w, r)
		return
	}
	if scan.Status != models.ScanRunning {
		http.Error(w, "scan not running", http.StatusConflict)
		return
	}
	urlPrefix := strings.TrimSpace(r.FormValue("url"))
	if urlPrefix == "" {
		http.Error(w, "missing url", http.StatusBadRequest)
		return
	}
	// Cap the per-URL prefix length to keep map keys bounded.
	if len(urlPrefix) > 2048 {
		http.Error(w, "url too long", http.StatusBadRequest)
		return
	}
	h.scanMgr.SkipPath(scanID, urlPrefix)
	w.WriteHeader(http.StatusNoContent)
}

// DirEnumSkippedList returns the prefixes the user has marked skip for
// this scan. The UI hits this on each partial-refresh tick to grey out
// rows that are already cancelled (across page reloads, since skips
// live in memory only — they're cleared when the scan ends).
func (h *Handler) DirEnumSkippedList(w http.ResponseWriter, r *http.Request) {
	scanID := strings.TrimPrefix(r.URL.Path, "/modules/direnum/skipped/")
	if scanID == "" {
		http.Error(w, "missing scan id", http.StatusBadRequest)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{
		"skipped": h.scanMgr.SkippedPaths(scanID),
	})
}

func (h *Handler) DirEnumResults(w http.ResponseWriter, r *http.Request) {
	scanID := strings.TrimPrefix(r.URL.Path, "/modules/direnum/results/")
	scan, err := h.db.GetScan(scanID)
	if err != nil {
		http.NotFound(w, r)
		return
	}
	data := h.baseData(r, "DirEnum Results - scaNNer", "direnum_results")
	var result direnum.ScanResult
	json.Unmarshal([]byte(scan.Result), &result)

	totalFound := 0
	for _, tr := range result.Results {
		totalFound += tr.TotalFound
	}
	data["Scan"] = scan
	data["Results"] = result.Results
	data["TotalFound"] = totalFound
	h.renderResults(w, r, "direnum_results_inner", data)
}

func (h *Handler) DirEnumStatus(w http.ResponseWriter, r *http.Request) {
	scanID := strings.TrimPrefix(r.URL.Path, "/modules/direnum/status/")
	scan, err := h.db.GetScan(scanID)
	if err != nil {
		http.NotFound(w, r)
		return
	}
	h.writeScanStatus(w, scan)
}

func (h *Handler) runDirEnum(scanID string, urls []string, cfg direnum.ScanConfig, opts *shared.HTTPOptions) {
	if !h.db.MarkRunning(scanID) {
		return
	}
	opts = h.BeginScan(scanID, opts)
	defer h.FinishScan(scanID)

	// Audit perf fix: previously the partial callback fired on every
	// hit (potentially hundreds of times) and json.Marshal'd the whole
	// ScanResult on each call. With raw req/resp capture each DirEntry
	// can be ~512 KiB, so an N-hit snapshot is O(N²) total marshalling
	// in the hot path — exactly the work the 2-second ticker is meant
	// to coalesce. We now store the *ScanResult pointer under a mutex
	// and only marshal during the ticker tick, mirroring smbenum.go.
	var latestSnap *direnum.ScanResult
	var resultMu sync.Mutex
	doneCh := make(chan struct{})
	defer close(doneCh) // audit B20: panic-safe ticker shutdown
	go func() {
		ticker := time.NewTicker(2 * time.Second)
		defer ticker.Stop()
		for {
			select {
			case <-doneCh:
				return
			case <-ticker.C:
				resultMu.Lock()
				snap := latestSnap
				resultMu.Unlock()
				if snap == nil {
					continue
				}
				if b, err := json.Marshal(snap); err == nil {
					h.db.UpdateScanResult(scanID, string(b))
				}
			}
		}
	}()

	result := direnum.ScanFull(urls, cfg, opts,
		func(partial *direnum.ScanResult) {
			resultMu.Lock()
			latestSnap = partial
			resultMu.Unlock()
		},
		func(done int, msg string) {
			h.db.UpdateScanProgress(scanID, done, msg)
		},
		// EmitProgress: gives us real (done, total, msg) in HTTP-request units.
		// We feed it directly to UpdateScanProgressFull so percentage tracks
		// actual work done across all URLs, not URL index.
		func(done, total int, msg string) {
			h.db.UpdateScanProgressFull(scanID, done, total, msg)
		})


	resultJSON, _ := json.Marshal(result)
	h.db.UpdateScanResult(scanID, string(resultJSON))

	// Hard-failure surfacing: if every URL errored (all unreachable, DNS,
	// scheme mismatch, etc.), mark the scan failed with a translated reason
	// rather than reporting a silent "done" with zero findings.
	if opts.Ctx.Err() == nil {
		var errs []string
		for _, tr := range result.Results {
			if tr.Error != "" {
				errs = append(errs, tr.Error)
			}
		}
		h.markHardFailure(scanID, errs, len(urls))
	}
}
