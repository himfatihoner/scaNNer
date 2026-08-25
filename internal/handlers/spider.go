package handlers

import (
	"encoding/json"
	"log"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"time"

	"scanner/internal/models"
	"scanner/internal/modules/shared"
	"scanner/internal/modules/spider"
)

func (h *Handler) SpiderPage(w http.ResponseWriter, r *http.Request) {
	data := h.baseData(r, "Web Spider - scaNNer", "spider")
	ws := data["ActiveWorkspace"].(*models.Workspace)
	data["WSTargetGroups"] = h.groupTargetsByList(ws.ID)
	scans, _ := h.db.ListScansLite(ws.ID, "spider")
	data["Scans"] = scans
	h.render(w, "layout", data)
}

func (h *Handler) SpiderRun(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Redirect(w, r, "/modules/spider", http.StatusSeeOther)
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
		http.Redirect(w, r, "/modules/spider?error=no_urls", http.StatusSeeOther)
		return
	}

	maxDepth := 5
	// No hard upper bound on depth (user request): the crawl's total work
	// is already bounded by Max Pages, so depth only decides how deep the
	// BFS is allowed to go — a high value just means "follow links until we
	// run out of pages", which is the desired behavior for a thorough crawl.
	if v, err := strconv.Atoi(r.FormValue("max_depth")); err == nil && v >= 1 {
		maxDepth = v
	}
	maxPages := 500
	if v, err := strconv.Atoi(r.FormValue("max_pages")); err == nil && v >= 10 && v <= 10000 {
		maxPages = v
	}

	// Optional new form fields for real-engagement toggles: include
	// subdomains, path-exclude regex list, per-request delay. All
	// missing/empty = current defaults (audit finding — form was
	// missing standard pentest crawl knobs).
	includeSubdomains := r.FormValue("include_subdomains") == "on" || r.FormValue("include_subdomains") == "true"
	var excludeRegex []string
	if raw := r.FormValue("exclude_regex"); raw != "" {
		for _, line := range strings.Split(raw, "\n") {
			line = strings.TrimSpace(line)
			if line != "" {
				excludeRegex = append(excludeRegex, line)
			}
		}
	}
	var requestDelay time.Duration
	if v, err := strconv.Atoi(r.FormValue("request_delay_ms")); err == nil && v > 0 && v <= 60_000 {
		requestDelay = time.Duration(v) * time.Millisecond
	}

	opts := h.BuildHTTPOptions(r)
	conc, _ := h.applyHTTPTuning(r, opts)

	cfg := spider.DefaultConfig()
	cfg.MaxDepth = maxDepth
	cfg.MaxPages = maxPages
	cfg.Concurrency = conc
	cfg.Timeout = opts.Timeout // honor the per-scan / global request-timeout override
	cfg.IncludeSubdomains = includeSubdomains
	cfg.ExcludeRegex = excludeRegex
	cfg.RequestDelay = requestDelay

	cfgJSON, _ := json.Marshal(map[string]interface{}{
		"urls":               urls,
		"max_depth":          maxDepth,
		"max_pages":          maxPages,
		"include_subdomains": includeSubdomains,
		"exclude_regex":      excludeRegex,
		"request_delay_ms":   int(requestDelay / time.Millisecond),
	})
	// Progress-bar total is per-page across all seeds (matches how
	// spider.Scan reports done counts). Otherwise a single-seed crawl
	// stays at 0/1 for the entire run (audit finding).
	// total=0 → indeterminate bar. A crawl's real size is unknown ahead of
	// time (MaxPages is a ceiling, not a target); the scanner reports the
	// live cumulative page count as `done` instead of a fake percentage.
	scan, _ := h.db.CreateScan(ws.ID, "spider", string(cfgJSON), 0)
	// Sequential scanning: if the operator ticked "start after the current
	// scan finishes" and this workspace is busy, park this run as queued.
	if h.queueIfSequential(w, r, scan) {
		return
	}

	go h.runSpider(scan.ID, urls, cfg, opts)
	http.Redirect(w, r, "/modules/spider/results/"+scan.ID, http.StatusSeeOther)
}

// spiderParseCache memoises the parsed ScanResult for each running
// scan so an htmx poll flurry (5 s cadence × multi-MB result blob)
// doesn't pay a fresh json.Unmarshal on every hit. Keyed by scanID,
// invalidated when len(scan.Result) changes (cheap version signal that
// tracks any partial-write from the runner goroutine) or when the
// scan reaches a terminal state (audit finding, perf). No LRU / TTL —
// each scan has one entry that gets replaced or falls out when the
// results page stops polling.
type spiderParseEntry struct {
	resultLen  int
	status     models.ScanStatus
	result     spider.ScanResult
	totalRes   int
	totalDirs  int
	totalFiles int
}

var (
	spiderParseMu    sync.Mutex
	spiderParseCache = map[string]*spiderParseEntry{}
)

func (h *Handler) SpiderResults(w http.ResponseWriter, r *http.Request) {
	scanID := strings.TrimPrefix(r.URL.Path, "/modules/spider/results/")
	scan, err := h.db.GetScan(scanID)
	if err != nil {
		http.NotFound(w, r)
		return
	}
	data := h.baseData(r, "Spider Results - scaNNer", "spider_results")

	// Serve from cache when the raw result blob hasn't grown/shrunk
	// and the terminal state is unchanged. Otherwise unmarshal and
	// refresh the entry.
	spiderParseMu.Lock()
	cached, hit := spiderParseCache[scanID]
	spiderParseMu.Unlock()

	var result spider.ScanResult
	totalRes, totalDirs, totalFiles := 0, 0, 0
	if hit && cached.resultLen == len(scan.Result) && cached.status == scan.Status {
		result = cached.result
		totalRes = cached.totalRes
		totalDirs = cached.totalDirs
		totalFiles = cached.totalFiles
	} else {
		if scan.Result != "" {
			if unmarshalErr := json.Unmarshal([]byte(scan.Result), &result); unmarshalErr != nil {
				// Silent corruption used to render as "no results" —
				// log so the operator has a breadcrumb (audit finding).
				log.Printf("spider scan %s: result unmarshal failed: %v", scanID, unmarshalErr)
			}
		}
		for _, tr := range result.Results {
			totalRes += len(tr.Resources)
			totalDirs += tr.TotalDirs
			totalFiles += tr.TotalFiles
		}
		spiderParseMu.Lock()
		spiderParseCache[scanID] = &spiderParseEntry{
			resultLen:  len(scan.Result),
			status:     scan.Status,
			result:     result,
			totalRes:   totalRes,
			totalDirs:  totalDirs,
			totalFiles: totalFiles,
		}
		spiderParseMu.Unlock()
	}

	// Filter
	filterType := r.URL.Query().Get("type")

	data["Scan"] = scan
	data["Results"] = result.Results
	data["TotalRes"] = totalRes
	data["TotalDirs"] = totalDirs
	data["TotalFiles"] = totalFiles
	data["FilterType"] = filterType
	h.renderResults(w, r, "spider_results_inner", data)
}

func (h *Handler) SpiderStatus(w http.ResponseWriter, r *http.Request) {
	scanID := strings.TrimPrefix(r.URL.Path, "/modules/spider/status/")
	scan, err := h.db.GetScan(scanID)
	if err != nil {
		http.NotFound(w, r)
		return
	}
	h.writeScanStatus(w, scan)
}

func (h *Handler) runSpider(scanID string, urls []string, cfg spider.SpiderConfig, opts *shared.HTTPOptions) {
	if !h.db.MarkRunning(scanID) {
		return
	}
	opts = h.BeginScan(scanID, opts)
	defer h.FinishScan(scanID)

	// Periodic saver for live intermediate results.
	//
	// Audit fix (perf): previously the partial callback called
	// json.Marshal on the full ScanResult per spider page completion
	// (up to MaxPages=10000) — each marshal walks every Resource
	// including RawRequest/RawResponse blobs (~20 KB each), so a full
	// crawl could spend O(N²) bytes marshalling on the hot path. Now
	// the callback only stores the *ScanResult pointer; the 2 s ticker
	// goroutine marshals once per interval. That collapses thousands
	// of marshals into ~scan-duration/2 marshals.
	var latestPartial *spider.ScanResult
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
				p := latestPartial
				resultMu.Unlock()
				if p == nil {
					continue
				}
				if b, err := json.Marshal(p); err == nil {
					h.db.UpdateScanResult(scanID, string(b))
				}
			}
		}
	}()

	result := spider.Scan(urls, cfg, opts,
		func(partial *spider.ScanResult) {
			resultMu.Lock()
			latestPartial = partial
			resultMu.Unlock()
		},
		func(done int, msg string) {
			h.db.UpdateScanProgress(scanID, done, msg)
		})

	// Wipe the partial cache BEFORE the final write (audit B33). The
	// ticker goroutine keeps running until the deferred close(doneCh)
	// fires at function-return; without this wipe there's a microsecond
	// race window where the ticker could overwrite our fresh final
	// result with the stale last-partial. Setting latestPartial to nil
	// makes any remaining tick a no-op (the goroutine's `if p == nil`
	// guard skips the UpdateScanResult call).
	resultMu.Lock()
	latestPartial = nil
	resultMu.Unlock()

	// Surface marshal failures (audit B65). json.Marshal on a normal
	// scan result almost never fails, but if it does (cyclic ref, weird
	// type), we'd silently overwrite the DB row with empty `""` —
	// looking like the scan produced no results. Log + skip so the
	// previous partial-result column survives.
	if resultJSON, err := json.Marshal(result); err == nil {
		h.db.UpdateScanResult(scanID, string(resultJSON))
	} else {
		log.Printf("spider scan %s: result marshal failed: %v", scanID, err)
	}

	// Drop the parse cache entry — the next results-page hit will
	// re-unmarshal off the freshly written blob and cache the terminal
	// state. Without this, a rare race could leave the running-state
	// entry in place after the scan flips to done.
	spiderParseMu.Lock()
	delete(spiderParseCache, scanID)
	spiderParseMu.Unlock()
}
