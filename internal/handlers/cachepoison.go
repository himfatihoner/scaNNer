package handlers

import (
	"encoding/json"
	"net/http"
	"strings"
	"sync"
	"time"

	"scanner/internal/models"
	"scanner/internal/modules/cachepoison"
	"scanner/internal/modules/shared"
)

func (h *Handler) CachePoisonPage(w http.ResponseWriter, r *http.Request) {
	data := h.baseData(r, "Cache Poisoning & Smuggling - scaNNer", "cachepoison")
	ws := data["ActiveWorkspace"].(*models.Workspace)
	data["WSTargetGroups"] = h.groupTargetsByList(ws.ID)
	scans, _ := h.db.ListScansLite(ws.ID, "cachepoison")
	data["Scans"] = scans
	h.render(w, "layout", data)
}

func (h *Handler) CachePoisonRun(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Redirect(w, r, "/modules/cachepoison", http.StatusSeeOther)
		return
	}
	r.ParseForm()
	ws := h.activeWorkspace(r)

	var urls []string
	for _, line := range strings.Split(r.FormValue("urls"), "\n") {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		if !strings.HasPrefix(line, "http://") && !strings.HasPrefix(line, "https://") {
			line = "https://" + line
		}
		urls = append(urls, line)
	}
	if selected := r.Form["targets"]; len(selected) > 0 {
		urls = append(urls, selected...)
	}
	if len(urls) == 0 {
		http.Redirect(w, r, "/modules/cachepoison?error=no_urls", http.StatusSeeOther)
		return
	}

	// audit M3: reject runs that explicitly disabled both probe modes
	// rather than silently re-enabling them. Concurrency + per-request
	// timeout come from the shared http_tuning partial: applyHTTPTuning
	// sets opts.Timeout (override or global) and returns the effective
	// concurrency. The module reads cfg.Timeout for its HTTP client and
	// raw smuggling sockets, so mirror opts.Timeout into the config.
	opts := h.BuildHTTPOptions(r)
	conc, _ := h.applyHTTPTuning(r, opts)

	cfg := cachepoison.Config{
		URLs:        urls,
		TestPoison:  r.FormValue("test_poison") == "on",
		TestSmuggle: r.FormValue("test_smuggle") == "on",
		EvilHost:    strings.TrimSpace(r.FormValue("evil_host")),
		Concurrency: conc,
		Timeout:     opts.Timeout,
	}
	if !cfg.TestPoison && !cfg.TestSmuggle {
		http.Redirect(w, r, "/modules/cachepoison?error=no_probe_selected", http.StatusSeeOther)
		return
	}
	cfgJSON, _ := json.Marshal(cfg)
	scan, err := h.db.CreateScan(ws.ID, "cachepoison", string(cfgJSON), len(urls))
	if err != nil {
		http.Redirect(w, r, "/modules/cachepoison?error=db_error", http.StatusSeeOther)
		return
	}
	// Sequential scanning: if the operator ticked "start after the current
	// scan finishes" and this workspace is busy, park this run as queued.
	if h.queueIfSequential(w, r, scan) {
		return
	}
	go h.runCachePoison(scan.ID, cfg, opts)
	http.Redirect(w, r, "/modules/cachepoison/results/"+scan.ID, http.StatusSeeOther)
}

func (h *Handler) CachePoisonResults(w http.ResponseWriter, r *http.Request) {
	scanID := strings.TrimPrefix(r.URL.Path, "/modules/cachepoison/results/")
	scan, err := h.db.GetScan(scanID)
	if err != nil {
		http.NotFound(w, r)
		return
	}
	data := h.baseData(r, "Cache/Smuggle Results - scaNNer", "cachepoison_results")
	var result cachepoison.ScanResult
	json.Unmarshal([]byte(scan.Result), &result)
	totalFindings, totalProbes := 0, 0
	for _, ur := range result.Results {
		totalFindings += len(ur.Findings)
		totalProbes += ur.Tested
	}
	data["Scan"] = scan
	data["Results"] = result.Results
	data["TotalFindings"] = totalFindings
	data["TotalProbes"] = totalProbes
	h.renderResults(w, r, "cachepoison_results_inner", data)
}

func (h *Handler) CachePoisonStatus(w http.ResponseWriter, r *http.Request) {
	scanID := strings.TrimPrefix(r.URL.Path, "/modules/cachepoison/status/")
	scan, err := h.db.GetScan(scanID)
	if err != nil {
		http.NotFound(w, r)
		return
	}
	h.writeScanStatus(w, scan)
}

func (h *Handler) runCachePoison(scanID string, cfg cachepoison.Config, opts *shared.HTTPOptions) {
	if !h.db.MarkRunning(scanID) {
		return
	}
	opts = h.BeginScan(scanID, opts)
	defer h.FinishScan(scanID)

	// audit M1: canonical 2-second buffered partial flush — coalesces
	// snapshots so the DB UPDATE happens at most once per 2s regardless
	// of how fast the module fires partial(p) callbacks.
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

	result := cachepoison.Scan(opts.Ctx, cfg, opts,
		func(done int, msg string) { h.db.UpdateScanProgress(scanID, done, msg) },
		func(p *cachepoison.ScanResult) {
			b, err := json.Marshal(p)
			if err == nil {
				mu.Lock()
				latest = b
				mu.Unlock()
			}
		})

	resultJSON, _ := json.Marshal(result)
	h.db.UpdateScanResult(scanID, string(resultJSON))

	// Hard-failure surfacing: if every unit errored, mark the scan failed
	// with a translated reason rather than a silent "done" with zero findings.
	if opts.Ctx.Err() == nil {
		var errs []string
		for _, ur := range result.Results {
			if ur.Error != "" {
				errs = append(errs, ur.Error)
			}
		}
		h.markHardFailure(scanID, errs, len(cfg.URLs))
	}
}
