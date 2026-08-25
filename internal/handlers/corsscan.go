package handlers

import (
	"encoding/json"
	"net/http"
	"strings"
	"sync"
	"time"

	"scanner/internal/models"
	"scanner/internal/modules/corsscan"
	"scanner/internal/modules/shared"
)

func (h *Handler) CORSScanPage(w http.ResponseWriter, r *http.Request) {
	data := h.baseData(r, "CORS Misconfig - scaNNer", "corsscan")
	ws := data["ActiveWorkspace"].(*models.Workspace)
	data["WSTargetGroups"] = h.groupTargetsByList(ws.ID)
	scans, _ := h.db.ListScansLite(ws.ID, "corsscan")
	data["Scans"] = scans
	h.render(w, "layout", data)
}

func (h *Handler) CORSScanRun(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Redirect(w, r, "/modules/corsscan", http.StatusSeeOther)
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
		for _, line := range selected {
			line = strings.TrimSpace(line)
			if line == "" {
				continue
			}
			if !strings.HasPrefix(line, "http://") && !strings.HasPrefix(line, "https://") {
				line = "https://" + line
			}
			urls = append(urls, line)
		}
	}
	if len(urls) == 0 {
		http.Redirect(w, r, "/modules/corsscan?error=no_urls", http.StatusSeeOther)
		return
	}

	opts := h.BuildHTTPOptions(r)
	conc, _ := h.applyHTTPTuning(r, opts)

	cfg := corsscan.Config{URLs: urls, Concurrency: conc, Timeout: opts.Timeout}
	cfgJSON, _ := json.Marshal(cfg)
	scan, err := h.db.CreateScan(ws.ID, "corsscan", string(cfgJSON), len(urls))
	if err != nil {
		http.Redirect(w, r, "/modules/corsscan?error=db_error", http.StatusSeeOther)
		return
	}
	// Sequential scanning: if the operator ticked "start after the current
	// scan finishes" and this workspace is busy, park this run as queued.
	if h.queueIfSequential(w, r, scan) {
		return
	}
	go h.runCORSScan(scan.ID, cfg, opts)
	http.Redirect(w, r, "/modules/corsscan/results/"+scan.ID, http.StatusSeeOther)
}

func (h *Handler) CORSScanResults(w http.ResponseWriter, r *http.Request) {
	scanID := strings.TrimPrefix(r.URL.Path, "/modules/corsscan/results/")
	scan, err := h.db.GetScan(scanID)
	if err != nil {
		http.NotFound(w, r)
		return
	}
	data := h.baseData(r, "CORS Results - scaNNer", "corsscan_results")
	var result corsscan.ScanResult
	json.Unmarshal([]byte(scan.Result), &result)
	totalFindings := 0
	for _, ur := range result.Results {
		totalFindings += len(ur.Findings)
	}
	data["Scan"] = scan
	data["Results"] = result.Results
	data["TotalFindings"] = totalFindings
	h.renderResults(w, r, "corsscan_results_inner", data)
}

func (h *Handler) CORSScanStatus(w http.ResponseWriter, r *http.Request) {
	scanID := strings.TrimPrefix(r.URL.Path, "/modules/corsscan/status/")
	scan, err := h.db.GetScan(scanID)
	if err != nil {
		http.NotFound(w, r)
		return
	}
	h.writeScanStatus(w, scan)
}

func (h *Handler) runCORSScan(scanID string, cfg corsscan.Config, opts *shared.HTTPOptions) {
	if !h.db.MarkRunning(scanID) {
		return
	}
	opts = h.BeginScan(scanID, opts)
	defer h.FinishScan(scanID)

	// Audit MEDIUM fix: buffer the latest partial snapshot and flush every
	// 2s via a single ticker goroutine instead of issuing a synchronous
	// UpdateScanResult on every URL completion (which generated N SQLite
	// writes per scan, with each blob growing — O(N^2) bytes through WAL).
	// Mirrors the canonical pattern in runSMBEnum.
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

	result := corsscan.Scan(opts.Ctx, cfg, opts,
		func(done int, msg string) { h.db.UpdateScanProgress(scanID, done, msg) },
		func(p *corsscan.ScanResult) {
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
