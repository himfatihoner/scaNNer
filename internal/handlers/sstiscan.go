package handlers

import (
	"encoding/json"
	"net/http"
	"strings"
	"sync"
	"time"

	"scanner/internal/models"
	"scanner/internal/modules/shared"
	"scanner/internal/modules/sstiscan"
)

func (h *Handler) SSTIScanPage(w http.ResponseWriter, r *http.Request) {
	data := h.baseData(r, "SSTI Probe - scaNNer", "sstiscan")
	ws := data["ActiveWorkspace"].(*models.Workspace)
	data["WSTargetGroups"] = h.groupTargetsByList(ws.ID)
	scans, _ := h.db.ListScansLite(ws.ID, "sstiscan")
	data["Scans"] = scans
	h.render(w, "layout", data)
}

func (h *Handler) SSTIScanRun(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Redirect(w, r, "/modules/sstiscan", http.StatusSeeOther)
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
		http.Redirect(w, r, "/modules/sstiscan?error=no_urls", http.StatusSeeOther)
		return
	}

	var params []string
	if extra := strings.TrimSpace(r.FormValue("params")); extra != "" {
		for _, p := range strings.Split(extra, ",") {
			p = strings.TrimSpace(p)
			if p != "" {
				params = append(params, p)
			}
		}
	}

	method := strings.ToUpper(strings.TrimSpace(r.FormValue("method")))
	switch method {
	case "GET", "POST", "BOTH":
	default:
		method = "GET"
	}

	var injectHeaders []string
	if raw := strings.TrimSpace(r.FormValue("inject_headers")); raw != "" {
		for _, h := range strings.Split(raw, ",") {
			h = strings.TrimSpace(h)
			if h != "" {
				injectHeaders = append(injectHeaders, h)
			}
		}
	}

	opts := h.BuildHTTPOptions(r)
	// Per-scan HTTP tuning: sets opts.Timeout (override or global Web
	// default) and returns the effective concurrency. Blank inputs inherit
	// Settings. The rate-limit return is unused — SSTI has no rate knob.
	conc, _ := h.applyHTTPTuning(r, opts)

	cfg := sstiscan.Config{
		URLs:          urls,
		Params:        params,
		Concurrency:   conc,
		Timeout:       opts.Timeout,
		Method:        method,
		InjectHeaders: injectHeaders,
	}
	cfgJSON, _ := json.Marshal(cfg)
	// Audit MEDIUM fix: total must match what Scan reports via progress().
	// scanner.go emits progress(done, ...) where done is the URL counter
	// (one increment per URL, not per engine), so the denominator has to
	// be len(urls). Previously len(urls)*len(Engines) made the bar stall
	// at ~1/len(Engines) of real progress and jump to 100% only when
	// writeScanStatus clamped on Status=done.
	total := len(urls)
	scan, err := h.db.CreateScan(ws.ID, "sstiscan", string(cfgJSON), total)
	if err != nil {
		http.Redirect(w, r, "/modules/sstiscan?error=db_error", http.StatusSeeOther)
		return
	}
	// Sequential scanning: if the operator ticked "start after the current
	// scan finishes" and this workspace is busy, park this run as queued.
	if h.queueIfSequential(w, r, scan) {
		return
	}
	go h.runSSTIScan(scan.ID, cfg, opts)
	http.Redirect(w, r, "/modules/sstiscan/results/"+scan.ID, http.StatusSeeOther)
}

func (h *Handler) SSTIScanResults(w http.ResponseWriter, r *http.Request) {
	scanID := strings.TrimPrefix(r.URL.Path, "/modules/sstiscan/results/")
	scan, err := h.db.GetScan(scanID)
	if err != nil {
		http.NotFound(w, r)
		return
	}
	data := h.baseData(r, "SSTI Results - scaNNer", "sstiscan_results")
	var result sstiscan.ScanResult
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
	h.renderResults(w, r, "sstiscan_results_inner", data)
}

func (h *Handler) SSTIScanStatus(w http.ResponseWriter, r *http.Request) {
	scanID := strings.TrimPrefix(r.URL.Path, "/modules/sstiscan/status/")
	scan, err := h.db.GetScan(scanID)
	if err != nil {
		http.NotFound(w, r)
		return
	}
	h.writeScanStatus(w, scan)
}

func (h *Handler) runSSTIScan(scanID string, cfg sstiscan.Config, opts *shared.HTTPOptions) {
	if !h.db.MarkRunning(scanID) {
		return
	}
	opts = h.BeginScan(scanID, opts)
	defer h.FinishScan(scanID)

	// Audit MEDIUM fix: canonical 2-second ticker pattern (see
	// smbenum.go:169-189). Previously the partial callback did a
	// synchronous json.Marshal + SQLite UPDATE per URL completion,
	// which serialised the scanner's goroutines through the DB write.
	// Now the callback only stashes the latest marshaled bytes under a
	// mutex; a background ticker flushes them every 2s, and doneCh
	// stops the ticker on return (panic-safe via defer close).
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

	result := sstiscan.Scan(opts.Ctx, cfg, opts,
		func(done int, msg string) { h.db.UpdateScanProgress(scanID, done, msg) },
		func(p *sstiscan.ScanResult) {
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
		for _, u := range result.Results {
			if u.Error != "" {
				errs = append(errs, u.Error)
			}
		}
		h.markHardFailure(scanID, errs, len(cfg.URLs))
	}
}
