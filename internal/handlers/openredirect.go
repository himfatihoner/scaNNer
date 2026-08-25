package handlers

import (
	"encoding/json"
	"net/http"
	"strings"
	"sync"
	"time"

	"scanner/internal/models"
	"scanner/internal/modules/openredirect"
	"scanner/internal/modules/shared"
)

func (h *Handler) OpenRedirectPage(w http.ResponseWriter, r *http.Request) {
	data := h.baseData(r, "Open Redirect - scaNNer", "openredirect")
	ws := data["ActiveWorkspace"].(*models.Workspace)
	scans, _ := h.db.ListScansLite(ws.ID, "openredirect")
	data["Scans"] = scans
	data["WSTargetGroups"] = h.groupTargetsByList(ws.ID)
	data["DefaultParams"] = strings.Join(openredirect.DefaultParams, ", ")
	h.render(w, "layout", data)
}

func (h *Handler) OpenRedirectRun(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Redirect(w, r, "/modules/openredirect", http.StatusSeeOther)
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
		http.Redirect(w, r, "/modules/openredirect?error=no_urls", http.StatusSeeOther)
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

	opts := h.BuildHTTPOptions(r)
	conc, _ := h.applyHTTPTuning(r, opts)

	cfg := openredirect.Config{
		URLs:        urls,
		Params:      params,
		EvilHost:    strings.TrimSpace(r.FormValue("evil_host")),
		Concurrency: conc,
		Timeout:     opts.Timeout,
		StopOnHit:   r.FormValue("stop_on_hit") == "on",
	}
	cfgJSON, _ := json.Marshal(cfg)
	scan, err := h.db.CreateScan(ws.ID, "openredirect", string(cfgJSON), len(urls))
	if err != nil {
		http.Redirect(w, r, "/modules/openredirect?error=db_error", http.StatusSeeOther)
		return
	}
	// Sequential scanning: if the operator ticked "start after the current
	// scan finishes" and this workspace is busy, park this run as queued.
	if h.queueIfSequential(w, r, scan) {
		return
	}
	go h.runOpenRedirect(scan.ID, cfg, opts)
	http.Redirect(w, r, "/modules/openredirect/results/"+scan.ID, http.StatusSeeOther)
}

func (h *Handler) OpenRedirectResults(w http.ResponseWriter, r *http.Request) {
	scanID := strings.TrimPrefix(r.URL.Path, "/modules/openredirect/results/")
	scan, err := h.db.GetScan(scanID)
	if err != nil {
		http.NotFound(w, r)
		return
	}
	data := h.baseData(r, "Open Redirect Results - scaNNer", "openredirect_results")
	var result openredirect.ScanResult
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
	h.renderResults(w, r, "openredirect_results_inner", data)
}

func (h *Handler) OpenRedirectStatus(w http.ResponseWriter, r *http.Request) {
	scanID := strings.TrimPrefix(r.URL.Path, "/modules/openredirect/status/")
	scan, err := h.db.GetScan(scanID)
	if err != nil {
		http.NotFound(w, r)
		return
	}
	h.writeScanStatus(w, scan)
}

func (h *Handler) runOpenRedirect(scanID string, cfg openredirect.Config, opts *shared.HTTPOptions) {
	if !h.db.MarkRunning(scanID) {
		return
	}
	opts = h.BeginScan(scanID, opts)
	defer h.FinishScan(scanID)

	// Canonical partial-flush pattern (mirrors smbenum.go): buffer the
	// most-recent marshalled snapshot under mu and flush at most once per
	// 2 seconds from a ticker. The scanner already throttles partial() to
	// 2s (audit S2) but this ticker keeps the DB write path off the hot
	// scanner goroutine and matches the framework contract from CLAUDE.md.
	var latest []byte
	var mu sync.Mutex
	doneCh := make(chan struct{})
	defer close(doneCh) // audit B20: panic-safe ticker shutdown
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

	result := openredirect.Scan(opts.Ctx, cfg, opts,
		func(done int, msg string) { h.db.UpdateScanProgress(scanID, done, msg) },
		func(p *openredirect.ScanResult) {
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
