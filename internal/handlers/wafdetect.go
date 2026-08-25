package handlers

import (
	"encoding/json"
	"net/http"
	"strings"
	"sync"
	"time"

	"scanner/internal/models"
	"scanner/internal/modules/shared"
	"scanner/internal/modules/wafdetect"
)

func (h *Handler) WAFDetectPage(w http.ResponseWriter, r *http.Request) {
	data := h.baseData(r, "WAF Detector - scaNNer", "wafdetect")
	ws := data["ActiveWorkspace"].(*models.Workspace)
	targets, _ := h.db.ListTargets(ws.ID, "")
	data["WSTargets"] = targets
	data["WSTargetGroups"] = h.groupTargetsByList(ws.ID)
	scans, _ := h.db.ListScansLite(ws.ID, "wafdetect")
	data["Scans"] = scans
	h.render(w, "layout", data)
}

func (h *Handler) WAFDetectRun(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Redirect(w, r, "/modules/wafdetect", http.StatusSeeOther)
		return
	}
	ws := h.activeWorkspace(r)

	var targets []string
	if manual := strings.TrimSpace(r.FormValue("manual_targets")); manual != "" {
		for _, line := range strings.Split(manual, "\n") {
			line = strings.TrimSpace(line)
			if line != "" {
				targets = append(targets, line)
			}
		}
	}
	if selected := r.Form["targets"]; len(selected) > 0 {
		targets = append(targets, selected...)
	}
	if len(targets) == 0 {
		http.Redirect(w, r, "/modules/wafdetect?error=no_targets", http.StatusSeeOther)
		return
	}
	// Expand CIDR/range entries so each host counts toward progress.
	targets = shared.ExpandTargets(targets, 1024)

	opts := h.BuildHTTPOptions(r)
	conc, _ := h.applyHTTPTuning(r, opts)

	// Per-scan HTTP tuning: applyHTTPTuning set opts.Timeout (override or the
	// global Web timeout) and returned the effective concurrency. Mirror both
	// into the module Config — this module reads its per-request timeout from
	// cfg.TimeoutSeconds (via cfg.timeout()), not opts.Timeout, so bridge it.
	cfg := wafdetect.Config{Targets: targets, EnablePayloads: true, Concurrency: conc}
	if opts != nil && opts.Timeout > 0 {
		cfg.TimeoutSeconds = int(opts.Timeout / time.Second)
	}
	// The form always renders a hidden enable_payloads_present sentinel; if
	// it is submitted without enable_payloads=1, the checkbox was unchecked.
	if r.FormValue("enable_payloads_present") == "1" && r.FormValue("enable_payloads") != "1" {
		cfg.EnablePayloads = false
	}
	// Audit fix: persist HTTP options in cfg so Restart replays the same
	// proxy / UA / headers / cookies / BurpSuccessOnly shape instead of
	// silently falling back to Settings-only defaults.
	if opts != nil {
		cfg.Headers = opts.Headers
		cfg.Cookies = opts.Cookies
		cfg.UserAgent = opts.UserAgent
		cfg.ProxyURL = opts.ProxyURL
		cfg.BurpSuccessOnly = opts.BurpSuccessOnly
	}
	cfgJSON, _ := json.Marshal(cfg)
	totalProbes := len(targets) * wafdetect.ProbesPerTargetFor(cfg)
	scan, err := h.db.CreateScan(ws.ID, "wafdetect", string(cfgJSON), totalProbes)
	if err != nil {
		http.Redirect(w, r, "/modules/wafdetect?error=db_error", http.StatusSeeOther)
		return
	}
	// Sequential scanning: if the operator ticked "start after the current
	// scan finishes" and this workspace is busy, park this run as queued.
	if h.queueIfSequential(w, r, scan) {
		return
	}

	go h.runWAFDetect(scan.ID, cfg, opts)
	http.Redirect(w, r, "/modules/wafdetect/results/"+scan.ID, http.StatusSeeOther)
}

func (h *Handler) WAFDetectResults(w http.ResponseWriter, r *http.Request) {
	scanID := strings.TrimPrefix(r.URL.Path, "/modules/wafdetect/results/")
	if scanID == "" {
		http.Redirect(w, r, "/modules/wafdetect", http.StatusSeeOther)
		return
	}
	scan, err := h.db.GetScan(scanID)
	if err != nil {
		http.NotFound(w, r)
		return
	}

	data := h.baseData(r, "WAF Results - scaNNer", "wafdetect_results")
	var result wafdetect.ScanResult
	json.Unmarshal([]byte(scan.Result), &result)

	wafCount := 0
	for _, tr := range result.Results {
		if tr.WAFDetected {
			wafCount++
		}
	}

	data["Scan"] = scan
	data["Results"] = result.Results
	data["WAFCount"] = wafCount
	h.renderResults(w, r, "wafdetect_results_inner", data)
}

func (h *Handler) WAFDetectStatus(w http.ResponseWriter, r *http.Request) {
	scanID := strings.TrimPrefix(r.URL.Path, "/modules/wafdetect/status/")
	scan, err := h.db.GetScan(scanID)
	if err != nil {
		http.NotFound(w, r)
		return
	}
	h.writeScanStatus(w, scan)
}

func (h *Handler) runWAFDetect(scanID string, cfg wafdetect.Config, opts *shared.HTTPOptions) {
	if !h.db.MarkRunning(scanID) {
		return
	}
	opts = h.BeginScan(scanID, opts)
	defer h.FinishScan(scanID)

	// Audit: 2-second partial-flush ticker so the results page streams in
	// each TargetResult as it completes instead of staying on "Waiting for
	// first results..." for the entire multi-minute scan.
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

	result := wafdetect.Scan(cfg, opts,
		func(done int, msg string) {
			h.db.UpdateScanProgress(scanID, done, msg)
		},
		func(p *wafdetect.ScanResult) {
			b, err := json.Marshal(p)
			if err == nil {
				mu.Lock()
				latest = b
				mu.Unlock()
			}
		})

	resultJSON, _ := json.Marshal(result)
	h.db.UpdateScanResult(scanID, string(resultJSON))

	// Hard-failure surfacing: if every target errored, mark the scan failed
	// with a translated reason rather than a silent "done" with zero findings.
	if opts.Ctx.Err() == nil {
		var errs []string
		for _, tr := range result.Results {
			if tr.Error != "" {
				errs = append(errs, tr.Error)
			}
		}
		h.markHardFailure(scanID, errs, len(cfg.Targets))
	}
}
