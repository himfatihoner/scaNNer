package handlers

import (
	"encoding/json"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"time"

	"scanner/internal/models"
	"scanner/internal/modules/concurtest"
	"scanner/internal/modules/shared"
)

func (h *Handler) ConcurTestPage(w http.ResponseWriter, r *http.Request) {
	data := h.baseData(r, "Concurrency Tester - scaNNer", "concurtest")
	ws := data["ActiveWorkspace"].(*models.Workspace)
	targets, _ := h.db.ListTargets(ws.ID, "")
	data["WSTargets"] = targets
	data["WSTargetGroups"] = h.groupTargetsByList(ws.ID)
	scans, _ := h.db.ListScansLite(ws.ID, "concurtest")
	data["Scans"] = scans
	h.render(w, "layout", data)
}

func (h *Handler) ConcurTestRun(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Redirect(w, r, "/modules/concurtest", http.StatusSeeOther)
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
		http.Redirect(w, r, "/modules/concurtest?error=no_targets", http.StatusSeeOther)
		return
	}

	cfg := concurtest.DefaultConfig()
	// Caps lifted to the C10K territory. Going past ~10 000 concurrent
	// connections from a single client typically hits ephemeral-port
	// exhaustion (~28 K usable, and TIME_WAIT halves that under churn)
	// and OS fd limits — past that point you need SO_REUSEPORT, multiple
	// source IPs, or a real load-gen tool (wrk2, vegeta, k6).
	if v, err := strconv.Atoi(r.FormValue("max_concurrency")); err == nil && v >= 2 && v <= 10000 {
		cfg.MaxConcurrency = v
	}
	if v, err := strconv.Atoi(r.FormValue("reqs_per_level")); err == nil && v >= 5 && v <= 200 {
		cfg.ReqsPerLevel = v
	}
	cfg.RunSustained = r.FormValue("run_sustained") == "on"
	if v, err := strconv.Atoi(r.FormValue("sustained_concurrency")); err == nil && v >= 0 && v <= 10000 {
		cfg.SustainedConcurrency = v
	}
	if v, err := strconv.Atoi(r.FormValue("sustained_duration")); err == nil && v >= 5 && v <= 300 {
		cfg.SustainedDurationSec = v
	}
	cfg.RunBurst = r.FormValue("run_burst") == "on"
	if v, err := strconv.Atoi(r.FormValue("burst_size")); err == nil && v >= 5 && v <= 1000 {
		cfg.BurstSize = v
	}
	if v, err := strconv.Atoi(r.FormValue("burst_count")); err == nil && v >= 1 && v <= 20 {
		cfg.BurstCount = v
	}
	if v, err := strconv.Atoi(r.FormValue("burst_idle")); err == nil && v >= 0 && v <= 30000 {
		cfg.BurstIdleMs = v
	}
	if mode := r.FormValue("probe_mode"); mode == "single" || mode == "varied" {
		cfg.ProbeMode = mode
	}
	// Method + body let users measure POST capacity (POST /api/search,
	// POST /graphql, POST /login). Whitelisted methods only — anything
	// else falls back to the default GET.
	if m := strings.ToUpper(strings.TrimSpace(r.FormValue("http_method"))); m != "" {
		switch m {
		case "GET", "POST", "PUT", "PATCH", "DELETE", "HEAD":
			cfg.Method = m
		}
	}
	if body := r.FormValue("http_body"); body != "" {
		cfg.Body = body
	}
	if ct := strings.TrimSpace(r.FormValue("http_content_type")); ct != "" {
		cfg.ContentType = ct
	}
	// ForceHTTP1 default = true; checkbox absence in POST means unchecked
	// only when the form was submitted (it always is here).
	cfg.ForceHTTP1 = r.FormValue("force_http1") == "on"

	opts := h.BuildHTTPOptions(r)

	cfgJSON, _ := json.Marshal(map[string]interface{}{
		"targets": targets,
		"config":  cfg,
	})

	// Coarse total-units count for the progress bar — same units the
	// scanner emits. Each ramp level is 1 unit, sustained is 1, burst is 1.
	// Share the scanner's RampLevels() so the count never drifts when
	// MaxConcurrency falls outside the preset list (which silently
	// appends an extra level).
	per := len(concurtest.RampLevels(cfg.MaxConcurrency))
	if per == 0 {
		per = 1
	}
	if cfg.RunSustained {
		per++
	}
	if cfg.RunBurst {
		per++
	}
	total := per * len(targets)

	scan, err := h.db.CreateScan(ws.ID, "concurtest", string(cfgJSON), total)
	if err != nil {
		http.Redirect(w, r, "/modules/concurtest?error=db_error", http.StatusSeeOther)
		return
	}

	go h.runConcurTest(scan.ID, targets, cfg, opts)
	http.Redirect(w, r, "/modules/concurtest/results/"+scan.ID, http.StatusSeeOther)
}

func (h *Handler) ConcurTestResults(w http.ResponseWriter, r *http.Request) {
	scanID := strings.TrimPrefix(r.URL.Path, "/modules/concurtest/results/")
	if scanID == "" {
		http.Redirect(w, r, "/modules/concurtest", http.StatusSeeOther)
		return
	}
	scan, err := h.db.GetScan(scanID)
	if err != nil {
		http.NotFound(w, r)
		return
	}
	data := h.baseData(r, "Concurrency Test Results - scaNNer", "concurtest_results")
	var result concurtest.ScanResult
	json.Unmarshal([]byte(scan.Result), &result)

	data["Scan"] = scan
	data["Results"] = result.Targets
	h.renderResults(w, r, "concurtest_results_inner", data)
}

func (h *Handler) ConcurTestStatus(w http.ResponseWriter, r *http.Request) {
	scanID := strings.TrimPrefix(r.URL.Path, "/modules/concurtest/status/")
	scan, err := h.db.GetScan(scanID)
	if err != nil {
		http.NotFound(w, r)
		return
	}
	h.writeScanStatus(w, scan)
}

func (h *Handler) runConcurTest(scanID string, targets []string, cfg concurtest.ScanConfig, opts *shared.HTTPOptions) {
	if !h.db.MarkRunning(scanID) {
		return
	}
	opts = h.BeginScan(scanID, opts)
	defer h.FinishScan(scanID)

	// Partial-flush ticker (canonical 2 s pattern; see smbenum.go:125).
	// Without this the result blob is only persisted once at the end —
	// a 5-minute sustained test shows an empty results page the entire
	// time and any crash / forced kill loses all in-progress data.
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

	result := concurtest.Scan(targets, cfg, opts,
		func(done, total int, msg string) {
			h.db.UpdateScanProgressFull(scanID, done, total, msg)
		},
		func(snap *concurtest.ScanResult) {
			b, err := json.Marshal(snap)
			if err == nil {
				mu.Lock()
				latest = b
				mu.Unlock()
			}
		})

	resultJSON, _ := json.Marshal(result)
	h.db.UpdateScanResult(scanID, string(resultJSON))

	// Hard-failure surfacing: if every target errored (all unreachable, DNS,
	// scheme mismatch, etc.), mark the scan failed with a translated reason
	// rather than reporting a silent "done" with zero findings.
	if opts.Ctx.Err() == nil {
		var errs []string
		for _, tr := range result.Targets {
			if tr.Error != "" {
				errs = append(errs, tr.Error)
			}
		}
		h.markHardFailure(scanID, errs, len(targets))
	}
}
