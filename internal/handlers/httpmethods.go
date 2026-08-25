package handlers

import (
	"encoding/json"
	"net/http"
	"strings"
	"sync"
	"time"

	"scanner/internal/models"
	"scanner/internal/modules/httpmethods"
	"scanner/internal/modules/shared"
)

type HTTPMethodsConfig struct {
	URLs []string `json:"urls"`
	// Audit fix: persist the per-scan HTTP options so Restart replays the
	// same headers/cookies/UA instead of silently dropping them. Proxy +
	// NetworkInterface are intentionally NOT stored here — those are
	// Settings-driven and are reapplied by BuildHTTPOptionsFromSettings()
	// at restart time, so a Settings change is respected on re-run.
	Headers   map[string]string `json:"headers,omitempty"`
	Cookies   map[string]string `json:"cookies,omitempty"`
	UserAgent string            `json:"user_agent,omitempty"`
}

func (h *Handler) HTTPMethodsPage(w http.ResponseWriter, r *http.Request) {
	data := h.baseData(r, "HTTP Method Tester - scaNNer", "httpmethods")
	ws := data["ActiveWorkspace"].(*models.Workspace)
	data["WSTargetGroups"] = h.groupTargetsByList(ws.ID)
	scans, _ := h.db.ListScansLite(ws.ID, "httpmethods")
	data["Scans"] = scans
	h.render(w, "layout", data)
}

func (h *Handler) HTTPMethodsRun(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Redirect(w, r, "/modules/httpmethods", http.StatusSeeOther)
		return
	}
	ws := h.activeWorkspace(r)

	var urls []string
	raw := r.FormValue("urls")
	for _, line := range strings.Split(raw, "\n") {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		// Ensure URL has scheme
		if !strings.HasPrefix(line, "http://") && !strings.HasPrefix(line, "https://") {
			line = "http://" + line
		}
		urls = append(urls, line)
	}

	if selected := r.Form["targets"]; len(selected) > 0 {
		urls = append(urls, selected...)
	}

	if len(urls) == 0 {
		http.Redirect(w, r, "/modules/httpmethods?error=no_urls", http.StatusSeeOther)
		return
	}

	opts := h.BuildHTTPOptions(r)
	conc, _ := h.applyHTTPTuning(r, opts)

	cfg := HTTPMethodsConfig{URLs: urls}
	if opts != nil {
		cfg.Headers = opts.Headers
		cfg.Cookies = opts.Cookies
		cfg.UserAgent = opts.UserAgent
	}
	cfgJSON, _ := json.Marshal(cfg)
	totalTests := len(urls) * httpmethods.TotalTestsPerURL()
	scan, err := h.db.CreateScan(ws.ID, "httpmethods", string(cfgJSON), totalTests)
	if err != nil {
		http.Redirect(w, r, "/modules/httpmethods?error=db_error", http.StatusSeeOther)
		return
	}
	// Sequential scanning: if the operator ticked "start after the current
	// scan finishes" and this workspace is busy, park this run as queued.
	if h.queueIfSequential(w, r, scan) {
		return
	}

	go h.runHTTPMethods(scan.ID, urls, opts, conc)
	http.Redirect(w, r, "/modules/httpmethods/results/"+scan.ID, http.StatusSeeOther)
}

func (h *Handler) HTTPMethodsResults(w http.ResponseWriter, r *http.Request) {
	scanID := strings.TrimPrefix(r.URL.Path, "/modules/httpmethods/results/")
	if scanID == "" {
		http.Redirect(w, r, "/modules/httpmethods", http.StatusSeeOther)
		return
	}
	scan, err := h.db.GetScan(scanID)
	if err != nil {
		http.NotFound(w, r)
		return
	}

	data := h.baseData(r, "Method Test Results - scaNNer", "httpmethods_results")
	var result httpmethods.ScanResult
	json.Unmarshal([]byte(scan.Result), &result)

	// Count dangerous findings
	dangerousCount := 0
	for _, ur := range result.Results {
		for _, m := range ur.Methods {
			if m.Dangerous && m.Status == "Allowed" {
				dangerousCount++
			}
		}
	}

	data["Scan"] = scan
	data["Results"] = result.Results
	data["DangerousCount"] = dangerousCount
	h.renderResults(w, r, "httpmethods_results_inner", data)
}

func (h *Handler) HTTPMethodsStatus(w http.ResponseWriter, r *http.Request) {
	scanID := strings.TrimPrefix(r.URL.Path, "/modules/httpmethods/status/")
	scan, err := h.db.GetScan(scanID)
	if err != nil {
		http.NotFound(w, r)
		return
	}
	h.writeScanStatus(w, scan)
}

// conc is the effective concurrency resolved by applyHTTPTuning in the Run
// handler (which has the request). It is variadic so the Restart path in
// scan_control.go — which replays a stored config with no tuning form — can
// call this without a value and inherit the global Web default below.
func (h *Handler) runHTTPMethods(scanID string, urls []string, opts *shared.HTTPOptions, conc ...int) {
	if !h.db.MarkRunning(scanID) {
		return
	}
	opts = h.BeginScan(scanID, opts)
	defer h.FinishScan(scanID)

	// Periodic saver — reads the latest in-memory snapshot from the partial
	// callback and writes it to the DB every 2s so the result page can show
	// rows filling in live.
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

	effConc := h.db.GetSettings().EffectiveWebMaxConcurrent()
	if len(conc) > 0 {
		effConc = conc[0]
	}
	result := httpmethods.ScanWithPartial(urls, opts, effConc,
		func(done int, msg string) { h.db.UpdateScanProgress(scanID, done, msg) },
		func(p *httpmethods.ScanResult) {
			b, err := json.Marshal(p)
			if err == nil {
				mu.Lock()
				latest = b
				mu.Unlock()
			}
		})

	resultJSON, _ := json.Marshal(result)
	h.db.UpdateScanResult(scanID, string(resultJSON))

	// Hard-failure surfacing: if every URL was entirely unreachable (all of
	// its method probes errored — DNS, refused, timeout, scheme mismatch),
	// mark the scan failed with a translated reason rather than reporting a
	// silent "done" with zero findings. The per-unit error is nested one
	// level down in MethodResult.Error, so a URL counts as a failed unit only
	// when every probe against it errored; a reachable URL yields at least one
	// non-error status code and is skipped.
	if opts.Ctx.Err() == nil {
		var errs []string
		for _, ur := range result.Results {
			if len(ur.Methods) == 0 {
				continue
			}
			allErr := true
			firstErr := ""
			for _, m := range ur.Methods {
				if m.Error == "" {
					allErr = false
					break
				}
				if firstErr == "" {
					firstErr = m.Error
				}
			}
			if allErr {
				errs = append(errs, firstErr)
			}
		}
		h.markHardFailure(scanID, errs, len(urls))
	}
}
