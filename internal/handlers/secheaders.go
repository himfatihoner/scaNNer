package handlers

import (
	"encoding/json"
	"net/http"
	"strings"

	"scanner/internal/models"
	"scanner/internal/modules/secheaders"
	"scanner/internal/modules/shared"
)

func (h *Handler) SecHeadersPage(w http.ResponseWriter, r *http.Request) {
	data := h.baseData(r, "Security Headers - scaNNer", "secheaders")
	ws := data["ActiveWorkspace"].(*models.Workspace)
	data["WSTargetGroups"] = h.groupTargetsByList(ws.ID)
	scans, _ := h.db.ListScansLite(ws.ID, "secheaders")
	data["Scans"] = scans
	h.render(w, "layout", data)
}

func (h *Handler) SecHeadersRun(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Redirect(w, r, "/modules/secheaders", http.StatusSeeOther)
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
		http.Redirect(w, r, "/modules/secheaders?error=no_urls", http.StatusSeeOther)
		return
	}

	// HTTP methods to test. The scanner expands each into the relevant
	// content-type variants (POST/PUT/PATCH each have several JSON / form
	// variants). Default = GET + POST when nothing checked.
	methods := r.Form["methods"]
	if len(methods) == 0 {
		methods = []string{"GET"}
	}

	opts := h.BuildHTTPOptions(r)
	conc, _ := h.applyHTTPTuning(r, opts)

	// Audit fix: persist the per-scan Headers/Cookies (and the user's
	// proxy / UA preference) so Restart can rebuild the same request
	// mix instead of silently falling back to defaults. Settings-derived
	// fields (proxy URL, killswitch binding) re-derive from current
	// Settings at restart time, which is intentional — only per-scan
	// extras need to be persisted here.
	cfgMap := map[string]interface{}{
		"urls":    urls,
		"methods": methods,
	}
	if opts != nil {
		if len(opts.Headers) > 0 {
			cfgMap["http_headers"] = opts.Headers
		}
		if len(opts.Cookies) > 0 {
			cfgMap["http_cookies"] = opts.Cookies
		}
		if opts.UserAgent != "" {
			cfgMap["user_agent"] = opts.UserAgent
		}
	}
	cfgJSON, _ := json.Marshal(cfgMap)
	totalProbes := len(urls) * secheaders.ProbesForMethods(methods)
	scan, _ := h.db.CreateScan(ws.ID, "secheaders", string(cfgJSON), totalProbes)
	// Sequential scanning: if the operator ticked "start after the current
	// scan finishes" and this workspace is busy, park this run as queued.
	if h.queueIfSequential(w, r, scan) {
		return
	}

	go h.runSecHeaders(scan.ID, urls, methods, opts, conc)
	http.Redirect(w, r, "/modules/secheaders/results/"+scan.ID, http.StatusSeeOther)
}

func (h *Handler) SecHeadersResults(w http.ResponseWriter, r *http.Request) {
	scanID := strings.TrimPrefix(r.URL.Path, "/modules/secheaders/results/")
	scan, err := h.db.GetScan(scanID)
	if err != nil {
		http.NotFound(w, r)
		return
	}
	data := h.baseData(r, "Header Results - scaNNer", "secheaders_results")
	var result secheaders.ScanResult
	json.Unmarshal([]byte(scan.Result), &result)
	data["Scan"] = scan
	data["Results"] = result.Results
	h.renderResults(w, r, "secheaders_results_inner", data)
}

func (h *Handler) SecHeadersStatus(w http.ResponseWriter, r *http.Request) {
	scanID := strings.TrimPrefix(r.URL.Path, "/modules/secheaders/status/")
	scan, err := h.db.GetScan(scanID)
	if err != nil {
		http.NotFound(w, r)
		return
	}
	h.writeScanStatus(w, scan)
}

func (h *Handler) runSecHeaders(scanID string, urls []string, methods []string, opts *shared.HTTPOptions, conc int) {
	if !h.db.MarkRunning(scanID) {
		return
	}
	opts = h.BeginScan(scanID, opts)
	defer h.FinishScan(scanID)
	// Audit fix: persist partial snapshots so a long scan doesn't blank
	// the results page mid-run and a cancel/crash doesn't drop completed
	// URL data. The scanner already throttles to 2s.
	partialFn := func(snap *secheaders.ScanResult) {
		if js, err := json.Marshal(snap); err == nil {
			h.db.UpdateScanResult(scanID, string(js))
		}
	}
	result := secheaders.Scan(urls, opts, conc, methods, func(done int, msg string) {
		h.db.UpdateScanProgress(scanID, done, msg)
	}, partialFn)
	resultJSON, _ := json.Marshal(result)
	h.db.UpdateScanResult(scanID, string(resultJSON))
}
