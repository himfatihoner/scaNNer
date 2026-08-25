package handlers

import (
	"encoding/json"
	"net/http"
	"strings"
	"sync"
	"time"

	"scanner/internal/models"
	"scanner/internal/modules/graphqlscan"
	"scanner/internal/modules/shared"
)

func (h *Handler) GraphQLScanPage(w http.ResponseWriter, r *http.Request) {
	data := h.baseData(r, "GraphQL Scanner - scaNNer", "graphqlscan")
	ws := data["ActiveWorkspace"].(*models.Workspace)
	scans, _ := h.db.ListScansLite(ws.ID, "graphqlscan")
	data["Scans"] = scans
	data["WSTargetGroups"] = h.groupTargetsByList(ws.ID)
	data["CommonEndpoints"] = strings.Join(graphqlscan.CommonEndpoints, ", ")
	h.render(w, "layout", data)
}

func (h *Handler) GraphQLScanRun(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Redirect(w, r, "/modules/graphqlscan", http.StatusSeeOther)
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
		http.Redirect(w, r, "/modules/graphqlscan?error=no_urls", http.StatusSeeOther)
		return
	}

	var custom []string
	if extra := strings.TrimSpace(r.FormValue("custom_endpoints")); extra != "" {
		for _, line := range strings.Split(extra, "\n") {
			line = strings.TrimSpace(line)
			if line != "" {
				custom = append(custom, line)
			}
		}
	}

	opts := h.BuildHTTPOptions(r)
	// Per-scan HTTP tuning: sets opts.Timeout (override or global Web default)
	// and returns the effective concurrency. Blank inputs inherit Settings.
	// The rate-limit return is unused — GraphQL scan has no rate knob.
	conc, _ := h.applyHTTPTuning(r, opts)

	cfg := graphqlscan.Config{
		BaseURLs:        urls,
		CustomEndpoints: custom,
		Concurrency:     conc,
		Timeout:         opts.Timeout,
	}
	cfgJSON, _ := json.Marshal(cfg)

	// Estimate total candidates so progress bar makes sense.
	totalCandidates := 0
	for range urls {
		if len(custom) > 0 {
			totalCandidates += len(custom)
		} else {
			totalCandidates += len(graphqlscan.CommonEndpoints)
		}
	}

	scan, err := h.db.CreateScan(ws.ID, "graphqlscan", string(cfgJSON), totalCandidates)
	if err != nil {
		http.Redirect(w, r, "/modules/graphqlscan?error=db_error", http.StatusSeeOther)
		return
	}
	// Sequential scanning: if the operator ticked "start after the current
	// scan finishes" and this workspace is busy, park this run as queued.
	if h.queueIfSequential(w, r, scan) {
		return
	}
	go h.runGraphQLScan(scan.ID, cfg, opts)
	http.Redirect(w, r, "/modules/graphqlscan/results/"+scan.ID, http.StatusSeeOther)
}

func (h *Handler) GraphQLScanResults(w http.ResponseWriter, r *http.Request) {
	scanID := strings.TrimPrefix(r.URL.Path, "/modules/graphqlscan/results/")
	scan, err := h.db.GetScan(scanID)
	if err != nil {
		http.NotFound(w, r)
		return
	}
	data := h.baseData(r, "GraphQL Results - scaNNer", "graphqlscan_results")
	var result graphqlscan.ScanResult
	json.Unmarshal([]byte(scan.Result), &result)

	gqlCount, findingsCount := 0, 0
	for _, e := range result.Endpoints {
		if e.IsGraphQL {
			gqlCount++
		}
		findingsCount += len(e.Findings)
	}
	data["Scan"] = scan
	data["Endpoints"] = result.Endpoints
	data["GQLCount"] = gqlCount
	data["FindingsCount"] = findingsCount
	h.renderResults(w, r, "graphqlscan_results_inner", data)
}

func (h *Handler) GraphQLScanStatus(w http.ResponseWriter, r *http.Request) {
	scanID := strings.TrimPrefix(r.URL.Path, "/modules/graphqlscan/status/")
	scan, err := h.db.GetScan(scanID)
	if err != nil {
		http.NotFound(w, r)
		return
	}
	h.writeScanStatus(w, scan)
}

func (h *Handler) runGraphQLScan(scanID string, cfg graphqlscan.Config, opts *shared.HTTPOptions) {
	if !h.db.MarkRunning(scanID) {
		return
	}
	opts = h.BeginScan(scanID, opts)
	defer h.FinishScan(scanID)

	// Canonical 2s flush ticker (matches smbenum.go:148-181). The partial
	// callback only updates the in-memory `latest` snapshot under a mutex; a
	// single goroutine flushes the most recent bytes every 2s, so a scan
	// with N probes does at most one DB write per 2s instead of one per probe.
	var latest []byte
	var mu sync.Mutex
	doneCh := make(chan struct{})
	defer close(doneCh) // panic-safe ticker shutdown
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

	result := graphqlscan.Scan(opts.Ctx, cfg, opts,
		func(done int, msg string) { h.db.UpdateScanProgress(scanID, done, msg) },
		func(p *graphqlscan.ScanResult) {
			b, err := json.Marshal(p)
			if err == nil {
				mu.Lock()
				latest = b
				mu.Unlock()
			}
		})

	resultJSON, _ := json.Marshal(result)
	h.db.UpdateScanResult(scanID, string(resultJSON))

	// Hard-failure surfacing: if every probed endpoint errored, mark the scan
	// failed with a translated reason rather than a silent "done" with zero
	// findings.
	if opts.Ctx.Err() == nil {
		var errs []string
		for _, e := range result.Endpoints {
			if e.Error != "" {
				errs = append(errs, e.Error)
			}
		}
		h.markHardFailure(scanID, errs, len(result.Endpoints))
	}
}
