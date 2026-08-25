package handlers

import (
	"context"
	"encoding/json"
	"net/http"
	"strings"
	"sync"
	"time"

	"scanner/internal/models"
	"scanner/internal/modules/paramdisc"
	"scanner/internal/modules/shared"
)

type paramDiscConfig struct {
	URLs     []string `json:"urls"`
	Method   string   `json:"method"`
	Wordlist []string `json:"wordlist,omitempty"`
}

func (h *Handler) ParamDiscPage(w http.ResponseWriter, r *http.Request) {
	data := h.baseData(r, "Parameter Discovery - scaNNer", "paramdisc")
	ws := data["ActiveWorkspace"].(*models.Workspace)
	data["WSTargetGroups"] = h.groupTargetsByList(ws.ID)
	scans, _ := h.db.ListScansLite(ws.ID, "paramdisc")
	data["Scans"] = scans
	data["DefaultParams"] = strings.Join(paramdisc.DefaultParams, "\n")
	h.render(w, "layout", data)
}

func parseParamDiscForm(r *http.Request) paramDiscConfig {
	cfg := paramDiscConfig{}
	for _, line := range strings.Split(r.FormValue("urls"), "\n") {
		line = strings.TrimSpace(line)
		if line != "" {
			cfg.URLs = append(cfg.URLs, line)
		}
	}
	cfg.Method = strings.ToUpper(strings.TrimSpace(r.FormValue("method")))
	if cfg.Method == "" {
		cfg.Method = "GET"
	}
	for _, line := range strings.Split(r.FormValue("wordlist"), "\n") {
		line = strings.TrimSpace(line)
		if line != "" {
			cfg.Wordlist = append(cfg.Wordlist, line)
		}
	}
	return cfg
}

func (h *Handler) ParamDiscRun(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Redirect(w, r, "/modules/paramdisc", http.StatusSeeOther)
		return
	}
	r.ParseForm()
	ws := h.activeWorkspace(r)
	cfg := parseParamDiscForm(r)
	if selected := r.Form["targets"]; len(selected) > 0 {
		cfg.URLs = append(cfg.URLs, selected...)
	}
	if len(cfg.URLs) == 0 {
		http.Redirect(w, r, "/modules/paramdisc?error=no_urls", http.StatusSeeOther)
		return
	}
	opts := h.BuildHTTPOptions(r)
	conc, _ := h.applyHTTPTuning(r, opts)
	cfgJSON, _ := json.Marshal(cfg)
	// Audit: when Method == BOTH, the scanner loops GET + POST per URL and
	// increments done once per (URL, method) pair, so the denominator must
	// be doubled — otherwise the progress bar runs to 200%.
	totalUnits := len(cfg.URLs)
	if cfg.Method == "BOTH" {
		totalUnits *= 2
	}
	scan, err := h.db.CreateScan(ws.ID, "paramdisc", string(cfgJSON), totalUnits)
	if err != nil {
		http.Redirect(w, r, "/modules/paramdisc?error=db_error", http.StatusSeeOther)
		return
	}
	// Sequential scanning: if the operator ticked "start after the current
	// scan finishes" and this workspace is busy, park this run as queued.
	if h.queueIfSequential(w, r, scan) {
		return
	}
	go h.runParamDisc(scan.ID, cfg, opts, conc)
	http.Redirect(w, r, "/modules/paramdisc/results/"+scan.ID, http.StatusSeeOther)
}

func (h *Handler) ParamDiscResults(w http.ResponseWriter, r *http.Request) {
	scanID := strings.TrimPrefix(r.URL.Path, "/modules/paramdisc/results/")
	scan, err := h.db.GetScan(scanID)
	if err != nil {
		http.NotFound(w, r)
		return
	}
	data := h.baseData(r, "Parameter Discovery Results - scaNNer", "paramdisc_results")
	var result paramdisc.ScanResult
	json.Unmarshal([]byte(scan.Result), &result)
	totalHits := 0
	for _, tr := range result.Results {
		totalHits += len(tr.Hits)
	}
	data["Scan"] = scan
	data["Results"] = result.Results
	data["TotalHits"] = totalHits
	h.renderResults(w, r, "paramdisc_results_inner", data)
}

func (h *Handler) ParamDiscStatus(w http.ResponseWriter, r *http.Request) {
	scanID := strings.TrimPrefix(r.URL.Path, "/modules/paramdisc/status/")
	scan, err := h.db.GetScan(scanID)
	if err != nil {
		http.NotFound(w, r)
		return
	}
	h.writeScanStatus(w, scan)
}

// ctxAdapter satisfies the minimal interface paramdisc.Scan expects.
type ctxAdapter struct{ ctx context.Context }

func (c ctxAdapter) Done() <-chan struct{} { return c.ctx.Done() }
func (c ctxAdapter) Err() error            { return c.ctx.Err() }

func (h *Handler) runParamDisc(scanID string, cfg paramDiscConfig, opts *shared.HTTPOptions, conc int) {
	if !h.db.MarkRunning(scanID) {
		return
	}
	opts = h.BeginScan(scanID, opts)
	defer h.FinishScan(scanID)

	scanCfg := paramdisc.Config{
		URLs:        cfg.URLs,
		Method:      cfg.Method,
		Wordlist:    cfg.Wordlist,
		Concurrency: conc,
	}

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

	result := paramdisc.Scan(ctxAdapter{ctx: opts.Ctx}, scanCfg, opts,
		// Audit fix (F9): per-hit progress callbacks fire from worker
		// goroutines and can arrive dozens of times per target. Route
		// through the batched writer so we're not doing a synchronous
		// SQLite UPDATE per hit under 30-way concurrency. FinalizeScan
		// (called via FinishScan) drains the last batch.
		func(done int, msg string) { h.db.UpdateScanProgressBatched(scanID, done, msg) },
		func(p *paramdisc.ScanResult) {
			b, err := json.Marshal(p)
			if err == nil {
				mu.Lock()
				latest = b
				mu.Unlock()
			}
		})
	resJSON, _ := json.Marshal(result)
	h.db.UpdateScanResult(scanID, string(resJSON))

	// Hard-failure surfacing: if every attempted unit errored, mark the scan
	// failed with a translated reason rather than a silent "done" with zero
	// findings. totalUnits mirrors the CreateScan denominator — one unit per
	// URL, doubled when Method == BOTH probes GET + POST per URL.
	if opts.Ctx.Err() == nil {
		totalUnits := len(cfg.URLs)
		if cfg.Method == "BOTH" {
			totalUnits *= 2
		}
		var errs []string
		for _, tr := range result.Results {
			if tr.Error != "" {
				errs = append(errs, tr.Error)
			}
		}
		h.markHardFailure(scanID, errs, totalUnits)
	}
}
