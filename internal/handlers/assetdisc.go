package handlers

import (
	"encoding/json"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"time"

	"scanner/internal/models"
	"scanner/internal/modules/assetdisc"
	"scanner/internal/modules/shared"
)

func (h *Handler) AssetDiscPage(w http.ResponseWriter, r *http.Request) {
	data := h.baseData(r, "Asset Discovery - scaNNer", "assetdisc")
	ws := data["ActiveWorkspace"].(*models.Workspace)
	scans, _ := h.db.ListScansLite(ws.ID, "assetdisc")
	data["Scans"] = scans
	settings := h.db.GetSettings()
	data["HasShodanKey"] = settings.ShodanAPIKey != ""
	data["HasCensysKey"] = settings.CensysID != "" && settings.CensysSecret != ""
	h.render(w, "layout", data)
}

func (h *Handler) AssetDiscRun(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Redirect(w, r, "/modules/assetdisc", http.StatusSeeOther)
		return
	}
	r.ParseForm()
	ws := h.activeWorkspace(r)

	var queries []string
	for _, line := range strings.Split(r.FormValue("queries"), "\n") {
		line = strings.TrimSpace(line)
		if line != "" {
			queries = append(queries, line)
		}
	}
	if len(queries) == 0 {
		http.Redirect(w, r, "/modules/assetdisc?error=no_queries", http.StatusSeeOther)
		return
	}

	settings := h.db.GetSettings()
	// Audit M1: expose MaxPages so paid Shodan/Censys plans can page beyond
	// the first 100 hits. Default 1 preserves the historical behavior and
	// avoids burning query credits by accident.
	maxPages := 1
	if v := strings.TrimSpace(r.FormValue("max_pages")); v != "" {
		if n, err := strconv.Atoi(v); err == nil && n >= 1 && n <= 20 {
			maxPages = n
		}
	}
	maxPerQuery := 100 * maxPages
	opts := h.BuildHTTPOptions(r)
	// Per-scan HTTP tuning: applyHTTPTuning sets opts.Timeout from the operator
	// override (req_timeout) or the global Web timeout. assetdisc has no
	// concurrency knob, so the returned concurrency/rate are discarded; only the
	// timeout is honored — fed into cfg.Timeout, which drives its HTTP client.
	h.applyHTTPTuning(r, opts)
	cfg := assetdisc.Config{
		Queries:      queries,
		UseShodan:    r.FormValue("use_shodan") == "on",
		UseCensys:    r.FormValue("use_censys") == "on",
		ShodanKey:    settings.ShodanAPIKey,
		CensysID:     settings.CensysID,
		CensysSecret: settings.CensysSecret,
		MaxPerQuery:  maxPerQuery,
		MaxPages:     maxPages,
		Timeout:      opts.Timeout,
	}
	srcCount := 0
	if cfg.UseShodan {
		srcCount++
	}
	if cfg.UseCensys {
		srcCount++
	}
	if srcCount == 0 {
		http.Redirect(w, r, "/modules/assetdisc?error=no_sources", http.StatusSeeOther)
		return
	}
	cfgJSON, _ := json.Marshal(cfg)
	total := len(queries) * srcCount
	scan, err := h.db.CreateScan(ws.ID, "assetdisc", string(cfgJSON), total)
	if err != nil {
		http.Redirect(w, r, "/modules/assetdisc?error=db_error", http.StatusSeeOther)
		return
	}
	// Sequential scanning: if the operator ticked "start after the current
	// scan finishes" and this workspace is busy, park this run as queued.
	if h.queueIfSequential(w, r, scan) {
		return
	}
	go h.runAssetDisc(scan.ID, cfg, opts)
	http.Redirect(w, r, "/modules/assetdisc/results/"+scan.ID, http.StatusSeeOther)
}

func (h *Handler) AssetDiscResults(w http.ResponseWriter, r *http.Request) {
	scanID := strings.TrimPrefix(r.URL.Path, "/modules/assetdisc/results/")
	scan, err := h.db.GetScan(scanID)
	if err != nil {
		http.NotFound(w, r)
		return
	}
	data := h.baseData(r, "Asset Discovery Results - scaNNer", "assetdisc_results")
	var result assetdisc.ScanResult
	json.Unmarshal([]byte(scan.Result), &result)

	total := 0
	for _, q := range result.Queries {
		total += len(q.Assets)
	}
	data["Scan"] = scan
	data["Queries"] = result.Queries
	data["TotalAssets"] = total
	if p := r.URL.Query().Get("promoted"); p != "" {
		if n, err := strconv.Atoi(p); err == nil && n > 0 {
			data["Promoted"] = n
		}
	}
	h.renderResults(w, r, "assetdisc_results_inner", data)
}

// AssetDiscPromote takes selected IPs/hostnames from the results table and
// adds them to the active workspace as targets. Audit M2: previously the
// results page was display-only, killing the recon→scan pivot workflow.
func (h *Handler) AssetDiscPromote(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Redirect(w, r, "/modules/assetdisc", http.StatusSeeOther)
		return
	}
	r.ParseForm()
	scanID := strings.TrimSpace(r.FormValue("scan_id"))
	if scanID == "" {
		http.Error(w, "missing scan_id", http.StatusBadRequest)
		return
	}
	ws := h.activeWorkspace(r)
	selected := r.Form["asset"] // repeated form field; one entry per checked row
	note := "assetdisc " + scanID
	added := 0
	seen := map[string]bool{}
	for _, raw := range selected {
		raw = strings.TrimSpace(raw)
		if raw == "" || seen[raw] {
			continue
		}
		seen[raw] = true
		ci, err := shared.ClassifyInput(raw)
		if err != nil {
			continue
		}
		var t models.TargetType
		switch ci.Kind {
		case shared.KindIP:
			t = models.TargetIPv4
		case shared.KindDomain:
			t = models.TargetDomain
		case shared.KindURL:
			t = models.TargetURL
		default:
			continue
		}
		if _, err := h.db.CreateTarget(ws.ID, ci.Raw, t, note); err == nil {
			added++
		}
	}
	http.Redirect(w, r, "/modules/assetdisc/results/"+scanID+"?promoted="+strconv.Itoa(added), http.StatusSeeOther)
}

func (h *Handler) AssetDiscStatus(w http.ResponseWriter, r *http.Request) {
	scanID := strings.TrimPrefix(r.URL.Path, "/modules/assetdisc/status/")
	scan, err := h.db.GetScan(scanID)
	if err != nil {
		http.NotFound(w, r)
		return
	}
	h.writeScanStatus(w, scan)
}

func (h *Handler) runAssetDisc(scanID string, cfg assetdisc.Config, opts *shared.HTTPOptions) {
	if !h.db.MarkRunning(scanID) {
		return
	}
	opts = h.BeginScan(scanID, opts)
	defer h.FinishScan(scanID)

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

	result := assetdisc.Scan(opts.Ctx, cfg, opts,
		func(done int, msg string) { h.db.UpdateScanProgress(scanID, done, msg) },
		func(p *assetdisc.ScanResult) {
			b, err := json.Marshal(p)
			if err == nil {
				mu.Lock()
				latest = b
				mu.Unlock()
			}
		})

	resultJSON, _ := json.Marshal(result)
	h.db.UpdateScanResult(scanID, string(resultJSON))

	// Hard-failure surfacing: if every (query × source) unit errored, mark the
	// scan failed with a translated reason rather than a silent "done" with
	// zero findings.
	if opts.Ctx.Err() == nil {
		var errs []string
		for _, u := range result.Queries {
			if u.Error != "" {
				errs = append(errs, u.Error)
			}
		}
		srcCount := 0
		if cfg.UseShodan {
			srcCount++
		}
		if cfg.UseCensys {
			srcCount++
		}
		h.markHardFailure(scanID, errs, len(cfg.Queries)*srcCount)
	}
}
