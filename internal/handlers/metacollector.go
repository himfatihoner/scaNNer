package handlers

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"time"

	"scanner/internal/models"
	"scanner/internal/modules/metacollector"
)

// metaCollectorConfig is the persisted launch form (replayed by Restart).
type metaCollectorConfig struct {
	Domains     []string `json:"domains"`
	Split       bool     `json:"split"`
	Timeout     int      `json:"timeout,omitempty"`     // request timeout, seconds (0 = inherit Web default)
	Concurrency int      `json:"concurrency,omitempty"` // download workers (0 = inherit Web default)
}

func (h *Handler) MetaCollectorPage(w http.ResponseWriter, r *http.Request) {
	data := h.baseData(r, "Google Metadata Collector - scaNNer", "metacollector")
	ws := data["ActiveWorkspace"].(*models.Workspace)
	scans, _ := h.db.ListScansLite(ws.ID, "metacollector")
	data["Scans"] = scans
	data["HasSerperKey"] = strings.TrimSpace(h.db.GetSettings().SerperAPIKey) != ""
	data["Filetypes"] = metacollector.DefaultFiletypes
	h.render(w, "layout", data)
}

func parseMetaCollectorForm(r *http.Request) metaCollectorConfig {
	cfg := metaCollectorConfig{}
	for _, line := range strings.Split(r.FormValue("domains"), "\n") {
		if d := strings.TrimSpace(line); d != "" {
			cfg.Domains = append(cfg.Domains, d)
		}
	}
	cfg.Split = r.FormValue("split") == "on"
	return cfg
}

func (h *Handler) MetaCollectorRun(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Redirect(w, r, "/modules/metacollector", http.StatusSeeOther)
		return
	}
	r.ParseForm()
	// Hard gate: the module cannot run without a Serper API key.
	if strings.TrimSpace(h.db.GetSettings().SerperAPIKey) == "" {
		http.Redirect(w, r, "/modules/metacollector?error=no_serper_key", http.StatusSeeOther)
		return
	}
	ws := h.activeWorkspace(r)
	cfg := parseMetaCollectorForm(r)
	if len(cfg.Domains) == 0 {
		http.Redirect(w, r, "/modules/metacollector?error=no_domains", http.StatusSeeOther)
		return
	}
	opts := h.BuildHTTPOptions(r)
	conc, _ := h.applyHTTPTuning(r, opts)
	cfg.Concurrency = conc
	cfg.Timeout = int(opts.Timeout / time.Second)
	cfgJSON, _ := json.Marshal(cfg)
	scan, err := h.db.CreateScan(ws.ID, "metacollector", string(cfgJSON), len(cfg.Domains))
	if err != nil {
		http.Redirect(w, r, "/modules/metacollector?error=db_error", http.StatusSeeOther)
		return
	}
	if h.queueIfSequential(w, r, scan) {
		return
	}
	go h.runMetaCollector(scan.ID, cfg)
	http.Redirect(w, r, "/modules/metacollector/results/"+scan.ID, http.StatusSeeOther)
}

func (h *Handler) MetaCollectorResults(w http.ResponseWriter, r *http.Request) {
	scanID := strings.TrimPrefix(r.URL.Path, "/modules/metacollector/results/")
	scan, err := h.db.GetScan(scanID)
	if err != nil {
		http.NotFound(w, r)
		return
	}
	data := h.baseData(r, "Metadata Collector Results - scaNNer", "metacollector_results")
	var result metacollector.ScanResult
	json.Unmarshal([]byte(scan.Result), &result)
	populateMetaResultsData(data, &result)
	data["Scan"] = scan
	h.renderResults(w, r, "metacollector_results_inner", data)
}

// populateMetaResultsData computes the FOCA display panels from the stored result.
func populateMetaResultsData(data map[string]interface{}, result *metacollector.ScanResult) {
	agg := metacollector.NewAggregator(result.Findings, result.Documents)
	cats := agg.Cats()
	data["Result"] = result
	data["Documents"] = result.Documents
	data["StatusCount"] = result.StatusCount
	data["Warnings"] = result.Warnings
	data["Stopped"] = result.Stopped
	data["Counts"] = cats
	data["TotalDocs"] = len(result.Documents)
	data["LeakCount"] = cats["path"] + cats["server"]
	top := func(cat string) []metacollector.ValCount { return agg.Top(cat, 50) }
	data["TopUsers"] = top("user")
	data["TopSoftware"] = top("software")
	data["TopEmails"] = top("email")
	data["TopCompany"] = top("company")
	data["TopPaths"] = top("path")
	data["TopServers"] = top("server")
	data["TopOS"] = top("os")
	data["TopPrinters"] = top("printer")
	data["TopGPS"] = top("gps")
	data["TopDates"] = top("date")
	// Correlation (top 15 users × software/os/path) as display rows.
	type corrRow struct {
		User, Software, PathOS string
	}
	var rows []corrRow
	for _, c := range agg.Correlation([]string{"software", "os", "path"}, 15) {
		user := c[0].(string)
		rel := c[1].(map[string][]string)
		sw := joinN(rel["software"], 5)
		po := joinN(append(append([]string{}, rel["path"]...), rel["os"]...), 3)
		if sw == "" && po == "" {
			continue
		}
		rows = append(rows, corrRow{User: user, Software: sw, PathOS: po})
	}
	data["Correlation"] = rows
	data["HasReport"] = len(result.Documents) > 0
}

func (h *Handler) MetaCollectorStatus(w http.ResponseWriter, r *http.Request) {
	scanID := strings.TrimPrefix(r.URL.Path, "/modules/metacollector/status/")
	scan, err := h.db.GetScan(scanID)
	if err != nil {
		http.NotFound(w, r)
		return
	}
	h.writeScanStatus(w, scan)
}

func (h *Handler) runMetaCollector(scanID string, cfg metaCollectorConfig) {
	if !h.db.MarkRunning(scanID) {
		return
	}
	baseOpts := h.BuildHTTPOptionsFromSettings()
	if cfg.Timeout > 0 {
		baseOpts.Timeout = time.Duration(cfg.Timeout) * time.Second
	}
	opts := h.BeginScan(scanID, baseOpts)
	ctx := opts.Ctx
	defer h.FinishScan(scanID)
	settings := h.db.GetSettings()

	scanCfg := metacollector.Config{
		Domains:     cfg.Domains,
		SerperKey:   settings.SerperAPIKey,
		Split:       cfg.Split,
		Concurrency: cfg.Concurrency,
		ScanBody:    true,
		HTTPOpts:    opts,
	}

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

	onProgress := func(done int, msg string) {
		if strings.HasPrefix(msg, metacollector.TotalUpdatePrefix) {
			if n, err := strconv.Atoi(strings.TrimPrefix(msg, metacollector.TotalUpdatePrefix)); err == nil {
				h.db.UpdateScanProgressFull(scanID, done, n, "")
			}
			return
		}
		h.db.UpdateScanProgressBatched(scanID, done, msg)
	}
	onPartial := func(p *metacollector.ScanResult) {
		if b, err := json.Marshal(p); err == nil {
			mu.Lock()
			latest = b
			mu.Unlock()
		}
	}

	result := metacollector.Scan(ctx, scanCfg, onProgress, onPartial)
	resJSON, _ := json.Marshal(result)
	h.db.UpdateScanResult(scanID, string(resJSON))

	// Terminal message: never a silent success. Explain a 0-document outcome
	// (SetFinalProgressMsg drains the progress batch so it can't be clobbered).
	if ctx.Err() == nil {
		h.db.SetFinalProgressMsg(scanID, metaTerminalMsg(result))
	}
}

func metaTerminalMsg(res *metacollector.ScanResult) string {
	if len(res.Documents) == 0 {
		if res.Stopped != "" {
			return "0 documents collected — " + res.Stopped
		}
		return "0 documents found — the domains returned no indexed documents for the searched file types."
	}
	msg := fmt.Sprintf("%d documents, %d metadata findings", len(res.Documents), len(res.Findings))
	if res.Stopped != "" {
		msg += " (search stopped early: " + res.Stopped + ")"
	}
	return msg
}

// ---- Branded report export (asked after the scan) ----

// MetaCollectorReport handles both the GET customization form and the POST
// multipart build (theme/colour/logo/title/org/appendix/format/lang).
func (h *Handler) MetaCollectorReport(w http.ResponseWriter, r *http.Request) {
	scanID := strings.TrimPrefix(r.URL.Path, "/modules/metacollector/report/")
	scan, err := h.db.GetScan(scanID)
	if err != nil {
		http.NotFound(w, r)
		return
	}
	if r.Method != http.MethodPost {
		data := h.baseData(r, "Metadata Report - scaNNer", "metacollector_report")
		data["Scan"] = scan
		data["DefaultTitle"] = metaLabelsFor(h.lang(r)).coverTitle
		h.render(w, "layout", data)
		return
	}

	if err := r.ParseMultipartForm(8 << 20); err != nil {
		http.Error(w, "invalid form: "+err.Error(), http.StatusBadRequest)
		return
	}
	var result metacollector.ScanResult
	json.Unmarshal([]byte(scan.Result), &result)

	opts := metaReportOptions{
		Theme:     strings.TrimSpace(r.FormValue("theme")),
		Color:     strings.TrimSpace(r.FormValue("color")),
		Title:     strings.TrimSpace(r.FormValue("title")),
		TargetOrg: strings.TrimSpace(r.FormValue("target_org")),
		Appendix:  r.FormValue("appendix"),
		Lang:      strings.ToLower(strings.TrimSpace(r.FormValue("lang"))),
	}
	if opts.Appendix != "none" {
		opts.Appendix = "full"
	}
	if opts.Lang != "en" && opts.Lang != "tr" {
		opts.Lang = h.lang(r)
	}
	if file, hdr, ferr := r.FormFile("logo"); ferr == nil {
		defer file.Close()
		if hdr.Size <= 8<<20 {
			opts.Logo, _ = io.ReadAll(io.LimitReader(file, 8<<20))
		}
	}

	base := "metadata_report_" + shortID(scanID)
	if t := fsSafeToken(firstNonEmpty(opts.TargetOrg, opts.Title)); t != "" {
		base = t + "_" + shortID(scanID)
	}

	format := strings.ToLower(r.FormValue("format"))
	switch format {
	case "csv":
		w.Header().Set("Content-Type", "text/csv")
		w.Header().Set("Content-Disposition", "attachment; filename="+base+".csv")
		w.Write(buildMetaReportCSV(&result))
	case "json":
		w.Header().Set("Content-Type", "application/json")
		w.Header().Set("Content-Disposition", "attachment; filename="+base+".json")
		w.Write(buildMetaReportJSON(&result))
	default:
		data, berr := buildMetaReportPDF(&result, opts)
		if berr != nil {
			http.Error(w, "PDF generation failed: "+berr.Error(), http.StatusInternalServerError)
			return
		}
		w.Header().Set("Content-Type", "application/pdf")
		w.Header().Set("Content-Disposition", "attachment; filename="+base+".pdf")
		w.Write(data)
	}
}

func shortID(id string) string {
	if len(id) > 8 {
		return id[:8]
	}
	return id
}
