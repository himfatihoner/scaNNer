package handlers

import (
	"encoding/json"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"time"

	"scanner/internal/models"
	"scanner/internal/modules/leakscan"
	"scanner/internal/modules/shared"
)

type leakScanConfig struct {
	Queries     []string `json:"queries"`
	GitHubToken string   `json:"github_token,omitempty"`
	MaxFiles    int      `json:"max_files"`
	// FetchSnippets downloads each hit's raw file (256 KB cap) and runs
	// the built-in secret-pattern regexes against it.
	FetchSnippets bool `json:"fetch_snippets"`
	// Audit MEDIUM: the scanner code supports Pastebin and Wayback as
	// extra source surfaces, but the form had no checkboxes and the
	// handler config had no fields — making both code paths dead. These
	// fields now plumb the toggles through end-to-end.
	IncludePastebin bool `json:"include_pastebin"`
	IncludeWayback  bool `json:"include_wayback"`
}

func (h *Handler) LeakScanPage(w http.ResponseWriter, r *http.Request) {
	data := h.baseData(r, "GitHub Leak Scanner - scaNNer", "leakscan")
	ws := data["ActiveWorkspace"].(*models.Workspace)
	scans, _ := h.db.ListScansLite(ws.ID, "leakscan")
	data["Scans"] = scans
	data["HasGitHubToken"] = strings.TrimSpace(h.db.GetSettings().GitHubToken) != ""
	h.render(w, "layout", data)
}

func parseLeakScanForm(r *http.Request) leakScanConfig {
	cfg := leakScanConfig{}
	for _, line := range strings.Split(r.FormValue("queries"), "\n") {
		line = strings.TrimSpace(line)
		if line != "" {
			cfg.Queries = append(cfg.Queries, line)
		}
	}
	// GitHub token is read from global Settings, not the per-scan form.
	cfg.MaxFiles, _ = strconv.Atoi(strings.TrimSpace(r.FormValue("max_files")))
	cfg.FetchSnippets = r.FormValue("fetch_snippets") == "on"
	// Audit MEDIUM fix: expose the Pastebin/Wayback source toggles that
	// the scanner code already implements — previously the Config struct
	// carried them but no form field / handler code set them, making
	// searchPastebin / searchWayback unreachable dead code paths.
	cfg.IncludePastebin = r.FormValue("include_pastebin") == "on"
	cfg.IncludeWayback = r.FormValue("include_wayback") == "on"
	return cfg
}

func (h *Handler) LeakScanRun(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Redirect(w, r, "/modules/leakscan", http.StatusSeeOther)
		return
	}
	r.ParseForm()
	ws := h.activeWorkspace(r)
	cfg := parseLeakScanForm(r)
	if len(cfg.Queries) == 0 {
		http.Redirect(w, r, "/modules/leakscan?error=no_queries", http.StatusSeeOther)
		return
	}
	if strings.TrimSpace(h.db.GetSettings().GitHubToken) == "" {
		http.Redirect(w, r, "/modules/leakscan?error=no_token", http.StatusSeeOther)
		return
	}
	cfgJSON, _ := json.Marshal(cfg)
	scan, err := h.db.CreateScan(ws.ID, "leakscan", string(cfgJSON), len(cfg.Queries))
	if err != nil {
		http.Redirect(w, r, "/modules/leakscan?error=db_error", http.StatusSeeOther)
		return
	}
	// Sequential scanning: if the operator ticked "start after the current
	// scan finishes" and this workspace is busy, park this run as queued.
	if h.queueIfSequential(w, r, scan) {
		return
	}
	// Audit MEDIUM fix: build HTTPOptions from the request+settings so
	// the module's outbound HTTP inherits proxy / UA / timeout AND —
	// critically — the killswitch source-IP binding + transport-idle-pool
	// registration. Previously runLeakScan built a package-local client
	// that bypassed both layers.
	opts := h.BuildHTTPOptions(r)
	// applyHTTPTuning reads the http_tuning partial (req_timeout /
	// max_concurrent) and sets opts.Timeout to the per-scan override or the
	// global Web default. leakscan has no concurrency parameter — its per-hit
	// fetch fan-out is a fixed internal semaphore, and Config carries no conc
	// field — so the returned effective concurrency is intentionally ignored.
	h.applyHTTPTuning(r, opts)
	go h.runLeakScan(scan.ID, cfg, opts)
	http.Redirect(w, r, "/modules/leakscan/results/"+scan.ID, http.StatusSeeOther)
}

func (h *Handler) LeakScanResults(w http.ResponseWriter, r *http.Request) {
	scanID := strings.TrimPrefix(r.URL.Path, "/modules/leakscan/results/")
	scan, err := h.db.GetScan(scanID)
	if err != nil {
		http.NotFound(w, r)
		return
	}
	data := h.baseData(r, "Leak Scan Results - scaNNer", "leakscan_results")
	var result leakscan.ScanResult
	json.Unmarshal([]byte(scan.Result), &result)
	totalHits, totalMatches := 0, 0
	for _, qr := range result.Results {
		totalHits += len(qr.Hits)
		totalMatches += qr.MatchCount
	}
	data["Scan"] = scan
	data["Results"] = result.Results
	data["TotalHits"] = totalHits
	data["TotalMatches"] = totalMatches
	h.renderResults(w, r, "leakscan_results_inner", data)
}

func (h *Handler) LeakScanStatus(w http.ResponseWriter, r *http.Request) {
	scanID := strings.TrimPrefix(r.URL.Path, "/modules/leakscan/status/")
	scan, err := h.db.GetScan(scanID)
	if err != nil {
		http.NotFound(w, r)
		return
	}
	h.writeScanStatus(w, scan)
}

func (h *Handler) runLeakScan(scanID string, cfg leakScanConfig, opts *shared.HTTPOptions) {
	if !h.db.MarkRunning(scanID) {
		return
	}
	// BeginScan registers the scan context + attaches opts to the
	// ScanManager so cancel can flush this scan's HTTP idle-pool.
	opts = h.BeginScan(scanID, opts)
	defer h.FinishScan(scanID)

	scanCfg := leakscan.Config{
		Queries:         cfg.Queries,
		GitHubToken:     h.db.GetSettings().GitHubToken,
		MaxFiles:        cfg.MaxFiles,
		FetchSnippets:   cfg.FetchSnippets,
		IncludePastebin: cfg.IncludePastebin,
		IncludeWayback:  cfg.IncludeWayback,
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

	// Audit MEDIUM fix: use opts-built client so every outbound request
	// honors the killswitch (BoundDialer via HTTPOptions) AND registers
	// its transport with the ScanManager (idle-pool flush on cancel).
	client := opts.NewHTTPClient()
	result := leakscan.ScanWithClient(opts.Ctx, scanCfg, client,
		func(done int, msg string) { h.db.UpdateScanProgress(scanID, done, msg) },
		func(p *leakscan.ScanResult) {
			b, err := json.Marshal(p)
			if err == nil {
				mu.Lock()
				latest = b
				mu.Unlock()
			}
		})
	resJSON, _ := json.Marshal(result)
	h.db.UpdateScanResult(scanID, string(resJSON))

	// Hard-failure surfacing: if every query errored, mark the scan failed
	// with a translated reason rather than a silent "done" with zero findings.
	if opts.Ctx.Err() == nil {
		var errs []string
		for _, qr := range result.Results {
			if qr.Error != "" {
				errs = append(errs, qr.Error)
			}
		}
		h.markHardFailure(scanID, errs, len(cfg.Queries))
	}
}
