package handlers

import (
	"encoding/json"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"time"

	"scanner/internal/models"
	"scanner/internal/modules/emailharvest"
)

type emailHarvestConfig struct {
	Domains   []string `json:"domains"`
	Sources   []string `json:"sources"`
	Limit     int      `json:"limit"`
	DNSAuth   bool     `json:"dns_auth"`
	HIBPCheck bool     `json:"hibp_check"`
	HIBPKey   string   `json:"hibp_key,omitempty"`
	// Per-scan HTTP tuning (http_tuning partial). Persisted so the values reach
	// the run goroutine and are replayed verbatim by the Restart path, which has
	// no request to re-read the form from. 0 = inherit the global Web defaults.
	Timeout     int `json:"timeout,omitempty"`     // request timeout, seconds
	Concurrency int `json:"concurrency,omitempty"` // max concurrent domains
}

func (h *Handler) EmailHarvestPage(w http.ResponseWriter, r *http.Request) {
	data := h.baseData(r, "Email Harvester - scaNNer", "emailharvest")
	ws := data["ActiveWorkspace"].(*models.Workspace)
	scans, _ := h.db.ListScansLite(ws.ID, "emailharvest")
	data["Scans"] = scans
	data["AllSources"] = emailharvest.AllSources
	// Expose the default-selected sources to the template so the pre-ticked
	// boxes and the scanner's actual defaults can't drift apart.
	defSet := map[string]bool{}
	for _, s := range emailharvest.DefaultSources {
		defSet[s] = true
	}
	data["DefaultSources"] = defSet
	data["DefaultSourcesList"] = strings.Join(emailharvest.DefaultSources, ", ")
	data["HasHIBPKey"] = strings.TrimSpace(h.db.GetSettings().HIBPAPIKey) != ""
	h.render(w, "layout", data)
}

func parseEmailHarvestForm(r *http.Request) emailHarvestConfig {
	cfg := emailHarvestConfig{}
	for _, line := range strings.Split(r.FormValue("domains"), "\n") {
		line = strings.TrimSpace(line)
		if line != "" {
			cfg.Domains = append(cfg.Domains, line)
		}
	}
	cfg.Sources = r.Form["sources"]
	cfg.Limit, _ = strconv.Atoi(strings.TrimSpace(r.FormValue("limit")))
	cfg.DNSAuth = r.FormValue("dns_auth") == "on"
	cfg.HIBPCheck = r.FormValue("hibp_check") == "on"
	// HIBP key is read from global Settings (not the per-scan form).
	return cfg
}

func (h *Handler) EmailHarvestRun(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Redirect(w, r, "/modules/emailharvest", http.StatusSeeOther)
		return
	}
	r.ParseForm()
	ws := h.activeWorkspace(r)
	cfg := parseEmailHarvestForm(r)
	if len(cfg.Domains) == 0 {
		http.Redirect(w, r, "/modules/emailharvest?error=no_domains", http.StatusSeeOther)
		return
	}
	// Per-scan HTTP tuning: applyHTTPTuning reads req_timeout/max_concurrent from
	// the http_tuning partial, sets opts.Timeout (override or the global Web
	// timeout) and returns the effective concurrency. emailharvest has no request
	// rate-limit concept, so the 2nd return is ignored. Persist both resolved
	// values into the config so the run goroutine and the Restart replay both use
	// them (the goroutine rebuilds opts from Settings and re-reads these).
	opts := h.BuildHTTPOptions(r)
	conc, _ := h.applyHTTPTuning(r, opts)
	cfg.Concurrency = conc
	cfg.Timeout = int(opts.Timeout / time.Second)
	cfgJSON, _ := json.Marshal(cfg)
	scan, err := h.db.CreateScan(ws.ID, "emailharvest", string(cfgJSON), len(cfg.Domains))
	if err != nil {
		http.Redirect(w, r, "/modules/emailharvest?error=db_error", http.StatusSeeOther)
		return
	}
	// Sequential scanning: if the operator ticked "start after the current
	// scan finishes" and this workspace is busy, park this run as queued.
	if h.queueIfSequential(w, r, scan) {
		return
	}
	go h.runEmailHarvest(scan.ID, cfg)
	http.Redirect(w, r, "/modules/emailharvest/results/"+scan.ID, http.StatusSeeOther)
}

func (h *Handler) EmailHarvestResults(w http.ResponseWriter, r *http.Request) {
	scanID := strings.TrimPrefix(r.URL.Path, "/modules/emailharvest/results/")
	scan, err := h.db.GetScan(scanID)
	if err != nil {
		http.NotFound(w, r)
		return
	}
	data := h.baseData(r, "Email Harvest Results - scaNNer", "emailharvest_results")
	var result emailharvest.ScanResult
	json.Unmarshal([]byte(scan.Result), &result)

	totalEmails, totalHosts, totalIPs := 0, 0, 0
	for _, dr := range result.Results {
		totalEmails += len(dr.Emails)
		totalHosts += len(dr.Hosts)
		totalIPs += len(dr.IPs)
	}
	data["Scan"] = scan
	data["Results"] = result.Results
	data["TotalEmails"] = totalEmails
	data["TotalHosts"] = totalHosts
	data["TotalIPs"] = totalIPs
	h.renderResults(w, r, "emailharvest_results_inner", data)
}

func (h *Handler) EmailHarvestStatus(w http.ResponseWriter, r *http.Request) {
	scanID := strings.TrimPrefix(r.URL.Path, "/modules/emailharvest/status/")
	scan, err := h.db.GetScan(scanID)
	if err != nil {
		http.NotFound(w, r)
		return
	}
	h.writeScanStatus(w, scan)
}

func (h *Handler) runEmailHarvest(scanID string, cfg emailHarvestConfig) {
	if !h.db.MarkRunning(scanID) {
		return
	}
	// Audit M finding: HIBP HTTP client previously bypassed BoundDialer / opts
	// registry. Build opts from current Settings (works for both fresh-scan and
	// Restart paths since the form has no per-scan HTTP fields), then register
	// with the ScanManager via BeginScan so cancel flushes idle TCP pools and
	// killswitch L2 source-IP binding applies.
	baseOpts := h.BuildHTTPOptionsFromSettings()
	// Honor the per-scan request-timeout override resolved by applyHTTPTuning in
	// the Run handler and persisted in the config. 0 = inherit, which the
	// Settings-derived opts.Timeout already carries.
	if cfg.Timeout > 0 {
		baseOpts.Timeout = time.Duration(cfg.Timeout) * time.Second
	}
	opts := h.BeginScan(scanID, baseOpts)
	ctx := opts.Ctx
	defer h.FinishScan(scanID)
	settings := h.db.GetSettings()
	// Effective concurrency from the tuning partial; 0 = inherit the global Web
	// default so a blank form (or an older stored config) behaves sensibly.
	conc := cfg.Concurrency
	if conc <= 0 {
		conc = settings.EffectiveWebMaxConcurrent()
	}
	scanCfg := emailharvest.Config{
		Domains:     cfg.Domains,
		Sources:     cfg.Sources,
		Limit:       cfg.Limit,
		Concurrency: conc,
		DNSAuth:     cfg.DNSAuth,
		HIBPCheck:   cfg.HIBPCheck,
		HIBPKey:     settings.HIBPAPIKey,
		HTTPOpts:    opts,
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

	result := emailharvest.Scan(ctx, scanCfg,
		func(done int, msg string) { h.db.UpdateScanProgress(scanID, done, msg) },
		func(p *emailharvest.ScanResult) {
			b, err := json.Marshal(p)
			if err == nil {
				mu.Lock()
				latest = b
				mu.Unlock()
			}
		})
	resJSON, _ := json.Marshal(result)
	h.db.UpdateScanResult(scanID, string(resJSON))

	// Hard-failure surfacing: if every domain errored, mark the scan failed
	// with a translated reason rather than a silent "done" with zero findings.
	if opts.Ctx.Err() == nil {
		var errs []string
		for _, dr := range result.Results {
			if dr.Error != "" {
				errs = append(errs, dr.Error)
			}
		}
		h.markHardFailure(scanID, errs, len(cfg.Domains))
	}
}
