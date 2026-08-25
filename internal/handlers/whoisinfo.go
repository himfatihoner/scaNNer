package handlers

import (
	"encoding/json"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"time"

	"scanner/internal/models"
	"scanner/internal/modules/whoisinfo"
)

type whoisinfoConfig struct {
	Targets       []string `json:"targets"`
	IncludePrefix bool     `json:"include_prefix"`
	Concurrency   int      `json:"concurrency,omitempty"`
}

func (h *Handler) WhoisInfoPage(w http.ResponseWriter, r *http.Request) {
	data := h.baseData(r, "WHOIS / ASN Lookup - scaNNer", "whoisinfo")
	ws := data["ActiveWorkspace"].(*models.Workspace)
	scans, _ := h.db.ListScansLite(ws.ID, "whoisinfo")
	data["Scans"] = scans
	targets, _ := h.db.ListTargets(ws.ID, "")
	data["WSTargets"] = targets
	data["WSTargetGroups"] = h.groupTargetsByList(ws.ID)
	h.render(w, "layout", data)
}

func parseWhoisInfoForm(r *http.Request) whoisinfoConfig {
	cfg := whoisinfoConfig{}
	for _, t := range r.Form["targets"] {
		t = strings.TrimSpace(t)
		if t != "" {
			cfg.Targets = append(cfg.Targets, t)
		}
	}
	for _, line := range strings.Split(r.FormValue("manual_targets"), "\n") {
		line = strings.TrimSpace(line)
		if line != "" {
			cfg.Targets = append(cfg.Targets, line)
		}
	}
	cfg.IncludePrefix = r.FormValue("include_prefix") == "on"
	// Audit MEDIUM: expose concurrency to the operator so large batches
	// aren't stuck at 4 parallel. Clamped 1..16 to avoid abusing the
	// upstream whois servers.
	if v := strings.TrimSpace(r.FormValue("concurrency")); v != "" {
		if n, err := strconv.Atoi(v); err == nil {
			if n < 1 {
				n = 1
			}
			if n > 16 {
				n = 16
			}
			cfg.Concurrency = n
		}
	}
	return cfg
}

func (h *Handler) WhoisInfoRun(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Redirect(w, r, "/modules/whoisinfo", http.StatusSeeOther)
		return
	}
	r.ParseForm()
	ws := h.activeWorkspace(r)
	cfg := parseWhoisInfoForm(r)
	if len(cfg.Targets) == 0 {
		http.Redirect(w, r, "/modules/whoisinfo?error=no_targets", http.StatusSeeOther)
		return
	}
	// Do NOT expand CIDRs — every IP inside a single allocation belongs to
	// the same registry record, and expanding /22 to 1024 IPs floods ARIN's
	// 1-query/3s cap and gets the scanner rate-limited. whois servers accept
	// CIDR / range strings directly, so we hand them off as-is. Hyphen ranges
	// likewise pass through to the underlying tool.
	cfgJSON, _ := json.Marshal(cfg)
	scan, err := h.db.CreateScan(ws.ID, "whoisinfo", string(cfgJSON), len(cfg.Targets))
	if err != nil {
		http.Redirect(w, r, "/modules/whoisinfo?error=db_error", http.StatusSeeOther)
		return
	}
	if h.queueIfSequential(w, r, scan) {
		return
	}
	go h.runWhoisInfo(scan.ID, cfg)
	http.Redirect(w, r, "/modules/whoisinfo/results/"+scan.ID, http.StatusSeeOther)
}

func (h *Handler) WhoisInfoResults(w http.ResponseWriter, r *http.Request) {
	scanID := strings.TrimPrefix(r.URL.Path, "/modules/whoisinfo/results/")
	scan, err := h.db.GetScan(scanID)
	if err != nil {
		http.NotFound(w, r)
		return
	}
	data := h.baseData(r, "WHOIS Results - scaNNer", "whoisinfo_results")
	var result whoisinfo.ScanResult
	json.Unmarshal([]byte(scan.Result), &result)
	data["Scan"] = scan
	data["Results"] = result.Results
	h.renderResults(w, r, "whoisinfo_results_inner", data)
}

func (h *Handler) WhoisInfoStatus(w http.ResponseWriter, r *http.Request) {
	scanID := strings.TrimPrefix(r.URL.Path, "/modules/whoisinfo/status/")
	scan, err := h.db.GetScan(scanID)
	if err != nil {
		http.NotFound(w, r)
		return
	}
	h.writeScanStatus(w, scan)
}

func (h *Handler) runWhoisInfo(scanID string, cfg whoisinfoConfig) {
	if !h.db.MarkRunning(scanID) {
		return
	}
	ctx := h.scanMgr.Register(scanID)
	defer h.FinishScan(scanID)

	conc := cfg.Concurrency
	if conc <= 0 {
		conc = 4
	}
	scanCfg := whoisinfo.Config{
		Targets:       cfg.Targets,
		IncludePrefix: cfg.IncludePrefix,
		Concurrency:   conc,
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

	result := whoisinfo.Scan(ctx, scanCfg,
		func(done int, msg string) { h.db.UpdateScanProgress(scanID, done, msg) },
		func(p *whoisinfo.ScanResult) {
			b, err := json.Marshal(p)
			if err == nil {
				mu.Lock()
				latest = b
				mu.Unlock()
			}
		})
	resJSON, _ := json.Marshal(result)
	h.db.UpdateScanResult(scanID, string(resJSON))

	// Hard-failure surfacing: if every unit errored, mark the scan failed
	// with a translated reason rather than a silent "done" with zero findings.
	if ctx.Err() == nil {
		var errs []string
		for _, u := range result.Results {
			if u.Error != "" {
				errs = append(errs, u.Error)
			}
		}
		h.markHardFailure(scanID, errs, len(cfg.Targets))
	}
}
