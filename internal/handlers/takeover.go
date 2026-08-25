package handlers

import (
	"encoding/json"
	"net/http"
	"strings"
	"sync"
	"time"

	"scanner/internal/models"
	"scanner/internal/modules/shared"
	"scanner/internal/modules/takeover"
)

func (h *Handler) TakeoverPage(w http.ResponseWriter, r *http.Request) {
	data := h.baseData(r, "Subdomain Takeover - scaNNer", "takeover")
	ws := data["ActiveWorkspace"].(*models.Workspace)
	data["WSTargetGroups"] = h.groupTargetsByList(ws.ID)
	scans, _ := h.db.ListScansLite(ws.ID, "takeover")
	data["Scans"] = scans
	dnsScans, _ := h.db.ListScansLite(ws.ID, "dnsenum")
	data["DNSScans"] = dnsScans
	h.render(w, "layout", data)
}

func (h *Handler) TakeoverRun(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Redirect(w, r, "/modules/takeover", http.StatusSeeOther)
		return
	}
	r.ParseForm()
	ws := h.activeWorkspace(r)

	var subs []string
	for _, line := range strings.Split(r.FormValue("subdomains"), "\n") {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		line = strings.TrimPrefix(line, "http://")
		line = strings.TrimPrefix(line, "https://")
		if idx := strings.IndexAny(line, "/?#"); idx >= 0 {
			line = line[:idx]
		}
		subs = append(subs, line)
	}

	if selected := r.Form["targets"]; len(selected) > 0 {
		subs = append(subs, selected...)
	}

	if src := strings.TrimSpace(r.FormValue("import_dnsenum")); src != "" {
		if scan, err := h.db.GetScan(src); err == nil {
			var parsed struct {
				Results []struct {
					Subdomains []struct {
						Subdomain string `json:"subdomain"`
					} `json:"subdomains"`
				} `json:"results"`
			}
			if json.Unmarshal([]byte(scan.Result), &parsed) == nil {
				seen := map[string]bool{}
				for _, s := range subs {
					seen[s] = true
				}
				for _, dr := range parsed.Results {
					for _, sd := range dr.Subdomains {
						s := strings.ToLower(strings.TrimSpace(sd.Subdomain))
						if s == "" || seen[s] {
							continue
						}
						seen[s] = true
						subs = append(subs, s)
					}
				}
			}
		}
	}

	if len(subs) == 0 {
		http.Redirect(w, r, "/modules/takeover?error=no_subdomains", http.StatusSeeOther)
		return
	}

	opts := h.BuildHTTPOptions(r)
	conc, _ := h.applyHTTPTuning(r, opts)

	cfg := takeover.Config{
		Subdomains:  subs,
		Concurrency: conc,
		Timeout:     opts.Timeout,
	}
	cfgJSON, _ := json.Marshal(cfg)
	scan, err := h.db.CreateScan(ws.ID, "takeover", string(cfgJSON), len(subs))
	if err != nil {
		http.Redirect(w, r, "/modules/takeover?error=db_error", http.StatusSeeOther)
		return
	}
	// Sequential scanning: if the operator ticked "start after the current
	// scan finishes" and this workspace is busy, park this run as queued.
	if h.queueIfSequential(w, r, scan) {
		return
	}
	go h.runTakeover(scan.ID, cfg, opts)
	http.Redirect(w, r, "/modules/takeover/results/"+scan.ID, http.StatusSeeOther)
}

func (h *Handler) TakeoverResults(w http.ResponseWriter, r *http.Request) {
	scanID := strings.TrimPrefix(r.URL.Path, "/modules/takeover/results/")
	scan, err := h.db.GetScan(scanID)
	if err != nil {
		http.NotFound(w, r)
		return
	}
	data := h.baseData(r, "Takeover Results - scaNNer", "takeover_results")
	var result takeover.ScanResult
	json.Unmarshal([]byte(scan.Result), &result)
	data["Scan"] = scan
	data["Results"] = result.Results
	data["Findings"] = result.Findings
	h.renderResults(w, r, "takeover_results_inner", data)
}

func (h *Handler) TakeoverStatus(w http.ResponseWriter, r *http.Request) {
	scanID := strings.TrimPrefix(r.URL.Path, "/modules/takeover/status/")
	scan, err := h.db.GetScan(scanID)
	if err != nil {
		http.NotFound(w, r)
		return
	}
	h.writeScanStatus(w, scan)
}

func (h *Handler) runTakeover(scanID string, cfg takeover.Config, opts *shared.HTTPOptions) {
	if !h.db.MarkRunning(scanID) {
		return
	}
	opts = h.BeginScan(scanID, opts)
	defer h.FinishScan(scanID)

	// 2s coalesced flush of the latest partial snapshot (mirrors smbenum.go).
	// Without this, every probe completion would trigger a full marshal +
	// DB UPDATE, which serializes the scan on the SQLite WAL writer.
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

	result := takeover.Scan(opts.Ctx, cfg, opts,
		func(done int, msg string) { h.db.UpdateScanProgress(scanID, done, msg) },
		func(p *takeover.ScanResult) {
			b, err := json.Marshal(p)
			if err == nil {
				mu.Lock()
				latest = b
				mu.Unlock()
			}
		})

	resultJSON, _ := json.Marshal(result)
	h.db.UpdateScanResult(scanID, string(resultJSON))
}
