package handlers

import (
	"encoding/json"
	"fmt"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"time"

	"scanner/internal/models"
	"scanner/internal/modules/httpxfind"
	"scanner/internal/modules/shared"
)

type HTTPXFindConfig struct {
	Targets []string           `json:"targets"`
	Mode    httpxfind.ScanMode `json:"mode"`
}

func (h *Handler) HTTPXFindPage(w http.ResponseWriter, r *http.Request) {
	data := h.baseData(r, "HTTPX Finder - scaNNer", "httpxfind")
	ws := data["ActiveWorkspace"].(*models.Workspace)
	targets, _ := h.db.ListTargets(ws.ID, "")
	data["WSTargets"] = targets
	data["WSTargetGroups"] = h.groupTargetsByList(ws.ID)
	scans, _ := h.db.ListScansLite(ws.ID, "httpxfind")
	data["Scans"] = scans
	h.render(w, "layout", data)
}

func (h *Handler) HTTPXFindRun(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Redirect(w, r, "/modules/httpxfind", http.StatusSeeOther)
		return
	}
	ws := h.activeWorkspace(r)

	var rawTargets []string
	if manual := strings.TrimSpace(r.FormValue("manual_targets")); manual != "" {
		for _, line := range strings.Split(manual, "\n") {
			line = strings.TrimSpace(line)
			if line != "" {
				rawTargets = append(rawTargets, line)
			}
		}
	}
	if selected := r.Form["targets"]; len(selected) > 0 {
		rawTargets = append(rawTargets, selected...)
	}
	// shared.ExpandTargets handles CIDR / hyphen-range / IPv6 uniformly
	// — the previous in-handler expandCIDRToIPs helper silently dropped
	// IPv6 and >/16 IPv4 blocks. Keeping the call site consistent with
	// sslscan / smbenum / portservice.
	targets := shared.ExpandTargets(rawTargets, 65536)
	if len(targets) == 0 {
		http.Redirect(w, r, "/modules/httpxfind?error=no_targets", http.StatusSeeOther)
		return
	}

	mode := httpxfind.ScanMode(r.FormValue("mode"))
	if mode != httpxfind.ModeFull {
		mode = httpxfind.ModeCommon
	}

	// No artificial target cap: the operator must be able to run large sweeps
	// (e.g. 500 IPs × all 65 535 ports in Full mode). The only bound is the
	// ExpandTargets expansion limit above (65 536 hosts) which stops a single
	// pasted /8 from allocating millions of host strings. Memory stays bounded
	// regardless of mode: Full mode scans one host at a time and only records
	// the OPEN ports it discovers (not 65 535 tasks/host), and Common mode's
	// task slice is len(targets) × len(CommonPorts) of tiny {host,port} structs.
	// A huge sweep is slow — that's the operator's time to spend — not a memory
	// blow-up, so it's allowed to run instead of being refused.

	// ModeCommon has a deterministic denominator (targets × CommonPorts).
	// ModeCommon: deterministic (targets × 4 common ports).
	// ModeFull: the DOMINANT work is the 65535-port TCP discovery sweep, so we
	// seed total = targets × 65535 up front and the module now reports `done`
	// in global port units (Task 1) — the bar climbs smoothly through discovery
	// instead of sitting on an indeterminate spinner. Post-discovery the module
	// emits a TotalUpdatePrefix sentinel bumping the denominator by the small
	// HTTP-probe tail via db.UpdateScanProgressFull.
	total := 0
	switch mode {
	case httpxfind.ModeCommon:
		total = len(targets) * len(httpxfind.CommonPorts)
	case httpxfind.ModeFull:
		total = len(targets) * 65535
	}

	opts := h.BuildHTTPOptions(r)

	cfgJSON, _ := json.Marshal(HTTPXFindConfig{Targets: targets, Mode: mode})
	scan, err := h.db.CreateScan(ws.ID, "httpxfind", string(cfgJSON), total)
	if err != nil {
		http.Redirect(w, r, "/modules/httpxfind?error=db_error", http.StatusSeeOther)
		return
	}
	// Sequential scanning: if the operator ticked "start after the current
	// scan finishes" and this workspace is busy, park this run as queued.
	if h.queueIfSequential(w, r, scan) {
		return
	}

	conc, rate := h.applyHTTPTuning(r, opts)
	// httpxfind full-mode maps rate this way (tcpRate in the module): blank →
	// inherit → the safe module default (500/s); an EXPLICIT rate_limit=0 means
	// "unlimited" per the form tooltip, but the module treats 0 as "use default",
	// so translate explicit-zero to the -1 unlimited sentinel.
	if t := parseHTTPTuning(r); t.RateSet && t.RateLimit == 0 {
		rate = -1
	}
	go h.runHTTPXFind(scan.ID, targets, mode, opts, conc, rate)
	http.Redirect(w, r, "/modules/httpxfind/results/"+scan.ID, http.StatusSeeOther)
}

func (h *Handler) HTTPXFindResults(w http.ResponseWriter, r *http.Request) {
	scanID := strings.TrimPrefix(r.URL.Path, "/modules/httpxfind/results/")
	if scanID == "" {
		http.Redirect(w, r, "/modules/httpxfind", http.StatusSeeOther)
		return
	}
	scan, err := h.db.GetScan(scanID)
	if err != nil {
		http.NotFound(w, r)
		return
	}

	data := h.baseData(r, "HTTPX Results - scaNNer", "httpxfind_results")
	var result httpxfind.ScanResult
	json.Unmarshal([]byte(scan.Result), &result)

	data["Scan"] = scan
	data["Services"] = result.Services
	data["ServiceCount"] = len(result.Services)
	h.renderResults(w, r, "httpxfind_results_inner", data)
}

func (h *Handler) HTTPXFindStatus(w http.ResponseWriter, r *http.Request) {
	scanID := strings.TrimPrefix(r.URL.Path, "/modules/httpxfind/status/")
	scan, err := h.db.GetScan(scanID)
	if err != nil {
		http.NotFound(w, r)
		return
	}
	h.writeScanStatus(w, scan)
}

func (h *Handler) runHTTPXFind(scanID string, targets []string, mode httpxfind.ScanMode, opts *shared.HTTPOptions, tcpConc, tcpRate int) {
	if !h.db.MarkRunning(scanID) {
		return
	}
	opts = h.BeginScan(scanID, opts)
	defer h.FinishScan(scanID)

	// Periodic saver for live intermediate results
	var latestResult []byte
	var resultMu sync.Mutex
	doneCh := make(chan struct{})
	defer close(doneCh) // audit B20: panic-safe ticker shutdown
	go func() {
		ticker := time.NewTicker(2 * time.Second)
		defer ticker.Stop()
		for {
			select {
			case <-doneCh:
				return
			case <-ticker.C:
				resultMu.Lock()
				r := latestResult
				resultMu.Unlock()
				if r != nil {
					h.db.UpdateScanResult(scanID, string(r))
				}
			}
		}
	}()

	onPartial := func(partial *httpxfind.ScanResult) {
		b, err := json.Marshal(partial)
		if err == nil {
			resultMu.Lock()
			latestResult = b
			resultMu.Unlock()
		}
	}
	onProgress := func(done int, msg string) {
			// Intercept the module's post-discovery total-update sentinel
			// (full mode only): translate it into an UpdateScanProgressFull
			// so writeScanStatus switches from indeterminate (spinner) to
			// the real denominator. Sentinel messages are NOT forwarded to
			// the UI as a regular progress line.
			if strings.HasPrefix(msg, httpxfind.TotalUpdatePrefix) {
				if n, err := strconv.Atoi(strings.TrimPrefix(msg, httpxfind.TotalUpdatePrefix)); err == nil {
					h.db.UpdateScanProgressFull(scanID, done, n, "")
				}
				return
			}
			// audit perf fix: batched writer coalesces high-frequency
			// per-probe updates so SQLite isn't serializing every probe
			// completion. Terminal write is the final UpdateScanResult
			// below; FinalizeScan/MarkDone drain any pending entry.
			h.db.UpdateScanProgressBatched(scanID, done, msg)
		}

	// Full mode honors the per-scan TCP concurrency + rate overrides (Task 6,
	// tied to the Task 0a home-connection safety knobs); other modes use the
	// probe defaults.
	var result *httpxfind.ScanResult
	if mode == httpxfind.ModeFull {
		result = httpxfind.ScanFull(targets, 0, tcpConc, tcpRate, opts, onPartial, onProgress)
	} else {
		result = httpxfind.Scan(targets, mode, opts, onPartial, onProgress)
	}

	resultJSON, _ := json.Marshal(result)
	h.db.UpdateScanResult(scanID, string(resultJSON))

	// 0 live services is ambiguous — say WHY. A pile of connection
	// refused/timeout/DNS errors means the targets were unreachable from the
	// scanner (down, firewalled, geo-blocked, no route), not that they run no
	// HTTP. Surface the recorded breakdown so the operator isn't left staring
	// at a bare "0 services".
	if opts.Ctx.Err() == nil && len(result.Services) == 0 {
		if n, brk := opts.ErrorSummary(); n > 0 {
			h.db.UpdateScanProgress(scanID, 0, fmt.Sprintf(
				"⚠ 0 live services — %d probe failure(s) (%s): targets unreachable from the scanner (down, firewalled, geo-blocked, or no route). DNS resolving but no TCP/HTTP connection succeeded.",
				n, brk))
		}
	}
}
