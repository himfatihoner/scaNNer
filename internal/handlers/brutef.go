package handlers

import (
	"encoding/json"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"time"

	"scanner/internal/models"
	"scanner/internal/modules/brutef"
	"scanner/internal/modules/shared"
)

type bruteFConfig struct {
	Targets         []string `json:"targets"`
	Protocol        string   `json:"protocol"`
	Port            int      `json:"port,omitempty"`
	UserList        []string `json:"user_list"`
	PassList        []string `json:"pass_list"`
	UseSingleUser   string   `json:"single_user,omitempty"`
	StopOnFirst     bool     `json:"stop_on_first"`
	Threads         int      `json:"threads,omitempty"`
	IncludeDefaults bool     `json:"include_defaults,omitempty"`
}

func (h *Handler) BruteFPage(w http.ResponseWriter, r *http.Request) {
	data := h.baseData(r, "Service Brute Forcer - scaNNer", "brutef")
	ws := data["ActiveWorkspace"].(*models.Workspace)
	scans, _ := h.db.ListScansLite(ws.ID, "brutef")
	data["Scans"] = scans
	targets, _ := h.db.ListTargets(ws.ID, "")
	data["WSTargets"] = targets
	data["WSTargetGroups"] = h.groupTargetsByList(ws.ID)
	h.render(w, "layout", data)
}

func parseBruteFForm(r *http.Request) bruteFConfig {
	cfg := bruteFConfig{}
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
	cfg.Protocol = strings.ToLower(strings.TrimSpace(r.FormValue("protocol")))
	cfg.Port, _ = strconv.Atoi(strings.TrimSpace(r.FormValue("port")))
	cfg.StopOnFirst = r.FormValue("stop_on_first") == "on"
	cfg.UseSingleUser = strings.TrimSpace(r.FormValue("single_user"))

	for _, line := range strings.Split(r.FormValue("user_list"), "\n") {
		line = strings.TrimSpace(line)
		if line != "" {
			cfg.UserList = append(cfg.UserList, line)
		}
	}
	for _, line := range strings.Split(r.FormValue("pass_list"), "\n") {
		line = strings.TrimSpace(line)
		if line != "" {
			cfg.PassList = append(cfg.PassList, line)
		}
	}
	cfg.Threads, _ = strconv.Atoi(strings.TrimSpace(r.FormValue("threads")))
	cfg.IncludeDefaults = r.FormValue("include_defaults") == "on"
	return cfg
}

func (h *Handler) BruteFRun(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Redirect(w, r, "/modules/brutef", http.StatusSeeOther)
		return
	}
	r.ParseForm()
	ws := h.activeWorkspace(r)
	cfg := parseBruteFForm(r)
	if len(cfg.Targets) == 0 {
		http.Redirect(w, r, "/modules/brutef?error=no_targets", http.StatusSeeOther)
		return
	}
	proto := brutef.Protocol(cfg.Protocol)
	if !proto.Valid() {
		http.Redirect(w, r, "/modules/brutef?error=bad_protocol", http.StatusSeeOther)
		return
	}
	if cfg.UseSingleUser == "" && len(cfg.UserList) == 0 {
		http.Redirect(w, r, "/modules/brutef?error=no_users", http.StatusSeeOther)
		return
	}
	if len(cfg.PassList) == 0 {
		http.Redirect(w, r, "/modules/brutef?error=no_passes", http.StatusSeeOther)
		return
	}
	// Expand any CIDR / range entries — hydra accepts a target file via -M but
	// our wrapper drives one-target-per-process, so flatten upfront.
	cfg.Targets = shared.ExpandTargets(cfg.Targets, 256)
	// Audit security: reject targets that would expand into hydra flags
	// or contain shell metacharacters before persisting / scheduling.
	safeTargets := cfg.Targets[:0]
	for _, t := range cfg.Targets {
		if _, ok := shared.SafeTarget(t); ok {
			safeTargets = append(safeTargets, t)
		}
	}
	cfg.Targets = safeTargets
	if len(cfg.Targets) == 0 {
		http.Redirect(w, r, "/modules/brutef?error=unsafe_target", http.StatusSeeOther)
		return
	}
	if cfg.UseSingleUser != "" {
		if _, ok := shared.SafeTarget(cfg.UseSingleUser); !ok {
			http.Redirect(w, r, "/modules/brutef?error=unsafe_target", http.StatusSeeOther)
			return
		}
	}
	cfgJSON, _ := json.Marshal(cfg)
	scan, err := h.db.CreateScan(ws.ID, "brutef", string(cfgJSON), len(cfg.Targets))
	if err != nil {
		http.Redirect(w, r, "/modules/brutef?error=db_error", http.StatusSeeOther)
		return
	}
	if h.queueIfSequential(w, r, scan) {
		return
	}
	go h.runBruteF(scan.ID, cfg)
	http.Redirect(w, r, "/modules/brutef/results/"+scan.ID, http.StatusSeeOther)
}

func (h *Handler) BruteFResults(w http.ResponseWriter, r *http.Request) {
	scanID := strings.TrimPrefix(r.URL.Path, "/modules/brutef/results/")
	scan, err := h.db.GetScan(scanID)
	if err != nil {
		http.NotFound(w, r)
		return
	}
	data := h.baseData(r, "Brute Force Results - scaNNer", "brutef_results")
	var result brutef.ScanResult
	json.Unmarshal([]byte(scan.Result), &result)

	totalFound, totalAttempts := 0, 0
	for _, tr := range result.Results {
		totalFound += len(tr.Found)
		totalAttempts += tr.Attempts
	}
	data["Scan"] = scan
	data["Results"] = result.Results
	data["TotalFound"] = totalFound
	data["TotalAttempts"] = totalAttempts
	h.renderResults(w, r, "brutef_results_inner", data)
}

func (h *Handler) BruteFStatus(w http.ResponseWriter, r *http.Request) {
	scanID := strings.TrimPrefix(r.URL.Path, "/modules/brutef/status/")
	scan, err := h.db.GetScan(scanID)
	if err != nil {
		http.NotFound(w, r)
		return
	}
	h.writeScanStatus(w, scan)
}

func (h *Handler) runBruteF(scanID string, cfg bruteFConfig) {
	if !h.db.MarkRunning(scanID) {
		return
	}
	ctx := h.scanMgr.Register(scanID)
	defer h.FinishScan(scanID)

	settings := h.db.GetSettings()
	concurrency := settings.EffectiveNetworkMaxConcurrent()
	// Brutef caps at 4 parallel hydra processes — each hydra already
	// spawns Threads (default 16) parallel logins, so going higher
	// stacks credential pressure on the target. Previous code silently
	// reset > 4 to 2 (looked like a typo and ignored operator intent).
	// Now: clamp to ceiling 4, fall back to 2 only on invalid/zero.
	if concurrency <= 0 {
		concurrency = 2
	}
	if concurrency > 4 {
		concurrency = 4
	}

	scanCfg := brutef.Config{
		Targets:         cfg.Targets,
		Protocol:        brutef.Protocol(cfg.Protocol),
		Port:            cfg.Port,
		UserList:        cfg.UserList,
		PassList:        cfg.PassList,
		UseSingleUser:   cfg.UseSingleUser,
		StopOnFirst:     cfg.StopOnFirst,
		Threads:         cfg.Threads,
		Concurrency:     concurrency,
		IncludeDefaults: cfg.IncludeDefaults,
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

	result := brutef.Scan(ctx, scanCfg,
		func(done int, msg string) { h.db.UpdateScanProgress(scanID, done, msg) },
		func(p *brutef.ScanResult) {
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
		for _, tr := range result.Results {
			if tr.Error != "" {
				errs = append(errs, tr.Error)
			}
		}
		h.markHardFailure(scanID, errs, len(cfg.Targets))
	}
}
