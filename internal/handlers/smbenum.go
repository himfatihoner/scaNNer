package handlers

import (
	"encoding/json"
	"net/http"
	"strings"
	"sync"
	"time"

	"scanner/internal/models"
	"scanner/internal/modules/shared"
	"scanner/internal/modules/smbenum"
)

type smbEnumConfig struct {
	Targets       []string `json:"targets"`
	UseEnum4Linux bool     `json:"use_enum4linux"`
	UseNmap       bool     `json:"use_nmap"`
	UseSmbClient  bool     `json:"use_smbclient"`
	WalkShares    bool     `json:"walk_shares,omitempty"`
	Username      string   `json:"username,omitempty"`
	Password      string   `json:"password,omitempty"`
}

func (h *Handler) SMBEnumPage(w http.ResponseWriter, r *http.Request) {
	data := h.baseData(r, "SMB Enum - scaNNer", "smbenum")
	ws := data["ActiveWorkspace"].(*models.Workspace)
	scans, _ := h.db.ListScansLite(ws.ID, "smbenum")
	data["Scans"] = scans
	targets, _ := h.db.ListTargets(ws.ID, "")
	data["WSTargets"] = targets
	data["WSTargetGroups"] = h.groupTargetsByList(ws.ID)
	h.render(w, "layout", data)
}

func parseSMBEnumForm(r *http.Request) smbEnumConfig {
	cfg := smbEnumConfig{}
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
	cfg.UseNmap = r.FormValue("use_nmap") == "on"
	cfg.UseEnum4Linux = r.FormValue("use_enum4linux") == "on"
	cfg.UseSmbClient = r.FormValue("use_smbclient") == "on"
	cfg.WalkShares = r.FormValue("use_walk_shares") == "on"
	// Default: all on if user submitted nothing
	if !cfg.UseNmap && !cfg.UseEnum4Linux && !cfg.UseSmbClient {
		cfg.UseNmap = true
		cfg.UseEnum4Linux = true
		cfg.UseSmbClient = true
	}
	cfg.Username = strings.TrimSpace(r.FormValue("username"))
	cfg.Password = r.FormValue("password")
	return cfg
}

func (h *Handler) SMBEnumRun(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Redirect(w, r, "/modules/smbenum", http.StatusSeeOther)
		return
	}
	r.ParseForm()
	ws := h.activeWorkspace(r)
	cfg := parseSMBEnumForm(r)
	if len(cfg.Targets) == 0 {
		http.Redirect(w, r, "/modules/smbenum?error=no_targets", http.StatusSeeOther)
		return
	}
	// Expand any CIDR / range entries up-front so smbclient & enum4linux see
	// concrete IPs (they don't accept network notation themselves).
	cfg.Targets = shared.ExpandTargets(cfg.Targets, 256)
	// audit M6: cap total expanded targets. Each host runs up to four
	// child processes (nmap, smbclient -L, smbclient walk per share,
	// enum4linux) and Concurrency defaults to 3 — an unbounded expansion
	// pins the box for hours and blows past MaxResultBytes on the JSON
	// write. 1024 hosts is a very generous ceiling for lab work.
	if len(cfg.Targets) > 1024 {
		http.Redirect(w, r, "/modules/smbenum?error=too_many_targets", http.StatusSeeOther)
		return
	}
	// audit M5: strip Password before persisting the launch config to
	// scans.config. The plaintext lives on scans.db (WAL, umask, no
	// at-rest encryption) and Restart replays the config verbatim — so a
	// backup of scanner.db recovers every SMB credential the operator
	// has ever entered. Keep the field in cfg (used by the live scan
	// goroutine) but strip the JSON copy. Restart will prompt for the
	// password again via the launch form.
	cfgForPersist := cfg
	cfgForPersist.Password = ""
	cfgJSON, _ := json.Marshal(cfgForPersist)
	scan, err := h.db.CreateScan(ws.ID, "smbenum", string(cfgJSON), len(cfg.Targets))
	if err != nil {
		http.Redirect(w, r, "/modules/smbenum?error=db_error", http.StatusSeeOther)
		return
	}
	if h.queueIfSequential(w, r, scan) {
		return
	}
	go h.runSMBEnum(scan.ID, cfg)
	http.Redirect(w, r, "/modules/smbenum/results/"+scan.ID, http.StatusSeeOther)
}

func (h *Handler) SMBEnumResults(w http.ResponseWriter, r *http.Request) {
	scanID := strings.TrimPrefix(r.URL.Path, "/modules/smbenum/results/")
	scan, err := h.db.GetScan(scanID)
	if err != nil {
		http.NotFound(w, r)
		return
	}
	data := h.baseData(r, "SMB Enum Results - scaNNer", "smbenum_results")
	var result smbenum.ScanResult
	json.Unmarshal([]byte(scan.Result), &result)

	totalShares, totalUsers, openHosts := 0, 0, 0
	for _, tr := range result.Results {
		totalShares += len(tr.Shares)
		totalUsers += len(tr.Users)
		if tr.SMBPortOpen {
			openHosts++
		}
	}
	data["Scan"] = scan
	data["Results"] = result.Results
	data["TotalShares"] = totalShares
	data["TotalUsers"] = totalUsers
	data["OpenHosts"] = openHosts
	h.renderResults(w, r, "smbenum_results_inner", data)
}

func (h *Handler) SMBEnumStatus(w http.ResponseWriter, r *http.Request) {
	scanID := strings.TrimPrefix(r.URL.Path, "/modules/smbenum/status/")
	scan, err := h.db.GetScan(scanID)
	if err != nil {
		http.NotFound(w, r)
		return
	}
	h.writeScanStatus(w, scan)
}

func (h *Handler) runSMBEnum(scanID string, cfg smbEnumConfig) {
	if !h.db.MarkRunning(scanID) {
		return
	}
	ctx := h.scanMgr.Register(scanID)
	defer h.FinishScan(scanID)

	settings := h.db.GetSettings()
	concurrency := settings.EffectiveNetworkMaxConcurrent()
	if concurrency <= 0 || concurrency > 4 {
		concurrency = 3
	}

	scanCfg := smbenum.Config{
		Targets:       cfg.Targets,
		UseNmap:       cfg.UseNmap,
		UseEnum4Linux: cfg.UseEnum4Linux,
		UseSmbClient:  cfg.UseSmbClient,
		WalkShares:    cfg.WalkShares,
		Username:      cfg.Username,
		Password:      cfg.Password,
		Concurrency:   concurrency,
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

	result := smbenum.Scan(ctx, scanCfg,
		// audit M11: enumerate() emits ~5-6 progress events per target
		// (port check, nmap, smbclient, walk each share, enum4linux)
		// plus start/finish. Against a /24 that's thousands of raw
		// UPDATEs; UpdateScanProgressBatched coalesces to a 500 ms
		// flush. Command-crumb "$ " messages route through the
		// non-batched path so the commands column captures each one
		// (the batched map coalesces on scanID and would drop them).
		func(done int, msg string) {
			if strings.HasPrefix(msg, "$ ") {
				h.db.UpdateScanProgress(scanID, done, msg)
				return
			}
			h.db.UpdateScanProgressBatched(scanID, done, msg)
		},
		func(p *smbenum.ScanResult) {
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
