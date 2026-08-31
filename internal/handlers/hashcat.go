package handlers

import (
	"encoding/json"
	"html/template"
	"io"
	"math"
	"net/http"
	"os"
	"strconv"
	"strings"
	"sync"
	"time"

	"scanner/internal/models"
	"scanner/internal/modules/hashcat"
	"scanner/internal/sysmon"
)

// hashcatConfig is the JSON-persisted launch config (replayed by Restart).
// Uploaded-wordlist temp paths are NOT persisted (UploadedWL has json:"-").
type hashcatConfig struct {
	Hashes        []string `json:"hashes"`
	ModeID        int      `json:"mode_id"`
	ModeName      string   `json:"mode_name,omitempty"`
	DetectMode    bool     `json:"detect_mode"` // no mode chosen → auto-detect via hashid
	Attack        int      `json:"attack"`      // 0 = dictionary+rules, 3 = mask
	Wordlist      string   `json:"wordlist,omitempty"`
	Rules         []string `json:"rules,omitempty"`
	Mask          string   `json:"mask,omitempty"`
	Workload      int      `json:"workload"`
	CPUOnly       bool     `json:"cpu_only"`
	MaxCPUPct     int      `json:"max_cpu_pct"`     // operator's slider value
	AffinityCores int      `json:"affinity_cores"`  // resolved core count (0 = all)
	RuntimeSec    int      `json:"runtime_sec,omitempty"`
	UploadedWL    string   `json:"-"`               // temp file to clean up post-run
}

func (h *Handler) HashcatPage(w http.ResponseWriter, r *http.Request) {
	data := h.baseData(r, "Hashcat - scaNNer", "hashcat")
	ws := data["ActiveWorkspace"].(*models.Workspace)
	scans, _ := h.db.ListScansLite(ws.ID, "hashcat")
	data["Scans"] = scans

	modes := hashcat.HashModes()
	if b, err := json.Marshal(modes); err == nil {
		data["ModesJSON"] = template.JS(b) // embedded as a JS array literal for the searchable picker
	} else {
		data["ModesJSON"] = template.JS("[]")
	}
	data["ModeCount"] = len(modes)
	data["WordlistGroups"] = groupWordlists(hashcat.Wordlists())
	data["Rules"] = hashcat.Rules()
	data["Cores"] = sysmon.ReadLimits().Cores
	data["DefaultCPUPct"] = h.db.GetSettings().EffectiveMaxCPUPercent()
	h.render(w, "layout", data)
}

// wlGroup buckets wordlists by their display group for <optgroup> rendering.
type wlGroup struct {
	Group string
	Items []hashcat.WordlistOption
}

func groupWordlists(wls []hashcat.WordlistOption) []wlGroup {
	var groups []wlGroup
	idx := map[string]int{}
	for _, w := range wls {
		i, ok := idx[w.Group]
		if !ok {
			i = len(groups)
			idx[w.Group] = i
			groups = append(groups, wlGroup{Group: w.Group})
		}
		groups[i].Items = append(groups[i].Items, w)
	}
	return groups
}

func (h *Handler) parseHashcatForm(r *http.Request) hashcatConfig {
	_ = r.ParseMultipartForm(20 << 20) // 20MB — hash lists are small; wordlist uploads streamed to a temp file
	cfg := hashcatConfig{}

	// Hashes: uploaded file wins over the textarea.
	if f, _, err := r.FormFile("hashfile"); err == nil {
		defer f.Close()
		cfg.Hashes = readLines(f)
	} else {
		for _, line := range strings.Split(r.FormValue("hashes"), "\n") {
			if s := strings.TrimSpace(line); s != "" {
				cfg.Hashes = append(cfg.Hashes, s)
			}
		}
	}

	rawMode := strings.TrimSpace(r.FormValue("mode_id"))
	if rawMode == "" {
		cfg.DetectMode = true // no algorithm chosen → auto-detect + try candidates
	} else {
		cfg.ModeID, _ = strconv.Atoi(rawMode)
		cfg.ModeName = strings.TrimSpace(r.FormValue("mode_name"))
		if cfg.ModeName == "" {
			cfg.ModeName = hashcat.ModeName(cfg.ModeID)
		}
	}

	if r.FormValue("attack") == "3" {
		cfg.Attack = 3
		cfg.Mask = strings.TrimSpace(r.FormValue("mask"))
	} else {
		cfg.Attack = 0
		// Wordlist: uploaded file → temp path; else custom path; else dropdown.
		if f, _, err := r.FormFile("wordlistfile"); err == nil {
			defer f.Close()
			if tmp, e := os.CreateTemp("", "hashcat-wl-*.txt"); e == nil {
				io.Copy(tmp, f)
				tmp.Close()
				cfg.Wordlist = tmp.Name()
				cfg.UploadedWL = tmp.Name()
			}
		}
		if cfg.Wordlist == "" {
			if custom := strings.TrimSpace(r.FormValue("wordlist_custom")); custom != "" {
				cfg.Wordlist = custom
			} else {
				cfg.Wordlist = strings.TrimSpace(r.FormValue("wordlist_select"))
			}
		}
		// Rules: multi-select checkboxes (paths) + an optional custom rule path.
		for _, rp := range r.Form["rules"] {
			if s := strings.TrimSpace(rp); s != "" {
				cfg.Rules = append(cfg.Rules, s)
			}
		}
		if rc := strings.TrimSpace(r.FormValue("rule_custom")); rc != "" {
			cfg.Rules = append(cfg.Rules, rc)
		}
	}

	cfg.Workload, _ = strconv.Atoi(r.FormValue("workload"))
	if cfg.Workload < 1 || cfg.Workload > 4 {
		cfg.Workload = 2
	}
	cfg.CPUOnly = r.FormValue("cpu_only") == "on"
	cfg.MaxCPUPct, _ = strconv.Atoi(r.FormValue("max_cpu_pct"))
	if cfg.MaxCPUPct <= 0 || cfg.MaxCPUPct > 100 {
		cfg.MaxCPUPct = h.db.GetSettings().EffectiveMaxCPUPercent()
	}
	cfg.AffinityCores = resolveAffinityCores(cfg.MaxCPUPct)
	cfg.RuntimeSec, _ = strconv.Atoi(r.FormValue("runtime_sec"))
	return cfg
}

// resolveAffinityCores maps a "max CPU %" to a core count for --cpu-affinity.
// 100% (or unset) → 0 = no cap (all cores).
func resolveAffinityCores(pct int) int {
	cores := sysmon.ReadLimits().Cores
	if cores < 1 {
		cores = 1
	}
	if pct <= 0 || pct >= 100 {
		return 0
	}
	k := int(math.Round(float64(cores) * float64(pct) / 100.0))
	if k < 1 {
		k = 1
	}
	if k > cores {
		k = cores
	}
	return k
}

func (h *Handler) HashcatRun(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Redirect(w, r, "/modules/hashcat", http.StatusSeeOther)
		return
	}
	cfg := h.parseHashcatForm(r)
	if len(cfg.Hashes) == 0 {
		http.Redirect(w, r, "/modules/hashcat?error=no_hashes", http.StatusSeeOther)
		return
	}
	if cfg.Attack == 3 {
		if cfg.Mask == "" {
			http.Redirect(w, r, "/modules/hashcat?error=no_mask", http.StatusSeeOther)
			return
		}
	} else if cfg.Wordlist == "" {
		http.Redirect(w, r, "/modules/hashcat?error=no_wordlist", http.StatusSeeOther)
		return
	}

	ws := h.activeWorkspace(r)
	cfgJSON, _ := json.Marshal(cfg) // UploadedWL is json:"-", so not persisted
	// total=100 so the progress bar reflects hashcat's keyspace percent.
	scan, err := h.db.CreateScan(ws.ID, "hashcat", string(cfgJSON), 100)
	if err != nil {
		http.Redirect(w, r, "/modules/hashcat?error=db_error", http.StatusSeeOther)
		return
	}
	if h.queueIfSequential(w, r, scan) {
		return
	}
	go h.runHashcat(scan.ID, cfg)
	http.Redirect(w, r, "/modules/hashcat/results/"+scan.ID, http.StatusSeeOther)
}

func (h *Handler) HashcatResults(w http.ResponseWriter, r *http.Request) {
	scanID := strings.TrimPrefix(r.URL.Path, "/modules/hashcat/results/")
	scan, err := h.db.GetScan(scanID)
	if err != nil {
		http.NotFound(w, r)
		return
	}
	data := h.baseData(r, "Hashcat Results - scaNNer", "hashcat_results")
	var result hashcat.ScanResult
	json.Unmarshal([]byte(scan.Result), &result)
	data["Scan"] = scan
	data["Summary"] = result.Summary
	data["Hashes"] = result.Hashes
	h.renderResults(w, r, "hashcat_results_inner", data)
}

func (h *Handler) HashcatStatus(w http.ResponseWriter, r *http.Request) {
	scanID := strings.TrimPrefix(r.URL.Path, "/modules/hashcat/status/")
	scan, err := h.db.GetScan(scanID)
	if err != nil {
		http.NotFound(w, r)
		return
	}
	h.writeScanStatus(w, scan)
}

func (h *Handler) runHashcat(scanID string, cfg hashcatConfig) {
	if !h.db.MarkRunning(scanID) {
		return
	}
	ctx := h.scanMgr.Register(scanID)
	defer h.FinishScan(scanID)
	if cfg.UploadedWL != "" {
		defer os.Remove(cfg.UploadedWL)
	}

	scanCfg := hashcat.Config{
		Hashes:        cfg.Hashes,
		ModeID:        cfg.ModeID,
		ModeName:      cfg.ModeName,
		DetectMode:    cfg.DetectMode,
		Attack:        cfg.Attack,
		Wordlist:      cfg.Wordlist,
		Rules:         cfg.Rules,
		Mask:          cfg.Mask,
		Workload:      cfg.Workload,
		CPUOnly:       cfg.CPUOnly,
		AffinityCores: cfg.AffinityCores,
		RuntimeSec:    cfg.RuntimeSec,
	}

	var latest []byte
	var mu sync.Mutex
	doneCh := make(chan struct{})
	defer close(doneCh) // panic-safe ticker shutdown
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

	result := hashcat.Scan(ctx, scanCfg,
		func(done int, msg string) {
			// "$ " crumbs → commands column (non-batched); everything else the
			// coalesced path. hashcat emits few progress events so batching is
			// optional, but this matches the house style.
			if strings.HasPrefix(msg, "$ ") {
				h.db.UpdateScanProgress(scanID, done, msg)
				return
			}
			h.db.UpdateScanProgress(scanID, done, msg)
		},
		func(p *hashcat.ScanResult) {
			b, err := json.Marshal(p)
			if err == nil {
				mu.Lock()
				latest = b
				mu.Unlock()
			}
		})

	resJSON, _ := json.Marshal(result)
	h.db.UpdateScanResult(scanID, string(resJSON))

	if ctx.Err() == nil && result.Summary.Status == "error" {
		h.markHardFailure(scanID, []string{result.Summary.Warning}, 1)
	}
}
