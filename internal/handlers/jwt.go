package handlers

import (
	"encoding/json"
	"net/http"
	"strings"
	"sync"
	"time"

	"scanner/internal/models"
	"scanner/internal/modules/jwt"
)

type jwtConfig struct {
	Tokens          []string `json:"tokens"`
	Wordlist        []string `json:"wordlist,omitempty"`
	WordlistPath    string   `json:"wordlist_path,omitempty"`
	IncludeDefault  bool     `json:"include_default"`
	GenerateAttacks bool     `json:"generate_attacks"`
	// Active replay (audit MEDIUM fix): when TargetURL is non-empty every
	// generated attack token is sent to TargetURL and the per-token status
	// + response length is stored on the AttackToken so the operator can
	// see which forgeries the verifier actually accepts. Empty = skip.
	TargetURL    string `json:"target_url,omitempty"`
	HeaderName   string `json:"header_name,omitempty"`
	HeaderPrefix string `json:"header_prefix,omitempty"`
	// ReqTimeout is the effective per-request HTTP timeout (seconds) for the
	// active-replay phase, resolved from the http_tuning partial (override) or
	// the global Web settings via applyHTTPTuning. Persisted on the config so
	// the Restart path replays the same value. 0 = inherit the global Web
	// timeout at run time.
	ReqTimeout int `json:"req_timeout,omitempty"`
}

func (h *Handler) JWTPage(w http.ResponseWriter, r *http.Request) {
	data := h.baseData(r, "JWT Analyzer - scaNNer", "jwt")
	ws := data["ActiveWorkspace"].(*models.Workspace)
	scans, _ := h.db.ListScansLite(ws.ID, "jwt")
	data["Scans"] = scans
	h.render(w, "layout", data)
}

func parseJWTForm(r *http.Request) jwtConfig {
	cfg := jwtConfig{}
	for _, line := range strings.Split(r.FormValue("tokens"), "\n") {
		line = strings.TrimSpace(line)
		if line != "" {
			cfg.Tokens = append(cfg.Tokens, line)
		}
	}
	for _, line := range strings.Split(r.FormValue("wordlist"), "\n") {
		line = strings.TrimSpace(line)
		if line != "" {
			cfg.Wordlist = append(cfg.Wordlist, line)
		}
	}
	cfg.WordlistPath = strings.TrimSpace(r.FormValue("wordlist_path"))
	cfg.IncludeDefault = r.FormValue("include_default") == "on"
	cfg.GenerateAttacks = r.FormValue("generate_attacks") == "on"
	cfg.TargetURL = strings.TrimSpace(r.FormValue("target_url"))
	cfg.HeaderName = strings.TrimSpace(r.FormValue("header_name"))
	// Prefix intentionally NOT trimmed — a trailing space after "Bearer" is
	// the canonical spelling and users typing it literally should get it.
	cfg.HeaderPrefix = r.FormValue("header_prefix")
	return cfg
}

func (h *Handler) JWTRun(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Redirect(w, r, "/modules/jwt", http.StatusSeeOther)
		return
	}
	r.ParseForm()
	ws := h.activeWorkspace(r)
	cfg := parseJWTForm(r)
	if len(cfg.Tokens) == 0 {
		http.Redirect(w, r, "/modules/jwt?error=no_tokens", http.StatusSeeOther)
		return
	}
	// Per-scan HTTP tuning (http_tuning partial). jwt has NO concurrency
	// parameter — tokens are analysed serially and the HMAC cracker fans out
	// over runtime.NumCPU internally, not from config — so applyHTTPTuning's
	// effective concurrency is intentionally ignored. It sets opts.Timeout; we
	// persist that resolved timeout on the config so the active-replay client
	// honours the per-scan override AND the Restart path replays it.
	tuneOpts := h.BuildHTTPOptions(r)
	h.applyHTTPTuning(r, tuneOpts)
	cfg.ReqTimeout = int(tuneOpts.Timeout / time.Second)
	cfgJSON, _ := json.Marshal(cfg)
	scan, err := h.db.CreateScan(ws.ID, "jwt", string(cfgJSON), len(cfg.Tokens))
	if err != nil {
		http.Redirect(w, r, "/modules/jwt?error=db_error", http.StatusSeeOther)
		return
	}
	// Sequential scanning: if the operator ticked "start after the current
	// scan finishes" and this workspace is busy, park this run as queued.
	if h.queueIfSequential(w, r, scan) {
		return
	}
	go h.runJWT(scan.ID, cfg)
	http.Redirect(w, r, "/modules/jwt/results/"+scan.ID, http.StatusSeeOther)
}

func (h *Handler) JWTResults(w http.ResponseWriter, r *http.Request) {
	scanID := strings.TrimPrefix(r.URL.Path, "/modules/jwt/results/")
	scan, err := h.db.GetScan(scanID)
	if err != nil {
		http.NotFound(w, r)
		return
	}
	data := h.baseData(r, "JWT Analyzer Results - scaNNer", "jwt_results")
	var result jwt.ScanResult
	json.Unmarshal([]byte(scan.Result), &result)
	cracked := 0
	totalFindings := 0
	for _, tr := range result.Results {
		if tr.CrackedSecret != "" {
			cracked++
		}
		totalFindings += len(tr.Findings)
	}
	data["Scan"] = scan
	data["Results"] = result.Results
	data["CrackedCount"] = cracked
	data["TotalFindings"] = totalFindings
	h.renderResults(w, r, "jwt_results_inner", data)
}

func (h *Handler) JWTStatus(w http.ResponseWriter, r *http.Request) {
	scanID := strings.TrimPrefix(r.URL.Path, "/modules/jwt/status/")
	scan, err := h.db.GetScan(scanID)
	if err != nil {
		http.NotFound(w, r)
		return
	}
	h.writeScanStatus(w, scan)
}

func (h *Handler) runJWT(scanID string, cfg jwtConfig) {
	if !h.db.MarkRunning(scanID) {
		return
	}
	// Register via BeginScan so cancel flushes any HTTP idle pool opened by
	// the replay phase (audit MEDIUM fix). BuildHTTPOptionsFromSettings so
	// the killswitch source-IP binding + proxy / UA are picked up for the
	// forged-token replay probes.
	opts := h.BeginScan(scanID, h.BuildHTTPOptionsFromSettings())
	// Honour the per-scan HTTP timeout resolved by applyHTTPTuning in JWTRun
	// (and replayed from the stored config on Restart). BuildHTTPOptionsFromSettings
	// seeds opts.Timeout with the global Web default; override it when the scan
	// carried an explicit/effective value.
	if cfg.ReqTimeout > 0 {
		opts.Timeout = time.Duration(cfg.ReqTimeout) * time.Second
	}
	ctx := opts.Ctx
	defer h.FinishScan(scanID)
	scanCfg := jwt.Config{
		Tokens:          cfg.Tokens,
		Wordlist:        cfg.Wordlist,
		WordlistPath:    cfg.WordlistPath,
		IncludeDefault:  cfg.IncludeDefault,
		GenerateAttacks: cfg.GenerateAttacks,
		TargetURL:       cfg.TargetURL,
		HeaderName:      cfg.HeaderName,
		Prefix:          cfg.HeaderPrefix,
		HTTPOpts:        opts,
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

	result := jwt.Scan(ctx, scanCfg,
		func(done int, msg string) { h.db.UpdateScanProgress(scanID, done, msg) },
		func(p *jwt.ScanResult) {
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
	if opts.Ctx.Err() == nil {
		var errs []string
		for _, u := range result.Results {
			if u.Error != "" {
				errs = append(errs, u.Error)
			}
		}
		h.markHardFailure(scanID, errs, len(cfg.Tokens))
	}
}
