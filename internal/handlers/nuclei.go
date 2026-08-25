package handlers

import (
	"encoding/json"
	"net/http"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"time"

	"scanner/internal/capacity"
	"scanner/internal/models"
	"scanner/internal/modules/nuclei"
	"scanner/internal/modules/shared"
	"scanner/internal/sysmon"
)

// nucleiTemplateIDRe matches a nuclei template ID (alphanumeric, dash,
// underscore) OR a relative path under the configured templates dir
// (slashes, dashes, underscores, alphanumerics, ending in .yaml/.yml).
// Audit SEC fix: previously any string from the textarea was forwarded
// verbatim as `-t <value>`, letting an operator (or anyone reaching the
// unauthenticated UI on :9090) point nuclei at /etc/, ~/.ssh, etc., for
// arbitrary local-file/directory enumeration. We reject:
//   - leading "-" (flag injection)
//   - absolute paths (leading "/" or "\\")
//   - ".." anywhere (parent-dir escape)
//   - any character outside [a-zA-Z0-9._/\-]
//   - empty / whitespace-only entries (caller already filters)
//
// Both bare template IDs ("wordpress-detect") and relative paths
// ("http/cves/2023/CVE-2023-12345.yaml") are accepted.
var nucleiTemplateIDRe = regexp.MustCompile(`^[a-zA-Z0-9][a-zA-Z0-9._/\-]*$`)

// safeNucleiTemplate validates a user-supplied -t value. Returns
// (value, true) when the entry is safe, (value, false) otherwise.
func safeNucleiTemplate(s string) (string, bool) {
	s = strings.TrimSpace(s)
	if s == "" {
		return "", false
	}
	if strings.HasPrefix(s, "-") || strings.HasPrefix(s, "/") || strings.HasPrefix(s, "\\") {
		return s, false
	}
	if strings.Contains(s, "..") {
		return s, false
	}
	if !nucleiTemplateIDRe.MatchString(s) {
		return s, false
	}
	return s, true
}

func (h *Handler) NucleiPage(w http.ResponseWriter, r *http.Request) {
	data := h.baseData(r, "Nuclei - scaNNer", "nuclei")
	ws := data["ActiveWorkspace"].(*models.Workspace)
	data["WSTargetGroups"] = h.groupTargetsByList(ws.ID)
	scans, _ := h.db.ListScansLite(ws.ID, "nuclei")
	data["Scans"] = scans
	h.render(w, "layout", data)
}

// nucleiConfig is the form-side serialization stored in scans.config.
type nucleiConfig struct {
	URLs               []string `json:"urls"`
	Severity           []string `json:"severity"`
	Tags               []string `json:"tags"`
	TemplateIDs        []string `json:"template_ids"`
	ExcludeTags        []string `json:"exclude_tags,omitempty"`
	ExcludeTemplates   []string `json:"exclude_templates,omitempty"`
	RateLimit          int      `json:"rate_limit"`
	Concurrency        int      `json:"concurrency"`
	Level              string   `json:"level,omitempty"` // aggressiveness: polite|normal|aggressive
	UpdateTemplates    bool     `json:"update_templates"`
	DAST               bool     `json:"dast,omitempty"`
	AutomaticScan      bool     `json:"automatic_scan,omitempty"`
	// HTTP auth knobs — wired from the run form + global Settings via
	// BuildHTTPOptions. Persisted on the scan row so Restart replays
	// the same auth setup.
	FollowRedirects bool `json:"follow_redirects"`
	SNIHost         string `json:"sni_host,omitempty"`

	// rejectedTemplates is populated by parseNucleiForm with template
	// entries that failed safeNucleiTemplate validation. NucleiRun uses
	// it to bounce the user back to the form with a friendly error. Not
	// persisted on the scan row (json:"-").
	rejectedTemplates []string `json:"-"`
}

func parseNucleiForm(r *http.Request) nucleiConfig {
	cfg := nucleiConfig{}
	for _, line := range strings.Split(r.FormValue("urls"), "\n") {
		line = strings.TrimSpace(line)
		if line != "" {
			cfg.URLs = append(cfg.URLs, line)
		}
	}
	cfg.Severity = r.Form["severity"]
	for _, t := range strings.Split(r.FormValue("tags"), ",") {
		t = strings.TrimSpace(t)
		if t != "" {
			cfg.Tags = append(cfg.Tags, t)
		}
	}
	for _, line := range strings.Split(r.FormValue("templates"), "\n") {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		if v, ok := safeNucleiTemplate(line); ok {
			cfg.TemplateIDs = append(cfg.TemplateIDs, v)
		} else {
			cfg.rejectedTemplates = append(cfg.rejectedTemplates, line)
		}
	}
	for _, t := range strings.Split(r.FormValue("exclude_tags"), ",") {
		t = strings.TrimSpace(t)
		if t != "" {
			cfg.ExcludeTags = append(cfg.ExcludeTags, t)
		}
	}
	for _, line := range strings.Split(r.FormValue("exclude_templates"), "\n") {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		if v, ok := safeNucleiTemplate(line); ok {
			cfg.ExcludeTemplates = append(cfg.ExcludeTemplates, v)
		} else {
			cfg.rejectedTemplates = append(cfg.rejectedTemplates, line)
		}
	}
	cfg.Level = strings.TrimSpace(r.FormValue("nuclei_level"))
	cfg.UpdateTemplates = r.FormValue("update_templates") == "on"
	cfg.DAST = r.FormValue("dast") == "on"
	cfg.AutomaticScan = r.FormValue("automatic_scan") == "on"
	cfg.FollowRedirects = r.FormValue("follow_redirects") == "on"
	cfg.SNIHost = strings.TrimSpace(r.FormValue("sni_host"))
	// Audit Q8 fix: allow per-scan rate limit + concurrency override.
	// Blank / 0 falls back to global Settings.EffectiveWebRateLimit /
	// EffectiveWebMaxConcurrent inside runNuclei so the italic "inherited
	// from Settings" hint on the form stays truthful.
	if v := strings.TrimSpace(r.FormValue("rate_limit")); v != "" {
		if n, err := strconv.Atoi(v); err == nil && n > 0 {
			cfg.RateLimit = n
		}
	}
	if v := strings.TrimSpace(r.FormValue("concurrency")); v != "" {
		if n, err := strconv.Atoi(v); err == nil && n > 0 {
			cfg.Concurrency = n
		}
	}
	return cfg
}

func (h *Handler) NucleiRun(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Redirect(w, r, "/modules/nuclei", http.StatusSeeOther)
		return
	}
	r.ParseForm()
	ws := h.activeWorkspace(r)
	cfg := parseNucleiForm(r)
	if selected := r.Form["targets"]; len(selected) > 0 {
		cfg.URLs = append(cfg.URLs, selected...)
	}
	if len(cfg.URLs) == 0 {
		http.Redirect(w, r, "/modules/nuclei?error=no_urls", http.StatusSeeOther)
		return
	}
	if len(cfg.rejectedTemplates) > 0 {
		// At least one template entry failed safeNucleiTemplate (contained
		// "..", absolute path, or shell metachars). Refuse the whole scan
		// rather than silently dropping the entries — operator probably
		// wanted those templates to run.
		http.Redirect(w, r, "/modules/nuclei?error=unsafe_template", http.StatusSeeOther)
		return
	}

	opts := h.BuildHTTPOptions(r)
	cfgJSON, _ := json.Marshal(cfg)
	scan, err := h.db.CreateScan(ws.ID, "nuclei", string(cfgJSON), len(cfg.URLs))
	if err != nil {
		http.Redirect(w, r, "/modules/nuclei?error=db_error", http.StatusSeeOther)
		return
	}

	// Sequential scanning: if the operator ticked "start after the current
	// scan finishes" and this workspace is busy, park this run as queued.
	if h.queueIfSequential(w, r, scan) {
		return
	}

	go h.runNuclei(scan.ID, cfg, opts)
	http.Redirect(w, r, "/modules/nuclei/results/"+scan.ID, http.StatusSeeOther)
}

func (h *Handler) NucleiResults(w http.ResponseWriter, r *http.Request) {
	scanID := strings.TrimPrefix(r.URL.Path, "/modules/nuclei/results/")
	if scanID == "" {
		http.Redirect(w, r, "/modules/nuclei", http.StatusSeeOther)
		return
	}
	scan, err := h.db.GetScan(scanID)
	if err != nil {
		http.NotFound(w, r)
		return
	}
	data := h.baseData(r, "Nuclei Results - scaNNer", "nuclei_results")

	// Audit S4: NucleiResults is hit on every initial page load AND every
	// htmx partial poll. Skip the json.Unmarshal + severity walk when the
	// result blob is empty (scan still pending / running with no findings
	// yet) — the inner template handles the empty Results case.
	var result nuclei.ScanResult
	var critical, high, medium, low, info, unknown int
	if len(scan.Result) > 0 {
		json.Unmarshal([]byte(scan.Result), &result)
		for _, tr := range result.Results {
			for _, f := range tr.Findings {
				switch f.Severity {
				case "critical":
					critical++
				case "high":
					high++
				case "medium":
					medium++
				case "low":
					low++
				case "info":
					info++
				default:
					unknown++
				}
			}
		}
	}

	data["Scan"] = scan
	data["Results"] = result.Results
	data["Truncated"] = result.Truncated
	data["TruncateReason"] = result.TruncateReason
	data["CriticalCount"] = critical
	data["HighCount"] = high
	data["MediumCount"] = medium
	data["LowCount"] = low
	data["InfoCount"] = info
	data["UnknownCount"] = unknown
	data["TotalFindings"] = critical + high + medium + low + info + unknown
	h.renderResults(w, r, "nuclei_results_inner", data)
}

func (h *Handler) NucleiStatus(w http.ResponseWriter, r *http.Request) {
	scanID := strings.TrimPrefix(r.URL.Path, "/modules/nuclei/status/")
	scan, err := h.db.GetScan(scanID)
	if err != nil {
		http.NotFound(w, r)
		return
	}
	h.writeScanStatus(w, scan)
}

func (h *Handler) runNuclei(scanID string, cfg nucleiConfig, opts *shared.HTTPOptions) {
	if !h.db.MarkRunning(scanID) {
		return
	}
	opts = h.BeginScan(scanID, opts)
	ctx := opts.Ctx
	defer h.FinishScan(scanID)

	// Live result saver. Audit S2: previously the partial callback
	// marshalled the entire (growing) ScanResult per fire, then the
	// 2-second DB ticker marshalled again. Now we keep only the latest
	// snapshot pointer; the ticker is the sole marshal site, so the
	// hot path drops the per-finding marshal cost.
	var latest *nuclei.ScanResult
	var mu sync.Mutex
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
				mu.Lock()
				snap := latest
				mu.Unlock()
				if snap == nil {
					continue
				}
				if b, err := json.Marshal(snap); err == nil {
					h.db.UpdateScanResult(scanID, string(b))
				}
			}
		}
	}()

	settings := h.db.GetSettings()
	// Do NOT inherit the gentle web-tier rate limit for nuclei. web_rate_limit
	// throttles polite in-process web scanning, but nuclei is a bulk engine:
	// forcing it to e.g. 10 req/s turns a full-template scan over many hosts
	// into a multi-day, guaranteed-truncated crawl (this is exactly what
	// bit the operator). Honor an explicit per-scan rate limit only;
	// otherwise leave nuclei at its own (much faster) default.
	scanCfg := buildNucleiScanConfig(cfg, settings, opts)

	result := nuclei.Scan(ctx, cfg.URLs, scanCfg,
		func(done int, msg string) {
			h.db.UpdateScanProgress(scanID, done, msg)
		},
		func(partial *nuclei.ScanResult) {
			// Cheap pointer swap — the snapshot was already deep-copied
			// inside the module under its own mutex. Marshal happens
			// once on the 2s DB ticker, not per finding.
			mu.Lock()
			latest = partial
			mu.Unlock()
		})

	resultJSON, _ := json.Marshal(result)
	h.db.UpdateScanResult(scanID, string(resultJSON))
	// A truncated run is INCOMPLETE — finalize it as such so the Scans list
	// / dashboard badge is NOT a clean green "done". MarkScanError sets the
	// terminal status now; the deferred FinishScan's MarkDoneUnlessCancelled
	// won't override an already-error row. The results page also shows the
	// red INCOMPLETE banner via the Truncated flag.
	if result.Truncated {
		h.db.MarkScanError(scanID, "INCOMPLETE — "+result.TruncateReason)
	}
}

// buildNucleiScanConfig maps a stored nucleiConfig + settings + opts into the
// module ScanConfig. Extracted so runNuclei and runNucleiResume stay in sync.
func buildNucleiScanConfig(cfg nucleiConfig, settings models.AppSettings, opts *shared.HTTPOptions) nuclei.ScanConfig {
	rl := cfg.RateLimit
	conc := cfg.Concurrency
	bulk := 0
	if cfg.Level != "" {
		lrl, lconc, lbulk := nuclei.LevelSettings(cfg.Level)
		if rl <= 0 {
			rl = lrl
		}
		if conc <= 0 {
			conc = lconc
		}
		bulk = lbulk
	} else {
		if conc <= 0 {
			// Capacity-recommended (ClassToolRate) instead of the flat web global
			// — caps nuclei -c at a machine-aware value rather than a possible 999.
			conc = capacity.Recommend("nuclei", sysmon.ReadLimits())
		}
		if conc < 25 {
			conc = 25
		}
	}
	scanCfg := nuclei.ScanConfig{
		Severity:         cfg.Severity,
		Tags:             cfg.Tags,
		TemplateIDs:      cfg.TemplateIDs,
		ExcludeTags:      cfg.ExcludeTags,
		ExcludeTemplates: cfg.ExcludeTemplates,
		RateLimit:        rl,
		Concurrency:      conc,
		BulkSize:         bulk,
		UpdateTemplates:  cfg.UpdateTemplates,
		DAST:             cfg.DAST,
		AutomaticScan:    cfg.AutomaticScan,
		FollowRedirects:  cfg.FollowRedirects,
		SNIHost:          cfg.SNIHost,
		Opts:             opts,
	}
	if opts != nil {
		scanCfg.CustomHeaders = opts.Headers
		scanCfg.Cookies = opts.Cookies
		scanCfg.ProxyURL = opts.ProxyURL
		scanCfg.UserAgent = opts.UserAgent
	}
	return scanCfg
}
