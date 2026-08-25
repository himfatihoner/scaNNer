package handlers

import (
	"encoding/json"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"time"

	"scanner/internal/models"
	"scanner/internal/modules/shared"
	"scanner/internal/modules/wpscan"
)

func (h *Handler) WPScanPage(w http.ResponseWriter, r *http.Request) {
	data := h.baseData(r, "WPScan - scaNNer", "wpscan")
	ws := data["ActiveWorkspace"].(*models.Workspace)
	scans, _ := h.db.ListScansLite(ws.ID, "wpscan")
	data["Scans"] = scans
	data["WSTargetGroups"] = h.groupTargetsByList(ws.ID)
	data["HasAPIKey"] = strings.TrimSpace(h.db.GetSettings().WPScanAPIKey) != ""
	h.render(w, "layout", data)
}

func (h *Handler) WPScanRun(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Redirect(w, r, "/modules/wpscan", http.StatusSeeOther)
		return
	}
	ws := h.activeWorkspace(r)

	var urls []string
	raw := r.FormValue("urls")
	for _, line := range strings.Split(raw, "\n") {
		line = strings.TrimSpace(line)
		if line != "" {
			urls = append(urls, line)
		}
	}
	if selected := r.Form["targets"]; len(selected) > 0 {
		urls = append(urls, selected...)
	}
	if len(urls) == 0 {
		http.Redirect(w, r, "/modules/wpscan?error=no_urls", http.StatusSeeOther)
		return
	}

	speed := wpscan.Speed(strings.TrimSpace(r.FormValue("speed")))
	switch speed {
	case wpscan.SpeedFast, wpscan.SpeedNormal, wpscan.SpeedAggressive:
	default:
		speed = wpscan.SpeedFast
	}

	// Build HTTP options from Settings (proxy / UA / killswitch binding)
	// + per-request headers/cookies parsed via ParseHTTPOptions. Without
	// this, wpscan ran blind to the user's proxy / UA / cookie config
	// and couldn't scan auth-gated or WAF-fronted WordPress installs.
	opts := h.BuildHTTPOptions(r)
	hp := buildWPScanHTTPParams(r, opts)

	// Optional Advanced form overrides for concurrency / per-process
	// thread count. Empty / non-numeric → fall back to module defaults
	// (2 processes × 30 threads). Capped to sane bounds so a typo
	// (e.g. "1000000") can't melt a target.
	maxConcurrent := parsePositiveInt(r.FormValue("max_concurrent"), 0, 16)
	maxThreads := parsePositiveInt(r.FormValue("max_threads"), 0, 100)

	cfgMap := map[string]interface{}{"urls": urls, "speed": speed}
	if hp.Proxy != "" {
		cfgMap["proxy"] = hp.Proxy
	}
	if hp.UserAgent != "" {
		cfgMap["user_agent"] = hp.UserAgent
	}
	if hp.CookieString != "" {
		cfgMap["cookie_string"] = hp.CookieString
	}
	if hp.HTTPAuth != "" {
		cfgMap["http_auth"] = hp.HTTPAuth
	}
	if len(hp.Headers) > 0 {
		cfgMap["http_headers"] = hp.Headers
	}
	if maxConcurrent > 0 {
		cfgMap["max_concurrent"] = maxConcurrent
	}
	if maxThreads > 0 {
		cfgMap["max_threads"] = maxThreads
	}
	cfgJSON, _ := json.Marshal(cfgMap)
	scan, err := h.db.CreateScan(ws.ID, "wpscan", string(cfgJSON), len(urls))
	if err != nil {
		http.Redirect(w, r, "/modules/wpscan?error=db_error", http.StatusSeeOther)
		return
	}

	if h.queueIfSequential(w, r, scan) {
		return
	}
	go h.runWPScan(scan.ID, urls, speed, hp, maxConcurrent, maxThreads, opts)
	http.Redirect(w, r, "/modules/wpscan/results/"+scan.ID, http.StatusSeeOther)
}

// parsePositiveInt returns the value clamped to [1, max] when the form
// field is a positive integer; otherwise returns 0 (meaning "use module
// default"). Invalid / negative input is silently coerced to 0 to avoid
// argv injection or absurd values reaching wpscan.
func parsePositiveInt(raw string, _ int, max int) int {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return 0
	}
	n, err := strconv.Atoi(raw)
	if err != nil || n <= 0 {
		return 0
	}
	if max > 0 && n > max {
		return max
	}
	return n
}

// buildWPScanHTTPParams gathers the per-scan HTTP knobs wpscan understands
// from the request form + the pre-built HTTPOptions. Headers/cookies parsed
// via ParseHTTPOptions are joined into wpscan's native flag formats
// (--headers "Name: Value", --cookie-string "a=b; c=d").
func buildWPScanHTTPParams(r *http.Request, opts *shared.HTTPOptions) wpscan.HTTPParams {
	hp := wpscan.HTTPParams{}
	if opts != nil {
		hp.Proxy = opts.ProxyURL
		hp.UserAgent = opts.UserAgent
		// Headers map → "Name: Value" entries; one --headers flag each.
		for name, value := range opts.Headers {
			name = strings.TrimSpace(name)
			value = strings.TrimSpace(value)
			if name == "" || value == "" {
				continue
			}
			hp.Headers = append(hp.Headers, name+": "+value)
		}
	}
	// Per-scan extras (textareas) — separate from the headers/cookies
	// matrix so users can paste a long auth cookie or basic-auth creds
	// without filling individual rows.
	if cs := strings.TrimSpace(r.FormValue("cookie_string")); cs != "" {
		hp.CookieString = cs
	} else if opts != nil && len(opts.Cookies) > 0 {
		// Fall back to ParseHTTPOptions' cookie matrix; serialise into
		// wpscan's expected `name1=val1; name2=val2` form.
		parts := make([]string, 0, len(opts.Cookies))
		for k, v := range opts.Cookies {
			k = strings.TrimSpace(k)
			v = strings.TrimSpace(v)
			if k != "" && v != "" {
				parts = append(parts, k+"="+v)
			}
		}
		if len(parts) > 0 {
			hp.CookieString = strings.Join(parts, "; ")
		}
	}
	if ha := strings.TrimSpace(r.FormValue("http_auth")); ha != "" {
		hp.HTTPAuth = ha
	}
	// Free-form custom headers, one per line ("Name: Value"). Lets users
	// paste an X-Forwarded-For / Authorization header without dealing
	// with the headers matrix.
	if extra := strings.TrimSpace(r.FormValue("custom_headers")); extra != "" {
		for _, line := range strings.Split(extra, "\n") {
			line = strings.TrimSpace(line)
			if line != "" && strings.Contains(line, ":") {
				hp.Headers = append(hp.Headers, line)
			}
		}
	}
	return hp
}

func (h *Handler) WPScanResults(w http.ResponseWriter, r *http.Request) {
	scanID := strings.TrimPrefix(r.URL.Path, "/modules/wpscan/results/")
	if scanID == "" {
		http.Redirect(w, r, "/modules/wpscan", http.StatusSeeOther)
		return
	}
	scan, err := h.db.GetScan(scanID)
	if err != nil {
		http.NotFound(w, r)
		return
	}

	data := h.baseData(r, "WPScan Results - scaNNer", "wpscan_results")
	var result wpscan.ScanResult
	json.Unmarshal([]byte(scan.Result), &result)

	vulnCount := 0
	infoCount := 0
	for _, tr := range result.Results {
		for _, f := range tr.Findings {
			if f.Severity == "INFO" {
				infoCount++
			} else {
				vulnCount++
			}
		}
	}

	data["Scan"] = scan
	data["Results"] = result.Results
	data["VulnCount"] = vulnCount
	data["InfoCount"] = infoCount
	h.renderResults(w, r, "wpscan_results_inner", data)
}

func (h *Handler) WPScanStatus(w http.ResponseWriter, r *http.Request) {
	scanID := strings.TrimPrefix(r.URL.Path, "/modules/wpscan/status/")
	scan, err := h.db.GetScan(scanID)
	if err != nil {
		http.NotFound(w, r)
		return
	}
	h.writeScanStatus(w, scan)
}

func (h *Handler) runWPScan(scanID string, urls []string, speed wpscan.Speed, hp wpscan.HTTPParams, maxConcurrent, maxThreads int, opts *shared.HTTPOptions) {
	if !h.db.MarkRunning(scanID) {
		return
	}
	// BeginScan registers the cancel ctx + HTTPOptions on the scan manager
	// so a Cancel flushes idle TCP pools. Previously this module called
	// scanMgr.Register directly which left opts unregistered.
	opts = h.BeginScan(scanID, opts)
	defer h.FinishScan(scanID)
	ctx := opts.Ctx

	// Audit fix: previously the handler mutated the package-level
	// `wpscan.APIToken` global, which two concurrent scans would race on
	// (and could even leak scan A's token into scan B mid-run). Now the
	// token is read once per scan and plumbed through Config, so each scan
	// goroutine reads its own immutable value.
	token := h.db.GetSettings().WPScanAPIKey

	// Canonical 2-second partial-flush ticker (template: smbenum.go:125).
	// Aggressive runs spend 30-60 min per host; without periodic flushing
	// the results page stays blank for hours, and any crash / cancel mid-run
	// drops every completed target's data. The PartialFunc receives a
	// snapshot after each target finishes; we marshal it under mu and the
	// ticker pushes the latest snapshot to UpdateScanResult on a 2s cadence.
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

	result := wpscan.ScanWithConfig(ctx, wpscan.Config{
		URLs:          urls,
		Speed:         speed,
		APIToken:      token,
		HTTPParams:    hp,
		MaxConcurrent: maxConcurrent,
		MaxThreads:    maxThreads,
		Opts:          opts,
	},
		func(done int, msg string) { h.db.UpdateScanProgress(scanID, done, msg) },
		func(p *wpscan.ScanResult) {
			b, err := json.Marshal(p)
			if err == nil {
				mu.Lock()
				latest = b
				mu.Unlock()
			}
		})

	resultJSON, _ := json.Marshal(result)
	h.db.UpdateScanResult(scanID, string(resultJSON))

	// Hard-failure surfacing: if every unit errored, mark the scan failed
	// with a translated reason rather than a silent "done" with zero findings.
	if opts.Ctx.Err() == nil {
		var errs []string
		for _, tr := range result.Results {
			if tr.Error != "" {
				errs = append(errs, tr.Error)
			}
		}
		h.markHardFailure(scanID, errs, len(urls))
	}
}
