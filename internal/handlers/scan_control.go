package handlers

import (
	"encoding/json"
	"net/http"
	"strings"

	"scanner/internal/models"
	"scanner/internal/modules/advancedweb"
	"scanner/internal/modules/assetdisc"
	"scanner/internal/modules/authtest"
	"scanner/internal/modules/cachepoison"
	"scanner/internal/modules/concurtest"
	"scanner/internal/modules/corsscan"
	"scanner/internal/modules/cvematch"
	"scanner/internal/modules/graphqlscan"
	"scanner/internal/modules/oob"
	"scanner/internal/modules/openredirect"
	"scanner/internal/modules/shared"
	"scanner/internal/modules/sstiscan"
	"scanner/internal/modules/takeover"
	"scanner/internal/modules/wafdetect"
	"scanner/internal/modules/wpscan"
)

// ScanStop cancels a running scan
func (h *Handler) ScanStop(w http.ResponseWriter, r *http.Request) {
	scanID := r.FormValue("id")
	if scanID == "" {
		scanID = strings.TrimPrefix(r.URL.Path, "/scans/stop/")
	}
	if scanID == "" {
		http.Error(w, "missing scan id", http.StatusBadRequest)
		return
	}
	scan, err := h.db.GetScan(scanID)
	if err != nil {
		http.NotFound(w, r)
		return
	}
	if scan.Status == models.ScanQueued {
		// A queued scan (sequential scanning) never started — no scanMgr
		// context, no subprocesses. "Cancel queue" just drops it out of the
		// queue by stamping it cancelled so the scheduler skips it.
		h.db.UpdateScanStatus(scanID, models.ScanCancelled)
		h.db.UpdateScanProgress(scanID, 0, "Removed from queue")
		h.redirectBack(w, r)
		return
	}
	if scan.Status == models.ScanRunning || scan.Status == models.ScanPending {
		h.scanMgr.Cancel(scanID)
		// Audit fix: OOB sessions bypass scanMgr; without an explicit
		// Drop the listener + goroutines survive the "stop" click.
		// Mirrors OOBStop for parity across generic Stop and per-module
		// Stop routes.
		if scan.Module == "oob" {
			var s OOBSession
			if json.Unmarshal([]byte(scan.Config), &s) == nil && s.SessionID != "" {
				if sess := oob.Get(s.SessionID); sess != nil {
					interactions := sess.Interactions()
					resJSON, _ := json.Marshal(map[string]any{"interactions": interactions})
					h.db.UpdateScanResult(scanID, string(resJSON))
					oob.Drop(s.SessionID)
				}
			}
		}
		h.db.UpdateScanStatus(scanID, models.ScanCancelled)
		// Audit B73: replace whatever progress_msg the in-flight scanner
		// was writing with an explicit "cancelled" note. Without this
		// the UI showed the last partial-progress text frozen forever
		// (e.g. "scanning host 5/40" on a scan the user cancelled
		// minutes ago), which read as a stuck scan.
		h.db.UpdateScanProgress(scanID, scan.ProgressDone, "Cancelled by user")
	}
	h.redirectBack(w, r)
}

// ScanDelete removes a scan record
func (h *Handler) ScanDelete(w http.ResponseWriter, r *http.Request) {
	scanID := r.FormValue("id")
	if scanID == "" {
		scanID = strings.TrimPrefix(r.URL.Path, "/scans/delete/")
	}
	if scanID == "" {
		http.Error(w, "missing scan id", http.StatusBadRequest)
		return
	}
	// Cancel if still running
	scan, err := h.db.GetScan(scanID)
	if err == nil && (scan.Status == models.ScanRunning || scan.Status == models.ScanPending) {
		h.scanMgr.Cancel(scanID)
	}
	// Audit fix: OOB sessions don't route through scanMgr, so a Delete
	// would leak the HTTP listener + goroutines + interaction slice
	// until process exit. Drop the session before removing the row.
	if err == nil && scan != nil && scan.Module == "oob" {
		var s OOBSession
		if json.Unmarshal([]byte(scan.Config), &s) == nil && s.SessionID != "" {
			oob.Drop(s.SessionID)
		}
	}
	// Record who deleted what BEFORE the row is gone. The audit log has no FK
	// to scans, so this entry survives the delete (and can't be purged).
	if scan != nil {
		h.db.AddAudit(models.AuditEntry{
			UserID:      auditUserID(h.currentUser(r)),
			Username:    auditUsername(h.currentUser(r)),
			Category:    models.AuditScan,
			Action:      "scan.delete",
			Module:      scan.Module,
			WorkspaceID: scan.WorkspaceID,
			ScanID:      scanID,
			IP:          clientIP(r),
		})
	}

	h.db.DeleteScan(scanID)
	h.db.DeleteScanVulnCache(scanID) // drop this scan's per-scan vuln cache row
	h.db.ClearRescanVerify(scanID)   // drop any rescan-verify links (else they orphan)

	// A scan's findings are derived from its stored result, so deleting the
	// scan must also drop the derived data: invalidate the workspace's
	// vulnerability index + asset search index (in memory and on disk) so the
	// deleted scan's vulnerabilities/assets disappear immediately.
	if err == nil && scan != nil && scan.WorkspaceID != "" {
		h.invalidateWorkspaceIndexes(scan.WorkspaceID)
	}

	// If redirect target is the deleted scan's results page, redirect to scans page
	ref := r.Header.Get("Referer")
	if strings.Contains(ref, scanID) {
		http.Redirect(w, r, "/scans", http.StatusSeeOther)
		return
	}
	h.redirectBack(w, r)
}

// ScanArchive flips a scan's archived flag (1 ↔ 0). Archived scans are
// hidden from /scans and the dashboard but kept in the DB; the /scans/archive
// page lists them. POST id=<scanID>&action=archive|unarchive.
func (h *Handler) ScanArchive(w http.ResponseWriter, r *http.Request) {
	scanID := r.FormValue("id")
	if scanID == "" {
		scanID = strings.TrimPrefix(r.URL.Path, "/scans/archive/")
	}
	if scanID == "" {
		http.Error(w, "missing scan id", http.StatusBadRequest)
		return
	}
	action := r.FormValue("action")
	scan, err := h.db.GetScan(scanID)
	if err != nil {
		http.NotFound(w, r)
		return
	}
	// Block archiving live scans — they need to land in done/error/cancelled
	// first so the archive holds only completed work.
	if !scan.Archived && (scan.Status == models.ScanRunning || scan.Status == models.ScanPending) {
		http.Redirect(w, r, "/scans?error=cannot_archive_running", http.StatusSeeOther)
		return
	}
	archived := !scan.Archived
	if action == "unarchive" {
		archived = false
	} else if action == "archive" {
		archived = true
	}
	h.db.SetScanArchived(scanID, archived)
	// If we just archived from a results page, redirect to /scans;
	// unarchive stays put.
	ref := r.Header.Get("Referer")
	if archived && strings.Contains(ref, "/results/") {
		http.Redirect(w, r, "/scans", http.StatusSeeOther)
		return
	}
	h.redirectBack(w, r)
}

// ScanResume continues a single paused scan from its checkpoint (manual
// button). The connectivity monitor calls the same resumeOne on auto-recovery;
// ResumeToRunning makes the two idempotent (only one wins the paused→running
// flip).
func (h *Handler) ScanResume(w http.ResponseWriter, r *http.Request) {
	scanID := r.FormValue("id")
	if scanID == "" {
		scanID = strings.TrimPrefix(r.URL.Path, "/scans/resume/")
	}
	if scanID == "" {
		http.Error(w, "missing scan id", http.StatusBadRequest)
		return
	}
	scan, err := h.db.GetScan(scanID)
	if err != nil {
		http.NotFound(w, r)
		return
	}
	if scan.Status == models.ScanPaused {
		if !h.resumeOne(*scan) {
			http.Redirect(w, r, resultsURL(scan.Module, scanID)+"?error=resume_unsupported", http.StatusSeeOther)
			return
		}
	}
	http.Redirect(w, r, resultsURL(scan.Module, scanID), http.StatusSeeOther)
}

// ScanRestart re-runs a scan with its original config
func (h *Handler) ScanRestart(w http.ResponseWriter, r *http.Request) {
	scanID := r.FormValue("id")
	if scanID == "" {
		scanID = strings.TrimPrefix(r.URL.Path, "/scans/restart/")
	}
	if scanID == "" {
		http.Error(w, "missing scan id", http.StatusBadRequest)
		return
	}
	scan, err := h.db.GetScan(scanID)
	if err != nil {
		http.NotFound(w, r)
		return
	}

	// Cancel if running
	if scan.Status == models.ScanRunning || scan.Status == models.ScanPending {
		h.scanMgr.Cancel(scanID)
	}

	// Create a new scan with same config
	newScan, err := h.db.CreateScan(scan.WorkspaceID, scan.Module, scan.Config, scan.ProgressTotal)
	if err != nil {
		http.Error(w, "failed to create scan", http.StatusInternalServerError)
		return
	}

	// Restart launches a module, so it must leave an audit trail like a normal
	// run (the /modules/*/run audit choke doesn't see this path).
	me := h.currentUser(r)
	h.db.AddAudit(models.AuditEntry{
		UserID:      auditUserID(me),
		Username:    auditUsername(me),
		Category:    models.AuditScan,
		Action:      "scan.restart",
		Module:      scan.Module,
		WorkspaceID: scan.WorkspaceID,
		ScanID:      newScan.ID,
		IP:          clientIP(r),
	})

	// Dispatch based on module — reuse config parsing from each module
	h.dispatchRestart(newScan.ID, scan.Module, scan.Config)

	// Redirect to new scan's results page
	http.Redirect(w, r, resultsURL(scan.Module, newScan.ID), http.StatusSeeOther)
}

func (h *Handler) dispatchRestart(scanID, module, configJSON string) {
	opts := &sharedOpts{}
	_ = opts
	switch module {
	case "sslscan":
		var cfg SSLScanConfig
		json.Unmarshal([]byte(configJSON), &cfg)
		// Restart replays the stored config against Settings-derived
		// HTTPOptions (no per-scan Request to inherit from). BeginScan
		// wires up the cancellable scan-manager context so a subsequent
		// Stop propagates to the in-flight TLS probes.
		sslopts := h.BeginScan(scanID, h.BuildHTTPOptionsFromSettings())
		go h.runSSLScan(scanID, cfg.Targets, cfg.Ports, cfg.StartTLS, sslopts.Ctx)
	case "httpxfind":
		var cfg HTTPXFindConfig
		json.Unmarshal([]byte(configJSON), &cfg)
		go h.runHTTPXFind(scanID, cfg.Targets, cfg.Mode, h.BuildHTTPOptionsFromSettings(), 0, 0)
	case "httpmethods":
		var cfg HTTPMethodsConfig
		json.Unmarshal([]byte(configJSON), &cfg)
		// Audit fix: re-attach per-scan Headers/Cookies/UA from the
		// stored config onto the Settings-derived opts so Restart
		// replays the same probe shape. Proxy + NetworkInterface come
		// from current Settings (so a Settings change is honoured).
		ropts := h.BuildHTTPOptionsFromSettings()
		if ropts != nil {
			if len(cfg.Headers) > 0 {
				ropts.Headers = cfg.Headers
			}
			if len(cfg.Cookies) > 0 {
				ropts.Cookies = cfg.Cookies
			}
			if cfg.UserAgent != "" {
				ropts.UserAgent = cfg.UserAgent
			}
		}
		go h.runHTTPMethods(scanID, cfg.URLs, ropts)
	case "wafdetect":
		var c wafdetect.Config
		json.Unmarshal([]byte(configJSON), &c)
		// Audit fix: replay the same HTTP-options shape on restart —
		// proxy/UA/custom headers/BurpSuccessOnly were previously dropped.
		// NetworkInterface still comes from current Settings so a Settings
		// change is honoured.
		ropts := h.BuildHTTPOptionsFromSettings()
		if ropts != nil {
			if len(c.Headers) > 0 {
				ropts.Headers = c.Headers
			}
			if len(c.Cookies) > 0 {
				ropts.Cookies = c.Cookies
			}
			if c.UserAgent != "" {
				ropts.UserAgent = c.UserAgent
			}
			if c.ProxyURL != "" {
				ropts.ProxyURL = c.ProxyURL
			}
			if c.BurpSuccessOnly {
				ropts.BurpSuccessOnly = true
			}
		}
		go h.runWAFDetect(scanID, c, ropts)
	case "techdetect":
		var c struct {
			URLs         []string          `json:"urls"`
			AutoCVEMatch bool              `json:"auto_cvematch"`
			Aggressive   bool              `json:"aggressive"`
			Headers      map[string]string `json:"headers"`
			Cookies      map[string]string `json:"cookies"`
			UserAgent    string            `json:"user_agent"`
		}
		json.Unmarshal([]byte(configJSON), &c)
		// Look up workspace from the scan row — restart re-uses the same scan ID.
		scan, _ := h.db.GetScan(scanID)
		wsID := ""
		if scan != nil {
			wsID = scan.WorkspaceID
		}
		// Audit fix: re-attach per-scan Headers/Cookies/UA from the
		// stored config onto the Settings-derived opts so Restart
		// replays the same probe shape. Proxy + NetworkInterface come
		// from current Settings (so a Settings change is honoured).
		ropts := h.BuildHTTPOptionsFromSettings()
		if ropts != nil {
			if len(c.Headers) > 0 {
				ropts.Headers = c.Headers
			}
			if len(c.Cookies) > 0 {
				ropts.Cookies = c.Cookies
			}
			if c.UserAgent != "" {
				ropts.UserAgent = c.UserAgent
			}
		}
		go h.runTechDetect(scanID, wsID, c.URLs, ropts, c.AutoCVEMatch, c.Aggressive)
	case "spider":
		var c struct {
			URLs     []string `json:"urls"`
			MaxDepth int      `json:"max_depth"`
			MaxPages int      `json:"max_pages"`
		}
		json.Unmarshal([]byte(configJSON), &c)
		sc := defaultSpiderConfig()
		if c.MaxDepth > 0 {
			sc.MaxDepth = c.MaxDepth
		}
		if c.MaxPages > 0 {
			sc.MaxPages = c.MaxPages
		}
		go h.runSpider(scanID, c.URLs, sc, h.BuildHTTPOptionsFromSettings())
	case "direnum":
		go h.restartDirEnum(scanID, configJSON)
	case "secheaders":
		var c struct {
			URLs        []string          `json:"urls"`
			Methods     []string          `json:"methods"`
			HTTPHeaders map[string]string `json:"http_headers"`
			HTTPCookies map[string]string `json:"http_cookies"`
			UserAgent   string            `json:"user_agent"`
		}
		json.Unmarshal([]byte(configJSON), &c)
		if len(c.Methods) == 0 {
			c.Methods = []string{"GET"}
		}
		// Audit fix: previously passed nil opts → Restart dropped
		// proxy / UA / killswitch binding even when Settings hadn't
		// changed, AND dropped the original launch-form Headers/Cookies
		// so a re-run silently hit unauthenticated endpoints. Rebuild
		// HTTPOptions from current Settings, then graft the persisted
		// per-scan extras back on.
		opts := h.BuildHTTPOptionsFromSettings()
		if opts == nil {
			opts = &shared.HTTPOptions{}
		}
		if len(c.HTTPHeaders) > 0 {
			opts.Headers = c.HTTPHeaders
		}
		if len(c.HTTPCookies) > 0 {
			opts.Cookies = c.HTTPCookies
		}
		if c.UserAgent != "" {
			opts.UserAgent = c.UserAgent
		}
		go h.runSecHeaders(scanID, c.URLs, c.Methods, opts, h.db.GetSettings().EffectiveWebMaxConcurrent())
	case "wpscan":
		var c struct {
			URLs          []string     `json:"urls"`
			Speed         wpscan.Speed `json:"speed"`
			Proxy         string       `json:"proxy"`
			UserAgent     string       `json:"user_agent"`
			CookieString  string       `json:"cookie_string"`
			HTTPAuth      string       `json:"http_auth"`
			HTTPHeaders   []string     `json:"http_headers"`
			MaxConcurrent int          `json:"max_concurrent"`
			MaxThreads    int          `json:"max_threads"`
		}
		json.Unmarshal([]byte(configJSON), &c)
		if c.Speed == "" {
			c.Speed = wpscan.SpeedFast
		}
		// Rebuild HTTP options from current Settings (proxy / UA /
		// killswitch binding) so the replay honours the live config,
		// then graft persisted per-scan extras (cookie / http-auth /
		// custom headers / explicit UA override) back on.
		opts := h.BuildHTTPOptionsFromSettings()
		if opts == nil {
			opts = &shared.HTTPOptions{}
		}
		if c.UserAgent != "" {
			opts.UserAgent = c.UserAgent
		}
		hp := wpscan.HTTPParams{
			Proxy:        c.Proxy,
			UserAgent:    c.UserAgent,
			CookieString: c.CookieString,
			HTTPAuth:     c.HTTPAuth,
			Headers:      c.HTTPHeaders,
		}
		if hp.Proxy == "" {
			hp.Proxy = opts.ProxyURL
		}
		if hp.UserAgent == "" {
			hp.UserAgent = opts.UserAgent
		}
		go h.runWPScan(scanID, c.URLs, c.Speed, hp, c.MaxConcurrent, c.MaxThreads, opts)
	case "dnsenum":
		go h.restartDNSEnum(scanID, configJSON)
	case "nuclei":
		var c nucleiConfig
		json.Unmarshal([]byte(configJSON), &c)
		go h.runNuclei(scanID, c, h.BuildHTTPOptionsFromSettings())
	case "hostdiscovery":
		var c hostDiscoveryConfig
		json.Unmarshal([]byte(configJSON), &c)
		go h.runHostDiscovery(scanID, c)
	case "portservice":
		var c portServiceConfig
		json.Unmarshal([]byte(configJSON), &c)
		go h.runPortService(scanID, c, h.BuildHTTPOptionsFromSettings())
	case "smbenum":
		var c smbEnumConfig
		json.Unmarshal([]byte(configJSON), &c)
		// audit M5: Password is not persisted to scans.config, so a
		// Restart of an authenticated scan re-runs anonymously unless
		// the operator re-enters the password on the launch form.
		// Restart clears any Username as well so the anonymous run is
		// unambiguous — the operator either wants the same auth (uses
		// the launch form) or an anonymous re-run.
		if c.Password == "" {
			c.Username = ""
		}
		go h.runSMBEnum(scanID, c)
	case "brutef":
		var c bruteFConfig
		json.Unmarshal([]byte(configJSON), &c)
		go h.runBruteF(scanID, c)
	case "whoisinfo":
		var c whoisinfoConfig
		json.Unmarshal([]byte(configJSON), &c)
		go h.runWhoisInfo(scanID, c)
	case "emailharvest":
		var c emailHarvestConfig
		json.Unmarshal([]byte(configJSON), &c)
		go h.runEmailHarvest(scanID, c)
	case "leakscan":
		var c leakScanConfig
		json.Unmarshal([]byte(configJSON), &c)
		// Audit MEDIUM fix: restart path was missing HTTPOptions plumb,
		// so a re-run silently dropped killswitch binding + proxy/UA
		// even though those Settings hadn't changed. BuildHTTPOptionsFromSettings
		// rebuilds from current Settings only (no per-request headers).
		go h.runLeakScan(scanID, c, h.BuildHTTPOptionsFromSettings())
	case "snmpenum":
		var c snmpEnumConfig
		json.Unmarshal([]byte(configJSON), &c)
		go h.runSNMPEnum(scanID, c)
	case "jwt":
		var c jwtConfig
		json.Unmarshal([]byte(configJSON), &c)
		go h.runJWT(scanID, c)
	case "paramdisc":
		var c paramDiscConfig
		json.Unmarshal([]byte(configJSON), &c)
		go h.runParamDisc(scanID, c, h.BuildHTTPOptionsFromSettings(), h.db.GetSettings().EffectiveWebMaxConcurrent())

	// Modules whose restart was previously a no-op — clicking Restart
	// on these used to create a new scan record that stayed Pending
	// forever because dispatchRestart had no case for them. The
	// user's report ("Rescan does something weird") was this bug:
	// the new scan appeared but nothing ran.
	case "advancedweb":
		var c advancedweb.Config
		json.Unmarshal([]byte(configJSON), &c)
		go h.runAdvancedWeb(scanID, c, h.BuildHTTPOptionsFromSettings())
	case "cvematch":
		var c cvematch.Config
		json.Unmarshal([]byte(configJSON), &c)
		go h.runCVEMatch(scanID, c)
	case "sstiscan":
		var c sstiscan.Config
		json.Unmarshal([]byte(configJSON), &c)
		go h.runSSTIScan(scanID, c, h.BuildHTTPOptionsFromSettings())
	case "takeover":
		var c takeover.Config
		json.Unmarshal([]byte(configJSON), &c)
		go h.runTakeover(scanID, c, h.BuildHTTPOptionsFromSettings())
	case "corsscan":
		var c corsscan.Config
		json.Unmarshal([]byte(configJSON), &c)
		go h.runCORSScan(scanID, c, h.BuildHTTPOptionsFromSettings())
	case "graphqlscan":
		var c graphqlscan.Config
		json.Unmarshal([]byte(configJSON), &c)
		go h.runGraphQLScan(scanID, c, h.BuildHTTPOptionsFromSettings())
	case "openredirect":
		var c openredirect.Config
		json.Unmarshal([]byte(configJSON), &c)
		go h.runOpenRedirect(scanID, c, h.BuildHTTPOptionsFromSettings())
	case "authtest":
		var c authtest.Config
		json.Unmarshal([]byte(configJSON), &c)
		go h.runAuthTest(scanID, c, h.BuildHTTPOptionsFromSettings())
	case "concurtest":
		// concurtest serializes as {targets, config} — see ConcurTestRun.
		var c struct {
			Targets []string             `json:"targets"`
			Config  concurtest.ScanConfig `json:"config"`
		}
		json.Unmarshal([]byte(configJSON), &c)
		go h.runConcurTest(scanID, c.Targets, c.Config, h.BuildHTTPOptionsFromSettings())
	case "assetdisc":
		var c assetdisc.Config
		json.Unmarshal([]byte(configJSON), &c)
		go h.runAssetDisc(scanID, c, h.BuildHTTPOptionsFromSettings())
	case "cachepoison":
		var c cachepoison.Config
		json.Unmarshal([]byte(configJSON), &c)
		go h.runCachePoison(scanID, c, h.BuildHTTPOptionsFromSettings())
	case "oob":
		// Audit fix: previously OOB restart was a no-op — clicking
		// Restart created a new scan row that stayed Pending forever
		// with no listener bound. startOOBRestart mints a fresh
		// session (new tokens + listener) and rewrites the row's
		// Config to point at the new session.
		var prev OOBSession
		json.Unmarshal([]byte(configJSON), &prev)
		go h.startOOBRestart(scanID, prev)
	case "adpentest":
		var cfg adpentestForm
		json.Unmarshal([]byte(configJSON), &cfg)
		go h.runAdpentest(scanID, cfg)
	default:
		// No restart dispatcher for this module — fail the freshly-created scan
		// visibly instead of leaving a permanent 'pending' ghost. A pending row
		// counts as active (CountActiveScans) and would wedge the workspace's
		// sequential-scan queue until the next process restart.
		h.db.MarkScanError(scanID, "Restart is not supported for module "+module)
	}
}

// sharedOpts is a placeholder for future use
type sharedOpts struct{}

func resultsURL(module, scanID string) string {
	return "/modules/" + module + "/results/" + scanID
}

// redirectBack sends the user back to where they came from
func (h *Handler) redirectBack(w http.ResponseWriter, r *http.Request) {
	ref := r.Header.Get("Referer")
	if ref == "" {
		ref = "/scans"
	}
	http.Redirect(w, r, ref, http.StatusSeeOther)
}
