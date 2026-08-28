package handlers

import (
	"bufio"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"html/template"
	"io"
	"log"
	"math"
	"net"
	"net/http"
	"net/url"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"time"

	"scanner/internal/capacity"
	"scanner/internal/database"
	"scanner/internal/models"
	"scanner/internal/modules"
	"scanner/internal/modules/shared"
	scannet "scanner/internal/network"
	"scanner/internal/sysmon"
)

const activeWSCookie = "scanner_active_ws"

// Handler holds dependencies for HTTP handlers
type Handler struct {
	registry      *modules.Registry
	db            *database.DB
	templates     *template.Template
	scanMgr       *ScanManager
	secureCookies bool // Secure flag on the session cookie (true when serving HTTPS)
}

// ScanMgr exposes the manager so external bootstrap code (cmd/scanner)
// can wire the killswitch monitor's CancelAll callback without poking
// at unexported state.
func (h *Handler) ScanMgr() *ScanManager { return h.scanMgr }

// New creates a new Handler
func New(registry *modules.Registry, db *database.DB, templateDir string) (*Handler, error) {
	funcMap := template.FuncMap{
		"targetTypeLabel":   models.TargetTypeLabel,
		"moduleDisplayName": models.ModuleDisplayName,
		"isVulnEmitter":     modules.IsVulnEmitter,
		// assetKey is the bare, scheme-stripped host used as the /assets/<key>
		// path — linking with a raw "https://host" would put "://" in the URL
		// path, which net/http path-cleans into a broken "/assets/https:/host".
		"assetKey": normalizeAsset,
		// vulnID computes the stable report ID for a finding so the same ID
		// shows on the Vulnerabilities page and the per-asset findings.
		"vulnID": vulnID,
		// vulnReport resolves a vuln into the same fully-Turkish report the
		// export produces (translated title/description, KB narrative, cleaned
		// CVE, nmap/openssl PoC) for the Vulnerabilities-page detail drawer.
		"vulnReport": func(v GlobalVuln) VulnReport { return buildVulnReport(v, "tr") },
		// moduleIcon looks up the icon (emoji) from the registry so scans
		// list / dashboards stay in sync as new modules are added. Falls
		// back to "🧩" for unknown modules.
		"moduleIcon": func(name string) string {
			if m, ok := registry.Get(name); ok {
				return m.Icon()
			}
			return "🧩"
		},
		"divf": func(a, b float64) float64 {
			if b == 0 {
				return 0
			}
			return a / b
		},
		"mulf": func(a, b float64) float64 { return a * b },
		"intf": func(a int) float64 { return float64(a) },
		"list": func(args ...interface{}) []interface{} { return args },
		"add":  func(a, b int) int { return a + b },
		// scanPct is the progress percentage clamped to [0,100] so a module
		// that momentarily emits progress_done > progress_total (e.g. a chained
		// second phase with its own counter) never renders a bar past 100%.
		"scanVulnCounts": func(scanID string) VulnCountPair { return scanVulnCountsFrom(db, scanID) },
		"scanPct": func(done, total int) int {
			if total <= 0 {
				return 0
			}
			if done > total {
				done = total
			}
			if done < 0 {
				done = 0
			}
			return done * 100 / total
		},
		// Severity macros need case-normalize before comparison so a
		// module emitting "critical" matches one emitting "CRITICAL".
		"upper": strings.ToUpper,
		"lower": strings.ToLower,
		"scanTargetCount": func(s models.Scan) int {
			// ProgressTotal often conflates "targets × probes" or, in
			// the suite's case, "stages" — neither is the same as
			// "how many hosts the user asked to scan". Parse the
			// per-module Config JSON for the canonical target fields
			// (target / targets / urls / domains) and fall back to
			// ProgressTotal only when nothing recognisable is there.
			if s.Config == "" || s.Config == "{}" {
				return s.ProgressTotal
			}
			var cfg struct {
				Target  string   `json:"target"`
				Targets []string `json:"targets"`
				URLs    []string `json:"urls"`
				Domains []string `json:"domains"`
				Hosts   []string `json:"hosts"`
			}
			if err := json.Unmarshal([]byte(s.Config), &cfg); err != nil {
				return s.ProgressTotal
			}
			// Plural slices take priority — when a handler writes
			// BOTH (advancedweb sets cfg.Target = rawTargets[0] as a
			// legacy alias for older JSON consumers) the multi-target
			// count is the one the user cares about. The previous
			// version short-circuited on a non-empty .Target and
			// surfaced "1 target" for scans launched against a 396-
			// entry target list — fixed by checking the slices first.
			if n := len(cfg.Targets); n > 0 {
				return n
			}
			if n := len(cfg.URLs); n > 0 {
				return n
			}
			if n := len(cfg.Domains); n > 0 {
				return n
			}
			if n := len(cfg.Hosts); n > 0 {
				return n
			}
			if cfg.Target != "" {
				return 1
			}
			return s.ProgressTotal
		},
		"dict": func(values ...interface{}) (map[string]interface{}, error) {
			// Build a map from alternating key/value args. Used by the
			// advancedweb suite results template to pass synthetic data
			// shapes into each module's `_results_inner` template.
			if len(values)%2 != 0 {
				return nil, fmt.Errorf("dict requires an even number of args")
			}
			m := make(map[string]interface{}, len(values)/2)
			for i := 0; i < len(values); i += 2 {
				k, ok := values[i].(string)
				if !ok {
					return nil, fmt.Errorf("dict key #%d is not a string", i/2)
				}
				m[k] = values[i+1]
			}
			return m, nil
		},
		"subInt": func(a, b int) int { return a - b },
		// httpStatusText returns the IANA-registered reason phrase
		// for a numeric status code ("OK", "Not Found", ...). Used by
		// the HTTPX result panel header to render "404 Not Found"
		// next to the status pill. Falls back to "" for codes the
		// stdlib doesn't know (custom server values), which the
		// template handles by emitting just the number.
		"httpStatusText": func(code int) string { return http.StatusText(code) },
		// friendlyFormError maps a ?error=<code> query param to a
		// user-readable explanation rendered by the form_error template
		// partial. Codes are emitted by module run-handlers when a
		// submission is rejected (no targets, db write failed, missing
		// token, etc). Unknown codes pass through verbatim so the
		// operator at least sees the raw token. Audit ER fix.
		"friendlyFormError": func(code string) string {
			switch code {
			case "no_urls", "no_targets", "no_target", "no_hosts", "no_domains":
				return "No targets were submitted. Enter at least one target before launching the scan."
			case "no_queries":
				return "No search queries were submitted."
			case "no_tokens":
				return "No JWT tokens were submitted."
			case "no_token":
				return "A required API token is missing. Set it in Settings before launching this scan."
			case "no_subdomains":
				return "No subdomains were submitted."
			case "no_seed", "no_seeds":
				return "No seed URL was submitted."
			case "no_login":
				return "Login URL is required."
			case "no_creds", "no_credentials":
				return "Credentials are required (username/password or hash)."
			case "no_users":
				return "Username list is empty. Provide either a single username or a username list."
			case "no_passes":
				return "Password list is empty. Provide at least one candidate password."
			case "bad_protocol":
				return "Selected protocol is not supported. Choose SSH, FTP, RDP, SMB, MSSQL, MySQL, PostgreSQL, VNC, LDAP, or Telnet."
			case "no_dc", "no_domain":
				return "Domain Controller or domain name is required."
			case "spray_needs_threshold":
				return "Password Spray is enabled but no lockout threshold was provided. Enter a lockout threshold (or disable Password Spray) before launching."
			case "no_probe_selected":
				return "Select at least one probe type (cache poisoning and/or HTTP smuggling) before launching."
			case "v3_missing_auth":
				return "SNMPv3 auth level requires an Auth Password of at least 8 characters. Fill it in (or switch to noAuthNoPriv) before launching."
			case "v3_missing_priv":
				return "SNMPv3 authPriv requires a Priv Password of at least 8 characters. Fill it in (or drop to authNoPriv) before launching."
			case "db_error":
				return "The scan could not be saved to the database. Check the server logs."
			case "invalid_url", "bad_url":
				return "One or more URLs were malformed. Use the http(s):// prefix."
			case "invalid_target", "bad_target", "unsafe_target":
				return "One or more targets were rejected (contains shell or flag characters)."
			case "invalid_method":
				return "HTTP method value is not one of GET/POST/BOTH."
			case "method_not_allowed":
				return "Run endpoint requires POST."
			case "tool_missing":
				return "An external tool required by this module is not installed. Check the startup banner."
			case "too_many_tasks":
				return "Too many scan tasks (targets × ports) — reduce target count or port range."
			case "too_many_urls":
				return "Too many target URLs submitted. Limit is 500 per scan — split the list across multiple runs."
			case "too_many_ports":
				return "Port range too large — narrow the range (max 1024 ports per scan)."
			case "too_many_targets":
				return "Target list is too large — reduce the number of entries or narrow each CIDR (aggregate cap is 65 536 hosts and 256 lines)."
			case "cidr_too_large":
				return "One of the supplied CIDRs is wider than /16. Split it into /16-or-narrower blocks before launching."
			case "bad_ports":
				return "Custom / Range port spec is malformed — use comma-separated ports or a hyphen range (e.g. 80,443 or 1-1024)."
			case "httpx_custom_ports_required":
				return "Custom HTTPX port spec is required when HTTPX mode is set to Custom. Enter a comma-separated list (e.g. 80,443,8080-8090)."
			case "httpx_custom_ports_invalid":
				return "Custom HTTPX port spec could not be parsed — use comma-separated ports or ranges (e.g. 80,443,8080-8090)."
			case "no_stages":
				return "At least one suite stage must be enabled before launching the scan."
			case "":
				return ""
			default:
				return "Submission rejected: " + code
			}
		},
		"scanResultsURL": func(scan models.Scan) string {
			switch scan.Module {
			case "sslscan":
				return "/modules/sslscan/results/" + scan.ID
			case "httpxfind":
				return "/modules/httpxfind/results/" + scan.ID
			case "httpmethods":
				return "/modules/httpmethods/results/" + scan.ID
			case "wafdetect":
				return "/modules/wafdetect/results/" + scan.ID
			case "wpscan":
				return "/modules/wpscan/results/" + scan.ID
			case "dnsenum":
				return "/modules/dnsenum/results/" + scan.ID
			case "techdetect":
				return "/modules/techdetect/results/" + scan.ID
			case "spider":
				return "/modules/spider/results/" + scan.ID
			case "direnum":
				return "/modules/direnum/results/" + scan.ID
			case "secheaders":
				return "/modules/secheaders/results/" + scan.ID
			case "nuclei":
				return "/modules/nuclei/results/" + scan.ID
			case "hostdiscovery":
				return "/modules/hostdiscovery/results/" + scan.ID
			case "portservice":
				return "/modules/portservice/results/" + scan.ID
			case "smbenum":
				return "/modules/smbenum/results/" + scan.ID
			case "brutef":
				return "/modules/brutef/results/" + scan.ID
			case "whoisinfo":
				return "/modules/whoisinfo/results/" + scan.ID
			case "emailharvest":
				return "/modules/emailharvest/results/" + scan.ID
			case "leakscan":
				return "/modules/leakscan/results/" + scan.ID
			case "snmpenum":
				return "/modules/snmpenum/results/" + scan.ID
			case "jwt":
				return "/modules/jwt/results/" + scan.ID
			case "paramdisc":
				return "/modules/paramdisc/results/" + scan.ID
			case "concurtest":
				return "/modules/concurtest/results/" + scan.ID
			case "advancedweb":
				return "/modules/advanced-web/results/" + scan.ID
			case "takeover":
				return "/modules/takeover/results/" + scan.ID
			case "corsscan":
				return "/modules/corsscan/results/" + scan.ID
			case "openredirect":
				return "/modules/openredirect/results/" + scan.ID
			case "cvematch":
				return "/modules/cvematch/results/" + scan.ID
			case "graphqlscan":
				return "/modules/graphqlscan/results/" + scan.ID
			case "authtest":
				return "/modules/authtest/results/" + scan.ID
			case "assetdisc":
				return "/modules/assetdisc/results/" + scan.ID
			case "oob":
				return "/modules/oob/results/" + scan.ID
			case "sstiscan":
				return "/modules/sstiscan/results/" + scan.ID
			case "cachepoison":
				return "/modules/cachepoison/results/" + scan.ID
			default:
				return "/scans"
			}
		},
		"deref": func(t *time.Time) time.Time {
			if t == nil {
				return time.Time{}
			}
			return *t
		},
		"pageHeading": func(page string) string {
			// Drop the "_results" suffix for module result pages so the header
			// reads "Host Discovery" instead of "hostdiscovery_results".
			module := strings.TrimSuffix(page, "_results")
			if name := models.ModuleDisplayName(module); name != module {
				if module != page {
					return name + " — Results"
				}
				return name
			}
			switch page {
			case "dashboard":
				return "Dashboard"
			case "modules":
				return "Modules"
			case "scans":
				return "Scans"
			case "targets":
				return "Targets"
			case "assets":
				return "Assets"
			case "asset_detail":
				return "Asset Detail"
			case "settings":
				return "Settings"
			}
			// Fallback: prettify "snake_case" → "Snake Case"
			parts := strings.Split(page, "_")
			for i, p := range parts {
				if p == "" {
					continue
				}
				parts[i] = strings.ToUpper(p[:1]) + p[1:]
			}
			return strings.Join(parts, " ")
		},
		"hasVulnHint": func(s string) bool {
			ls := strings.ToLower(s)
			return strings.Contains(ls, "vulnerable") || strings.Contains(ls, "cve-") ||
				strings.Contains(ls, "state: vulnerable")
		},
		"ipToNum": func(ip string) int64 {
			// Map an IPv4 string to a sortable 32-bit number. Returns 0 for
			// non-IPv4 input so hostnames sort before any real IP.
			parts := strings.Split(ip, ".")
			if len(parts) != 4 {
				return 0
			}
			var v int64
			for _, p := range parts {
				n := 0
				if _, err := fmt.Sscanf(p, "%d", &n); err != nil || n < 0 || n > 255 {
					return 0
				}
				v = v*256 + int64(n)
			}
			return v
		},
		"formatDuration": func(d time.Duration) string {
			if d < time.Second {
				return "< 1s"
			}
			s := int(d.Seconds())
			if s < 60 {
				return fmt.Sprintf("%ds", s)
			}
			m := s / 60
			s = s % 60
			return fmt.Sprintf("%dm %ds", m, s)
		},
	}
	tmpl, err := template.New("").Funcs(funcMap).ParseGlob(filepath.Join(templateDir, "*.html"))
	if err != nil {
		return nil, err
	}
	h := &Handler{
		registry:  registry,
		db:        db,
		templates: tmpl,
		scanMgr:   NewScanManager(),
	}
	// Periodic orphan reaper. MarkOrphanedScans only runs at startup;
	// across an 18+ hour uptime, any goroutine that died silently leaves
	// its scans row stuck as 'running' forever. Every 5 minutes we
	// snapshot the live set from ScanManager and ask the DB to error
	// out any 'running' row not in that set AND older than 10 minutes
	// (a floor to avoid racing the brand-new MarkRunning → Register
	// window). See db.ReapOrphanedScans for the SQL.
	go h.runOrphanReaper()
	return h, nil
}

// runOrphanReaper is the in-uptime janitor for stuck "running" rows.
// Spawned once by handlers.New; runs until the process exits. The 5-
// minute tick + 10-minute minimum-age combination means a freshly
// dispatched scan has at least 10 minutes to wire up its ScanMgr
// registration before it's eligible for reaping, and a dead goroutine
// is recovered within at most 15 minutes (one tick after the floor).
func (h *Handler) runOrphanReaper() {
	t := time.NewTicker(5 * time.Minute)
	defer t.Stop()
	for range t.C {
		ids := h.scanMgr.ActiveIDs()
		n, err := h.db.ReapOrphanedScans(ids, 10*time.Minute)
		if err != nil {
			log.Printf("orphan reaper: %v", err)
			continue
		}
		if n > 0 {
			log.Printf("orphan reaper: reaped %d stale running scan(s)", n)
		}
	}
}

// activeWorkspace resolves the workspace the current request operates in. It is
// user-aware and access-enforcing: for a non-admin it can only ever resolve to a
// workspace they hold a grant in (see effectiveWorkspace). This MUST match what
// the auth middleware authorized against — a handler using the raw cookie
// instead would let a non-admin forge scanner_active_ws to an inaccessible
// workspace and operate there. All handlers go through here.
func (h *Handler) activeWorkspace(r *http.Request) *models.Workspace {
	return h.effectiveWorkspace(r, h.currentUser(r))
}

// baseData builds the common template data every page needs
func (h *Handler) baseData(r *http.Request, title, page string) map[string]interface{} {
	user := h.currentUser(r)
	ws := h.effectiveWorkspace(r, user)
	workspaces, _ := h.db.ListWorkspaces()
	// Non-admins only ever see workspaces they hold a grant in (both in the
	// switcher and everywhere .Workspaces is rendered).
	if user != nil && !user.IsAdmin() {
		accessible, _ := h.db.UserWorkspaceIDs(user.ID)
		filtered := workspaces[:0]
		for _, wsStat := range workspaces {
			if accessible[wsStat.ID] {
				filtered = append(filtered, wsStat)
			}
		}
		workspaces = filtered
	}
	// Killswitch state for the sidebar status chip — surfaced on every
	// page so the operator can see at a glance whether scan traffic is
	// pinned to the chosen interface. `KillswitchActive` is the live
	// atomic-bool the runtime monitor maintains; `KillswitchInterface`
	// is the iface name the user pinned in Settings (shown as a tooltip
	// + chip subtitle).
	settings := h.db.GetSettings()
	data := map[string]interface{}{
		"Title":               title,
		"Page":                page,
		"ActiveWorkspace":     ws,
		"Workspaces":          workspaces,
		"KillswitchActive":    scannet.IsActive(),
		"KillswitchInterface": settings.NetworkInterface,
		"CurrentUser":         user,
		"IsAdmin":             user != nil && user.IsAdmin(),
	}
	// Audit ER fix: surface ?error=<code> query params to the form_error
	// template partial so the user actually sees why their submit was
	// rejected. Codes are mapped to friendly messages via the
	// friendlyFormError FuncMap helper.
	if e := r.URL.Query().Get("error"); e != "" {
		data["FormError"] = e
	}
	// Derive module name from page and attach its info if available
	modName := strings.TrimSuffix(page, "_results")
	if info, ok := modules.Infos[modName]; ok {
		data["ModuleInfo"] = info
	}
	// On a module's launch form (not *_results), surface the capacity-recommended
	// per-module concurrency as the http_tuning "max_concurrent" placeholder, so
	// "blank = inherit" visibly means "inherit the smart, machine-aware default",
	// plus a small badge (module_info.html) showing whether that value is
	// empirically calibrated or a conservative default awaiting calibration.
	if page == modName && capacity.IsModule(page) {
		rec := capacity.Recommend(page, sysmon.ReadLimits())
		data["TuneConcHint"] = fmt.Sprintf("auto: %d", rec)
		data["CapModule"] = true
		data["CapMeasured"] = capacity.Measured(page)
		data["CapRecommended"] = rec
		data["CapWired"] = capacityWired(page) // false = uses a conservative default, not the formula
	}
	return data
}

// capacityWired reports whether a module's runtime concurrency actually comes
// from capacity.Recommend (web tier + techdetect + nuclei). The network-tier
// host scanners (portservice/hostdiscovery/smbenum/brutef) still use the
// conservative EffectiveNetworkMaxConcurrent path — deferred until calibrated —
// so the badge tells them apart.
func capacityWired(module string) bool {
	switch module {
	case "portservice", "hostdiscovery", "smbenum", "brutef", "snmpenum", "whoisinfo",
		"dnsenum", "cvematch", "jwt", "oob", "leakscan", "assetdisc", "concurtest", "adpentest", "wpscan":
		return false
	default:
		return true
	}
}

// SwitchWorkspace sets the active workspace cookie
func (h *Handler) SwitchWorkspace(w http.ResponseWriter, r *http.Request) {
	wsID := r.FormValue("workspace_id")
	if wsID == "" {
		wsID = database.DefaultWorkspaceID
	}
	if !h.db.WorkspaceExists(wsID) {
		wsID = database.DefaultWorkspaceID
	}
	// Non-admins may only switch into a workspace they hold a grant in.
	if user := h.currentUser(r); user != nil && !user.IsAdmin() {
		if accessible, _ := h.db.UserWorkspaceIDs(user.ID); !accessible[wsID] {
			ref := r.Header.Get("Referer")
			if ref == "" {
				ref = "/"
			}
			http.Redirect(w, r, ref, http.StatusSeeOther)
			return
		}
	}
	http.SetCookie(w, &http.Cookie{
		Name:     activeWSCookie,
		Value:    wsID,
		Path:     "/",
		MaxAge:   365 * 24 * 3600,
		HttpOnly: true,
		SameSite: http.SameSiteLaxMode,
	})
	ref := r.Header.Get("Referer")
	if ref == "" {
		ref = "/"
	}
	http.Redirect(w, r, ref, http.StatusSeeOther)
}

// --- Page handlers ---

// DashboardChartsAPI returns the same chart payload as the embedded JSON on
// the dashboard, but as a standalone JSON response. The dashboard polls this
// endpoint every 30s so the Traffic Activity cumulative line, Scans/Vulns/
// Assets chart, and Network Connections widget update without a full page
// reload — previously the cumulative number appeared "stuck" because the
// page only computed it at initial render.
func (h *Handler) DashboardChartsAPI(w http.ResponseWriter, r *http.Request) {
	ws := h.activeWorkspace(r)
	// Lite — chart aggregation reads SeverityCount / OpenConnectionsCount
	// directly off the row, not from Result. The full BLOB never has to
	// leave SQLite for this endpoint.
	allScans, _ := h.db.ListScansLite(ws.ID, "")
	vulns, _ := h.getVulnIndex(ws.ID, allScans)
	chart := buildDashboardCharts(allScans, vulns)
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	json.NewEncoder(w).Encode(chart)
}

func (h *Handler) Dashboard(w http.ResponseWriter, r *http.Request) {
	if r.URL.Path != "/" {
		http.NotFound(w, r)
		return
	}
	data := h.baseData(r, "scaNNer", "dashboard")
	ws := data["ActiveWorkspace"].(*models.Workspace)
	total, ipv4, domain, fqdn, _ := h.db.GetTargetCounts(ws.ID)
	data["Categories"] = h.registry.Categories()
	data["Modules"] = h.registry.List()
	data["TotalCount"] = total
	data["IPv4Count"] = ipv4
	data["DomainCount"] = domain
	data["FQDNCount"] = fqdn

	// Recent scans for the activity feed (capped at 6 for layout) AND
	// the workspace-wide counters. "Total Scans" + "Active" used to be
	// computed from the trimmed-to-6 list — so a workspace with 50
	// scans would show "6". Fix: count from the full list, then trim
	// only the slice we hand to the feed.
	// Lite — chart aggregation now reads denormalised SeverityCount /
	// OpenConnectionsCount columns; we never need the Result blob.
	allScansForCounts, _ := h.db.ListScansLite(ws.ID, "")
	totalScanCount := len(allScansForCounts)
	activeCount := 0
	for _, s := range allScansForCounts {
		if s.Status == models.ScanRunning {
			activeCount++
		}
	}
	recentScans := allScansForCounts
	if len(recentScans) > 6 {
		recentScans = recentScans[:6]
	}
	data["RecentScans"] = recentScans
	data["TotalScanCount"] = totalScanCount
	data["ActiveScanCount"] = activeCount

	// Per-scan target list for the activity feed. We surface up to the first
	// 3 targets so the user sees what each scan is hitting at a glance.
	scanTargets := map[string][]string{}
	scanExtra := map[string]int{}
	for _, s := range recentScans {
		raw := extractAssetsFromConfig(s.Config)
		if len(raw) > 3 {
			scanExtra[s.ID] = len(raw) - 3
			raw = raw[:3]
		}
		scanTargets[s.ID] = raw
	}
	data["ScanTargets"] = scanTargets
	data["ScanExtra"] = scanExtra

	// Recent Assets — top 8 most-recently-scanned across all modules.
	// Reuses the scan slice fetched above (one DB round-trip total) instead
	// of letting aggregateAssets re-issue its own ListScans. Asset
	// aggregation only consumes Config/Status/CreatedAt/Module, so the
	// full ListScans payload (which we need anyway for chart vuln counts)
	// satisfies the aggregator without any extra fetch.
	allAssets := h.aggregateAssetsFromScans(ws.ID, allScansForCounts)
	if len(allAssets) > 8 {
		allAssets = allAssets[:8]
	}
	data["RecentAssets"] = allAssets

	// Dashboard charts: last-7-days scan activity + status mix + per-module mix.
	// We reuse the full scan list fetched above for accurate buckets
	// (one DB round-trip instead of two).
	dashVulns, _ := h.getVulnIndex(ws.ID, allScansForCounts)
	chart := buildDashboardCharts(allScansForCounts, dashVulns)
	chartJSON, _ := json.Marshal(chart)
	data["ChartJSON"] = template.JS(chartJSON)
	data["ChartHasData"] = len(allScansForCounts) > 0

	h.render(w, "layout", data)
}

// dashboardCharts is the JSON-friendly shape consumed by the dashboard's
// inline chart drawer. Day labels are oldest→newest.
type dashboardCharts struct {
	Days []string `json:"days"` // "May 04"

	// Status mix donut + module bars (kept from the previous design)
	StatusTotal map[string]int `json:"status_total"`
	ModuleMix   []moduleSlice  `json:"module_mix"`

	// Traffic Activity — total HTTP probes processed per day. Approximated by
	// summing each scan's progress_done across its bucket day. This roughly
	// tracks bandwidth/throughput we generated.
	DailyRequests []int `json:"daily_requests"`

	// Scans · Vulnerabilities · Assets — three lines on the same chart.
	DailyScans  []int `json:"daily_scans"`  // scans created on this day
	DailyVulns  []int `json:"daily_vulns"`  // critical+high+medium findings discovered
	DailyAssets []int `json:"daily_assets"` // unique new assets that first appeared on this day

	// Cumulative request count over the 7-day window — drawn as a separate
	// rising line so the total HTTP volume trend is obvious.
	DailyRequestsCumul []int `json:"daily_requests_cumul"`

	// First-detected vulnerabilities per day, split by severity. Each series is
	// the count of DISTINCT (deduped) findings whose FirstSeen falls on that day —
	// sourced from the workspace vuln index, so a recurring finding is counted
	// only on the day it was first seen, not every scan day.
	DailyCrit []int `json:"daily_crit"`
	DailyHigh []int `json:"daily_high"`
	DailyMed  []int `json:"daily_med"`
	DailyLow  []int `json:"daily_low"`
}

type moduleSlice struct {
	Module      string `json:"module"`       // slug (e.g. "httpmethods")
	DisplayName string `json:"display_name"` // human label (e.g. "HTTP Method Tester")
	Count       int    `json:"count"`
}

func buildDashboardCharts(scans []models.Scan, vulns []GlobalVuln) dashboardCharts {
	const days = 7
	// UTC bucketing (audit B74). SQLite stores created_at in UTC, but
	// time.Now().Location() is the system local TZ. On DST transitions
	// (or simply servers in different TZs than the user) "day" boundaries
	// drifted by an hour or rolled to the previous/next day — dashboard
	// charts visibly mis-shifted by ±1 day across DST. Forcing both
	// reference times to UTC makes bucketing deterministic.
	now := time.Now().UTC()
	startOfToday := time.Date(now.Year(), now.Month(), now.Day(), 0, 0, 0, 0, time.UTC)

	out := dashboardCharts{
		Days:               make([]string, days),
		DailyRequests:      make([]int, days),
		DailyScans:         make([]int, days),
		DailyVulns:         make([]int, days),
		DailyAssets:        make([]int, days),
		DailyRequestsCumul: make([]int, days),
		DailyCrit:          make([]int, days),
		DailyHigh:          make([]int, days),
		DailyMed:           make([]int, days),
		DailyLow:           make([]int, days),
		StatusTotal:        map[string]int{},
	}
	for i := 0; i < days; i++ {
		d := startOfToday.AddDate(0, 0, -(days - 1 - i))
		out.Days[i] = d.Format("Jan 02")
	}

	dayIdx := func(t time.Time) int {
		// Normalize the scan timestamp to UTC before bucketing so a
		// scan created at "2026-06-15 00:30 +03:00" (which SQLite
		// stores as "2026-06-14 21:30 UTC") falls into the right
		// UTC day — same axis the dashboard chart labels use. Without
		// this, evening scans in eastern TZs were attributed to the
		// next UTC day and skewed counts.
		u := t.UTC()
		dayDiff := int(startOfToday.Sub(time.Date(u.Year(), u.Month(), u.Day(), 0, 0, 0, 0, time.UTC)).Hours() / 24)
		if dayDiff < 0 || dayDiff >= days {
			return -1
		}
		return days - 1 - dayDiff
	}

	// Sort scans chronologically so "first time we saw asset X" attribution
	// goes to the right day.
	chrono := append([]models.Scan(nil), scans...)
	sort.Slice(chrono, func(i, j int) bool { return chrono[i].CreatedAt.Before(chrono[j].CreatedAt) })

	moduleCounts := map[string]int{}
	assetFirstSeen := map[string]int{} // assetKey → day index (chronological order ensures correctness)

	for _, s := range chrono {
		idx := dayIdx(s.CreatedAt)

		// Status mix + module mix span all-time, not just last 7 days.
		out.StatusTotal[string(s.Status)]++
		moduleCounts[s.Module]++

		if idx < 0 {
			continue
		}

		// Scans / requests bucketed
		out.DailyScans[idx]++
		out.DailyRequests[idx] += s.ProgressDone

		// Vulnerabilities discovered in this scan. Reads the denormalised
		// column kept in sync by UpdateScanResult so we never parse the
		// multi-megabyte Result blob here.
		out.DailyVulns[idx] += s.SeverityCount

		// Unique assets that first appeared on this day
		for _, raw := range extractAssetsFromConfig(s.Config) {
			key := normalizeAsset(raw)
			if key == "" {
				continue
			}
			if _, exists := assetFirstSeen[key]; !exists {
				assetFirstSeen[key] = idx
				out.DailyAssets[idx]++
			}
		}
	}

	// First-detected vulnerabilities per severity, bucketed by FirstSeen (the
	// day the deduped finding was first observed) — so each unique vuln counts
	// once, on its discovery day. Reuses the same dayIdx window as the scans.
	for _, v := range vulns {
		if v.FirstSeen.IsZero() {
			continue
		}
		idx := dayIdx(v.FirstSeen)
		if idx < 0 {
			continue
		}
		switch v.SevRank {
		case 4:
			out.DailyCrit[idx]++
		case 3:
			out.DailyHigh[idx]++
		case 2:
			out.DailyMed[idx]++
		case 1:
			out.DailyLow[idx]++
		}
	}

	// Cumulative requests
	running := 0
	for i := 0; i < days; i++ {
		running += out.DailyRequests[i]
		out.DailyRequestsCumul[i] = running
	}

	// Top 6 modules — emit both slug + display name so the dashboard chart
	// can show friendly labels without relying on a JS-side translation table.
	for m, c := range moduleCounts {
		out.ModuleMix = append(out.ModuleMix, moduleSlice{
			Module:      m,
			DisplayName: models.ModuleDisplayName(m),
			Count:       c,
		})
	}
	sort.Slice(out.ModuleMix, func(i, j int) bool { return out.ModuleMix[i].Count > out.ModuleMix[j].Count })
	if len(out.ModuleMix) > 6 {
		out.ModuleMix = out.ModuleMix[:6]
	}
	return out
}


// TargetGroup buckets targets in a workspace by their TargetList. Used by
// every module form's target picker so users can tick a list to select
// all of its hosts at once. The first group is always "No list" members;
// the rest follow the lists' creation order.
type TargetGroup struct {
	ID      string          // "" = no-list bucket
	Name    string          // "No list" or the list's name
	Targets []models.Target // members of this bucket (all schemes)
	// Scheme-split views of Targets, so the picker can separate URL targets
	// added as http:// vs https:// (the scheme lives in the Value prefix —
	// the same host under both schemes is two distinct target rows). Other
	// holds schemeless targets (ipv4 / domain / fqdn).
	HTTPS []models.Target
	HTTP  []models.Target
	Other []models.Target
}

// splitByScheme partitions a group's members into https:// , http:// and
// everything-else buckets by inspecting the Value prefix. Members are sorted
// alphabetically (case-insensitive) first so each bucket — and the "N hedef"
// listing — comes out in a predictable order.
func splitByScheme(g *TargetGroup) {
	sort.SliceStable(g.Targets, func(i, j int) bool {
		return strings.ToLower(g.Targets[i].Value) < strings.ToLower(g.Targets[j].Value)
	})
	for _, t := range g.Targets {
		switch {
		case strings.HasPrefix(t.Value, "https://"):
			g.HTTPS = append(g.HTTPS, t)
		case strings.HasPrefix(t.Value, "http://"):
			g.HTTP = append(g.HTTP, t)
		default:
			g.Other = append(g.Other, t)
		}
	}
}

// groupTargetsByList returns every target in the workspace grouped by its
// category (TargetList). Empty groups are filtered out so the form only
// renders buckets with members.
//
// Grouping is by the many-to-many category membership (the target_list_members
// join table, via TargetListMembership) — the SAME source the Targets page and
// the "Manage categories" modal write to. The earlier version bucketed by the
// legacy single `targets.list_id` column, which SetTargetLists never touches,
// so re-categorizing a target never showed up in the module picker (the
// reported bug). A target in several categories now appears under each; a
// target in none falls into "No list".
func (h *Handler) groupTargetsByList(workspaceID string) []TargetGroup {
	targets, _ := h.db.ListTargets(workspaceID, "")
	lists, _ := h.db.ListTargetLists(workspaceID)
	membership := h.db.TargetListMembership(workspaceID) // targetID -> []TargetList

	byList := map[string][]models.Target{} // listID ("" = uncategorized) -> members
	for _, t := range targets {
		cats := membership[t.ID]
		if len(cats) == 0 {
			byList[""] = append(byList[""], t)
			continue
		}
		for _, c := range cats {
			byList[c.ID] = append(byList[c.ID], t)
		}
	}
	out := []TargetGroup{}
	if uncat := byList[""]; len(uncat) > 0 {
		g := TargetGroup{ID: "", Name: "No list", Targets: uncat}
		splitByScheme(&g)
		out = append(out, g)
	}
	for _, l := range lists {
		if members, ok := byList[l.ID]; ok && len(members) > 0 {
			g := TargetGroup{ID: l.ID, Name: l.Name, Targets: members}
			splitByScheme(&g)
			out = append(out, g)
		}
	}
	return out
}

func (h *Handler) Targets(w http.ResponseWriter, r *http.Request) {
	data := h.baseData(r, "Targets - scaNNer", "targets")
	ws := data["ActiveWorkspace"].(*models.Workspace)
	filterType := r.URL.Query().Get("type")
	filterList := r.URL.Query().Get("list")
	// Always load every target. Type + list filters are applied client-side
	// so the active list/tab can change without a full reload.
	targets, _ := h.db.ListTargets(ws.ID, "")
	// Attach each target's categories (many-to-many) for chip rendering +
	// client-side category filtering.
	membership := h.db.TargetListMembership(ws.ID)
	for i := range targets {
		targets[i].Categories = membership[targets[i].ID]
	}
	lists, _ := h.db.ListTargetLists(ws.ID)
	listCounts := h.db.CountTargetsPerList(ws.ID)
	listNames := map[string]string{}
	for _, l := range lists {
		listNames[l.ID] = l.Name
	}
	total, ipv4, domain, fqdn, _ := h.db.GetTargetCounts(ws.ID)
	data["Targets"] = targets
	data["TargetLists"] = lists
	data["TargetListCounts"] = listCounts
	data["TargetListNames"] = listNames
	data["NoListCount"] = listCounts[""]
	// Grouped view (by list + http/https, alphabetically sorted) for the
	// "New Target List" modal's existing-targets picker, so the operator can
	// file whole categories / all-https / all-http in one click.
	data["WSTargetGroups"] = h.groupTargetsByList(ws.ID)
	// keep alias for any template still referring to the old name during transition
	data["UncategorizedCount"] = listCounts[""]
	data["FilterType"] = filterType
	data["FilterList"] = filterList
	data["TotalCount"] = total
	data["IPv4Count"] = ipv4
	data["DomainCount"] = domain
	data["FQDNCount"] = fqdn
	h.render(w, "layout", data)
}

func (h *Handler) Modules(w http.ResponseWriter, r *http.Request) {
	data := h.baseData(r, "Modules - scaNNer", "modules")
	user := h.currentUser(r)
	mods := h.registry.List()
	cats := h.registry.Categories()
	canAdvWeb := true
	// Non-admins only see modules they hold a grant for in the active workspace.
	if user != nil && !user.IsAdmin() {
		ws := data["ActiveWorkspace"].(*models.Workspace)
		allowed, _ := h.db.UserModulesInWorkspace(user.ID, ws.ID)
		mods = filterModuleInfos(mods, allowed)
		filteredCats := map[string][]modules.ModuleInfo{}
		for cat, list := range cats {
			if f := filterModuleInfos(list, allowed); len(f) > 0 {
				filteredCats[cat] = f
			}
		}
		cats = filteredCats
		canAdvWeb = allowed["advancedweb"]
	}
	// The Advanced Web suite is presented as the hero card at the top of the
	// page, so drop it from the regular module grid to avoid showing it twice.
	mods = excludeModule(mods, "advancedweb")
	for cat, list := range cats {
		if f := excludeModule(list, "advancedweb"); len(f) > 0 {
			cats[cat] = f
		} else {
			delete(cats, cat)
		}
	}
	data["Categories"] = cats
	data["Modules"] = mods
	data["CanAdvancedWeb"] = canAdvWeb
	h.render(w, "layout", data)
}

// excludeModule returns the list without the named module.
func excludeModule(in []modules.ModuleInfo, name string) []modules.ModuleInfo {
	out := in[:0:0]
	for _, m := range in {
		if m.Name != name {
			out = append(out, m)
		}
	}
	return out
}

// filterModuleInfos keeps only the modules present in the allowed set.
func filterModuleInfos(in []modules.ModuleInfo, allowed map[string]bool) []modules.ModuleInfo {
	out := in[:0:0]
	for _, m := range in {
		if allowed[m.Name] {
			out = append(out, m)
		}
	}
	return out
}

func (h *Handler) Scans(w http.ResponseWriter, r *http.Request) {
	data := h.baseData(r, "Scans - scaNNer", "scans")
	ws := data["ActiveWorkspace"].(*models.Workspace)
	scans, _ := h.db.ListScansLite(ws.ID, "")
	hasRunning := false
	for _, s := range scans {
		if s.Status == models.ScanRunning || s.Status == models.ScanPending {
			hasRunning = true
			break
		}
	}
	data["Scans"] = scans
	data["ArchivedCount"] = h.db.CountArchivedScans(ws.ID)
	data["HasRunning"] = hasRunning
	data["IsArchive"] = false
	h.renderResults(w, r, "scans_inner", data)
}

// ScansArchive renders the archive view — same page key, same template, but
// loaded from ListArchivedScansLite and with IsArchive=true so the toolbar
// can switch labels (Unarchive instead of Archive, etc.).
func (h *Handler) ScansArchive(w http.ResponseWriter, r *http.Request) {
	data := h.baseData(r, "Scans (Archive) - scaNNer", "scans")
	ws := data["ActiveWorkspace"].(*models.Workspace)
	scans, _ := h.db.ListArchivedScansLite(ws.ID)
	data["Scans"] = scans
	data["ArchivedCount"] = len(scans)
	data["HasRunning"] = false
	data["IsArchive"] = true
	h.renderResults(w, r, "scans_inner", data)
}

func (h *Handler) Settings(w http.ResponseWriter, r *http.Request) {
	data := h.baseData(r, "Settings - scaNNer", "settings")
	data["Settings"] = h.db.GetSettings()
	data["HasRunning"] = h.db.HasRunningScans()
	// SMTP test result (from the /settings/smtp-test redirect).
	data["SMTPResult"] = r.URL.Query().Get("smtp_result")
	data["SMTPOK"] = r.URL.Query().Get("smtp_ok")
	// Network interface list for the killswitch dropdown. Non-loopback
	// interfaces only; user shouldn't be encouraged to pick `lo`.
	// Errors are non-fatal — empty list just hides the picker.
	if ifaces, err := scannet.ListInterfaces(); err == nil {
		visible := make([]scannet.InterfaceInfo, 0, len(ifaces))
		for _, i := range ifaces {
			if i.Loopback {
				continue
			}
			visible = append(visible, i)
		}
		data["NetworkInterfaces"] = visible
	}
	// Killswitch diagnostic data for the UI. Two distinct error
	// channels are surfaced because they need different remediations:
	//   - PrivilegeError = "iptables -t nat -S POSTROUTING" itself
	//     failed (most often "(must be root)") → the operator has a
	//     setcap/sudo decision to make.
	//   - SetupError    = privilege probe passed but the actual
	//     namespace + veth + iptables wiring failed during startup
	//     (Kali xtables.lock, missing nf_tables module, iface dropped
	//     between the probe and Setup, etc.) → operator needs to fix
	//     state on the host, not capability bits.
	if err := scannet.RequiresPrivilege(); err != nil {
		data["KillswitchPrivilegeError"] = err.Error()
	}
	if msg := scannet.LastSetupError(); msg != "" {
		data["KillswitchSetupError"] = msg
		// An interface-state failure (down / no IPv4 / renamed / gone) is a
		// host-state problem the operator fixes by bringing the interface up
		// (e.g. reconnecting the VPN) — not a privilege problem. Flag it so the
		// UI shows that instead of the sudo/installer capability guidance.
		data["KillswitchSetupErrorIface"] = scannet.IsInterfaceStateError(msg)
	}
	data["KillswitchActive"] = scannet.IsActive()
	// Housekeeping panel — top-10 largest scan rows so the operator
	// can prune the actual offenders. Failures are non-fatal.
	if largest, err := h.db.ListLargestScans(10); err == nil {
		data["LargestScans"] = largest
	}
	// VACUUM result flash from /settings/vacuum redirect.
	data["VacuumResult"] = r.URL.Query().Get("vacuum")
	// Network Tuning panel: current sysctls vs recommended + helper availability.
	data["NetTune"] = netTuneData(r)
	// Server Clock panel (TOTP time / NTP offset).
	data["NTP"] = ntpData()
	h.render(w, "layout", data)
}

// SettingsVacuum is the manual housekeeping button. POST-only; runs
// WAL checkpoint + VACUUM; redirects back to /settings with a flash
// query param so the page can show the result. Blocking and slow on a
// large DB — there's an explicit confirmation in the UI.
func (h *Handler) SettingsVacuum(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Redirect(w, r, "/settings", http.StatusSeeOther)
		return
	}
	if err := h.db.VacuumNow(); err != nil {
		http.Redirect(w, r, "/settings?vacuum=error", http.StatusSeeOther)
		return
	}
	http.Redirect(w, r, "/settings?vacuum=done", http.StatusSeeOther)
}

// SettingsSave handles POST to save settings
func (h *Handler) SettingsSave(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Redirect(w, r, "/settings", http.StatusSeeOther)
		return
	}
	// Block save if scans are running
	if h.db.HasRunningScans() {
		http.Redirect(w, r, "/settings?error=scans_running", http.StatusSeeOther)
		return
	}

	// Helper that parses a numeric form field into the given pointer with
	// optional clamping. Empty / unparsable input leaves the value at its
	// zero-default (which the Effective*() helpers fall back from).
	pi := func(name string, lo, hi int) int {
		v := 0
		fmt.Sscanf(r.FormValue(name), "%d", &v)
		if hi > 0 && v > hi {
			v = hi
		}
		if v < lo {
			v = lo
		}
		return v
	}

	// Web tier
	webTimeout := pi("web_timeout", 1, 600)
	webConc := pi("web_max_concurrent", 1, 999)
	webRate := pi("web_rate_limit", 0, 10000)

	// Network tier
	netTimeout := pi("network_timeout", 1, 1800)
	netConc := pi("network_max_concurrent", 1, 32)
	netRate := pi("network_rate_limit", 0, 1000000)
	bruteThreads := pi("brute_threads", 1, 256)
	maxCPU := pi("max_cpu_percent", 10, 100)

	// Legacy globals — keep them in sync with the web tier so older code
	// paths that still read MaxConcurrent / RateLimit / DefaultTimeout
	// directly behave identically to the web settings.
	timeout := webTimeout
	if timeout == 0 {
		timeout = 30
	}
	conc := webConc
	if conc == 0 {
		conc = 30
	}
	rateLimit := webRate

	proxyURL := strings.TrimSpace(r.FormValue("proxy_url"))
	useProxy := r.FormValue("use_proxy") == "on"
	useBurp := r.FormValue("burp_proxy") == "on"
	if useBurp {
		proxyURL = "http://127.0.0.1:8080"
		useProxy = true
	}
	burpSuccessOnly := r.FormValue("burp_success_only") == "on"
	// Replaying findings is meaningless without a proxy URL — clamp here
	// so a stale "on" flag from before the proxy was disabled doesn't
	// linger in saved settings.
	if !useProxy || proxyURL == "" {
		burpSuccessOnly = false
	}

	userAgent := strings.TrimSpace(r.FormValue("user_agent"))
	if userAgent == "" {
		userAgent = "scaNNer/1.0"
	}

	exportFmt := r.FormValue("default_export_fmt")

	// Outbound network interface (killswitch). Empty value = default
	// mode (no binding). Non-empty must resolve to a real, UP interface
	// with a primary IPv4 — otherwise reject the save so the user
	// can't end up with a configured iface that doesn't actually bind.
	ifaceName := strings.TrimSpace(r.FormValue("network_interface"))
	ifaceIP := ""
	if ifaceName != "" {
		ip, err := scannet.ResolvePrimaryIPv4(ifaceName)
		if err != nil {
			http.Redirect(w, r, "/settings?error=iface_invalid&detail="+url.QueryEscape(err.Error()), http.StatusSeeOther)
			return
		}
		ifaceIP = ip
	}

	// VPN watchdog (auto-reconnect + resume on tunnel drop). Checkbox absent =
	// unchecked = off; the value is always persisted so the default-on only
	// applies until the first save.
	vpnAutoReconnect := r.FormValue("vpn_auto_reconnect") == "on"
	vpnConnection := strings.TrimSpace(r.FormValue("vpn_connection"))
	vpnInterface := strings.TrimSpace(r.FormValue("vpn_interface"))
	vpnReconnectAfter := pi("vpn_reconnect_after_sec", 5, 3600)
	webPreflight := r.FormValue("web_reachability_preflight") == "on"
	webPreflightTimeout := pi("web_preflight_timeout", 1, 60)

	// Keep the stored SMTP password when the field is submitted blank (the form
	// never renders the saved secret, so blank means "unchanged") — but ONLY
	// while a username is present. With no username there is no authentication,
	// so a blank password means "clear it". That's how you convert a previously
	// authenticated config to a no-auth relay: empty the Username field and the
	// stored password is dropped too (rather than lingering, unused).
	smtpUser := strings.TrimSpace(r.FormValue("smtp_user"))
	// The form never renders the saved password (secrecy), so a blank field
	// ALWAYS means "unchanged" — keep the stored one. This is unconditional so
	// saving any other setting can never wipe the password. To actually remove
	// it, the operator ticks the explicit "clear saved password" box.
	smtpPass := r.FormValue("smtp_password")
	if smtpPass == "" && r.FormValue("smtp_password_clear") != "on" {
		smtpPass = h.db.GetSettings().SMTPPassword
	}

	s := models.AppSettings{
		DefaultTimeout:       timeout,
		MaxConcurrent:        conc,
		RateLimit:            rateLimit,
		WebTimeout:               webTimeout,
		WebMaxConcurrent:         webConc,
		WebRateLimit:             webRate,
		WebReachabilityPreflight: webPreflight,
		WebPreflightTimeout:      webPreflightTimeout,
		NetworkTimeout:       netTimeout,
		NetworkMaxConcurrent: netConc,
		NetworkRateLimit:     netRate,
		BruteThreads:         bruteThreads,
		MaxCPUPercent:        maxCPU,
		ProxyURL:             proxyURL,
		UseProxy:             useProxy,
		BurpSuccessOnly:      burpSuccessOnly,
		UserAgent:            userAgent,
		DefaultExportFmt:     exportFmt,
		WPScanAPIKey:         strings.TrimSpace(r.FormValue("wpscan_api_key")),
		HIBPAPIKey:           strings.TrimSpace(r.FormValue("hibp_api_key")),
		GitHubToken:          strings.TrimSpace(r.FormValue("github_token")),
		ShodanAPIKey:         strings.TrimSpace(r.FormValue("shodan_api_key")),
		CensysID:             strings.TrimSpace(r.FormValue("censys_id")),
		CensysSecret:         strings.TrimSpace(r.FormValue("censys_secret")),
		VirusTotalAPIKey:     strings.TrimSpace(r.FormValue("virustotal_api_key")),
		NetworkInterface:     ifaceName,
		NetworkInterfaceIP:   ifaceIP,
		VPNAutoReconnect:     vpnAutoReconnect,
		VPNConnection:        vpnConnection,
		VPNInterface:         vpnInterface,
		VPNReconnectAfterSec: vpnReconnectAfter,
		SMTPHost:             strings.TrimSpace(r.FormValue("smtp_host")),
		SMTPPort:             pi("smtp_port", 0, 65535),
		SMTPUser:             smtpUser,
		SMTPFrom:             strings.TrimSpace(r.FormValue("smtp_from")),
		SMTPTLSMode:          smtpTLSMode(r.FormValue("smtp_tls_mode")),
		SMTPPassword:         smtpPass,
		TwoFactorAvailable:   r.FormValue("two_factor_available") == "on",
		NTPServer:            strings.TrimSpace(r.FormValue("ntp_server")),
	}
	h.db.SaveSettings(s)
	// Re-measure the TOTP clock offset against the (possibly new) NTP server.
	// Async — an unreachable server must not block saving the rest of settings.
	go h.refreshNTP()
	// Apply the CPU budget to the capacity governor immediately (no restart).
	capacity.SetCPUBudget(float64(s.EffectiveMaxCPUPercent()) / 100)

	// Rebuild the killswitch namespace + monitor to match the new
	// settings value. Order matters: tear down the old one first so the
	// veth name doesn't collide, then Setup with the new iface (which
	// also re-arms the runtime monitor inside Setup → StartMonitor flow).
	//
	// Errors are logged but don't roll back the settings save — the
	// user explicitly asked for this iface and may need to fix
	// privileges or restore the interface manually.
	_ = scannet.Teardown()
	if s.NetworkInterface != "" {
		if err := scannet.RequiresPrivilege(); err != nil {
			log.Printf("⚠ Killswitch unavailable: %v", err)
		} else if err := scannet.Setup(s.NetworkInterface); err != nil {
			log.Printf("⚠ Killswitch setup failed: %v", err)
		} else {
			scannet.StartMonitor(
				s.NetworkInterface,
				s.NetworkInterfaceIP,
				h.scanMgr.CancelAll,
				h.db.MarkScanError,
			)
		}
	} else {
		// Switching back to default mode — stop the runtime monitor too.
		scannet.StartMonitor("", "", h.scanMgr.CancelAll, h.db.MarkScanError)
	}

	http.Redirect(w, r, "/settings?success=saved", http.StatusSeeOther)
}

// SettingsAPI returns current settings as JSON (for scan lock checks)
func (h *Handler) SettingsAPI(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{
		"settings":    h.db.GetSettings(),
		"has_running": h.db.HasRunningScans(),
	})
}

// PreflightInterfaceCheck is the killswitch's pre-scan health gate.
// Returns nil if either default mode is in effect (no killswitch) or
// the pinned interface is still UP and still carrying the expected
// IPv4. Returns a wrapped error otherwise — handler should redirect
// the user with ?error=iface_down and NOT create a scan record.
func (h *Handler) PreflightInterfaceCheck() error {
	s := h.db.GetSettings()
	return scannet.CheckInterfaceUp(s.NetworkInterface, s.NetworkInterfaceIP)
}

// BuildHTTPOptions creates HTTPOptions from current settings + per-scan form data
// BuildHTTPOptionsFromSettings builds the same shared.HTTPOptions that
// BuildHTTPOptions would produce, but reads only from Settings — no
// per-request fields. Used by Restart paths where there is no Request
// context. Audit fix: many scan_control.go restart cases passed nil
// opts, which meant a re-run silently dropped proxy / UA / killswitch
// binding even though those Settings hadn't changed.
func (h *Handler) BuildHTTPOptionsFromSettings() *shared.HTTPOptions {
	return h.BuildHTTPOptions(nil)
}

func (h *Handler) BuildHTTPOptions(r *http.Request) *shared.HTTPOptions {
	settings := h.db.GetSettings()
	var opts *shared.HTTPOptions
	if r != nil {
		opts = shared.ParseHTTPOptions(r)
	}
	if opts == nil {
		opts = &shared.HTTPOptions{}
	}
	if settings.UserAgent != "" && opts.UserAgent == "" {
		opts.UserAgent = settings.UserAgent
	}
	if settings.UseProxy && settings.ProxyURL != "" {
		opts.ProxyURL = settings.ProxyURL
		opts.BurpSuccessOnly = settings.BurpSuccessOnly
	}
	opts.Timeout = time.Duration(settings.EffectiveWebTimeout()) * time.Second
	// Reachability preflight — web modules skip TLS-dead targets when enabled.
	opts.PreflightEnabled = settings.WebReachabilityPreflight
	opts.PreflightTimeout = time.Duration(settings.EffectiveWebPreflightTimeout()) * time.Second

	// Wire the outbound-binding killswitch. When the user has pinned
	// a network interface in Settings, every dialer + subprocess in
	// the scan pipeline must source its traffic from this IP. nil
	// LocalAddr = default mode (no binding), which is the safe
	// fallback if NetworkInterfaceIP somehow ends up unparseable.
	//
	// Also installs the value into shared.SetGlobalLocalAddr so the
	// 20+ inline net.Dialer sites across modules that don't thread
	// opts through can still pick it up via BoundDialer's fallback
	// path. This way a settings change propagates to every dialer
	// without each module needing a signature update.
	if settings.NetworkInterface != "" && settings.NetworkInterfaceIP != "" {
		if ip := net.ParseIP(settings.NetworkInterfaceIP); ip != nil {
			opts.NetworkInterface = settings.NetworkInterface
			opts.LocalAddr = &net.TCPAddr{IP: ip}
			shared.SetGlobalLocalAddr(opts.LocalAddr)
		}
	} else {
		shared.SetGlobalLocalAddr(nil)
	}
	return opts
}

// BeginScan registers a scan with the manager and attaches the cancellation context
// + warning callback to opts. It also records the opts pointer on the
// ScanManager so FinishScan / Cancel can flush its transport idle pools
// at scan-end without modules having to remember to do it themselves.
func (h *Handler) BeginScan(scanID string, opts *shared.HTTPOptions) *shared.HTTPOptions {
	ctx := h.scanMgr.Register(scanID)
	if opts == nil {
		opts = &shared.HTTPOptions{}
	}
	opts.Ctx = ctx
	opts.OnWarning = func(msg string) {
		h.scanMgr.SetWarning(scanID, msg)
	}
	h.scanMgr.RegisterOpts(scanID, opts)
	// Proxy-reachability preflight. A common support confusion: the user
	// has an upstream proxy (Burp) enabled in Settings but the proxy
	// isn't running, so confirmed-hit replays (ReplayHit) silently fail
	// and the operator concludes "the scan is full of connection errors /
	// broken". Probe the proxy once at scan start with a short localhost
	// dial and surface a single clear warning if it's down, instead of
	// leaving the failures silent. Uses a plain dialer (NOT BoundDialer):
	// a localhost proxy must not be reached through the killswitch's
	// pinned outbound interface.
	if px := strings.TrimSpace(opts.ProxyURL); px != "" {
		if u, err := url.Parse(px); err == nil && u.Host != "" {
			addr := u.Host
			if u.Port() == "" {
				if u.Scheme == "https" {
					addr = u.Host + ":443"
				} else {
					addr = u.Host + ":8080"
				}
			}
			if c, derr := net.DialTimeout("tcp", addr, 1500*time.Millisecond); derr != nil {
				opts.OnWarning(fmt.Sprintf("Proxy %s is enabled in Settings but unreachable — confirmed-hit replays to Burp will not arrive. Start Burp/the proxy, or turn off the proxy in Settings.", px))
			} else {
				c.Close()
			}
		}
	}
	return opts
}

// FinishScan marks a scan done (unless cancelled) and releases its context.
// Uses an atomic conditional UPDATE (audit B34) so a cancel that fires
// concurrently with the scan-completion goroutine doesn't get overwritten.
// Previously this Read→Write sequence was TOCTOU-racy and would flip a
// freshly-cancelled scan back to done.
func (h *Handler) FinishScan(scanID string) {
	// If the connectivity monitor paused this scan, stamp 'paused' (preserving
	// the partial result for resume) instead of finalizing it as done/error.
	if h.scanMgr.WasPaused(scanID) {
		msg := h.scanMgr.Warning(scanID)
		if msg == "" {
			msg = "Paused — connectivity lost; will resume automatically when the internet is back."
		}
		h.db.MarkScanPaused(scanID, msg)
	} else {
		h.db.MarkDoneUnlessCancelled(scanID)
	}
	// Drop any resume-base stash for this scan (set when it was a resumed run).
	// If it re-paused, the DB result already holds the merged old+new, so the
	// next resume re-derives a fresh base from the row.
	h.db.ClearResumeBase(scanID)
	h.scanMgr.Unregister(scanID)
	// This scan just freed its workspace — wake the sequential-scan scheduler
	// so any scan queued behind it starts within ~1s instead of on the next tick.
	kickScanQueue()
	// Extract + cache this scan's vulnerabilities off the request path so the
	// /vulnerabilities index build never has to walk this (possibly huge) result
	// blob on page load. Best-effort; safe to skip on failure.
	go h.warmScanVulnCache(scanID)
	// If this scan was a vulnerability rescan, reconcile: archive any verified
	// finding the fresh run no longer reports (no-op for normal scans).
	go h.reconcileRescan(scanID)
}

// --- Workspace CRUD ---

func (h *Handler) WorkspaceCreate(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Redirect(w, r, "/settings", http.StatusSeeOther)
		return
	}
	name := strings.TrimSpace(r.FormValue("name"))
	desc := strings.TrimSpace(r.FormValue("description"))
	if name == "" {
		http.Redirect(w, r, "/settings?error=name_required", http.StatusSeeOther)
		return
	}
	_, err := h.db.CreateWorkspace(name, desc)
	if err != nil {
		http.Redirect(w, r, "/settings?error=create_failed", http.StatusSeeOther)
		return
	}
	http.Redirect(w, r, "/settings?success=workspace_created", http.StatusSeeOther)
}

func (h *Handler) WorkspaceDelete(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Redirect(w, r, "/settings", http.StatusSeeOther)
		return
	}
	id := r.FormValue("id")
	if id == database.DefaultWorkspaceID {
		http.Redirect(w, r, "/settings?error=cannot_delete_default", http.StatusSeeOther)
		return
	}
	if id != "" {
		h.db.DeleteWorkspace(id)
		if c, err := r.Cookie(activeWSCookie); err == nil && c.Value == id {
			http.SetCookie(w, &http.Cookie{
				Name:     activeWSCookie,
				Value:    database.DefaultWorkspaceID,
				Path:     "/",
				MaxAge:   365 * 24 * 3600,
				HttpOnly: true,
				SameSite: http.SameSiteLaxMode,
			})
		}
	}
	http.Redirect(w, r, "/settings", http.StatusSeeOther)
}

// WorkspaceReset wipes all per-workspace data (scans, targets, target
// lists) for the active workspace WITHOUT deleting the workspace itself.
// Global state — settings, API keys, CVE DB cache — is preserved.
// Destructive; requires POST + confirm form field.
func (h *Handler) WorkspaceReset(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Redirect(w, r, "/settings", http.StatusSeeOther)
		return
	}
	ws := h.activeWorkspace(r)
	if ws == nil {
		http.Redirect(w, r, "/settings?error=no_workspace", http.StatusSeeOther)
		return
	}
	// Hard-confirm checkbox required.
	if r.FormValue("confirm") != "yes" {
		http.Redirect(w, r, "/settings?error=reset_not_confirmed", http.StatusSeeOther)
		return
	}
	scanCount, targetCount, listCount := h.db.ResetWorkspace(ws.ID)
	http.Redirect(w, r,
		"/settings?success=workspace_reset&scans="+strconv.Itoa(scanCount)+
			"&targets="+strconv.Itoa(targetCount)+"&lists="+strconv.Itoa(listCount),
		http.StatusSeeOther)
}

// --- Target CRUD ---

// TargetAdd handles adding a single target
func (h *Handler) TargetAdd(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}
	ws := h.activeWorkspace(r)
	value := strings.TrimSpace(r.FormValue("value"))
	targetType := models.TargetType(r.FormValue("type"))
	note := strings.TrimSpace(r.FormValue("note"))
	listIDs := h.resolveListIDs(r, ws.ID)

	if value == "" {
		http.Redirect(w, r, "/targets?error=value_required", http.StatusSeeOther)
		return
	}

	// If IPv4 type and value is a CIDR or hyphen-range, expand to per-IP rows.
	if targetType == models.TargetIPv4 && (strings.Contains(value, "/") || isIPv4Range(value)) {
		var added, skipped, invalid int
		if strings.Contains(value, "/") {
			added, skipped, invalid = h.expandAndAddCIDR(ws.ID, value, note, listIDs)
		} else {
			added, skipped, invalid = h.expandAndAddIPSpec(ws.ID, value, note, listIDs)
		}
		http.Redirect(w, r, fmt.Sprintf("/targets?success=bulk_added&added=%d&skipped=%d&invalid=%d", added, skipped, invalid), http.StatusSeeOther)
		return
	}

	if !validateTarget(value, targetType) {
		http.Redirect(w, r, "/targets?error=invalid_target", http.StatusSeeOther)
		return
	}
	// If the target already exists, don't reject it as a duplicate when this
	// submission carries categor(ies) — apply them to the existing target
	// (a target can belong to several categories) instead of dropping it.
	if h.db.TargetExists(ws.ID, value) {
		if len(listIDs) > 0 {
			h.db.CreateTargetMulti(ws.ID, value, targetType, note, listIDs)
			http.Redirect(w, r, "/targets?success=recategorized", http.StatusSeeOther)
			return
		}
		http.Redirect(w, r, "/targets?error=duplicate", http.StatusSeeOther)
		return
	}

	h.db.CreateTargetMulti(ws.ID, value, targetType, note, listIDs)
	http.Redirect(w, r, "/targets?success=target_added", http.StatusSeeOther)
}

// TargetListCreate handles POST /targets/lists/create — adds a new named
// bucket within the active workspace.
func (h *Handler) TargetListCreate(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}
	ws := h.activeWorkspace(r)
	name := strings.TrimSpace(r.FormValue("name"))
	desc := strings.TrimSpace(r.FormValue("description"))
	if name == "" {
		http.Redirect(w, r, "/targets?error=list_name_required", http.StatusSeeOther)
		return
	}
	tl, err := h.db.CreateTargetList(ws.ID, name, desc)
	if err != nil || tl == nil {
		http.Redirect(w, r, "/targets?error=list_create_failed", http.StatusSeeOther)
		return
	}
	// A category can be created around EXISTING targets: any checked
	// `target_ids` are filed under the new list right away (the operator's
	// stated goal — categorize targets already in the system, not just add
	// brand-new ones). Each is validated to belong to the workspace.
	if ids := h.validateWorkspaceTargetIDs(r.Form["target_ids"], ws.ID); len(ids) > 0 {
		h.db.AddTargetsToList(tl.ID, ids)
	}
	http.Redirect(w, r, "/targets?list="+tl.ID+"&success=list_created", http.StatusSeeOther)
}

// validateWorkspaceTargetIDs filters a set of target IDs down to those that
// actually belong to the workspace (guards the membership endpoints against
// cross-workspace IDs submitted via a crafted/stale form).
func (h *Handler) validateWorkspaceTargetIDs(ids []string, workspaceID string) []string {
	var out []string
	for _, id := range ids {
		id = strings.TrimSpace(id)
		if id == "" {
			continue
		}
		if t, err := h.db.GetTarget(id); err == nil && t != nil && t.WorkspaceID == workspaceID {
			out = append(out, id)
		}
	}
	return out
}

// TargetListAddTargets handles POST /targets/lists/add — files EXISTING
// targets under an existing category. This is the "add already-present
// targets to this list" flow.
func (h *Handler) TargetListAddTargets(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}
	r.ParseForm()
	ws := h.activeWorkspace(r)
	listID := strings.TrimSpace(r.FormValue("list_id"))
	tl, err := h.db.GetTargetList(listID)
	if err != nil || tl == nil || tl.WorkspaceID != ws.ID {
		http.Redirect(w, r, "/targets?error=list_not_found", http.StatusSeeOther)
		return
	}
	ids := h.validateWorkspaceTargetIDs(r.Form["target_ids"], ws.ID)
	if len(ids) > 0 {
		h.db.AddTargetsToList(listID, ids)
	}
	http.Redirect(w, r, "/targets?list="+listID+"&success=targets_categorized", http.StatusSeeOther)
}

// TargetSetCategories handles POST /targets/categories — replaces the full
// set of categories a single target belongs to (per-target category editor).
// A target may be filed under several; an empty set leaves it uncategorized.
func (h *Handler) TargetSetCategories(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}
	r.ParseForm()
	ws := h.activeWorkspace(r)
	targetID := strings.TrimSpace(r.FormValue("target_id"))
	t, err := h.db.GetTarget(targetID)
	if err != nil || t == nil || t.WorkspaceID != ws.ID {
		http.Redirect(w, r, "/targets?error=target_not_found", http.StatusSeeOther)
		return
	}
	// Validate each chosen list belongs to the workspace, plus allow an
	// inline-new category (new_list_name) created on the spot.
	var listIDs []string
	seen := map[string]bool{}
	if name := strings.TrimSpace(r.FormValue("new_list_name")); name != "" {
		if tl, e := h.db.CreateTargetList(ws.ID, name, ""); e == nil && tl != nil {
			listIDs = append(listIDs, tl.ID)
			seen[tl.ID] = true
		}
	}
	for _, id := range r.Form["list_ids"] {
		if seen[id] {
			continue
		}
		if tl, e := h.db.GetTargetList(id); e == nil && tl != nil && tl.WorkspaceID == ws.ID {
			listIDs = append(listIDs, id)
			seen[id] = true
		}
	}
	h.db.SetTargetLists(targetID, listIDs)
	http.Redirect(w, r, "/targets?success=categories_updated", http.StatusSeeOther)
}

// TargetListDelete handles POST /targets/lists/delete — drops the list and
// resets every member's list_id to NULL (members are not deleted).
func (h *Handler) TargetListDelete(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}
	ws := h.activeWorkspace(r)
	id := strings.TrimSpace(r.FormValue("id"))
	if id == "" {
		http.Redirect(w, r, "/targets", http.StatusSeeOther)
		return
	}
	tl, err := h.db.GetTargetList(id)
	if err != nil || tl == nil || tl.WorkspaceID != ws.ID {
		http.Redirect(w, r, "/targets?error=list_not_found", http.StatusSeeOther)
		return
	}
	h.db.DeleteTargetList(id)
	http.Redirect(w, r, "/targets?success=list_deleted", http.StatusSeeOther)
}

// resolveListID picks the list_id for an add/bulk-import request. The form
// can either pick an existing list (`list_id=<uuid>`) or create a new one
// inline (`list_id=__new__` + `new_list_name=<text>`). Returns "" for the
// uncategorized bucket. The list is verified to belong to the workspace.
// resolveListIDs is the many-to-many version: it reads every checked
// `list_ids` value (a target may be filed under several categories) plus an
// optional inline-new list (`list_id=__new__` + `new_list_name`). Each is
// validated to belong to the workspace. Returns a de-duplicated slice; empty
// = uncategorized.
func (h *Handler) resolveListIDs(r *http.Request, workspaceID string) []string {
	r.ParseForm() // idempotent; ensures r.Form["list_ids"] is populated
	seen := map[string]bool{}
	var out []string
	add := func(id string) {
		id = strings.TrimSpace(id)
		if id == "" || seen[id] {
			return
		}
		seen[id] = true
		out = append(out, id)
	}
	// Inline-new list (from the "＋ new category" field on the add form).
	if strings.TrimSpace(r.FormValue("list_id")) == "__new__" || strings.TrimSpace(r.FormValue("new_list_name")) != "" {
		if name := strings.TrimSpace(r.FormValue("new_list_name")); name != "" {
			if tl, err := h.db.CreateTargetList(workspaceID, name, strings.TrimSpace(r.FormValue("new_list_description"))); err == nil && tl != nil {
				add(tl.ID)
			}
		}
	}
	// Existing categories: checkboxes named list_ids. Also accept a single
	// legacy list_id value (non-sentinel) for back-compat.
	for _, id := range r.Form["list_ids"] {
		if tl, err := h.db.GetTargetList(id); err == nil && tl != nil && tl.WorkspaceID == workspaceID {
			add(id)
		}
	}
	if single := strings.TrimSpace(r.FormValue("list_id")); single != "" && single != "__new__" {
		if tl, err := h.db.GetTargetList(single); err == nil && tl != nil && tl.WorkspaceID == workspaceID {
			add(single)
		}
	}
	return out
}

func (h *Handler) resolveListID(r *http.Request, workspaceID string) string {
	listID := strings.TrimSpace(r.FormValue("list_id"))
	if listID == "__new__" {
		name := strings.TrimSpace(r.FormValue("new_list_name"))
		if name == "" {
			return ""
		}
		desc := strings.TrimSpace(r.FormValue("new_list_description"))
		tl, err := h.db.CreateTargetList(workspaceID, name, desc)
		if err != nil || tl == nil {
			return ""
		}
		return tl.ID
	}
	if listID == "" {
		return ""
	}
	tl, err := h.db.GetTargetList(listID)
	if err != nil || tl == nil || tl.WorkspaceID != workspaceID {
		return ""
	}
	return listID
}

// TargetBulkAdd handles bulk target import (textarea or file upload)
func (h *Handler) TargetBulkAdd(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}
	ws := h.activeWorkspace(r)
	r.ParseMultipartForm(10 << 20) // 10MB max — also fills r.PostForm for resolveListIDs
	note := strings.TrimSpace(r.FormValue("note"))
	listIDs := h.resolveListIDs(r, ws.ID)

	// Two input streams:
	//   - hostsField: free-form IPs / CIDRs / hyphen-ranges / domains / FQDNs.
	//                 Each line is classified by shared.ClassifyInput; no
	//                 type radio. CIDR/range entries expand to per-IP rows.
	//   - urlsField:  URLs with explicit scheme. Each non-empty, non-# line
	//                 is added as TargetURL verbatim (no expansion — the
	//                 path is meaningful and must survive).
	// File upload falls into the hosts stream (operators don't typically
	// paste URL lists from files).
	hostLines := []string{}
	file, _, err := r.FormFile("file")
	if err == nil {
		defer file.Close()
		hostLines = readLines(file)
	} else {
		hostLines = parseTargetLines(r.FormValue("targets"))
	}
	urlLines := parseTargetLines(r.FormValue("urls"))

	if len(hostLines) == 0 && len(urlLines) == 0 {
		http.Redirect(w, r, "/targets?error=no_targets", http.StatusSeeOther)
		return
	}

	added, skipped, invalid, recat := 0, 0, 0, 0

	// --- Hosts stream: auto-classify per line ---
	for _, line := range hostLines {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}

		// CIDR / hyphen-range: only valid for IPs. Try to expand.
		if strings.Contains(line, "/") || isIPv4Range(line) {
			if strings.Contains(line, "/") {
				if _, _, err := net.ParseCIDR(line); err == nil {
					a, s, i := h.expandAndAddCIDR(ws.ID, line, note, listIDs)
					added += a
					skipped += s
					invalid += i
					continue
				}
			} else if isIPv4Range(line) {
				a, s, i := h.expandAndAddIPSpec(ws.ID, line, note, listIDs)
				added += a
				skipped += s
				invalid += i
				continue
			}
			// Not a valid CIDR — fall through to classifier (might be
			// a hostname with a slash, which we reject below anyway).
		}

		// Single-token: let shared.ClassifyInput decide ipv4 / domain / fqdn.
		// A URL pasted into the hosts box gets re-routed to the URL type
		// rather than rejected, so the user isn't punished for putting
		// it in the wrong field.
		c, cerr := shared.ClassifyInput(line)
		if cerr != nil {
			invalid++
			continue
		}
		t := models.TargetType("")
		switch c.Kind {
		case shared.KindIP:
			t = models.TargetIPv4
		case shared.KindURL:
			t = models.TargetURL
		case shared.KindDomain:
			// shared.ClassifyInput collapses domain / FQDN into one kind.
			// Use the same heuristic the form used to: 3+ labels → FQDN.
			if strings.Count(line, ".") >= 2 {
				t = models.TargetFQDN
			} else {
				t = models.TargetDomain
			}
		default:
			invalid++
			continue
		}
		exists := h.db.TargetExists(ws.ID, line)
		if _, err := h.db.CreateTargetMulti(ws.ID, line, t, note, listIDs); err != nil {
			skipped++
		} else if !exists {
			added++
		} else if len(listIDs) > 0 {
			// Already in the workspace, but this upload carried categor(ies)
			// it wasn't in yet — apply them WITHOUT dropping its existing
			// ones (a target can belong to several categories at once).
			recat++
		} else {
			skipped++
		}
	}

	// --- URL stream: each line is a TargetURL (scheme required by classifier) ---
	for _, line := range urlLines {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		// Tolerant: if user pasted a bare host into the URLs field,
		// prepend http:// so it still validates as a URL kind.
		if !strings.Contains(line, "://") {
			line = "http://" + line
		}
		c, cerr := shared.ClassifyInput(line)
		if cerr != nil || c.Kind != shared.KindURL {
			invalid++
			continue
		}
		exists := h.db.TargetExists(ws.ID, line)
		if _, err := h.db.CreateTargetMulti(ws.ID, line, models.TargetURL, note, listIDs); err != nil {
			skipped++
		} else if !exists {
			added++
		} else if len(listIDs) > 0 {
			recat++
		} else {
			skipped++
		}
	}

	http.Redirect(w, r, fmt.Sprintf("/targets?success=bulk_added&added=%d&skipped=%d&invalid=%d&recat=%d", added, skipped, invalid, recat), http.StatusSeeOther)
}

func (h *Handler) TargetDelete(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}
	id := r.FormValue("id")
	if id != "" {
		h.db.DeleteTarget(id)
	}
	http.Redirect(w, r, "/targets", http.StatusSeeOther)
}

// --- IPv4 range / CIDR expansion ---

// isIPv4Range returns true when the input looks like a hyphen-range:
//
//	192.168.1.10-50              (last-octet shorthand)
//	10.0.0.1-10.0.0.50           (full IP-to-IP range)
//
// Detection is purely syntactic — final validity is decided by the expander.
func isIPv4Range(s string) bool {
	s = strings.TrimSpace(s)
	if !strings.Contains(s, "-") || strings.Contains(s, "/") {
		return false
	}
	dash := strings.LastIndex(s, "-")
	if dash <= 0 {
		return false
	}
	left := s[:dash]
	octets := strings.Split(left, ".")
	if len(octets) != 4 {
		return false
	}
	for _, o := range octets {
		if o == "" {
			return false
		}
		for _, r := range o {
			if r < '0' || r > '9' {
				return false
			}
		}
	}
	return true
}

// expandAndAddIPSpec accepts either a CIDR (192.168.1.0/24) or a hyphen
// range (192.168.1.10-50 or 10.0.0.1-10.0.0.50) and adds each resulting
// host IP as a target. Wraps shared.ExpandTargets so we get the same
// expansion semantics the scanners use.
func (h *Handler) expandAndAddIPSpec(wsID, spec, note string, listIDs []string) (added, skipped, invalid int) {
	ips := shared.ExpandTargets([]string{spec}, 65536)
	if len(ips) == 0 || (len(ips) == 1 && ips[0] == spec) {
		// Expander returned the input unchanged → it's not a recognized
		// CIDR/range; treat as invalid here.
		return 0, 0, 1
	}
	for _, ip := range ips {
		exists := h.db.TargetExists(wsID, ip)
		// Always upsert so an already-present IP still gains any new categories
		// from this upload (a target can belong to several categories at once)
		// instead of being silently dropped.
		if _, err := h.db.CreateTargetMulti(wsID, ip, models.TargetIPv4, note, listIDs); err != nil {
			skipped++
		} else if exists {
			skipped++
		} else {
			added++
		}
	}
	return
}

// expandAndAddCIDR parses a CIDR block and adds each host IP as a target.
// Returns (added, skipped, invalid) counts. listID may be "" for the
// uncategorized bucket.
func (h *Handler) expandAndAddCIDR(wsID, cidr, note string, listIDs []string) (added, skipped, invalid int) {
	_, ipNet, err := net.ParseCIDR(cidr)
	if err != nil {
		return 0, 0, 1
	}

	// Safety: don't expand blocks larger than /16 (65536 hosts)
	ones, bits := ipNet.Mask.Size()
	if bits != 32 || ones < 16 {
		return 0, 0, 1
	}

	hostCount := int(math.Pow(2, float64(bits-ones)))

	// Convert network IP to uint32 for iteration
	ip := ipNet.IP.To4()
	start := binary.BigEndian.Uint32(ip)

	for i := 0; i < hostCount; i++ {
		current := start + uint32(i)
		ipBytes := make(net.IP, 4)
		binary.BigEndian.PutUint32(ipBytes, current)
		ipStr := ipBytes.String()

		// Skip network and broadcast for /31+ blocks
		if hostCount > 2 {
			if i == 0 || i == hostCount-1 {
				continue
			}
		}

		exists := h.db.TargetExists(wsID, ipStr)
		// Always upsert so an already-present IP still gains any new categories
		// from this upload instead of being silently dropped.
		_, err := h.db.CreateTargetMulti(wsID, ipStr, models.TargetIPv4, note, listIDs)
		if err != nil {
			skipped++
		} else if exists {
			skipped++
		} else {
			added++
		}
	}
	return
}

// --- Helpers ---

// parseTargetLines splits input text by newlines, commas, or semicolons
func parseTargetLines(text string) []string {
	// Normalize separators to newlines
	text = strings.ReplaceAll(text, ",", "\n")
	text = strings.ReplaceAll(text, ";", "\n")
	text = strings.ReplaceAll(text, "\r\n", "\n")

	var result []string
	for _, line := range strings.Split(text, "\n") {
		line = strings.TrimSpace(line)
		if line != "" {
			result = append(result, line)
		}
	}
	return result
}

// readLines reads lines from an io.Reader (file upload)
func readLines(r io.Reader) []string {
	var lines []string
	scanner := bufio.NewScanner(r)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line != "" {
			// Also handle comma-separated values in file
			for _, part := range strings.Split(line, ",") {
				part = strings.TrimSpace(part)
				if part != "" {
					lines = append(lines, part)
				}
			}
		}
	}
	return lines
}

// --- Validation ---

func validateTarget(value string, t models.TargetType) bool {
	value = strings.TrimSpace(value)
	if value == "" {
		return false
	}
	switch t {
	case models.TargetIPv4:
		// Accept a single IP, a CIDR, or a hyphen-range (192.168.1.10-50
		// or 10.0.0.1-10.0.0.50). CIDR/range get expanded by the caller.
		if strings.Contains(value, "/") {
			if _, _, err := net.ParseCIDR(value); err == nil {
				return true
			}
			return false
		}
		if isIPv4Range(value) {
			ips := shared.ExpandTargets([]string{value}, 65536)
			return len(ips) > 0 && (len(ips) > 1 || ips[0] != value)
		}
		ip := net.ParseIP(value)
		return ip != nil && ip.To4() != nil
	case models.TargetDomain, models.TargetFQDN:
		// Accept any hostname-shaped input — at least one dot, no spaces /
		// slashes / scheme. The previous "exactly 2 / at least 3 dots" rule
		// rejected legitimate inputs like sub.example.com under the wrong
		// type. We trust the user to pick the label that makes sense to
		// them and only reject obviously malformed text here.
		if strings.ContainsAny(value, " \t/?#") {
			return false
		}
		if !strings.Contains(value, ".") {
			return false
		}
		for _, p := range strings.Split(value, ".") {
			if p == "" {
				return false
			}
		}
		return true
	default:
		return false
	}
}

func (h *Handler) render(w http.ResponseWriter, name string, data interface{}) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	if err := h.templates.ExecuteTemplate(w, name, data); err != nil {
		http.Error(w, "Template error: "+err.Error(), http.StatusInternalServerError)
	}
}

// renderResults handles the partial vs. full-page split for /modules/<x>/results/<id>.
// When the request carries ?partial=1, only the named inner template is rendered so
// the live-update JS can swap just the results section without reloading the page.
func (h *Handler) renderResults(w http.ResponseWriter, r *http.Request, innerTemplate string, data interface{}) {
	if r.URL.Query().Get("partial") == "1" {
		h.render(w, innerTemplate, data)
		return
	}
	h.render(w, "layout", data)
}

// writeScanStatus writes the standard scan-progress JSON used by scan_progress.html,
// including any sticky warning the ScanManager has tracked for this scan.
//
// Adds two safety nets the UI relies on for an honest progress bar:
//
//  1. Clamping — done is capped at total so the percent never exceeds
//     100% (some scanners over-count when a target yields multiple
//     probes).
//  2. Indeterminate flag — when total is 0 (modules that don't know
//     their denominator upfront), we tell the UI to render a spinner
//     instead of "0% forever". The UI honors `indeterminate=true` even
//     when done > 0 (e.g. a scanner emitting "queries sent" with no
//     upfront count).
// markToolError marks a scan failed with a human-readable reason, translating
// the raw tool error (stderr / exec error / result Error field) via
// shared.ExplainToolError so the results-page error banner explains the
// failure and what to do. Modules call this when they detect a HARD failure
// (tool missing, non-zero exit, or every target errored with zero results);
// partial failures should stay 'done' with a warning instead.
func (h *Handler) markToolError(scanID, rawErr string) {
	h.db.MarkScanError(scanID, shared.ExplainToolError(rawErr))
}

// markHardFailure flips a finished scan to 'error' with a translated reason
// IFF every attempted unit failed — a hard failure (tool missing, all targets
// unreachable), not a legitimately empty result (a clean host, no CVEs, no
// dangling CNAME). unitErrors holds the non-empty per-unit error strings;
// totalUnits is how many units (targets/urls/domains) were attempted. It
// prefers an error the catalog recognizes so the banner shows the most
// actionable one. Call it AFTER the final UpdateScanResult and ONLY when the
// scan wasn't cancelled (ctx.Err()==nil); MarkScanError additionally refuses
// to override a 'cancelled' row. Returns true if it marked an error.
func (h *Handler) markHardFailure(scanID string, unitErrors []string, totalUnits int) bool {
	if totalUnits <= 0 || len(unitErrors) < totalUnits {
		return false
	}
	reason := unitErrors[0]
	for _, e := range unitErrors {
		if _, ok := shared.TranslateToolError(e); ok {
			reason = e
			break
		}
	}
	h.markToolError(scanID, reason)
	return true
}

func (h *Handler) writeScanStatus(w http.ResponseWriter, scan *models.Scan) {
	done := scan.ProgressDone
	total := scan.ProgressTotal
	indeterminate := total <= 0
	pct := 0
	if total > 0 {
		if done > total {
			done = total
		}
		pct = (done * 100) / total
	}
	// When the scan is finished, the bar should sit at 100% regardless
	// of whether the scanner emitted a final progress() call. Some
	// modules return before flushing the last "done = total" tick.
	if scan.Status == models.ScanDone && !indeterminate {
		pct = 100
		done = total
	}
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{
		"status":        scan.Status,
		"done":          done,
		"total":         total,
		"percent":       pct,
		"indeterminate": indeterminate,
		"message":       scan.ProgressMsg,
		// Full console history (every progress line, lossless). The client
		// renders this instead of piecing the log together from 2s samples
		// of `message`, so nothing is lost between polls and a reload shows
		// the whole run.
		"log":      scan.ConsoleLog,
		"logLines": len(scan.ConsoleLines()),
		"warning":  h.scanMgr.Warning(scan.ID),
	})
}
