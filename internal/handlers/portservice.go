package handlers

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"scanner/internal/database"
	"scanner/internal/models"
	"scanner/internal/modules/nuclei"
	"scanner/internal/modules/portservice"
	"scanner/internal/modules/shared"
)

type portServiceConfig struct {
	Targets      []string `json:"targets"`
	Scope        string   `json:"scope"`
	PortSpec     string   `json:"port_spec,omitempty"`
	Speed        string   `json:"speed,omitempty"`
	Concurrency  int      `json:"concurrency,omitempty"` // 0 → fall back to global Settings
	UDPScan      bool     `json:"udp_scan,omitempty"`
	ScriptDepth  string   `json:"script_depth,omitempty"`  // "safe" (default) | "deep"
	UsernameList []string `json:"username_list,omitempty"` // brute/auth wordlist
	PasswordList []string `json:"password_list,omitempty"`
	ScriptCat    string   `json:"script_cat,omitempty"` // legacy, ignored
}

func (h *Handler) PortServicePage(w http.ResponseWriter, r *http.Request) {
	data := h.baseData(r, "Advanced Host Scanner - scaNNer", "portservice")
	ws := data["ActiveWorkspace"].(*models.Workspace)
	scans, _ := h.db.ListScansLite(ws.ID, "portservice")
	data["Scans"] = scans
	targets, _ := h.db.ListTargets(ws.ID, "")
	data["WSTargets"] = targets
	data["WSTargetGroups"] = h.groupTargetsByList(ws.ID)
	// Surface the effective concurrency so the user can see how many hosts
	// will be scanned in parallel — sourced from Settings → Network Scan
	// Defaults → Max Concurrent. Audit MED fix: previously the display was
	// silently clamped to 16 here while the actual runtime cap in
	// runPortService is 50, so the hero card advertised "Soft cap: 16"
	// while the slider went to 50 and the runtime honoured that. Cap both
	// at 50 for internal consistency; the form + hero text now agree.
	concurrency := h.db.GetSettings().EffectiveNetworkMaxConcurrent()
	if concurrency <= 0 {
		concurrency = 4
	}
	if concurrency > 50 {
		concurrency = 50
	}
	data["EffectiveConcurrency"] = concurrency
	h.render(w, "layout", data)
}

func parsePortServiceForm(r *http.Request) portServiceConfig {
	cfg := portServiceConfig{}
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
	cfg.Scope = strings.ToLower(strings.TrimSpace(r.FormValue("scope")))
	if cfg.Scope == "" {
		cfg.Scope = "common"
	}
	cfg.PortSpec = strings.TrimSpace(r.FormValue("port_spec"))
	cfg.Speed = strings.ToLower(strings.TrimSpace(r.FormValue("speed")))
	cfg.UDPScan = r.FormValue("udp_scan") == "on"
	if v, err := strconv.Atoi(strings.TrimSpace(r.FormValue("concurrency"))); err == nil && v >= 1 && v <= 50 {
		cfg.Concurrency = v
	}
	cfg.ScriptDepth = strings.ToLower(strings.TrimSpace(r.FormValue("script_depth")))
	if cfg.ScriptDepth != "deep" {
		cfg.ScriptDepth = "safe" // safe default
	}
	// Parse newline/comma-separated wordlists from textarea inputs.
	// Brute + auth NSE scripts only fire when BOTH lists are non-empty;
	// the scanner package re-checks this so a partial submission (only
	// users, or only passwords) silently falls back to no-brute.
	splitWordlist := func(raw string) []string {
		var out []string
		for _, line := range strings.FieldsFunc(raw, func(r rune) bool { return r == '\n' || r == ',' }) {
			if v := strings.TrimSpace(line); v != "" {
				out = append(out, v)
			}
		}
		return out
	}
	cfg.UsernameList = splitWordlist(r.FormValue("username_list"))
	cfg.PasswordList = splitWordlist(r.FormValue("password_list"))
	if cfg.Speed == "" {
		cfg.Speed = "fast"
	}
	return cfg
}

func (h *Handler) PortServiceRun(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Redirect(w, r, "/modules/portservice", http.StatusSeeOther)
		return
	}
	r.ParseForm()
	ws := h.activeWorkspace(r)
	cfg := parsePortServiceForm(r)
	if len(cfg.Targets) == 0 {
		http.Redirect(w, r, "/modules/portservice?error=no_targets", http.StatusSeeOther)
		return
	}
	if (cfg.Scope == "custom" || cfg.Scope == "range") && cfg.PortSpec != "" && !shared.ValidPortSpec(cfg.PortSpec) {
		http.Redirect(w, r, "/modules/portservice?error=bad_ports", http.StatusSeeOther)
		return
	}

	cfgJSON, _ := json.Marshal(cfg)
	// Progress total = expanded host count so a /24 reports as 256 hosts,
	// not 1. cfg.Targets stays as user-supplied strings (CIDR / range) so
	// nmap still does a single batched invocation per target; the scanner
	// bumps `done` by len(rows) per target to keep the indicator accurate.
	totalHosts := len(shared.ExpandTargets(cfg.Targets, 65536))
	if totalHosts < len(cfg.Targets) {
		totalHosts = len(cfg.Targets)
	}
	scan, err := h.db.CreateScan(ws.ID, "portservice", string(cfgJSON), totalHosts)
	if err != nil {
		http.Redirect(w, r, "/modules/portservice?error=db_error", http.StatusSeeOther)
		return
	}
	if h.queueIfSequential(w, r, scan) {
		return
	}
	go h.runPortService(scan.ID, cfg, h.BuildHTTPOptions(r))
	http.Redirect(w, r, "/modules/portservice/results/"+scan.ID, http.StatusSeeOther)
}

// portServiceResultCache is a per-scanID memo of the parsed result blob so
// the htmx polling endpoint (which re-hits this handler every ~2s while a
// scan is running) doesn't re-unmarshal a growing multi-MB JSON blob every
// tick. Keyed by scan.ID + a "version" derived from Result length +
// UpdatedAt — either change forces a re-parse; otherwise we serve the
// cached aggregates. Once scan.Status == done, the cached entry is the
// final one (polling stops at that point anyway, per scan_progress.html).
type portServiceCachedResult struct {
	resultLen     int
	updatedAtNano int64
	results       []portservice.TargetResult
	upHosts       int
	downHosts     int
	filteredHosts int
	totalPorts    int
	totalScripts  int
}

var (
	portServiceResultCache   = map[string]*portServiceCachedResult{}
	portServiceResultCacheMu sync.RWMutex
)

func (h *Handler) PortServiceResults(w http.ResponseWriter, r *http.Request) {
	rest := strings.TrimPrefix(r.URL.Path, "/modules/portservice/results/")
	// Sub-route: /modules/portservice/results/{scan}/host/{ip} → dedicated
	// per-host detail page. Dispatched here so we keep a single registered
	// route prefix and don't have to mess with mux ordering.
	if strings.Contains(rest, "/host/") {
		h.PortServiceHostDetail(w, r)
		return
	}
	scanID := rest
	scan, err := h.db.GetScan(scanID)
	if err != nil {
		http.NotFound(w, r)
		return
	}
	data := h.baseData(r, "Advanced Host Scanner Results - scaNNer", "portservice_results")

	// Audit MED perf fix: parse the result blob at most once per (scanID,
	// resultLen, updatedAt) tuple. htmx polls this endpoint every ~2s and
	// the blob can be tens of MB on a /24 with NSE + banner + Nuclei
	// data — repeated unmarshal at that scale is a measurable CPU cost.
	resultLen := len(scan.Result)
	// scans has no UpdatedAt column — use FinishedAt when the scan has
	// terminated, otherwise ProgressDone (monotonic during a running
	// scan) as the cache-invalidation salt. Either way a change to the
	// result blob forces re-parse via resultLen anyway.
	var updatedNano int64
	if scan.FinishedAt != nil {
		updatedNano = scan.FinishedAt.UnixNano()
	} else {
		updatedNano = int64(scan.ProgressDone)
	}

	portServiceResultCacheMu.RLock()
	cached, ok := portServiceResultCache[scanID]
	portServiceResultCacheMu.RUnlock()

	if !ok || cached.resultLen != resultLen || cached.updatedAtNano != updatedNano {
		var result portservice.ScanResult
		json.Unmarshal([]byte(scan.Result), &result)
		upHosts, downHosts, filteredHosts, totalPorts, totalScripts := 0, 0, 0, 0, 0
		for _, tr := range result.Results {
			if !tr.HostUp {
				downHosts++
			} else {
				upHosts++
				if tr.IcmpFiltered {
					filteredHosts++
				}
				totalPorts += tr.OpenCount
				for _, p := range tr.Ports {
					totalScripts += len(p.Scripts)
				}
			}
		}
		cached = &portServiceCachedResult{
			resultLen:     resultLen,
			updatedAtNano: updatedNano,
			results:       result.Results,
			upHosts:       upHosts,
			downHosts:     downHosts,
			filteredHosts: filteredHosts,
			totalPorts:    totalPorts,
			totalScripts:  totalScripts,
		}
		portServiceResultCacheMu.Lock()
		portServiceResultCache[scanID] = cached
		// Cheap bounded-cache eviction: cap at 128 concurrently-viewed
		// scans. Drops arbitrary entries when over the cap; the finished
		// scans not in the map just re-parse once next time they're
		// opened, no correctness impact.
		if len(portServiceResultCache) > 128 {
			for k := range portServiceResultCache {
				if k == scanID {
					continue
				}
				delete(portServiceResultCache, k)
				if len(portServiceResultCache) <= 128 {
					break
				}
			}
		}
		portServiceResultCacheMu.Unlock()
	}

	data["Scan"] = scan
	data["Results"] = cached.results
	data["UpHosts"] = cached.upHosts
	data["DownHosts"] = cached.downHosts
	data["FilteredHosts"] = cached.filteredHosts
	data["TotalPorts"] = cached.totalPorts
	data["TotalScripts"] = cached.totalScripts
	h.renderResults(w, r, "portservice_results_inner", data)
}

// PortServiceHostDetail renders the dedicated per-host page (Shodan-style):
// every nmap-detected service banner, every NSE script output, and every
// nuclei finding in full detail. Path: /modules/portservice/results/{scan}/host/{ip}.
func (h *Handler) PortServiceHostDetail(w http.ResponseWriter, r *http.Request) {
	rest := strings.TrimPrefix(r.URL.Path, "/modules/portservice/results/")
	parts := strings.SplitN(rest, "/host/", 2)
	if len(parts) != 2 {
		http.NotFound(w, r)
		return
	}
	scanID := parts[0]
	ip := parts[1]
	scan, err := h.db.GetScan(scanID)
	if err != nil {
		http.NotFound(w, r)
		return
	}
	var result portservice.ScanResult
	json.Unmarshal([]byte(scan.Result), &result)
	var host *portservice.TargetResult
	for i := range result.Results {
		if result.Results[i].IP == ip || result.Results[i].Target == ip {
			host = &result.Results[i]
			break
		}
	}
	if host == nil {
		http.NotFound(w, r)
		return
	}
	data := h.baseData(r, "Host "+ip+" — Advanced Host Scanner", "portservice_host")
	data["Scan"] = scan
	data["Host"] = host
	// Pre-bucket findings by severity for the summary cards.
	sevCount := map[string]int{}
	for _, f := range host.NucleiFindings {
		sevCount[f.Severity]++
	}
	data["SevCount"] = sevCount
	h.render(w, "layout", data)
}

func (h *Handler) PortServiceStatus(w http.ResponseWriter, r *http.Request) {
	scanID := strings.TrimPrefix(r.URL.Path, "/modules/portservice/status/")
	scan, err := h.db.GetScan(scanID)
	if err != nil {
		http.NotFound(w, r)
		return
	}
	h.writeScanStatus(w, scan)
}

func (h *Handler) runPortService(scanID string, cfg portServiceConfig, opts *shared.HTTPOptions) {
	if !h.db.MarkRunning(scanID) {
		return
	}
	// Audit MED fix: previously this used scanMgr.Register directly and
	// never plumbed HTTPOptions into the banner enrichment / Nuclei
	// phases — meaning Settings (proxy, custom User-Agent, custom
	// headers, source-IP killswitch, per-scan timeout) were silently
	// ignored for the two web-touching phases of this module. BeginScan
	// wires ctx + OnWarning + RegisterOpts so cancel-time transport
	// flushes and warning surfacing work like every other web module.
	opts = h.BeginScan(scanID, opts)
	ctx := opts.Ctx
	defer h.FinishScan(scanID)

	// Honor the user's Settings → Network Scan Defaults → Max Concurrent
	// value verbatim, with a soft safety cap of 16 (running >16 nmap -A
	// processes simultaneously can starve the box). Previously this was
	// clamped to ≤4 silently — so if a user set 8 or 16 in Settings, the
	// scanner ignored it.
	settings := h.db.GetSettings()
	// Concurrency precedence: per-scan form value > global setting >
	// hardcoded default. User's form choice (1-25) wins so the slider
	// actually does something even when global Settings cap is lower.
	concurrency := cfg.Concurrency
	if concurrency <= 0 {
		concurrency = settings.EffectiveNetworkMaxConcurrent()
	}
	if concurrency <= 0 {
		concurrency = 10
	}
	if concurrency > 50 {
		concurrency = 50
	}

	scanCfg := portservice.Config{
		Targets:      cfg.Targets,
		Scope:        portservice.Scope(cfg.Scope),
		PortSpec:     cfg.PortSpec,
		Speed:        cfg.Speed,
		Concurrency:  concurrency,
		UDPScan:      cfg.UDPScan,
		ScriptDepth:  cfg.ScriptDepth,
		UsernameList: cfg.UsernameList,
		PasswordList: cfg.PasswordList,
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

	result := portservice.Scan(ctx, scanCfg,
		func(done int, msg string) { h.db.UpdateScanProgress(scanID, done, msg) },
		func(p *portservice.ScanResult) {
			b, err := json.Marshal(p)
			if err == nil {
				mu.Lock()
				latest = b
				mu.Unlock()
			}
		})

	// Phase 3.5 — Banner enrichment. Connects to every open port and
	// captures Shodan-style data: HTTP status + headers + body preview for
	// HTTP/HTTPS, plain TCP banners (SSH/FTP/SMTP/...) elsewhere. Results
	// are stitched into Port.HTTPResp / Port.Banner so the host detail page
	// can render real responses, not just nmap's parsed service tag.
	//
	// Audit MED fix: guard each post-Scan phase with a ctx.Err() check.
	// Previously a mid-scan Cancel would return control from Scan() but
	// then unconditionally launch EnrichBanners (thousands of TCP+HTTP
	// probes) and runNucleiPhase (nuclei subprocess) — a "cancel" that
	// silently continued to burn network for minutes.
	if ctx.Err() == nil {
		totalAtNmap := 0
		if s, _ := h.db.GetScan(scanID); s != nil {
			totalAtNmap = s.ProgressTotal
		}
		h.db.UpdateScanProgress(scanID, totalAtNmap, "→ Banner enrichment phase")
		portservice.EnrichBanners(ctx, opts, result, func(msg string) {
			h.db.UpdateScanProgress(scanID, totalAtNmap, msg)
		})
		// Flush latest snapshot with banner data before Nuclei runs so
		// the UI shows enrichment progress even if Nuclei stalls.
		if b, err := json.Marshal(result); err == nil {
			mu.Lock()
			latest = b
			mu.Unlock()
		}
	}

	// Phase 4 — Nuclei. Per-host vulnerability assessment against every open
	// HTTP/HTTPS service nmap surfaced. Findings are stitched back into the
	// matching TargetResult so the UI can render them next to the host's ports.
	if ctx.Err() == nil {
		runNucleiPhase(ctx, scanID, result, h.db, opts)
	}

	resJSON, _ := json.Marshal(result)
	h.db.UpdateScanResult(scanID, string(resJSON))

	// Hard-failure surfacing: if every host row errored, mark the scan failed
	// with a translated reason rather than a silent "done" with zero findings.
	if opts.Ctx.Err() == nil {
		var errs []string
		for _, tr := range result.Results {
			if tr.Error != "" {
				errs = append(errs, tr.Error)
			}
		}
		h.markHardFailure(scanID, errs, len(result.Results))
	}
}

// runNucleiPhase walks every host in the result, builds an http(s)://host:port
// URL for each open web service, runs nuclei against the union, then attaches
// each finding to its host's TargetResult. Skips hosts with no web services.
// Takes a *database.DB so it can also reset progress_total to len(URLs) — the
// nmap phases hit total before nuclei starts, which made the live progress
// bar look "Done" prematurely.
func runNucleiPhase(ctx context.Context, scanID string, result *portservice.ScanResult, db *database.DB, opts *shared.HTTPOptions) {
	if result == nil || len(result.Results) == 0 {
		return
	}
	type hostURL struct {
		host string
		url  string
	}
	urlSet := map[string]string{} // url → host (deduped — same scheme://host:port can't appear twice)
	hostsWithUrls := map[string]struct{}{}
	for _, tr := range result.Results {
		host := tr.IP
		if host == "" {
			host = tr.Target
		}
		if host == "" {
			continue
		}
		for _, p := range tr.Ports {
			if p.State != "open" {
				continue
			}
			scheme := ""
			svc := strings.ToLower(p.Service)
			tunnel := strings.ToLower(p.Tunnel)
			if tunnel == "ssl" || strings.Contains(svc, "https") || svc == "ssl/http" {
				scheme = "https"
			} else if strings.Contains(svc, "http") || strings.Contains(svc, "www") {
				scheme = "http"
			}
			if scheme == "" {
				continue
			}
			u := fmt.Sprintf("%s://%s:%d", scheme, host, p.Port)
			urlSet[u] = host
			hostsWithUrls[host] = struct{}{}
		}
	}
	urls := make([]string, 0, len(urlSet))
	urlToHost := make(map[string]string, len(urlSet))
	for u, h := range urlSet {
		urls = append(urls, u)
		urlToHost[u] = h
	}
	if len(urls) == 0 {
		return
	}
	// Keep progress_total stable — it stays at the user's original host
	// count for the entire scan. The progress bar drops to 0 here and then
	// refills back to the host count as nuclei walks the URL list (URL
	// progress is mapped onto the host-count scale so the totals never
	// change underneath the user). This avoids the confusing "6 hosts
	// became 12 mid-scan" effect a user reported when total was reset to
	// len(urls).
	totalScale := 0
	if s, _ := db.GetScan(scanID); s != nil {
		totalScale = s.ProgressTotal
	}
	if totalScale <= 0 {
		totalScale = len(urls) // fallback if for some reason total wasn't set
	}
	db.UpdateScanProgress(scanID, 0,
		fmt.Sprintf("→ Phase 4: Nuclei on %d URL(s) across %d host(s) — http+https endpoints both probed", len(urls), len(hostsWithUrls)))

	cfg := nuclei.ScanConfig{
		// Severity: every band — critical, high, medium, low, info — per
		// the user's request. Speed is kept manageable by the tag filter
		// below + per-template timeout in nuclei.Scan.
		// Tags: actionable buckets only (CVEs, explicit vulns, exposed
		// panels, default creds, misconfigurations). Skips fuzz / generic
		// / banner-only template categories that double runtime with
		// little signal.
		Severity:        []string{"critical", "high", "medium", "low", "info"},
		Tags:            []string{"cve", "vulnerability", "exposure", "default-login", "misconfig"},
		RateLimit:       0,
		Concurrency:     50,
		UpdateTemplates: false,
	}
	// Audit MED fix: propagate Settings-derived proxy, custom UA/headers,
	// and cookies to nuclei so the outbound traffic is consistent with
	// every other web-touching module. Rate limit / concurrency are
	// intentionally left at the module's tuned defaults (per user
	// constraint — don't change scan parameters here).
	if opts != nil {
		cfg.CustomHeaders = opts.Headers
		cfg.Cookies = opts.Cookies
		cfg.ProxyURL = opts.ProxyURL
		cfg.UserAgent = opts.UserAgent
	}
	nres := nuclei.Scan(ctx, urls, cfg,
		func(done int, msg string) {
			// Map nuclei's URL-level progress (0..len(urls)) onto the
			// fixed host-count scale we promised the user — so the bar
			// climbs from 0 back to total without ever changing total.
			mapped := done
			if len(urls) > 0 && totalScale > 0 {
				mapped = int(float64(done) / float64(len(urls)) * float64(totalScale))
				if mapped > totalScale {
					mapped = totalScale
				}
			}
			// Don't prepend "nuclei · " when the message is already a
			// "$ " command — that would break db.UpdateScanProgress's
			// detection and the command wouldn't land in the Commands
			// run panel.
			out := msg
			if !strings.HasPrefix(msg, "$ ") {
				out = "nuclei · " + msg
			}
			db.UpdateScanProgress(scanID, mapped, out)
		}, nil)
	if nres == nil {
		return
	}
	// Surface a time-cap truncation so the Port/Service scan doesn't present
	// an INCOMPLETE nuclei phase as a clean pass (same fix as advancedweb /
	// standalone nuclei). Findings gathered before the kill are still
	// stitched in below.
	if nres.Truncated {
		db.UpdateScanProgress(scanID, totalScale, "⚠ nuclei phase INCOMPLETE — "+nres.TruncateReason)
	}
	// Stitch findings back into the per-host result.
	hostFindings := map[string][]portservice.NucleiFinding{}
	for _, ntr := range nres.Results {
		host, ok := urlToHost[ntr.URL]
		if !ok {
			continue
		}
		for _, f := range ntr.Findings {
			hostFindings[host] = append(hostFindings[host], portservice.NucleiFinding{
				TemplateID:  f.TemplateID,
				Name:        f.Name,
				Severity:    f.Severity,
				Type:        f.Type,
				Host:        f.Host,
				MatchedAt:   f.MatchedAt,
				Description: f.Description,
				Tags:        f.Tags,
				CVEs:        f.CVEs,
				CWEs:        f.CWEs,
				References:  f.References,
				Extracted:   f.Extracted,
			})
		}
	}
	for i := range result.Results {
		host := result.Results[i].IP
		if host == "" {
			host = result.Results[i].Target
		}
		if found, ok := hostFindings[host]; ok && len(found) > 0 {
			// Severity-rank sort (critical → high → medium → low → info →
			// unknown) so both the inline-summary preview and the host
			// detail page show the worst issues first.
			sort.SliceStable(found, func(a, b int) bool {
				return nuclei.SeverityRank(found[a].Severity) > nuclei.SeverityRank(found[b].Severity)
			})
			result.Results[i].NucleiFindings = found
		}
	}
}
