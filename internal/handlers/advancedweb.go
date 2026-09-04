package handlers

import (
	"encoding/json"
	"net/http"
	"runtime"
	"runtime/debug"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"scanner/internal/models"
	"scanner/internal/modules/advancedweb"
	"scanner/internal/modules/cvematch"
	"scanner/internal/modules/direnum"
	"scanner/internal/modules/dnsenum"
	"scanner/internal/modules/httpmethods"
	"scanner/internal/modules/httpxfind"
	"scanner/internal/modules/nuclei"
	"scanner/internal/modules/secheaders"
	"scanner/internal/modules/shared"
	"scanner/internal/modules/spider"
	"scanner/internal/modules/sslscan"
	"scanner/internal/modules/techdetect"
	"scanner/internal/modules/wafdetect"
	"scanner/internal/modules/whoisinfo"
	"scanner/internal/modules/wpscan"
)

func (h *Handler) AdvancedWebPage(w http.ResponseWriter, r *http.Request) {
	data := h.baseData(r, "Advanced Web Application Scanner - scaNNer", "advancedweb")
	ws := data["ActiveWorkspace"].(*models.Workspace)
	scans, _ := h.db.ListScansLite(ws.ID, "advancedweb")
	data["Scans"] = scans
	// Target lists for the multi-pick UI — each checkbox selects every
	// member of that list. The suite enqueues one scan per resolved
	// (list ∪ manual target) entry. Members are pulled per list so the
	// form can show a count chip ("Company A · 14 targets").
	lists, _ := h.db.ListTargetLists(ws.ID)
	listMembers := map[string][]models.Target{}
	listCounts := map[string]int{}
	for _, l := range lists {
		members, _ := h.db.ListTargetsInList(l.ID)
		listMembers[l.ID] = members
		listCounts[l.ID] = len(members)
	}
	data["TargetLists"] = lists
	data["TargetListMembers"] = listMembers
	data["TargetListCounts"] = listCounts
	// Grouped per-list target picker (same UX as every other module form):
	// select individual targets, whole lists, or per-scheme via the shared
	// "workspace_targets" partial (posts name="targets").
	data["WSTargetGroups"] = h.groupTargetsByList(ws.ID)
	// Surface WPScan API-token presence so the suite form can mirror the
	// standalone WPScan page's warning banner.
	data["HasWPScanAPIKey"] = strings.TrimSpace(h.db.GetSettings().WPScanAPIKey) != ""
	// Per-user stage visibility: a user only sees a sub-scan they can run in
	// this workspace. Admins see all. The template wraps each stage in
	// {{if index .AllowedStages "<stage>"}}.
	data["AllowedStages"] = h.advWebAllowedStages(r, ws.ID)
	h.render(w, "layout", data)
}

// advWebStageModules maps each suite stage (the enable_* form key suffix) to the
// registry module grant(s) that authorize it. A stage is allowed if the user
// holds a grant for any of its modules in the active workspace.
var advWebStageModules = map[string][]string{
	"whois":       {"whoisinfo"},
	"dnsenum":     {"dnsenum"},
	"httpxfind":   {"httpxfind"},
	"sslscan":     {"sslscan"},
	"wafdetect":   {"wafdetect"},
	"techdetect":  {"techdetect"},
	"cvematch":    {"cvematch"},
	"wpscan":      {"wpscan"},
	"nuclei":      {"nuclei"},
	"dirspider":   {"direnum", "spider"},
	"httpmethods": {"httpmethods"},
	"secheaders":  {"secheaders"},
}

// advWebAllowedStages returns the set of suite stages the current user may run
// in the given workspace (all stages for admins).
func (h *Handler) advWebAllowedStages(r *http.Request, wsID string) map[string]bool {
	res := map[string]bool{}
	user := h.currentUser(r)
	if user == nil || user.IsAdmin() {
		for k := range advWebStageModules {
			res[k] = true
		}
		return res
	}
	allowed, _ := h.db.UserModulesInWorkspace(user.ID, wsID)
	for stage, mods := range advWebStageModules {
		for _, m := range mods {
			if allowed[m] {
				res[stage] = true
				break
			}
		}
	}
	return res
}

func (h *Handler) AdvancedWebRun(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Redirect(w, r, "/modules/advanced-web", http.StatusSeeOther)
		return
	}
	ws := h.activeWorkspace(r)

	r.ParseForm()
	manual := strings.TrimSpace(r.FormValue("target"))
	// Collect every unique target across the manual input and the
	// checked target lists. List members are dedup'd in case the same
	// host belongs to multiple lists.
	targetSet := map[string]bool{}
	if manual != "" {
		targetSet[manual] = true
	}
	for _, lid := range r.Form["target_list_ids"] {
		lid = strings.TrimSpace(lid)
		if lid == "" {
			continue
		}
		// Workspace scope-check (audit B-xworkspace-target-list).
		// Previously target_list_ids was trusted verbatim: an
		// attacker (or CSRF) could submit any list ID and enumerate
		// targets from other workspaces. Reject any list whose
		// workspace_id doesn't match the active workspace — silently
		// skipped, same UX as the manual-IP filter below.
		tl, err := h.db.GetTargetList(lid)
		if err != nil || tl == nil || tl.WorkspaceID != ws.ID {
			continue
		}
		members, _ := h.db.ListTargetsInList(lid)
		for _, m := range members {
			if v := strings.TrimSpace(m.Value); v != "" {
				targetSet[v] = true
			}
		}
	}
	// Individual targets ticked in the workspace target-list picker
	// ({{template "workspace_targets"}}, name="targets") — same UX as the other
	// module forms. These are already resolved target strings; the per-target
	// validation below still rejects IPs/malformed entries.
	for _, v := range r.Form["targets"] {
		if v = strings.TrimSpace(v); v != "" {
			targetSet[v] = true
		}
	}
	if len(targetSet) == 0 {
		http.Redirect(w, r, "/modules/advanced-web?error=no_target", http.StatusSeeOther)
		return
	}
	// Pre-validate each target so we reject IPs and malformed input
	// before kicking off any scan goroutines.
	type tgt struct {
		raw  string
		kind shared.InputKind
	}
	targets := make([]tgt, 0, len(targetSet))
	for raw := range targetSet {
		classified, err := shared.ClassifyInput(raw)
		if err != nil || classified.Kind == shared.KindIP {
			continue // skip silently; user's other targets still run
		}
		targets = append(targets, tgt{raw: raw, kind: classified.Kind})
	}
	if len(targets) == 0 {
		http.Redirect(w, r, "/modules/advanced-web?error=invalid_target", http.StatusSeeOther)
		return
	}
	// For pre-validation defaults below we use the first target's kind;
	// the per-scan goroutine re-validates per target.
	classified := shared.ClassifiedInput{Kind: targets[0].kind}

	// Re-check stage permissions server-side so a hidden stage cannot be
	// re-enabled by a forged POST (defense-in-depth beyond the hidden UI).
	stageOK := h.advWebAllowedStages(r, ws.ID)
	cfg := advancedweb.Config{
		EnableWhois:       r.FormValue("enable_whois") == "on" && stageOK["whois"],
		EnableDNSEnum:     r.FormValue("enable_dnsenum") == "on" && stageOK["dnsenum"],
		EnableHTTPXFind:   r.FormValue("enable_httpxfind") == "on" && stageOK["httpxfind"],
		EnableSSLScan:     r.FormValue("enable_sslscan") == "on" && stageOK["sslscan"],
		EnableWAFDetect:   r.FormValue("enable_wafdetect") == "on" && stageOK["wafdetect"],
		EnableTechDetect:  r.FormValue("enable_techdetect") == "on" && stageOK["techdetect"],
		EnableCVEMatch:    r.FormValue("enable_cvematch") == "on" && stageOK["cvematch"],
		EnableWPScan:      r.FormValue("enable_wpscan") == "on" && stageOK["wpscan"],
		EnableNuclei:      r.FormValue("enable_nuclei") == "on" && stageOK["nuclei"],
		EnableDirSpider:   r.FormValue("enable_dirspider") == "on" && stageOK["dirspider"],
		EnableHTTPMethods: r.FormValue("enable_httpmethods") == "on" && stageOK["httpmethods"],
		EnableSecHeaders:  r.FormValue("enable_secheaders") == "on" && stageOK["secheaders"],
		DNSEnumSpeed:       r.FormValue("dnsenum_speed"),
		HTTPXMode:          r.FormValue("httpx_mode"),
		HTTPXCustomPorts:   strings.TrimSpace(r.FormValue("httpx_custom_ports")),
		HTTPXDirectHTTP:    r.FormValue("httpx_direct_http") == "on",
		SSLScanPorts:       strings.TrimSpace(r.FormValue("sslscan_ports")),
		DirEnumLevel:       r.FormValue("direnum_level"),
		DirEnumSmartScan:   r.FormValue("direnum_smart_scan") == "on",
		DirEnumRecursive:   r.FormValue("direnum_recursive") == "on",
		NucleiSeverities:   r.Form["nuclei_severities"],
		NucleiLevel:        r.FormValue("nuclei_level"),
		TechDetectAggressive: r.FormValue("techdetect_aggressive") == "on",
		WPScanSpeed:        r.FormValue("wpscan_speed"),
		SecHeadersMethods:  r.Form["secheaders_methods"],
		SecHeadersOverride: r.FormValue("secheaders_override") == "on",
	}
	if v, err := strconv.Atoi(r.FormValue("dnsenum_max_depth")); err == nil && v >= 1 && v <= 3 {
		cfg.DNSEnumMaxDepth = v
	}
	if v, err := strconv.Atoi(r.FormValue("httpx_concurrency")); err == nil && v >= 1 && v <= 1000 {
		cfg.HTTPXConcurrency = v
	}
	// When HTTPX is enabled in custom mode the port spec is required +
	// must be parseable. Fail-fast at the form layer rather than letting
	// the scanner silently fall back to common ports.
	if cfg.EnableHTTPXFind && cfg.HTTPXMode == "custom" {
		if cfg.HTTPXCustomPorts == "" {
			http.Redirect(w, r, "/modules/advanced-web?error=httpx_custom_ports_required", http.StatusSeeOther)
			return
		}
		if !shared.ValidPortSpec(cfg.HTTPXCustomPorts) {
			http.Redirect(w, r, "/modules/advanced-web?error=httpx_custom_ports_invalid", http.StatusSeeOther)
			return
		}
	}
	// SSL/TLS ports are optional (blank → default 443,8443); when set they must
	// be a valid CSV+range port spec.
	if cfg.EnableSSLScan && cfg.SSLScanPorts != "" && !shared.ValidPortSpec(cfg.SSLScanPorts) {
		http.Redirect(w, r, "/modules/advanced-web?error=sslscan_ports_invalid", http.StatusSeeOther)
		return
	}
	if v, err := strconv.Atoi(r.FormValue("direnum_max_depth")); err == nil && v >= 1 && v <= 5 {
		cfg.DirEnumMaxDepth = v
	} else if cfg.DirEnumRecursive {
		cfg.DirEnumMaxDepth = 2
	}
	if v, err := strconv.Atoi(r.FormValue("spider_max_depth")); err == nil && v >= 1 && v <= 10 {
		cfg.SpiderMaxDepth = v
	}
	if v, err := strconv.Atoi(r.FormValue("spider_max_pages")); err == nil && v >= 10 && v <= 5000 {
		cfg.SpiderMaxPages = v
	}

	// Fail fast: at least one stage has to be enabled.
	any := cfg.EnableWhois || cfg.EnableDNSEnum || cfg.EnableHTTPXFind ||
		cfg.EnableSSLScan || cfg.EnableWAFDetect || cfg.EnableTechDetect ||
		cfg.EnableCVEMatch || cfg.EnableWPScan || cfg.EnableNuclei ||
		cfg.EnableDirSpider || cfg.EnableHTTPMethods || cfg.EnableSecHeaders
	if !any {
		http.Redirect(w, r, "/modules/advanced-web?error=no_stages", http.StatusSeeOther)
		return
	}

	opts := h.BuildHTTPOptions(r)

	// Pre-compute the progress denominator so it matches what the scanner
	// will emit. The scanner only bumps `done` for stages that are
	// enabled AND not skipped by input-kind (stages 1/2/3 are skipped
	// for URL input). If we hardcoded 10 here, the bar would briefly
	// show "X/10" and then jump down to "X/7" once the scanner
	// re-emitted the real total — looking like the count was being
	// "multiplied" by some factor.
	isURL := classified.Kind == shared.KindURL
	enabledCount := 0
	addUnit := func(on, urlSkips bool) {
		if !on {
			return
		}
		if urlSkips && isURL {
			return
		}
		enabledCount++
	}
	addUnit(cfg.EnableWhois, true)
	addUnit(cfg.EnableDNSEnum, true)
	addUnit(cfg.EnableHTTPXFind, true)
	addUnit(cfg.EnableSSLScan, false)
	addUnit(cfg.EnableWAFDetect, false)
	addUnit(cfg.EnableTechDetect, false)
	// CVE Matcher / WPScan only count when techdetect is also on
	// (else they're no-op skips driven by missing inputs).
	addUnit(cfg.EnableCVEMatch && cfg.EnableTechDetect, false)
	addUnit(cfg.EnableWPScan && cfg.EnableTechDetect, false)
	addUnit(cfg.EnableNuclei, false)
	addUnit(cfg.EnableDirSpider, false)
	addUnit(cfg.EnableHTTPMethods, false)
	addUnit(cfg.EnableSecHeaders, false)
	if enabledCount == 0 {
		enabledCount = 1
	}

	// ONE scan covering ALL selected targets. Previously each target
	// spawned its own scan, which flooded the queue when a target list
	// had hundreds of entries. The suite scanner now consumes a multi-
	// target list and runs each stage against the unified host set.
	rawTargets := make([]string, 0, len(targets))
	for _, t := range targets {
		rawTargets = append(rawTargets, t.raw)
	}
	cfg.Targets = rawTargets
	cfg.Target = rawTargets[0] // legacy alias for older JSON consumers
	cfgJSON, _ := json.Marshal(cfg)
	scan, err := h.db.CreateScan(ws.ID, "advancedweb", string(cfgJSON), enabledCount)
	if err != nil {
		http.Redirect(w, r, "/modules/advanced-web?error=db_error", http.StatusSeeOther)
		return
	}
	// Sequential scanning: if the operator ticked "start after the current
	// scan finishes" and this workspace is busy, park this run as queued.
	if h.queueIfSequential(w, r, scan) {
		return
	}
	go h.runAdvancedWeb(scan.ID, cfg, opts)
	http.Redirect(w, r, "/modules/advanced-web/results/"+scan.ID, http.StatusSeeOther)
}

func (h *Handler) runAdvancedWeb(scanID string, cfg advancedweb.Config, opts *shared.HTTPOptions) {
	if !h.db.MarkRunning(scanID) {
		return
	}
	opts = h.BeginScan(scanID, opts)
	defer h.FinishScan(scanID)

	// Live partial saver — every 2s, marshal the latest snapshot and
	// write it to the scan's result column so partial-refresh polls can
	// render mid-flight progress.
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
				snap := latest
				mu.Unlock()
				if snap != nil {
					h.db.UpdateScanResult(scanID, string(snap))
				}
			}
		}
	}()

	conc := h.db.GetSettings().EffectiveWebMaxConcurrent()

	// CVE lookup closure — adapts h.db.CVELookup to the suite's
	// CVELookup signature. Identical to the standalone CVE Matcher
	// handler's lookup; keeps both code paths consistent.
	cveLookup := func(productKey string) []cvematch.CacheCVE {
		recs, err := h.db.CVELookup(productKey)
		if err != nil || len(recs) == 0 {
			return nil
		}
		out := make([]cvematch.CacheCVE, 0, len(recs))
		for _, r := range recs {
			out = append(out, cvematch.CacheCVE{
				CVEID:       r.CVEID,
				ProductKey:  r.ProductKey,
				ProductName: r.ProductName,
				VersionLo:   r.VersionLo,
				VersionHi:   r.VersionHi,
				LoInc:       r.LoInc == 1,
				HiInc:       r.HiInc == 1,
				FixedIn:     r.FixedIn,
				Severity:    r.Severity,
				CVSS:        r.CVSS,
				Description: r.Description,
				Remediation: r.Remediation,
				Reference:   r.Reference,
			})
		}
		return out
	}

	result, err := advancedweb.Scan(cfg, opts, conc, cveLookup,
		func(done, total int, msg string) {
			h.db.UpdateScanProgressFull(scanID, done, total, msg)
		},
		func(partial *advancedweb.ScanResult) {
			b, e := json.Marshal(partial)
			if e == nil {
				mu.Lock()
				latest = b
				mu.Unlock()
			}
		})

	if err != nil {
		// Surface the validation/setup failure both into the result blob
		// (so the UI sees Error=...) and on the scan status. Without
		// this the user sees an `error` badge with no explanation.
		errResult := &advancedweb.ScanResult{
			Target: cfg.Target,
			Error:  err.Error(),
		}
		// Single atomic finalize (audit B8) — result + msg + status in
		// one UPDATE instead of three separate writes.
		b, _ := json.Marshal(errResult)
		h.db.FinalizeScan(scanID, string(b), "error: "+err.Error(), models.ScanError)
		return
	}
	resultJSON, _ := json.Marshal(result)
	// A non-nil ScanResult.Error (from a captured panic or stage-level
	// fatal) should also flip the overall scan status to error so the
	// list view and progress badge tell the right story.
	if result != nil && result.Error != "" {
		h.db.FinalizeScan(scanID, string(resultJSON), "error: "+result.Error, models.ScanError)
		return
	}
	// Incomplete suite (a stage was cut short by its time cap — e.g. nuclei
	// or DirSpider). The scan produced usable partial results but did NOT
	// fully cover the target, so it must NOT show as a clean green "done"
	// in the Scans list / dashboard. Finalize as error with a message that
	// makes clear it's a truncation, not a crash. (This is the fix for the
	// operator's report: a 90-min nuclei run killed at its cap was being
	// reported as "done · 0 findings".)
	if result != nil && result.Incomplete {
		h.db.FinalizeScan(scanID, string(resultJSON), "INCOMPLETE — "+result.IncompleteReason, models.ScanError)
		return
	}
	// Normal completion path. FinalizeScan honors a concurrent cancel
	// (its WHERE clause skips rows whose status went to cancelled in
	// the meantime), so we don't need to read-then-write.
	h.db.FinalizeScan(scanID, string(resultJSON), "completed", models.ScanDone)
}

// jsonEscape is a tiny helper for stuffing an error message into a
// pre-baked JSON string without bringing in the encoder.
func jsonEscape(s string) string {
	b, _ := json.Marshal(s)
	if len(b) >= 2 {
		return string(b[1 : len(b)-1])
	}
	return s
}

// extractScanID grabs the scanID after a /modules/<slug>/<action>/
// prefix. Used by both the hyphenated and slug-form URLs.
func extractScanID(p, action string) string {
	for _, prefix := range []string{"/modules/advanced-web/" + action + "/", "/modules/advancedweb/" + action + "/"} {
		if strings.HasPrefix(p, prefix) {
			return strings.TrimPrefix(p, prefix)
		}
	}
	return p
}

func (h *Handler) AdvancedWebStatus(w http.ResponseWriter, r *http.Request) {
	scanID := extractScanID(r.URL.Path, "status")
	scan, err := h.db.GetScan(scanID)
	if err != nil {
		http.NotFound(w, r)
		return
	}
	h.writeScanStatus(w, scan)
}

func (h *Handler) AdvancedWebResults(w http.ResponseWriter, r *http.Request) {
	scanID := extractScanID(r.URL.Path, "results")
	scan, err := h.db.GetScan(scanID)
	if err != nil {
		http.NotFound(w, r)
		return
	}
	data := h.baseData(r, "Advanced Web Suite Results - scaNNer", "advancedweb_results")
	var result advancedweb.ScanResult
	if scan.Result != "" && scan.Result != "{}" {
		json.Unmarshal([]byte(scan.Result), &result)
	}
	// Backfill: when the scan has just been created, scan.Result is "{}"
	// (set by CreateScan) and the unmarshal leaves Stages == nil. The
	// template iterates StageOrder and looks up each stage in Stages;
	// a nil entry would panic on `$sr.Status`. Seed every stage so the
	// page renders cleanly during the running-but-not-yet-flushed window.
	if result.Stages == nil {
		result.Stages = map[advancedweb.Stage]*advancedweb.StageResult{}
	}
	for _, s := range advancedweb.StageOrder {
		if _, ok := result.Stages[s]; !ok {
			result.Stages[s] = &advancedweb.StageResult{
				Stage:  s,
				Status: advancedweb.StatusPending,
			}
		}
	}
	if result.Target == "" {
		result.Target = scan.ID
	}

	// Pre-decode each stage's native result type so the embedded
	// per-stage templates can range over their own data structures
	// directly. We pass these as separate keys on the data map so the
	// suite results template can pick the right one per stage.
	//
	// HARD CAP: each heavy slice is trimmed to displayRowCap rows
	// before reaching the template. A 1818-target run was producing a
	// 44MB HTML page; even after the initial 200-row cap a separate
	// 212MB advancedweb scan still rendered a 5.35MB / 4.15s page
	// because the per-row inner fields (httpxfind RawRequest +
	// RawResponse, sslscan cert PEM, nuclei matcher payloads) carry
	// the bulk of the weight. The fix strips the heaviest inner fields
	// per row before they reach the template (see the httpxfind stage
	// below), so each displayed row is lightweight (raw req/resp are
	// truncated to a small preview). With the per-row weight removed the
	// cap can be generous: 200 rows keeps the page fast while showing far
	// more than the old 50 (users found "874 services, 50 shown"
	// confusing). Rows beyond the cap remain in the scan's Result blob
	// and are reachable via "Copy all URLs", Export, and the standalone
	// module page (which serves the full set ungated).
	const displayRowCap = 200
	stageData := map[string]any{}
	if sr, ok := result.Stages[advancedweb.StageWhois]; ok && len(sr.Result) > 0 {
		var v whoisinfo.ScanResult
		if json.Unmarshal(sr.Result, &v) == nil {
			stageData[string(advancedweb.StageWhois)] = &v
		}
	}
	// stageMeta is populated in the same decode passes below — each
	// per-stage Result blob is only unmarshalled ONCE per request
	// (audit fix: previously DNSEnum/HTTPXFind/SSLScan/Nuclei/
	// HTTPMethods/SecHeaders all decoded twice on every 2 s htmx poll,
	// doubling parser CPU + allocs while a scan streams).
	stageMeta := map[string]int{}
	if sr, ok := result.Stages[advancedweb.StageDNSEnum]; ok && len(sr.Result) > 0 {
		var v dnsenum.ScanResult
		if json.Unmarshal(sr.Result, &v) == nil {
			// Counters computed on the FULL slice before display
			// truncation so top-line badges stay accurate.
			c := 0
			for _, dr := range v.Results {
				c += dr.TotalFound
			}
			stageMeta["dnsenum_count"] = c
			// Build the FULL flat list of subdomain names BEFORE
			// truncating display rows, so "Copy all" in the suite
			// view can dump every discovered subdomain even though
			// the visible table is capped at displayRowCap. Without
			// this the clipboard copy was silently limited to the
			// first 200 rows.
			var bulk strings.Builder
			for _, dr := range v.Results {
				for _, sub := range dr.Subdomains {
					bulk.WriteString(sub.Subdomain)
					bulk.WriteByte('\n')
				}
			}
			for i := range v.Results {
				if len(v.Results[i].Subdomains) > displayRowCap {
					v.Results[i].Subdomains = v.Results[i].Subdomains[:displayRowCap]
				}
			}
			stageData[string(advancedweb.StageDNSEnum)] = &v
			stageData[string(advancedweb.StageDNSEnum)+"_bulk"] = bulk.String()
		}
	}
	if sr, ok := result.Stages[advancedweb.StageHTTPXFind]; ok && len(sr.Result) > 0 {
		var v httpxfind.ScanResult
		if json.Unmarshal(sr.Result, &v) == nil {
			// HTTPX rows carry RawRequest+RawResponse+ResponseBody
			// (multi-KB each — RawResponse alone can be 64KB+). These
			// are the heaviest contributors to the suite page payload.
			// Capture the full URL list first (so "Copy all URLs" gets
			// every URL), cap row count, then TRUNCATE the heavy fields
			// to small previews instead of blanking them — operators
			// complained that "View" produced an empty panel. Previews
			// big enough to show response headers + the first chunk of
			// body. For full data the standalone module page is one
			// click away (the "Open in module view" link in the stage
			// card header).
			const (
				bodyPreviewBytes = 4096
				rawPreviewBytes  = 2048
			)
			stageMeta["httpxfind_count"] = len(v.Services) // real total, before any cap
			var hbulk strings.Builder
			for _, svc := range v.Services {
				hbulk.WriteString(svc.URL)
				hbulk.WriteByte('\n')
			}
			// Server-side "Show more": the ?httpx= query param chooses how
			// many rows to render. Default 50 keeps the page light — the
			// user explicitly opts into more (200 / all) via links, so the
			// heavier payload is only paid when requested. Only the first
			// httpxDetailWindow rows carry (trimmed) inline response detail;
			// rows beyond it are main-row only, so even "all" (bounded at
			// httpxHardMax) stays a few MB, not tens. Rows past the hard max
			// remain reachable via Copy-all / Export / the standalone module.
			const (
				httpxDefaultRows  = 50
				httpxHardMax      = 1000
				httpxDetailWindow = 50
			)
			httpxRows := httpxDefaultRows
			switch r.URL.Query().Get("httpx") {
			case "200":
				httpxRows = 200
			case "500":
				httpxRows = 500
			case "all":
				httpxRows = len(v.Services)
				if httpxRows > httpxHardMax {
					httpxRows = httpxHardMax
				}
			}
			if len(v.Services) > httpxRows {
				v.Services = v.Services[:httpxRows]
			}
			for i := range v.Services {
				if i < httpxDetailWindow {
					v.Services[i].RawRequest = truncatePreview(v.Services[i].RawRequest, rawPreviewBytes)
					v.Services[i].RawResponse = truncatePreview(v.Services[i].RawResponse, rawPreviewBytes)
					v.Services[i].ResponseBody = truncatePreview(v.Services[i].ResponseBody, bodyPreviewBytes)
				} else {
					v.Services[i].RawRequest = ""
					v.Services[i].RawResponse = ""
					v.Services[i].ResponseBody = ""
					v.Services[i].ResponseHeaders = ""
				}
			}
			stageData[string(advancedweb.StageHTTPXFind)] = &v
			stageData[string(advancedweb.StageHTTPXFind)+"_bulk"] = hbulk.String()
		}
	}
	if sr, ok := result.Stages[advancedweb.StageSSLScan]; ok && len(sr.Result) > 0 {
		var v []*sslscan.HostResult
		if json.Unmarshal(sr.Result, &v) == nil {
			stageData[string(advancedweb.StageSSLScan)] = v
			c, crit, high, med, low, info := 0, 0, 0, 0, 0, 0
			for _, h := range v {
				if h != nil {
					for _, f := range h.Findings {
						c++
						switch f.Severity {
						case sslscan.SevCritical:
							crit++
						case sslscan.SevHigh:
							high++
						case sslscan.SevMedium:
							med++
						case sslscan.SevLow:
							low++
						case sslscan.SevInfo:
							info++
						}
					}
				}
			}
			stageMeta["sslscan_count"] = c
			// sslscan_results_inner expects severity-bucketed counts at
			// the top level. Standalone handler computes these in
			// sslscan.go; we mirror them here so the embedded view in
			// the advancedweb suite doesn't render "<no value>".
			stageMeta["sslscan_critical"] = crit
			stageMeta["sslscan_high"] = high
			stageMeta["sslscan_medium"] = med
			stageMeta["sslscan_low"] = low
			stageMeta["sslscan_info"] = info
		}
	}
	if sr, ok := result.Stages[advancedweb.StageWAFDetect]; ok && len(sr.Result) > 0 {
		var v wafdetect.ScanResult
		if json.Unmarshal(sr.Result, &v) == nil {
			if len(v.Results) > displayRowCap {
				v.Results = v.Results[:displayRowCap]
			}
			stageData[string(advancedweb.StageWAFDetect)] = &v
			c := 0
			for _, t := range v.Results {
				if t.WAFDetected {
					c++
				}
			}
			stageMeta["wafdetect_count"] = c
		}
	}
	if sr, ok := result.Stages[advancedweb.StageTechDetect]; ok && len(sr.Result) > 0 {
		var v techdetect.ScanResult
		if json.Unmarshal(sr.Result, &v) == nil {
			// techdetect_count is the REAL total tech count across ALL results,
			// computed before any row cap so the badge stays accurate.
			c := 0
			for _, t := range v.Results {
				c += len(t.Technologies)
			}
			stageMeta["techdetect_count"] = c
			stageMeta["techdetect_total_rows"] = len(v.Results)

			// Bug report: a host was visible in CVE Matcher but NOT in Tech
			// Detection. Cause: the display truncated to the FIRST 200 rows in
			// raw scan order, so a versioned/vulnerable host past row 200 was
			// dropped here even though CVE Matcher (fed by the full in-memory
			// set) surfaced it. Fix ordering + let the operator load more:
			//
			//   1. Sort so the most CVE-relevant rows survive the cap — hosts
			//      carrying a version-bearing technology first (those are the
			//      exact rows that produce CVE inputs), then by tech count.
			//      Anything CVE Matcher can flag is now at the front of the
			//      Tech Detection list too.
			//   2. ?techrows= toggle (200 default / 500 / all, hard-capped) so
			//      a specific host beyond the default window is reachable
			//      in-page, not only via export.
			sort.SliceStable(v.Results, func(i, j int) bool {
				vi, vj := techHasVersion(v.Results[i]), techHasVersion(v.Results[j])
				if vi != vj {
					return vi // version-bearing (CVE-relevant) first
				}
				return len(v.Results[i].Technologies) > len(v.Results[j].Technologies)
			})

			const techHardMax = 2000
			techRows := displayRowCap
			switch r.URL.Query().Get("techrows") {
			case "500":
				techRows = 500
			case "all":
				techRows = len(v.Results)
				if techRows > techHardMax {
					techRows = techHardMax
				}
			}
			if len(v.Results) > techRows {
				v.Results = v.Results[:techRows]
			}
			stageMeta["techdetect_shown_rows"] = len(v.Results)
			// Raw request/response blobs (up to a 2 MB captured body each) are
			// what made this stage the heaviest on the page. Trim to previews
			// for the shown rows so a larger window is affordable; full data is
			// one click away on the standalone module page / export.
			const (
				tdRawPreview  = 2048
				tdRespPreview = 4096
			)
			for i := range v.Results {
				v.Results[i].RawRequest = truncatePreview(v.Results[i].RawRequest, tdRawPreview)
				v.Results[i].RawResponse = truncatePreview(v.Results[i].RawResponse, tdRespPreview)
			}
			stageData[string(advancedweb.StageTechDetect)] = &v
		}
	}
	// CVE Matcher stage — unmarshal its native ScanResult AND compute
	// severity bucket counts so cvematch_results_inner renders correctly
	// (it expects a map[string]int via the "SeverityCounts" key).
	cveSeverityCounts := map[string]int{"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0}
	if sr, ok := result.Stages[advancedweb.StageCVEMatch]; ok && len(sr.Result) > 0 {
		var v cvematch.ScanResult
		if json.Unmarshal(sr.Result, &v) == nil {
			// Counts are computed BEFORE truncating so badges stay accurate.
			for _, m := range v.Matches {
				cveSeverityCounts[m.Severity]++
			}
			stageMeta["cvematch_count"] = len(v.Matches)
			if len(v.Matches) > displayRowCap {
				v.Matches = v.Matches[:displayRowCap]
			}
			if len(v.Inputs) > displayRowCap {
				v.Inputs = v.Inputs[:displayRowCap]
			}
			stageData[string(advancedweb.StageCVEMatch)] = &v
		}
	}
	// WPScan stage — unmarshal native shape + count findings.
	if sr, ok := result.Stages[advancedweb.StageWPScan]; ok && len(sr.Result) > 0 {
		var v wpscan.ScanResult
		if json.Unmarshal(sr.Result, &v) == nil {
			if len(v.Results) > displayRowCap {
				v.Results = v.Results[:displayRowCap]
			}
			stageData[string(advancedweb.StageWPScan)] = &v
			total := 0
			for _, tr := range v.Results {
				total += len(tr.Findings)
			}
			stageMeta["wpscan_count"] = total
		}
	}
	if sr, ok := result.Stages[advancedweb.StageNuclei]; ok && len(sr.Result) > 0 {
		var v nuclei.ScanResult
		if json.Unmarshal(sr.Result, &v) == nil {
			// Severity buckets computed on the FULL slice BEFORE
			// display truncation so top-line badges stay accurate.
			total, crit, high, med, low := 0, 0, 0, 0, 0
			for _, t := range v.Results {
				for _, f := range t.Findings {
					total++
					switch strings.ToLower(f.Severity) {
					case "critical":
						crit++
					case "high":
						high++
					case "medium":
						med++
					case "low":
						low++
					}
				}
			}
			stageMeta["nuclei_count"] = total
			stageMeta["nuclei_critical"] = crit
			stageMeta["nuclei_high"] = high
			stageMeta["nuclei_medium"] = med
			stageMeta["nuclei_low"] = low
			// Per-URL Findings list — cap each one, then cap outer.
			for i := range v.Results {
				if len(v.Results[i].Findings) > displayRowCap {
					v.Results[i].Findings = v.Results[i].Findings[:displayRowCap]
				}
			}
			if len(v.Results) > displayRowCap {
				v.Results = v.Results[:displayRowCap]
			}
			stageData[string(advancedweb.StageNuclei)] = &v
		}
	}
	if sr, ok := result.Stages[advancedweb.StageDirSpider]; ok && len(sr.Result) > 0 {
		var combined struct {
			DirEnum      *direnum.ScanResult `json:"direnum,omitempty"`
			Spider       *spider.ScanResult  `json:"spider,omitempty"`
			IterationLog []string            `json:"iteration_log,omitempty"`
		}
		if json.Unmarshal(sr.Result, &combined) == nil {
			// Cap dir entries + spider resources per target.
			if combined.DirEnum != nil {
				for i := range combined.DirEnum.Results {
					if len(combined.DirEnum.Results[i].Entries) > displayRowCap {
						combined.DirEnum.Results[i].Entries = combined.DirEnum.Results[i].Entries[:displayRowCap]
					}
				}
			}
			if combined.Spider != nil {
				for i := range combined.Spider.Results {
					if len(combined.Spider.Results[i].Resources) > displayRowCap {
						combined.Spider.Results[i].Resources = combined.Spider.Results[i].Resources[:displayRowCap]
					}
				}
			}
			stageData[string(advancedweb.StageDirSpider)] = &combined
			c := 0
			if combined.DirEnum != nil {
				for _, tr := range combined.DirEnum.Results {
					c += tr.TotalFound
				}
			}
			stageMeta["direnum_count"] = c
			sc := 0
			if combined.Spider != nil {
				for _, tr := range combined.Spider.Results {
					sc += len(tr.Resources)
				}
			}
			stageMeta["spider_count"] = sc
		}
	}
	if sr, ok := result.Stages[advancedweb.StageHTTPMethods]; ok && len(sr.Result) > 0 {
		var v httpmethods.ScanResult
		if json.Unmarshal(sr.Result, &v) == nil {
			// Counters computed on the FULL slice BEFORE display
			// truncation so top-line badges stay accurate.
			c, dangerous := 0, 0
			for _, ur := range v.Results {
				for _, mr := range ur.Methods {
					if mr.StatusCode >= 200 && mr.StatusCode < 400 {
						c++
					}
					if mr.Dangerous && mr.StatusCode >= 200 && mr.StatusCode < 400 {
						dangerous++
					}
				}
			}
			stageMeta["httpmethods_count"] = c
			stageMeta["httpmethods_dangerous"] = dangerous
			if len(v.Results) > displayRowCap {
				v.Results = v.Results[:displayRowCap]
			}
			stageData[string(advancedweb.StageHTTPMethods)] = &v
		}
	}
	if sr, ok := result.Stages[advancedweb.StageSecHeaders]; ok && len(sr.Result) > 0 {
		var v secheaders.ScanResult
		if json.Unmarshal(sr.Result, &v) == nil {
			// Counters computed on the FULL slice BEFORE display
			// truncation so top-line badges stay accurate.
			c, missing := 0, 0
			for _, ur := range v.Results {
				c += len(ur.Findings)
				for _, f := range ur.Findings {
					if string(f.Severity) == "HIGH" || string(f.Severity) == "MEDIUM" {
						missing++
					}
				}
			}
			stageMeta["secheaders_count"] = c
			stageMeta["secheaders_missing"] = missing
			if len(v.Results) > displayRowCap {
				v.Results = v.Results[:displayRowCap]
			}
			stageData[string(advancedweb.StageSecHeaders)] = &v
		}
	}

	// Decode the original Config blob so the results template can
	// surface a "Scan Config" side panel. Without this, a user
	// arriving mid-scan can't tell which stages were enabled, what
	// depth presets were picked, or which per-module overrides were
	// applied — they only see the stage timeline. The decoded struct
	// is read-only on the template side.
	var origCfg advancedweb.Config
	if scan.Config != "" {
		_ = json.Unmarshal([]byte(scan.Config), &origCfg)
	}

	data["Scan"] = scan
	data["SuiteResult"] = &result
	data["ScanConfig"] = &origCfg
	data["StageData"] = stageData
	data["StageMeta"] = stageMeta
	data["CVESeverityCounts"] = cveSeverityCounts
	data["StageOrder"] = advancedweb.StageOrder
	data["StageDisplayNames"] = advancedweb.StageDisplayNames

	// Heavy-result memory mitigation: a 200+ MB Result blob leaves
	// hundreds of MB of arena-allocated byte slices and the unmarshalled
	// struct graph mapped into RSS. Go's runtime won't return that to
	// the OS without explicit help — we end up with sticky 1+ GB RSS
	// hours after the request completed. Only triggered for outsized
	// results (cheap len(...) check) so normal render paths pay nothing.
	wasHuge := len(scan.Result) > 50*1024*1024
	h.renderResults(w, r, "advancedweb_results_inner", data)
	if wasHuge {
		// Release struct graph + intermediate slices before GC.
		result = advancedweb.ScanResult{}
		stageData = nil
		stageMeta = nil
		runtime.GC()
		debug.FreeOSMemory()
	}
}

// techHasVersion reports whether a Tech Detection row carries at least one
// version-bearing technology — i.e. the rows that actually feed CVE Matcher.
// Used to sort those rows to the front so the display row cap never hides a
// host that CVE Matcher flagged.
func techHasVersion(t techdetect.TargetResult) bool {
	for _, tech := range t.Technologies {
		if tech.Version != "" {
			return true
		}
	}
	return false
}

// truncatePreview returns the first n bytes of s plus a "[…truncated]"
// marker when s is longer than n. The marker lets the operator know
// they're looking at a preview, not the full payload — full data is
// always one click away on the standalone module page. Returns the
// original string when it already fits within the budget.
func truncatePreview(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n] + "\n\n[… truncated in suite view — open the standalone module page for the full payload]"
}
