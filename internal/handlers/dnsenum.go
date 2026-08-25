package handlers

import (
	"encoding/json"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"time"

	"scanner/internal/models"
	"scanner/internal/modules/dnsenum"
)

func (h *Handler) DNSEnumPage(w http.ResponseWriter, r *http.Request) {
	data := h.baseData(r, "DNS Enumerator - scaNNer", "dnsenum")
	ws := data["ActiveWorkspace"].(*models.Workspace)
	targets, _ := h.db.ListTargets(ws.ID, "domain")
	data["DomainTargets"] = targets
	scans, _ := h.db.ListScansLite(ws.ID, "dnsenum")
	data["Scans"] = scans
	h.render(w, "layout", data)
}

func (h *Handler) DNSEnumRun(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Redirect(w, r, "/modules/dnsenum", http.StatusSeeOther)
		return
	}
	ws := h.activeWorkspace(r)

	// Audit fix: manual_domains flowed straight into the scan config with
	// no hostname validation, so a line like "-o /tmp/foo" or
	// "evil.com\nrun; sh -c ..." could reach subprocess argv / recon-ng
	// resource files. Reuse validateTarget(FQDN) for parity with the
	// import handler, and reject any label that begins with '-' so a
	// domain cannot be interpreted as an argv flag by subfinder/amass/etc.
	acceptDomain := func(v string) bool {
		if !validateTarget(v, models.TargetFQDN) {
			return false
		}
		for _, label := range strings.Split(v, ".") {
			if label == "" || strings.HasPrefix(label, "-") || strings.HasSuffix(label, "-") {
				return false
			}
		}
		return true
	}
	var domains []string
	var rejected int
	if manual := strings.TrimSpace(r.FormValue("manual_domains")); manual != "" {
		for _, line := range strings.Split(manual, "\n") {
			line = strings.TrimSpace(line)
			if line == "" {
				continue
			}
			if !acceptDomain(line) {
				rejected++
				continue
			}
			domains = append(domains, line)
		}
	}
	if selected := r.Form["domains"]; len(selected) > 0 {
		for _, line := range selected {
			line = strings.TrimSpace(line)
			if line == "" {
				continue
			}
			if !acceptDomain(line) {
				rejected++
				continue
			}
			domains = append(domains, line)
		}
	}
	if len(domains) == 0 {
		reason := "no_domains"
		if rejected > 0 {
			reason = "invalid_domains"
		}
		http.Redirect(w, r, "/modules/dnsenum?error="+reason, http.StatusSeeOther)
		return
	}

	speed := dnsenum.Speed(r.FormValue("speed"))
	if speed != dnsenum.SpeedNormal && speed != dnsenum.SpeedDeep {
		speed = dnsenum.SpeedFast
	}

	// Pull external-source API keys from settings so VT / Shodan /
	// Censys can be queried alongside the built-in passive sources.
	// Keys are optional — empty values silently skip the source.
	settings := h.db.GetSettings()
	maxDepth := 0
	if v := strings.TrimSpace(r.FormValue("max_depth")); v != "" {
		if n, err := strconv.Atoi(v); err == nil && n > 0 {
			maxDepth = n
		}
	}
	// Audit fix: surface the three DNS-load knobs (resolve fan-out,
	// puredns rate-limit, PTR fan-out) so the operator can dial down
	// load on a fragile target resolver. All optional; 0 falls back to
	// the per-speed defaults inside the scanner.
	parseIntField := func(name string) int {
		if v := strings.TrimSpace(r.FormValue(name)); v != "" {
			if n, err := strconv.Atoi(v); err == nil && n > 0 {
				return n
			}
		}
		return 0
	}
	opts := dnsenum.Options{
		AXFR:               r.FormValue("axfr") == "on",
		ReverseDNS:         r.FormValue("reverse_dns") == "on",
		CrtSh:              r.FormValue("crtsh") == "on",
		ReverseCIDR:        strings.TrimSpace(r.FormValue("reverse_cidr")),
		MaxDepth:           maxDepth,
		VirusTotalKey:      settings.VirusTotalAPIKey,
		ShodanKey:          settings.ShodanAPIKey,
		CensysID:           settings.CensysID,
		CensysSecret:       settings.CensysSecret,
		ResolveConcurrency: parseIntField("resolve_concurrency"),
		BruteRateLimit:     parseIntField("brute_rate_limit"),
		PTRConcurrency:     parseIntField("ptr_concurrency"),
		WordlistPath:       strings.TrimSpace(r.FormValue("wordlist_path")),
	}

	cfgJSON, _ := json.Marshal(map[string]interface{}{
		"domains": domains, "speed": speed,
		"axfr": opts.AXFR, "reverse_dns": opts.ReverseDNS, "crtsh": opts.CrtSh, "reverse_cidr": opts.ReverseCIDR,
		"max_depth":           maxDepth,
		"resolve_concurrency": opts.ResolveConcurrency,
		"brute_rate_limit":    opts.BruteRateLimit,
		"ptr_concurrency":     opts.PTRConcurrency,
		"wordlist_path":       opts.WordlistPath,
	})
	// Audit fix: inflate total by dnsenum.PhaseCount so the progress bar
	// advances within a domain (passive/brute/NS-brute/permutation/resolve
	// each report a sub-step). Without this, a single-domain scan sat at
	// 0/1 for the entire run and looked indistinguishable from a hang.
	scan, err := h.db.CreateScan(ws.ID, "dnsenum", string(cfgJSON), len(domains)*dnsenum.PhaseCount)
	if err != nil {
		http.Redirect(w, r, "/modules/dnsenum?error=db_error", http.StatusSeeOther)
		return
	}

	if h.queueIfSequential(w, r, scan) {
		return
	}
	go h.runDNSEnum(scan.ID, domains, speed, opts)
	http.Redirect(w, r, "/modules/dnsenum/results/"+scan.ID, http.StatusSeeOther)
}

func (h *Handler) DNSEnumResults(w http.ResponseWriter, r *http.Request) {
	scanID := strings.TrimPrefix(r.URL.Path, "/modules/dnsenum/results/")
	if scanID == "" {
		http.Redirect(w, r, "/modules/dnsenum", http.StatusSeeOther)
		return
	}
	scan, err := h.db.GetScan(scanID)
	if err != nil {
		http.NotFound(w, r)
		return
	}

	data := h.baseData(r, "DNS Enum Results - scaNNer", "dnsenum_results")
	var result dnsenum.ScanResult
	// Audit fix: previously the unmarshal error was swallowed. If the
	// scan.Result blob is corrupt / truncated (50MB soft-cap, schema
	// drift, etc.) the page rendered "No results" with no indication.
	// Surface the parse error via ParseError so the template can render
	// a banner.
	if strings.TrimSpace(scan.Result) != "" {
		if err := json.Unmarshal([]byte(scan.Result), &result); err != nil {
			data["ParseError"] = err.Error()
		}
	}

	totalSubs := 0
	for _, dr := range result.Results {
		totalSubs += dr.TotalFound
	}

	// Workspace target-lists so the import form can pick one.
	ws := h.activeWorkspace(r)
	lists, _ := h.db.ListTargetLists(ws.ID)
	data["TargetLists"] = lists

	data["Scan"] = scan
	data["Results"] = result.Results
	data["TotalSubs"] = totalSubs
	h.renderResults(w, r, "dnsenum_results_inner", data)
}

// DNSEnumImportTargets pushes discovered subdomains into the workspace's
// Targets, attached to a target-list of the user's choice (or a new one
// created inline). Filters honor "include wildcards" + "only resolved".
// Returns JSON {added, skipped, invalid, list_id, list_name} so the UI
// can render an inline confirmation without a full page reload.
func (h *Handler) DNSEnumImportTargets(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}
	scanID := strings.TrimPrefix(r.URL.Path, "/modules/dnsenum/import/")
	scan, err := h.db.GetScan(scanID)
	if err != nil {
		http.NotFound(w, r)
		return
	}
	if err := r.ParseForm(); err != nil {
		http.Error(w, "bad form", http.StatusBadRequest)
		return
	}
	ws := h.activeWorkspace(r)
	if scan.WorkspaceID != ws.ID {
		http.Error(w, "scan not in active workspace", http.StatusForbidden)
		return
	}

	includeWildcards := r.FormValue("include_wildcards") == "on"
	onlyResolved := r.FormValue("only_resolved") == "on"
	listID := h.resolveListID(r, ws.ID)

	// Pull the list name back for the response — useful for the inline
	// confirmation banner ("Added N subs to <ListName>").
	listName := "No list"
	if listID != "" {
		if tl, err := h.db.GetTargetList(listID); err == nil && tl != nil {
			listName = tl.Name
		}
	}

	var result dnsenum.ScanResult
	// Audit fix: previously swallowed. A corrupt scan.Result blob would
	// silently import 0 subdomains and the inline confirmation banner
	// would say "Added 0 targets" — operator has no idea the import
	// failed. Return 500 with an explanatory JSON body so the UI can
	// render the actual reason.
	if err := json.Unmarshal([]byte(scan.Result), &result); err != nil {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusInternalServerError)
		json.NewEncoder(w).Encode(map[string]interface{}{
			"error": "Could not parse scan result: " + err.Error(),
		})
		return
	}

	added, skipped, invalid := 0, 0, 0
	seen := map[string]bool{}
	for _, dr := range result.Results {
		for _, sub := range dr.Subdomains {
			name := strings.ToLower(strings.TrimSpace(sub.Subdomain))
			if name == "" || seen[name] {
				continue
			}
			seen[name] = true
			if !includeWildcards && sub.IsWild {
				skipped++
				continue
			}
			if onlyResolved && len(sub.IPs) == 0 {
				skipped++
				continue
			}
			// Validate as FQDN.
			if !validateTarget(name, models.TargetFQDN) {
				invalid++
				continue
			}
			if h.db.TargetExists(ws.ID, name) {
				skipped++
				continue
			}
			note := "From DNS Enum scan " + scanID[:8]
			if sub.Source != "" {
				note += " (" + sub.Source + ")"
			}
			if _, err := h.db.CreateTargetInList(ws.ID, name, models.TargetFQDN, note, listID); err != nil {
				skipped++
				continue
			}
			added++
		}
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{
		"added":     added,
		"skipped":   skipped,
		"invalid":   invalid,
		"list_id":   listID,
		"list_name": listName,
	})
}

func (h *Handler) DNSEnumStatus(w http.ResponseWriter, r *http.Request) {
	scanID := strings.TrimPrefix(r.URL.Path, "/modules/dnsenum/status/")
	scan, err := h.db.GetScan(scanID)
	if err != nil {
		http.NotFound(w, r)
		return
	}
	h.writeScanStatus(w, scan)
}

func (h *Handler) runDNSEnum(scanID string, domains []string, speed dnsenum.Speed, opts dnsenum.Options) {
	if !h.db.MarkRunning(scanID) {
		return
	}
	ctx := h.scanMgr.Register(scanID)
	defer h.FinishScan(scanID)

	// Periodic saver for live intermediate results
	var latestResult []byte
	var resultMu sync.Mutex
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
				resultMu.Lock()
				r := latestResult
				resultMu.Unlock()
				if r != nil {
					h.db.UpdateScanResult(scanID, string(r))
				}
			}
		}
	}()

	result := dnsenum.ScanWithOpts(ctx, domains, speed, opts,
		func(partial *dnsenum.ScanResult) {
			b, err := json.Marshal(partial)
			if err == nil {
				resultMu.Lock()
				latestResult = b
				resultMu.Unlock()
			}
		},
		func(done int, msg string) {
			h.db.UpdateScanProgress(scanID, done, msg)
		})


	resultJSON, _ := json.Marshal(result)
	h.db.UpdateScanResult(scanID, string(resultJSON))

	// Hard-failure surfacing: if every unit errored, mark the scan failed
	// with a translated reason rather than a silent "done" with zero findings.
	if ctx.Err() == nil {
		var errs []string
		for _, dr := range result.Results {
			if dr.Error != "" {
				errs = append(errs, dr.Error)
			}
		}
		h.markHardFailure(scanID, errs, len(domains))
		// Promote every discovered subdomain to a real workspace target (if it
		// isn't one already) so it shows up in Targets/Assets like a
		// manually-added target and can be scanned directly.
		h.addDiscoveredSubdomains(scanID, result)
	}
}

// ensureTargetList returns the id of the workspace list with the given name,
// creating it once if absent. Used to group DNS-discovered subdomains under a
// per-parent-domain category.
func (h *Handler) ensureTargetList(wsID, name string) string {
	name = strings.TrimSpace(name)
	if name == "" {
		return ""
	}
	if lists, err := h.db.ListTargetLists(wsID); err == nil {
		for _, l := range lists {
			if strings.EqualFold(l.Name, name) {
				return l.ID
			}
		}
	}
	if tl, err := h.db.CreateTargetList(wsID, name, "auto-created from DNS Enum discovery"); err == nil && tl != nil {
		return tl.ID
	}
	return ""
}

// addDiscoveredSubdomains inserts each subdomain DNS Enum found as a workspace
// target. Uses the upsert-safe CreateTargetMulti, so an already-present target
// is left untouched (keeps its categories) and only genuinely new subdomains
// are added. Grouped under a per-parent-domain category ("<domain> subdomains")
// so the discovered set is easy to find.
func (h *Handler) addDiscoveredSubdomains(scanID string, result *dnsenum.ScanResult) {
	scan, err := h.db.GetScan(scanID)
	if err != nil || scan == nil {
		return
	}
	wsID := scan.WorkspaceID
	seen := map[string]bool{}
	for _, dr := range result.Results {
		var listIDs []string
		if lid := h.ensureTargetList(wsID, dr.Domain+" subdomains"); lid != "" {
			listIDs = []string{lid}
		}
		for _, s := range dr.Subdomains {
			val := strings.ToLower(strings.TrimSpace(s.Subdomain))
			if val == "" || seen[val] {
				continue
			}
			seen[val] = true
			t := models.TargetFQDN
			if strings.Count(val, ".") < 2 {
				t = models.TargetDomain
			}
			h.db.CreateTargetMulti(wsID, val, t, "discovered via DNS Enum", listIDs)
		}
	}
}
