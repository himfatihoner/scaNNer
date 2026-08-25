package handlers

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"

	"scanner/internal/models"
)

// retargetConfig clones a source scan's launch-config JSON, replacing whichever
// recognised target field it carries with `hosts` (preserving that field's JSON
// shape: a string array stays an array, a scalar string stays a newline-joined
// string). Returns ok=false when no known target field is present — the caller
// then SKIPS the rescan for that scan rather than risk archiving a finding whose
// module we couldn't faithfully re-run.
// suiteStages is every advancedweb stage's config toggle, in enable_<name> form.
var suiteStages = []string{"whois", "dnsenum", "httpxfind", "sslscan", "wafdetect",
	"techdetect", "cvematch", "wpscan", "nuclei", "dirspider", "httpmethods", "secheaders"}

// trimSuiteStages narrows an advancedweb rescan config to only the stage(s) that
// produced the finding(s) under verification (the vuln's Tool is the stage name),
// so re-checking one TLS finding replays sslscan alone instead of the whole
// aggressive suite (DNS enumeration + nuclei + …). cvematch additionally needs
// techdetect, which feeds it. dnsenum is never re-enabled: the rescan targets
// already-known hosts, so subdomain discovery is both pointless here and the main
// scan-blow-up risk. If provenance is unknown (no Tool on any finding) the full
// config is left intact — correctness over speed.
func trimSuiteStages(configJSON string, tools map[string]bool) string {
	need := map[string]bool{}
	for t := range tools {
		if t == "" {
			continue
		}
		need[t] = true
		if t == "cvematch" {
			need["techdetect"] = true // cvematch is fed by techdetect's product/version output
		}
	}
	if len(need) == 0 {
		return configJSON // unknown provenance — don't risk a false archive; verify fully
	}
	var m map[string]json.RawMessage
	if json.Unmarshal([]byte(configJSON), &m) != nil {
		return configJSON
	}
	changed := false
	for _, s := range suiteStages {
		key := "enable_" + s
		if _, ok := m[key]; !ok {
			continue
		}
		nv, _ := json.Marshal(need[s])
		m[key] = nv
		changed = true
	}
	if !changed {
		return configJSON
	}
	out, err := json.Marshal(m)
	if err != nil {
		return configJSON
	}
	return string(out)
}

// narrowRescanConfig scopes a rescan to the single check that produced the
// finding. advancedweb: keep only the finding's stage (trimSuiteStages) and, for
// a nuclei finding, only its template. Standalone nuclei: only that template.
// Other modules re-run as-is on the single host — already the minimal unit.
func narrowRescanConfig(cfg, module, tool, checkID string) string {
	if module == "advancedweb" {
		if tool != "" {
			cfg = trimSuiteStages(cfg, map[string]bool{tool: true})
		}
		if tool == "nuclei" && checkID != "" {
			cfg = setJSONStringSlice(cfg, "nuclei_template_ids", []string{checkID})
		}
		if tool == "sslscan" {
			// Force the SSL stage onto the full-evidence engine (openssl + the
			// nmap/sslscan/openssl transcripts the PoC references) — the suite's
			// bulk path skips them; a one-host rescan can afford them.
			cfg = setJSONBool(cfg, "sslscan_full_evidence", true)
		}
		return cfg
	}
	if module == "nuclei" && checkID != "" {
		cfg = setJSONStringSlice(cfg, "template_ids", []string{checkID})
	}
	return cfg
}

// setJSONStringSlice sets key=value on a JSON object string (best-effort; returns
// the input unchanged on any parse/marshal error).
func setJSONStringSlice(cfg, key string, value []string) string {
	nv, err := json.Marshal(value)
	if err != nil {
		return cfg
	}
	return setJSONRaw(cfg, key, nv)
}

// setJSONBool sets key=<bool> on a JSON object string (best-effort).
func setJSONBool(cfg, key string, value bool) string {
	nv, _ := json.Marshal(value)
	return setJSONRaw(cfg, key, nv)
}

func setJSONRaw(cfg, key string, raw json.RawMessage) string {
	var m map[string]json.RawMessage
	if json.Unmarshal([]byte(cfg), &m) != nil {
		return cfg
	}
	m[key] = raw
	out, err := json.Marshal(m)
	if err != nil {
		return cfg
	}
	return string(out)
}

func retargetConfig(configJSON string, hosts []string) (string, bool) {
	var m map[string]json.RawMessage
	if json.Unmarshal([]byte(configJSON), &m) != nil {
		return "", false
	}
	// Ordered by specificity; the first field found is the target list.
	for _, k := range []string{"urls", "targets", "manual_targets", "domains", "target"} {
		rv, ok := m[k]
		if !ok {
			continue
		}
		t := bytes.TrimSpace(rv)
		var nb []byte
		if len(t) > 0 && t[0] == '[' {
			nb, _ = json.Marshal(hosts) // []string field
		} else {
			nb, _ = json.Marshal(strings.Join(hosts, "\n")) // scalar (newline-separated) field
		}
		m[k] = nb
		// Keep the scalar/array target aliases in sync so the rescan scan (and
		// its results page) shows the retargeted host, not the original seed —
		// advancedweb scans Targets but displays the legacy scalar Target, which
		// would otherwise still read "example.com" while actually scanning one
		// discovered subdomain.
		if _, ok := m["target"]; ok && k != "target" {
			tv, _ := json.Marshal(hosts[0])
			m["target"] = tv
		}
		if _, ok := m["targets"]; ok && k != "targets" {
			tv, _ := json.Marshal(hosts)
			m["targets"] = tv
		}
		out, err := json.Marshal(m)
		if err != nil {
			return "", false
		}
		return string(out), true
	}
	return "", false
}

// VulnRescan re-verifies each selected vulnerability with the NARROWEST scope:
// one rescan per (source scan × asset), targeting that single host with only the
// check that produced the finding — never the whole module across every affected
// host. Selection: id=<SCN> (single) or ids=<SCN,SCN,…> (bulk checkbox). Each
// rescan clones the source config, narrows targets to the one host, trims an
// advancedweb suite to just the finding's stage(s), and records — via
// rescan_verify — which vuln_ids it checks so reconcileRescan archives the ones
// the fresh run no longer reports (see FinishScan).
func (h *Handler) VulnRescan(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Redirect(w, r, "/vulnerabilities", http.StatusSeeOther)
		return
	}
	ws := h.activeWorkspace(r)
	if ws == nil {
		http.Error(w, "no active workspace", http.StatusBadRequest)
		return
	}
	_ = r.ParseForm()
	idSet := map[string]bool{}
	if v := strings.TrimSpace(r.FormValue("id")); v != "" {
		idSet[v] = true
	}
	for _, v := range strings.Split(r.FormValue("ids"), ",") {
		if v = strings.TrimSpace(v); v != "" {
			idSet[v] = true
		}
	}
	if len(idSet) == 0 {
		http.Redirect(w, r, "/vulnerabilities", http.StatusSeeOther)
		return
	}

	liteScans, _ := h.db.ListScansLite(ws.ID, "")
	vulns, _ := h.getVulnIndex(ws.ID, liteScans)
	byID := map[string]GlobalVuln{}
	for _, v := range vulns {
		if idSet[v.ID] {
			byID[v.ID] = v
		}
	}

	// Group selected vulns by (source scan × asset × tool × specific check), so
	// each rescan verifies ONE finding with the narrowest possible scope: the
	// exact check that produced it, on its host — never the whole module across
	// every affected host. For nuclei that means `nuclei -t <template-id>` on the
	// one host; for an advancedweb suite finding, only its stage; for tools with
	// no per-finding selector (sslscan, cvematch) the single host + that tool.
	// Two findings sharing the exact same (host, tool, check) reuse one rescan.
	type grp struct {
		scanID  string
		host    string // original host/URL string (first seen) for retargeting
		tool    string // the detecting tool/stage (nuclei, sslscan, cvematch, …)
		checkID string // nuclei template-id (empty for tools without a selector)
		vulnIDs []string
	}
	groups := map[string]*grp{}
	order := []string{}
	for id := range idSet {
		v, ok := byID[id]
		if !ok || v.ScanID == "" || v.Host == "" {
			continue // gone from the index, or no asset to target
		}
		key := v.ScanID + "\x00" + normalizeAsset(v.Host) + "\x00" + v.Tool + "\x00" + v.CheckID
		g := groups[key]
		if g == nil {
			g = &grp{scanID: v.ScanID, host: v.Host, tool: v.Tool, checkID: v.CheckID}
			groups[key] = g
			order = append(order, key)
		}
		g.vulnIDs = append(g.vulnIDs, id)
	}

	launched, skipped := 0, 0
	for _, key := range order {
		g := groups[key]
		src, err := h.db.GetScan(g.scanID)
		if err != nil || src == nil {
			skipped++
			continue
		}
		// A rescan re-executes the source scan's module, so it must be gated by
		// the SAME per-(user,workspace,module) grant as running it — otherwise a
		// user could re-run a module they were never granted via the vuln list.
		if !h.canAccessScan(h.currentUser(r), src) {
			skipped++
			continue
		}
		newCfg, ok := retargetConfig(src.Config, []string{g.host})
		if !ok {
			skipped++ // module config has no recognised target field — don't fake-archive
			continue
		}
		newCfg = narrowRescanConfig(newCfg, src.Module, g.tool, g.checkID)
		ns, err := h.db.CreateScan(ws.ID, src.Module, newCfg, 1)
		if err != nil {
			skipped++
			continue
		}
		h.db.AddRescanVerify(ns.ID, g.vulnIDs)
		h.dispatchRestart(ns.ID, src.Module, newCfg)
		launched++
	}
	http.Redirect(w, r, fmt.Sprintf("/vulnerabilities?rescan=%d&skipped=%d", launched, skipped), http.StatusSeeOther)
}

// VulnArchiveToggle manually archives, restores, or permanently deletes
// vulnerabilities. POST with id=<SCN> (single) or ids=<SCN,…> (bulk) and
// action=archive|unarchive|delete. Drives the Archive tab's "Restore" +
// "Delete" buttons and the main list's manual "Archive". A deleted finding is
// hidden from both the active list and the Archive tab (see SetVulnDeleted).
func (h *Handler) VulnArchiveToggle(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Redirect(w, r, "/vulnerabilities", http.StatusSeeOther)
		return
	}
	ws := h.activeWorkspace(r)
	if ws == nil {
		http.Error(w, "no active workspace", http.StatusBadRequest)
		return
	}
	_ = r.ParseForm()
	var ids []string
	if v := strings.TrimSpace(r.FormValue("id")); v != "" {
		ids = append(ids, v)
	}
	for _, v := range strings.Split(r.FormValue("ids"), ",") {
		if v = strings.TrimSpace(v); v != "" {
			ids = append(ids, v)
		}
	}
	action := r.FormValue("action")
	dest := "/vulnerabilities"
	if r.FormValue("from") == "archive" {
		dest = "/vulnerabilities?tab=archive"
	}
	if action == "delete" {
		for _, id := range ids {
			h.db.SetVulnDeleted(id, ws.ID, true)
		}
		http.Redirect(w, r, dest, http.StatusSeeOther)
		return
	}
	archived := action != "unarchive"
	reason := ""
	if archived {
		reason = "Manually archived"
	}
	for _, id := range ids {
		h.db.SetVulnArchived(id, ws.ID, archived, reason)
	}
	http.Redirect(w, r, dest, http.StatusSeeOther)
}

// reconcileRescan runs from FinishScan for EVERY scan; it no-ops unless the scan
// is a rescan (has rescan_verify rows). For a cleanly-completed rescan it archives
// each verified vuln the fresh run no longer reports and (re-)activates those it
// still finds. On error/cancel it just drops the verify links WITHOUT archiving —
// a failed rescan is not evidence the finding is gone. On pause it leaves the
// links so the resumed run reconciles when it finally completes.
func (h *Handler) reconcileRescan(scanID string) {
	verifyIDs := h.db.RescanVerifyIDs(scanID)
	if len(verifyIDs) == 0 {
		return // normal scan
	}
	src, err := h.db.GetScan(scanID)
	if err != nil || src == nil {
		return
	}
	switch src.Status {
	case models.ScanDone:
		// proceed
	case models.ScanError, models.ScanCancelled:
		h.db.ClearRescanVerify(scanID) // give up; never archive on a failed rescan
		return
	default: // pending/running/paused — wait for a terminal completion
		return
	}

	found := map[string]bool{}
	for _, v := range extractScanVulns(src.Result, src.Module, scanID) {
		found[v.ID] = true
	}
	short := scanID
	if len(short) > 8 {
		short = short[:8]
	}
	for _, id := range verifyIDs {
		if found[id] {
			h.db.SetVulnArchived(id, src.WorkspaceID, false, "") // still present → keep active
		} else {
			h.db.SetVulnArchived(id, src.WorkspaceID, true,
				fmt.Sprintf("Rescan no longer detected this finding (scan %s)", short))
		}
	}
	h.db.ClearRescanVerify(scanID)
}
