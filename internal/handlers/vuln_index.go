package handlers

import (
	"crypto/sha1"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"sort"
	"strings"
	"sync"
	"time"

	"scanner/internal/database"
	"scanner/internal/models"
)

// vulnID is the stable, deterministic identifier for a vulnerability, derived
// from its identity tuple (module | normalized host | title). It is identical
// wherever the same finding surfaces — the global Vulnerabilities page and the
// per-asset findings on /assets/<host> — so a report ID cross-references
// cleanly. Not persisted; recomputed on every index build (stable because the
// inputs are stable). Caveat: a tool renaming a title forks the ID.
func vulnID(module, host, title string) string {
	sum := sha1.Sum([]byte(module + "|" + normalizeAsset(host) + "|" + strings.TrimSpace(title)))
	return "SCN-" + strings.ToUpper(hex.EncodeToString(sum[:])[:6])
}

// finalizeVulnEnrichment fills the derivable report fields that need context
// beyond the raw finding object: the port/protocol (from an explicit port or
// the host URL scheme) and a CVE-database join (CVSS/description/remediation)
// when the finding carries a CVE but the module didn't inline that data.
func finalizeVulnEnrichment(h *Handler, v *GlobalVuln) {
	if v.Port == "" || v.Protocol == "" {
		port, proto := portProtoFromHost(v.Host)
		if v.Port == "" {
			v.Port = port
		}
		if v.Protocol == "" {
			v.Protocol = proto
		}
	}
	if v.Port != "" && v.Protocol == "" {
		v.Protocol = "tcp" // a known port with no explicit protocol is TCP (TLS/HTTP)
	}
	if h != nil && len(v.CVEs) > 0 && (v.CVSSScore == "" || v.Description == "" || v.Remediation == "") {
		if rec, ok := h.db.CVEByID(v.CVEs[0]); ok {
			if v.CVSSScore == "" && rec.CVSS > 0 {
				v.CVSSScore = fmt.Sprintf("%.1f", rec.CVSS)
			}
			if v.Description == "" {
				v.Description = capStr(rec.Description, vulnTextCap)
			}
			if v.Remediation == "" {
				v.Remediation = capStr(rec.Remediation, vulnTextCap)
			}
			if len(v.References) == 0 && rec.Reference != "" {
				v.References = []string{rec.Reference}
			}
		}
	}
}

// backfillVuln copies enrichment from a fresh sighting into an existing deduped
// vuln when the existing one is missing a field (first non-empty wins).
func backfillVuln(dst, src *GlobalVuln) {
	if len(dst.CVEs) == 0 {
		dst.CVEs = src.CVEs
	}
	set := func(d *string, s string) {
		if *d == "" && s != "" {
			*d = s
		}
	}
	set(&dst.Description, src.Description)
	set(&dst.CVSSScore, src.CVSSScore)
	set(&dst.CVSSVector, src.CVSSVector)
	set(&dst.Remediation, src.Remediation)
	set(&dst.Evidence, src.Evidence)
	set(&dst.RawRequest, src.RawRequest)
	set(&dst.RawResponse, src.RawResponse)
	set(&dst.Port, src.Port)
	set(&dst.Protocol, src.Protocol)
	set(&dst.Product, src.Product)
	set(&dst.Tool, src.Tool)
	set(&dst.CheckID, src.CheckID)
	if len(dst.CWEs) == 0 {
		dst.CWEs = src.CWEs
	}
	if len(dst.References) == 0 {
		dst.References = src.References
	}
}

// portProtoFromHost infers a port/protocol from a finding's host string: an
// explicit host:port, else the URL scheme (https→443/tcp, http→80/tcp).
func portProtoFromHost(host string) (port, proto string) {
	s := strings.TrimSpace(host)
	if s == "" {
		return "", ""
	}
	if strings.Contains(s, "://") {
		if u, err := url.Parse(s); err == nil {
			if u.Port() != "" {
				return u.Port(), "tcp"
			}
			switch strings.ToLower(u.Scheme) {
			case "https":
				return "443", "tcp"
			case "http":
				return "80", "tcp"
			}
		}
		return "", ""
	}
	// bare host[:port] — net.SplitHostPort rejects an unbracketed IPv6 literal
	// (multiple colons), so "2001:db8::1" won't have its last hextet misread as
	// a port, while "ex.com:8080" and "[::1]:443" still parse correctly.
	if host, port, err := net.SplitHostPort(s); err == nil && host != "" && port != "" {
		allNum := true
		for _, r := range port {
			if r < '0' || r > '9' {
				allNum = false
				break
			}
		}
		if allNum {
			return port, "tcp"
		}
	}
	return "", ""
}

// Vulnerabilities renders the workspace-wide vulnerabilities page: every
// severity-bearing finding across every asset, in one filterable table.
func (h *Handler) Vulnerabilities(w http.ResponseWriter, r *http.Request) {
	data := h.baseData(r, "Vulnerabilities - scaNNer", "vulnerabilities")
	ws := data["ActiveWorkspace"].(*models.Workspace)
	liteScans, _ := h.db.ListScansLite(ws.ID, "")
	allVulns, ready := h.getVulnIndex(ws.ID, liteScans)

	// Partition into active vs archived using the mutable per-vuln overlay
	// (vuln_overrides). Archiving is applied at render — not baked into the
	// cached index — so a rescan's archive decision reflects instantly without
	// an index rebuild.
	archivedMap := h.db.ArchivedVulnIDs(ws.ID)
	deletedSet := h.db.DeletedVulnIDs(ws.ID)
	rescanningSet := h.db.RescanningVulnIDs(ws.ID)
	vulns := make([]GlobalVuln, 0, len(allVulns))
	var archivedVulns []GlobalVuln
	for _, v := range allVulns {
		if deletedSet[v.ID] {
			continue // permanently deleted — hidden from active AND archive
		}
		v.Rescanning = rescanningSet[v.ID] // spin the rescan icon while in flight
		if reason, ok := archivedMap[v.ID]; ok {
			v.ArchiveReason = reason
			archivedVulns = append(archivedVulns, v)
		} else {
			vulns = append(vulns, v)
		}
	}
	tab := r.URL.Query().Get("tab")
	data["ActiveTab"] = tab // "archive" or "" (active)
	data["Vulns"] = vulns
	data["ArchivedVulns"] = archivedVulns
	data["ArchivedCount"] = len(archivedVulns)
	data["VulnReady"] = ready
	if n := r.URL.Query().Get("rescan"); n != "" && n != "0" {
		data["RescanNotice"] = n
		data["RescanSkipped"] = r.URL.Query().Get("skipped")
	}
	// Any running/pending scan → the page keeps auto-refreshing so findings the
	// index now extracts from partial results appear live (see vulnIndexFingerprint).
	hasRunning := false
	for _, s := range liteScans {
		if s.Status == models.ScanRunning || s.Status == models.ScanPending {
			hasRunning = true
			break
		}
	}
	data["HasRunning"] = hasRunning

	var crit, high, med, low int
	modSet := map[string]bool{}
	for _, v := range vulns {
		switch v.SevRank {
		case 4:
			crit++
		case 3:
			high++
		case 2:
			med++
		case 1:
			low++
		}
		modSet[v.Module] = true
	}
	mods := make([]string, 0, len(modSet))
	for m := range modSet {
		mods = append(mods, m)
	}
	sort.Strings(mods)
	data["VCrit"], data["VHigh"], data["VMed"], data["VLow"] = crit, high, med, low
	data["VulnModules"] = mods
	h.render(w, "layout", data)
}

// Workspace-wide vulnerability index (Task 4 part 2). The per-asset findings
// engine (target_findings.go) is host-scoped; for a single page that lists
// EVERY vulnerability across EVERY asset we build a background index instead —
// streaming each scan result once (bounded memory, like asset_search) and
// pulling severity-bearing findings out with a generic JSON walk that works for
// any module shape ({results:[{findings}]}, {matches}, top-level arrays, and
// advancedweb's nested per-stage results) without a per-module extractor.

// GlobalVuln is one deduped vulnerability row for the /vulnerabilities page.
// The base fields (Host/Severity/Title/Module/CVEs/Scan*) drive the table; the
// report fields below are best-effort enrichment pulled by extractVulnsGeneric
// from whatever the module's stored result happens to carry (bounded in size),
// and are consumed by the per-vulnerability export (vuln_report.go). ID is a
// deterministic hash of the vuln identity (see vulnID) — stable across index
// rebuilds and identical to the ID shown for the same finding on the asset
// detail page.
type GlobalVuln struct {
	ID       string
	Host     string
	Severity string
	SevRank  int
	Title    string
	Module   string
	// Tool is the SPECIFIC tool/stage that produced the finding — the underlying
	// detector, not the launch module. For a standalone scan it equals Module; for
	// the advancedweb suite it is the stage ("nuclei", "sslscan", "cvematch", …) so
	// the UI can say "nuclei via advancedweb" instead of just "advancedweb".
	Tool     string
	// CheckID is the specific check that produced the finding, when the tool has
	// one — for nuclei it's the template-id. A rescan uses it to re-run ONLY that
	// check (e.g. `nuclei -t <template-id>`) against the host, instead of the
	// whole module. Empty for tools without a per-finding selector (sslscan, …).
	CheckID  string
	CVEs     []string
	ScanID   string
	ScanURL  string
	Count    int

	// ArchiveReason is set only on rows served to the Archive tab (why the finding
	// was archived, e.g. "Rescan no longer detected this finding"). Empty on the
	// active list. Not part of the cached index — assigned at render.
	ArchiveReason string

	// Product is the software that the finding is about (e.g. "jQuery 3.2.1",
	// "Apache httpd 2.4.1") — populated when the finding carries a product/version
	// (CVE matches from tech-detection, nmap service products, etc.). Drives the
	// "Software" column on the Vulnerabilities page. Empty for findings that
	// aren't tied to a specific product (most nuclei/ssl/header findings).
	Product string

	// FirstSeen / LastSeen are folded across every scan that reported this
	// (deduped) vuln — earliest and latest scan time. Assigned at index
	// assembly from the scanRef timestamps (NOT stored in the per-scan cache),
	// mirroring how enrichment is applied. Zero when no timestamp was available.
	FirstSeen time.Time
	LastSeen  time.Time

	// Report-enrichment fields (best-effort; may be empty — the export's
	// knowledge base fills the gaps). Raw request/response are truncated to
	// keep the in-memory index bounded.
	Description string
	CVSSScore   string
	CVSSVector  string
	CWEs        []string
	Port        string
	Protocol    string
	Remediation string
	Evidence    string
	RawRequest  string
	RawResponse string
	References  []string
	// PoCCommand / PoCOutput carry a real reproducible command and its console
	// output (e.g. the sslscan module captures the exact nmap/sslscan/openssl
	// run that evidenced the finding). When present they drive a command+output
	// PoC in the report instead of a synthesized one.
	PoCCommand string
	PoCOutput  string

	// Rescanning is a render-only flag (not cached): true when this finding has
	// an in-flight rescan, so the UI spins its rescan icon until it resolves.
	Rescanning bool
}

// Size caps for the enrichment fields so the cached index stays bounded even
// with hundreds of findings carrying raw HTTP captures.
const (
	vulnRawCap  = 16 * 1024
	vulnTextCap = 4 * 1024
)

// vulnExtractVersion is part of each scan's per-scan cache fingerprint. Bump it
// whenever extractVulnsGeneric/enrichVuln/extractScanVulns changes what it pulls
// out, so persisted per-scan vuln caches from an older extractor are treated as
// stale and re-extracted on the next build.
const vulnExtractVersion = "v5"

type wsVulnIndex struct {
	fingerprint string
	vulns       []GlobalVuln
	ready       bool
	building    bool
}

var (
	vulnIndexMu    sync.Mutex
	vulnIndexCache = map[string]*wsVulnIndex{}
)

// getVulnIndex returns the workspace's vulnerability list, kicking off a
// background rebuild when the scan set changed. Returns whatever is ready now.
func (h *Handler) getVulnIndex(workspaceID string, liteScans []models.Scan) ([]GlobalVuln, bool) {
	fp := vulnIndexFingerprint(liteScans)
	vulnIndexMu.Lock()
	idx := vulnIndexCache[workspaceID]
	if idx == nil {
		idx = &wsVulnIndex{}
		vulnIndexCache[workspaceID] = idx
	}
	cur := idx.vulns
	ready := idx.ready && idx.fingerprint == fp
	needsBuild := idx.fingerprint != fp && !idx.building
	if needsBuild {
		idx.building = true
	}
	vulnIndexMu.Unlock()

	if !needsBuild {
		return cur, ready
	}

	// The in-memory cache is cold (process restart) or stale. Before the slow
	// multi-GB rebuild, try the PERSISTED index — if it was built from the same
	// scan set (fingerprint match), load it instantly. This is what stops the
	// "Building the vulnerability index…" banner appearing on every restart.
	if dbFp, dbData, ok := h.db.LoadVulnIndexCache(workspaceID); ok && dbFp == fp && dbData != "" {
		var vulns []GlobalVuln
		if json.Unmarshal([]byte(dbData), &vulns) == nil {
			vulnIndexMu.Lock()
			idx.vulns = vulns
			idx.fingerprint = fp
			idx.ready = true
			idx.building = false
			vulnIndexMu.Unlock()
			return vulns, true
		}
	}

	// Nothing usable persisted (first ever build, or scans changed) — rebuild
	// in the background and serve the stale set meanwhile. Each ref carries the
	// scan's per-scan fingerprint (computed here from the already-loaded lite
	// scan, NO result-blob read) so the build can reuse the per-scan vuln cache
	// and only re-walk a scan whose result actually changed.
	refs := make([]scanRef, 0, len(liteScans))
	for _, s := range liteScans {
		// Include RUNNING/PENDING scans so their incrementally-flushed partial
		// results surface on the Vulnerabilities page live (not only at
		// completion). vulnIndexFingerprint folds running progress so the index
		// actually rebuilds as findings arrive.
		switch s.Status {
		case models.ScanDone, models.ScanCancelled, models.ScanPaused, models.ScanRunning, models.ScanPending:
			refs = append(refs, scanRef{
				ID: s.ID, Module: s.Module, Fingerprint: scanVulnFingerprint(s),
				CreatedAt: s.CreatedAt, FinishedAt: s.FinishedAt,
			})
		}
	}
	go h.buildVulnIndex(workspaceID, fp, refs)
	return cur, ready
}

// scanRef is one scan's identity for the index build: its ID, module, and the
// per-scan cache fingerprint (see scanVulnFingerprint).
type scanRef struct {
	ID          string
	Module      string
	Fingerprint string
	CreatedAt   time.Time
	FinishedAt  *time.Time
}

// seenAt is the timestamp folded into FirstSeen/LastSeen: the scan's finish
// time if it finished, else its creation time (a running scan is "seen now-ish").
func (r scanRef) seenAt() time.Time {
	if r.FinishedAt != nil {
		return *r.FinishedAt
	}
	return r.CreatedAt
}

// vulnIndexFingerprint changes as running scans emit findings (folds their
// ProgressDone), so the Vulnerabilities index rebuilds live — mirrors
// assetSearchFingerprint. searchFingerprint (finished-only) never moved
// mid-scan, which is why vulns previously appeared only on completion.
func vulnIndexFingerprint(scans []models.Scan) string {
	var maxFin int64
	running := 0
	for _, s := range scans {
		if s.FinishedAt != nil && s.FinishedAt.Unix() > maxFin {
			maxFin = s.FinishedAt.Unix()
		}
		if s.Status == models.ScanRunning || s.Status == models.ScanPending {
			running += s.ProgressDone
		}
	}
	// vulnExtractVersion is folded in so bumping the extractor invalidates the
	// workspace-level persisted index too (LoadVulnIndexCache is keyed on this
	// fingerprint) — otherwise a stale whole-workspace index built by an older
	// extractor would keep being served even though every per-scan cache re-walks.
	return fmt.Sprintf("%d:%d:%d:%s", len(scans), maxFin, running, vulnExtractVersion)
}

// scanVulnFingerprint identifies a scan's extractable state cheaply, from a
// BLOB-free lite scan row: status + finished-at + the denormalized severity
// count (kept in sync with the result on every write) + the extractor version.
// It changes exactly when the scan's result changes or the extractor is revised,
// so a matching fingerprint means the per-scan vuln cache is still valid.
func scanVulnFingerprint(s models.Scan) string {
	fin := int64(0)
	if s.FinishedAt != nil {
		fin = s.FinishedAt.Unix()
	}
	// For running/pending scans fold ProgressDone so re-extraction isn't gated
	// solely on severity_count (a new LOW/INFO finding doesn't move the crit+high
	// +med count, but ProgressDone advances) — catches those live too.
	prog := 0
	if s.Status == models.ScanRunning || s.Status == models.ScanPending {
		prog = s.ProgressDone
	}
	return fmt.Sprintf("%s:%d:%d:%d:%s", s.Status, fin, s.SeverityCount, prog, vulnExtractVersion)
}

func (h *Handler) buildVulnIndex(workspaceID, fp string, refs []scanRef) {
	agg := map[string]*GlobalVuln{}
	order := []string{}
	for _, ref := range refs {
		seen := ref.seenAt() // for FirstSeen/LastSeen folding (assembly-time, not cached)
		// scanVulns serves this scan's vulns from the per-scan cache when the
		// fingerprint matches — walking the (possibly hundreds-of-MB) result blob
		// at most once ever, not on every rebuild.
		for _, v := range h.scanVulns(ref) {
			// finalizeVulnEnrichment (CVE-DB join + port/proto) runs here at
			// ASSEMBLY, not in the cached extraction, so a CVE-DB refresh is
			// always reflected and the per-scan cache stays CVE-DB-independent.
			finalizeVulnEnrichment(h, &v)
			// Dedup key MUST use the same normalized host the ID hashes, or two
			// rows differing only by scheme/port (http:// vs https://ex.com)
			// would stay separate yet share one SCN ID — making single-export
			// by id ambiguous. Merging them into one row keeps IDs unique.
			key := ref.Module + "|" + normalizeAsset(v.Host) + "|" + v.Title
			if e := agg[key]; e != nil {
				e.Count++
				backfillVuln(e, &v)
				if !seen.IsZero() {
					if e.FirstSeen.IsZero() || seen.Before(e.FirstSeen) {
						e.FirstSeen = seen
					}
					if seen.After(e.LastSeen) {
						e.LastSeen = seen
					}
				}
				continue
			}
			v.Count = 1
			v.FirstSeen, v.LastSeen = seen, seen
			vv := v
			agg[key] = &vv
			order = append(order, key)
		}
	}
	out := make([]GlobalVuln, 0, len(order))
	for _, k := range order {
		out = append(out, *agg[k])
	}
	// Severity desc, then host.
	sort.SliceStable(out, func(i, j int) bool {
		if out[i].SevRank != out[j].SevRank {
			return out[i].SevRank > out[j].SevRank
		}
		return out[i].Host < out[j].Host
	})

	vulnIndexMu.Lock()
	idx := vulnIndexCache[workspaceID]
	if idx == nil {
		idx = &wsVulnIndex{}
		vulnIndexCache[workspaceID] = idx
	}
	idx.vulns = out
	idx.fingerprint = fp
	idx.ready = true
	idx.building = false
	vulnIndexMu.Unlock()

	// Persist so the next process restart reloads it instantly instead of
	// re-streaming every scan result (see getVulnIndex).
	if data, err := json.Marshal(out); err == nil {
		_ = h.db.SaveVulnIndexCache(workspaceID, fp, string(data))
	}
}

// scanVulns returns one scan's extracted vulnerabilities, from the per-scan
// cache when its fingerprint still matches (cheap — no result-blob read), else
// by loading the scan and walking its result ONCE and caching the outcome.
func (h *Handler) scanVulns(ref scanRef) []GlobalVuln {
	if cfp, cdata, ok := h.db.LoadScanVulnCache(ref.ID); ok && cfp == ref.Fingerprint {
		var vulns []GlobalVuln
		if json.Unmarshal([]byte(cdata), &vulns) == nil {
			return vulns
		}
	}
	scan, err := h.db.GetScan(ref.ID)
	if err != nil || scan == nil || scan.Result == "" {
		return nil
	}
	vulns := extractScanVulns(scan.Result, ref.Module, ref.ID)
	scan.Result = "" // release the (possibly huge) blob promptly
	// Persist the per-scan cache only for FINISHED scans. A running scan's
	// fingerprint moves on every 2s flush, so caching it would never hit and
	// would churn the DB; running scans re-extract each rebuild (bounded by the
	// page poll) to stay live.
	if ref.FinishedAt != nil {
		if data, err := json.Marshal(vulns); err == nil {
			_ = h.db.SaveScanVulnCache(ref.ID, ref.Fingerprint, string(data))
		}
	}
	return vulns
}

// VulnCountPair reports a scan's RAW severity-bearing findings vs the DEDUPED
// count (distinct asset+title) that the Vulnerabilities page shows. The two
// differ because the index collapses the same finding seen on the same asset
// (e.g. across ports) into one row — this pair lets the results header say
// "N findings · M unique" so the count difference isn't confusing. Sevs carries
// the same split per severity (Critical→Low) so the header can reconcile the
// exact per-severity badge the user is looking at, e.g. "High 27 → 21".
type VulnCountPair struct {
	Raw, Unique int
	Sevs        []SevCount
}

// SevCount is one severity's raw vs deduped finding count for a scan.
type SevCount struct {
	Label  string // "Critical" / "High" / "Medium" / "Low"
	Raw    int
	Unique int
}

// Differs reports whether dedup changed this severity's count (raw != unique),
// so the template can highlight only the severities that actually collapse.
func (s SevCount) Differs() bool { return s.Raw != s.Unique }

// scanVulnCountsFrom returns (raw, unique) finding counts for a scan from its
// per-scan vuln cache, both in total and split per severity. Zero when the
// cache isn't built yet (non-vuln scans, or the index hasn't been warmed) — the
// results header then shows nothing. Standalone (not a Handler method) so the
// template FuncMap, built before the Handler exists in New(), can close over
// the *database.DB directly.
func scanVulnCountsFrom(db *database.DB, scanID string) VulnCountPair {
	_, data, ok := db.LoadScanVulnCache(scanID)
	if !ok {
		return VulnCountPair{}
	}
	var vulns []GlobalVuln
	if json.Unmarshal([]byte(data), &vulns) != nil {
		return VulnCountPair{}
	}
	ids := make(map[string]struct{}, len(vulns))
	// Per-severity raw counts + distinct-ID sets, keyed by SevRank (4=crit..1=low).
	rawBySev := map[int]int{}
	idsBySev := map[int]map[string]struct{}{}
	for _, v := range vulns {
		ids[v.ID] = struct{}{}
		rawBySev[v.SevRank]++
		if idsBySev[v.SevRank] == nil {
			idsBySev[v.SevRank] = map[string]struct{}{}
		}
		idsBySev[v.SevRank][v.ID] = struct{}{}
	}
	var sevs []SevCount
	for _, s := range []struct {
		rank  int
		label string
	}{{4, "Critical"}, {3, "High"}, {2, "Medium"}, {1, "Low"}} {
		if rawBySev[s.rank] == 0 {
			continue
		}
		sevs = append(sevs, SevCount{Label: s.label, Raw: rawBySev[s.rank], Unique: len(idsBySev[s.rank])})
	}
	return VulnCountPair{Raw: len(vulns), Unique: len(ids), Sevs: sevs}
}

// extractScanVulns walks a single scan's result and returns its severity-bearing
// findings with the scan-identity fields (Module/ScanID/ScanURL/ID) set. It does
// NOT run finalizeVulnEnrichment — the CVE-DB join is applied at assembly so the
// cached output stays independent of CVE-database state.
func extractScanVulns(result, module, scanID string) []GlobalVuln {
	scanURL := "/modules/" + module + "/results/" + scanID
	// The advancedweb suite nests each tool's output under stages.<name>.result.
	// Extract PER STAGE so every finding carries the specific tool that produced it
	// ("nuclei", "sslscan", "cvematch"…) instead of the generic "advancedweb". The
	// scan-identity (Module/ScanID/ScanURL/ID) still points at the advancedweb scan.
	if module == "advancedweb" {
		var suite struct {
			Stages map[string]struct {
				Result json.RawMessage `json:"result"`
			} `json:"stages"`
		}
		if json.Unmarshal([]byte(result), &suite) == nil && len(suite.Stages) > 0 {
			var out []GlobalVuln
			for stage, st := range suite.Stages {
				if len(st.Result) == 0 {
					continue
				}
				for _, v := range extractVulnsGeneric(st.Result, vulnInherit{}) {
					if v.Title == "" || v.SevRank < 1 {
						continue
					}
					v.Module = module
					v.Tool = stage
					v.ScanID = scanID
					v.ScanURL = scanURL
					v.ID = vulnID(module, v.Host, v.Title)
					out = append(out, v)
				}
			}
			return out
		}
	}
	var out []GlobalVuln
	for _, v := range extractVulnsGeneric(json.RawMessage(result), vulnInherit{}) {
		if v.Title == "" || v.SevRank < 1 { // skip info/recon (SevRank 0/-1)
			continue
		}
		v.Module = module
		v.Tool = module
		v.ScanID = scanID
		v.ScanURL = scanURL
		v.ID = vulnID(module, v.Host, v.Title)
		out = append(out, v)
	}
	return out
}

// warmScanVulnCache extracts and caches a just-finished scan's vulns off the
// request path (called from FinishScan) so the /vulnerabilities build never has
// to walk this scan's result blob on the page load. Best-effort; a miss just
// means the next index build extracts it lazily.
func (h *Handler) warmScanVulnCache(scanID string) {
	scan, err := h.db.GetScan(scanID)
	if err != nil || scan == nil || scan.Result == "" {
		return
	}
	switch scan.Status {
	case models.ScanDone, models.ScanCancelled, models.ScanPaused:
	default:
		return // running/pending/error: nothing stable to cache
	}
	fp := scanVulnFingerprint(*scan)
	if cfp, _, ok := h.db.LoadScanVulnCache(scanID); ok && cfp == fp {
		return // already warm
	}
	vulns := extractScanVulns(scan.Result, scan.Module, scanID)
	if data, err := json.Marshal(vulns); err == nil {
		_ = h.db.SaveScanVulnCache(scanID, fp, string(data))
	}
}

// invalidateWorkspaceIndexes drops a workspace's derived caches (vulnerability
// index + asset search index), in memory and on disk, so data derived from a
// just-deleted scan disappears immediately instead of lingering until the next
// fingerprint-triggered rebuild.
func (h *Handler) invalidateWorkspaceIndexes(workspaceID string) {
	vulnIndexMu.Lock()
	delete(vulnIndexCache, workspaceID)
	vulnIndexMu.Unlock()
	_ = h.db.DeleteVulnIndexCache(workspaceID)

	assetSearchMu.Lock()
	delete(assetSearchCache, workspaceID)
	assetSearchMu.Unlock()
}

// sevRankOf maps a severity string to the engine's rank (4=crit … 1=low).
func sevRankOf(sev string) int {
	switch strings.ToUpper(strings.TrimSpace(sev)) {
	case "CRITICAL":
		return 4
	case "HIGH":
		return 3
	case "MEDIUM":
		return 2
	case "LOW":
		return 1
	case "INFO", "INFORMATIONAL", "UNKNOWN", "NONE":
		return 0
	}
	return 0
}

// vulnInherit carries context down the recursion so a finding nested inside a
// parent (e.g. nuclei's "info" object, whose request/response/matched-at live
// on the enclosing object) still resolves its host and PoC bytes.
type vulnInherit struct {
	Host       string
	Req        string
	Resp       string
	Port       string // e.g. sslscan nests findings under a host object carrying the port
	TLSPresent bool   // enclosing host record's has_tls — used to drop contradictory findings
}

// boolField reads a boolean value by key, reporting whether it was present.
func boolField(obj map[string]json.RawMessage, key string) (val, ok bool) {
	rv, present := obj[key]
	if !present {
		return false, false
	}
	var b bool
	if json.Unmarshal(rv, &b) == nil {
		return b, true
	}
	return false, false
}

// extractVulnsGeneric recursively walks a module result and pulls out every
// object that looks like a severity-bearing finding: it has a non-empty
// "severity" and a title/name. The host is the nearest enclosing url/host/
// matched_at/target; request/response bytes are likewise inherited from the
// nearest enclosing object. Besides the base identity it best-effort enriches
// each finding with description/cvss/cwe/evidence/remediation/references/port
// for the per-vuln export. Works for {results:[{url,findings:[…]}]},
// {matches:[…]}, top-level arrays (sslscan), and advancedweb's nested stages.
func extractVulnsGeneric(raw json.RawMessage, inh vulnInherit) []GlobalVuln {
	var out []GlobalVuln
	// Try object first.
	var obj map[string]json.RawMessage
	if json.Unmarshal(raw, &obj) == nil && obj != nil {
		host := inh.Host
		// url/host/matched_at/target are the canonical, most-specific host keys
		// (checked first, first match wins); ip/ip_address/hostname are fallbacks
		// so a finding that only carries an IP still gets an asset (fixes the
		// "empty Asset" rows — e.g. cvematch findings whose source had no URL).
		for _, k := range []string{"url", "host", "matched_at", "target", "ip", "ip_address", "hostname"} {
			if rv, ok := obj[k]; ok {
				var s string
				if json.Unmarshal(rv, &s) == nil && s != "" {
					host = s
					break
				}
			}
		}
		// Refine inherited PoC bytes from this object if present.
		req := inh.Req
		if s := jsonStr(obj, "request", "http_request", "raw_request", "curl_command", "curl-command"); s != "" {
			req = s
		}
		resp := inh.Resp
		if s := jsonStr(obj, "response", "http_response", "raw_response"); s != "" {
			resp = s
		}
		port := inh.Port
		if s := jsonNumStr(obj, "port"); s != "" {
			port = s
		}
		// Inherit whether the enclosing host record proved TLS is present
		// (sslscan's has_tls) so a nested finding can be sanity-checked below.
		tlsPresent := inh.TLSPresent
		if b, ok := boolField(obj, "has_tls"); ok {
			tlsPresent = b
		}
		childInh := vulnInherit{Host: host, Req: req, Resp: resp, Port: port, TLSPresent: tlsPresent}

		// Is THIS object a finding?
		var sev string
		if rv, ok := obj["severity"]; ok {
			_ = json.Unmarshal(rv, &sev)
		}
		if r := sevRankOf(sev); sev != "" && r >= 1 {
			title := jsonStr(obj, "title", "name", "template_id")
			var cves []string
			if rv, ok := obj["cves"]; ok {
				_ = json.Unmarshal(rv, &cves)
			}
			if len(cves) == 0 {
				if c := jsonStr(obj, "cve"); c != "" {
					cves = []string{c}
				}
			}
			cves = validCVEs(cves) // drop placeholders like "N/A", "None"
			if title == "" && len(cves) > 0 {
				title = cves[0]
			}
			// Suppress the sslscan "No Modern TLS" HIGH finding when the same
			// host record proves TLS is present (has_tls=true) — a self-
			// contradiction from probing an SNI-routed server by IP (see the
			// sslscan module fix). Retroactively cleans stored pre-fix results
			// so re-scanning isn't required to drop the false positive.
			contradiction := tlsPresent && title == "No Modern TLS"
			// Asset-less manual CVE-Matcher lookups (a product/version typed into
			// the CVE Matcher WITHOUT a target host) aren't findings against a
			// scanned asset — they're "does this product/version have any CVEs"
			// queries. The Vulnerabilities page is asset-oriented, so drop them here
			// (they still appear on the CVE Matcher scan's own results page). The
			// guard is precise: source=="manual" is emitted only by cvematch, and
			// host=="" means no target was supplied.
			manualLookup := host == "" && jsonStr(obj, "source") == "manual"
			if title != "" && !contradiction && !manualLookup {
				gv := GlobalVuln{Host: host, Severity: strings.ToUpper(sev), SevRank: r, Title: title, CVEs: cves}
				// The specific check that fired (nuclei template-id), so a rescan can
				// re-run only it. matcher-name refines a multi-matcher template but the
				// base template-id is what `nuclei -t` selects on.
				gv.CheckID = jsonStr(obj, "template-id", "template_id", "templateID", "template")
				enrichVuln(&gv, obj, req, resp, port)
				// Software that the finding is about: "<product> <version>". Only
				// set when a real product key is present (so a bare "version" on a
				// TLS/header finding doesn't leak in). Drives the Software column.
				if prod := jsonStr(obj, "product", "software"); prod != "" {
					if ver := jsonStr(obj, "version"); ver != "" {
						prod = prod + " " + ver
					}
					gv.Product = prod
				}
				out = append(out, gv)
			}
		}
		// Recurse into children with the refined context.
		for _, rv := range obj {
			out = append(out, extractVulnsGeneric(rv, childInh)...)
		}
		return out
	}
	// Array.
	var arr []json.RawMessage
	if json.Unmarshal(raw, &arr) == nil {
		for _, el := range arr {
			out = append(out, extractVulnsGeneric(el, inh)...)
		}
	}
	return out
}

// enrichVuln best-effort fills the report fields of gv from the finding object
// (and inherited PoC bytes). Every field is optional — the export KB fills any
// gaps. Bounded by vulnRawCap/vulnTextCap so the cached index stays small.
func enrichVuln(gv *GlobalVuln, obj map[string]json.RawMessage, inhReq, inhResp, inhPort string) {
	gv.Description = capStr(jsonStr(obj, "description", "desc"), vulnTextCap)
	gv.Remediation = capStr(jsonStr(obj, "remediation", "solution", "fix", "recommendation"), vulnTextCap)
	gv.Evidence = capStr(jsonStr(obj, "evidence", "proof", "extracted_results", "extracted-results", "detail", "matcher_name"), vulnTextCap)
	gv.CVSSScore = jsonNumStr(obj, "cvss", "cvss_score", "cvss-score", "cvssScore", "score", "cvss_base_score")
	gv.CVSSVector = jsonStr(obj, "cvss_vector", "cvss-vector", "vector", "cvss_metrics", "cvss-metrics")
	gv.CWEs = jsonStrArr(obj, "cwes", "cwe", "cwe_id", "cwe-id", "cwe_ids")
	gv.References = jsonStrArr(obj, "references", "reference", "refs")
	gv.Port = jsonNumStr(obj, "port")
	if gv.Port == "" {
		gv.Port = inhPort // e.g. sslscan: the port lives on the enclosing host object
	}
	gv.Protocol = jsonStr(obj, "protocol", "proto")

	req := jsonStr(obj, "request", "http_request", "raw_request", "curl_command", "curl-command")
	if req == "" {
		req = inhReq
	}
	resp := jsonStr(obj, "response", "http_response", "raw_response")
	if resp == "" {
		resp = inhResp
	}
	gv.RawRequest = capStr(req, vulnRawCap)
	gv.RawResponse = capStr(resp, vulnRawCap)

	// Real captured command + output (sslscan module) — drives a command-based
	// PoC showing the exact tool run and its console output.
	gv.PoCCommand = capStr(jsonStr(obj, "poc_command"), vulnTextCap)
	gv.PoCOutput = capStr(jsonStr(obj, "poc_output"), vulnRawCap)

	// nuclei-style nested classification block.
	if rv, ok := obj["classification"]; ok {
		var cl map[string]json.RawMessage
		if json.Unmarshal(rv, &cl) == nil && cl != nil {
			if gv.CVSSVector == "" {
				gv.CVSSVector = jsonStr(cl, "cvss-metrics", "cvss_metrics")
			}
			if gv.CVSSScore == "" {
				gv.CVSSScore = jsonNumStr(cl, "cvss-score", "cvss_score")
			}
			if len(gv.CWEs) == 0 {
				gv.CWEs = jsonStrArr(cl, "cwe-id", "cwe_id", "cwe")
			}
		}
	}
}

func jsonStr(obj map[string]json.RawMessage, keys ...string) string {
	for _, k := range keys {
		if rv, ok := obj[k]; ok {
			var s string
			if json.Unmarshal(rv, &s) == nil && s != "" {
				return s
			}
		}
	}
	return ""
}

// jsonStrArr returns the first key that unmarshals to a non-empty []string,
// or a single string wrapped in a slice.
func jsonStrArr(obj map[string]json.RawMessage, keys ...string) []string {
	for _, k := range keys {
		rv, ok := obj[k]
		if !ok {
			continue
		}
		var arr []string
		if json.Unmarshal(rv, &arr) == nil && len(arr) > 0 {
			return arr
		}
		var s string
		if json.Unmarshal(rv, &s) == nil && s != "" {
			return []string{s}
		}
	}
	return nil
}

// jsonNumStr returns the first key whose value is a number (rendered without a
// trailing .0) or a non-empty numeric string. Used for CVSS scores which some
// modules emit as a float and others as a string.
func jsonNumStr(obj map[string]json.RawMessage, keys ...string) string {
	for _, k := range keys {
		rv, ok := obj[k]
		if !ok {
			continue
		}
		var f float64
		if json.Unmarshal(rv, &f) == nil && f > 0 {
			return strings.TrimSuffix(fmt.Sprintf("%.1f", f), ".0")
		}
		var s string
		if json.Unmarshal(rv, &s) == nil && s != "" {
			return s
		}
	}
	return ""
}

// validCVEs keeps only well-formed CVE identifiers, dropping module
// placeholders like "N/A", "None", "-" that some scanners (e.g. sslscan) put
// in their cves array so those never surface as a fake CVE in the report.
func validCVEs(in []string) []string {
	var out []string
	for _, c := range in {
		c = strings.TrimSpace(c)
		if len(c) >= 5 && strings.EqualFold(c[:4], "CVE-") {
			out = append(out, strings.ToUpper(c))
		}
	}
	return out
}

// capStr truncates s to at most max bytes (rune-safe-ish), appending an
// ellipsis marker when it had to cut, to keep the cached index bounded.
func capStr(s string, max int) string {
	if len(s) <= max {
		return s
	}
	return strings.ToValidUTF8(s[:max], "") + "…"
}
