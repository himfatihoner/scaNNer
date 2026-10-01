package handlers

import (
	"crypto/sha1"
	"encoding/hex"
	"net/http"
	"sort"
	"strings"
	"sync"

	"scanner/internal/models"
)

// The /info page lists INFO-severity findings (tech/version disclosures, benign
// exposures, panels, …) that the Vulnerabilities page deliberately drops. Unlike
// that page (one row per host+title), the info index DEDUPES by title — one row
// per distinct finding — and aggregates the hosts it was seen on, so clicking a
// row reveals which targets have it. It reuses the per-scan vuln cache (scanVulns)
// and the vuln index fingerprint; only the aggregation (by title, info-only)
// differs. See vuln_index.go for isInfoSev / scanRef / scanVulns.

// InfoFinding is one deduped info-severity finding across all of a workspace's
// scans, with the set of hosts it appeared on.
type InfoFinding struct {
	ID          string   // "INF-"+sha1(lower(title)) — stable key for /info/detail
	Title       string
	Severity    string   // always "INFO"
	Module      string   // representative source module
	Tool        string   // representative detecting tool/stage
	CheckID     string   // representative check (e.g. nuclei template-id)
	Count       int      // total sightings across hosts/scans
	Hosts       []string // distinct hosts (sorted)
	Description string
	References  []string
	CVEs        []string
}

type wsInfoIndex struct {
	findings    []InfoFinding
	fingerprint string
	ready       bool
	building    bool
}

var (
	infoIndexMu    sync.Mutex
	infoIndexCache = map[string]*wsInfoIndex{}
)

// infoID is the stable, title-derived id for a deduped info finding.
func infoID(title string) string {
	sum := sha1.Sum([]byte(strings.ToLower(strings.TrimSpace(title))))
	return "INF-" + hex.EncodeToString(sum[:])[:8]
}

// getInfoIndex returns the deduped info findings for a workspace, rebuilding in
// the background (serving the stale set meanwhile) when the scan set changed.
// In-memory only — the deduped index is small, and it re-derives from the shared
// per-scan cache so a cold start is cheap.
func (h *Handler) getInfoIndex(workspaceID string, liteScans []models.Scan) ([]InfoFinding, bool) {
	fp := vulnIndexFingerprint(liteScans) // same fingerprint as the vuln index
	infoIndexMu.Lock()
	idx := infoIndexCache[workspaceID]
	if idx == nil {
		idx = &wsInfoIndex{}
		infoIndexCache[workspaceID] = idx
	}
	cur := idx.findings
	ready := idx.ready && idx.fingerprint == fp
	needsBuild := idx.fingerprint != fp && !idx.building
	if needsBuild {
		idx.building = true
	}
	infoIndexMu.Unlock()
	if !needsBuild {
		return cur, ready
	}
	refs := make([]scanRef, 0, len(liteScans))
	for _, s := range liteScans {
		switch s.Status {
		case models.ScanDone, models.ScanCancelled, models.ScanPaused, models.ScanRunning, models.ScanPending:
			refs = append(refs, scanRef{
				ID: s.ID, Module: s.Module, Fingerprint: scanVulnFingerprint(s),
				CreatedAt: s.CreatedAt, FinishedAt: s.FinishedAt,
			})
		}
	}
	go h.buildInfoIndex(workspaceID, fp, refs)
	return cur, ready
}

// infoAggregator folds info findings (one per scan, streamed) into the deduped
// per-title set with aggregated hosts — kept as a reusable struct so the build
// stays memory-bounded (only the deduped data is held) and is unit-testable
// without a DB.
type infoAggregator struct {
	agg      map[string]*InfoFinding
	hostSeen map[string]map[string]bool
	order    []string
}

func newInfoAggregator() *infoAggregator {
	return &infoAggregator{agg: map[string]*InfoFinding{}, hostSeen: map[string]map[string]bool{}}
}

// add folds one finding in, keeping only genuine info-severity ones, deduped by
// title, accumulating distinct hosts and backfilling representative detail.
func (a *infoAggregator) add(v GlobalVuln) {
	if v.SevRank >= 1 || !isInfoSev(v.Severity) {
		return // only genuine info-severity findings
	}
	key := strings.ToLower(strings.TrimSpace(v.Title))
	if key == "" {
		return
	}
	e := a.agg[key]
	if e == nil {
		e = &InfoFinding{
			ID: infoID(v.Title), Title: v.Title, Severity: "INFO",
			Module: v.Module, Tool: v.Tool, CheckID: v.CheckID,
			Description: v.Description, References: v.References, CVEs: v.CVEs,
		}
		a.agg[key] = e
		a.hostSeen[key] = map[string]bool{}
		a.order = append(a.order, key)
	}
	e.Count++
	if host := normalizeAsset(v.Host); host != "" && !a.hostSeen[key][host] {
		a.hostSeen[key][host] = true
		e.Hosts = append(e.Hosts, host)
	}
	// Backfill representative detail from later sightings if the first was bare.
	if e.Description == "" && v.Description != "" {
		e.Description = v.Description
	}
	if len(e.References) == 0 && len(v.References) > 0 {
		e.References = v.References
	}
	if e.CheckID == "" && v.CheckID != "" {
		e.CheckID = v.CheckID
	}
	if len(e.CVEs) == 0 && len(v.CVEs) > 0 {
		e.CVEs = v.CVEs
	}
}

// result returns the deduped findings, hosts sorted, most-widespread first.
func (a *infoAggregator) result() []InfoFinding {
	out := make([]InfoFinding, 0, len(a.order))
	for _, k := range a.order {
		e := a.agg[k]
		sort.Strings(e.Hosts)
		out = append(out, *e)
	}
	sort.SliceStable(out, func(i, j int) bool {
		if len(out[i].Hosts) != len(out[j].Hosts) {
			return len(out[i].Hosts) > len(out[j].Hosts)
		}
		return out[i].Title < out[j].Title
	})
	return out
}

// buildInfoIndex streams each scan's cached findings (scanVulns — info included
// since vulnExtractVersion v7) through the aggregator and publishes the result.
func (h *Handler) buildInfoIndex(workspaceID, fp string, refs []scanRef) {
	ag := newInfoAggregator()
	for _, ref := range refs {
		for _, v := range h.scanVulns(ref) {
			ag.add(v)
		}
	}
	out := ag.result()

	infoIndexMu.Lock()
	idx := infoIndexCache[workspaceID]
	if idx == nil {
		idx = &wsInfoIndex{}
		infoIndexCache[workspaceID] = idx
	}
	idx.findings = out
	idx.fingerprint = fp
	idx.ready = true
	idx.building = false
	infoIndexMu.Unlock()
}

// Info renders the Info page: deduped info-severity findings, one row per title.
func (h *Handler) Info(w http.ResponseWriter, r *http.Request) {
	data := h.baseData(r, "Info - scaNNer", "info")
	ws := data["ActiveWorkspace"].(*models.Workspace)
	liteScans, _ := h.db.ListScansLite(ws.ID, "")
	findings, ready := h.getInfoIndex(ws.ID, liteScans)
	data["InfoFindings"] = findings
	data["InfoCount"] = len(findings)
	data["InfoReady"] = ready
	hasRunning := false
	for _, s := range liteScans {
		if s.Status == models.ScanRunning || s.Status == models.ScanPending {
			hasRunning = true
			break
		}
	}
	data["HasRunning"] = hasRunning
	h.render(w, "layout", data)
}

// InfoDetail serves one deduped finding's detail fragment (host list + details),
// lazy-loaded when a row is expanded. Mirrors VulnDetail.
func (h *Handler) InfoDetail(w http.ResponseWriter, r *http.Request) {
	ws := h.activeWorkspace(r)
	if ws == nil {
		http.NotFound(w, r)
		return
	}
	id := strings.TrimSpace(r.URL.Query().Get("id"))
	if id == "" {
		http.NotFound(w, r)
		return
	}
	liteScans, _ := h.db.ListScansLite(ws.ID, "")
	findings, _ := h.getInfoIndex(ws.ID, liteScans)
	for i := range findings {
		if findings[i].ID == id {
			h.renderLang(w, h.lang(r), "info_detail_inner", findings[i])
			return
		}
	}
	http.NotFound(w, r)
}
