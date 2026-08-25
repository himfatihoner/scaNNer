package handlers

import (
	"encoding/json"
	"net/http"
	"net/url"
	"sort"
	"strings"
	"time"

	"golang.org/x/net/publicsuffix"

	"scanner/internal/models"
	"scanner/internal/modules/shared"
)

// AssetSummary is one row on the /assets page.
type AssetSummary struct {
	Value       string
	Type        string // ipv4 | domain | fqdn | url
	ScanCount   int
	RunningJobs int
	LastScanned time.Time
	InWorkspace bool
	Modules     []string // unique module names that scanned this asset
	// Search is a space-joined lowercase token blob (open ports, services,
	// technologies, WAF, server) built from the asset's scan results by the
	// background search index — so the /assets search box can match on
	// ports/services/tech, not just the hostname.
	Search string
	// PortSummary is a compact, numerically-sorted "80/tcp 443/tcp +N" list of
	// the asset's open ports for the assets-list column (Task 5). Built from the
	// same background index; full port/service detail is on the asset page.
	PortSummary string
	// Related lists the asset's resolution cross-references: for an IP, the
	// subdomains/hosts that resolve to it; for a hostname, its resolved IP(s).
	Related []string
	// Categories are the workspace target-list memberships of this asset (when
	// it is also a workspace target), so the assets page can offer the same
	// category filter as the targets page.
	Categories []models.TargetList
	// Technologies are the tech names techdetect fingerprinted on this host,
	// shown as chips in the assets-list row.
	Technologies []string
	// ResolvedIPs are the IP(s) this hostname resolves to (the IPv4 subset of
	// the resolution cross-reference). Empty for assets that are themselves IPs.
	ResolvedIPs []string
	// Live is true when an HTTP(S) probe actually answered for this asset;
	// LiveStatus carries the best status code seen (0 when unknown).
	Live       bool
	LiveStatus int
	// RedirectTo is the redirect target when the asset answered with a 3xx /
	// Location; empty otherwise.
	RedirectTo string
	// BaseDomain is the registrable domain (eTLD+1) of the asset — used both for
	// the row's data-basedomain attribute and to build the base-domain filter
	// chips. For IP assets it is the IP itself.
	BaseDomain string
	// Discovered is true when the asset was NOT an explicit scan target but was
	// discovered from a scan's results (a dnsenum subdomain, an httpxfind live
	// service, a resolved IP, …) and promoted to a first-class asset.
	Discovered bool
}

// baseDomain returns the registrable domain (eTLD+1) of a host via the public
// suffix list, e.g. "foo.bar.example.co.uk" -> "example.co.uk". IP addresses
// have no eTLD+1, so they return themselves; on any lookup error the host is
// returned unchanged.
func baseDomain(host string) string {
	host = strings.TrimSpace(host)
	if host == "" {
		return ""
	}
	if classifyAsset(host) == "ipv4" {
		return host
	}
	if bd, err := publicsuffix.EffectiveTLDPlusOne(host); err == nil && bd != "" {
		return bd
	}
	return host
}

// AssetScanGroup groups scans on the detail page by module.
type AssetScanGroup struct {
	Module      string
	DisplayName string
	Scans       []models.Scan
}

// extractAssetsFromConfig pulls the list of targets/urls/domains out of a
// scan's config JSON. All scanner modules store their subject list in one of
// the fields below — see handlers/*.go where `cfgJSON` is marshalled.
//
// Returned values are the raw user-supplied strings; CIDR blocks and ranges
// are kept intact. Use extractAssetsExpanded when you need the per-IP list
// that the scan actually walked.
func extractAssetsFromConfig(cfgJSON string) []string {
	var c struct {
		Target  string   `json:"target"` // singular — used by advancedweb suite + others
		Targets []string `json:"targets"`
		URLs    []string `json:"urls"`
		Domains []string `json:"domains"`
	}
	_ = json.Unmarshal([]byte(cfgJSON), &c)
	out := make([]string, 0, 1+len(c.Targets)+len(c.URLs)+len(c.Domains))
	if strings.TrimSpace(c.Target) != "" {
		out = append(out, c.Target)
	}
	out = append(out, c.Targets...)
	out = append(out, c.URLs...)
	out = append(out, c.Domains...)
	return out
}

// extractAssetsExpanded returns the per-host list that each scan actually
// walked, expanding CIDR blocks (≤/22) and hyphen ranges so each individual
// IP shows up as its own asset on the /assets page. Non-IP entries (URLs,
// hostnames) pass through untouched.
func extractAssetsExpanded(cfgJSON string) []string {
	return shared.ExpandTargets(extractAssetsFromConfig(cfgJSON), 1024)
}

// normalizeAsset reduces a raw target/URL to its canonical host form so that
// http://example.com/foo, https://example.com, and example.com all merge into
// the same asset entry.
func normalizeAsset(raw string) string {
	s := strings.TrimSpace(raw)
	if s == "" {
		return ""
	}
	if strings.Contains(s, "://") {
		if u, err := url.Parse(s); err == nil && u.Host != "" {
			h := u.Host
			if i := strings.LastIndex(h, ":"); i > 0 {
				// keep port off the key so http://x:80 and https://x:443 merge
				h = h[:i]
			}
			return strings.ToLower(h)
		}
	}
	if i := strings.Index(s, "/"); i > 0 {
		s = s[:i]
	}
	if i := strings.LastIndex(s, ":"); i > 0 {
		s = s[:i]
	}
	return strings.ToLower(s)
}

// classifyAsset returns a coarse type label for display.
func classifyAsset(a string) string {
	if a == "" {
		return "unknown"
	}
	// IPv4 — four numeric octets
	parts := strings.Split(a, ".")
	if len(parts) == 4 {
		allNum := true
		for _, p := range parts {
			if p == "" {
				allNum = false
				break
			}
			for _, r := range p {
				if r < '0' || r > '9' {
					allNum = false
					break
				}
			}
			if !allNum {
				break
			}
		}
		if allNum {
			return "ipv4"
		}
	}
	if len(parts) >= 3 {
		return "fqdn"
	}
	if len(parts) == 2 {
		return "domain"
	}
	return "host"
}

// aggregateAssets builds the deduplicated asset list for a workspace, sorted by
// last-scanned descending. Used by /assets standalone — fetches its own scan
// list (Lite — Config is the only field we read).
func (h *Handler) aggregateAssets(workspaceID string) []AssetSummary {
	scans, _ := h.db.ListScansLite(workspaceID, "")
	return h.aggregateAssetsFromScans(workspaceID, scans)
}

// aggregateAssetsFromScans is the version that takes an already-fetched
// scan slice. Used by the Dashboard so the page render doesn't issue two
// `ListScans` queries (the Dashboard already pulls scans for chart aggregation).
//
// We only consume Config, Status, CreatedAt, Module — none of which are
// BLOB columns — so the caller can hand us either the full ListScans
// output or the Lite variant; both work.
func (h *Handler) aggregateAssetsFromScans(workspaceID string, scans []models.Scan) []AssetSummary {
	type acc struct {
		summary AssetSummary
		seenMod map[string]bool
	}
	index := map[string]*acc{}

	for _, s := range scans {
		for _, raw := range extractAssetsExpanded(s.Config) {
			key := normalizeAsset(raw)
			if key == "" {
				continue
			}
			a, ok := index[key]
			if !ok {
				a = &acc{
					summary: AssetSummary{Value: key, Type: classifyAsset(key)},
					seenMod: map[string]bool{},
				}
				index[key] = a
			}
			a.summary.ScanCount++
			if s.Status == models.ScanRunning || s.Status == models.ScanPending {
				a.summary.RunningJobs++
			}
			if s.CreatedAt.After(a.summary.LastScanned) {
				a.summary.LastScanned = s.CreatedAt
			}
			if !a.seenMod[s.Module] {
				a.seenMod[s.Module] = true
				a.summary.Modules = append(a.summary.Modules, s.Module)
			}
		}
	}

	if wsTargets, err := h.db.ListTargets(workspaceID, ""); err == nil {
		for _, t := range wsTargets {
			if a, ok := index[normalizeAsset(t.Value)]; ok {
				a.summary.InWorkspace = true
			}
		}
	}

	assets := make([]AssetSummary, 0, len(index))
	for _, a := range index {
		sort.Strings(a.summary.Modules)
		assets = append(assets, a.summary)
	}
	sort.Slice(assets, func(i, j int) bool {
		if !assets[i].LastScanned.Equal(assets[j].LastScanned) {
			return assets[i].LastScanned.After(assets[j].LastScanned)
		}
		return assets[i].Value < assets[j].Value
	})
	return assets
}

// Assets renders the /assets page — aggregates every scan's targets into one
// deduplicated list.
func (h *Handler) Assets(w http.ResponseWriter, r *http.Request) {
	data := h.baseData(r, "Assets - scaNNer", "assets")
	ws := data["ActiveWorkspace"].(*models.Workspace)

	liteScans, _ := h.db.ListScansLite(ws.ID, "")
	assets := h.aggregateAssetsFromScans(ws.ID, liteScans)
	// Attach per-asset search tokens (ports/services/tech) from the cached,
	// background-built index so the search box can match on findings.
	searchBlob := h.getAssetSearchBlob(ws.ID, liteScans)
	portsBlob := h.getAssetPorts(ws.ID)
	relatedBlob := h.getAssetRelated(ws.ID)
	techBlob := h.getAssetTechnologies(ws.ID)
	ipsBlob := h.getAssetIPs(ws.ID)
	liveBlob := h.getAssetLive(ws.ID)
	redirectBlob := h.getAssetRedirect(ws.ID)

	// Promote DISCOVERED hosts to first-class assets: any host the background
	// index saw in scan RESULTS (dnsenum subdomains, httpxfind live services,
	// resolved IPs, advancedweb suite stages, …) that was never an explicit scan
	// target. Without this a discovered host — and every finding/technology on it
	// — has no asset row to attach to and stays invisible on /assets.
	{
		existing := make(map[string]bool, len(assets))
		for i := range assets {
			existing[assets[i].Value] = true
		}
		var latest time.Time
		for _, s := range liteScans {
			if s.CreatedAt.After(latest) {
				latest = s.CreatedAt
			}
		}
		discovered := map[string]bool{}
		for k := range searchBlob {
			discovered[k] = true
		}
		for k := range relatedBlob {
			discovered[k] = true
		}
		for k := range techBlob {
			discovered[k] = true
		}
		for k := range ipsBlob {
			discovered[k] = true
		}
		for k := range liveBlob {
			discovered[k] = true
		}
		for k := range redirectBlob {
			discovered[k] = true
		}
		for k := range portsBlob {
			discovered[k] = true
		}
		for host := range discovered {
			if host == "" || existing[host] {
				continue
			}
			typ := classifyAsset(host)
			if typ == "" {
				continue
			}
			assets = append(assets, AssetSummary{
				Value: host, Type: typ, Discovered: true, LastScanned: latest,
			})
			existing[host] = true
		}
		sort.Slice(assets, func(i, j int) bool {
			if !assets[i].LastScanned.Equal(assets[j].LastScanned) {
				return assets[i].LastScanned.After(assets[j].LastScanned)
			}
			return assets[i].Value < assets[j].Value
		})
	}

	// Category (target-list) membership keyed by the asset value, so an asset
	// that is also a workspace target carries the same categories as on the
	// targets page.
	wsTargets, _ := h.db.ListTargets(ws.ID, "")
	membership := h.db.TargetListMembership(ws.ID)
	catByValue := map[string][]models.TargetList{}
	for _, t := range wsTargets {
		if cats := membership[t.ID]; len(cats) > 0 {
			catByValue[t.Value] = cats
		}
	}
	lists, _ := h.db.ListTargetLists(ws.ID)
	catCounts := map[string]int{}
	// Base-domain filter chips: one chip per distinct registrable domain present
	// among the hostname assets (IPs are excluded — they are their own base and
	// would flood the chip row).
	baseDomainCounts := map[string]int{}

	for i := range assets {
		assets[i].Search = searchBlob[assets[i].Value]
		assets[i].PortSummary = portsBlob[assets[i].Value]
		assets[i].Related = relatedBlob[assets[i].Value]
		assets[i].Technologies = techBlob[assets[i].Value]
		assets[i].Categories = catByValue[assets[i].Value]
		assets[i].ResolvedIPs = ipsBlob[assets[i].Value]
		if st := liveBlob[assets[i].Value]; st > 0 {
			assets[i].Live = true
			assets[i].LiveStatus = st
		}
		assets[i].RedirectTo = redirectBlob[assets[i].Value]
		assets[i].BaseDomain = baseDomain(assets[i].Value)
		if assets[i].Type != "ipv4" && assets[i].BaseDomain != "" {
			baseDomainCounts[assets[i].BaseDomain]++
		}
		for _, c := range assets[i].Categories {
			catCounts[c.ID]++
		}
	}
	baseDomains := make([]string, 0, len(baseDomainCounts))
	for bd := range baseDomainCounts {
		baseDomains = append(baseDomains, bd)
	}
	sort.Strings(baseDomains)
	data["AssetBaseDomains"] = baseDomains
	data["AssetBaseDomainCounts"] = baseDomainCounts
	data["AssetTargetLists"] = lists
	data["AssetCatCounts"] = catCounts

	// Counts are computed off the full asset set so that the type-tab filter
	// (now applied client-side) doesn't change the totals shown in the stat
	// cards. The ?type= query param is only used to set the initial active tab.
	total, ipv4Cnt, domainCnt, fqdnCnt, runningCnt := 0, 0, 0, 0, 0
	for _, a := range assets {
		total++
		switch a.Type {
		case "ipv4":
			ipv4Cnt++
		case "domain":
			domainCnt++
		case "fqdn":
			fqdnCnt++
		}
		if a.RunningJobs > 0 {
			runningCnt++
		}
	}

	data["Assets"] = assets
	data["AssetTotal"] = total
	data["AssetIPv4"] = ipv4Cnt
	data["AssetDomain"] = domainCnt
	data["AssetFQDN"] = fqdnCnt
	data["AssetRunning"] = runningCnt
	// The type filter is now a two-way FQDN/IP tab; FQDN is the default view.
	filterType := r.URL.Query().Get("type")
	if filterType == "" {
		filterType = "fqdn"
	}
	data["FilterType"] = filterType
	h.render(w, "layout", data)
}

// AssetListsCreate / AssetListsDelete / AssetMembership were removed
// when the user-curated asset-lists feature was retired. Assets are now
// strictly the read-only set of things any scan has touched.

// AssetDetail renders /assets/{value} — every scan that touched this asset,
// grouped by module.
func (h *Handler) AssetDetail(w http.ResponseWriter, r *http.Request) {
	raw := strings.TrimPrefix(r.URL.Path, "/assets/")
	if raw == "" || raw == "/" {
		http.Redirect(w, r, "/assets", http.StatusSeeOther)
		return
	}
	decoded, err := url.PathUnescape(raw)
	if err != nil {
		decoded = raw
	}
	asset := normalizeAsset(decoded)
	if asset == "" {
		http.Redirect(w, r, "/assets", http.StatusSeeOther)
		return
	}

	data := h.baseData(r, asset+" - Asset - scaNNer", "asset_detail")
	ws := data["ActiveWorkspace"].(*models.Workspace)

	// Two-step fetch:
	//   1. Lite scan list (Config + metadata only — no Result BLOB).
	//      Used to find which scans actually touched this asset.
	//   2. GetScan(id) for the matching subset to pull Result so
	//      extractAssetFindings can parse it.
	//
	// Previous version fetched every scan with its full Result up front;
	// on workspaces with dozens of multi-MB results that single line was
	// ~1.7 s of wall-time. The filter ratio in practice is ≤10% so the
	// second pass is usually two or three GetScan calls instead of N.
	liteScans, _ := h.db.ListScansLite(ws.ID, "")

	groupsByModule := map[string]*AssetScanGroup{}
	var latest time.Time
	running := 0
	totalScans := 0
	matchedIDs := make([]string, 0, 8)
	// Discovery-capable modules can surface a host that was NEVER an explicit
	// target (a dnsenum subdomain / httpxfind live service found from a seed
	// domain). For those, also match when the asset is a subdomain of a bare
	// registrable-domain config target — the scan's result carries the host's
	// per-stage findings even though only the seed was configured.
	discoveryModule := map[string]bool{"advancedweb": true, "dnsenum": true, "hostdiscovery": true, "assetdisc": true}
	for _, s := range liteScans {
		match := false
		for _, raw := range extractAssetsFromConfig(s.Config) {
			na := normalizeAsset(raw)
			if na == asset {
				match = true
				break
			}
			if discoveryModule[s.Module] && na != "" && classifyAsset(na) != "ipv4" && strings.HasSuffix(asset, "."+na) {
				match = true
				break
			}
		}
		if !match {
			continue
		}
		totalScans++
		if s.Status == models.ScanRunning || s.Status == models.ScanPending {
			running++
		}
		if s.CreatedAt.After(latest) {
			latest = s.CreatedAt
		}
		g, ok := groupsByModule[s.Module]
		if !ok {
			g = &AssetScanGroup{
				Module:      s.Module,
				DisplayName: models.ModuleDisplayName(s.Module),
			}
			groupsByModule[s.Module] = g
		}
		g.Scans = append(g.Scans, s)
		matchedIDs = append(matchedIDs, s.ID)
	}

	groups := make([]AssetScanGroup, 0, len(groupsByModule))
	for _, g := range groupsByModule {
		sort.Slice(g.Scans, func(i, j int) bool { return g.Scans[i].CreatedAt.After(g.Scans[j].CreatedAt) })
		groups = append(groups, *g)
	}
	sort.Slice(groups, func(i, j int) bool { return groups[i].DisplayName < groups[j].DisplayName })

	// Workspace membership
	inWorkspace := false
	var wsTargetType string
	if wsTargets, err := h.db.ListTargets(ws.ID, ""); err == nil {
		for _, t := range wsTargets {
			if normalizeAsset(t.Value) == asset {
				inWorkspace = true
				wsTargetType = string(t.Type)
				break
			}
		}
	}

	// Now load Result only for the scans that actually touched this asset.
	// extractTargetFindings reads s.Result for module-specific parsers.
	fullScans := make([]models.Scan, 0, len(matchedIDs))
	for _, id := range matchedIDs {
		if s, err := h.db.GetScan(id); err == nil {
			fullScans = append(fullScans, *s)
		}
	}

	data["Asset"] = AssetSummary{
		Value:       asset,
		Type:        classifyAsset(asset),
		ScanCount:   totalScans,
		RunningJobs: running,
		LastScanned: latest,
		InWorkspace: inWorkspace,
	}
	data["Groups"] = groups
	data["WSTargetType"] = wsTargetType
	data["FindingSet"] = h.extractTargetFindings(asset, fullScans)
	h.render(w, "layout", data)
}
