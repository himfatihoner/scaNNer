package handlers

import (
	"encoding/json"
	"fmt"
	"sort"
	"strconv"
	"strings"
	"sync"

	"scanner/internal/models"
)

// asset_search.go — powers "search assets by port / service / technology" on
// the /assets page.
//
// The finding data (open ports, service/product names, detected technologies,
// WAF, server banners) lives inside each scan's result JSON, which in this
// codebase can be hundreds of MB per scan (advancedweb). Parsing all of it on
// every page load is infeasible, so we build a COMPACT per-asset token index
// once, in a background goroutine, loading scan results ONE AT A TIME (bounded
// memory) and parsing with light structs that skip the heavy raw req/resp
// fields. The index is cached per workspace and rebuilt only when the scan set
// changes (fingerprint = scan count + latest finished_at).

// wsSearchIndex is the cached asset→tokens map for one workspace.
type wsSearchIndex struct {
	fingerprint string
	blob        map[string]string   // normalizedAsset -> space-joined lowercase tokens
	ports       map[string]string   // normalizedAsset -> compact "80/tcp 443/tcp +N" summary (Task 5)
	related     map[string][]string // normalizedAsset -> related hosts/IPs (IP↔subdomain cross-ref)
	tech        map[string][]string // normalizedAsset -> detected technology names (techdetect)
	ips         map[string][]string // normalizedAsset -> resolved IP(s) (the IPv4 subset of related)
	live        map[string]int      // normalizedAsset -> best HTTP status an HTTP(S) probe returned (0 = unknown)
	redirect    map[string]string   // normalizedAsset -> redirect target when the asset answered with a 3xx / Location
	ready       bool
	building    bool
}

// statusRank ranks HTTP status codes for "best status seen" selection when an
// asset was probed more than once: a 2xx (live & OK) beats a 3xx (redirect)
// beats a 1xx beats a 4xx/5xx; 0 means nothing was observed.
func statusRank(s int) int {
	switch {
	case s >= 200 && s < 300:
		return 4
	case s >= 300 && s < 400:
		return 3
	case s >= 100 && s < 200:
		return 2
	case s >= 400:
		return 1
	default:
		return 0
	}
}

// betterStatus reports whether cand is a stronger liveness signal than cur.
func betterStatus(cand, cur int) bool { return statusRank(cand) > statusRank(cur) }

// scanResolutionPairs extracts (hostname, ip) resolution pairs from one scan's
// result, so the assets page can show the subdomains behind an IP and the IP
// behind a subdomain. Sources: portservice/hostdiscovery (Target/IP + reverse
// Host) and dnsenum (subdomain → A-record IPs).
func scanResolutionPairs(module, result string) [][2]string {
	var out [][2]string
	addPair := func(host, ip string) {
		host = strings.TrimSpace(host)
		ip = strings.TrimSpace(ip)
		if host == "" || ip == "" || host == ip {
			return
		}
		// Only keep pairs where exactly one side is an IP and the other isn't.
		if (classifyAsset(ip) == "ipv4") != (classifyAsset(host) == "ipv4") {
			out = append(out, [2]string{host, ip})
		}
	}
	switch module {
	case "portservice", "hostdiscovery":
		var r struct {
			Results []struct {
				Target string `json:"target"`
				IP     string `json:"ip"`
				Host   string `json:"host"`
			} `json:"results"`
		}
		if json.Unmarshal([]byte(result), &r) != nil {
			return out
		}
		for _, tr := range r.Results {
			addPair(tr.Target, tr.IP) // hostname target → resolved IP
			addPair(tr.Host, tr.IP)   // reverse-DNS host → IP
		}
	case "dnsenum":
		var r struct {
			Results []struct {
				Subdomains []struct {
					Subdomain string   `json:"subdomain"`
					IPs       []string `json:"ips"`
				} `json:"subdomains"`
			} `json:"results"`
		}
		if json.Unmarshal([]byte(result), &r) != nil {
			return out
		}
		for _, res := range r.Results {
			for _, sd := range res.Subdomains {
				for _, ip := range sd.IPs {
					addPair(sd.Subdomain, ip)
				}
			}
		}
	case "advancedweb":
		// Descend into each stage's native result and reuse this extractor, so the
		// suite's DNS-Enum / PortService / HostDiscovery stages contribute host↔IP
		// pairs (and thus their discovered hosts) exactly like standalone runs.
		var r struct {
			Stages map[string]struct {
				Result json.RawMessage `json:"result"`
			} `json:"stages"`
		}
		if json.Unmarshal([]byte(result), &r) != nil {
			return out
		}
		for stage, sr := range r.Stages {
			if len(sr.Result) == 0 {
				continue
			}
			out = append(out, scanResolutionPairs(stage, string(sr.Result))...)
		}
	}
	return out
}

// scanLiveRedirect extracts, from one scan's result, per-asset liveness (the
// best HTTP status an HTTP(S) probe actually returned) and redirect targets.
// An asset is "live" when a probe answered with status > 0; it "redirects" when
// the answer was a 3xx or carried an explicit redirect location. Sources:
// httpxfind (ServiceResult.StatusCode / RedirectURL) and portservice
// (Port.HTTPResp.Status / RedirectedTo). Keyed by normalizeAsset(host/URL).
func scanLiveRedirect(module, result string) (map[string]int, map[string]string) {
	live := map[string]int{}
	redirect := map[string]string{}
	markLive := func(host string, status int) {
		a := normalizeAsset(host)
		if a == "" || status <= 0 {
			return
		}
		if betterStatus(status, live[a]) {
			live[a] = status
		}
	}
	markRedirect := func(host, target string) {
		a := normalizeAsset(host)
		target = strings.TrimSpace(target)
		if a == "" || target == "" {
			return
		}
		if _, ok := redirect[a]; !ok {
			redirect[a] = target
		}
	}
	switch module {
	case "httpxfind":
		var r struct {
			Services []struct {
				URL         string `json:"url"`
				Host        string `json:"host"`
				StatusCode  int    `json:"status_code"`
				RedirectURL string `json:"redirect_url"`
			} `json:"services"`
		}
		if json.Unmarshal([]byte(result), &r) != nil {
			return live, redirect
		}
		for _, s := range r.Services {
			for _, host := range []string{s.Host, s.URL} {
				markLive(host, s.StatusCode)
				if s.RedirectURL != "" || (s.StatusCode >= 300 && s.StatusCode < 400) {
					markRedirect(host, s.RedirectURL)
				}
			}
		}
	case "portservice", "hostdiscovery":
		var r struct {
			Results []struct {
				Target string `json:"target"`
				IP     string `json:"ip"`
				Host   string `json:"host"`
				Ports  []struct {
					HTTPResp *struct {
						Status       int    `json:"status"`
						RedirectedTo string `json:"redirected_to"`
					} `json:"http_resp"`
				} `json:"ports"`
			} `json:"results"`
		}
		if json.Unmarshal([]byte(result), &r) != nil {
			return live, redirect
		}
		for _, tr := range r.Results {
			for _, p := range tr.Ports {
				if p.HTTPResp == nil {
					continue
				}
				for _, host := range []string{tr.Target, tr.IP, tr.Host} {
					markLive(host, p.HTTPResp.Status)
					if p.HTTPResp.RedirectedTo != "" || (p.HTTPResp.Status >= 300 && p.HTTPResp.Status < 400) {
						markRedirect(host, p.HTTPResp.RedirectedTo)
					}
				}
			}
		}
	case "advancedweb":
		// Descend into each stage's native result and reuse this extractor.
		var r struct {
			Stages map[string]struct {
				Result json.RawMessage `json:"result"`
			} `json:"stages"`
		}
		if json.Unmarshal([]byte(result), &r) != nil {
			return live, redirect
		}
		for stage, sr := range r.Stages {
			if len(sr.Result) == 0 {
				continue
			}
			l, rd := scanLiveRedirect(stage, string(sr.Result))
			for a, st := range l {
				if betterStatus(st, live[a]) {
					live[a] = st
				}
			}
			for a, t := range rd {
				if _, ok := redirect[a]; !ok {
					redirect[a] = t
				}
			}
		}
	}
	return live, redirect
}

var (
	assetSearchMu    sync.Mutex
	assetSearchCache = map[string]*wsSearchIndex{} // workspaceID -> index
)

// getAssetSearchBlob returns the current asset→search-tokens map for the
// workspace, kicking off a background rebuild when the scan set has changed.
// Callers get whatever is ready now (possibly empty on the very first load
// while the background build runs); a refresh a moment later shows full data.
func (h *Handler) getAssetSearchBlob(workspaceID string, liteScans []models.Scan) map[string]string {
	fp := assetSearchFingerprint(liteScans)

	assetSearchMu.Lock()
	idx := assetSearchCache[workspaceID]
	if idx == nil {
		idx = &wsSearchIndex{blob: map[string]string{}}
		assetSearchCache[workspaceID] = idx
	}
	current := idx.blob
	needsBuild := idx.fingerprint != fp && !idx.building
	if needsBuild {
		idx.building = true
	}
	assetSearchMu.Unlock()

	if needsBuild {
		// Snapshot the scan id/module list for the builder (cheap fields only).
		// RUNNING scans are included too so the assets page reflects the
		// services/technologies detected SO FAR, live — each visit re-reads the
		// scan's flushed partial result.
		ids := make([][2]string, 0, len(liteScans))
		for _, s := range liteScans {
			if s.Status == models.ScanDone || s.Status == models.ScanCancelled || s.Status == models.ScanRunning {
				ids = append(ids, [2]string{s.ID, s.Module})
			}
		}
		go h.buildAssetSearchIndex(workspaceID, fp, ids)
	}
	return current
}

// searchFingerprint identifies the scan set so the (vulnerability) index is
// rebuilt only when scans are added/removed/finish.
func searchFingerprint(scans []models.Scan) string {
	latest := int64(0)
	for _, s := range scans {
		if s.FinishedAt != nil {
			if u := s.FinishedAt.Unix(); u > latest {
				latest = u
			}
		}
	}
	return fmt.Sprintf("%d:%d", len(scans), latest)
}

// assetSearchFingerprint is like searchFingerprint but also folds in the
// progress of RUNNING scans, so the assets page rebuilds and shows freshly
// detected services/technologies while a scan is still in flight (live update
// on refresh) — not only after it finishes.
func assetSearchFingerprint(scans []models.Scan) string {
	latest := int64(0)
	runningProgress := 0
	for _, s := range scans {
		if s.FinishedAt != nil {
			if u := s.FinishedAt.Unix(); u > latest {
				latest = u
			}
		}
		if s.Status == models.ScanRunning || s.Status == models.ScanPending {
			runningProgress += s.ProgressDone
		}
	}
	return fmt.Sprintf("%d:%d:%d", len(scans), latest, runningProgress)
}

// buildAssetSearchIndex loads each scan's full result ONE AT A TIME, extracts
// per-host search tokens, merges them per asset, and publishes the compact
// index. Memory stays bounded to a single result at a time.
func (h *Handler) buildAssetSearchIndex(workspaceID, fp string, ids [][2]string) {
	perAsset := map[string]map[string]bool{}
	mergeInto := func(tokens map[string]map[string]bool) {
		for asset, toks := range tokens {
			dst := perAsset[asset]
			if dst == nil {
				dst = map[string]bool{}
				perAsset[asset] = dst
			}
			for t := range toks {
				dst[t] = true
			}
		}
	}

	// Resolution cross-reference: host -> set of IPs and IP -> set of hosts.
	host2ip := map[string]map[string]bool{}
	addRel := func(a, v string) {
		a = normalizeAsset(a)
		if a == "" || v == "" {
			return
		}
		if host2ip[a] == nil {
			host2ip[a] = map[string]bool{}
		}
		host2ip[a][v] = true
	}

	// Detected technologies per asset (techdetect / advancedweb's techdetect
	// stage), for the assets-list Technologies column.
	techByAsset := map[string]map[string]bool{}
	mergeTech := func(m map[string][]string) {
		for a, names := range m {
			if techByAsset[a] == nil {
				techByAsset[a] = map[string]bool{}
			}
			for _, n := range names {
				techByAsset[a][n] = true
			}
		}
	}

	// Liveness (best HTTP status seen) and redirect target per asset, accumulated
	// across every scan that probed the host (httpxfind + portservice).
	liveByAsset := map[string]int{}
	redirectByAsset := map[string]string{}

	for _, im := range ids {
		scan, err := h.db.GetScan(im[0])
		if err != nil || scan == nil || scan.Result == "" {
			continue
		}
		mergeInto(scanSearchTokens(im[1], scan.Result))
		mergeTech(scanTechnologies(im[1], scan.Result))
		for _, pr := range scanResolutionPairs(im[1], scan.Result) {
			// pr = {hostname, ip}: the IP asset lists the hostname, and the
			// hostname asset lists the IP.
			addRel(pr[1], pr[0]) // IP  -> hostname
			addRel(pr[0], pr[1]) // host -> IP
		}
		l, rd := scanLiveRedirect(im[1], scan.Result)
		for a, st := range l {
			if betterStatus(st, liveByAsset[a]) {
				liveByAsset[a] = st
			}
		}
		for a, t := range rd {
			if _, ok := redirectByAsset[a]; !ok {
				redirectByAsset[a] = t
			}
		}
		scan.Result = "" // release the (possibly huge) blob before the next one
	}

	tech := make(map[string][]string, len(techByAsset))
	for a, set := range techByAsset {
		list := make([]string, 0, len(set))
		for n := range set {
			list = append(list, n)
		}
		sort.Strings(list)
		tech[a] = list
	}

	related := make(map[string][]string, len(host2ip))
	ips := make(map[string][]string, len(host2ip))
	for a, set := range host2ip {
		list := make([]string, 0, len(set))
		var ipList []string
		for v := range set {
			list = append(list, v)
			if classifyAsset(v) == "ipv4" {
				ipList = append(ipList, v)
			}
		}
		sort.Strings(list)
		related[a] = list
		if len(ipList) > 0 {
			sort.Strings(ipList)
			ips[a] = ipList
		}
	}

	blob := make(map[string]string, len(perAsset))
	ports := make(map[string]string, len(perAsset))
	for asset, toks := range perAsset {
		list := make([]string, 0, len(toks))
		// Port tokens are already emitted as "<num>/<proto>" by scanSearchTokens;
		// pull them out (numerically sorted, compacted) for the assets-list
		// Ports/Services column (Task 5) without a second parse of the results.
		type portTok struct {
			n   int
			tok string
		}
		var pts []portTok
		for t := range toks {
			list = append(list, t)
			if before, _, ok := strings.Cut(t, "/"); ok {
				if n, err := strconv.Atoi(before); err == nil {
					pts = append(pts, portTok{n, t})
				}
			}
		}
		sort.Strings(list)
		blob[asset] = strings.Join(list, " ")
		if len(pts) > 0 {
			sort.Slice(pts, func(i, j int) bool { return pts[i].n < pts[j].n })
			const maxShow = 6
			extra := 0
			if len(pts) > maxShow {
				extra = len(pts) - maxShow
				pts = pts[:maxShow]
			}
			parts := make([]string, len(pts))
			for i, p := range pts {
				parts[i] = p.tok
			}
			s := strings.Join(parts, " ")
			if extra > 0 {
				s += fmt.Sprintf(" +%d", extra)
			}
			ports[asset] = s
		}
	}

	assetSearchMu.Lock()
	idx := assetSearchCache[workspaceID]
	if idx == nil {
		idx = &wsSearchIndex{}
		assetSearchCache[workspaceID] = idx
	}
	idx.blob = blob
	idx.ports = ports
	idx.related = related
	idx.tech = tech
	idx.ips = ips
	idx.live = liveByAsset
	idx.redirect = redirectByAsset
	idx.fingerprint = fp
	idx.ready = true
	idx.building = false
	assetSearchMu.Unlock()
}

// getAssetRelated returns the per-asset resolution cross-reference (IP→hosts /
// host→IPs) from the (already triggered via getAssetSearchBlob) index.
func (h *Handler) getAssetRelated(workspaceID string) map[string][]string {
	assetSearchMu.Lock()
	defer assetSearchMu.Unlock()
	if idx := assetSearchCache[workspaceID]; idx != nil && idx.related != nil {
		return idx.related
	}
	return map[string][]string{}
}

// getAssetIPs returns the per-asset resolved-IP list (the IPv4 subset of the
// resolution cross-reference) from the (already triggered via
// getAssetSearchBlob) index. Empty until the background build finishes.
func (h *Handler) getAssetIPs(workspaceID string) map[string][]string {
	assetSearchMu.Lock()
	defer assetSearchMu.Unlock()
	if idx := assetSearchCache[workspaceID]; idx != nil && idx.ips != nil {
		return idx.ips
	}
	return map[string][]string{}
}

// getAssetLive returns the per-asset best-HTTP-status map (0 = unknown) from the
// (already triggered via getAssetSearchBlob) index. A non-zero value means an
// HTTP(S) probe actually answered for that asset.
func (h *Handler) getAssetLive(workspaceID string) map[string]int {
	assetSearchMu.Lock()
	defer assetSearchMu.Unlock()
	if idx := assetSearchCache[workspaceID]; idx != nil && idx.live != nil {
		return idx.live
	}
	return map[string]int{}
}

// getAssetRedirect returns the per-asset redirect target map from the (already
// triggered via getAssetSearchBlob) index. Empty until the background build
// finishes.
func (h *Handler) getAssetRedirect(workspaceID string) map[string]string {
	assetSearchMu.Lock()
	defer assetSearchMu.Unlock()
	if idx := assetSearchCache[workspaceID]; idx != nil && idx.redirect != nil {
		return idx.redirect
	}
	return map[string]string{}
}

// getAssetTechnologies returns the per-asset detected-technology names from the
// (already triggered via getAssetSearchBlob) index. Empty until the background
// build finishes.
func (h *Handler) getAssetTechnologies(workspaceID string) map[string][]string {
	assetSearchMu.Lock()
	defer assetSearchMu.Unlock()
	if idx := assetSearchCache[workspaceID]; idx != nil && idx.tech != nil {
		return idx.tech
	}
	return map[string][]string{}
}

// scanTechnologies extracts detected technology names per normalized asset from
// a techdetect result (standalone module or advancedweb's techdetect stage).
func scanTechnologies(module, result string) map[string][]string {
	out := map[string][]string{}
	add := func(host string, names ...string) {
		a := normalizeAsset(host)
		if a == "" {
			return
		}
		seen := map[string]bool{}
		for _, n := range out[a] {
			seen[n] = true
		}
		for _, n := range names {
			if n = strings.TrimSpace(n); n != "" && !seen[n] {
				out[a] = append(out[a], n)
				seen[n] = true
			}
		}
	}
	parseTD := func(raw string) {
		var r struct {
			Results []struct {
				URL          string `json:"url"`
				Host         string `json:"host"`
				Technologies []struct {
					Name string `json:"name"`
				} `json:"technologies"`
			} `json:"results"`
		}
		if json.Unmarshal([]byte(raw), &r) != nil {
			return
		}
		for _, tr := range r.Results {
			host := tr.URL
			if host == "" {
				host = tr.Host
			}
			for _, t := range tr.Technologies {
				add(host, t.Name)
			}
		}
	}
	// parseSvc pulls detected SERVICES (nmap product/version, else the service
	// name) per host from a portservice-shaped result, so the assets column
	// shows services alongside technologies.
	parseSvc := func(raw string) {
		var r struct {
			Results []struct {
				Target string `json:"target"`
				Host   string `json:"host"`
				Ports  []struct {
					Service string `json:"service"`
					Product string `json:"product"`
					Version string `json:"version"`
				} `json:"ports"`
			} `json:"results"`
		}
		if json.Unmarshal([]byte(raw), &r) != nil {
			return
		}
		for _, tr := range r.Results {
			for _, p := range tr.Ports {
				label := strings.TrimSpace(p.Product)
				if label != "" && strings.TrimSpace(p.Version) != "" {
					label += " " + strings.TrimSpace(p.Version)
				}
				if label == "" {
					label = strings.TrimSpace(p.Service)
				}
				if label == "" {
					continue
				}
				add(tr.Target, label)
				add(tr.Host, label)
			}
		}
	}
	switch module {
	case "techdetect":
		parseTD(result)
	case "portservice":
		parseSvc(result)
	case "advancedweb":
		// The suite nests each stage's result under stages.<name>.result.
		var suite struct {
			Stages map[string]struct {
				Result json.RawMessage `json:"result"`
			} `json:"stages"`
		}
		if json.Unmarshal([]byte(result), &suite) == nil {
			if st, ok := suite.Stages["techdetect"]; ok && len(st.Result) > 0 {
				parseTD(string(st.Result))
			}
			if st, ok := suite.Stages["portservice"]; ok && len(st.Result) > 0 {
				parseSvc(string(st.Result))
			}
		}
	}
	return out
}

// getAssetPorts returns the per-asset compact ports summary from the (already
// triggered via getAssetSearchBlob) index. Empty until the background build
// finishes — a refresh a moment later fills it in.
func (h *Handler) getAssetPorts(workspaceID string) map[string]string {
	assetSearchMu.Lock()
	defer assetSearchMu.Unlock()
	if idx := assetSearchCache[workspaceID]; idx != nil && idx.ports != nil {
		return idx.ports
	}
	return map[string]string{}
}

// scanSearchTokens extracts a per-host token set (open ports, service/product
// names, technologies, WAF, server) from one scan's result. Keyed by
// normalizeAsset(host). Only the token-producing modules are handled; light
// structs skip the heavy raw request/response fields so the parse stays cheap.
func scanSearchTokens(module, result string) map[string]map[string]bool {
	idx := map[string]map[string]bool{}
	add := func(host string, toks ...string) {
		a := normalizeAsset(host)
		if a == "" {
			return
		}
		set := idx[a]
		if set == nil {
			set = map[string]bool{}
			idx[a] = set
		}
		for _, t := range toks {
			t = strings.ToLower(strings.TrimSpace(t))
			if t != "" {
				set[t] = true
			}
		}
	}

	switch module {
	case "portservice", "hostdiscovery":
		var r struct {
			Results []struct {
				Target string `json:"target"`
				IP     string `json:"ip"`
				Host   string `json:"host"`
				Ports  []struct {
					Port     int    `json:"port"`
					Protocol string `json:"protocol"`
					State    string `json:"state"`
					Service  string `json:"service"`
					Product  string `json:"product"`
					Version  string `json:"version"`
				} `json:"ports"`
			} `json:"results"`
		}
		if json.Unmarshal([]byte(result), &r) != nil {
			return idx
		}
		for _, tr := range r.Results {
			for _, host := range []string{tr.Target, tr.IP, tr.Host} {
				for _, p := range tr.Ports {
					if p.State != "" && p.State != "open" {
						continue
					}
					add(host, fmt.Sprintf("%d/%s", p.Port, p.Protocol), p.Service, p.Product, p.Version)
				}
			}
		}

	case "httpxfind":
		var r struct {
			Services []struct {
				URL    string `json:"url"`
				Host   string `json:"host"`
				Port   int    `json:"port"`
				Scheme string `json:"scheme"`
				Server string `json:"server"`
			} `json:"services"`
		}
		if json.Unmarshal([]byte(result), &r) != nil {
			return idx
		}
		for _, s := range r.Services {
			for _, host := range []string{s.Host, s.URL} {
				add(host, s.Server, s.Scheme, fmt.Sprintf("%d/tcp", s.Port))
			}
		}

	case "techdetect":
		var r struct {
			Results []struct {
				URL          string `json:"url"`
				Server       string `json:"server"`
				Technologies []struct {
					Name    string `json:"name"`
					Version string `json:"version"`
				} `json:"technologies"`
			} `json:"results"`
		}
		if json.Unmarshal([]byte(result), &r) != nil {
			return idx
		}
		for _, tr := range r.Results {
			add(tr.URL, tr.Server)
			for _, t := range tr.Technologies {
				add(tr.URL, t.Name, t.Version)
			}
		}

	case "wafdetect":
		var r struct {
			Results []struct {
				URL       string `json:"url"`
				WAFName   string `json:"waf_name"`
				WAFVendor string `json:"waf_vendor"`
				Server    string `json:"server"`
			} `json:"results"`
		}
		if json.Unmarshal([]byte(result), &r) != nil {
			return idx
		}
		for _, tr := range r.Results {
			add(tr.URL, tr.WAFName, tr.WAFVendor, tr.Server)
		}

	case "wpscan":
		var r struct {
			Results []struct {
				URL       string `json:"url"`
				WPVersion string `json:"wp_version"`
				Theme     string `json:"theme"`
			} `json:"results"`
		}
		if json.Unmarshal([]byte(result), &r) != nil {
			return idx
		}
		for _, tr := range r.Results {
			add(tr.URL, "wordpress", tr.WPVersion, tr.Theme)
		}

	case "smbenum":
		var r struct {
			Results []struct {
				Target string `json:"target"`
				IP     string `json:"ip"`
				OS     string `json:"os"`
			} `json:"results"`
		}
		if json.Unmarshal([]byte(result), &r) != nil {
			return idx
		}
		for _, tr := range r.Results {
			add(tr.Target, "smb", tr.OS)
			add(tr.IP, "smb", tr.OS)
		}

	case "sslscan":
		var hosts []struct {
			Host      string `json:"host"`
			Protocols []struct {
				Name      string `json:"name"`
				Supported bool   `json:"supported"`
			} `json:"protocols"`
		}
		if json.Unmarshal([]byte(result), &hosts) != nil {
			return idx
		}
		for _, hst := range hosts {
			add(hst.Host, "tls")
			for _, p := range hst.Protocols {
				if p.Supported {
					add(hst.Host, p.Name)
				}
			}
		}

	case "advancedweb":
		// Descend into each stage's native result and reuse the extractors.
		var r struct {
			Stages map[string]struct {
				Result json.RawMessage `json:"result"`
			} `json:"stages"`
		}
		if json.Unmarshal([]byte(result), &r) != nil {
			return idx
		}
		for stage, sr := range r.Stages {
			if len(sr.Result) == 0 {
				continue
			}
			if stage == "dirspider" {
				continue // paths, not ports/services/tech
			}
			for asset, toks := range scanSearchTokens(stage, string(sr.Result)) {
				dst := idx[asset]
				if dst == nil {
					dst = map[string]bool{}
					idx[asset] = dst
				}
				for t := range toks {
					dst[t] = true
				}
			}
		}
	}

	return idx
}
