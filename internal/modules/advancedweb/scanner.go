package advancedweb

import (
	"context"
	"encoding/json"
	"fmt"
	"net/url"
	"strings"
	"sync"
	"sync/atomic"
	"time"

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

// hasDNSSubdomains reports whether DNS enumeration discovered any subdomains —
// an alternate source of live hosts to scan when HTTPX found none.
func hasDNSSubdomains(dnsResult *dnsenum.ScanResult) bool {
	if dnsResult == nil {
		return false
	}
	for _, dr := range dnsResult.Results {
		if len(dr.Subdomains) > 0 {
			return true
		}
	}
	return false
}

// ProgressFunc mirrors what scan_progress.html consumes — flat done/total
// with a free-text message. Stage labels are baked into the message.
type ProgressFunc func(done, total int, msg string)
type PartialFunc func(partial *ScanResult)

// stage8MaxDuration caps the DirEnum ↔ Spider iterative loop's wall
// clock. Per user direction this is set wide (3 days) so heavy
// scans — aggressive level + deep recursion across many seed URLs —
// can run to completion without being cut off. The deadline still
// exists so a genuinely stuck loop (no progress, just retries against
// a dead host) can't pin the scan as "running" forever; in that
// failure mode the user will see partial results returned with an
// explicit deadline message after 72 hours.
const stage8MaxDuration = 72 * time.Hour

// Scan runs the suite end-to-end. concurrency is the per-stage HTTP
// concurrency taken from settings (each web stage that supports it
// receives this value). Cancellation propagates through opts.Ctx.
//
// The function is wrapped in a top-level recover() so a panic in any
// sub-module is captured into result.Error instead of crashing the
// whole HTTP server — past bugs in individual scanners surfaced as
// blank error pages with no diagnostic.
// CVELookup is the DB-fed lookup function for the CVE Matcher stage.
// Passed in by the handler so the suite package doesn't need a direct
// database dependency. May be nil — the matcher stage will then be
// marked skipped with an explanatory message.
type CVELookup func(productKey string) []cvematch.CacheCVE

func Scan(cfg Config, opts *shared.HTTPOptions, concurrency int, cveLookup CVELookup, progress ProgressFunc, partial PartialFunc) (out *ScanResult, retErr error) {
	// Build the input list — Targets is the new multi-target field, but
	// fall back to the legacy single Target if Targets is empty. Filter
	// out IPs (the suite is web-focused and IPs are handled by the
	// network-scan suite).
	rawTargets := cfg.Targets
	if len(rawTargets) == 0 && strings.TrimSpace(cfg.Target) != "" {
		rawTargets = []string{cfg.Target}
	}
	if len(rawTargets) == 0 {
		return nil, fmt.Errorf("Advanced Web Suite needs at least one target (manual entry or a target list)")
	}
	var allClassified []shared.ClassifiedInput
	for _, t := range rawTargets {
		c, err := shared.ClassifyInput(strings.TrimSpace(t))
		if err != nil || c.Kind == shared.KindIP {
			continue
		}
		allClassified = append(allClassified, c)
	}
	if len(allClassified) == 0 {
		return nil, fmt.Errorf("Advanced Web Suite needs a domain or URL — none of the supplied targets qualified (plain IPs are not supported)")
	}
	// `classified` (legacy var name kept) is the representative target —
	// used for ScanResult.Target/Kind display + URL-vs-domain skip logic.
	// When the user supplies a mix, "all are URL" decides the skip.
	classified := allClassified[0]
	allURL := true
	for _, c := range allClassified {
		if c.Kind != shared.KindURL {
			allURL = false
			break
		}
	}
	_ = allURL // currently used implicitly via classified.Kind below; refactor in progress

	ctx := context.Background()
	if opts != nil && opts.Ctx != nil {
		ctx = opts.Ctx
	}

	// Display target — single name when one input, "first (+N more)" otherwise.
	displayTarget := classified.Raw
	if len(allClassified) > 1 {
		displayTarget = fmt.Sprintf("%s (+%d more)", classified.Raw, len(allClassified)-1)
	}
	result := &ScanResult{
		Target:     displayTarget,
		Kind:       string(classified.Kind),
		StartedAt:  time.Now(),
		StageOrder: append([]Stage(nil), StageOrder...),
		Stages:     map[Stage]*StageResult{},
	}
	for _, s := range StageOrder {
		result.Stages[s] = &StageResult{Stage: s, Status: StatusDisabled}
	}
	// Make `out` point at the same `result` early so a defer/recover
	// after a panic still hands the caller whatever progress was made
	// before the crash, instead of returning nil.
	out = result
	defer func() {
		if r := recover(); r != nil {
			result.Error = fmt.Sprintf("panic in suite: %v", r)
			result.FinishedAt = time.Now()
			if partial != nil {
				partial(result)
			}
			retErr = nil
		}
	}()

	// Mark stages the user disabled vs. ones the input kind disqualifies.
	enabledMap := map[Stage]bool{
		StageWhois:       cfg.EnableWhois,
		StageDNSEnum:     cfg.EnableDNSEnum,
		StageHTTPXFind:   cfg.EnableHTTPXFind,
		StageSSLScan:     cfg.EnableSSLScan,
		StageWAFDetect:   cfg.EnableWAFDetect,
		StageTechDetect:  cfg.EnableTechDetect,
		// CVE Matcher requires Tech Detection — it consumes its (product,
		// version) pairs. If techdetect isn't enabled the matcher has no
		// inputs and is force-disabled, regardless of the user's checkbox.
		StageCVEMatch: cfg.EnableCVEMatch && cfg.EnableTechDetect,
		// WPScan requires Tech Detection — only relevant when WordPress is
		// detected. We pre-enable it whenever both checkboxes are on, and
		// the stage itself runtime-checks for WordPress URLs before doing
		// any work (skipped with a clear message when none found).
		StageWPScan: cfg.EnableWPScan && cfg.EnableTechDetect,
		StageNuclei: cfg.EnableNuclei,
		StageDirSpider:   cfg.EnableDirSpider,
		StageHTTPMethods: cfg.EnableHTTPMethods,
		StageSecHeaders:  cfg.EnableSecHeaders,
	}

	// URL input → stages 1/2/3 (whois, dnsenum, httpxfind) are skipped:
	// they all answer questions about the host registry / DNS / live
	// service map, which the user has already implicitly resolved by
	// giving us a URL with a specific path.
	skippedByKind := map[Stage]bool{}
	// Skip WHOIS/DNS/HTTPX only when EVERY supplied target is a URL — even
	// a single domain in the mix means we still need to do recon.
	if allURL {
		for _, s := range []Stage{StageWhois, StageDNSEnum, StageHTTPXFind} {
			skippedByKind[s] = true
			result.Stages[s].Status = StatusSkipped
			result.Stages[s].Message = "all inputs are URLs — stage runs against domains, skipped"
		}
		result.Notes = append(result.Notes, fmt.Sprintf("All targets are URLs — using their schemes passively. Stages 1–3 (WHOIS/DNS/HTTPX) skipped."))
	}

	// Stage-level resume (Task 0): seed the stages that already completed before
	// a connectivity pause. Every seeded stage is marked done and force-disabled
	// so it's excluded from totalUnits below (the resume run only counts the
	// stages that still have work) — the data-producing stages (DNS/HTTPX/
	// TechDetect) reconstruct their in-memory result at their own gate, which
	// checks cfg.ResumeStages BEFORE the enabledMap branch, so disabling them
	// here doesn't stop the reconstruction. Safe no-op for a fresh scan.
	for stage, raw := range cfg.ResumeStages {
		sr := result.Stages[stage]
		if sr == nil || len(raw) == 0 {
			continue
		}
		sr.Status = StatusDone
		sr.Result = raw
		sr.Message = "resumed — completed before the pause"
		enabledMap[stage] = false
	}

	// resultMu serializes every mutation of result.* and the partial()
	// callback's marshal pass. The heartbeat goroutine (below) calls
	// partial → handler json.Marshal(result) concurrently with the main
	// pipeline mutating result.Stages[*].ProgressDone/ProgressMsg/
	// Status/Result/etc. (audit B-heartbeat-race). Without the lock,
	// json.Marshal sees torn writes on the stage map and the encoder
	// races on the StageResult fields. Held only briefly per call —
	// the heartbeat cadence (1.5s) plus the per-stage start/finish/
	// progress points keep contention negligible.
	var resultMu sync.Mutex
	pushPartial := func() {
		if partial != nil {
			resultMu.Lock()
			partial(result)
			resultMu.Unlock()
		}
	}
	// Periodic mid-stage pusher: long-running stages (techdetect on 100+
	// URLs, nuclei sweeps) update their progress counters via the
	// stageProgress closure, but only stage boundaries call pushPartial
	// directly. Without this, the UI sees no progress updates between
	// boundaries. 1.5s matches the handler's per-scan ticker cadence.
	stopHeartbeat := make(chan struct{})
	go func() {
		t := time.NewTicker(1500 * time.Millisecond)
		defer t.Stop()
		for {
			select {
			case <-stopHeartbeat:
				return
			case <-t.C:
				pushPartial()
			}
		}
	}()
	defer close(stopHeartbeat)

	// Total progress units = number of *enabled and not-skipped* stages,
	// minimum 1 so the bar is meaningful. We bump exactly once per
	// stage, not per intra-stage probe.
	totalUnits := 0
	for _, s := range StageOrder {
		if enabledMap[s] && !skippedByKind[s] {
			totalUnits++
		}
	}
	if totalUnits == 0 {
		totalUnits = 1
	}
	// doneUnits is touched by bumpStage (synchronously, from the main
	// pipeline goroutine) AND by liveProgress (from per-stage callback
	// goroutines such as DirSpider's partial-result emitter). Without
	// the atomic load, the race detector flags it; in practice the
	// torn-read produces nonsensical "[5/7] running" / "[3/7] done"
	// flickers in the UI (audit B30). atomic.Int32 keeps reads + writes
	// strictly ordered without needing a Mutex.
	var doneUnits atomic.Int32
	bumpStage := func(stageIdx int, label, msg string) {
		d := doneUnits.Add(1)
		if progress != nil {
			progress(int(d), totalUnits, fmt.Sprintf("[%d/%d] %s · %s", d, totalUnits, label, msg))
		}
	}
	// liveProgress is called by long-running stages (currently stage 8)
	// to refresh the top-of-page message while still in flight, so the
	// user doesn't see "[4/7] Nuclei · 0 findings" stuck for 30 minutes
	// while DirSpider chews through the wordlist. The done counter
	// stays put — only message text updates — so the bar percentage
	// still reflects "finished stages / total".
	liveProgress := func(label, msg string) {
		if progress != nil {
			d := doneUnits.Load()
			progress(int(d), totalUnits, fmt.Sprintf("[%d/%d] running: %s · %s", d, totalUnits, label, msg))
		}
	}

	startStage := func(stage Stage) *StageResult {
		resultMu.Lock()
		sr := result.Stages[stage]
		sr.Status = StatusRunning
		sr.StartedAt = time.Now()
		resultMu.Unlock()
		// Reset the per-scan error counter at stage boundaries — without
		// this, errors from the previous stage (e.g. thousands of DNS
		// lookup failures during DNS Enum) visually bleed into the next
		// stage's "X errors so far" warning, making it look like HTTPX
		// is generating DNS errors. The opts object is shared across all
		// stages so we have to actively clear it.
		if opts != nil {
			opts.ResetErrors()
		}
		// Emit a "running" message immediately so the top-of-page
		// status line reflects what's actually executing rather than
		// the previous stage's completion message.
		liveProgress(StageDisplayNames[stage], "starting…")
		pushPartial()
		return sr
	}
	finishStage := func(sr *StageResult, status StageStatus, msg string, payload any) {
		var b []byte
		var marshalErr error
		if payload != nil {
			b, marshalErr = json.Marshal(payload)
		}
		resultMu.Lock()
		sr.Status = status
		sr.Message = msg
		sr.FinishedAt = time.Now()
		if payload != nil {
			if marshalErr == nil {
				sr.Result = b
			} else {
				sr.Error = "marshal failed: " + marshalErr.Error()
			}
		}
		resultMu.Unlock()
		pushPartial()
	}
	// stageProgress builds a (done int, msg string) closure suitable for
	// passing into each module's progress callback. `total` is the upfront
	// denominator the suite knows about (e.g. len(urls)). The closure
	// writes ProgressDone/ProgressTotal into sr so the partial saver
	// picks it up on its next tick; the UI shows a % bar while running.
	// stageProgress delegates to shared.ProgressTracker so every stage
	// gets the same monotonic clamp + message coalescing behavior
	// standalone handlers also use. The tracker writes into sr each
	// time the underlying module's progress callback fires, and the
	// partial saver picks the values up on its next 1.5s tick.
	stageProgress := func(sr *StageResult, total int) func(int, string) {
		tr := shared.NewProgressTracker(total, func(done, total int, msg string) {
			resultMu.Lock()
			sr.ProgressTotal = total
			sr.ProgressDone = done
			if msg != "" {
				sr.ProgressMsg = msg
			}
			resultMu.Unlock()
		})
		// Seed the total immediately so the bar can render the
		// denominator even before the first module callback fires.
		tr.Update(0, "")
		return tr.Update
	}
	disableStage := func(stage Stage) {
		resultMu.Lock()
		sr := result.Stages[stage]
		if sr.Status != StatusDone { // preserve a resume-seeded completed stage
			sr.Status = StatusDisabled
		}
		resultMu.Unlock()
		pushPartial()
	}

	// Build the unique non-URL host list — both WHOIS and DNS Enum operate
	// on bare domains. URL-kind targets skip these stages individually.
	allDomains := []string{}
	domainSeen := map[string]bool{}
	for _, c := range allClassified {
		if c.Kind == shared.KindURL {
			continue
		}
		if h := strings.TrimSpace(c.Host); h != "" && !domainSeen[h] {
			allDomains = append(allDomains, h)
			domainSeen[h] = true
		}
	}
	// Legacy single-domain alias — still used by fallback paths in
	// seedURLs()/seedHosts() when no other source produced a list.
	domain := classified.Host

	// ---------------- Stage 1: WHOIS / ASN ----------------
	if !enabledMap[StageWhois] {
		disableStage(StageWhois)
	} else if skippedByKind[StageWhois] || len(allDomains) == 0 {
		// already marked (or no non-URL domain to query)
	} else {
		sr := startStage(StageWhois)
		whoisRes := whoisinfo.Scan(ctx, whoisinfo.Config{
			Targets:     allDomains,
			Concurrency: 4,
		}, stageProgress(sr, len(allDomains)), nil)
		finishStage(sr, StatusDone,
			fmt.Sprintf("%d records across %d domains", len(whoisRes.Results), len(allDomains)), whoisRes)
		bumpStage(1, "WHOIS / ASN", fmt.Sprintf("%d records", len(whoisRes.Results)))
	}

	// ---------------- Stage 2: DNS Enum ----------------
	var dnsResult *dnsenum.ScanResult
	if raw, ok := cfg.ResumeStages[StageDNSEnum]; ok {
		// Resumed: reconstruct dnsResult from the seeded stage so downstream
		// stages (HTTPX seeds, etc.) still get the subdomain list; skip re-running.
		var seeded dnsenum.ScanResult
		if json.Unmarshal(raw, &seeded) == nil {
			dnsResult = &seeded
		}
	} else if !enabledMap[StageDNSEnum] {
		disableStage(StageDNSEnum)
	} else if skippedByKind[StageDNSEnum] || len(allDomains) == 0 {
		// already marked
	} else {
		sr := startStage(StageDNSEnum)
		dnsSpeed := dnsenum.SpeedFast
		switch cfg.DNSEnumSpeed {
		case "normal":
			dnsSpeed = dnsenum.SpeedNormal
		case "aggressive":
			dnsSpeed = dnsenum.Speed("aggressive")
		}
		dnsOpts := dnsenum.Options{}
		if cfg.DNSEnumMaxDepth > 0 {
			dnsOpts.MaxDepth = cfg.DNSEnumMaxDepth
		}
		dnsResult = dnsenum.ScanWithOpts(ctx, allDomains, dnsSpeed, dnsOpts,
			nil, stageProgress(sr, len(allDomains)))
		count := 0
		for _, dr := range dnsResult.Results {
			count += dr.TotalFound
		}
		finishStage(sr, StatusDone,
			fmt.Sprintf("%d subdomains", count), dnsResult)
		bumpStage(2, "DNS Enumeration", fmt.Sprintf("%d subdomains", count))
	}

	// ---------------- Stage 3: HTTPX Finder ----------------
	var httpxResult *httpxfind.ScanResult
	if raw, ok := cfg.ResumeStages[StageHTTPXFind]; ok {
		// Resumed: reconstruct httpxResult (the live-service map every later
		// stage consumes) from the seeded stage; skip re-running.
		var seeded httpxfind.ScanResult
		if json.Unmarshal(raw, &seeded) == nil {
			httpxResult = &seeded
		}
	} else if !enabledMap[StageHTTPXFind] {
		disableStage(StageHTTPXFind)
	} else if skippedByKind[StageHTTPXFind] {
		// already marked
	} else {
		sr := startStage(StageHTTPXFind)
		// Feed: every user-supplied host plus every DNS-discovered subdomain.
		// When DNS Enum ran, its subdomain list is the dominant source; when
		// it didn't (or only some targets were domain-typed), we still want
		// to probe the explicit hosts the user supplied.
		var hosts []string
		seen := map[string]bool{}
		for _, d := range allDomains {
			if !seen[d] {
				hosts = append(hosts, d)
				seen[d] = true
			}
		}
		if dnsResult != nil {
			for _, dr := range dnsResult.Results {
				for _, sub := range dr.Subdomains {
					if !seen[sub.Subdomain] {
						hosts = append(hosts, sub.Subdomain)
						seen[sub.Subdomain] = true
					}
				}
				if !seen[dr.Domain] {
					hosts = append(hosts, dr.Domain)
					seen[dr.Domain] = true
				}
			}
		}
		if len(hosts) == 0 {
			hosts = []string{domain}
		}
		httpxMode := httpxfind.ModeCommon
		var customPorts []int
		switch cfg.HTTPXMode {
		case "full":
			httpxMode = httpxfind.ModeFull
		case "custom":
			customPorts = shared.ExpandPortSpec(cfg.HTTPXCustomPorts)
			// Empty / invalid spec → fall back to Common rather than
			// silently doing nothing. The form layer is supposed to
			// validate, but defence in depth.
			if len(customPorts) == 0 {
				httpxMode = httpxfind.ModeCommon
			}
		}
		// HTTPX emits progress per (host × port) probe, not per host.
		// Total must match that or the % bar overshoots / lies. For the
		// custom-port branch the total is exact (no pre-discovery), so
		// the bar tracks real progress 1:1.
		httpxTotal := len(hosts) * len(httpxfind.CommonPorts)
		switch {
		case len(customPorts) > 0:
			httpxTotal = len(hosts) * len(customPorts)
		case httpxMode == httpxfind.ModeFull:
			// Full mode probes every port and reports `done` in port units
			// (up to hosts×65535), so that's the honest denominator.
			httpxTotal = len(hosts) * 65535
		}
		// Reset the shared error counters so the post-probe ErrorSummary
		// isolates THIS stage's reachability failures (refused/timeout/DNS).
		opts.ResetErrors()
		// The suite tracks httpx as one fixed-budget stage, so swallow the
		// module's post-discovery __TOTAL__ total-bump sentinel — otherwise it
		// leaks into the stage's progress text.
		rawProg := stageProgress(sr, httpxTotal)
		httpxProg := func(done int, msg string) {
			if strings.HasPrefix(msg, httpxfind.TotalUpdatePrefix) {
				return
			}
			rawProg(done, msg)
		}
		switch {
		case len(customPorts) > 0:
			httpxResult = httpxfind.ScanWithPorts(hosts, customPorts, cfg.HTTPXConcurrency, opts, nil, httpxProg)
		case httpxMode == httpxfind.ModeFull:
			// Full mode: honour the direct-HTTP toggle (skip the connect
			// port-scan, HTTP-probe every port directly) via ScanFull.
			httpxResult = httpxfind.ScanFull(hosts, cfg.HTTPXConcurrency, 0, 0, cfg.HTTPXDirectHTTP, opts, nil, httpxProg)
		default:
			httpxResult = httpxfind.ScanWithConcurrency(hosts, httpxMode, cfg.HTTPXConcurrency, opts, nil, httpxProg)
		}
		if len(httpxResult.Services) == 0 {
			// 0 live is ambiguous: no HTTP anywhere, OR every target was
			// unreachable. Surface the recorded probe-error breakdown so the
			// operator can tell — and add a suite Note, since nothing
			// downstream (tech/CVE/nuclei) can run without live services.
			msg := "0 live services"
			if n, brk := opts.ErrorSummary(); n > 0 {
				msg = fmt.Sprintf("0 live services — %d probe failure(s) (%s): targets unreachable from the scanner (down, firewalled, geo-blocked, or no route)", n, brk)
				resultMu.Lock()
				result.Notes = append(result.Notes, fmt.Sprintf(
					"HTTPX reached 0 of %d host(s): %s. DNS resolved but no TCP/HTTP connection succeeded — verify the targets are up and reachable from the scanner's network (firewall / geo-block / VPN / killswitch interface). Tech Detection, CVE Matcher and Nuclei have nothing live to scan.",
					len(hosts), brk))
				resultMu.Unlock()
			}
			finishStage(sr, StatusDone, msg, httpxResult)
			bumpStage(3, "HTTPX Finder", "0 live services (targets unreachable)")
		} else {
			// Store a body-free copy: the per-service 256 KB response bodies/headers
			// would persist as ~250 MB over 1600 live hosts and hit the 50 MB cap the
			// moment this stage marshals — BEFORE Tech Detection (which reuses them
			// from the LIVE httpxResult) even runs. The live result keeps them.
			finishStage(sr, StatusDone,
				fmt.Sprintf("%d live services", len(httpxResult.Services)), httpxLite(httpxResult))
			bumpStage(3, "HTTPX Finder", fmt.Sprintf("%d live services", len(httpxResult.Services)))
		}
	}

	// Helper: derive the canonical seed URL list for stages 4-7 / 8.
	// Spec: "2 kendinden sonra gelen modülü besleyecek hangi modül olursa olsun /
	// 3 kendinden sonra gelen modülü besleyecek hangi modül olursa olsun".
	// So the chain is HTTPX > DNS subdomains > bare input — if the user
	// disabled HTTPX but ran DNS, the discovered subdomains still feed
	// into stages 4–7 instead of those stages defaulting to just the
	// input domain.
	seedURLs := func() []string {
		// 1. HTTPX live services (preferred — has real scheme/port info).
		if httpxResult != nil && len(httpxResult.Services) > 0 {
			urls := make([]string, 0, len(httpxResult.Services))
			seen := map[string]bool{}
			for _, s := range httpxResult.Services {
				if !seen[s.URL] {
					urls = append(urls, s.URL)
					seen[s.URL] = true
				}
			}
			return urls
		}
		// 2. DNS subdomains formatted as https://.
		if dnsResult != nil {
			out := []string{}
			seen := map[string]bool{}
			for _, dr := range dnsResult.Results {
				for _, sub := range dr.Subdomains {
					u := "https://" + sub.Subdomain
					if !seen[u] {
						out = append(out, u)
						seen[u] = true
					}
				}
			}
			if len(out) > 0 {
				return out
			}
		}
		// 3. All user-supplied inputs (multi-target safe).
		out := []string{}
		seen := map[string]bool{}
		for _, c := range allClassified {
			u := c.EnsureURL()
			if !seen[u] {
				out = append(out, u)
				seen[u] = true
			}
		}
		return out
	}
	// sslHosts is the SSL/TLS stage's host source. Unlike seedHosts it does NOT
	// consume HTTPX's live-service list: the SSL/TLS stage is independent, so it
	// probes every DNS-discovered host (or, failing that, the user's targets) on
	// its own configured port set — rather than only the exact HTTPS endpoints
	// HTTPX surfaced, which skipped TLS on ports HTTPX never reached. HTTPX
	// output still feeds the later web stages, just not this one.
	sslHosts := func() []string {
		if dnsResult != nil {
			out := []string{}
			seen := map[string]bool{}
			for _, dr := range dnsResult.Results {
				for _, sub := range dr.Subdomains {
					if !seen[sub.Subdomain] {
						out = append(out, sub.Subdomain)
						seen[sub.Subdomain] = true
					}
				}
			}
			if len(out) > 0 {
				return out
			}
		}
		out := []string{}
		seen := map[string]bool{}
		for _, c := range allClassified {
			if c.Host != "" && !seen[c.Host] {
				out = append(out, c.Host)
				seen[c.Host] = true
			}
		}
		return out
	}

	// ---------------- Stage 4: SSL/TLS ----------------
	if !enabledMap[StageSSLScan] {
		disableStage(StageSSLScan)
	} else {
		sr := startStage(StageSSLScan)
		// Independent of HTTPX (user request): probe every discovered host
		// (sslHosts — DNS subdomains or targets, NOT HTTPX's HTTPS-only service
		// list) on the CONFIGURED port set, so TLS on ports HTTPX didn't surface
		// (e.g. 8443/993/995, or a host HTTPX marked non-HTTPS) is no longer
		// skipped. Ports come from cfg.SSLScanPorts (CSV+range), defaulting to
		// 443,8443. Dedup by host:port.
		type sslEndpoint struct {
			host string
			port int
		}
		var endpoints []sslEndpoint
		sslPorts := shared.ExpandPortSpec(cfg.SSLScanPorts)
		if len(sslPorts) == 0 {
			sslPorts = []int{443, 8443}
		}
		seenEP := map[string]bool{}
		for _, h := range sslHosts() {
			if h == "" {
				continue
			}
			for _, p := range sslPorts {
				key := fmt.Sprintf("%s:%d", h, p)
				if !seenEP[key] {
					seenEP[key] = true
					endpoints = append(endpoints, sslEndpoint{h, p})
				}
			}
		}
		// Bulk SSL detection: sslscan.ScanHostBulk runs the tool-driven engine
		// (nmap ssl-enum + sslscan) for comprehensive protocol/cipher/vuln
		// findings, but WITHOUT the heavy per-host/finding evidence capture
		// (tool transcripts + PoC) and openssl, and with a tight per-tool
		// timeout. That keeps this stage stable across 1000s of hosts — the full
		// evidence path (ScanHostOpts) blew a suite result past 200 MB and froze
		// the process. Run the endpoints through a bounded worker pool at the
		// same web concurrency as every other stage.
		sslEmit := stageProgress(sr, len(endpoints))
		results := make([]*sslscan.HostResult, len(endpoints))
		sslConc := concurrency
		// This stage spawns external tools (nmap + sslscan) per endpoint, so a
		// very high web concurrency (e.g. 999) would fan out to thousands of
		// concurrent subprocesses and exhaust the machine. Cap at a
		// subprocess-safe worker count.
		if sslConc > 20 {
			sslConc = 20
		}
		if sslConc < 1 {
			sslConc = 1
		}
		if sslConc > len(endpoints) {
			sslConc = len(endpoints)
		}
		var sslWG sync.WaitGroup
		sslSem := make(chan struct{}, sslConc)
		var sslDone int64
		for i, ep := range endpoints {
			if ctx.Err() != nil {
				break
			}
			sslWG.Add(1)
			sslSem <- struct{}{}
			go func(i int, ep sslEndpoint) {
				defer sslWG.Done()
				defer func() { <-sslSem }()
				if ctx.Err() != nil {
					return
				}
				if cfg.SSLScanFullEvidence {
					// Single-finding rescan: run the full-evidence engine (adds
					// openssl + the exact nmap/sslscan/openssl transcripts the PoC
					// references) with a generous timeout, since it's one host.
					results[i] = sslscan.ScanHostOpts(ctx, ep.host, ep.port, 30*time.Second, "")
				} else {
					results[i] = sslscan.ScanHostBulk(ctx, ep.host, ep.port, 8*time.Second, "")
				}
				n := atomic.AddInt64(&sslDone, 1)
				sslEmit(int(n), fmt.Sprintf("%s:%d done · %d/%d", ep.host, ep.port, n, len(endpoints)))
			}(i, ep)
		}
		sslWG.Wait()
		// Compact out any nil slots (endpoints skipped by ctx cancellation).
		hostResults := make([]*sslscan.HostResult, 0, len(results))
		for _, hr := range results {
			if hr != nil {
				hostResults = append(hostResults, hr)
			}
		}
		finishStage(sr, StatusDone,
			fmt.Sprintf("%d hosts probed", len(hostResults)), hostResults)
		bumpStage(4, "SSL/TLS", fmt.Sprintf("%d hosts probed", len(hostResults)))
	}

	// ---------------- Stage 5: WAF / Firewall ----------------
	if !enabledMap[StageWAFDetect] {
		disableStage(StageWAFDetect)
	} else {
		sr := startStage(StageWAFDetect)
		urls := seedURLs()
		wafRes := wafdetect.Scan(wafdetect.Config{Targets: urls, EnablePayloads: true}, opts, stageProgress(sr, len(urls)), nil)
		detected := 0
		for _, t := range wafRes.Results {
			if t.WAFDetected {
				detected++
			}
		}
		finishStage(sr, StatusDone,
			fmt.Sprintf("%d / %d targets behind a WAF", detected, len(wafRes.Results)), wafRes)
		bumpStage(5, "WAF / Firewall", fmt.Sprintf("%d/%d behind WAF", detected, len(wafRes.Results)))
	}

	// ---------------- Stage 6: Tech Detection ----------------
	var techResult *techdetect.ScanResult
	if raw, ok := cfg.ResumeStages[StageTechDetect]; ok {
		// Resumed: reconstruct techResult (feeds CVE Matcher + WPScan) from the
		// seeded stage; skip re-running.
		var seeded techdetect.ScanResult
		if json.Unmarshal(raw, &seeded) == nil {
			techResult = &seeded
		}
	} else if !enabledMap[StageTechDetect] {
		disableStage(StageTechDetect)
	} else {
		sr := startStage(StageTechDetect)
		urls := seedURLs()
		// Aggressive mode (opt-in checkbox): run whatweb -a 3 on EVERY live
		// service via techdetect's fresh GET path — deeper version/plugin
		// detection, but much slower (a whatweb subprocess per host). Skips
		// the fast prefetched shortcut entirely. Default (unchecked) keeps the
		// network-free prefetched path below.
		if cfg.TechDetectAggressive && len(urls) > 0 {
			techResult = techdetect.ScanWithConfig(
				techdetect.Config{URLs: urls, Aggressive: true, LightCapture: true},
				opts, stageProgress(sr, len(urls)), nil)
		} else if httpxResult != nil && len(httpxResult.Services) > 0 {
			// If HTTPX already ran, reuse its fetched response bodies/headers
			// — saves a second round-trip per URL and dodges the WAF "second
			// probe RST" pattern (different User-Agent on the second fetch
			// frequently gets reset by Cloudflare/Akamai/etc.). When HTTPX
			// didn't run we fall back to techdetect's own GET path.
			pre := make([]techdetect.PrefetchedResponse, 0, len(httpxResult.Services))
			var freshURLs []string // live services HTTPX captured no payload for
			for _, s := range httpxResult.Services {
				if s.ResponseBody == "" && s.ResponseHeaders == "" {
					// HTTPX marked this live but captured NO payload (an empty or
					// timed-out HTTP response, a non-HTML/raw port). The old code
					// dropped it entirely — the fresh-fetch fallback below only
					// ran when `pre` was TOTALLY empty, so on a mixed run these
					// services got no tech detection at all (~45/scan observed).
					// Fresh-fetch them so they still get full detection.
					if s.URL != "" {
						freshURLs = append(freshURLs, s.URL)
					}
					continue
				}
				pre = append(pre, techdetect.PrefetchedResponse{
					URL:        s.URL,
					StatusCode: s.StatusCode,
					Headers:    s.ResponseHeaders,
					Body:       s.ResponseBody,
					Server:     s.Server,
				})
			}
			totalTD := len(pre) + len(freshURLs)
			// ONE progress tracker for both phases: stageProgress builds a fresh
			// monotonic tracker each call (seeded Update(0,"")), so calling it
			// twice made the bar climb during prefetch then snap back to 0 when
			// the fresh phase started. Offset the fresh numerator past `pre`.
			tdProgress := stageProgress(sr, totalTD)
			if len(pre) > 0 {
				techResult = techdetect.ScanFromPrefetched(pre, opts, tdProgress)
			}
			if len(freshURLs) > 0 {
				fresh := techdetect.ScanWithConfig(
					techdetect.Config{URLs: freshURLs, LightCapture: true}, opts,
					func(done int, msg string) { tdProgress(len(pre)+done, msg) }, nil)
				if techResult == nil {
					techResult = fresh
				} else {
					techResult.Results = append(techResult.Results, fresh.Results...)
				}
			}
		}
		if techResult == nil {
			techResult = techdetect.ScanWithConfig(
				techdetect.Config{URLs: urls, LightCapture: true}, opts,
				stageProgress(sr, len(urls)), nil)
		}
		// Aggregate technology count across all targets for the badge.
		techCount := 0
		for _, t := range techResult.Results {
			techCount += len(t.Technologies)
		}
		finishStage(sr, StatusDone,
			fmt.Sprintf("%d technologies across %d targets", techCount, len(techResult.Results)), techResult)
		bumpStage(6, "Tech Detection", fmt.Sprintf("%d techs", techCount))

		// Tech Detection has consumed the prefetched bodies (from the LIVE result);
		// free them now so they don't sit in memory for the rest of the suite. The
		// STORED httpxfind stage was already written body-free (httpxLite above).
		if httpxResult != nil {
			for i := range httpxResult.Services {
				httpxResult.Services[i].ResponseBody = ""
				httpxResult.Services[i].ResponseHeaders = ""
			}
		}
	}

	// ---------------- Stage 7: CVE Matcher ----------------
	// Consumes (product, version) pairs detected by Stage 6. Requires
	// techdetect output AND the DB lookup function; otherwise skip with
	// an explanatory message.
	if !enabledMap[StageCVEMatch] {
		if cfg.EnableCVEMatch && !cfg.EnableTechDetect {
			sr := startStage(StageCVEMatch)
			finishStage(sr, StatusSkipped,
				"CVE Matcher needs Tech Detection enabled — fed by its product/version output.", nil)
		} else {
			disableStage(StageCVEMatch)
		}
	} else if cveLookup == nil {
		sr := startStage(StageCVEMatch)
		finishStage(sr, StatusSkipped, "CVE Matcher unavailable (no DB lookup wired in).", nil)
	} else if techResult == nil || len(techResult.Results) == 0 {
		sr := startStage(StageCVEMatch)
		finishStage(sr, StatusSkipped, "No tech detection results to match against.", nil)
	} else {
		sr := startStage(StageCVEMatch)
		// Map techdetect output → cvematch.Input, one entry per
		// (URL × technology) pair so the matcher's source-URL stays
		// attached — but CLEAN the feed first, otherwise the CVE matcher
		// drowns in false positives:
		//
		//   (a) Skip CatSecurity technologies. HSTS/CSP are HTTP response
		//       headers and WAF/CAPTCHA hits are middleboxes — none are
		//       versioned products, so feeding them to a CVE database only
		//       manufactures bogus matches (one live run produced 501
		//       phantom "HSTS" inputs alone).
		//
		//   (b) De-duplicate by (canonical product, URL). A single IIS box
		//       surfaces under three fingerprint names — "IIS",
		//       "Microsoft IIS" and "Microsoft-IIS" — and only the last
		//       carries a version, so the version-less copies matched every
		//       IIS CVE (e.g. CVE-2017-7269 against IIS 10.0). Collapse the
		//       duplicates to one input, preferring the copy that actually
		//       carries a Version so the versioned entry wins.
		// Only NON-product security signals are CVE-irrelevant: response
		// headers (HSTS/CSP), CAPTCHAs and pure edge/WAF middleboxes have no
		// versioned product to match. Real security APPLIANCES in the same
		// category — F5 BIG-IP, Citrix NetScaler, FortiWeb, Kong, ModSecurity,
		// Wordfence — absolutely do carry CVEs (CitrixBleed, iControl RCE, …),
		// so the old blanket `CatSecurity → skip` hid them entirely (audit).
		nonProductSecurity := map[string]bool{
			"recaptcha": true, "hcaptcha": true, "hsts": true, "csp": true,
			"cloudflare waf": true, "aws waf": true, "barracuda waf": true,
			"akamai bot manager": true, "perimeterx": true, "datadome": true,
			"comodo cwatch": true, "aws api gateway": true,
			"cloudflare turnstile": true,
		}
		var inputs []cvematch.Input
		seenInput := map[string]int{} // canonical product+URL → index in inputs
		for _, tr := range techResult.Results {
			for _, t := range tr.Technologies {
				if t.Category == techdetect.CatSecurity && nonProductSecurity[strings.ToLower(t.Name)] {
					continue
				}
				key := canonProduct(t.Name) + "\x00" + tr.URL
				if idx, ok := seenInput[key]; ok {
					// Same product already seen for this URL — upgrade the
					// kept entry to the versioned copy if it has one.
					if inputs[idx].Version == "" && t.Version != "" {
						inputs[idx].Product = t.Name
						inputs[idx].Version = t.Version
					}
					continue
				}
				seenInput[key] = len(inputs)
				inputs = append(inputs, cvematch.Input{
					Product: t.Name,
					Version: t.Version,
					URL:     tr.URL,
					Source:  "techdetect",
					// The request/response that fingerprinted this tech, so a CVE
					// matched off it shows the evidencing exchange in its PoC.
					// Bounded so N techs on one URL don't each persist a 256 KB body.
					RawRequest:  capRawPoC(tr.RawRequest),
					RawResponse: capRawPoC(tr.RawResponse),
				})
			}
		}
		if len(inputs) == 0 {
			finishStage(sr, StatusSkipped,
				"Tech Detection found no products to match.", nil)
		} else {
			cveRes := cvematch.Scan(cvematch.Config{Inputs: inputs},
				stageProgress(sr, len(inputs)),
				func(pk string) []cvematch.CacheCVE { return cveLookup(pk) })
			// Severity badge — count critical+high for the bumpStage line.
			critHigh := 0
			for _, m := range cveRes.Matches {
				if m.Severity == "CRITICAL" || m.Severity == "HIGH" {
					critHigh++
				}
			}
			finishStage(sr, StatusDone,
				fmt.Sprintf("%d CVE matches (%d critical/high) across %d inputs",
					len(cveRes.Matches), critHigh, len(inputs)), cveRes)
			bumpStage(7, "CVE Matcher",
				fmt.Sprintf("%d matches", len(cveRes.Matches)))
		}
	}

	// ---------------- Stage 8: WPScan (gated on WordPress detection) ----
	// Only runs URLs where Tech Detection actually identified WordPress —
	// no point running WPScan on a Vue/Next.js site. Detection is by
	// fingerprint name match (case-insensitive) so any of "WordPress",
	// "WordPress.com", etc. count.
	if !enabledMap[StageWPScan] {
		if cfg.EnableWPScan && !cfg.EnableTechDetect {
			sr := startStage(StageWPScan)
			finishStage(sr, StatusSkipped,
				"WPScan needs Tech Detection enabled — it consumes its WordPress hits.", nil)
		} else {
			disableStage(StageWPScan)
		}
	} else if techResult == nil || len(techResult.Results) == 0 {
		sr := startStage(StageWPScan)
		finishStage(sr, StatusSkipped, "No tech detection results to inspect for WordPress.", nil)
	} else {
		sr := startStage(StageWPScan)
		// Collect URLs whose Technologies imply WordPress. Core markers
		// (/wp-content/, wp-json, generator=wordpress) are often absent on
		// CDN-rewritten sites, yet a WordPress-EXCLUSIVE plugin/theme is a
		// dead giveaway. Treat those as implying WordPress so WPScan isn't
		// skipped on a real WP site detected only via WooCommerce/Elementor/
		// Divi/Yoast/WP Rocket (audit: name=="wordpress*" gate too narrow).
		wpImplied := map[string]bool{
			"woocommerce": true, "elementor": true, "divi": true,
			"yoast seo": true, "wp rocket": true,
		}
		var wpURLs []string
		seen := map[string]bool{}
		for _, tr := range techResult.Results {
			for _, t := range tr.Technologies {
				name := strings.ToLower(t.Name)
				if strings.HasPrefix(name, "wordpress") || wpImplied[name] {
					if !seen[tr.URL] {
						wpURLs = append(wpURLs, tr.URL)
						seen[tr.URL] = true
					}
					break
				}
			}
		}
		if len(wpURLs) == 0 {
			finishStage(sr, StatusSkipped,
				"Tech Detection found no WordPress instances — nothing for WPScan to probe.", nil)
		} else {
			wpSpeed := wpscan.SpeedFast
			switch cfg.WPScanSpeed {
			case "normal":
				wpSpeed = wpscan.SpeedNormal
			case "aggressive":
				wpSpeed = wpscan.SpeedAggressive
			}
			// Hoist tracker construction out of the per-callback closure
			// (audit B-wpscan-progress-rebuild). The previous form
			// allocated a fresh shared.ProgressTracker on every wpscan
			// emit, which reset its monotonic-clamp state to zero and
			// re-wrote sr.ProgressDone=0 before each update fired —
			// defeating the clamp entirely and flickering the bar.
			wpProgress := stageProgress(sr, len(wpURLs))
			wpRes := wpscan.ScanWithConfig(ctx, wpscan.Config{URLs: wpURLs, Speed: wpSpeed, Opts: opts}, wpProgress, nil)
			findingCount := 0
			if wpRes != nil {
				for _, t := range wpRes.Results {
					findingCount += len(t.Findings)
				}
			}
			finishStage(sr, StatusDone,
				fmt.Sprintf("%d WordPress targets · %d findings", len(wpURLs), findingCount),
				wpRes)
			bumpStage(8, "WPScan", fmt.Sprintf("%d findings", findingCount))
		}
	}

	// ---------------- Stage 9: Nuclei ----------------
	if !enabledMap[StageNuclei] {
		disableStage(StageNuclei)
	} else if httpxResult != nil && len(httpxResult.Services) == 0 && !hasDNSSubdomains(dnsResult) {
		// HTTPX ran and confirmed ZERO live services, and DNS discovered no
		// subdomains either — there is nothing reachable to scan. Running
		// nuclei against the unreachable fallback host list just makes it
		// exit non-zero and (previously) failed the WHOLE suite with a
		// misleading "OOM" error. Skip it cleanly instead.
		sr := startStage(StageNuclei)
		finishStage(sr, StatusSkipped, "no live services to scan — every target was unreachable", nil)
		bumpStage(9, "Nuclei", "skipped · no live services")
	} else {
		sr := startStage(StageNuclei)
		severities := cfg.NucleiSeverities
		if len(severities) == 0 {
			severities = []string{"critical", "high", "medium"}
		}
		nucleiSeeds := seedURLs()
		// Up-front honesty: 'low'/'info' severity runs nuclei's full
		// template set (~thousands). Over many hosts that is a multi-hour
		// job that will very likely hit the time cap and be reported
		// INCOMPLETE. Surface it before the run so a truncated result is
		// not a surprise (the operator saw "0 findings in 90 min" and
		// rightly suspected something was wrong).
		heavy := false
		for _, s := range severities {
			if s == "low" || s == "info" {
				heavy = true
			}
		}
		if heavy && len(nucleiSeeds) > 50 {
			resultMu.Lock()
			result.Notes = append(result.Notes, fmt.Sprintf(
				"Nuclei: 'low'/'info' severity across %d hosts runs the full template set — this is a multi-hour job and may hit the time cap and be reported INCOMPLETE. For a complete pass, drop 'low'+'info' severity or scan fewer hosts.",
				len(nucleiSeeds)))
			resultMu.Unlock()
		}
		// Aggressiveness preset (polite/normal/aggressive) sets rate-limit +
		// concurrency + bulk-size together — the same mapping the standalone
		// nuclei module uses. When no level is chosen we keep the historical
		// behaviour: nuclei's own default rate limit + a >=25 concurrency floor
		// (nuclei is a bulk scanner; the gentle web rate limit would turn a big
		// scan into a multi-day one).
		nucleiCfg := nuclei.ScanConfig{Severity: severities, Opts: opts}
		// A single-finding rescan narrows the stage to just the template(s) that
		// produced the finding being verified, so re-checking one nuclei hit runs
		// `nuclei -t <template-id>` on the host instead of the whole template set.
		if len(cfg.NucleiTemplateIDs) > 0 {
			nucleiCfg.TemplateIDs = cfg.NucleiTemplateIDs
		}
		if cfg.NucleiLevel != "" {
			rl, conc, bulk := nuclei.LevelSettings(cfg.NucleiLevel)
			nucleiCfg.RateLimit, nucleiCfg.Concurrency, nucleiCfg.BulkSize = rl, conc, bulk
		} else {
			nucleiConc := concurrency
			if nucleiConc < 25 {
				nucleiConc = 25
			}
			nucleiCfg.Concurrency = nucleiConc
		}
		nucleiRes := nuclei.Scan(ctx, nucleiSeeds, nucleiCfg, stageProgress(sr, len(nucleiSeeds)), nil)
		findingCount := 0
		for _, t := range nucleiRes.Results {
			findingCount += len(t.Findings)
		}
		if nucleiRes.Truncated {
			// Report the truncation as an error state with the full reason
			// so the UI shows it clearly instead of a green "done". The
			// scan did not fail — it ran out of time — but the result is
			// INCOMPLETE and must not be presented as a clean pass.
			finishStage(sr, StatusError,
				"INCOMPLETE — "+nucleiRes.TruncateReason, nucleiRes)
			// Don't hardcode "(time cap)" — the reason may be an abnormal exit
			// (unreachable targets, missing templates), not the wall-clock cap.
			bumpStage(9, "Nuclei", fmt.Sprintf("INCOMPLETE · %d findings", findingCount))
			// Propagate to the suite level so the Scans list / dashboard
			// badge and the results top-banner reflect the incomplete run
			// (a stage-only StatusError would leave the scan row green).
			resultMu.Lock()
			if !result.Incomplete {
				result.Incomplete = true
				result.IncompleteReason = "Nuclei stage INCOMPLETE — " + nucleiRes.TruncateReason
			}
			resultMu.Unlock()
		} else {
			finishStage(sr, StatusDone,
				fmt.Sprintf("%d findings", findingCount), nucleiRes)
			bumpStage(9, "Nuclei", fmt.Sprintf("%d findings", findingCount))
		}
	}

	// ---------------- Stage 10: DirEnum ↔ Spider iterative cross-feed ----------------
	type dirSpiderCombined struct {
		DirEnum *direnum.ScanResult `json:"direnum,omitempty"`
		Spider  *spider.ScanResult  `json:"spider,omitempty"`
		// IterationLog records each cross-feed round so the UI can show
		// the back-and-forth.
		IterationLog []string `json:"iteration_log,omitempty"`
	}
	if !enabledMap[StageDirSpider] {
		disableStage(StageDirSpider)
	} else {
		sr := startStage(StageDirSpider)
		// Hard deadline on stage 8 — see stage8MaxDuration. We build a
		// derived context and a shallow copy of opts with that context
		// so the sub-modules' HTTP calls bail out when the deadline
		// fires, regardless of how deep the iterative loop is.
		stageCtx, stageCancel := context.WithTimeout(ctx, stage8MaxDuration)
		// Use HTTPOptions.WithCtx so the derived options copy preserves
		// LocalAddr + NetworkInterface (killswitch Layer-2 source-IP
		// binding) and OnWarning/ErrorThreshold (error telemetry). The
		// previous hand-rolled struct literal silently dropped both
		// (audit B-stageOpts-shallow-copy); only the global LocalAddr
		// fallback kept traffic on the pinned interface.
		stageOpts := opts.WithCtx(stageCtx)
		profiles := []string{"general"}
		if techResult != nil {
			techs := []techdetect.Technology{}
			for _, t := range techResult.Results {
				techs = append(techs, t.Technologies...)
			}
			profiles = TechToDirenumProfiles(techs)
			resultMu.Lock()
			result.Notes = append(result.Notes,
				fmt.Sprintf("Directory + Spider profiles auto-selected from tech detection: %s", strings.Join(profiles, ",")))
			resultMu.Unlock()
		}
		level := direnum.LevelNormal
		switch cfg.DirEnumLevel {
		case "light":
			level = direnum.LevelLight
		case "aggressive":
			level = direnum.LevelAggressive
		}
		direnumCfg := direnum.ScanConfig{
			Techs:       profiles,
			Level:       level,
			SmartScan:   cfg.DirEnumSmartScan,
			Concurrency: concurrency,
			Timeout:     10 * time.Second,
			Recursive:   cfg.DirEnumRecursive,
			MaxDepth:    cfg.DirEnumMaxDepth,
		}
		spiderCfg := spider.SpiderConfig{
			MaxDepth:    cfg.SpiderMaxDepth,
			MaxPages:    cfg.SpiderMaxPages,
			Concurrency: concurrency,
			Timeout:     10 * time.Second,
		}
		if spiderCfg.MaxDepth <= 0 {
			spiderCfg.MaxDepth = 3
		}
		if spiderCfg.MaxPages <= 0 {
			spiderCfg.MaxPages = 200
		}

		combined := &dirSpiderCombined{
			DirEnum: &direnum.ScanResult{},
			Spider:  &spider.ScanResult{},
		}
		seenDirenum := map[string]bool{}
		seenSpider := map[string]bool{}
		seeds := seedURLs()
		const maxIter = 3
		// DirEnum + Spider runs up to maxIter iterations, each iteration
		// alternating direnum then spider. 2 sub-steps per iter × maxIter
		// = maxIter*2 total slots. The per-stage progress bar advances
		// 1 unit each time one sub-step completes — gives the user a
		// concrete % even though the inner work is arbitrary.
		dsEmit := stageProgress(sr, maxIter*2)
		dsStep := 0
		stageHitDeadline := false
		for iter := 1; iter <= maxIter && len(seeds) > 0 && stageCtx.Err() == nil; iter++ {
			// Filter out already-direnum'd seeds.
			fresh := []string{}
			for _, u := range seeds {
				if !seenDirenum[u] {
					fresh = append(fresh, u)
					seenDirenum[u] = true
				}
			}
			if len(fresh) == 0 {
				break
			}
			combined.IterationLog = append(combined.IterationLog,
				fmt.Sprintf("iter %d: direnum on %d seed URLs", iter, len(fresh)))

			// Live mid-iteration streaming: every time direnum emits a
			// partial we splice it into combined.DirEnum.Results,
			// pushPartial() so the suite results page shows entries as
			// they're discovered, AND emit a liveProgress so the top
			// status line shows running totals instead of being stuck
			// on the previous stage's completion message.
			//
			// Throttle the JSON marshal (audit B64). Previously every
			// per-page partial called json.Marshal(combined) — an O(N)
			// operation per call. With N up to ~10k entries across iters,
			// that's O(N²) = quadratic total work + GC pressure that
			// pinned the heap. Now we marshal at most every 1500 ms;
			// in between we just update the in-memory combined slice
			// and rely on the heartbeat goroutine to flush.
			direnumPrev := len(combined.DirEnum.Results)
			var lastMarshalDE time.Time
			// direnum.ScanFull fires its partial callback from worker
			// goroutines concurrently (audit B-direnum-partial-race).
			// Serialise every closure body with a per-iter mutex so
			// the slice mutation + JSON marshal + sr.Result write are
			// atomic with respect to each other.
			var deMu sync.Mutex
			direnumRes := direnum.ScanFull(fresh, direnumCfg, stageOpts,
				func(p *direnum.ScanResult) {
					if p == nil {
						return
					}
					deMu.Lock()
					defer deMu.Unlock()
					combined.DirEnum.Results = append(combined.DirEnum.Results[:direnumPrev:direnumPrev], p.Results...)
					running := 0
					for _, tr := range combined.DirEnum.Results {
						running += tr.TotalFound
					}
					liveProgress("Directory + Spider", fmt.Sprintf("direnum iter %d · %d entries discovered", iter, running))
					// Throttle the expensive serialization to once per
					// 1.5s; UI heartbeat picks it up on its next tick.
					if time.Since(lastMarshalDE) >= 1500*time.Millisecond {
						b, _ := json.Marshal(combined)
						resultMu.Lock()
						sr.Result = b
						resultMu.Unlock()
						lastMarshalDE = time.Now()
						pushPartial()
					}
				},
				func(int, string) {}, nil)
			deMu.Lock()
			combined.DirEnum.Results = append(combined.DirEnum.Results[:direnumPrev:direnumPrev], direnumRes.Results...)
			// One forced marshal at end-of-stage so the final partial
			// matches the canonical combined state.
			b, _ := json.Marshal(combined)
			deMu.Unlock()
			resultMu.Lock()
			sr.Result = b
			resultMu.Unlock()
			pushPartial()
			dsStep++
			dsEmit(dsStep, fmt.Sprintf("iter %d: direnum done (%d entries)", iter, len(direnumRes.Results)))

			// Spider seeds = newly-discovered dir entries spider hasn't crawled yet.
			spiderSeeds := []string{}
			for _, tr := range direnumRes.Results {
				for _, e := range tr.Entries {
					if e.IsDir && !seenSpider[e.URL] {
						spiderSeeds = append(spiderSeeds, e.URL)
						seenSpider[e.URL] = true
					}
				}
			}
			if len(spiderSeeds) == 0 {
				combined.IterationLog = append(combined.IterationLog,
					fmt.Sprintf("iter %d: no new dirs from direnum, stopping", iter))
				break
			}
			combined.IterationLog = append(combined.IterationLog,
				fmt.Sprintf("iter %d: spider on %d dirs from direnum", iter, len(spiderSeeds)))

			// Run spider with shallower depth on these specific dir URLs.
			shallow := spiderCfg
			if shallow.MaxDepth > 1 {
				shallow.MaxDepth = 1
			}
			// Same live-streaming treatment for spider's partials —
			// throttled marshal (audit B64) to keep O(N²) JSON work
			// bounded on long crawls.
			spiderPrev := len(combined.Spider.Results)
			var lastMarshalSp time.Time
			// spider.Scan also fires partials concurrently from workers
			// (audit B-spider-partial-race) — same per-iter mutex pattern
			// as direnum above.
			var spMu sync.Mutex
			spiderRes := spider.Scan(spiderSeeds, shallow, stageOpts,
				func(p *spider.ScanResult) {
					if p == nil {
						return
					}
					spMu.Lock()
					defer spMu.Unlock()
					combined.Spider.Results = append(combined.Spider.Results[:spiderPrev:spiderPrev], p.Results...)
					running := 0
					for _, tr := range combined.Spider.Results {
						running += len(tr.Resources)
					}
					liveProgress("Directory + Spider", fmt.Sprintf("spider iter %d · %d resources crawled", iter, running))
					if time.Since(lastMarshalSp) >= 1500*time.Millisecond {
						b, _ := json.Marshal(combined)
						resultMu.Lock()
						sr.Result = b
						resultMu.Unlock()
						lastMarshalSp = time.Now()
						pushPartial()
					}
				},
				func(int, string) {})
			spMu.Lock()
			combined.Spider.Results = append(combined.Spider.Results[:spiderPrev:spiderPrev], spiderRes.Results...)
			// Forced final marshal so canonical state matches partial.
			b2, _ := json.Marshal(combined)
			spMu.Unlock()
			resultMu.Lock()
			sr.Result = b2
			resultMu.Unlock()
			pushPartial()
			dsStep++
			dsEmit(dsStep, fmt.Sprintf("iter %d: spider done (%d resources)", iter, len(spiderRes.Results)))

			// Next-iteration direnum seeds = directory resources the spider
			// found that direnum hasn't already covered.
			nextSeeds := []string{}
			for _, tr := range spiderRes.Results {
				for _, r := range tr.Resources {
					if r.Type == spider.TypeDirectory && !seenDirenum[r.URL] {
						nextSeeds = append(nextSeeds, r.URL)
					}
				}
			}
			if len(nextSeeds) == 0 {
				combined.IterationLog = append(combined.IterationLog,
					fmt.Sprintf("iter %d: no new dirs from spider, stopping", iter))
				break
			}
			seeds = nextSeeds
		}
		// If the deadline fired mid-iteration, mark the iteration log
		// so the user understands why stage 8 stopped early.
		if stageCtx.Err() == context.DeadlineExceeded {
			stageHitDeadline = true
			combined.IterationLog = append(combined.IterationLog,
				fmt.Sprintf("stopped: stage hit %s deadline", stage8MaxDuration))
		}
		stageCancel()

		dirCount := 0
		for _, tr := range combined.DirEnum.Results {
			dirCount += tr.TotalFound
		}
		spiderCount := 0
		for _, tr := range combined.Spider.Results {
			spiderCount += len(tr.Resources)
		}
		stageStatus := StatusDone
		stageMsg := fmt.Sprintf("direnum=%d entries · spider=%d resources · profiles=%s",
			dirCount, spiderCount, strings.Join(profiles, ","))
		if stageHitDeadline {
			// Keep the stage status as Done — the iterative loop hit
			// its wall-clock budget but still produced usable partial
			// results, and downstream stages (HTTP Methods, Security
			// Headers) need to be able to consume them via pickURLSource
			// (audit B-deadline-status). Surface the deadline via
			// sr.Error + result.Notes so the timeline + Suite Notes
			// panel still flag it prominently.
			stageMsg = fmt.Sprintf("deadline (%s) reached — partial results: direnum=%d entries · spider=%d resources",
				stage8MaxDuration, dirCount, spiderCount)
			sr.Error = "Directory + Spider stage exceeded its " + stage8MaxDuration.String() + " budget; partial results returned"
			// Under resultMu: the heartbeat goroutine marshals result
			// (incl. Notes/Incomplete) concurrently.
			resultMu.Lock()
			result.Notes = append(result.Notes, sr.Error)
			if !result.Incomplete {
				result.Incomplete = true
				result.IncompleteReason = sr.Error
			}
			resultMu.Unlock()
		}
		finishStage(sr, stageStatus, stageMsg, combined)
		bumpStage(10, "Directory + Spider",
			fmt.Sprintf("%d entries · %d resources", dirCount, spiderCount))
	}

	// Helper for stages 11/12: pick URL source per the dependency chain
	// — direnum > httpxfind > dnsenum > input.
	pickURLSource := func() []string {
		out := []string{}
		seen := map[string]bool{}
		add := func(u string) {
			if u != "" && !seen[u] {
				seen[u] = true
				out = append(out, u)
			}
		}

		// 1. HTTPX live services — the BASE coverage. Every live host must be
		//    method-probed / header-analysed, at ANY status: 401/403/405/5xx is
		//    exactly where a missing-header or loose-method finding matters.
		//    (audit: the old code returned ONLY direnum entries once DirSpider
		//    produced any entry, silently dropping every httpx service whose root
		//    the wordlist didn't re-surface — the same httpx-drop class as the
		//    techdetect empty-payload bug.)
		if httpxResult != nil {
			for _, s := range httpxResult.Services {
				add(s.URL)
			}
		}

		// 2. Directory entries — ADDITIVE (extra alive sub-paths worth probing),
		//    not a replacement for the httpx set. Accept Done and Error (deadline)
		//    statuses: a deadline hit still leaves usable partial results in
		//    ds.Result (audit B-deadline-status). Keep the 200–399 filter here:
		//    root-level 401/403/5xx services are already covered via the httpx
		//    set above (httpx keeps live services at any status), so we don't
		//    also fan every 403/401 brute-forced SUB-path into method/header
		//    probing — on a protected app that's thousands of low-value URLs.
		ds := result.Stages[StageDirSpider]
		if ds != nil && (ds.Status == StatusDone || ds.Status == StatusError) && len(ds.Result) > 0 {
			var combined dirSpiderCombined
			if json.Unmarshal(ds.Result, &combined) == nil && combined.DirEnum != nil {
				for _, tr := range combined.DirEnum.Results {
					for _, e := range tr.Entries {
						if e.StatusCode >= 200 && e.StatusCode < 400 {
							add(e.URL)
						}
					}
				}
			}
		}
		if len(out) > 0 {
			return out
		}

		// 3. DNS subdomains (formatted as https://).
		if dnsResult != nil {
			for _, dr := range dnsResult.Results {
				for _, sub := range dr.Subdomains {
					add("https://" + sub.Subdomain)
				}
			}
			if len(out) > 0 {
				return out
			}
		}

		// 4. All user-supplied inputs (multi-target safe).
		for _, c := range allClassified {
			add(c.EnsureURL())
		}
		return out
	}

	// ---------------- Stage 12: HTTP Methods ----------------
	var methodsResult *httpmethods.ScanResult
	if !enabledMap[StageHTTPMethods] {
		disableStage(StageHTTPMethods)
	} else {
		sr := startStage(StageHTTPMethods)
		urls := pickURLSource()
		methodsResult = httpmethods.ScanWithPartial(urls, opts, concurrency,
			stageProgress(sr, len(urls)), nil)
		finishStage(sr, StatusDone,
			fmt.Sprintf("%d URLs probed", len(methodsResult.Results)), methodsResult)
		bumpStage(12, "HTTP Methods", fmt.Sprintf("%d URLs", len(methodsResult.Results)))
	}

	// ---------------- Stage 13: Security Headers ----------------
	// Methods are auto-derived per spec ("11, 10'dan elde edilen bilgiler
	// kullanılarak"). If stage 10 ran, take the union of methods that any
	// URL responded successfully to (2xx), filtered to {GET,POST,PUT}.
	// If stage 10 didn't run, default to GET only.
	if !enabledMap[StageSecHeaders] {
		disableStage(StageSecHeaders)
	} else {
		sr := startStage(StageSecHeaders)
		urls := pickURLSource()

		filtered := []string{}
		if cfg.SecHeadersOverride && len(cfg.SecHeadersMethods) > 0 {
			// User explicitly picked the methods — skip auto-derive.
			for _, m := range cfg.SecHeadersMethods {
				up := strings.ToUpper(strings.TrimSpace(m))
				if up == "GET" || up == "POST" || up == "PUT" {
					filtered = append(filtered, up)
				}
			}
			resultMu.Lock()
			result.Notes = append(result.Notes,
				fmt.Sprintf("Security Headers methods set manually: %s", strings.Join(filtered, ",")))
			resultMu.Unlock()
		} else {
			methodSet := map[string]bool{}
			if methodsResult != nil {
				for _, ur := range methodsResult.Results {
					for _, mr := range ur.Methods {
						if mr.StatusCode >= 200 && mr.StatusCode < 300 {
							up := strings.ToUpper(mr.Method)
							if up == "GET" || up == "POST" || up == "PUT" {
								methodSet[up] = true
							}
						}
					}
				}
			}
			for _, m := range []string{"GET", "POST", "PUT"} { // stable order
				if methodSet[m] {
					filtered = append(filtered, m)
				}
			}
			resultMu.Lock()
			if methodsResult != nil {
				result.Notes = append(result.Notes,
					fmt.Sprintf("Security Headers methods auto-derived from HTTP Methods' successful responses: %s", strings.Join(filtered, ",")))
			} else {
				result.Notes = append(result.Notes,
					"Security Headers methods defaulted to GET (HTTP Methods stage was disabled)")
			}
			resultMu.Unlock()
		}
		if len(filtered) == 0 {
			filtered = []string{"GET"}
		}
		shRes := secheaders.Scan(urls, opts, concurrency, filtered, stageProgress(sr, len(urls)), nil)
		finishStage(sr, StatusDone,
			fmt.Sprintf("%d URLs · methods=%s", len(shRes.Results), strings.Join(filtered, ",")), shRes)
		bumpStage(13, "Security Headers",
			fmt.Sprintf("%d URLs", len(shRes.Results)))
	}

	result.FinishedAt = time.Now()
	pushPartial()
	out = result
	return out, nil
}

// AbsURL is a tiny helper used by templates: takes a path and a base
// URL and returns the absolute form. Exposed via Go template funcMap if
// needed; not required for current templates but documented here.
func AbsURL(base, path string) string {
	if base == "" {
		return path
	}
	if strings.HasPrefix(path, "http://") || strings.HasPrefix(path, "https://") {
		return path
	}
	u, err := url.Parse(base)
	if err != nil {
		return path
	}
	u.Path = strings.TrimRight(u.Path, "/") + "/" + strings.TrimLeft(path, "/")
	return u.String()
}

// canonProduct reduces a techdetect product name to a stable de-duplication
// key so the same server reported under slightly different fingerprint names
// collapses to one cvematch input. It lowercases, folds "-"/"_" to spaces,
// squeezes whitespace and drops a leading "microsoft " vendor token, so
// "IIS", "Microsoft IIS" and "Microsoft-IIS" all normalise to "iis". This is
// used only for de-duplication — the original Product string is preserved on
// the surviving Input so cvematch does its own canonicalisation downstream.
func canonProduct(name string) string {
	s := strings.ToLower(strings.TrimSpace(name))
	s = strings.ReplaceAll(s, "-", " ")
	s = strings.ReplaceAll(s, "_", " ")
	s = strings.Join(strings.Fields(s), " ")
	s = strings.TrimPrefix(s, "microsoft ")
	return s
}

// capRawPoC bounds a captured raw request/response before it's embedded into a
// per-tech CVE match, so the persisted result doesn't carry a full 256 KB
// response copy for every technology detected on the same URL. 16 KB matches
// the vuln index's own PoC-enrichment cap, so nothing is lost downstream.
func capRawPoC(s string) string {
	const cap = 16 * 1024
	if len(s) <= cap {
		return s
	}
	return s[:cap] + "\n... [truncated]"
}

// httpxLite returns a copy of an httpx result with the heavy per-service response
// bodies/headers stripped — for STORAGE in the httpxfind stage. The live result
// retains them (Tech Detection's prefetched path reuses them); persisting them
// would be ~256 KB × every live service (hundreds of MB → 50 MB-cap truncation).
func httpxLite(r *httpxfind.ScanResult) *httpxfind.ScanResult {
	if r == nil {
		return nil
	}
	cp := *r
	cp.Services = make([]httpxfind.ServiceResult, len(r.Services))
	copy(cp.Services, r.Services)
	for i := range cp.Services {
		// All four heavy per-service fields: the parsed body/headers AND httpxfind's
		// own Burp-Repeater raw request/response dump (CaptureResponse alone is ~256 KB
		// each) — a few hundred live services × ~256 KB is what still hit the cap.
		cp.Services[i].ResponseBody = ""
		cp.Services[i].ResponseHeaders = ""
		cp.Services[i].RawRequest = ""
		cp.Services[i].RawResponse = ""
	}
	return &cp
}
