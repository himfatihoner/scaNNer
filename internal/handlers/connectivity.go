package handlers

import (
	"context"
	"encoding/json"
	"log"
	"net"
	"net/http"
	"strings"
	"sync/atomic"
	"time"

	"scanner/internal/models"
	"scanner/internal/modules/advancedweb"
	"scanner/internal/modules/direnum"
	"scanner/internal/modules/shared"
	"scanner/internal/modules/spider"
)

// Connectivity monitor (Task 0b/0c). Independent of the killswitch iface
// monitor: it watches whether the internet is REACHABLE and, on loss, PAUSES
// every running scan (preserving its partial result) instead of letting the
// scans die. When reachability returns it auto-resumes the paused scans from
// where they left off.
//
// Rationale for a reachability probe (not just iface-up): a live-but-dead link
// (upstream router down, VPN tunnel up but dead, ISP outage, or the operator's
// own scan saturating the link) leaves the interface UP yet drops all new
// connections — exactly the case that lost the operator's HTTPX work.

const (
	connProbeInterval = 5 * time.Second
	connProbeTimeout  = 3 * time.Second
	// Require this many consecutive failed probes before pausing, so a single
	// transient blip doesn't pause everything (~15s of real loss to trip).
	connFailThreshold = 3
	// After an auto-resume, wait this long before the monitor is allowed to
	// pause again — dampens any resume→saturate→pause flap.
	connResumeCooldown = 30 * time.Second

	// --- Graded degradation (Task: adaptive network governor) ---
	// A stable name resolved via the SYSTEM resolver each tick — this measures
	// the operator's REAL DNS path (resolv.conf), which a raw 53/tcp dial to a
	// hardcoded IP misses (the exact failure mode of the VPN-drop incident:
	// fallback resolver answered the dial while the configured one stalled 8s).
	connDNSName    = "cloudflare.com"
	connDNSTimeout = 2 * time.Second
	// System DNS slower than this (but still resolving) = degraded, not down.
	connDegradeDNS = 1200 * time.Millisecond
	// Consecutive degraded samples before engaging the throttle (~10s).
	connDegradeStreak = 2
	// Throttle applied to ALL Go-side outbound while degraded: space new
	// connections ~40ms apart (~25/s) and add a 150ms per-connection pause, so
	// the scan eases off the strained link instead of saturating it further.
	connThrottleInterval = 40 * time.Millisecond
	connThrottleDelay    = 150 * time.Millisecond
)

// connProbeHosts are well-known anycast IPs; a 443/tcp handshake is the
// reachability signal. Port 443 (NOT 53) on purpose: many networks — including
// restrictive NAT/corporate egress and the environment scaNNer commonly runs in
// — BLOCK outbound DNS (53) to anything but their sanctioned resolver while
// allowing HTTPS. Probing 53 there gives a permanent false "internet down"
// (pausing scans + skipping auto-resume) even though the real scan path (443)
// is fine. 443 mirrors what the scans actually use and is the most universally
// open port, so the probe reflects true reachability.
var connProbeHosts = []string{"1.1.1.1:443", "8.8.8.8:443", "9.9.9.9:443"}

// netHealth is the graded network state driving the governor.
type netHealth int

const (
	netHealthy  netHealth = iota // full speed
	netDegraded                  // partial reachability or slow DNS → throttle + warn
	netDown                      // no reachability → pause
)

// netHealthState publishes the latest classification for the header connectivity
// indicator. Written by the monitor each tick; read by /api/health (no live
// probe → instant).
var netHealthState atomic.Int32

// netHealthLabel maps the published state to the string the UI polls for.
func netHealthLabel() string {
	switch netHealth(netHealthState.Load()) {
	case netDegraded:
		return "degraded"
	case netDown:
		return "down"
	default:
		return "ok"
	}
}

// netSample is one tick's measurement of the egress path.
type netSample struct {
	reachable  int           // probe hosts that answered (0..len(connProbeHosts))
	dnsOK      bool          // system resolver answered within connDNSTimeout
	dnsLatency time.Duration // how long the system-resolver lookup took
}

// probeNetwork measures reachability (via BoundDialer, exempt from the throttle
// so it reflects the REAL path) plus the system-resolver DNS latency.
func probeNetwork() netSample {
	s := netSample{}
	for _, host := range connProbeHosts {
		ctx, cancel := context.WithTimeout(shared.WithoutThrottle(context.Background()), connProbeTimeout)
		conn, err := shared.BoundDialer(nil, connProbeTimeout).DialContext(ctx, "tcp", host)
		cancel()
		if err == nil {
			conn.Close()
			s.reachable++
		}
	}
	ctx, cancel := context.WithTimeout(context.Background(), connDNSTimeout)
	start := time.Now()
	_, err := net.DefaultResolver.LookupHost(ctx, connDNSName)
	s.dnsLatency = time.Since(start)
	cancel()
	s.dnsOK = err == nil
	return s
}

// classify maps a sample to a health tier. DOWN = nothing answers; DEGRADED =
// reachable but the majority of probes fail OR the system DNS is slow/failing;
// otherwise HEALTHY.
func classify(s netSample) netHealth {
	if s.reachable == 0 {
		return netDown
	}
	if s.reachable < 2 || !s.dnsOK || s.dnsLatency > connDegradeDNS {
		return netDegraded
	}
	return netHealthy
}

// checkInternet reports whether any probe host is reachable (used by the
// startup resume path). Kept as a thin wrapper over probeNetwork.
func checkInternet() bool { return probeNetwork().reachable > 0 }

// Health reports the current network-connectivity status for the header
// indicator. It reads the cached monitor state (no live probe), so it's instant
// and safe to poll frequently.
func (h *Handler) Health(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	w.Write([]byte(`{"status":"` + netHealthLabel() + `"}`))
}

// StartConnectivityMonitor launches the background reachability watcher. Call
// once at startup. It only acts while scans are live (pause) or paused
// (resume), so an idle app just does a cheap 53/tcp dial every 5s.
func (h *Handler) StartConnectivityMonitor() {
	go func() {
		ticker := time.NewTicker(connProbeInterval)
		defer ticker.Stop()
		up := true // assume reachable at boot
		netHealthState.Store(int32(netHealthy))
		downFails := 0
		degradeStreak := 0
		throttled := false
		var lastResume time.Time

		// VPN watchdog local state (only used when Settings enables it).
		var vpnDownSince, lastReconnect time.Time
		var reconnecting atomic.Bool

		// clearThrottle releases the degradation throttle + warning (on recovery).
		clearThrottle := func() {
			if throttled {
				shared.SetNetworkThrottle(0, 0)
				h.scanMgr.WarnAll("")
				throttled = false
				log.Printf("connectivity: network recovered — throttle released")
			}
		}

		for range ticker.C {
			// --- VPN watchdog gate (runs before the internet classification) ---
			// When enabled, a dead VPN device forces a pause + active reconnect
			// EVEN IF plain internet is still reachable via another iface — so no
			// scan traffic leaks off the tunnel, and the scan resumes once it's
			// back. Precedence over the reachability logic below is deliberate.
			if st := h.db.GetSettings(); st.VPNAutoReconnect && st.VPNConnection != "" {
				iface := st.EffectiveVPNInterface()
				if !vpnInterfaceHealthy(iface) {
					if vpnDownSince.IsZero() {
						vpnDownSince = time.Now()
						log.Printf("vpn-watchdog: %s down — pausing scans; will reconnect %q", iface, st.VPNConnection)
					}
					if ids := h.scanMgr.ActiveIDs(); len(ids) > 0 {
						h.scanMgr.PauseAll("Paused — VPN (" + iface + ") koptu; otomatik reconnect + kaldığı yerden devam. · VPN down; auto-reconnecting.")
					}
					clearThrottle()
					up = false
					netHealthState.Store(int32(netDown)) // VPN down → report offline
					// After the grace period, fire one reconnect at a time (cooldown-spaced).
					grace := time.Duration(st.EffectiveVPNReconnectAfterSec()) * time.Second
					if !reconnecting.Load() && time.Since(vpnDownSince) >= grace && time.Since(lastReconnect) >= vpnReconnectCooldown {
						reconnecting.Store(true)
						lastReconnect = time.Now()
						name := st.VPNConnection
						go func() {
							defer reconnecting.Store(false)
							if err := reconnectVPN(name); err != nil {
								log.Printf("vpn-watchdog: reconnect %q failed: %v", name, err)
							} else {
								log.Printf("vpn-watchdog: reconnect %q issued — waiting for %s to come up", name, iface)
							}
						}()
					}
					continue // skip the reachability logic while the VPN is down
				}
				if !vpnDownSince.IsZero() {
					log.Printf("vpn-watchdog: %s back up", iface)
					vpnDownSince = time.Time{}
				}
			}

			sample := probeNetwork()
			hlth := classify(sample)
			netHealthState.Store(int32(hlth)) // publish for the header indicator
			switch hlth {

			case netHealthy:
				downFails, degradeStreak = 0, 0
				clearThrottle()
				if !up { // recovered from a pause
					if n := h.resumePausedScans(); n > 0 {
						log.Printf("connectivity: internet restored — auto-resumed %d paused scan(s)", n)
						lastResume = time.Now()
					}
					up = true
				}

			case netDegraded:
				downFails = 0
				degradeStreak++
				// Engage the throttle after a short streak so a one-tick blip
				// doesn't slow everything.
				if degradeStreak >= connDegradeStreak && !throttled {
					shared.SetNetworkThrottle(connThrottleInterval, connThrottleDelay)
					throttled = true
					log.Printf("connectivity: network degraded (dns=%s, reachable=%d/%d) — throttling scans",
						sample.dnsLatency.Round(time.Millisecond), sample.reachable, len(connProbeHosts))
					h.scanMgr.WarnAll("⚠ Ağ yavaşladı — tarama otomatik yavaşlatıldı · Network degraded — scan auto-throttled")
				}
				// Partial connectivity is enough to make (throttled) progress: if
				// we were paused by a full loss, resume now rather than waiting
				// for full health.
				if !up {
					if n := h.resumePausedScans(); n > 0 {
						log.Printf("connectivity: partial connectivity — resumed %d paused scan(s) (throttled)", n)
						lastResume = time.Now()
					}
					up = true
				}

			case netDown:
				degradeStreak = 0
				downFails++
				if !up || downFails < connFailThreshold {
					continue
				}
				if time.Since(lastResume) < connResumeCooldown {
					continue // just resumed — don't immediately re-pause (anti-flap)
				}
				if ids := h.scanMgr.ActiveIDs(); len(ids) > 0 {
					log.Printf("connectivity: internet unreachable — pausing %d running scan(s)", len(ids))
					h.scanMgr.PauseAll("Paused — internet connectivity lost; the scan will resume automatically when the connection is back.")
				}
				// A pause supersedes throttling; drop it so a fresh resume starts clean.
				clearThrottle()
				up = false
			}
		}
	}()
}

// ResumePausedOnStartup resumes scans left 'paused' by a prior process — but
// only if the internet is currently up. If it's down, the running monitor will
// resume them when connectivity returns.
func (h *Handler) ResumePausedOnStartup() int {
	if !checkInternet() {
		return 0
	}
	return h.resumePausedScans()
}

// resumePausedScans re-dispatches every paused scan in every workspace, each
// continuing from where it left off. Returns how many were resumed. Safe to
// call from the monitor (recovery) and the manual Resume endpoint.
func (h *Handler) resumePausedScans() int {
	scans, err := h.db.ListPausedScans()
	if err != nil {
		log.Printf("resumePausedScans: list failed: %v", err)
		return 0
	}
	n := 0
	for _, s := range scans {
		if h.resumeOne(s) {
			n++
		}
	}
	return n
}

// resumeOne continues a single paused scan from its checkpoint. It flips the
// row back to running and re-dispatches the module on the REMAINING work
// (config − already-done), appending into the same row. Returns true if a
// resume was actually launched.
func (h *Handler) resumeOne(s models.Scan) bool {
	if s.Status != models.ScanPaused {
		return false
	}
	launched := h.dispatchResume(s)
	if !launched {
		// No resume adapter for this module yet — leave it paused so the
		// operator can Restart it manually; don't lose the row.
		log.Printf("resume: module %q has no resume adapter yet — scan %s left paused", s.Module, s.ID)
	}
	return launched
}

// noGenericResume are modules the generic (config−done, re-dispatch, DB-merge)
// resume path can't handle losslessly and must NOT run through it:
//   - advancedweb (multi-stage), spider (crawl frontier), and direnum (root
//     request watermark) now have BESPOKE resume adapters (dispatchResume
//     routes to them before this check); they stay listed as a safety net so a
//     future refactor can't accidentally send them down the lossy generic path.
//     direnum's adapter itself declines recursive scans (frontier not
//     reconstructable) — those stay paused for a manual Restart.
//   - adpentest: deferred (dependent AD phases; see its Scan doc-comment).
//   - concurtest: a stress test; "remaining" is meaningless.
//   - oob / cvematch: no per-target network loop / offline.
var noGenericResume = map[string]bool{
	"spider": true, "direnum": true, "advancedweb": true, "adpentest": true,
	"concurtest": true, "oob": true, "cvematch": true,
}

// dispatchResume continues one paused scan from its checkpoint. For list-loop
// modules it computes remaining = configInputs − done, rewrites the config's
// target field to just the remainder, stashes the completed rows as a resume
// base (so UpdateScanResult merges old+new), flips paused→pending, and reuses
// the existing per-module dispatchRestart to run only the remainder into the
// SAME row. Returns true if a resume was launched (or the scan was already
// complete); false leaves it paused (stateful/deferred modules → manual
// Restart).
func (h *Handler) dispatchResume(s models.Scan) bool {
	// advancedweb is a multi-stage suite, not a list loop: it resumes by
	// seeding the stages that already finished and re-running only the
	// interrupted + remaining ones into the SAME row (bespoke, below).
	if s.Module == "advancedweb" {
		return h.resumeAdvancedWeb(s)
	}
	// spider resumes from a per-seed crawl-frontier checkpoint (bespoke, below):
	// the interrupted seed continues from its saved visited-set + queued URLs.
	if s.Module == "spider" {
		return h.resumeSpider(s)
	}
	// direnum resumes a non-recursive scan from its root-request watermark,
	// reusing the prior FP calibration (bespoke, below).
	if s.Module == "direnum" {
		return h.resumeDirEnum(s)
	}
	if noGenericResume[s.Module] {
		return false
	}
	field, inputs := configInputs(s.Config)
	if field == "" || len(inputs) == 0 {
		return false
	}
	rem := remaining(inputs, doneURLKeys(s.Result))
	if len(rem) == 0 {
		// Pause landed at the very end — nothing left; finalize as done.
		if h.db.ResumeToPending(s.ID, 0) {
			h.db.UpdateScanStatus(s.ID, models.ScanDone)
		}
		return true
	}
	newCfg, err := rewriteConfigField(s.Config, field, rem)
	if err != nil {
		return false
	}
	h.db.SetResumeBase(s.ID, s.Result)
	if !h.db.ResumeToPending(s.ID, len(rem)) {
		h.db.ClearResumeBase(s.ID) // another trigger already resumed it
		return false
	}
	h.dispatchRestart(s.ID, s.Module, newCfg)
	return true
}

// resumeAdvancedWeb continues a paused suite scan (Task 0 stage-level resume).
// It reads the stages that already completed cleanly from the stored result,
// seeds them into cfg.ResumeStages, and re-dispatches the suite: Scan skips
// re-running every seeded stage (reconstructing DNS/HTTPX/TechDetect in-memory
// so downstream stages still get their input) and runs only the interrupted +
// remaining stages into the SAME row. Unlike the generic list-loop path this
// does NOT set a resume base — the suite re-marshals the full aggregate result
// (seeded + freshly-run stages) itself, so a plain UpdateScanResult is correct.
// Returns false (leaving the scan paused for a manual Restart) when there's no
// clean partial progress to build on — a full restart would be equivalent.
func (h *Handler) resumeAdvancedWeb(s models.Scan) bool {
	var cfg advancedweb.Config
	if json.Unmarshal([]byte(s.Config), &cfg) != nil {
		return false
	}
	var res advancedweb.ScanResult
	if s.Result == "" || json.Unmarshal([]byte(s.Result), &res) != nil || len(res.Stages) == 0 {
		return false
	}
	seeds := map[advancedweb.Stage]json.RawMessage{}
	for stage, st := range res.Stages {
		if st != nil && st.Status == advancedweb.StatusDone && len(st.Result) > 0 {
			seeds[stage] = st.Result
		}
	}
	if len(seeds) == 0 {
		return false // nothing finished cleanly — a fresh Restart is equivalent
	}
	cfg.ResumeStages = seeds
	// progress_total is recomputed by the suite itself (enabled−skipped−seeded
	// stages), so 0 here is fine — the scanner emits the real denominator on its
	// first bumpStage.
	if !h.db.ResumeToPending(s.ID, 0) {
		return false // another trigger already resumed it
	}
	go h.runAdvancedWeb(s.ID, cfg, h.BuildHTTPOptionsFromSettings())
	return true
}

// resumeSpider continues a paused crawl from its per-seed frontier checkpoint
// (Task 0 lossless resume). The paused result holds one TargetResult per seed;
// finished seeds have a nil Checkpoint, the interrupted seed carries one with
// its exact frontier (visited-set + queued URLs + pages consumed). This:
//   - stashes the finished seeds as a resume base so they merge back into the
//     row untouched (never re-crawled);
//   - hands the interrupted seed's checkpoint (plus its partial finds) to Scan
//     via cfg.ResumeCheckpoints so its crawl continues exactly where it stopped;
//   - re-crawls any config seed that never started, fresh.
// Returns false (leaving the scan paused for a manual Restart) if there's no
// checkpoint to resume from.
func (h *Handler) resumeSpider(s models.Scan) bool {
	var c struct {
		URLs              []string `json:"urls"`
		MaxDepth          int      `json:"max_depth"`
		MaxPages          int      `json:"max_pages"`
		IncludeSubdomains bool     `json:"include_subdomains"`
		ExcludeRegex      []string `json:"exclude_regex"`
		RequestDelayMs    int      `json:"request_delay_ms"`
	}
	if json.Unmarshal([]byte(s.Config), &c) != nil || len(c.URLs) == 0 {
		return false
	}
	var res spider.ScanResult
	if s.Result == "" || json.Unmarshal([]byte(s.Result), &res) != nil {
		return false
	}

	// Partition seeds. doneNorm holds the normalized URLs of every seed that
	// won't be re-crawled (finished + the interrupted one, which resumes via
	// its checkpoint rather than a fresh entry in the seed list).
	var finished []spider.TargetResult
	var interrupted *spider.TargetResult
	doneNorm := map[string]bool{}
	for i := range res.Results {
		if res.Results[i].Checkpoint != nil {
			if interrupted == nil {
				interrupted = &res.Results[i]
			}
			continue
		}
		finished = append(finished, res.Results[i])
		doneNorm[res.Results[i].URL] = true
	}
	if interrupted == nil {
		return false // no checkpoint → nothing to resume; leave for manual Restart
	}
	doneNorm[interrupted.URL] = true

	cfg := defaultSpiderConfig()
	if c.MaxDepth > 0 {
		cfg.MaxDepth = c.MaxDepth
	}
	if c.MaxPages > 0 {
		cfg.MaxPages = c.MaxPages
	}
	cfg.IncludeSubdomains = c.IncludeSubdomains
	cfg.ExcludeRegex = c.ExcludeRegex
	if c.RequestDelayMs > 0 {
		cfg.RequestDelay = time.Duration(c.RequestDelayMs) * time.Millisecond
	}

	// Hand the interrupted seed its saved frontier + partial finds to preload.
	cp := interrupted.Checkpoint
	cp.Resources = interrupted.Resources
	cfg.ResumeCheckpoints = map[string]*spider.CrawlCheckpoint{interrupted.URL: cp}

	// Seed list: interrupted seed first (resumed), then config seeds that never
	// started. Compare on the same scheme-normalization crawl applies so a raw
	// "example.com" config entry matches its "https://example.com" result URL.
	resumeURLs := []string{interrupted.URL}
	for _, u := range c.URLs {
		if !doneNorm[normalizeSeedURL(u)] {
			resumeURLs = append(resumeURLs, u)
		}
	}

	// Finished seeds merge back via the resume base (concat, no re-crawl).
	if len(finished) > 0 {
		if base, err := json.Marshal(spider.ScanResult{Results: finished}); err == nil {
			h.db.SetResumeBase(s.ID, string(base))
		}
	}
	if !h.db.ResumeToPending(s.ID, 0) {
		h.db.ClearResumeBase(s.ID)
		return false
	}
	go h.runSpider(s.ID, resumeURLs, cfg, h.BuildHTTPOptionsFromSettings())
	return true
}

// resumeDirEnum continues a paused NON-RECURSIVE directory brute force from
// its root-request watermark (Task 0 lossless resume). The interrupted target
// carries a DirEnumCheckpoint; resume rebuilds the identical request list,
// skips the completed prefix, reuses the persisted FP calibration (no
// re-calibrate), and dedupes prior hits — so the resumed run covers every
// request above the watermark exactly once. Finished targets merge back via a
// resume base. Recursive scans return false (their BFS frontier can't be
// reconstructed losslessly) and stay paused for a manual Restart.
func (h *Handler) resumeDirEnum(s models.Scan) bool {
	var c struct {
		URLs            []string `json:"urls"`
		Techs           []string `json:"techs"`
		Level           int      `json:"level"`
		SmartScan       bool     `json:"smart_scan"`
		FilterCodes     []int    `json:"filter_codes"`
		Recursive       bool     `json:"recursive"`
		MaxDepth        int      `json:"max_depth"`
		ExcludePaths    []string `json:"exclude_paths"`
		CustomWordlists []string `json:"custom_wordlists"`
	}
	if json.Unmarshal([]byte(s.Config), &c) != nil || len(c.URLs) == 0 {
		return false
	}
	if c.Recursive {
		return false // recursion isn't losslessly resumable — manual Restart
	}
	var res direnum.ScanResult
	if s.Result == "" || json.Unmarshal([]byte(s.Result), &res) != nil {
		return false
	}

	var finished []direnum.TargetResult
	var interrupted *direnum.TargetResult
	doneNorm := map[string]bool{}
	for i := range res.Results {
		if res.Results[i].Checkpoint != nil {
			if interrupted == nil {
				interrupted = &res.Results[i]
			}
			continue
		}
		finished = append(finished, res.Results[i])
		doneNorm[res.Results[i].URL] = true
	}
	if interrupted == nil {
		return false // no checkpoint → nothing to resume; manual Restart
	}
	doneNorm[interrupted.URL] = true

	// Rebuild the config exactly as restartDirEnum does (Concurrency/Timeout
	// from live Settings), then attach the checkpoint.
	settings := h.db.GetSettings()
	cfg := direnum.DefaultConfig()
	if len(c.Techs) > 0 {
		cfg.Techs = c.Techs
	}
	cfg.Level = direnum.ScanLevel(c.Level)
	cfg.SmartScan = c.SmartScan
	cfg.Concurrency = settings.EffectiveWebMaxConcurrent()
	cfg.Timeout = time.Duration(settings.EffectiveWebTimeout()) * time.Second
	cfg.FilterCodes = c.FilterCodes
	cfg.Recursive = false
	cfg.MaxDepth = c.MaxDepth
	cfg.ExcludePaths = c.ExcludePaths
	cfg.CustomWordlists = c.CustomWordlists
	cfg.IsSkipped = func(absURL string) bool {
		return h.scanMgr.IsSkipped(s.ID, absURL)
	}

	cp := interrupted.Checkpoint
	cp.PriorEntries = interrupted.Entries
	cp.PriorFPCodes = interrupted.FPCodes
	cfg.ResumeCheckpoints = map[string]*direnum.DirEnumCheckpoint{interrupted.URL: cp}

	resumeURLs := []string{interrupted.URL}
	for _, u := range c.URLs {
		if !doneNorm[normalizeSeedURL(u)] {
			resumeURLs = append(resumeURLs, u)
		}
	}

	if len(finished) > 0 {
		if base, err := json.Marshal(direnum.ScanResult{Results: finished}); err == nil {
			h.db.SetResumeBase(s.ID, string(base))
		}
	}
	if !h.db.ResumeToPending(s.ID, 0) {
		h.db.ClearResumeBase(s.ID)
		return false
	}
	go h.runDirEnum(s.ID, resumeURLs, cfg, h.BuildHTTPOptionsFromSettings())
	return true
}

// normalizeSeedURL mirrors spider.crawl's seed normalization (prepend https://
// when no scheme is present) so config seeds match their result-row URLs.
func normalizeSeedURL(u string) string {
	u = strings.TrimSpace(u)
	if u != "" && !strings.HasPrefix(u, "http://") && !strings.HasPrefix(u, "https://") {
		return "https://" + u
	}
	return u
}

// configInputs finds the target/URL list in a stored config by trying the
// known field names, returning the first non-empty one.
func configInputs(configJSON string) (string, []string) {
	var m map[string]json.RawMessage
	if json.Unmarshal([]byte(configJSON), &m) != nil {
		return "", nil
	}
	for _, k := range []string{"urls", "targets", "domains", "hosts"} {
		raw, ok := m[k]
		if !ok {
			continue
		}
		var arr []string
		if json.Unmarshal(raw, &arr) == nil && len(arr) > 0 {
			return k, arr
		}
	}
	return "", nil
}

// rewriteConfigField returns configJSON with `field` replaced by `values`,
// preserving every other config key (severity, mode, speed, headers, …).
func rewriteConfigField(configJSON, field string, values []string) (string, error) {
	var m map[string]json.RawMessage
	if err := json.Unmarshal([]byte(configJSON), &m); err != nil {
		return "", err
	}
	vb, err := json.Marshal(values)
	if err != nil {
		return "", err
	}
	m[field] = vb
	out, err := json.Marshal(m)
	if err != nil {
		return "", err
	}
	return string(out), nil
}

// doneURLKeys extracts the set of input values already present in a stored
// result whose shape is {"results":[{"url"|"target":...}]} or
// {"services":[{"url":...}]}. Covers the common list-loop modules so
// remaining = configInputs − doneURLKeys is computable generically.
func doneURLKeys(resultJSON string) map[string]bool {
	done := map[string]bool{}
	if resultJSON == "" {
		return done
	}
	add := func(vals ...string) {
		for _, v := range vals {
			if v != "" {
				done[v] = true
			}
		}
	}
	// Top-level JSON array shape (e.g. sslscan's []HostResult). Without this the
	// generic resume can't see which targets are already done for these modules,
	// so it re-scans EVERY target and mergeResultArrays then duplicates the
	// completed rows. Parsing the array here makes remaining = truly-remaining.
	if strings.HasPrefix(strings.TrimSpace(resultJSON), "[") {
		var arr []struct {
			URL      string `json:"url"`
			Target   string `json:"target"`
			Host     string `json:"host"`
			Hostname string `json:"hostname"`
		}
		if json.Unmarshal([]byte(resultJSON), &arr) == nil {
			for _, r := range arr {
				add(r.URL, r.Target, r.Host, r.Hostname)
			}
			return done
		}
	}
	var probe struct {
		Results []struct {
			URL    string `json:"url"`
			Target string `json:"target"`
			Host   string `json:"host"`
		} `json:"results"`
		Services []struct {
			URL  string `json:"url"`
			Host string `json:"host"`
		} `json:"services"`
	}
	if json.Unmarshal([]byte(resultJSON), &probe) != nil {
		return done
	}
	for _, r := range probe.Results {
		add(r.URL, r.Target, r.Host)
	}
	for _, r := range probe.Services {
		add(r.URL, r.Host)
	}
	return done
}

// remaining returns the elements of inputs not present in done.
func remaining(inputs []string, done map[string]bool) []string {
	out := make([]string, 0, len(inputs))
	for _, in := range inputs {
		if !done[in] {
			out = append(out, in)
		}
	}
	return out
}
