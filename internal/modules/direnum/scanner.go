package direnum

import (
	"bufio"
	"crypto/rand"
	"crypto/tls"
	"fmt"
	"io"
	"log"
	"net/http"
	"net/url"
	"os"
	"scanner/internal/modules/shared"
	"sort"
	"strings"
	"sync"
	"time"
)

type ScanLevel int

const (
	LevelLight      ScanLevel = 0
	LevelNormal     ScanLevel = 1
	LevelAggressive ScanLevel = 2
)

type ScanConfig struct {
	Techs       []string // selected tech profile IDs
	Level       ScanLevel
	SmartScan   bool  // false positive filtering
	FilterCodes []int // manually selected codes to hide
	Concurrency int
	Timeout     time.Duration
	// Recursive enables BFS into discovered directories. When true, the
	// scanner re-runs the same wordlist+extensions inside each found dir,
	// up to MaxDepth levels deep. Each extra level multiplies request
	// volume by the number of directories found at the previous level.
	Recursive bool
	// MaxDepth: 0 = root only (same as non-recursive), 1 = root + 1 sub-
	// level, 2 = root + 2 sub-levels, etc. Capped at 5 to keep blast
	// radius bounded.
	MaxDepth int

	// IsSkipped is consulted before recursing into a directory or before
	// firing a request whose path lives under one. The handler wires it
	// to a per-scan skip set the user can grow at runtime via the
	// /modules/direnum/skip endpoint, letting them prune uninteresting
	// branches mid-scan to save time. nil = nothing is skipped.
	IsSkipped func(absURL string) bool

	// ExcludePaths is a list of path prefixes the user wants the
	// scanner to skip outright — set from the form before the scan
	// starts. Useful for known logout endpoints, admin areas the user
	// already knows about, or any branch they don't want to spend
	// requests on. Matching is prefix-based ("/admin" excludes
	// "/admin", "/admin/", "/admin/users", "/admin.php", etc.).
	ExcludePaths []string

	// CustomWordlists is a list of filesystem paths to extra wordlists
	// the operator supplied through the form. Loaded with the same
	// loadWordlist() helper as tech-profile lists, with the same
	// missing-file fallback. Entries are matrixed against the
	// effective extension set just like profile words — so a custom
	// list of "admin\nbackup\nconfig" + .php/.bak picks up
	// /admin.php, /admin.bak, /backup.php, etc.
	CustomWordlists []string

	// ResumeCheckpoints seeds a resumed scan (Task 0 lossless resume), keyed
	// by target URL. When scanTarget finds a checkpoint it skips the completed
	// root-request prefix and the FP calibration. Not persisted (json:"-") —
	// the resume adapter builds it from the paused result row.
	ResumeCheckpoints map[string]*DirEnumCheckpoint `json:"-"`
}

func DefaultConfig() ScanConfig {
	return ScanConfig{
		Techs:       []string{"general"},
		Level:       LevelNormal,
		SmartScan:   true,
		Concurrency: 30,
		Timeout:     10 * time.Second,
		Recursive:   false,
		MaxDepth:    2,
	}
}

type DirEntry struct {
	URL         string `json:"url"`
	Path        string `json:"path"`
	StatusCode  int    `json:"status_code"`
	Size        int64  `json:"size"`
	ContentType string `json:"content_type"`
	RedirectTo  string `json:"redirect_to,omitempty"`
	IsDir       bool   `json:"is_dir"`
	// On-the-wire request/response capture so pentesters can replay
	// the exact probe in Burp / curl / mitmproxy without rebuilding it.
	RawRequest  string `json:"raw_request,omitempty"`
	RawResponse string `json:"raw_response,omitempty"`
}

// FPSignature describes a false-positive response pattern: status code + common body sizes
type FPSignature struct {
	Code  int     `json:"code"`
	Sizes []int64 `json:"sizes"` // body sizes that consistently return this code
}

type TargetResult struct {
	URL           string                 `json:"url"`
	Entries       []DirEntry             `json:"entries"`
	FPCodes       map[string]FPSignature `json:"fp_codes"` // extension -> FP signature
	TotalRequests int                    `json:"total_requests"`
	TotalFound    int                    `json:"total_found"`
	Error         string                 `json:"error,omitempty"`

	// Checkpoint is set ONLY when this target's root-level brute force was
	// cut short by a connectivity pause (Task 0 lossless resume) — see
	// DirEnumCheckpoint. A finished target, or one paused during recursion
	// (not losslessly resumable), leaves it nil.
	Checkpoint *DirEnumCheckpoint `json:"checkpoint,omitempty"`
}

// DirEnumCheckpoint lets a paused root-level scan continue without re-probing
// the whole wordlist or re-running the multi-minute smart-scan calibration.
// RootWatermark is the count of root requests (in the deterministic build
// order) that fully completed as a contiguous prefix: resume rebuilds the
// identical request list and re-runs only [RootWatermark:], skipping known
// prior hits so nothing is duplicated and nothing (holes above the watermark
// or the un-dispatched tail) is missed. Calibration is skipped by reusing the
// persisted FPCodes. Only produced for the root level — recursion is not
// checkpointed (its BFS frontier can't be reconstructed losslessly), so a scan
// paused during recursion carries no checkpoint and restarts on Resume.
type DirEnumCheckpoint struct {
	RootWatermark int `json:"root_watermark"`

	// Transient (json:"-") resume inputs the handler fills in from the paused
	// result row: the prior hits (to dedupe re-found paths) and the prior FP
	// calibration (to skip recalibration). Never persisted — derived on resume.
	PriorEntries []DirEntry             `json:"-"`
	PriorFPCodes map[string]FPSignature `json:"-"`
}

type ScanResult struct {
	Results []TargetResult `json:"results"`
}

type ProgressFunc func(done int, msg string)

// PartialFunc fires whenever a new entry is added for live UI updates
type PartialFunc func(partial *ScanResult)

// EmitProgress lets the scanner push fine-grained progress triples (done/total/msg)
// so that percentage tracks actual HTTP requests, not URL count. May be nil.
type EmitProgress func(done, total int, msg string)

func Scan(urls []string, cfg ScanConfig, opts *shared.HTTPOptions, onPartial PartialFunc, progress ProgressFunc) *ScanResult {
	return ScanFull(urls, cfg, opts, onPartial, progress, nil)
}

func ScanFull(urls []string, cfg ScanConfig, opts *shared.HTTPOptions, onPartial PartialFunc, progress ProgressFunc, emit EmitProgress) *ScanResult {
	result := &ScanResult{}
	var mu sync.Mutex

	partialReport := func(currentTR *TargetResult) {
		if onPartial == nil {
			return
		}
		mu.Lock()
		snap := &ScanResult{Results: append([]TargetResult(nil), result.Results...)}
		if currentTR != nil {
			snap.Results = append(snap.Results, *currentTR)
		}
		mu.Unlock()
		onPartial(snap)
	}

	// Aggregated work-unit counters across all URLs. We populate `globalTotal`
	// after each target's request list is built, and `globalDone` is the sum of
	// requests sent across every target so far. This makes the dashboard's
	// percentage track actual HTTP work rather than URL index.
	var globalDone, globalTotal int

	// Reachability preflight: skip TLS-dead targets before the (expensive) BFS.
	if opts != nil && opts.PreflightEnabled {
		live, dead := shared.FilterReachable(opts.Ctx, opts, urls, opts.PreflightTimeout, 0)
		for t, reason := range dead {
			result.Results = append(result.Results, TargetResult{URL: t, Error: "unreachable — " + reason})
		}
		urls = live
	}

	for i, u := range urls {
		if opts.Done() {
			break
		}
		if progress != nil {
			progress(i, fmt.Sprintf("Scanning %s ...", u))
		}
		urlIdx := i
		tr := scanTarget(u, cfg, opts, func(msg string) {
			if progress != nil {
				progress(urlIdx, msg)
			}
		}, partialReport, func(addTotal, addDone int, msg string) {
			mu.Lock()
			if addTotal != 0 {
				globalTotal += addTotal
			}
			if addDone != 0 {
				globalDone += addDone
			}
			gd, gt := globalDone, globalTotal
			mu.Unlock()
			if emit != nil && gt > 0 {
				emit(gd, gt, msg)
			}
		})
		mu.Lock()
		result.Results = append(result.Results, *tr)
		mu.Unlock()
		if progress != nil {
			progress(i+1, fmt.Sprintf("[%d/%d] %s — %d found", i+1, len(urls), u, tr.TotalFound))
		}
		partialReport(nil)
	}
	return result
}

// emitDelta is called by scanTarget to bump global progress counters. Args:
//
//	addTotal: requests to add to the global denominator (set on first call only)
//	addDone:  requests completed (incremental, called on each request finish)
//	msg:      latest user-facing status line
type emitDelta func(addTotal, addDone int, msg string)

func scanTarget(target string, cfg ScanConfig, opts *shared.HTTPOptions, logFn func(string), partialFn func(*TargetResult), emit emitDelta) *TargetResult {
	tr := &TargetResult{URL: target, FPCodes: map[string]FPSignature{}}

	// Resume state (Task 0 lossless resume). Keyed by the raw target arg — the
	// adapter keys the map by the same string it puts in the seed list — so the
	// lookup happens before normalization to guarantee an exact match.
	var resume *DirEnumCheckpoint
	if cfg.ResumeCheckpoints != nil {
		resume = cfg.ResumeCheckpoints[target]
	}
	resumeSeen := map[string]bool{} // prior-hit paths — don't re-append (dedupe)
	if resume != nil {
		for _, e := range resume.PriorEntries {
			resumeSeen[e.Path] = true
		}
	}

	if !strings.HasPrefix(target, "http://") && !strings.HasPrefix(target, "https://") {
		target = "https://" + target
		tr.URL = target
	}
	target = strings.TrimRight(target, "/")

	transport := &http.Transport{
		TLSClientConfig:     &tls.Config{InsecureSkipVerify: true},
		DialContext:         shared.BoundDialer(nil, 5*time.Second).DialContext,
		MaxIdleConns:        cfg.Concurrency,
		MaxIdleConnsPerHost: cfg.Concurrency,
		// Backstop: without an idle timeout (0 = never expire) a keep-alive
		// socket whose CloseIdleConnections flush is ever missed would leak
		// indefinitely. Self-expire idle sockets after 90s like shared/spider.
		IdleConnTimeout: 90 * time.Second,
	}
	if opts != nil {
		opts.ApplyTransport(transport)
	}
	client := &http.Client{
		Timeout:   cfg.Timeout,
		Transport: transport,
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}

	// Build extension list, generic wordlist, and literal-path list from
	// the chosen tech profiles. `allWords` are paired with extensions in
	// the request builder; `literalPaths` are taken verbatim (already-
	// formed full paths from tech-specific SecLists files like
	// wordpress.fuzz.txt or Aspx-Fuzzing-Wordlist).
	allExts := []string{""} // empty = directory (no extension)
	allWords := map[string]bool{}
	literalPaths := map[string]bool{}
	var extraWords []string

	profiles := resolveProfiles(cfg.Techs)
	for _, p := range profiles {
		for _, ext := range p.Extensions {
			allExts = appendUnique(allExts, ext)
		}
		level := int(cfg.Level)
		for _, wlPath := range p.Wordlists[level] {
			for _, w := range loadWordlist(wlPath) {
				allWords[w] = true
			}
		}
		for _, wlPath := range p.LiteralLists[level] {
			for _, w := range loadWordlist(wlPath) {
				literalPaths[w] = true
			}
		}
		extraWords = append(extraWords, p.ExtraWords...)
	}
	for _, w := range extraWords {
		allWords[w] = true
	}

	// Custom wordlists from the launch form. Loaded via the same
	// loadWordlist helper so the missing-file embedded fallback path
	// still applies — a typo never results in a silent zero-result
	// scan.
	for _, wlPath := range cfg.CustomWordlists {
		for _, w := range loadWordlist(wlPath) {
			allWords[w] = true
		}
	}

	// Always probe common backup-file suffixes alongside profile-specific
	// extensions. Pentests routinely turn up gold via /config.bak,
	// /admin.swp, /db.sql.old — leftover editor swap files, deployment
	// archives, or hand-rolled backups committed by mistake. These suffixes
	// stack on top of every wordlist entry without touching tech profiles.
	for _, ext := range []string{".bak", ".swp", ".old", ".orig", ".tmp", ".~", ".back"} {
		allExts = appendUnique(allExts, ext)
	}

	// Filter out logout-related paths to avoid killing the user's session
	skippedLogout := 0
	words := make([]string, 0, len(allWords))
	for w := range allWords {
		if shared.IsLogoutPath(w) {
			skippedLogout++
			continue
		}
		words = append(words, w)
	}
	sort.Strings(words)

	// Same logout filter for tech-specific full-path lists, plus skip any
	// blank / commented entries that survive loadWordlist.
	literals := make([]string, 0, len(literalPaths))
	for p := range literalPaths {
		if shared.IsLogoutPath(p) {
			skippedLogout++
			continue
		}
		literals = append(literals, p)
	}
	sort.Strings(literals)

	// Level label for logs
	levelLabel := "normal"
	switch cfg.Level {
	case LevelLight:
		levelLabel = "light"
	case LevelAggressive:
		levelLabel = "aggressive"
	}
	logFn(fmt.Sprintf("[%s] Profiles: %s · Level: %s", target, strings.Join(cfg.Techs, ","), levelLabel))
	if skippedLogout > 0 {
		logFn(fmt.Sprintf("[%s] Skipped %d logout-related words (session safety)", target, skippedLogout))
	}
	extList := make([]string, 0, len(allExts))
	for _, e := range allExts {
		if e != "" {
			extList = append(extList, e)
		}
	}
	logFn(fmt.Sprintf("[%s] Extensions (%d): %s", target, len(extList), strings.Join(extList, " ")))
	logFn(fmt.Sprintf("[%s] Wordlist: %d unique words", target, len(words)))

	// ---- Smart Scan: calibrate false positives ----
	filterCodes := map[int]bool{}
	for _, c := range cfg.FilterCodes {
		filterCodes[c] = true
	}
	// Global FP body sizes observed across any extension — same size + same page = generic error
	globalFPSizes := map[int64]bool{}

	if resume != nil {
		// Resumed: reuse the FP calibration from the paused run. Recalibrating
		// would waste minutes AND could drift (soft-404 sampling varies run to
		// run), so the resumed half would filter differently from the original
		// half. Rebuild filterCodes/globalFPSizes from the persisted signatures.
		tr.FPCodes = resume.PriorFPCodes
		if tr.FPCodes == nil {
			tr.FPCodes = map[string]FPSignature{}
		}
		for _, sig := range tr.FPCodes {
			if sig.Code != -1 {
				filterCodes[sig.Code] = true
			}
			for _, sz := range sig.Sizes {
				globalFPSizes[sz] = true
			}
		}
		logFn(fmt.Sprintf("[%s] Resume: reusing %d calibrated FP signature(s) — skipping recalibration", target, len(tr.FPCodes)))
	} else if cfg.SmartScan {
		// Build the calibration extension set: every extension we'd send
		// plus extensions found inside literal full-path lists (e.g. an
		// Aspx-Fuzzing-Wordlist entry like "scripts/handler.ashx" gives
		// us .ashx even when the profile only declared .aspx). Servers
		// often have per-extension routing → per-extension "soft 404"
		// pages, and we'd miss those without probing each ext we'll hit.
		calibExtSet := map[string]struct{}{}
		for _, e := range allExts {
			if e != "" {
				calibExtSet[e] = struct{}{}
			}
		}
		for _, lp := range literals {
			if e := extractExtFromPath(lp); e != "" {
				calibExtSet[e] = struct{}{}
			}
		}
		calibExts := make([]string, 0, len(calibExtSet))
		for e := range calibExtSet {
			calibExts = append(calibExts, e)
		}
		sort.Strings(calibExts)
		// +1 for the directory probe (empty-string ext) prepended inside calibrateFP.
		logFn(fmt.Sprintf("[%s] Smart scan: probing %d extensions × 6 charsets × 8 lengths × 6 shapes × 8 (~2304 probes/ext) — this can take a few minutes", target, len(calibExts)+1))
		// Audit fix: previously globalTotal stayed at 0 throughout the
		// multi-minute calibration phase, so the UI sat at 0% / spinner
		// while the user assumed the scan was hung. Seed the
		// denominator with the calibration budget up front and tick
		// `done` on each probe so the bar advances monotonically.
		calibBudget := (len(calibExts) + 1) * fpProbesPerExt
		if emit != nil && calibBudget > 0 {
			emit(calibBudget, 0, fmt.Sprintf("[%s] smart scan: calibrating %d extensions (~%d probes)", target, len(calibExts)+1, calibBudget))
		}
		calibStart := time.Now()
		fpSigs := calibrateFP(client, target, calibExts, opts, func() {
			if emit != nil {
				emit(0, 1, "")
			}
		})
		logFn(fmt.Sprintf("[%s] Smart scan: baseline calibration complete in %s", target, time.Since(calibStart).Round(time.Second)))
		if len(fpSigs) == 0 {
			logFn(fmt.Sprintf("[%s] Smart scan: no consistent false-positive pattern detected", target))
		}
		for ext, sig := range fpSigs {
			tr.FPCodes[ext] = sig
			if sig.Code != -1 {
				filterCodes[sig.Code] = true
			}
			for _, sz := range sig.Sizes {
				globalFPSizes[sz] = true
			}
			label := ext
			if label == "" {
				label = "(directory)"
			}
			parts := []string{}
			if sig.Code != -1 {
				parts = append(parts, fmt.Sprintf("HTTP %d", sig.Code))
			}
			if len(sig.Sizes) > 0 {
				szs := []string{}
				for _, s := range sig.Sizes {
					szs = append(szs, fmt.Sprintf("%d", s))
				}
				parts = append(parts, fmt.Sprintf("sizes: [%s]", strings.Join(szs, ", ")))
			}
			logFn(fmt.Sprintf("[%s] FP calibrated: %s → %s", target, label, strings.Join(parts, " · ")))
		}
	}
	if len(filterCodes) > 0 || len(globalFPSizes) > 0 {
		parts := []string{}
		if len(filterCodes) > 0 {
			codes := []string{}
			for c := range filterCodes {
				codes = append(codes, fmt.Sprintf("%d", c))
			}
			parts = append(parts, fmt.Sprintf("codes: %s", strings.Join(codes, ", ")))
		}
		if len(globalFPSizes) > 0 {
			parts = append(parts, fmt.Sprintf("%d body sizes", len(globalFPSizes)))
		}
		logFn(fmt.Sprintf("[%s] Filtering: %s", target, strings.Join(parts, " · ")))
	}

	// ---- Build request list ----
	type reqItem struct {
		path string
		ext  string
	}
	var requests []reqItem

	// Normalize and dedupe the user-supplied exclude list. Empty lines
	// and bare slashes are dropped — "/" as a prefix would mean
	// "exclude everything". Each pattern is stored without trailing
	// slash so "/admin" and "/admin/" match identically.
	excludes := []string{}
	{
		seen := map[string]bool{}
		for _, raw := range cfg.ExcludePaths {
			p := strings.TrimSpace(raw)
			if p == "" || p == "/" {
				continue
			}
			if !strings.HasPrefix(p, "/") {
				p = "/" + p
			}
			p = strings.TrimRight(p, "/")
			if p == "" || seen[p] {
				continue
			}
			seen[p] = true
			excludes = append(excludes, p)
		}
	}
	matchesExclude := func(reqPath string) bool {
		if len(excludes) == 0 {
			return false
		}
		// Strip trailing slash before comparison so "/admin/" matches
		// the "/admin" pattern. Also treat the pattern as a *path
		// prefix*: "/admin" should match "/admin", "/admin/users",
		// "/admin.php" — but not "/administrator" (different segment).
		trimmed := strings.TrimRight(reqPath, "/")
		for _, pat := range excludes {
			if trimmed == pat {
				return true
			}
			if strings.HasPrefix(trimmed, pat+"/") || strings.HasPrefix(trimmed, pat+".") {
				return true
			}
		}
		return false
	}
	if len(excludes) > 0 {
		logFn(fmt.Sprintf("[%s] Exclude paths: %s", target, strings.Join(excludes, " · ")))
	}

	addRequest := func(r reqItem) {
		if matchesExclude(r.path) {
			return
		}
		requests = append(requests, r)
	}
	for _, word := range words {
		// Safety net: skip anything logout-related that slipped through
		if shared.IsLogoutPath(word) {
			continue
		}
		// If word already has an extension or is a path, add as-is
		if strings.Contains(word, ".") || strings.HasPrefix(word, "/") {
			addRequest(reqItem{path: "/" + strings.TrimLeft(word, "/")})
			continue
		}
		// Bare extensionless path — the clean-URL route (e.g. /panel/login with
		// no trailing slash and no extension). Modern frameworks route these
		// heavily, and they were previously NEVER requested: only "/word/" and
		// "/word.<ext>" were tested, so an extensionless page served without a
		// trailing slash was completely invisible to the scan.
		addRequest(reqItem{path: "/" + word, ext: ""})
		// Directory variant (trailing slash)
		addRequest(reqItem{path: "/" + word + "/", ext: ""})
		// With each extension
		for _, ext := range allExts {
			if ext == "" {
				continue
			}
			addRequest(reqItem{path: "/" + word + ext, ext: ext})
		}
	}
	// Literal full-path entries from tech-specific SecLists. These already
	// carry their own extensions, so we feed them straight in — no
	// matrixing against allExts. Saves both bandwidth (no `.aspx.aspx`-
	// style noise) and cuts thousands of bogus requests.
	//
	// Audit fix: the reqItem.ext field was left blank for literals, so
	// every literal request was filtered against the directory FP
	// signature (the empty-string key) instead of its actual per-
	// extension signature. extractExtFromPath returns the lowercase
	// ".ext" suffix when it looks like a real extension.
	for _, p := range literals {
		addRequest(reqItem{path: "/" + strings.TrimLeft(p, "/"), ext: extractExtFromPath(p)})
	}

	totalReqs := len(requests)
	tr.TotalRequests = totalReqs
	logFn(fmt.Sprintf("[%s] Queued %d requests — starting brute-force with %d concurrent workers", target, totalReqs, cfg.Concurrency))
	if emit != nil {
		emit(totalReqs, 0, fmt.Sprintf("[%s] queued %d requests", target, totalReqs))
	}

	// Root-level completion tracking for the resume watermark. rootCompleted[i]
	// flips true when request i (in this deterministic order) fully finishes
	// (reaches done++). On resume, startIdx skips the contiguous prefix that
	// already completed in the paused run; [0:startIdx) are pre-marked done.
	rootCompleted := make([]bool, totalReqs)
	startIdx := 0
	if resume != nil {
		startIdx = resume.RootWatermark
		if startIdx > totalReqs {
			startIdx = totalReqs
		}
		for i := 0; i < startIdx; i++ {
			rootCompleted[i] = true
		}
	}

	// ---- Send requests ----
	// On resume, preload the prior run's hits so this target's row ends up
	// complete (prior + newly-found) in ONE TargetResult — resumeSeen (above)
	// stops the re-run from appending duplicates. Non-recursive only (the
	// handler never hands a recursive scan a checkpoint), so this doesn't
	// perturb the recursion snapshot bookkeeping.
	var entries []DirEntry
	if resume != nil {
		entries = append(entries, resume.PriorEntries...)
	}
	var mu sync.Mutex
	sem := make(chan struct{}, cfg.Concurrency)
	var wg sync.WaitGroup
	done := 0
	filteredCount := 0
	startedAt := time.Now()

	// 403-dir paths get tracked separately so recursion still walks them
	// even when smart-scan / filterCodes drops them from visible results.
	// A 403 on a directory means "exists but you can't list it" — there's
	// often readable content one level deeper (e.g. /admin/users.php).
	// `forbiddenCursor` tracks how many we've already enqueued so each
	// BFS level seeds only entries discovered since the previous one.
	forbiddenDirs := []string{}
	forbiddenCursor := 0

	// Adaptive FP detection during scan: if the same (code, size) pair
	// is observed repeatedly in results, retroactively filter it out.
	type cs struct {
		code int
		size int64
	}
	liveCount := map[cs]int{}   // (code, size) -> occurrence
	liveBanned := map[cs]bool{} // (code, size) -> banned
	const adaptiveThreshold = 8 // after this many identical (code,size) we treat it as FP

	// Heartbeat: every 3s, push a richer progress line with rate / eta /
	// hits / filtered counts so the user always sees activity, not just hits.
	heartbeatDone := make(chan struct{})
	go func() {
		t := time.NewTicker(3 * time.Second)
		defer t.Stop()
		for {
			select {
			case <-heartbeatDone:
				return
			case <-t.C:
				// Audit fix: read totalReqs inside the lock too — the
				// BFS recursion mutates it under mu, and the previous
				// unlocked reads at the bottom of this branch were
				// racing with those writes.
				mu.Lock()
				dn := done
				hits := len(entries)
				filt := filteredCount
				tot := totalReqs
				mu.Unlock()
				if dn == 0 {
					continue
				}
				elapsed := time.Since(startedAt).Seconds()
				rate := float64(dn) / elapsed
				remaining := tot - dn
				etaStr := "—"
				if rate > 0 && remaining > 0 {
					etaSec := int(float64(remaining) / rate)
					etaStr = formatETA(etaSec)
				}
				logFn(fmt.Sprintf("[%s] [%d/%d] %.1f req/s · %d hits · %d filtered · ETA %s",
					target, dn, tot, rate, hits, filt, etaStr))
			}
		}
	}()
	defer close(heartbeatDone)

	// firePartial snapshots current state and reports it to the partial callback
	firePartial := func() {
		if partialFn == nil {
			return
		}
		mu.Lock()
		snap := &TargetResult{
			URL:           tr.URL,
			Entries:       append([]DirEntry(nil), entries...),
			FPCodes:       tr.FPCodes,
			TotalRequests: tr.TotalRequests,
			TotalFound:    len(entries),
		}
		mu.Unlock()
		partialFn(snap)
	}

	// Worker closure — extracted so both the initial root-level scan and
	// the recursive BFS levels (below) reuse the exact same probe + filter
	// + adaptive-FP + partial-report machinery. Captures all the state
	// vars from the surrounding scope.
	processRequest := func(r reqItem, w *sync.WaitGroup, idx int) {
		w.Add(1)
		sem <- struct{}{}
		go func() {
			defer w.Done()
			defer func() { <-sem }()

			if opts.Done() {
				return
			}

			fullURL := target + r.path
			entry := probeURL(client, fullURL, r.path, opts)

			// Locked section as a closure so `defer mu.Unlock()` (audit B29)
			// guarantees release on every early return AND on a panic. The
			// previous implementation had five `mu.Unlock(); return` pairs
			// and was one careless edit away from deadlocking the whole
			// scan. Returning `hit` lets us call the unlocked emit /
			// firePartial callbacks below without holding the mutex.
			hit := func() bool {
				mu.Lock()
				defer mu.Unlock()
				done++
				// Root request idx finished — record it for the resume
				// watermark (recursion passes idx=-1 and is not checkpointed).
				if idx >= 0 && idx < len(rootCompleted) {
					rootCompleted[idx] = true
				}

				if entry == nil {
					if done%50 == 0 {
						logFn(fmt.Sprintf("[%s] [%d/%d] scanning... %d hits so far", target, done, totalReqs, len(entries)))
					}
					return false
				}

				key := cs{code: entry.StatusCode, size: entry.Size}
				// 403 means the resource exists but auth is denied — that
				// is real signal, so we surface them to the user and walk
				// them recursively. Smart-scan FP filtering is bypassed
				// for 403 (otherwise a 403-as-not-found server would hide
				// every real forbidden dir), but the user's explicit
				// filterCodes still wins.
				is403 := entry.StatusCode == 403
				if is403 && strings.HasSuffix(r.path, "/") {
					forbiddenDirs = append(forbiddenDirs, r.path)
				}
				if filterCodes[entry.StatusCode] {
					filteredCount++
					return false
				}
				if cfg.SmartScan && !is403 {
					if sig, ok := tr.FPCodes[r.ext]; ok {
						if sig.Code != -1 && entry.StatusCode == sig.Code {
							filteredCount++
							return false
						}
						for _, sz := range sig.Sizes {
							if sz == entry.Size {
								filteredCount++
								return false
							}
						}
					}
					if globalFPSizes[entry.Size] {
						filteredCount++
						return false
					}
					if liveBanned[key] {
						filteredCount++
						return false
					}
				}

				// On resume, a path found in the paused run is already carried
				// in the resume base — don't append a duplicate. done++ above
				// still counted the request, so the watermark stays correct.
				if resumeSeen[r.path] {
					return false
				}
				entries = append(entries, *entry)
				opts.ReplayHit("GET", fullURL)

				// Don't let 403s feed the adaptive FP learner — a server
				// that returns lots of legitimate 403s would otherwise
				// trip the threshold and ban its own forbidden bucket.
				if cfg.SmartScan && !is403 {
					liveCount[key]++
					if liveCount[key] == adaptiveThreshold {
						liveBanned[key] = true
						globalFPSizes[entry.Size] = true
						filtered := entries[:0]
						removed := 0
						for _, e := range entries {
							if e.StatusCode == key.code && e.Size == key.size {
								removed++
								continue
							}
							filtered = append(filtered, e)
						}
						entries = filtered
						logFn(fmt.Sprintf("[%s] Adaptive FP: HTTP %d · %d bytes appeared %d× — banned and removed %d earlier results",
							target, key.code, key.size, adaptiveThreshold, removed))
					}
				}

				logFn(fmt.Sprintf("[%s] [%d/%d] ✓ %s → %d (%s, %d bytes)",
					target, done, totalReqs, r.path, entry.StatusCode, entry.ContentType, entry.Size))
				return true
			}()

			if emit != nil {
				emit(0, 1, "")
			}
			if hit {
				firePartial()
			}
		}()
	}

	// buildRequestsForPrefix turns the wordlist + extension matrix into a
	// reqItem list rooted at `prefix` (e.g. "/" for root or "/admin/" for
	// a recursive sublevel). Same logic as the initial-level builder, just
	// parameterized.
	buildRequestsForPrefix := func(prefix string) []reqItem {
		out := make([]reqItem, 0, len(words)*(len(allExts)+1)+len(literals))
		emit := func(r reqItem) {
			if matchesExclude(r.path) {
				return
			}
			out = append(out, r)
		}
		for _, word := range words {
			if shared.IsLogoutPath(word) {
				continue
			}
			if strings.Contains(word, ".") || strings.HasPrefix(word, "/") {
				emit(reqItem{path: prefix + strings.TrimLeft(word, "/")})
				continue
			}
			emit(reqItem{path: prefix + word + "/", ext: ""})
			for _, ext := range allExts {
				if ext == "" {
					continue
				}
				emit(reqItem{path: prefix + word + ext, ext: ext})
			}
		}
		// Tech-specific literals — used as-is, no extension iteration.
		// Audit fix: tag with the actual extension so the FP filter
		// looks up the right per-extension signature, not the directory
		// signature.
		for _, p := range literals {
			emit(reqItem{path: prefix + strings.TrimLeft(p, "/"), ext: extractExtFromPath(p)})
		}
		return out
	}

	// --- Root level ---
	// Audit fix: when opts.Done() fires mid-loop, every queued request
	// that we never reached still counts toward totalReqs but never
	// completes — leaving the progress bar parked under 100%. We
	// account for the un-dispatched tail by emitting their `done`
	// deltas so the bar accurately closes out on cancel.
	// On resume, count the already-completed prefix as done up front so the
	// bar reflects prior progress, then dispatch only [startIdx:].
	if startIdx > 0 {
		mu.Lock()
		done += startIdx
		mu.Unlock()
		if emit != nil {
			emit(0, startIdx, "")
		}
	}
	rootDispatched := startIdx
	for i := startIdx; i < len(requests); i++ {
		if opts.Done() {
			break
		}
		rootDispatched++
		processRequest(requests[i], &wg, i)
	}
	if skipped := len(requests) - rootDispatched; skipped > 0 {
		mu.Lock()
		done += skipped
		mu.Unlock()
		if emit != nil {
			emit(0, skipped, "")
		}
	}
	wg.Wait()

	// If a connectivity pause cut the root level short, snapshot the resume
	// watermark: the length of the contiguous run of completed requests from
	// index 0. Resume re-runs everything from there (holes + un-dispatched
	// tail), so nothing above the watermark is skipped. Recursion is not
	// checkpointed — a scan paused after root started recursing carries no
	// checkpoint and restarts (see DirEnumCheckpoint).
	if opts.Done() {
		w := 0
		for w < len(rootCompleted) && rootCompleted[w] {
			w++
		}
		tr.Checkpoint = &DirEnumCheckpoint{RootWatermark: w}
	}

	// --- Recursive BFS levels ---
	// Walk every directory we discovered at depth N and re-run the same
	// brute-force inside it for depth N+1, up to cfg.MaxDepth. `visited`
	// guards against cycles (e.g. a host that 200's on every path).
	if cfg.Recursive && cfg.MaxDepth > 0 && !opts.Done() {
		// Per-prefix skip check. Treat the absolute URL of a candidate
		// directory (target + path) as the key — that's exactly the
		// shape the user clicks on in the UI. Returns true if the user
		// has marked this dir (or any ancestor of it) as skipped, so
		// recursion drops it before queueing or before firing requests.
		isSkipped := func(prefix string) bool {
			if cfg.IsSkipped == nil {
				return false
			}
			return cfg.IsSkipped(target + prefix)
		}

		visited := map[string]bool{"/": true}
		queue := []string{}
		mu.Lock()
		seedSnapshot := append([]DirEntry(nil), entries...)
		forbiddenSeed := append([]string(nil), forbiddenDirs[forbiddenCursor:]...)
		forbiddenCursor = len(forbiddenDirs)
		mu.Unlock()
		skippedAtSeed := 0
		for _, e := range seedSnapshot {
			if !e.IsDir {
				continue
			}
			p := strings.TrimRight(e.Path, "/") + "/"
			if visited[p] {
				continue
			}
			visited[p] = true
			if isSkipped(p) || matchesExclude(p) {
				skippedAtSeed++
				continue
			}
			queue = append(queue, p)
		}
		// Add 403-only dirs that the FP filter would otherwise hide.
		for _, p := range forbiddenSeed {
			p = strings.TrimRight(p, "/") + "/"
			if visited[p] {
				continue
			}
			visited[p] = true
			if isSkipped(p) || matchesExclude(p) {
				skippedAtSeed++
				continue
			}
			queue = append(queue, p)
		}
		if skippedAtSeed > 0 {
			logFn(fmt.Sprintf("[%s] Skip list: dropped %d director%s before recursion", target, skippedAtSeed, pluralY(skippedAtSeed)))
		}
		for depth := 1; depth <= cfg.MaxDepth && len(queue) > 0 && !opts.Done(); depth++ {
			logFn(fmt.Sprintf("[%s] Recursive depth %d: scanning %d sub-director%s", target, depth, len(queue), pluralY(len(queue))))
			levelRequests := []reqItem{}
			for _, prefix := range queue {
				levelRequests = append(levelRequests, buildRequestsForPrefix(prefix)...)
			}
			mu.Lock()
			totalReqs += len(levelRequests)
			tr.TotalRequests = totalReqs
			prevLen := len(entries)
			mu.Unlock()
			if emit != nil {
				emit(len(levelRequests), 0,
					fmt.Sprintf("[%s] depth %d: queued %d sub-paths across %d dirs", target, depth, len(levelRequests), len(queue)))
			}

			var lwg sync.WaitGroup
			skippedThisLevel := 0
			for i, ri := range levelRequests {
				if opts.Done() {
					// Account for the un-iterated tail so totalReqs's
					// matching done counter still closes the bar out.
					skippedThisLevel += len(levelRequests) - i
					break
				}
				// Re-check on every request — the user may add a skip
				// mid-level, and we should drop in-flight work for that
				// prefix immediately rather than waiting for the next
				// depth boundary.
				if isSkipped(ri.path) {
					skippedThisLevel++
					continue
				}
				processRequest(ri, &lwg, -1)
			}
			lwg.Wait()
			if skippedThisLevel > 0 {
				logFn(fmt.Sprintf("[%s] Skip list: dropped %d in-flight request%s at depth %d", target, skippedThisLevel, pluralS(skippedThisLevel), depth))
				// Audit fix: bump the done counter (and emit the matching
				// delta) for every request we skipped or never reached
				// — they're already counted in totalReqs, so without this
				// the percentage bar parks short of 100%.
				mu.Lock()
				done += skippedThisLevel
				mu.Unlock()
				if emit != nil {
					emit(0, skippedThisLevel, "")
				}
			}

			// Collect dir hits added during this level for the next round.
			mu.Lock()
			newSnapshot := append([]DirEntry(nil), entries[prevLen:]...)
			newForbidden := append([]string(nil), forbiddenDirs[forbiddenCursor:]...)
			forbiddenCursor = len(forbiddenDirs)
			mu.Unlock()
			next := []string{}
			for _, e := range newSnapshot {
				if !e.IsDir {
					continue
				}
				p := strings.TrimRight(e.Path, "/") + "/"
				if visited[p] {
					continue
				}
				visited[p] = true
				if isSkipped(p) || matchesExclude(p) {
					continue
				}
				next = append(next, p)
			}
			for _, p := range newForbidden {
				p = strings.TrimRight(p, "/") + "/"
				if visited[p] {
					continue
				}
				visited[p] = true
				if isSkipped(p) || matchesExclude(p) {
					continue
				}
				next = append(next, p)
			}
			queue = next
		}
	}

	sort.Slice(entries, func(i, j int) bool {
		return entries[i].Path < entries[j].Path
	})

	tr.Entries = entries
	tr.TotalFound = len(entries)
	return tr
}

// Charsets used by the FP probe matrix. Each one exercises a different
// code path on the server side — generic apps tend to lump them together
// but routers, WAFs, and frameworks frequently route by character class.
const (
	fpAlnumCharset   = "abcdefghijklmnopqrstuvwxyz0123456789"
	fpSpecialCharset = "[]_?=)(/&%+^'!é<>*-+,.@_"
	fpDigitsCharset  = "0123456789"
	fpUpperCharset   = "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
	fpMixedCharset   = "AaBbCcDdEeFfGgHhIiJjKkLlMmNnOoPpQqRrSsTtUuVvWwXxYyZz0123456789"
	// Latin-extended + Cyrillic + Greek + a handful of CJK ideographs so
	// each rune ends up multi-byte after PathEscape — surfaces UTF-8
	// decode quirks (NFC/NFD normalization, IRI handling).
	fpUnicodeCharset = "àáâäçèéêëìíîïñòóôöùúûüÀÁÂÄÇÈÉÊËÌÍÎÏÑÒÓÔÖÙÚÛÜабвгдежзийклмнопрстуфхцчшщыэюяАБВГДЕЖЗИЙКЛМНОПРСТУФХЦЧШЩЫЭЮЯαβγδεζηθικλμνξοπρστυφχψω中文测试日本語"
)

// randomCharsFrom builds a random n-rune string by sampling charset
// uniformly. Multi-byte runes (e.g. é) survive intact.
func randomCharsFrom(charset string, n int) string {
	runes := []rune(charset)
	if len(runes) == 0 || n <= 0 {
		return ""
	}
	buf := make([]byte, n)
	rand.Read(buf)
	out := make([]rune, n)
	for i := 0; i < n; i++ {
		out[i] = runes[int(buf[i])%len(runes)]
	}
	return string(out)
}

// extractExtFromPath returns the lowercase ".ext" suffix of a literal full
// path if it looks like a normal file extension (≤ 8 chars, alnum after
// the dot). Returns "" otherwise — including for slashes-in-extension or
// directory entries.
func extractExtFromPath(p string) string {
	base := p
	if i := strings.LastIndex(base, "/"); i >= 0 {
		base = base[i+1:]
	}
	j := strings.LastIndex(base, ".")
	if j < 0 || j == len(base)-1 {
		return ""
	}
	e := strings.ToLower(base[j:])
	if len(e) > 8 {
		return ""
	}
	for _, c := range e[1:] {
		if !((c >= 'a' && c <= 'z') || (c >= '0' && c <= '9')) {
			return ""
		}
	}
	return e
}

// calibrateFP fingerprints each extension's "not-found" response so the
// scanner can drop matching live results. Servers can emit different soft
// 404s based on input length, charset, shape, or extension — single-shape
// probes miss those, so we sweep a wide matrix:
//
//	6 charsets × 8 lengths × 6 shapes × 8 reqs/bucket = 2304 probes per ext.
//
// Charsets: alnum / specials / digits-only / uppercase / mixed-case /
// unicode (Latin+Cyrillic+Greek+CJK). Lengths: 3, 12, 50, 100, 250, 500,
// 1000, 2000. Shapes: plain, leading-dot, quoted, spaced, double-with-dots,
// trailing-slash. The matrix takes a few minutes per scan but catches:
//
//   - per-charset routing differences (a router that 200s alnum but
//     redirects unicode through a different handler)
//   - length-boundary soft 404s (a CMS that switches to a generic error
//     page once the URL exceeds N chars)
//   - per-extension soft 404s (an .ashx handler returning a different
//     stub page than the .aspx default)
//   - encoded-special quirks (% < > ' triggering WAF intercept pages)
//
// Detection: any (status_code, body_size) recurring ≥5× anywhere in the
// matrix is recorded as a FP body-size signature. The status code itself
// is locked in only if it dominates ⅔+ of the matrix — heterogeneous
// servers (e.g. mixed 200 + 414) fall back to size-only filtering.
// fpProbesPerExt is the calibrateFP probe budget per extension: 6 charsets
// × 8 lengths × 6 shapes × 8 reqs/bucket. Exposed as a package-level const
// so the caller can pre-seed the progress denominator before calibration
// starts. Keep this in sync with the matrix dimensions inside calibrateFP.
const fpProbesPerExt = 6 * 8 * 6 * 8 // = 2304

// calibrateFP fingerprints each extension's "not-found" response. The optional
// `onProbe` callback fires once per completed (or failed) HTTP probe so the
// caller can advance an external progress counter — nil disables it. The
// callback runs from worker goroutines and must be cheap + goroutine-safe.
func calibrateFP(client *http.Client, target string, extensions []string, opts *shared.HTTPOptions, onProbe func()) map[string]FPSignature {
	result := map[string]FPSignature{}

	testExts := append([]string{""}, extensions...)

	var mu sync.Mutex
	var wg sync.WaitGroup
	sem := make(chan struct{}, 30)

	type shapeFn func(s string) string
	shapes := []shapeFn{
		func(s string) string { return s },             // plain
		func(s string) string { return "." + s },       // leading dot
		func(s string) string { return `"` + s + `"` }, // surrounding quotes (raw — PathEscape encodes them)
		func(s string) string { return " " + s + " " }, // surrounding spaces
		func(s string) string { return s + ".." + s },  // doubled with dots — exercises path-normalization
		func(s string) string { return s + "/" },       // trailing slash on the segment
	}
	charsets := []string{
		fpAlnumCharset,
		fpSpecialCharset,
		fpDigitsCharset,
		fpUpperCharset,
		fpMixedCharset,
		fpUnicodeCharset,
	}
	lengths := []int{3, 12, 50, 100, 250, 500, 1000, 2000}
	const perBucket = 8
	totalProbes := len(charsets) * len(lengths) * len(shapes) * perBucket

	for _, ext := range testExts {
		wg.Add(1)
		go func(extension string) {
			defer wg.Done()
			codes := map[int]int{}
			sizesByCode := map[int]map[int64]int{}

			var innerWg sync.WaitGroup
			for _, cs := range charsets {
				for _, ln := range lengths {
					for _, sh := range shapes {
						for i := 0; i < perBucket; i++ {
							innerWg.Add(1)
							sem <- struct{}{}
							go func(charset string, length int, shapeF shapeFn) {
								defer innerWg.Done()
								defer func() { <-sem }()
								// Audit fix: fire onProbe exactly once per
								// scheduled probe — regardless of HTTP /
								// build error — so the external progress
								// counter advances even on connection
								// resets and early-return paths.
								defer func() {
									if onProbe != nil {
										onProbe()
									}
								}()

								// Build a raw segment, then PathEscape once
								// so specials like ? = & / don't break URL
								// parsing or get interpreted as routing.
								raw := shapeF(randomCharsFrom(charset, length))
								seg := url.PathEscape(raw)
								var path string
								if extension == "" {
									path = "/" + seg + "/"
								} else {
									path = "/" + seg + extension
								}

								req, err := http.NewRequest("GET", target+path, nil)
								if err != nil {
									return
								}
								req.Header.Set("User-Agent", "scaNNer-DirEnum/1.0")
								if opts != nil {
									opts.ApplyTo(req)
								}
								req = opts.BindContext(req)
								resp, err := client.Do(req)
								if err != nil {
									return
								}
								body, _ := io.ReadAll(io.LimitReader(resp.Body, 1024*1024))
								resp.Body.Close()
								bodySize := int64(len(body))

								mu.Lock()
								codes[resp.StatusCode]++
								if sizesByCode[resp.StatusCode] == nil {
									sizesByCode[resp.StatusCode] = map[int64]int{}
								}
								sizesByCode[resp.StatusCode][bodySize]++
								mu.Unlock()
							}(cs, ln, sh)
						}
					}
				}
			}
			innerWg.Wait()

			// Most-common status code across the matrix.
			maxCode := 0
			maxCount := 0
			for code, count := range codes {
				if count > maxCount {
					maxCount = count
					maxCode = code
				}
			}

			sig := FPSignature{Code: -1}

			// Any (code, size) repeating ≥5× → FP signature size. Per-bucket
			// soft-404 pages will show up here even when they don't dominate
			// the whole matrix (e.g. only the 1000-char alnum bucket has a
			// distinct 414 size). With 2304 probes the floor of 5 keeps
			// random coincidences from polluting sig.Sizes — a real bucket
			// fires 8 reqs and easily clears 5; spurious matches don't.
			for _, sizeCounts := range sizesByCode {
				for size, cnt := range sizeCounts {
					if cnt >= 5 {
						exists := false
						for _, s := range sig.Sizes {
							if s == size {
								exists = true
								break
							}
						}
						if !exists {
							sig.Sizes = append(sig.Sizes, size)
						}
					}
				}
			}

			// Lock in the code only if it dominates ⅔+ of the matrix.
			// Heterogeneous-response servers (e.g. 200/414 mix) will
			// fall back to size-based filtering only.
			if totalProbes > 0 && maxCount*3 >= totalProbes*2 {
				sig.Code = maxCode
			}

			if sig.Code != -1 || len(sig.Sizes) > 0 {
				mu.Lock()
				result[extension] = sig
				mu.Unlock()
			}
		}(ext)
	}
	wg.Wait()
	return result
}

// pluralY returns "y" for n=1 and "ies" otherwise. Used in "1 directory" /
// "5 directories" log lines.
func pluralY(n int) string {
	if n == 1 {
		return "y"
	}
	return "ies"
}

func pluralS(n int) string {
	if n == 1 {
		return ""
	}
	return "s"
}

// formatETA renders seconds as a compact duration string ("12s", "3m", "1h 04m").
func formatETA(sec int) string {
	if sec <= 0 {
		return "0s"
	}
	if sec < 60 {
		return fmt.Sprintf("%ds", sec)
	}
	if sec < 3600 {
		return fmt.Sprintf("%dm %02ds", sec/60, sec%60)
	}
	return fmt.Sprintf("%dh %02dm", sec/3600, (sec%3600)/60)
}

func probeURL(client *http.Client, fullURL, path string, opts *shared.HTTPOptions) *DirEntry {
	req, err := http.NewRequest("GET", fullURL, nil)
	if err != nil {
		return nil
	}
	req.Header.Set("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36")
	if opts != nil {
		opts.ApplyTo(req)
	}
	req = opts.BindContext(req)

	// Capture the on-the-wire request BEFORE Do() — once it's executed
	// the body reader is drained. shared.CaptureRequest buffers + restores
	// so client.Do() still works after we've captured.
	rawReq := shared.CaptureRequest(req)

	resp, err := client.Do(req)
	if err != nil {
		opts.RecordError(shared.ClassifyError(err))
		return nil
	}
	// Read body to get accurate size (ContentLength may be -1 or unreliable)
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 1024*1024))
	resp.Body.Close()

	// Skip obvious not-found
	if resp.StatusCode == 404 || resp.StatusCode == 0 {
		return nil
	}

	// Build the raw response string ourselves — we've already drained
	// the body so we can't call shared.CaptureResponse anymore.
	rawResp := formatRawResponse(resp, body)

	return &DirEntry{
		URL:         fullURL,
		Path:        path,
		StatusCode:  resp.StatusCode,
		Size:        int64(len(body)),
		ContentType: resp.Header.Get("Content-Type"),
		RedirectTo:  resp.Header.Get("Location"),
		IsDir:       strings.HasSuffix(path, "/"),
		RawRequest:  rawReq,
		RawResponse: rawResp,
	}
}

// formatRawResponse rebuilds the wire-format response after we've
// already consumed the body — direnum reads the body for size accuracy
// before we know whether to keep the entry, so we can't rely on
// shared.CaptureResponse here.
func formatRawResponse(resp *http.Response, body []byte) string {
	var b strings.Builder
	fmt.Fprintf(&b, "HTTP/%d.%d %d %s\r\n",
		resp.ProtoMajor, resp.ProtoMinor, resp.StatusCode, http.StatusText(resp.StatusCode))
	for k, vals := range resp.Header {
		for _, v := range vals {
			fmt.Fprintf(&b, "%s: %s\r\n", k, v)
		}
	}
	b.WriteString("\r\n")
	if len(body) > shared.MaxRawBody {
		b.Write(body[:shared.MaxRawBody])
		fmt.Fprintf(&b, "\n... [truncated %d bytes]", len(body)-shared.MaxRawBody)
	} else {
		b.Write(body)
	}
	return b.String()
}

func resolveProfiles(techIDs []string) []*TechProfile {
	var result []*TechProfile
	for _, id := range techIDs {
		for i := range AllTechProfiles {
			if AllTechProfiles[i].ID == id {
				result = append(result, &AllTechProfiles[i])
			}
		}
	}
	if len(result) == 0 {
		// Fallback to general
		for i := range AllTechProfiles {
			if AllTechProfiles[i].ID == "general" {
				return []*TechProfile{&AllTechProfiles[i]}
			}
		}
	}
	return result
}

// embeddedFallbackWords is a tiny fallback wordlist used when the path
// loadWordlist was asked to open doesn't exist or is empty (audit B69).
// Without this, a misconfigured /usr/share/seclists path made every
// scan silently return zero results — the operator saw "scan complete,
// 0 entries" with no clue that the wordlist was missing. This 30-entry
// list at least guarantees a useful smoke-pass over the most common
// admin / config / backup paths so the operator notices and fixes the
// install. The actual recommended fix is `apt install seclists`.
var embeddedFallbackWords = []string{
	"admin", "administrator", "login", "wp-admin", "phpmyadmin",
	"config", "config.php", ".env", "backup", "backup.zip",
	"api", "api/v1", "api/v2", "graphql", "swagger.json",
	"robots.txt", "sitemap.xml", ".git", ".git/config", ".htaccess",
	"server-status", "server-info", "actuator", "console",
	"upload", "uploads", "files", "download", "downloads", "test",
}

func loadWordlist(path string) []string {
	f, err := os.Open(path)
	if err != nil {
		// File missing or unreadable. Log once per path so the operator
		// sees what's actually expected, then fall through to the tiny
		// embedded fallback.
		log.Printf("direnum: wordlist not found at %q; using embedded fallback (%d entries) — install seclists for real scans", path, len(embeddedFallbackWords))
		return embeddedFallbackWords
	}
	defer f.Close()

	var words []string
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		w := strings.TrimSpace(sc.Text())
		if w != "" && !strings.HasPrefix(w, "#") {
			words = append(words, w)
		}
	}
	if len(words) == 0 {
		log.Printf("direnum: wordlist %q opened but contained no usable entries; using embedded fallback", path)
		return embeddedFallbackWords
	}
	return words
}

func appendUnique(slice []string, item string) []string {
	for _, s := range slice {
		if s == item {
			return slice
		}
	}
	return append(slice, item)
}
