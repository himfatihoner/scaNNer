package direnum

import (
	"bufio"
	"compress/gzip"
	"crypto/rand"
	"crypto/tls"
	"fmt"
	"io"
	"log"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"scanner/internal/modules/shared"
	"scanner/internal/modules/spider"
	"sort"
	"strings"
	"sync"
	"sync/atomic"
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

	// ManualDirs are directory/file paths the operator typed into the launch
	// form (e.g. "/admin", "news/first/x.html"). Each is probed directly and its
	// ancestor directories are seeded into the scan frontier before the wordlist
	// brute force starts.
	ManualDirs []string

	// Spider enables an active same-FQDN web crawl (reusing the spider engine:
	// robots/sitemap seeding + link following) plus inline link-extraction from
	// every HTML page the brute force fetches. Discovered directories/paths are
	// folded into the globally-deduplicated scan frontier, so the brute force
	// also covers everything the site links to. Heavier — opt-in, default off.
	Spider bool

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

	// DirScans is the per-directory live scan state (feroxbuster-style): one
	// entry per directory the frontier processes, with its queued/scanning/done
	// status + request and hit counts. Surfaced in partial snapshots so the
	// results page can show which directories are being scanned in real time.
	DirScans []DirScanState `json:"dir_scans,omitempty"`
}

// DirScanState is the live status of one directory in the scan frontier,
// rendered as a feroxbuster-style "scanning /admin/ …" list on the results page.
type DirScanState struct {
	Prefix   string `json:"prefix"` // "/" (root) or "/admin/"
	Status   string `json:"status"` // "queued" | "scanning" | "done"
	ReqDone  int    `json:"req_done"`
	ReqTotal int    `json:"req_total"`
	Hits     int    `json:"hits"`
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
	// Parsed base for same-FQDN resolution (redirect-driven + spider frontier).
	targetURL, _ := url.Parse(target)

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
	level := int(cfg.Level)
	var bundledLoaded []string
	for _, p := range profiles {
		for _, ext := range p.Extensions {
			allExts = appendUnique(allExts, ext)
		}
		// Prefer the generated per-language tier list when it's been built. Its
		// extensions + backup/archive permutations are already baked in, so it
		// loads verbatim as literal paths and the system word×ext matrix for
		// this profile is skipped. Falls back to the system SecLists paths when
		// the bundle is absent (see bundledTierFor / BundleKey).
		if bundled, ok := bundledTierFor(p.BundleKey, level); ok {
			for _, w := range loadWordlist(bundled) {
				literalPaths[w] = true
			}
			bundledLoaded = append(bundledLoaded, fmt.Sprintf("%s=t%d", p.ID, level+1))
		} else {
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
	if len(bundledLoaded) > 0 {
		logFn(fmt.Sprintf("[%s] Bundled tier lists: %s (run scripts/build-direnum-wordlists.sh to (re)build)", target, strings.Join(bundledLoaded, " ")))
	}
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

	// ---- Unified, globally-deduplicated scan frontier ----
	// Every path probed — from the wordlist, manual input, the web spider, or
	// an HTTP redirect — is gated through `seen` so nothing is requested twice.
	// `pendingDirs`/`pendingLeaves` are the dynamic frontier the BFS drains at
	// each level: dirs to brute-force into, and one-shot leaf probes.
	// `visited` is the directory-recursion cycle guard (shared by the BFS and
	// the derive-from-discovery path). All mutated under `mu` once goroutines
	// start; the manual seed below runs single-threaded so needs no lock.
	seen := map[string]bool{}
	visited := map[string]bool{"/": true}
	// frontierSeen dedups what the derive-from-discovery sources (manual /
	// spider / redirect) ADD to the frontier, so a path linked from 50 pages is
	// enqueued once. It is deliberately separate from `visited` (which is the
	// BFS queue's own dedup, written only by enqueuePrefix) — conflating the two
	// would let an adder pre-mark a dir "visited" and make enqueuePrefix skip it.
	frontierSeen := map[string]bool{}
	pendingDirs := []string{}
	pendingLeaves := []reqItem{}
	spiderBudget := spiderCapFor(cfg)

	// DirScans: feroxbuster-style live per-directory status (#3). dirScanIdx maps
	// a prefix to its slice index for O(1) upserts.
	dirScans := []DirScanState{}
	dirScanIdx := map[string]int{}

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

	// isSkipped reports whether the user has marked this path (or an ancestor)
	// as skipped via the runtime skip endpoint. The absolute URL (target+path)
	// is the key — exactly what the user clicks in the UI. Shared by the manual
	// seed, the derive-from-discovery frontier, and the recursive BFS.
	isSkipped := func(prefix string) bool {
		if cfg.IsSkipped == nil {
			return false
		}
		return cfg.IsSkipped(target + prefix)
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

	// ---- Manual directories (#1) ----
	// Probe every operator-supplied path directly (counted into the root request
	// budget so the progress bar stays exact) and seed its parent directories —
	// plus itself when it's a directory — into the frontier so the brute force
	// also recurses into them. Runs single-threaded here (no goroutines yet).
	manualSeeded := 0
	for _, raw := range cfg.ManualDirs {
		leaf, dirs := splitLeafAndDirs(raw)
		if leaf == "" || leaf == "/" {
			continue
		}
		for _, d := range dirs {
			if frontierSeen[d] || matchesExclude(d) || isSkipped(d) {
				continue
			}
			frontierSeen[d] = true
			pendingDirs = append(pendingDirs, d)
		}
		if frontierSeen[leaf] || matchesExclude(leaf) || isSkipped(leaf) {
			continue
		}
		frontierSeen[leaf] = true
		ext := ""
		if !strings.HasSuffix(leaf, "/") {
			ext = extractExtFromPath(leaf)
		}
		// Not pre-marked `seen` — the processRequest gate is the sole authority
		// for `seen`, so it dedupes manual-vs-wordlist on dispatch.
		requests = append(requests, reqItem{path: leaf, ext: ext})
		manualSeeded++
	}
	if manualSeeded > 0 {
		logFn(fmt.Sprintf("[%s] Manual: seeded %d path(s) + their parent directories into the frontier", target, manualSeeded))
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
			DirScans:      append([]DirScanState(nil), dirScans...),
		}
		mu.Unlock()
		partialFn(snap)
	}

	// dirScanSet upserts a directory's live status for the feroxbuster-style
	// view (#3). Caller holds mu. A non-empty status / positive reqTotal updates
	// the field; a brand-new prefix is appended as queued/scanning.
	dirScanSet := func(prefix, status string, reqTotal int) {
		prefix = normSeenKey(prefix)
		if i, ok := dirScanIdx[prefix]; ok {
			if status != "" {
				dirScans[i].Status = status
			}
			if reqTotal > 0 {
				dirScans[i].ReqTotal = reqTotal
			}
			return
		}
		dirScans = append(dirScans, DirScanState{Prefix: prefix, Status: status, ReqTotal: reqTotal})
		dirScanIdx[prefix] = len(dirScans) - 1
	}

	// enqueueDerived folds a discovered leaf + its recurse-into directories into
	// the frontier, deduped (dirs via `visited`, leaves via the processRequest
	// `seen` gate on dispatch), honoring exclude/skip. Caller holds mu. Returns
	// true if anything new was added (so the caller can decrement spiderBudget).
	enqueueDerived := func(leaf string, dirs []string) bool {
		added := false
		for _, d := range dirs {
			if frontierSeen[d] || matchesExclude(d) || isSkipped(d) {
				continue
			}
			frontierSeen[d] = true
			pendingDirs = append(pendingDirs, d)
			added = true
		}
		if leaf != "" && leaf != "/" && !frontierSeen[leaf] && !matchesExclude(leaf) && !isSkipped(leaf) {
			frontierSeen[leaf] = true
			ext := ""
			if !strings.HasSuffix(leaf, "/") {
				ext = extractExtFromPath(leaf)
			}
			pendingLeaves = append(pendingLeaves, reqItem{path: leaf, ext: ext})
			added = true
		}
		return added
	}

	// isSameFQDNHTML reports whether an entry is an HTML page worth scraping for
	// links (2xx/3xx, text/html). Cross-host is impossible here (we only request
	// our own target) so only the content-type matters.
	isSameFQDNHTML := func(e *DirEntry) bool {
		if e == nil || e.StatusCode >= 400 {
			return false
		}
		return strings.Contains(strings.ToLower(e.ContentType), "text/html")
	}

	// maybeEnqueueFromEntry applies the always-on redirect expansion (#4/#6) and,
	// when the spider is enabled, the inline same-FQDN link extraction (#2) to a
	// freshly-probed entry, folding discoveries into the frontier. The expensive
	// HTML parse runs OUTSIDE mu; only the small enqueue bookkeeping re-takes it.
	maybeEnqueueFromEntry := func(entry *DirEntry, body []byte) {
		if entry == nil {
			return
		}
		// Redirect-driven frontier (#4 new-path, #6 dir promotion) — always on.
		if entry.StatusCode == 301 || entry.StatusCode == 302 {
			if loc := sameFQDNPath(entry.RedirectTo, targetURL); loc != "" {
				selfDir := strings.TrimRight(normSeenKey(entry.Path), "/") + "/"
				mu.Lock()
				if loc == selfDir {
					// #6: /admin -> /admin/ — the path is really a directory.
					if !frontierSeen[loc] && !matchesExclude(loc) && !isSkipped(loc) {
						frontierSeen[loc] = true
						pendingDirs = append(pendingDirs, loc)
					}
				} else if spiderBudget > 0 {
					// #4: redirect to a new path — derive + enqueue it.
					leaf, dirs := splitLeafAndDirs(loc)
					if enqueueDerived(leaf, dirs) {
						spiderBudget--
					}
				}
				mu.Unlock()
			}
		}
		// Inline spider link extraction (#2, opt-in): same-FQDN HTML only.
		if cfg.Spider && isSameFQDNHTML(entry) && len(body) > 0 {
			paths := extractSameFQDNPaths(body, targetURL) // regex over body — unlocked
			if len(paths) == 0 {
				return
			}
			mu.Lock()
			for _, p := range paths {
				if spiderBudget <= 0 {
					break
				}
				leaf, dirs := splitLeafAndDirs(p)
				if enqueueDerived(leaf, dirs) {
					spiderBudget--
				}
			}
			mu.Unlock()
		}
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

			// Global dedup gate (#2 "aynı dizin/dosya tekrar taranmasın"): skip if
			// this exact path was already dispatched from ANY source (wordlist /
			// manual / spider / redirect). The dup still counted toward totalReqs,
			// so compensate done++ + emit to keep the bar monotonic and closing.
			seenKey := normSeenKey(r.path)
			mu.Lock()
			if seen[seenKey] {
				done++
				if idx >= 0 && idx < len(rootCompleted) {
					rootCompleted[idx] = true
				}
				if i, ok := dirScanIdx[parentDir(r.path)]; ok {
					dirScans[i].ReqDone++
				}
				mu.Unlock()
				if emit != nil {
					emit(0, 1, "")
				}
				return
			}
			seen[seenKey] = true
			mu.Unlock()

			fullURL := target + r.path
			entry, body := probeURL(client, fullURL, r.path, opts)

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
				// Live per-directory request accounting (#3).
				if i, ok := dirScanIdx[parentDir(r.path)]; ok {
					dirScans[i].ReqDone++
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
				if i, ok := dirScanIdx[parentDir(r.path)]; ok {
					dirScans[i].Hits++
				}
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
			// Grow the frontier from this response: redirect expansion (#4/#6,
			// always) + inline spider link extraction (#2, when enabled). Runs
			// for every probed entry, not just surfaced hits, so a filtered-but-
			// real HTML page still contributes its links.
			maybeEnqueueFromEntry(entry, body)
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
	// Register the root "/" directory in the live view (#3) before dispatch.
	mu.Lock()
	dirScanSet("/", "scanning", len(requests))
	dirScans[dirScanIdx["/"]].ReqDone = startIdx
	mu.Unlock()
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
	mu.Lock()
	dirScanSet("/", "done", 0)
	mu.Unlock()
	firePartial()

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

	// --- Frontier / recursive BFS levels ---
	// Walk every directory discovered so far — from the wordlist root, the
	// manual seeds, HTTP redirects, and (when enabled) the active web spider —
	// and re-run the brute force inside it, up to maxDepth levels deep. The
	// dynamic frontier (pendingDirs/pendingLeaves, mu-guarded) is drained at the
	// top of every level, so discoveries that arrive mid-scan are folded in
	// automatically and deduped via the target-scope `visited`/`seen`.
	mu.Lock()
	frontierPending := len(pendingDirs) > 0 || len(pendingLeaves) > 0
	mu.Unlock()
	if ((cfg.Recursive && cfg.MaxDepth > 0) || cfg.Spider || frontierPending) && !opts.Done() {
		maxDepth := cfg.MaxDepth
		if maxDepth < 1 {
			maxDepth = 2 // spider/manual with the Recursive box off still needs depth
		}

		queue := []string{}
		skippedAtSeed := 0
		// enqueuePrefix visited-gates a directory into the live queue and marks
		// it queued in the feroxbuster-style view (#3).
		enqueuePrefix := func(raw string) {
			p := strings.TrimRight(normSeenKey(raw), "/") + "/"
			if p == "/" || visited[p] {
				return
			}
			visited[p] = true
			if isSkipped(p) || matchesExclude(p) {
				skippedAtSeed++
				return
			}
			queue = append(queue, p)
			mu.Lock()
			dirScanSet(p, "queued", 0)
			mu.Unlock()
		}

		// Seed from root discoveries (dir hits + 403 dirs) and the frontier that
		// the root brute force + manual seed already accumulated.
		mu.Lock()
		seedSnapshot := append([]DirEntry(nil), entries...)
		forbiddenSeed := append([]string(nil), forbiddenDirs[forbiddenCursor:]...)
		forbiddenCursor = len(forbiddenDirs)
		seedDirs := pendingDirs
		pendingDirs = nil
		mu.Unlock()
		for _, e := range seedSnapshot {
			if e.IsDir {
				enqueuePrefix(e.Path)
			}
		}
		for _, p := range forbiddenSeed {
			enqueuePrefix(p)
		}
		for _, p := range seedDirs {
			enqueuePrefix(p)
		}
		if skippedAtSeed > 0 {
			logFn(fmt.Sprintf("[%s] Skip list: dropped %d director%s before recursion", target, skippedAtSeed, pluralY(skippedAtSeed)))
		}

		// Start the active same-FQDN web crawl concurrently (#2). It feeds every
		// discovered dir/path into the same frontier the BFS drains, deduped.
		// spiderRunning keeps the drain loop alive across momentarily-empty
		// rounds until the crawl ends; opts.Ctx cancels it on pause/kill.
		var spiderRunning atomic.Bool
		var spiderWG sync.WaitGroup
		if cfg.Spider {
			spiderRunning.Store(true)
			spiderWG.Add(1)
			go func() {
				defer spiderWG.Done()
				defer spiderRunning.Store(false)
				runSpiderInto(target, cfg, opts, func(p string) {
					mu.Lock()
					if spiderBudget > 0 {
						leaf, dirs := splitLeafAndDirs(p)
						if enqueueDerived(leaf, dirs) {
							spiderBudget--
						}
					}
					mu.Unlock()
				})
			}()
			logFn(fmt.Sprintf("[%s] Web spider: active crawl started — feeding discovered paths into the scan frontier", target))
		}

		for depth := 1; depth <= maxDepth && !opts.Done(); depth++ {
			// Drain the frontier accumulated since the previous level: directories
			// to brute-force into + one-shot leaf probes (manual/spider/redirect).
			mu.Lock()
			leaves := pendingLeaves
			pendingLeaves = nil
			fdirs := pendingDirs
			pendingDirs = nil
			mu.Unlock()
			for _, p := range fdirs {
				enqueuePrefix(p)
			}

			if len(queue) == 0 && len(leaves) == 0 {
				// Nothing to scan this round. If the spider is still crawling,
				// wait briefly for it to produce work rather than exiting early;
				// an empty wait round does not consume a depth level.
				if cfg.Spider && spiderRunning.Load() && !opts.Done() {
					depth--
					ctxWait(opts, 400*time.Millisecond)
					continue
				}
				break
			}

			nDirs := len(queue)
			logFn(fmt.Sprintf("[%s] Depth %d: scanning %d sub-director%s + %d derived path%s",
				target, depth, nDirs, pluralY(nDirs), len(leaves), pluralS(len(leaves))))

			// This level's requests: frontier leaves first, then the wordlist×ext
			// matrix for every queued directory (marked scanning in the view).
			levelRequests := append([]reqItem(nil), leaves...)
			for _, prefix := range queue {
				reqs := buildRequestsForPrefix(prefix)
				mu.Lock()
				dirScanSet(prefix, "scanning", len(reqs))
				mu.Unlock()
				levelRequests = append(levelRequests, reqs...)
			}

			mu.Lock()
			totalReqs += len(levelRequests)
			tr.TotalRequests = totalReqs
			prevLen := len(entries)
			mu.Unlock()
			if emit != nil {
				emit(len(levelRequests), 0,
					fmt.Sprintf("[%s] depth %d: queued %d paths across %d dirs", target, depth, len(levelRequests), nDirs))
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
				// Re-check on every request — the user may add a skip mid-level,
				// and in-flight work for that prefix should drop immediately.
				if isSkipped(ri.path) {
					skippedThisLevel++
					continue
				}
				processRequest(ri, &lwg, -1)
			}
			lwg.Wait()

			// Mark this level's directories done in the live view.
			mu.Lock()
			for _, prefix := range queue {
				dirScanSet(prefix, "done", 0)
			}
			mu.Unlock()

			if skippedThisLevel > 0 {
				logFn(fmt.Sprintf("[%s] Skip list: dropped %d in-flight request%s at depth %d", target, skippedThisLevel, pluralS(skippedThisLevel), depth))
				// Bump done (+ emit) for every skipped/un-reached request — they
				// were counted in totalReqs, so the bar would otherwise park short.
				mu.Lock()
				done += skippedThisLevel
				mu.Unlock()
				if emit != nil {
					emit(0, skippedThisLevel, "")
				}
			}

			// Collect dir hits found this level for the next round.
			mu.Lock()
			newSnapshot := append([]DirEntry(nil), entries[prevLen:]...)
			newForbidden := append([]string(nil), forbiddenDirs[forbiddenCursor:]...)
			forbiddenCursor = len(forbiddenDirs)
			mu.Unlock()
			queue = nil
			for _, e := range newSnapshot {
				if e.IsDir {
					enqueuePrefix(e.Path)
				}
			}
			for _, p := range newForbidden {
				enqueuePrefix(p)
			}
		}

		// The depth ceiling (or a cancel) ended the loop. Let the spider finish
		// (it's bounded by MaxPages and opts.Ctx) and give any leaves it produced
		// after the last level a terminal one-shot probe — directories past the
		// ceiling are intentionally not brute-forced further.
		if cfg.Spider {
			spiderWG.Wait()
			mu.Lock()
			tailLeaves := pendingLeaves
			pendingLeaves = nil
			pendingDirs = nil
			mu.Unlock()
			if len(tailLeaves) > 0 && !opts.Done() {
				mu.Lock()
				totalReqs += len(tailLeaves)
				tr.TotalRequests = totalReqs
				mu.Unlock()
				if emit != nil {
					emit(len(tailLeaves), 0, fmt.Sprintf("[%s] spider: probing %d final derived path(s)", target, len(tailLeaves)))
				}
				var fwg sync.WaitGroup
				for _, ri := range tailLeaves {
					if opts.Done() {
						break
					}
					processRequest(ri, &fwg, -1)
				}
				fwg.Wait()
			}
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

// --- Multi-source frontier helpers (manual dirs / web spider / redirects) ---

// normSeenKey collapses a request path to its global dedup identity. Directory
// and file variants stay DISTINCT ("/admin" vs "/admin/" vs "/admin.php") — only
// genuinely identical paths dedup. Ensures one leading slash, collapses "//".
func normSeenKey(path string) string {
	if path == "" {
		return "/"
	}
	if !strings.HasPrefix(path, "/") {
		path = "/" + path
	}
	for strings.Contains(path, "//") {
		path = strings.ReplaceAll(path, "//", "/")
	}
	return path
}

// parentDir returns the directory containing path, trailing-slashed:
// "/a/b/c.php"->"/a/b/", "/a/b/"->"/a/", "/x"->"/", "/"->"/".
func parentDir(path string) string {
	p := strings.TrimRight(normSeenKey(path), "/")
	i := strings.LastIndex(p, "/")
	if i <= 0 {
		return "/"
	}
	return p[:i+1]
}

// ancestorDirs yields the PARENT directory chain of a path, root-to-leaf,
// trailing-slashed, EXCLUDING "/" (root is always scanned) and the path itself.
// "/a/b/c.html"->["/a/","/a/b/"]; "/a/b/"->["/a/"]; "/x"->nil; "/x/"->nil.
func ancestorDirs(path string) []string {
	trimmed := strings.Trim(normSeenKey(path), "/")
	if trimmed == "" {
		return nil
	}
	segs := strings.Split(trimmed, "/")
	n := len(segs) - 1 // always drop the last segment — ancestors never include self
	var out []string
	cur := ""
	for i := 0; i < n; i++ {
		cur += "/" + segs[i]
		out = append(out, cur+"/")
	}
	return out
}

// splitLeafAndDirs classifies a raw manual/spider/redirect path into a leaf
// probe path + the directories to recurse into: its ancestor chain PLUS itself
// when the path is a directory (trailing slash). So "/news/first/x.html" yields
// leaf="/news/first/x.html", dirs=["/news/","/news/first/"]; "/news/" yields
// leaf="/news/", dirs=["/news/"].
func splitLeafAndDirs(raw string) (leaf string, dirs []string) {
	leaf = normSeenKey(strings.TrimSpace(raw))
	dirs = ancestorDirs(leaf)
	if strings.HasSuffix(leaf, "/") && leaf != "/" {
		dirs = append(dirs, leaf)
	}
	return leaf, dirs
}

// spiderCapFor bounds how many NEW paths the spider + redirect sources may add
// to the frontier per target (scaled by level) so a link-rich site can't
// explode the queue.
func spiderCapFor(cfg ScanConfig) int {
	switch cfg.Level {
	case LevelLight:
		return 500
	case LevelAggressive:
		return 5000
	default:
		return 2000
	}
}

// hrefRe harvests navigable paths from HTML (href/src/action attribute values).
var hrefRe = regexp.MustCompile(`(?i)(?:href|src|action)\s*=\s*["']([^"'#>\s]+)`)

// extractSameFQDNPaths parses an HTML body for href/src/action targets, resolves
// each against base, keeps only same-host (same FQDN) results, and returns
// cleaned absolute PATHS (query + fragment stripped). direnum-local: tuned to
// produce navigable paths for parent-directory derivation.
func extractSameFQDNPaths(body []byte, base *url.URL) []string {
	if base == nil || len(body) == 0 {
		return nil
	}
	seen := map[string]bool{}
	var out []string
	for _, m := range hrefRe.FindAllSubmatch(body, -1) {
		raw := strings.TrimSpace(string(m[1]))
		if raw == "" {
			continue
		}
		low := strings.ToLower(raw)
		if strings.HasPrefix(low, "javascript:") || strings.HasPrefix(low, "mailto:") ||
			strings.HasPrefix(low, "data:") || strings.HasPrefix(low, "tel:") {
			continue
		}
		p := sameFQDNPath(raw, base)
		if p == "" || seen[p] {
			continue
		}
		seen[p] = true
		out = append(out, p)
	}
	return out
}

// sameFQDNPath resolves raw against base; if the result is on the SAME host as
// base it returns its path (query+fragment stripped), else "". Rejects
// protocol-relative and absolute cross-host links.
func sameFQDNPath(raw string, base *url.URL) string {
	u, err := url.Parse(strings.TrimSpace(raw))
	if err != nil {
		return ""
	}
	abs := base.ResolveReference(u)
	if abs == nil || !strings.EqualFold(abs.Hostname(), base.Hostname()) {
		return ""
	}
	p := abs.EscapedPath()
	if p == "" {
		p = "/"
	}
	return normSeenKey(p)
}

// ctxWait blocks for d, or until opts' context is cancelled, whichever comes
// first. Used by the frontier drain loop to wait on the concurrent spider
// without busy-spinning or ignoring a pause/kill.
func ctxWait(opts *shared.HTTPOptions, d time.Duration) {
	t := time.NewTimer(d)
	defer t.Stop()
	var done <-chan struct{}
	if opts != nil && opts.Ctx != nil {
		done = opts.Ctx.Done()
	}
	select {
	case <-t.C:
	case <-done:
	}
}

// runSpiderInto runs an active same-FQDN web crawl against target (reusing the
// spider engine: robots/sitemap seeding + link following) and routes every
// discovered path to feed(), which the caller folds into the brute-force
// frontier. Blocks until the crawl ends or opts is cancelled. Page budget and
// depth scale with the scan level.
func runSpiderInto(target string, cfg ScanConfig, opts *shared.HTTPOptions, feed func(path string)) {
	scfg := spider.DefaultConfig()
	scfg.IncludeSubdomains = false // same FQDN only — matches the brute-force scope
	if cfg.Timeout > 0 {
		scfg.Timeout = cfg.Timeout
	}
	switch cfg.Level {
	case LevelLight:
		scfg.MaxDepth, scfg.MaxPages = 3, 300
	case LevelAggressive:
		scfg.MaxDepth, scfg.MaxPages = 6, 1500
	default:
		scfg.MaxDepth, scfg.MaxPages = 5, 750
	}
	if cfg.MaxDepth > 0 && cfg.MaxDepth < scfg.MaxDepth {
		scfg.MaxDepth = cfg.MaxDepth
	}

	seen := map[string]bool{}
	route := func(res *spider.ScanResult) {
		if res == nil {
			return
		}
		for _, tr := range res.Results {
			for _, r := range tr.Resources {
				if r.Path == "" || seen[r.Path] {
					continue
				}
				seen[r.Path] = true
				feed(r.Path)
			}
			for _, l := range tr.Links {
				u, err := url.Parse(l)
				if err != nil || u.Path == "" || seen[u.Path] {
					continue
				}
				seen[u.Path] = true
				feed(u.Path)
			}
		}
	}
	res := spider.Scan([]string{target}, scfg, opts, route, func(int, string) {})
	route(res)
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

// probeURL fetches one path and returns its DirEntry (nil for 404/0/error) plus
// the response body (goroutine-local, capped at 1 MiB). The body is surfaced so
// the caller can extract same-FQDN links for the spider frontier WITHOUT a second
// fetch; it is never stored on the DirEntry or in the result.
func probeURL(client *http.Client, fullURL, path string, opts *shared.HTTPOptions) (*DirEntry, []byte) {
	req, err := http.NewRequest("GET", fullURL, nil)
	if err != nil {
		return nil, nil
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
		return nil, nil
	}
	// Read body to get accurate size (ContentLength may be -1 or unreliable)
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 1024*1024))
	resp.Body.Close()

	// Skip obvious not-found
	if resp.StatusCode == 404 || resp.StatusCode == 0 {
		return nil, nil
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
	}, body
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

// direnumDataDir returns the directory the generated, bundled tier wordlists
// live under, honoring the DATA_DIR env override the rest of the app uses
// (default "data", resolved relative to the working dir like hashcat's bundled
// lists). Built by scripts/build-direnum-wordlists.sh; gitignored.
func direnumDataDir() string {
	d := os.Getenv("DATA_DIR")
	if d == "" {
		d = "data"
	}
	return filepath.Join(d, "direnum-wordlists")
}

// bundledTierFor returns the absolute path of the generated tier list for a
// profile's BundleKey at the given level (0=t1, 1=t2, 2=t3) and whether it
// exists as a non-empty file. It stats the file directly rather than going
// through loadWordlist, so an ABSENT bundle (fresh clone that hasn't run the
// generator) cleanly falls back to the profile's system SecLists paths instead
// of injecting the 30-word embedded fallback once per missing list.
func bundledTierFor(key string, level int) (string, bool) {
	if key == "" {
		return "", false
	}
	p := filepath.Join(direnumDataDir(), fmt.Sprintf("%s-t%d.txt.gz", key, level+1))
	fi, err := os.Stat(p)
	if err != nil || fi.IsDir() || fi.Size() == 0 {
		return "", false
	}
	if abs, err := filepath.Abs(p); err == nil {
		p = abs
	}
	return p, true
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

	// Bundled per-language tier lists ship gzipped (data/direnum-wordlists/
	// *.txt.gz) to keep them off the plain-text read path's disk footprint;
	// transparently decompress so profiles can point at either .txt or .txt.gz.
	var r io.Reader = f
	if strings.HasSuffix(path, ".gz") {
		gz, err := gzip.NewReader(f)
		if err != nil {
			log.Printf("direnum: wordlist %q is not valid gzip: %v; using embedded fallback", path, err)
			return embeddedFallbackWords
		}
		defer gz.Close()
		r = gz
	}

	var words []string
	sc := bufio.NewScanner(r)
	// Bundled 1M/3M-entry lists can carry long paths; raise the line cap well
	// above bufio's 64 KiB default so a long entry never silently truncates.
	sc.Buffer(make([]byte, 0, 64*1024), 1024*1024)
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
