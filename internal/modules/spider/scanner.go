package spider

import (
	"bytes"
	"crypto/tls"
	"fmt"
	"io"
	"net/http"
	"net/http/httputil"
	"net/url"
	"regexp"
	"scanner/internal/modules/shared"
	"sort"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

// ResourceType classifies a discovered path
type ResourceType string

const (
	TypeDirectory ResourceType = "directory"
	TypeFile      ResourceType = "file"
	TypeEndpoint  ResourceType = "endpoint"
)

// Resource is a single discovered URL path
type Resource struct {
	URL         string       `json:"url"`
	Path        string       `json:"path"`
	Type        ResourceType `json:"type"`
	StatusCode  int          `json:"status_code"`
	Size        int64        `json:"size"`
	ContentType string       `json:"content_type"`
	FoundOn     string       `json:"found_on"` // the page that referenced this
	Depth       int          `json:"depth"`
	RawRequest  string       `json:"raw_request,omitempty"`
	RawResponse string       `json:"raw_response,omitempty"`
}

func truncateRaw(s string, max int) string {
	if len(s) <= max {
		return s
	}
	return s[:max] + "\n\n... [truncated " + fmt.Sprintf("%d", len(s)-max) + " bytes]"
}

// PageComment is one HTML comment (<!-- ... -->) found during the crawl,
// with the page it was found on. HTML comments frequently leak internal
// notes, disabled/legacy markup, dev TODOs, framework/build metadata and
// occasionally credentials or internal hostnames — high-signal for recon.
type PageComment struct {
	FoundOn string `json:"found_on"`
	Text    string `json:"text"`
}

// FormField is one input/select/textarea inside a discovered <form>.
type FormField struct {
	Name string `json:"name"`
	Type string `json:"type,omitempty"` // input type, or "select"/"textarea"
}

// PageForm is one HTML <form> discovered on a crawled page — the highest-
// value recon artifact for a web pentest (attack surface: what params the
// app accepts, where they post, and by which method).
type PageForm struct {
	FoundOn string      `json:"found_on"`
	Action  string      `json:"action"`
	Method  string      `json:"method"`
	Fields  []FormField `json:"fields,omitempty"`
}

// TargetResult holds all spider results for one seed URL.
//
// Beyond the crawled Resource tree, the spider harvests high-signal recon
// artifacts from every HTML page body (all deduped + capped):
//   - Emails        : addresses in text + mailto: links
//   - Links         : in-scope hyperlinks (navigable internal URLs)
//   - ExternalLinks : absolute links/files pointing OFF the in-scope host
//   - JSFiles       : referenced .js resources
//   - Images        : <img>/<source> image resources
//   - Videos        : <video>/<source> + embedded video URLs
//   - Audio         : <audio>/<source> audio resources
//   - Forms         : <form> action/method + their input fields
//   - Comments      : HTML <!-- ... --> blocks
type TargetResult struct {
	URL        string     `json:"url"`
	Resources  []Resource `json:"resources"`
	TotalPages int        `json:"total_pages"`
	TotalDirs  int        `json:"total_dirs"`
	TotalFiles int        `json:"total_files"`

	Emails        []string      `json:"emails,omitempty"`
	Links         []string      `json:"links,omitempty"`
	ExternalLinks []string      `json:"external_links,omitempty"`
	JSFiles       []string      `json:"js_files,omitempty"`
	Images        []string      `json:"images,omitempty"`
	Videos        []string      `json:"videos,omitempty"`
	Audio         []string      `json:"audio,omitempty"`
	Forms         []PageForm    `json:"forms,omitempty"`
	Comments      []PageComment `json:"comments,omitempty"`

	Error string `json:"error,omitempty"`

	// Checkpoint is set ONLY when this seed's crawl was cut short by a
	// connectivity pause (ctx cancel) before it finished. It carries the
	// exact frontier needed to resume the crawl losslessly (Task 0). A
	// finished seed has a nil Checkpoint. Not carried across the wire with
	// Resources populated — the resume adapter fills Checkpoint.Resources
	// from this TargetResult's Resources at resume time (see handlers).
	Checkpoint *CrawlCheckpoint `json:"checkpoint,omitempty"`
}

// CheckpointTask is the JSON-serialisable form of an internal crawlTask
// (whose fields are unexported and so can't marshal). One pending frontier
// entry: a URL still to fetch, at what depth, discovered on which page.
type CheckpointTask struct {
	URL     string `json:"url"`
	Depth   int    `json:"depth"`
	FoundOn string `json:"found_on"`
}

// CrawlCheckpoint is the minimal state that lets a paused crawl continue
// exactly where it stopped: the set of URLs already fetched-or-dead
// (Visited), the queue of URLs still to fetch (Frontier), and the pages-
// consumed counter (Count, for the MaxPages ceiling). Visited excludes the
// Frontier norms so a resumed crawl can re-enqueue the frontier through the
// normal visited-guarded path. Resources is empty when persisted (the finds
// live in TargetResult.Resources) and is populated in-memory by the resume
// adapter so the resumed crawl preloads prior finds.
type CrawlCheckpoint struct {
	Visited   []string         `json:"visited"`
	Frontier  []CheckpointTask `json:"frontier"`
	Count     int              `json:"count"`
	Resources []Resource       `json:"resources,omitempty"`
}

type ScanResult struct {
	Results []TargetResult `json:"results"`
}

type SpiderConfig struct {
	MaxDepth    int
	MaxPages    int
	Concurrency int
	Timeout     time.Duration
	// IncludeSubdomains widens the same-host scope check to the eTLD+1
	// (so api.example.com is followed when seeded from www.example.com).
	IncludeSubdomains bool
	// ExcludeRegex holds one regex pattern per line; any URL whose path
	// matches any of these is skipped (never enqueued, never fetched).
	// Compiled once in crawl().
	ExcludeRegex []string
	// RequestDelay is the delay applied before each page fetch so a
	// crawl can be rate-limited on flaky / production targets.
	RequestDelay time.Duration

	// ResumeCheckpoints seeds a resumed crawl (Task 0 lossless resume),
	// keyed by seed URL. When Scan finds a checkpoint for a seed it hands
	// it to crawl(), which preloads Visited/Count/Resources and re-seeds the
	// frontier instead of starting from robots/sitemap/seed. Not persisted
	// (json:"-") — the resume adapter builds it from the paused result row.
	ResumeCheckpoints map[string]*CrawlCheckpoint `json:"-"`
}

func DefaultConfig() SpiderConfig {
	return SpiderConfig{
		MaxDepth:    5,
		MaxPages:    500,
		Concurrency: 10,
		Timeout:     10 * time.Second,
	}
}

type ProgressFunc func(done int, msg string)

// PartialFunc fires as the scan discovers new resources for live UI updates
type PartialFunc func(partial *ScanResult)

func Scan(urls []string, cfg SpiderConfig, opts *shared.HTTPOptions, onPartial PartialFunc, progress ProgressFunc) *ScanResult {
	result := &ScanResult{}
	var mu sync.Mutex

	// Fires whenever the current crawler has a new page done — snapshots and reports
	partialReport := func(currentTR *TargetResult) {
		if onPartial == nil {
			return
		}
		mu.Lock()
		// Build snapshot: previously finished results + in-progress current result
		snap := &ScanResult{Results: append([]TargetResult(nil), result.Results...)}
		if currentTR != nil {
			snap.Results = append(snap.Results, *currentTR)
		}
		mu.Unlock()
		onPartial(snap)
	}

	// A crawl has no honest upfront denominator — MaxPages is a hard ceiling
	// that's almost never reached, so a "pages / (seeds×MaxPages)" bar sat at
	// a few percent the whole run and then snapped to 100%. The handler now
	// sets progress_total=0 (indeterminate: striped "working" bar), and we
	// report the REAL cumulative page count as `done`, so the UI shows an
	// honest "142 pages crawled" instead of a fictional percentage.
	pagesSoFar := 0
	// Reachability preflight: skip TLS-dead seeds up front.
	if opts != nil && opts.PreflightEnabled {
		live, dead := shared.FilterReachable(opts.Ctx, opts, urls, opts.PreflightTimeout, 0)
		for t, reason := range dead {
			result.Results = append(result.Results, TargetResult{URL: t, Error: "unreachable — " + reason})
		}
		urls = live
	}
	for i, seedURL := range urls {
		if opts.Done() {
			break
		}
		if progress != nil {
			progress(pagesSoFar, fmt.Sprintf("Crawling %s ...", seedURL))
		}
		// Resume this seed from its saved frontier if one was handed in.
		var cp *CrawlCheckpoint
		if cfg.ResumeCheckpoints != nil {
			cp = cfg.ResumeCheckpoints[seedURL]
		}
		tr := crawl(seedURL, cfg, opts, func(done int, msg string) {
			if progress != nil {
				progress(pagesSoFar+done, msg)
			}
		}, partialReport, cp)
		mu.Lock()
		result.Results = append(result.Results, *tr)
		mu.Unlock()
		pagesSoFar += tr.TotalPages
		if progress != nil {
			progress(pagesSoFar, fmt.Sprintf("[%d/%d] %s — %d pages, %d resources", i+1, len(urls), seedURL, tr.TotalPages, len(tr.Resources)))
		}
		// Final partial fire after each URL completes
		partialReport(nil)
	}
	return result
}

type crawler struct {
	cfg       SpiderConfig
	client    *http.Client
	opts      *shared.HTTPOptions
	baseURL   *url.URL
	baseHost  string
	// baseETLD is set when IncludeSubdomains is on: an in-scope host must
	// end with "." + baseETLD (or equal it). Cheaper than a full public-
	// suffix lookup — we treat the seed host's last two dotted labels as
	// the site root, which is right for the ~95 % common case.
	baseETLD  string
	// excludeRegex holds compiled exclude patterns (empty if none). URL
	// path matches short-circuit enqueue.
	excludeRegex []*regexp.Regexp
	visited   map[string]bool
	resources map[string]*Resource
	queue     chan crawlTask
	mu        sync.Mutex
	closed    bool // audit K10/K11: guards send-on-closed-channel panic; flipped true under mu before close(queue)
	wg        sync.WaitGroup
	count     int
	// reclaimed holds tasks that were popped/attempted but NOT recorded
	// because a connectivity pause (ctx cancel) fired mid-flight: workers
	// that bailed before counting a page, and children whose enqueue send
	// lost the ctx race. Combined with draining the queue at shutdown, this
	// is the complete un-processed frontier for a lossless resume. Guarded
	// by mu. Empty unless the crawl was cancelled.
	reclaimed []crawlTask
	// inflight counts tasks that have been enqueued but not yet finished
	// processing. Incremented in enqueue() after a successful channel send;
	// decremented via defer in processPage. The exhaustion poll loop only
	// declares the crawl finished when this is zero AND the queue is
	// empty AND we've gone N stale rounds. Without this, a slow target
	// whose workers are blocked in client.Do for >7.5 s would race the
	// close(c.queue) (audit fix: in-flight worker race).
	inflight  atomic.Int64
	logFn     func(done int, msg string)
	partialFn func(*TargetResult)
	// throttle rate-limits firePartial so big crawls don't pay O(N²)
	// snapshot-copy + callback cost on every page completion (audit fix).
	throttle *shared.PartialThrottler
	tr       *TargetResult

	// Recon-artifact aggregation across the whole crawl. Dedup sets are
	// guarded by mu (populated from concurrent worker goroutines) and
	// capped so a huge site can't blow the result blob. Emitted into
	// TargetResult at crawl end.
	emails        map[string]bool
	links         map[string]bool
	externalLinks map[string]bool
	jsFiles       map[string]bool
	images        map[string]bool
	videos        map[string]bool
	audio         map[string]bool
	commentSeen   map[string]bool
	comments      []PageComment
	formSeen      map[string]bool
	forms         []PageForm
}

type crawlTask struct {
	url     string
	depth   int
	foundOn string
}

func crawl(seedURL string, cfg SpiderConfig, opts *shared.HTTPOptions, logFn func(done int, msg string), partialFn func(*TargetResult), resume *CrawlCheckpoint) *TargetResult {
	tr := &TargetResult{URL: seedURL}

	if !strings.HasPrefix(seedURL, "http://") && !strings.HasPrefix(seedURL, "https://") {
		seedURL = "https://" + seedURL
		tr.URL = seedURL
	}

	parsed, err := url.Parse(seedURL)
	if err != nil {
		tr.Error = err.Error()
		return tr
	}

	transport := &http.Transport{
		TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
		DialContext:     shared.BoundDialer(nil, 5 * time.Second).DialContext,
		// Idle conn pool sized for the actual worker count. Default
		// MaxIdleConnsPerHost=2 starved keep-alive on single-host
		// crawls: with 10 workers, 8 finished conns evicted the pool
		// and forced fresh TCP+TLS handshakes on the next hit. Match
		// per-host cap to the concurrency ceiling so each worker keeps
		// its own warm socket (audit finding, perf).
		MaxIdleConns:        cfg.Concurrency,
		MaxIdleConnsPerHost: cfg.Concurrency,
		MaxConnsPerHost:     cfg.Concurrency,
		IdleConnTimeout:     30 * time.Second,
	}
	if opts != nil {
		opts.ApplyTransport(transport)
	}
	// Compile any exclude regex patterns up front. Bad patterns are
	// silently dropped — the alternative is failing the entire scan
	// on a typo, which is worse UX for a pentester twiddling toggles.
	var excludes []*regexp.Regexp
	for _, pat := range cfg.ExcludeRegex {
		pat = strings.TrimSpace(pat)
		if pat == "" {
			continue
		}
		if re, err := regexp.Compile(pat); err == nil {
			excludes = append(excludes, re)
		}
	}
	c := &crawler{
		cfg:          cfg,
		opts:         opts,
		baseURL:      parsed,
		baseHost:     parsed.Hostname(),
		baseETLD:     computeBaseETLD(parsed.Hostname()),
		excludeRegex: excludes,
		visited:      make(map[string]bool),
		resources:    make(map[string]*Resource),
		emails:        make(map[string]bool),
		links:         make(map[string]bool),
		externalLinks: make(map[string]bool),
		jsFiles:       make(map[string]bool),
		images:        make(map[string]bool),
		videos:        make(map[string]bool),
		audio:         make(map[string]bool),
		commentSeen:   make(map[string]bool),
		formSeen:      make(map[string]bool),
		queue:        make(chan crawlTask, cfg.MaxPages*2),
		logFn:        logFn,
		partialFn:    partialFn,
		// Throttle expensive snapshot+callback to at most once per second.
		// The handler's 2 s DB-flush ticker still picks up the latest snap.
		throttle: shared.NewPartialThrottler(1 * time.Second),
		tr:       tr,
		client: &http.Client{
			Timeout:   cfg.Timeout,
			Transport: transport,
			CheckRedirect: func(req *http.Request, via []*http.Request) error {
				if len(via) > 3 {
					return http.ErrUseLastResponse
				}
				return nil
			},
		},
	}

	// Start workers
	sem := make(chan struct{}, cfg.Concurrency)
	done := make(chan struct{})

	go func() {
		defer close(done)
		for {
			// Cancellation fast-path (audit B28): without this select, the
			// dispatcher only exits when c.queue closes — meaning a cancelled
			// scan with a 10k-page backlog had to drain every queued URL
			// (each calling processPage which short-circuits on Done(), but
			// still ate goroutine-spawn overhead). Now we abandon the queue
			// the moment cancel fires, leaving any unprocessed tasks behind.
			if opts.Done() {
				return
			}
			select {
			case task, ok := <-c.queue:
				if !ok {
					return
				}
				sem <- struct{}{}
				c.wg.Add(1)
				go func(t crawlTask) {
					defer c.wg.Done()
					defer func() { <-sem }()
					c.processPage(t)
				}(task)
			case <-time.After(100 * time.Millisecond):
				// Re-check opts.Done() so a cancel that fires between
				// queue reads is picked up within 100 ms.
			}
		}
	}()

	// Seed the crawl from robots.txt + sitemap.xml before the seed URL.
	// These are the two highest-yield "free" discovery sources on any
	// modern site and every serious pentest crawler consumes them.
	// Missing them is why users reach for katana/gospider mid-engagement.
	// Failures are silent — a 404 on /robots.txt is expected on most
	// custom apps and should not block the actual crawl.
	if resume != nil {
		// Resumed crawl: preload the prior visited-set/pages/finds and
		// re-seed the saved frontier instead of starting from scratch.
		c.loadCheckpoint(resume)
	} else {
		c.seedFromRobots(parsed)
		c.seedFromSitemap(parsed)

		// Seed
		c.enqueue(crawlTask{url: seedURL, depth: 0, foundOn: "seed"})
	}

	// Wait for all work to finish
	// Use a ticker to check if queue is drained
	// Adaptive stale-round detection (audit B76). Previously the ticker
	// fired every 500 ms and exit-after-6-stales gave a flat 3 s cap.
	// A slow target (high latency or rate-limited) frequently took longer
	// than 3 s between successful page fetches, causing the crawler to
	// give up early. Now the polling interval grows on each stale tick
	// (500 ms → 1 s → 2 s → 4 s) and we cap at 4 stale doublings,
	// equivalent to ~7.5 s of inactivity before exit. Any fresh activity
	// resets to 500 ms so a recovering target gets full responsiveness.
	pollInterval := 500 * time.Millisecond
	const maxPoll = 4 * time.Second
	lastCount := 0
	staleRounds := 0
	for {
		select {
		case <-time.After(pollInterval):
		}
		if opts.Done() {
			break
		}
		c.mu.Lock()
		currentCount := c.count
		c.mu.Unlock()
		queueLen := len(c.queue)
		inflight := c.inflight.Load()
		if currentCount == lastCount {
			staleRounds++
			// Exponential backoff: double the poll interval each stale
			// round, capped at maxPoll. This is cheap and avoids hot-
			// looping on a paused crawler.
			if pollInterval < maxPoll {
				pollInterval *= 2
				if pollInterval > maxPoll {
					pollInterval = maxPoll
				}
			}
		} else {
			staleRounds = 0
			lastCount = currentCount
			pollInterval = 500 * time.Millisecond
		}
		// Exit only when 4 consecutive stale polls AND no outstanding
		// work (queue empty AND no worker still mid-roundtrip). Without
		// the inflight/queue guard, a slow target whose workers are
		// stuck in client.Do for >7.5 s would race close(c.queue) →
		// send-on-closed-channel / lost progress (audit fix).
		if staleRounds >= 4 && inflight == 0 && queueLen == 0 {
			break
		}
	}

	// Flip closed under mu so any worker mid-enqueue sees the flag before
	// it tries to send on c.queue, then close. Without this, worker A pops
	// a task, parses links, and calls enqueue → `c.queue <- t` while we
	// close → panic("send on closed channel"). See K10/K11.
	c.mu.Lock()
	c.closed = true
	c.mu.Unlock()
	close(c.queue)
	c.wg.Wait()

	// If a connectivity pause cut the crawl short, snapshot the frontier so
	// the scan can resume exactly here. All workers have returned (wg.Wait
	// above) so visited/count/reclaimed are stable and the queue holds only
	// its un-dispatched leftovers. A naturally-completed crawl leaves
	// Checkpoint nil.
	if opts != nil && opts.Done() {
		tr.Checkpoint = c.buildCheckpoint()
	}

	// Build results
	for _, r := range c.resources {
		tr.Resources = append(tr.Resources, *r)
	}
	sort.Slice(tr.Resources, func(i, j int) bool {
		return tr.Resources[i].Path < tr.Resources[j].Path
	})

	for _, r := range tr.Resources {
		switch r.Type {
		case TypeDirectory:
			tr.TotalDirs++
		case TypeFile:
			tr.TotalFiles++
		}
		tr.TotalPages++
	}

	// Attach harvested recon artifacts (sorted for stable output).
	tr.Emails = sortedKeys(c.emails)
	tr.Links = sortedKeys(c.links)
	tr.ExternalLinks = sortedKeys(c.externalLinks)
	tr.JSFiles = sortedKeys(c.jsFiles)
	tr.Images = sortedKeys(c.images)
	tr.Videos = sortedKeys(c.videos)
	tr.Audio = sortedKeys(c.audio)
	tr.Comments = c.comments
	tr.Forms = c.forms
	return tr
}

// sortedKeys returns the map keys as a sorted slice (nil for an empty map
// so the JSON field is omitted).
func sortedKeys(m map[string]bool) []string {
	if len(m) == 0 {
		return nil
	}
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

// reclaim records a task that could not be processed because the crawl was
// cancelled (paused) mid-flight, so it re-enters the frontier on resume. Only
// call when opts.Done() — a task abandoned for any other reason (genuine
// error, MaxPages) is legitimately consumed and must NOT be reclaimed.
func (c *crawler) reclaim(t crawlTask) {
	c.mu.Lock()
	c.reclaimed = append(c.reclaimed, t)
	c.mu.Unlock()
}

// loadCheckpoint restores a paused crawl's state before the workers start
// consuming: the pages-consumed counter, the visited-set, the prior finds,
// and the saved frontier (re-enqueued through the normal path). Called once,
// before any worker runs, so no locking races with processPage.
func (c *crawler) loadCheckpoint(cp *CrawlCheckpoint) {
	c.mu.Lock()
	c.count = cp.Count
	for _, v := range cp.Visited {
		c.visited[v] = true
	}
	for i := range cp.Resources {
		r := cp.Resources[i]
		if _, ok := c.resources[r.Path]; !ok {
			c.resources[r.Path] = &r
		}
	}
	c.mu.Unlock()
	// Re-seed the frontier through enqueue so it stamps visited on send and
	// honours the MaxPages/MaxDepth ceilings. The checkpoint builder excluded
	// these norms from Visited, so enqueue won't reject them as already-seen.
	for _, t := range cp.Frontier {
		c.enqueue(crawlTask{url: t.URL, depth: t.Depth, foundOn: t.FoundOn})
	}
}

// buildCheckpoint captures the un-processed frontier of a cancelled crawl.
// MUST be called after c.wg.Wait() (no workers running) and after close(queue)
// (so the range drains rather than blocks). The frontier is the union of the
// queue's un-dispatched leftovers and the reclaimed in-flight/lost-send tasks,
// deduped by normalized URL. Visited is recorded MINUS the frontier norms so a
// resumed crawl re-enqueues the frontier through the visited-guarded path.
func (c *crawler) buildCheckpoint() *CrawlCheckpoint {
	cp := &CrawlCheckpoint{Count: c.count}

	raw := make([]crawlTask, 0, len(c.queue)+len(c.reclaimed))
	for t := range c.queue { // closed channel → drains buffered items then ends
		raw = append(raw, t)
	}
	c.mu.Lock()
	raw = append(raw, c.reclaimed...)
	visitedCopy := make([]string, 0, len(c.visited))
	for v := range c.visited {
		visitedCopy = append(visitedCopy, v)
	}
	c.mu.Unlock()

	seen := make(map[string]bool, len(raw))
	frontierNorms := make(map[string]bool, len(raw))
	for _, t := range raw {
		n := c.normURL(t.url)
		if n == "" || seen[n] {
			continue
		}
		seen[n] = true
		frontierNorms[n] = true
		cp.Frontier = append(cp.Frontier, CheckpointTask{URL: t.url, Depth: t.depth, FoundOn: t.foundOn})
	}
	for _, v := range visitedCopy {
		if !frontierNorms[v] {
			cp.Visited = append(cp.Visited, v)
		}
	}
	sort.Strings(cp.Visited)
	return cp
}

func (c *crawler) enqueue(t crawlTask) {
	c.mu.Lock()

	if c.closed {
		// crawl() shutdown path already closed c.queue; sending now panics.
		// If we're shutting down because of a pause, the child we were about
		// to enqueue is un-processed frontier — reclaim it so resume re-adds
		// it (it was never visited-stamped, so it'd otherwise be lost).
		if c.opts != nil && c.opts.Done() {
			c.reclaimed = append(c.reclaimed, t)
		}
		c.mu.Unlock()
		return
	}

	norm := c.normURL(t.url)
	if norm == "" || c.visited[norm] || c.count >= c.cfg.MaxPages || t.depth > c.cfg.MaxDepth {
		c.mu.Unlock()
		return
	}
	// Never follow logout / session-terminating URLs — they would kill user-provided cookies
	if shared.IsLogoutPath(norm) {
		c.visited[norm] = true
		c.mu.Unlock()
		return
	}
	// Apply per-path exclude regex — used to skip destructive links
	// (delete /unsubscribe /logout) on live targets.
	if c.matchesExclude(norm) {
		c.visited[norm] = true
		c.mu.Unlock()
		return
	}
	// NOTE: visited is set BEFORE we release mu — but only AFTER a
	// successful queue send. Previously enqueue marked visited before
	// the send, so a full-buffer default-branch drop permanently
	// blacklisted the URL from ever being retried. Now the queue send
	// is a blocking select against ctx.Done() and visited is only
	// stamped when the task is actually in flight (audit finding —
	// dropped tasks silently degrade crawl coverage).
	c.mu.Unlock()

	// Blocking send with an abort path. The queue is buffered to
	// cfg.MaxPages*2 which is enough headroom in practice; a blocked
	// send just means the workers are behind and enqueue naturally
	// backpressures. Ctx.Done() lets a cancelled scan abandon the send
	// without leaking a goroutine.
	var ctxDone <-chan struct{}
	if c.opts != nil && c.opts.Ctx != nil {
		ctxDone = c.opts.Ctx.Done()
	}
	select {
	case c.queue <- t:
		// Only mark visited AFTER the send succeeds. If ctx cancels
		// mid-send we return without visited-stamping so a resumed
		// crawl re-enqueues (see the ctxDone case).
		c.mu.Lock()
		c.visited[norm] = true
		c.mu.Unlock()
		// Track outstanding task so the exhaustion poll doesn't declare
		// the crawl done while a worker is mid-roundtrip.
		c.inflight.Add(1)
	case <-ctxDone:
		// Pause cut the send: the child was never visited-stamped nor
		// queued — reclaim it so resume picks it up (lossless frontier).
		c.reclaim(t)
		return
	}
}

// matchesExclude reports whether norm matches any compiled exclude
// pattern. Called under c.mu; safe because excludeRegex is read-only
// after crawler construction.
func (c *crawler) matchesExclude(norm string) bool {
	if len(c.excludeRegex) == 0 {
		return false
	}
	// Match against the path portion — patterns like ^/logout are the
	// common form. Full-URL matches also work because we pass norm.
	for _, re := range c.excludeRegex {
		if re.MatchString(norm) {
			return true
		}
	}
	return false
}

func (c *crawler) processPage(t crawlTask) {
	defer c.inflight.Add(-1)
	if c.opts.Done() {
		// Paused before this popped task did any work — it's un-processed
		// frontier. Reclaim so resume re-runs it (it's visited-stamped, so
		// the checkpoint builder drops it from Visited to let it re-enqueue).
		c.reclaim(t)
		return
	}
	// Optional per-request delay so an operator can throttle a crawl on
	// a rate-limited target. Sleep is bounded by ctx.Done() so cancels
	// don't wait out the delay.
	if c.cfg.RequestDelay > 0 {
		timer := time.NewTimer(c.cfg.RequestDelay)
		var ctxDone <-chan struct{}
		if c.opts != nil && c.opts.Ctx != nil {
			ctxDone = c.opts.Ctx.Done()
		}
		select {
		case <-timer.C:
		case <-ctxDone:
			timer.Stop()
			c.reclaim(t) // paused during the throttle delay — un-processed
			return
		}
	}
	req, err := http.NewRequest("GET", t.url, nil)
	if err != nil {
		return
	}
	req.Header.Set("User-Agent", "scaNNer-Spider/1.0")
	if c.opts != nil {
		c.opts.ApplyTo(req)
	}
	req = c.opts.BindContext(req)

	var rawReq string
	if dump, err := httputil.DumpRequestOut(req, true); err == nil {
		// Redact operator-supplied Cookie / Authorization / API-key
		// headers before persisting. c.opts.ApplyTo injects any
		// session cookies + custom headers from the http_options form
		// straight into req, and DumpRequestOut serialises them
		// verbatim — so without redaction those creds end up in
		// scans.result JSON on disk and rendered in the UI raw panel
		// (audit finding, security).
		rawReq = truncateRaw(shared.RedactSecretHeaders(string(dump)), 4*1024)
	}

	resp, err := c.client.Do(req)
	if err != nil {
		// A pause cancels the in-flight request: client.Do returns a ctx
		// error and the page never got recorded — reclaim it as frontier.
		// A genuine transport error (real target refused/timed out) is NOT
		// reclaimed: it was attempted and is legitimately consumed.
		if c.opts.Done() {
			c.reclaim(t)
		} else {
			c.opts.RecordError(shared.ClassifyError(err))
		}
		return
	}
	defer resp.Body.Close()

	bodyBytes, _ := io.ReadAll(io.LimitReader(resp.Body, 512*1024))
	body := string(bodyBytes)

	// Rebuild resp.Body so DumpResponse can serialize the captured (limited) bytes.
	resp.Body = io.NopCloser(bytes.NewReader(bodyBytes))
	var rawResp string
	if dump, err := httputil.DumpResponse(resp, true); err == nil {
		rawResp = truncateRaw(string(dump), 16*1024)
	}

	parsed, err := url.Parse(t.url)
	if err != nil {
		return
	}

	// Register this resource
	path := parsed.Path
	if path == "" {
		path = "/"
	}
	ct := resp.Header.Get("Content-Type")

	c.mu.Lock()
	c.count++
	firstSeen := false
	if _, exists := c.resources[path]; !exists {
		c.resources[path] = &Resource{
			URL:         t.url,
			Path:        path,
			Type:        classifyResource(path, ct),
			StatusCode:  resp.StatusCode,
			Size:        resp.ContentLength,
			ContentType: ct,
			FoundOn:     t.foundOn,
			Depth:       t.depth,
			RawRequest:  rawReq,
			RawResponse: rawResp,
		}
		firstSeen = true
	}
	current := c.count
	c.mu.Unlock()

	if firstSeen {
		c.opts.ReplayHit("GET", t.url)
	}

	// Fire partial after each processed page so the UI can show live progress
	c.firePartial()

	if c.logFn != nil {
		icon := "📄"
		if strings.Contains(ct, "html") {
			icon = "📂"
		} else if strings.Contains(ct, "json") || strings.Contains(ct, "xml") {
			icon = "🔌"
		}
		c.logFn(current, fmt.Sprintf("[%d/%d] %s %s → %d (%s)", current, c.cfg.MaxPages, icon, path, resp.StatusCode, ct))
	}

	// Only parse HTML for links
	if resp.StatusCode >= 400 {
		return
	}

	// Different parsers per content type. HTML drives normal crawl;
	// JS bodies get scraped for embedded API endpoints (the SPA-pattern
	// where /api/v1/... only appears inside bundle.js, never in HTML).
	var links []string
	switch {
	case strings.Contains(ct, "html"):
		// Harvest recon artifacts (emails, comments, forms, media +
		// external links) from every HTML page body.
		c.harvestArtifacts(body, t.url, c.baseURL)
		links = extractLinks(body, c.baseURL)
	case strings.Contains(ct, "javascript") || strings.HasSuffix(strings.ToLower(t.url), ".js"):
		links = extractJSEndpoints(body, c.baseURL)
	default:
		return
	}

	for _, link := range links {
		linkParsed, err := url.Parse(link)
		if err != nil {
			continue
		}
		// Same-host (or same-eTLD+1 when IncludeSubdomains is on) scope
		// filter. Modern apps split traffic between api.example.com,
		// cdn.example.com etc., so a strict same-host default misses
		// large chunks of surface. The operator opts in via the form
		// checkbox (audit finding).
		if linkParsed.Hostname() != "" && !c.hostInScope(linkParsed.Hostname()) {
			continue
		}

		// Register even if we won't crawl (external same-host resource)
		absLink := c.resolveURL(link, parsed)
		if absLink == "" {
			continue
		}

		absParsed, _ := url.Parse(absLink)
		absPath := "/"
		if absParsed != nil && absParsed.Path != "" {
			absPath = absParsed.Path
		}

		// Skip logout-related paths entirely
		if shared.IsLogoutPath(absPath) {
			continue
		}

		c.mu.Lock()
		if _, exists := c.resources[absPath]; !exists {
			c.resources[absPath] = &Resource{
				URL:     absLink,
				Path:    absPath,
				Type:    classifyResource(absPath, ""),
				FoundOn: path,
				Depth:   t.depth + 1,
			}
		}
		c.mu.Unlock()

		c.enqueue(crawlTask{
			url:     absLink,
			depth:   t.depth + 1,
			foundOn: path,
		})
	}
}

// firePartial snapshots the current target result and invokes the partial
// callback. Throttled at the source: at MaxPages=10000 the unthrottled
// version copied every Resource (with up to ~20 KB of raw req/resp each)
// on every page completion — O(N²) byte copies. The 1 s throttle caps
// fires; the handler's 2 s DB-flush ticker picks up the latest snapshot.
func (c *crawler) firePartial() {
	if c.partialFn == nil {
		return
	}
	if c.throttle != nil && !c.throttle.ShouldFire() {
		return
	}
	c.mu.Lock()
	// Build a snapshot TargetResult from the current resources
	snap := &TargetResult{
		URL: c.tr.URL,
	}
	for _, r := range c.resources {
		snap.Resources = append(snap.Resources, *r)
	}
	for _, r := range snap.Resources {
		switch r.Type {
		case TypeDirectory:
			snap.TotalDirs++
		case TypeFile:
			snap.TotalFiles++
		}
		snap.TotalPages++
	}
	c.mu.Unlock()
	c.partialFn(snap)
}

func (c *crawler) normURL(rawURL string) string {
	parsed, err := url.Parse(rawURL)
	if err != nil {
		return ""
	}
	host := parsed.Hostname()
	if host != "" && !c.hostInScope(host) {
		return ""
	}
	// Normalize: scheme + host + path (no query, no fragment). When
	// IncludeSubdomains is on we key off the actual link host so
	// api.example.com and www.example.com don't collide in visited.
	scheme := c.baseURL.Scheme
	if parsed.Scheme != "" {
		scheme = parsed.Scheme
	}
	if host == "" {
		host = c.baseHost
	}
	return scheme + "://" + host + parsed.Path
}

func (c *crawler) resolveURL(raw string, base *url.URL) string {
	ref, err := url.Parse(raw)
	if err != nil {
		return ""
	}
	resolved := base.ResolveReference(ref)
	if !c.hostInScope(resolved.Hostname()) {
		return ""
	}
	resolved.Fragment = ""
	return resolved.String()
}

// hostInScope reports whether host is inside the crawler's scope.
// Default: exact-match against the seed host. When IncludeSubdomains
// is on the check widens to any host ending in "." + baseETLD (a
// naive eTLD+1 approximation: last two dotted labels of the seed).
func (c *crawler) hostInScope(host string) bool {
	if host == "" {
		return true
	}
	if host == c.baseHost {
		return true
	}
	if c.cfg.IncludeSubdomains && c.baseETLD != "" {
		if host == c.baseETLD || strings.HasSuffix(host, "."+c.baseETLD) {
			return true
		}
	}
	return false
}

// computeBaseETLD extracts a naive "site root" from a hostname by
// keeping the last two dotted labels. For hosts on multi-label
// public suffixes (co.uk, com.au) this is imprecise, but this is a
// scope-widening heuristic used only when the operator opts in — a
// stricter public-suffix library would be nice, not required.
func computeBaseETLD(host string) string {
	if host == "" {
		return ""
	}
	labels := strings.Split(host, ".")
	if len(labels) < 2 {
		return host
	}
	return strings.Join(labels[len(labels)-2:], ".")
}

// fetchDiscovery does a single GET without disturbing the resource
// map — used to seed from robots.txt / sitemap.xml. Applies opts
// (proxy, headers, cookies) so the ancillary fetch shares the crawl's
// auth state. Returns nil body on any error.
func (c *crawler) fetchDiscovery(rawURL string) []byte {
	req, err := http.NewRequest("GET", rawURL, nil)
	if err != nil {
		return nil
	}
	req.Header.Set("User-Agent", "scaNNer-Spider/1.0")
	if c.opts != nil {
		c.opts.ApplyTo(req)
	}
	req = c.opts.BindContext(req)
	resp, err := c.client.Do(req)
	if err != nil {
		return nil
	}
	defer resp.Body.Close()
	if resp.StatusCode >= 300 {
		return nil
	}
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 1024*1024))
	return body
}

var (
	// robotsPathRe pulls Allow: / Disallow: path values from a robots.txt
	// without a full parser. Wildcard chars stay in the captured value
	// and are stripped by the caller.
	robotsPathRe = regexp.MustCompile(`(?im)^\s*(?:allow|disallow)\s*:\s*(/[^\s#]*)`)
	// robotsSiteRe captures Sitemap: declarations for chained fetch.
	robotsSiteRe = regexp.MustCompile(`(?im)^\s*sitemap\s*:\s*(\S+)`)
	// sitemapLocRe extracts <loc>...</loc> entries from a sitemap doc
	// (works for both <urlset> and <sitemapindex>).
	sitemapLocRe = regexp.MustCompile(`(?is)<loc[^>]*>\s*([^<]+?)\s*</loc>`)
)

// seedFromRobots fetches /robots.txt and enqueues each Allow: / Disallow:
// path as a crawl task; Sitemap: declarations are forwarded to
// seedFromSitemapURL. robots.txt is the single highest-yield "free"
// discovery source on any modern site — missing it is why users
// reach for katana/gospider mid-engagement. Silent on failure (404
// on /robots.txt is expected on many custom apps).
func (c *crawler) seedFromRobots(seed *url.URL) {
	robotsURL := seed.Scheme + "://" + seed.Host + "/robots.txt"
	body := c.fetchDiscovery(robotsURL)
	if len(body) == 0 {
		return
	}
	text := string(body)
	for _, m := range robotsPathRe.FindAllStringSubmatch(text, -1) {
		path := strings.TrimSpace(m[1])
		if path == "" || path == "/" {
			continue
		}
		// Wildcards can appear in the path ("Disallow: /*?sort="): keep
		// the prefix up to the first wildcard so we still enqueue a
		// discoverable path.
		if i := strings.IndexAny(path, "*?$"); i > 0 {
			path = path[:i]
		}
		abs := seed.Scheme + "://" + seed.Host + path
		c.enqueue(crawlTask{url: abs, depth: 1, foundOn: "robots.txt"})
	}
	for _, m := range robotsSiteRe.FindAllStringSubmatch(text, -1) {
		smURL := strings.TrimSpace(m[1])
		if smURL == "" {
			continue
		}
		c.seedFromSitemapURL(smURL, 0)
	}
}

// seedFromSitemap probes /sitemap.xml + /sitemap_index.xml on the seed
// host and feeds each <loc> entry into the crawl queue.
func (c *crawler) seedFromSitemap(seed *url.URL) {
	for _, path := range []string{"/sitemap.xml", "/sitemap_index.xml"} {
		c.seedFromSitemapURL(seed.Scheme+"://"+seed.Host+path, 0)
	}
}

// seedFromSitemapURL walks a sitemap XML doc — either a urlset (leaf)
// or a sitemapindex (points at more sitemap docs). Depth-limited to
// stop a maliciously (or accidentally) recursive index from fanning
// out unbounded.
func (c *crawler) seedFromSitemapURL(smURL string, depth int) {
	if depth > 2 {
		return
	}
	body := c.fetchDiscovery(smURL)
	if len(body) == 0 {
		return
	}
	text := string(body)
	isIndex := strings.Contains(text, "<sitemapindex")
	for _, m := range sitemapLocRe.FindAllStringSubmatch(text, -1) {
		loc := strings.TrimSpace(m[1])
		if loc == "" {
			continue
		}
		if isIndex {
			// Nested sitemap — recurse.
			c.seedFromSitemapURL(loc, depth+1)
			continue
		}
		locParsed, err := url.Parse(loc)
		if err != nil || locParsed.Hostname() == "" {
			continue
		}
		if !c.hostInScope(locParsed.Hostname()) {
			continue
		}
		c.enqueue(crawlTask{url: loc, depth: 1, foundOn: "sitemap.xml"})
	}
}

// --- Link extraction ---

var (
	hrefRe   = regexp.MustCompile(`(?i)(?:href|src|action|data-url|data-href)\s*=\s*["']([^"'#]+)["']`)
	srcsetRe = regexp.MustCompile(`(?i)srcset\s*=\s*["']([^"']+)["']`)
	urlCSSRe = regexp.MustCompile(`url\(\s*["']?([^)"']+)["']?\s*\)`)
	jsURLRe  = regexp.MustCompile(`["'](/[a-zA-Z0-9._\-/]+(?:\.[a-zA-Z0-9]+)?)["']`)
)

// extractJSEndpoints scrapes API-looking endpoints out of a JavaScript
// body. SPAs (Vue/React/Angular bundles) hide their entire surface in
// minified .js — none of those routes appear in the HTML. The patterns
// below catch the obvious cases: string literals starting with /api/,
// /v\d+/, fetch("..."), axios.get("..."), and bare path strings.
// False positives are tolerable here — the crawler will probe each
// candidate anyway and the failing ones won't yield a 200.
var jsEndpointPatterns = []*regexp.Regexp{
	regexp.MustCompile(`["'\x60](\/(?:api|v\d+|graphql|rest|service|services|auth|admin|user|account|public|private|internal|static|assets)\/[a-zA-Z0-9_\-\./?=&]*?)["'\x60]`),
	regexp.MustCompile(`(?:fetch|axios\.[a-z]+|\.get|\.post|\.put|\.delete|\.patch)\s*\(\s*["'\x60]([^"'\x60]+)["'\x60]`),
	regexp.MustCompile(`(?:url|endpoint|path|route)\s*[:=]\s*["'\x60](\/[^"'\x60]+)["'\x60]`),
}

func extractJSEndpoints(body string, baseURL *url.URL) []string {
	seen := map[string]bool{}
	var out []string
	for _, pat := range jsEndpointPatterns {
		for _, m := range pat.FindAllStringSubmatch(body, -1) {
			if len(m) < 2 {
				continue
			}
			ep := strings.TrimSpace(m[1])
			// Strip query string for the spider crawl set — we re-add
			// when probing if needed.
			if q := strings.IndexByte(ep, '?'); q >= 0 {
				ep = ep[:q]
			}
			if ep == "" || ep == "/" || seen[ep] {
				continue
			}
			// Heuristic: must start with /, must look like a path,
			// no spaces, no obviously-template-string artifacts ({,$).
			if !strings.HasPrefix(ep, "/") || strings.ContainsAny(ep, " ${}<>") {
				continue
			}
			seen[ep] = true
			out = append(out, ep)
			if len(out) >= 200 {
				return out // cap per JS file — enough signal, bounded crawl
			}
		}
	}
	return out
}

func extractLinks(body string, baseURL *url.URL) []string {
	seen := map[string]bool{}
	var links []string

	add := func(raw string) {
		raw = strings.TrimSpace(raw)
		if raw == "" || raw == "#" || raw == "/" || strings.HasPrefix(raw, "javascript:") ||
			strings.HasPrefix(raw, "mailto:") || strings.HasPrefix(raw, "data:") ||
			strings.HasPrefix(raw, "tel:") {
			return
		}
		if !seen[raw] {
			seen[raw] = true
			links = append(links, raw)
		}
	}

	// href, src, action attributes
	for _, m := range hrefRe.FindAllStringSubmatch(body, -1) {
		add(m[1])
	}

	// srcset
	for _, m := range srcsetRe.FindAllStringSubmatch(body, -1) {
		for _, part := range strings.Split(m[1], ",") {
			fields := strings.Fields(strings.TrimSpace(part))
			if len(fields) > 0 {
				add(fields[0])
			}
		}
	}

	// CSS url()
	for _, m := range urlCSSRe.FindAllStringSubmatch(body, -1) {
		add(m[1])
	}

	// JS string paths (conservative: only /path/like/this)
	for _, m := range jsURLRe.FindAllStringSubmatch(body, -1) {
		path := m[1]
		// Only add if looks like a real path
		if strings.Count(path, "/") >= 1 && !strings.Contains(path, "{{") && len(path) < 200 {
			add(path)
		}
	}

	return links
}

// --- Recon artifact extraction (emails, comments, forms, media links) ---

var (
	// Email addresses in page text + mailto: targets. Trailing-dot / TLD
	// bound keeps it from swallowing "user@host" without a domain.
	emailRe = regexp.MustCompile(`(?i)[a-z0-9._%+\-]+@[a-z0-9.\-]+\.[a-z]{2,24}`)
	// HTML comments. (?s) so it spans newlines; non-greedy so adjacent
	// comments don't merge.
	htmlCommentRe = regexp.MustCompile(`(?s)<!--(.*?)-->`)
	// <form ...> ... </form> blocks (non-greedy, dotall).
	formBlockRe = regexp.MustCompile(`(?is)<form\b([^>]*)>(.*?)</form>`)
	// One attribute on an opening tag: name="value" or name='value'.
	attrRe = regexp.MustCompile(`(?i)([a-z\-]+)\s*=\s*["']([^"']*)["']`)
	// input / select / textarea openers inside a form.
	fieldTagRe = regexp.MustCompile(`(?is)<(input|select|textarea)\b([^>]*)>`)
)

// media/type extension sets used to bucket a discovered URL.
var (
	imageExt = map[string]bool{".png": true, ".jpg": true, ".jpeg": true, ".gif": true, ".svg": true, ".webp": true, ".bmp": true, ".ico": true, ".avif": true, ".tif": true, ".tiff": true}
	videoExt = map[string]bool{".mp4": true, ".webm": true, ".ogv": true, ".mov": true, ".avi": true, ".mkv": true, ".m4v": true, ".mpg": true, ".mpeg": true, ".flv": true}
	audioExt = map[string]bool{".mp3": true, ".wav": true, ".ogg": true, ".m4a": true, ".flac": true, ".aac": true, ".opus": true, ".wma": true}
)

// artifact-aggregation caps so a huge site can't blow the result blob.
const (
	maxEmails   = 1000
	maxLinkSet  = 3000
	maxComments = 800
	maxForms    = 500
	maxCommentLen = 600
)

// harvestArtifacts parses one page body and folds its emails, HTML
// comments, forms and categorised links/media into the crawler's deduped
// aggregation sets. Safe to call from concurrent worker goroutines — all
// writes happen under c.mu. pageURL is the page the artifacts were found
// on; base is the crawl's base URL for resolving relative references.
func (c *crawler) harvestArtifacts(body, pageURL string, base *url.URL) {
	// Collect first (no lock), then commit under a single lock.
	var (
		foundEmails   []string
		foundComments []string
		foundForms    []PageForm
		catImages     []string
		catVideos     []string
		catAudio      []string
		catJS         []string
		catLinks      []string
		catExternal   []string
	)

	// Emails: text + mailto:. Lowercased + deduped at commit.
	for _, e := range emailRe.FindAllString(body, -1) {
		foundEmails = append(foundEmails, strings.ToLower(e))
	}

	// HTML comments (skip empty and IE conditional wrappers).
	for _, m := range htmlCommentRe.FindAllStringSubmatch(body, -1) {
		txt := strings.TrimSpace(m[1])
		if txt == "" {
			continue
		}
		low := strings.ToLower(txt)
		if strings.HasPrefix(low, "[if ") || low == "[endif]" || strings.HasPrefix(low, "<![endif]") {
			continue
		}
		if len(txt) > maxCommentLen {
			txt = txt[:maxCommentLen] + "…"
		}
		foundComments = append(foundComments, txt)
	}

	// Forms: action/method + input/select/textarea field names.
	for _, fm := range formBlockRe.FindAllStringSubmatch(body, -1) {
		openTag, inner := fm[1], fm[2]
		action, method := "", "GET"
		for _, a := range attrRe.FindAllStringSubmatch(openTag, -1) {
			switch strings.ToLower(a[1]) {
			case "action":
				action = strings.TrimSpace(a[2])
			case "method":
				if v := strings.TrimSpace(a[2]); v != "" {
					method = strings.ToUpper(v)
				}
			}
		}
		if action != "" {
			action = c.resolveMaybeExternal(action, base)
		} else {
			action = pageURL
		}
		var fields []FormField
		fieldSeen := map[string]bool{}
		for _, ft := range fieldTagRe.FindAllStringSubmatch(inner, -1) {
			tag := strings.ToLower(ft[1])
			name, typ := "", tag
			for _, a := range attrRe.FindAllStringSubmatch(ft[2], -1) {
				switch strings.ToLower(a[1]) {
				case "name":
					name = strings.TrimSpace(a[2])
				case "type":
					if tag == "input" {
						typ = strings.ToLower(strings.TrimSpace(a[2]))
					}
				}
			}
			if name == "" || fieldSeen[name] {
				continue
			}
			fieldSeen[name] = true
			fields = append(fields, FormField{Name: name, Type: typ})
		}
		foundForms = append(foundForms, PageForm{FoundOn: pageURL, Action: action, Method: method, Fields: fields})
	}

	// Categorise every referenced URL by media type / scope.
	for _, raw := range extractLinks(body, base) {
		abs := c.resolveMaybeExternal(raw, base)
		if abs == "" {
			continue
		}
		p, err := url.Parse(abs)
		if err != nil {
			continue
		}
		ext := strings.ToLower(pathExt(p.Path))
		switch {
		case ext == ".js":
			catJS = append(catJS, abs)
		case imageExt[ext]:
			catImages = append(catImages, abs)
		case videoExt[ext] || isVideoEmbed(p):
			catVideos = append(catVideos, abs)
		case audioExt[ext]:
			catAudio = append(catAudio, abs)
		case p.Hostname() != "" && !c.hostInScope(p.Hostname()):
			catExternal = append(catExternal, abs)
		default:
			catLinks = append(catLinks, abs)
		}
	}

	// Commit under lock with dedup + caps. The ordered slices are built
	// from these dedup sets at crawl end (sortedKeys).
	c.mu.Lock()
	defer c.mu.Unlock()
	addSet := func(set map[string]bool, vals []string, cap int) {
		for _, v := range vals {
			if v == "" || set[v] || len(set) >= cap {
				continue
			}
			set[v] = true
		}
	}
	addSet(c.emails, foundEmails, maxEmails)
	addSet(c.links, catLinks, maxLinkSet)
	addSet(c.externalLinks, catExternal, maxLinkSet)
	addSet(c.jsFiles, catJS, maxLinkSet)
	addSet(c.images, catImages, maxLinkSet)
	addSet(c.videos, catVideos, maxLinkSet)
	addSet(c.audio, catAudio, maxLinkSet)
	for _, txt := range foundComments {
		if len(c.comments) >= maxComments || c.commentSeen[txt] {
			continue
		}
		c.commentSeen[txt] = true
		c.comments = append(c.comments, PageComment{FoundOn: pageURL, Text: txt})
	}
	for _, f := range foundForms {
		key := f.Method + " " + f.Action + " " + fmt.Sprint(len(f.Fields))
		if len(c.forms) >= maxForms || c.formSeen[key] {
			continue
		}
		c.formSeen[key] = true
		c.forms = append(c.forms, f)
	}
}

// resolveMaybeExternal resolves a raw href/src to an absolute URL,
// preserving off-host targets (unlike resolveURL which scope-filters).
// mailto:/tel:/javascript:/data: are dropped (returns "").
func (c *crawler) resolveMaybeExternal(raw string, base *url.URL) string {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return ""
	}
	low := strings.ToLower(raw)
	if strings.HasPrefix(low, "mailto:") || strings.HasPrefix(low, "tel:") ||
		strings.HasPrefix(low, "javascript:") || strings.HasPrefix(low, "data:") {
		return ""
	}
	ref, err := url.Parse(raw)
	if err != nil {
		return ""
	}
	if base == nil {
		return raw
	}
	return base.ResolveReference(ref).String()
}

// pathExt returns the lowercase extension (incl. dot) of a URL path,
// ignoring any trailing query/fragment already stripped by url.Parse.
func pathExt(p string) string {
	i := strings.LastIndex(p, "/")
	if i >= 0 {
		p = p[i+1:]
	}
	if dot := strings.LastIndex(p, "."); dot >= 0 {
		return p[dot:]
	}
	return ""
}

// isVideoEmbed recognises common video-embed hosts (YouTube/Vimeo) so
// iframe embeds land in the Videos bucket even without a file extension.
func isVideoEmbed(u *url.URL) bool {
	h := strings.ToLower(u.Hostname())
	return strings.Contains(h, "youtube.com") || strings.Contains(h, "youtu.be") ||
		strings.Contains(h, "player.vimeo.com") || strings.Contains(h, "vimeo.com") ||
		strings.Contains(h, "dailymotion.com")
}

// --- Classification ---

var fileExtensions = map[string]bool{
	".html": true, ".htm": true, ".php": true, ".asp": true, ".aspx": true, ".jsp": true,
	".js": true, ".css": true, ".json": true, ".xml": true, ".txt": true, ".csv": true,
	".pdf": true, ".doc": true, ".docx": true, ".xls": true, ".xlsx": true,
	".png": true, ".jpg": true, ".jpeg": true, ".gif": true, ".svg": true, ".ico": true, ".webp": true,
	".mp4": true, ".mp3": true, ".webm": true, ".woff": true, ".woff2": true, ".ttf": true, ".eot": true,
	".zip": true, ".gz": true, ".tar": true, ".rar": true, ".7z": true,
	".map": true, ".yaml": true, ".yml": true, ".toml": true, ".conf": true, ".cfg": true,
	".env": true, ".bak": true, ".sql": true, ".log": true, ".swp": true,
}

func classifyResource(path, contentType string) ResourceType {
	// Check extension
	lastDot := strings.LastIndex(path, ".")
	if lastDot > strings.LastIndex(path, "/") && lastDot >= 0 {
		ext := strings.ToLower(path[lastDot:])
		if fileExtensions[ext] {
			return TypeFile
		}
	}

	// API-like paths
	if strings.Contains(path, "/api/") || strings.Contains(path, "/v1/") ||
		strings.Contains(path, "/v2/") || strings.Contains(path, "/graphql") {
		return TypeEndpoint
	}

	// Content-type hints
	if contentType != "" {
		if strings.Contains(contentType, "json") || strings.Contains(contentType, "xml") {
			return TypeEndpoint
		}
	}

	// Trailing slash or no extension = directory
	if strings.HasSuffix(path, "/") || lastDot <= strings.LastIndex(path, "/") {
		return TypeDirectory
	}

	return TypeFile
}
