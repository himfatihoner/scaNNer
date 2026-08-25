package concurtest

import (
	"bytes"
	"crypto/tls"
	"fmt"
	"io"
	"math/rand"
	"net/http"
	"net/url"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"scanner/internal/modules/shared"
)

// ScanConfig is what the handler hands the scanner. Defaults are picked
// to give a useful answer without flooding the target — total request
// volume across all scenarios stays under ~3 000 in the default config.
type ScanConfig struct {
	// Up to which level to ramp. Levels below this that are >= this value
	// are dropped, e.g. MaxConcurrency=50 → [1,2,5,10,25,50].
	MaxConcurrency int
	// Requests fired per ramp level. 30 is enough to compute stable p95s.
	ReqsPerLevel int
	// Whether to run the sustained-load scenario.
	RunSustained bool
	// Concurrency for the sustained scenario. 0 = use the detected knee
	// from the ramp test, falling back to 25 if no knee is found.
	SustainedConcurrency int
	// Total wall-clock seconds to keep the sustained scenario firing.
	SustainedDurationSec int
	// Whether to run the burst scenario.
	RunBurst    bool
	BurstSize   int // requests per burst
	BurstCount  int // number of bursts
	BurstIdleMs int // idle gap between bursts

	// ProbeMode shapes how each request URL is built. "single" hammers
	// one endpoint with a cache-buster query string (what we want when
	// measuring a specific page's capacity). "varied" appends a random
	// path segment to the URL on every request, so the load profile
	// matches what direnum-style brute-force scans actually do — most
	// requests miss and the server returns a fast 404 from its router,
	// never reaching the heavier code paths a real homepage hit would.
	ProbeMode string

	// HTTP request shape. Defaults: GET / no body. When Body is non-empty
	// and ContentType is set, the request fires as a POST-style payload
	// — lets users measure the capacity of POST /api/search, POST /login,
	// GraphQL endpoints, etc. (wrk2 / vegeta / k6 parity).
	Method      string
	Body        string
	ContentType string

	// ForceHTTP1 disables HTTP/2 so each in-flight request consumes a real
	// TCP connection — the right setting when measuring server concurrency
	// ceilings. Disable to let ALPN negotiate h2 (relevant when h2-only
	// targets reject HTTP/1.1 or you want to measure multiplexed
	// throughput). Default true for backward-compat with the original
	// capacity-testing intent.
	ForceHTTP1 bool

	Timeout time.Duration
}

func DefaultConfig() ScanConfig {
	return ScanConfig{
		MaxConcurrency:       200,
		ReqsPerLevel:         30,
		RunSustained:         true,
		SustainedConcurrency: 0, // 0 → auto from ramp knee
		SustainedDurationSec: 30,
		RunBurst:             true,
		BurstSize:            50,
		BurstCount:           5,
		BurstIdleMs:          3000,
		ProbeMode:            "varied",
		Method:               "GET",
		ForceHTTP1:           true,
		Timeout:              15 * time.Second,
	}
}

// PartialFunc receives in-progress snapshots of the result so the handler
// can flush them to the DB on a 2s ticker. The pointer's contents are
// owned by the scanner — handler should marshal and release the lock
// immediately rather than retain a reference.
type PartialFunc func(*ScanResult)

type ScanResult struct {
	Targets []*TargetResult `json:"targets"`
}

type TargetResult struct {
	URL          string    `json:"url"`
	BaselineMs   int64     `json:"baseline_ms"`
	PracticalMax int       `json:"practical_max"` // detected knee (highest "healthy" level)
	Notes        []string  `json:"notes"`
	Ramp         []*Bucket `json:"ramp"`
	Sustained    *Bucket   `json:"sustained,omitempty"`
	Burst        *Bucket   `json:"burst,omitempty"`
	Error        string    `json:"error,omitempty"`
}

type Bucket struct {
	Label         string         `json:"label"`
	Concurrency   int            `json:"concurrency"`
	Requests      int            `json:"requests"`
	Successes     int            `json:"successes"`
	Errors        int            `json:"errors"`
	P50Ms         int64          `json:"p50_ms"`
	P95Ms         int64          `json:"p95_ms"`
	P99Ms         int64          `json:"p99_ms"`
	AvgMs         int64          `json:"avg_ms"`
	ThroughputRPS float64        `json:"throughput_rps"`
	DurationMs    int64          `json:"duration_ms"`
	Statuses      map[string]int `json:"statuses"`
	ErrorTypes    map[string]int `json:"error_types"`
	// "Healthy" judgment: ≥98% success rate and p95 ≤ 2× baseline. Set
	// only on ramp buckets.
	Healthy bool `json:"healthy"`
}

// Scan iterates the user's targets and runs the scenarios on each one.
// progressFn(done, total, msg) drives the standard progress UI; the
// handler typically forwards it to UpdateScanProgressFull. partialFn (if
// non-nil) is invoked after each scenario bucket completes so the handler
// can flush an in-progress snapshot to the DB.
func Scan(targets []string, cfg ScanConfig, opts *shared.HTTPOptions,
	progressFn func(done, total int, msg string),
	partialFn PartialFunc) *ScanResult {

	if cfg.Timeout <= 0 {
		cfg.Timeout = 15 * time.Second
	}
	if cfg.MaxConcurrency <= 0 {
		cfg.MaxConcurrency = 200
	}
	if cfg.ReqsPerLevel <= 0 {
		cfg.ReqsPerLevel = 30
	}
	if strings.TrimSpace(cfg.Method) == "" {
		cfg.Method = http.MethodGet
	} else {
		cfg.Method = strings.ToUpper(strings.TrimSpace(cfg.Method))
	}

	result := &ScanResult{}

	// Estimate total work units for a smooth progress bar. Each ramp level
	// counts as one unit, sustained as one, burst as one — coarse but the
	// per-bucket message keeps users oriented.
	levels := RampLevels(cfg.MaxConcurrency)
	unitsPerTarget := len(levels)
	if cfg.RunSustained {
		unitsPerTarget++
	}
	if cfg.RunBurst {
		unitsPerTarget++
	}
	total := unitsPerTarget * len(targets)
	done := 0
	bump := func(msg string) {
		done++
		if progressFn != nil {
			progressFn(done, total, msg)
		}
	}
	pushPartial := func() {
		if partialFn != nil {
			partialFn(result)
		}
	}

	for _, raw := range targets {
		// Cancellation fast-path (audit B45).
		if opts != nil && opts.Done() {
			break
		}
		tr := &TargetResult{URL: raw}
		result.Targets = append(result.Targets, tr)

		u, err := normalizeTarget(raw)
		if err != nil {
			tr.Error = err.Error()
			// Account for the work we won't do so progress still hits 100%.
			for i := 0; i < unitsPerTarget; i++ {
				bump(fmt.Sprintf("[%s] skipped: %s", raw, err.Error()))
			}
			pushPartial()
			continue
		}
		tr.URL = u

		// Each target gets its own dedicated transport. By default we
		// force HTTP/1.1 so each in-flight request consumes a real
		// TCP/TLS connection — HTTP/2 multiplexing would mask the
		// server's actual concurrency ceiling behind a single
		// stream-multiplexed conn. Users can flip ForceHTTP1=false to
		// let ALPN negotiate h2 (test multiplexed throughput, or talk
		// to h2-only origins).
		client := newDedicatedClient(cfg, cfg.MaxConcurrency, opts)
		if cfg.ForceHTTP1 {
			tr.Notes = append(tr.Notes, "HTTP/1.1 forced — concurrency = TCP conns. Disable to test HTTP/2 multiplexed throughput.")
		} else {
			tr.Notes = append(tr.Notes, "HTTP/2 ALPN enabled — multiplexed streams may mask single-conn capacity ceilings.")
		}

		// --- Baseline: 5 sequential warm-up requests, take the median ---
		baseline, baseErr := measureBaseline(client, u, cfg, opts)
		tr.BaselineMs = baseline
		if baseErr != "" {
			tr.Error = baseErr
			tr.Notes = append(tr.Notes, "baseline failed: "+baseErr)
			// Even if baseline failed, run the rest — the user may still
			// want to see how the target behaves under load.
		}
		pushPartial()

		// --- Ramp test ---
		var detectedKnee int
		for _, c := range levels {
			if opts != nil && opts.Done() {
				break
			}
			b := runFixedBatch(client, u, cfg, c, cfg.ReqsPerLevel, opts)
			b.Label = fmt.Sprintf("ramp · %d concurrent", c)
			classifyHealth(b, baseline)
			tr.Ramp = append(tr.Ramp, b)
			if b.Healthy {
				detectedKnee = c
			}
			bump(fmt.Sprintf("[%s] ramp %d concurrent → %d/%d ok · p95=%dms", u, c, b.Successes, b.Requests, b.P95Ms))
			pushPartial()
		}
		tr.PracticalMax = detectedKnee
		if detectedKnee == 0 {
			tr.Notes = append(tr.Notes, "no level cleared the 98%/p95×2 health threshold — target may be saturated even at 1 concurrent")
		} else {
			tr.Notes = append(tr.Notes, fmt.Sprintf("highest healthy concurrency: %d (≥98%% success, p95 within 2× baseline)", detectedKnee))
		}

		// --- Sustained scenario ---
		if cfg.RunSustained && !(opts != nil && opts.Done()) {
			sc := cfg.SustainedConcurrency
			if sc <= 0 {
				if detectedKnee > 0 {
					sc = detectedKnee
				} else {
					sc = 25
				}
			}
			dur := cfg.SustainedDurationSec
			if dur <= 0 {
				dur = 30
			}
			b := runSustained(client, u, cfg, sc, time.Duration(dur)*time.Second, opts)
			b.Label = fmt.Sprintf("sustained · %d concurrent · %ds", sc, dur)
			tr.Sustained = b
			tr.Notes = append(tr.Notes, sustainedNote(b))
			bump(fmt.Sprintf("[%s] sustained %ds @ %d → %.1f rps · %d errors", u, dur, sc, b.ThroughputRPS, b.Errors))
			pushPartial()
		}

		// --- Burst scenario ---
		if cfg.RunBurst && !(opts != nil && opts.Done()) {
			size, count, idle := cfg.BurstSize, cfg.BurstCount, cfg.BurstIdleMs
			if size <= 0 {
				size = 50
			}
			if count <= 0 {
				count = 5
			}
			if idle < 0 {
				idle = 3000
			}
			b := runBurst(client, u, cfg, size, count, time.Duration(idle)*time.Millisecond, opts)
			b.Label = fmt.Sprintf("burst · %d × %d (idle %dms)", size, count, idle)
			tr.Burst = b
			tr.Notes = append(tr.Notes, burstNote(b, baseline))
			bump(fmt.Sprintf("[%s] burst %dx%d → %d/%d ok · p95=%dms", u, count, size, b.Successes, b.Requests, b.P95Ms))
			pushPartial()
		}

		// Flush idle conns before moving to the next target so we don't
		// carry connection state between hosts.
		client.CloseIdleConnections()
	}
	return result
}

// RampLevels picks a geometric-ish ramp up to (and including) max. The
// low end (1, 2, 5, 10, 25, 50, 100, 200) is dense so typical web
// targets are characterised in detail; the high end gets coarser steps
// (400 → 800 → 1500 → 3000 → 5000 → 7500 → 10000) because past 1k the
// interesting transition is "does the OS / network even let me get
// there", not fine-grained latency curves. Exported so the handler's
// progress-units math counts the same number of buckets the scanner
// will emit (audit fix: silently-appended max would drift by 1).
func RampLevels(max int) []int {
	all := []int{1, 2, 5, 10, 25, 50, 100, 200, 400, 800, 1500, 3000, 5000, 7500, 10000}
	out := []int{}
	for _, v := range all {
		if v <= max {
			out = append(out, v)
		}
	}
	if len(out) == 0 || out[len(out)-1] != max {
		out = append(out, max)
	}
	return out
}

func normalizeTarget(raw string) (string, error) {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return "", fmt.Errorf("empty target")
	}
	if !strings.Contains(raw, "://") {
		raw = "https://" + raw
	}
	u, err := url.Parse(raw)
	if err != nil {
		return "", fmt.Errorf("invalid URL: %w", err)
	}
	if u.Host == "" {
		return "", fmt.Errorf("invalid URL: missing host")
	}
	return u.String(), nil
}

// newDedicatedClient builds a per-target client with connection-pool
// limits scaled to the test ceiling, so a 200-concurrent burst actually
// opens 200 sockets instead of multiplexing on one. When cfg.ForceHTTP1
// is true (default) HTTP/2 is disabled — required for "TCP-conns ==
// concurrency" capacity testing. Honors opts.ProxyURL so Settings →
// Burp/upstream proxy is respected (previous code dropped it silently).
// Honors opts.LocalAddr / global pinned addr so killswitch L2 source-IP
// binding stays in force.
func newDedicatedClient(cfg ScanConfig, capLevel int, opts *shared.HTTPOptions) *http.Client {
	if capLevel < 16 {
		capLevel = 16
	}
	transport := &http.Transport{
		// Source-IP binding (audit S1) via BoundDialer — reads
		// opts.LocalAddr or the global pinned addr.
		DialContext:           shared.BoundDialer(opts, 5*time.Second).DialContext,
		TLSClientConfig:       &tls.Config{InsecureSkipVerify: true},
		MaxIdleConns:          capLevel * 2,
		MaxIdleConnsPerHost:   capLevel * 2,
		MaxConnsPerHost:       0, // unlimited — let the OS / target be the bottleneck
		IdleConnTimeout:       30 * time.Second,
		TLSHandshakeTimeout:   10 * time.Second,
		ExpectContinueTimeout: 1 * time.Second,
	}
	if cfg.ForceHTTP1 {
		// Disable HTTP/2 via the documented escape hatch — an empty
		// (non-nil) TLSNextProto map means "don't upgrade to h2 via
		// ALPN", and ForceAttemptHTTP2=false stops the transport from
		// trying anyway.
		transport.ForceAttemptHTTP2 = false
		transport.TLSNextProto = map[string]func(string, *tls.Conn) http.RoundTripper{}
	} else {
		// Let stdlib's default h2 + ALPN path work.
		transport.ForceAttemptHTTP2 = true
	}
	// Proxy wiring (audit fix): if the user configured a proxy in
	// Settings, route through it. Skips the override when
	// BurpSuccessOnly is set — that mode wants probes to bypass the
	// proxy and only the confirmed-hit replays go through it.
	if opts != nil && opts.ProxyURL != "" && !opts.BurpSuccessOnly {
		if u, err := url.Parse(opts.ProxyURL); err == nil {
			transport.Proxy = http.ProxyURL(u)
		}
	}
	if opts != nil {
		opts.RegisterTransport(transport)
	}
	return &http.Client{
		Timeout:   cfg.Timeout,
		Transport: transport,
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}
}

type result struct {
	status   int
	latency  time.Duration
	errClass string
	bytes    int64
}

func fireOne(client *http.Client, u string, cfg ScanConfig, opts *shared.HTTPOptions) result {
	start := time.Now()

	// In "varied" mode we mimic a direnum/brute-force load profile by
	// appending a random path segment — most requests will 404 fast
	// without touching backend code, exactly like a real scan. In
	// "single" mode we keep hitting the same endpoint with a query
	// cache-buster so the same URL is exercised under load.
	full := buildProbeURL(u, cfg.ProbeMode)

	method := cfg.Method
	if method == "" {
		method = http.MethodGet
	}
	var body io.Reader
	if cfg.Body != "" {
		body = bytes.NewReader([]byte(cfg.Body))
	}
	req, err := http.NewRequest(method, full, body)
	if err != nil {
		return result{errClass: "build", latency: time.Since(start)}
	}
	if opts != nil {
		opts.ApplyTo(req)
		req = opts.BindContext(req)
	}
	if cfg.Body != "" && cfg.ContentType != "" && req.Header.Get("Content-Type") == "" {
		req.Header.Set("Content-Type", cfg.ContentType)
	}
	// Cache-control headers only make sense on GET — POST is uncacheable
	// by spec and the headers look noisy in pcaps.
	if method == http.MethodGet {
		req.Header.Set("Cache-Control", "no-cache")
		req.Header.Set("Pragma", "no-cache")
	}

	resp, err := client.Do(req)
	if err != nil {
		return result{errClass: classifyErr(err), latency: time.Since(start)}
	}
	n, _ := io.Copy(io.Discard, io.LimitReader(resp.Body, 1<<20))
	resp.Body.Close()
	return result{status: resp.StatusCode, latency: time.Since(start), bytes: n}
}

// buildProbeURL returns the URL to fire for one probe, depending on
// mode. "varied" is the direnum-realistic default — each request gets a
// fresh random 12-char path segment so most hits 404 quickly without
// reaching heavy backend code. "single" keeps the original URL but
// appends a random `?_=…` so CDNs can't cache and serve from the edge.
func buildProbeURL(u, mode string) string {
	if mode == "" {
		mode = "varied"
	}
	if mode == "varied" {
		parsed, err := url.Parse(u)
		if err != nil {
			return u // best effort — let the http client surface the error
		}
		seg := randomSegment(12)
		base := strings.TrimRight(parsed.Path, "/")
		parsed.Path = base + "/" + seg
		parsed.RawQuery = "" // varied mode owns the path; drop user query
		parsed.Fragment = ""
		return parsed.String()
	}
	// "single" → cache-buster query
	sep := "?"
	if strings.Contains(u, "?") {
		sep = "&"
	}
	cb := strconv.FormatInt(rand.Int63(), 36)
	return u + sep + "_=" + cb
}

const probeAlnum = "abcdefghijklmnopqrstuvwxyz0123456789"

func randomSegment(n int) string {
	b := make([]byte, n)
	for i := range b {
		b[i] = probeAlnum[rand.Intn(len(probeAlnum))]
	}
	return string(b)
}

func classifyErr(err error) string {
	s := strings.ToLower(err.Error())
	switch {
	case strings.Contains(s, "context canceled"), strings.Contains(s, "context deadline"):
		return "cancelled"
	case strings.Contains(s, "timeout"), strings.Contains(s, "deadline exceeded"):
		return "timeout"
	case strings.Contains(s, "connection refused"):
		return "conn-refused"
	case strings.Contains(s, "connection reset"):
		return "conn-reset"
	case strings.Contains(s, "no such host"), strings.Contains(s, "dns"):
		return "dns"
	case strings.Contains(s, "tls"), strings.Contains(s, "x509"), strings.Contains(s, "certificate"):
		return "tls"
	case strings.Contains(s, "eof"):
		return "eof"
	default:
		return "other"
	}
}

// runFixedBatch fires `total` requests with `concurrency` workers. Used
// by ramp and as the primitive inside burst. ReqsPerLevel is honored
// literally: when the user asked for fewer requests than concurrency,
// extra workers idle out — request count is preserved instead of being
// silently amplified.
func runFixedBatch(client *http.Client, u string, cfg ScanConfig, concurrency, total int, opts *shared.HTTPOptions) *Bucket {
	if concurrency < 1 {
		concurrency = 1
	}
	if total < 1 {
		total = concurrency
	}
	results := make([]result, 0, total)
	var mu sync.Mutex
	var wg sync.WaitGroup
	jobs := make(chan struct{}, total)
	for i := 0; i < total; i++ {
		jobs <- struct{}{}
	}
	close(jobs)

	startAll := time.Now()
	for w := 0; w < concurrency; w++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for range jobs {
				// Cancellation check inside the worker loop so Stop
				// drains the remaining jobs instantly instead of
				// firing fast-failing requests until the channel
				// empties.
				if opts != nil && opts.Done() {
					return
				}
				r := fireOne(client, u, cfg, opts)
				mu.Lock()
				results = append(results, r)
				mu.Unlock()
			}
		}()
	}
	wg.Wait()
	dur := time.Since(startAll)
	return summarize(results, concurrency, dur)
}

// runSustained spawns `concurrency` workers that loop firing requests
// for `duration` and records every result. Honors opts cancellation so
// Stop interrupts within a request-time rather than waiting out the
// full duration (up to 300 s by default).
func runSustained(client *http.Client, u string, cfg ScanConfig, concurrency int, duration time.Duration, opts *shared.HTTPOptions) *Bucket {
	if concurrency < 1 {
		concurrency = 1
	}
	deadline := time.Now().Add(duration)
	var results []result
	var mu sync.Mutex
	var wg sync.WaitGroup

	startAll := time.Now()
	for w := 0; w < concurrency; w++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for time.Now().Before(deadline) {
				if opts != nil && opts.Done() {
					return
				}
				r := fireOne(client, u, cfg, opts)
				mu.Lock()
				results = append(results, r)
				mu.Unlock()
			}
		}()
	}
	wg.Wait()
	return summarize(results, concurrency, time.Since(startAll))
}

// runBurst fires `size` requests in parallel, then idles for `idle`
// before repeating `count` times. Detects anti-burst defenses that let
// sustained traffic through but cap rapid surges. The idle gap is
// interruptible — Stop unblocks within ms rather than waiting out the
// configured idle window (up to 30 s).
func runBurst(client *http.Client, u string, cfg ScanConfig, size, count int, idle time.Duration, opts *shared.HTTPOptions) *Bucket {
	all := []result{}
	var allMu sync.Mutex
	startAll := time.Now()
	for i := 0; i < count; i++ {
		if opts != nil && opts.Done() {
			break
		}
		var wg sync.WaitGroup
		for j := 0; j < size; j++ {
			wg.Add(1)
			go func() {
				defer wg.Done()
				if opts != nil && opts.Done() {
					return
				}
				r := fireOne(client, u, cfg, opts)
				allMu.Lock()
				all = append(all, r)
				allMu.Unlock()
			}()
		}
		wg.Wait()
		if i < count-1 && idle > 0 {
			// Interruptible sleep so cancel doesn't have to wait for
			// the full idle gap (default 3 s, max 30 s).
			if opts != nil && opts.Ctx != nil {
				select {
				case <-time.After(idle):
				case <-opts.Ctx.Done():
					return summarize(all, size, time.Since(startAll))
				}
			} else {
				time.Sleep(idle)
			}
		}
	}
	return summarize(all, size, time.Since(startAll))
}

// measureBaseline runs 5 sequential probes and returns the median latency
// in ms — used as the reference for "p95 within 2× baseline" health.
func measureBaseline(client *http.Client, u string, cfg ScanConfig, opts *shared.HTTPOptions) (int64, string) {
	const n = 5
	lats := make([]int64, 0, n)
	var lastErr string
	for i := 0; i < n; i++ {
		if opts != nil && opts.Done() {
			break
		}
		r := fireOne(client, u, cfg, opts)
		if r.errClass != "" {
			lastErr = r.errClass
			continue
		}
		lats = append(lats, r.latency.Milliseconds())
	}
	if len(lats) == 0 {
		return 0, lastErr
	}
	sort.Slice(lats, func(i, j int) bool { return lats[i] < lats[j] })
	return lats[len(lats)/2], ""
}

func summarize(results []result, concurrency int, dur time.Duration) *Bucket {
	b := &Bucket{
		Concurrency: concurrency,
		Requests:    len(results),
		DurationMs:  dur.Milliseconds(),
		Statuses:    map[string]int{},
		ErrorTypes:  map[string]int{},
	}
	lats := make([]int64, 0, len(results))
	var sumMs int64
	for _, r := range results {
		if r.errClass != "" {
			b.Errors++
			b.ErrorTypes[r.errClass]++
			lats = append(lats, r.latency.Milliseconds())
			sumMs += r.latency.Milliseconds()
			continue
		}
		// Treat 4xx/5xx as "responses" but flag 429 / 503 as throttling.
		b.Successes++
		key := strconv.Itoa(r.status)
		b.Statuses[key]++
		lats = append(lats, r.latency.Milliseconds())
		sumMs += r.latency.Milliseconds()
	}
	if len(lats) > 0 {
		sort.Slice(lats, func(i, j int) bool { return lats[i] < lats[j] })
		b.P50Ms = pct(lats, 0.50)
		b.P95Ms = pct(lats, 0.95)
		b.P99Ms = pct(lats, 0.99)
		b.AvgMs = sumMs / int64(len(lats))
	}
	if dur > 0 {
		b.ThroughputRPS = float64(len(results)) / dur.Seconds()
	}
	return b
}

func pct(sorted []int64, p float64) int64 {
	if len(sorted) == 0 {
		return 0
	}
	idx := int(float64(len(sorted)-1) * p)
	return sorted[idx]
}

// classifyHealth tags a ramp bucket "healthy" if the practical-max
// definition holds: ≥98% success rate AND p95 ≤ 2× baseline. Throttling
// codes (429/503) count as failures even if they're <500ms — getting a
// rate-limit response is by definition unhealthy capacity.
func classifyHealth(b *Bucket, baselineMs int64) {
	if b.Requests == 0 {
		return
	}
	throttled := b.Statuses["429"] + b.Statuses["503"]
	good := b.Successes - throttled
	if good < 0 {
		good = 0
	}
	successRate := float64(good) / float64(b.Requests)
	latencyOK := true
	if baselineMs > 0 {
		latencyOK = b.P95Ms <= baselineMs*2
	}
	b.Healthy = successRate >= 0.98 && latencyOK
}

// sustainedNote summarizes the sustained run: rate-limit detection,
// timeout fraction, and a one-line verdict.
func sustainedNote(b *Bucket) string {
	if b == nil || b.Requests == 0 {
		return "sustained: no data"
	}
	parts := []string{fmt.Sprintf("sustained: %d req in %.1fs (%.1f rps)",
		b.Requests, float64(b.DurationMs)/1000.0, b.ThroughputRPS)}
	if t := b.Statuses["429"] + b.Statuses["503"]; t > 0 {
		parts = append(parts, fmt.Sprintf("throttled %d× (HTTP 429/503) — server rate-limiter active", t))
	}
	if b.ErrorTypes["timeout"] > 0 {
		parts = append(parts, fmt.Sprintf("%d timeouts", b.ErrorTypes["timeout"]))
	}
	if b.ErrorTypes["conn-refused"] > 0 {
		parts = append(parts, fmt.Sprintf("%d connections refused (TCP backlog full?)", b.ErrorTypes["conn-refused"]))
	}
	if b.ErrorTypes["conn-reset"] > 0 {
		parts = append(parts, fmt.Sprintf("%d connections reset", b.ErrorTypes["conn-reset"]))
	}
	return strings.Join(parts, " · ")
}

func burstNote(b *Bucket, baselineMs int64) string {
	if b == nil || b.Requests == 0 {
		return "burst: no data"
	}
	parts := []string{fmt.Sprintf("burst: %d req · p95=%dms", b.Requests, b.P95Ms)}
	if t := b.Statuses["429"] + b.Statuses["503"]; t > 0 {
		parts = append(parts, fmt.Sprintf("anti-burst defense triggered (%d throttled)", t))
	}
	if baselineMs > 0 && b.P95Ms > baselineMs*3 {
		parts = append(parts, "p95 > 3× baseline — bursts are degrading service even if they don't 429")
	}
	if b.Errors == 0 && (b.Statuses["429"]+b.Statuses["503"]) == 0 {
		parts = append(parts, "no anti-burst signal detected")
	}
	return strings.Join(parts, " · ")
}
