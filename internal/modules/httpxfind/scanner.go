package httpxfind

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"io"
	"math/rand"
	"net"
	"net/http"
	"regexp"
	"scanner/internal/modules/shared"
	"scanner/internal/sysmon"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

// ScanMode determines which ports to probe
type ScanMode string

const (
	ModeCommon ScanMode = "common" // 80, 443, 8080, 8443
	ModeFull   ScanMode = "full"   // all 65535 ports
	ModePorts  ScanMode = "ports"  // an operator-supplied custom port list/range
)

// CommonPorts are the default HTTP/HTTPS ports
var CommonPorts = []int{80, 443, 8080, 8443}

const (
	maxBodySize = 256 * 1024 // 256 KB max response body
	tcpTimeout  = 2 * time.Second
	httpTimeout = 8 * time.Second
	// fullScanConc: default concurrency for the Full-mode TCP port scan.
	// Lowered from 500 → 150: at 500 concurrent connect()s with no rate cap
	// the Full sweep behaved like a SYN flood — a home router's conntrack/NAT
	// table fills and ALL traffic (including the operator's browsing) drops,
	// and the self-induced packet loss made genuinely-open ports time out and
	// be recorded closed. Overridable per-scan (Task 6).
	fullScanConc = 150
	// fullScanRate: default cap on NEW TCP connect attempts per second during
	// Full-mode discovery. This is the real safety valve — the concurrency
	// bound alone doesn't stop fast-RST ports from letting the loop spin at
	// tens of thousands of new flows/sec. 0 = unlimited. Overridable per-scan.
	fullScanRate   = 500
	probeConcLimit = 20 // concurrency for HTTP probing
	// fullMaxPort is the top of the full-sweep port range.
	fullMaxPort = 65535
	// memBackpressureFrac: the feeder PAUSES streaming new probe tasks while
	// MemAvailable/MemTotal drops below this fraction, so a wide sweep self-
	// limits BEFORE it trips the memory governor's hard abort (~0.12). This is
	// insurance on top of the result caps (addService) — the task channel is
	// already bounded, but a burst of large pages can still grow RSS between
	// GC cycles; backing off feeding lets GC catch up instead of OOMing.
	memBackpressureFrac = 0.20
)

// TotalUpdatePrefix is a sentinel prefix on progress messages used to
// communicate the post-discovery true task count back to the handler.
// The handler intercepts messages starting with this prefix and translates
// them into db.UpdateScanProgressFull, then suppresses the message from
// the UI. Audit fix for the full-mode "100% after first host" bar bug —
// the denominator isn't known until the resolve pass finishes, so the scan
// starts in indeterminate (total=0) mode and switches once we have the
// real number.
const TotalUpdatePrefix = "__TOTAL__:"

// ServiceResult holds one discovered HTTP(S) service
type ServiceResult struct {
	Host            string `json:"host"`
	Port            int    `json:"port"`
	URL             string `json:"url"`
	Scheme          string `json:"scheme"` // "http" or "https"
	StatusCode      int    `json:"status_code"`
	Title           string `json:"title"`
	Server          string `json:"server"`
	ContentType     string `json:"content_type"`
	ContentLength   int64  `json:"content_length"`
	RedirectURL     string `json:"redirect_url,omitempty"`
	ResponseHeaders string `json:"response_headers"`
	ResponseBody    string `json:"response_body"`
	RawRequest      string `json:"raw_request,omitempty"`
	RawResponse     string `json:"raw_response,omitempty"`
}

// ScanResult is the full output of a scan
type ScanResult struct {
	Services  []ServiceResult `json:"services"`
	Truncated bool            `json:"truncated,omitempty"` // resident-memory cap hit; heavy fields dropped / services capped
	bodyBytes int64           // running estimate of retained body/raw bytes (not serialized)
}

const (
	// maxServices hard-caps how many services are RETAINED in memory. An all-port
	// sweep against a catch-all/tarpit host that answers HTTP on every port would
	// otherwise grow result.Services toward hosts×65535 entries and OOM the box.
	maxServices = 20000
	// maxResultBodyBytes caps the total RETAINED response-body/raw bytes. Past it,
	// services are still recorded (host/port/status/title) but the heavy body/raw
	// fields are dropped, so the resident set stays bounded regardless of how many
	// large pages answer.
	maxResultBodyBytes = 128 * 1024 * 1024 // 128 MB
)

// addService appends svc under the caller's lock, enforcing the resident-memory
// bounds: past maxResultBodyBytes it keeps the metadata but strips the heavy
// body/raw fields; past maxServices it stops retaining new services entirely.
// Sets Truncated when either bound bites. Returns whether svc was retained.
func (r *ScanResult) addService(svc ServiceResult) bool {
	if len(r.Services) >= maxServices {
		r.Truncated = true
		return false
	}
	if r.bodyBytes > maxResultBodyBytes {
		svc.ResponseBody = ""
		svc.ResponseHeaders = ""
		svc.RawRequest = ""
		svc.RawResponse = ""
		r.Truncated = true
	} else {
		r.bodyBytes += int64(len(svc.ResponseBody) + len(svc.ResponseHeaders) + len(svc.RawRequest) + len(svc.RawResponse))
	}
	r.Services = append(r.Services, svc)
	return true
}

// ProgressFunc is called to report scan progress
type ProgressFunc func(done int, msg string)

// PartialFunc fires on each significant result change for live UI updates
type PartialFunc func(partial *ScanResult)

// Scan runs HTTP/HTTPS discovery using the default probe concurrency.
func Scan(targets []string, mode ScanMode, opts *shared.HTTPOptions, onPartial PartialFunc, progress ProgressFunc) *ScanResult {
	return ScanWithConcurrency(targets, mode, 0, opts, onPartial, progress)
}

// ScanWithConcurrency lets the caller override the HTTP probe concurrency.
// Pass 0 to keep the module default (probeConcLimit = 20). Useful for the
// advancedweb suite where Deep + lots of subdomains produces 200k+ tasks
// and a higher concurrency keeps wall-clock under an hour.
func ScanWithConcurrency(targets []string, mode ScanMode, concurrency int, opts *shared.HTTPOptions, onPartial PartialFunc, progress ProgressFunc) *ScanResult {
	return scanCore(targets, mode, nil, concurrency, 0, 0, false, opts, onPartial, progress)
}

// ScanCommon runs a fixed-port (Common) scan honouring BOTH per-scan overrides:
// concurrency = parallel HTTP probes (<=0 → module default probeConcLimit=20) and
// rate = a requests/sec cap on the probe (<=0 → unlimited). This is what wires the
// form's "Max concurrent" and "Rate limit (req/s)" fields into Common mode, which
// previously ignored them and always ran at the fixed default.
func ScanCommon(targets []string, concurrency, rate int, opts *shared.HTTPOptions, onPartial PartialFunc, progress ProgressFunc) *ScanResult {
	return scanCore(targets, ModeCommon, nil, concurrency, 0, rate, false, opts, onPartial, progress)
}

// ScanFull runs Full-mode discovery with explicit TCP-scan tuning (Task 6
// per-module override). tcpConc = concurrent connect()s during discovery
// (0 = default 150); tcpRate = max NEW connections/sec (0 = default 500,
// negative = unlimited). probeConc = HTTP-probe concurrency (0 = default).
// directHTTP skips the TCP connect port-scan entirely and fires HTTP/HTTPS
// straight at every port — only ports that actually answer HTTP are recorded,
// so a firewall that tarpits/accepts all connects can't inflate the result.
func ScanFull(targets []string, probeConc, tcpConc, tcpRate int, directHTTP bool, opts *shared.HTTPOptions, onPartial PartialFunc, progress ProgressFunc) *ScanResult {
	return scanCore(targets, ModeFull, nil, probeConc, tcpConc, tcpRate, directHTTP, opts, onPartial, progress)
}

// ScanWithPorts is the explicit-port-list variant. The caller supplies the exact
// ports to probe per host (e.g. parsed from a "80,443,8000-8100" user input via
// shared.ExpandPortSpec). An empty list falls back to the same default as
// ModeCommon.
//
// It honours the same two shapes as Full mode via the directHTTP flag:
//   - directHTTP = true  → single-phase HTTP/HTTPS probe of every listed port
//     (only ports that actually answer HTTP are recorded — the classic behaviour).
//   - directHTTP = false → a TCP connect pre-scan of the listed ports first, then
//     an HTTP probe of only the OPEN ones ("classic TCP → HTTP").
//
// rate caps NEW connections/probes per second (0 = module default, <0 =
// unlimited); concurrency bounds in-flight probes/connects.
func ScanWithPorts(targets []string, customPorts []int, concurrency, rate int, directHTTP bool, opts *shared.HTTPOptions, onPartial PartialFunc, progress ProgressFunc) *ScanResult {
	// connect + probe share the operator's "Max concurrent" for a custom list.
	return scanCore(targets, ModePorts, customPorts, concurrency, concurrency, rate, directHTTP, opts, onPartial, progress)
}

// scanCore builds the shared HTTP client/transport and dispatches to the single
// bounded worker-pool engine (runEngine). The port plan is derived from
// (mode, customPorts): a non-empty customPorts list = custom mode (overrides the
// mode arg); mode == ModeFull with no list = the 65535-port sweep; otherwise the
// fixed Common ports.
func scanCore(targets []string, mode ScanMode, customPorts []int, concurrency, tcpConc, tcpRate int, directHTTP bool, opts *shared.HTTPOptions, onPartial PartialFunc, progress ProgressFunc) *ScanResult {
	result := &ScanResult{}
	var mu sync.Mutex

	// HTTP-probe concurrency.
	if concurrency <= 0 {
		concurrency = probeConcLimit
	}
	if concurrency > 1000 {
		// Hard cap — past ~500 the FD limit + per-target rate-limit pushback
		// makes higher numbers slower, not faster.
		concurrency = 1000
	}
	// Connect-phase concurrency (full / custom connect mode). 0 = module default.
	if tcpConc <= 0 {
		tcpConc = fullScanConc
	}

	// Build ONE shared http.Transport for the whole scan (audit perf fix).
	// Previously tryScheme allocated a fresh Transport per scheme/port/host — for
	// a ModeFull scan with thousands of open ports that meant thousands of TLS
	// session caches + idle conn pools allocated and leaked for the scan's
	// lifetime. opts.ApplyTransport registers the transport so
	// ScanManager.Cancel can flush its idle pool.
	sharedTransport := &http.Transport{
		TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
		// audit K05/K06: shared.BoundDialer enforces L2 source-IP pinning even
		// when opts is nil (falls back to SetGlobalLocalAddr).
		DialContext:         shared.BoundDialer(opts, tcpTimeout).DialContext,
		MaxIdleConns:        100,
		MaxIdleConnsPerHost: 50,
		IdleConnTimeout:     90 * time.Second,
	}
	if opts != nil {
		opts.ApplyTransport(sharedTransport)
	}
	// Honor the per-scan / global request-timeout override (opts.Timeout, set by
	// the handler's applyHTTPTuning) for the HTTP probe; fall back to the 8s
	// module default.
	httpTO := httpTimeout
	if opts != nil && opts.Timeout > 0 {
		httpTO = opts.Timeout
	}
	sharedClient := &http.Client{
		Timeout:   httpTO,
		Transport: sharedTransport,
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse // don't follow redirects
		},
	}

	full := mode == ModeFull && len(customPorts) == 0
	custom := len(customPorts) > 0

	ec := engineConfig{
		result:     result,
		mu:         &mu,
		targets:    targets,
		full:       full,
		directHTTP: directHTTP,
		probeConc:  concurrency,
		connConc:   tcpConc,
		rate:       tcpRate,
		client:     sharedClient,
		opts:       opts,
		onPartial:  onPartial,
		progress:   progress,
	}
	switch {
	case full:
		// Full + custom resolve their targets up front and own the % denominator
		// (sentinel). Common does not (handler-seeded, fixed 4 ports).
		ec.resolve = true
		ec.label = "Full scan"
	case custom:
		ec.resolve = true
		ec.ports = customPorts
		ec.label = "Custom scan"
	default:
		ec.ports = CommonPorts
		ec.perTask = true // Common keeps its familiar per-task "[done/total] ✓ URL" lines.
		ec.label = "Common scan"
	}
	return runEngine(ec)
}

// probeTask is one (host, port) unit of work streamed through the worker pool.
type probeTask struct {
	host string
	port int
}

// engineConfig parameterises the single bounded engine.
type engineConfig struct {
	result     *ScanResult
	mu         *sync.Mutex
	targets    []string
	full       bool     // port source = portPermuter (1..65535); else `ports`
	ports      []int    // explicit ports (Common or custom) when !full
	directHTTP bool     // skip the TCP connect pre-scan; probe HTTP/HTTPS directly
	resolve    bool     // resolve targets up front + own the % denominator (full/custom)
	perTask    bool     // emit per-task progress lines (Common mode only)
	probeConc  int      // HTTP-probe worker count
	connConc   int      // connect-phase worker count (two-phase)
	rate       int      // NEW connections/probes per sec (0 = default/unlimited, see runEngine)
	label      string   // "Full scan" / "Custom scan" / "Common scan" for messages
	client     *http.Client
	opts       *shared.HTTPOptions
	onPartial  PartialFunc
	progress   ProgressFunc
}

// runEngine is the one bounded, fixed-worker-pool HTTP(S) discovery engine. It
// replaces the previous goroutine-per-probe loops: a single feeder goroutine
// streams (host,port) tasks into a BOUNDED channel (checking cancellation,
// draining a rate token, and applying memory back-pressure), and a fixed set of
// N long-lived workers drains it. Goroutine count is ~N + feeder + heartbeat,
// not ~hosts×ports, so a 3000×65535 sweep no longer churns ~196M goroutines
// (the GC-thrash / CPU-pin / RSS-growth that sank the old engine).
//
// Two shapes, selected by directHTTP:
//   - directHTTP (or Common) → single phase: HTTP/HTTPS-probe every (host,port);
//     only HTTP responders are recorded.
//   - connect (full/custom, directHTTP off) → two phase: a cheap TCP connect
//     sweep, then HTTP-probe only the OPEN ports.
func runEngine(ec engineConfig) *ScanResult {
	result, mu, opts := ec.result, ec.mu, ec.opts
	targets := ec.targets

	// ---- Resolve pass (full/custom only) ---------------------------------
	// Drop definitively-unresolvable hosts BEFORE the sweep (fail-open: only
	// NXDOMAIN is dropped) and dial each resolvable host by its ONE cached IP so
	// DNS isn't re-hit per port.
	var ipCache map[string]string
	if ec.resolve {
		var dropped int
		targets, ipCache, dropped = resolveTargets(targets, opts)
		if dropped > 0 && ec.progress != nil {
			ec.progress(0, fmt.Sprintf("%d unresolvable host(s) skipped — not probing their ports (fail-open: only definitively non-existent names are dropped)", dropped))
		}
		if len(targets) == 0 {
			if ec.progress != nil {
				ec.progress(0, fmt.Sprintf("No resolvable targets (%d host(s) unresolved) — nothing to scan", dropped))
			}
			return result
		}
		if len(ipCache) > 0 {
			if tr, ok := ec.client.Transport.(*http.Transport); ok {
				base := tr.DialContext
				tr.DialContext = func(ctx context.Context, network, addr string) (net.Conn, error) {
					if h, p, err := net.SplitHostPort(addr); err == nil {
						if ip := ipCache[h]; ip != "" {
							addr = net.JoinHostPort(ip, p)
						}
					}
					return base(ctx, network, addr)
				}
			}
		}
	}

	portsPerHost := fullMaxPort
	if !ec.full {
		portsPerHost = len(ec.ports)
	}
	discTotal := len(targets) * portsPerHost

	// ---- Rate normalisation ----------------------------------------------
	// After this: rate == 0 → unlimited (no token bucket); rate > 0 → capped.
	//   full/custom (resolve): a blank rate (0) → the safe fullScanRate default,
	//     an explicit unlimited (<0) stays unlimited.
	//   Common (no resolve): 0 stays unlimited so a blank rate_limit doesn't
	//     silently cap a small Common scan.
	rate := ec.rate
	switch {
	case rate < 0:
		rate = 0
	case rate == 0:
		if ec.resolve {
			rate = fullScanRate
		}
	}

	// Two-phase connect only when directHTTP is off AND this mode resolves
	// (full/custom). Common never pre-scans — a connect sweep of 4 ports is
	// pointless, so Common ignores directHTTP and always HTTP-probes directly.
	twoPhase := !ec.directHTTP && ec.resolve

	// Reserve the bar's tail for phase 2 (connect mode) so HTTP-probing the open
	// ports actually moves the %. The denominator is bumped up front so the bar
	// never jumps backwards when phase 2 begins.
	reserve := 0
	total := discTotal
	if twoPhase {
		reserve = discTotal / 6 // ~14% of the bar
		if reserve < 1 {
			reserve = 1
		}
		total = discTotal + reserve
	}
	if ec.resolve && ec.progress != nil {
		// Correct the handler-seeded total (accounts for dropped hosts + the
		// phase-2 reserve) so the % + ETA reflect the real remaining work.
		ec.progress(0, TotalUpdatePrefix+strconv.Itoa(total))
		shape := ec.label
		if ec.directHTTP {
			shape += " (direct HTTP/HTTPS)"
		}
		suffix := ""
		if ec.full {
			suffix = ", random order"
		}
		ec.progress(0, fmt.Sprintf("%s: %d hosts × %d ports%s", shape, len(targets), portsPerHost, suffix))
	}

	// ---- Rate limiter (shared token bucket) ------------------------------
	var tokens chan struct{}
	rlDone := make(chan struct{})
	defer close(rlDone)
	if rate > 0 {
		tokens = startRateLimiter(rate, rlDone)
	}

	// ---- Shared result sink ----------------------------------------------
	partialThrottle := shared.NewPartialThrottler(2 * time.Second)
	addAndPartial := func(svc *ServiceResult) {
		mu.Lock()
		added := result.addService(*svc)
		var snap *ScanResult
		// Gate the O(n) slice copy behind the throttler: without it a wide sweep
		// with many live services copies the whole retained slice on every hit.
		if added && ec.onPartial != nil && partialThrottle.ShouldFire() {
			snap = &ScanResult{Services: append([]ServiceResult(nil), result.Services...), Truncated: result.Truncated}
		}
		mu.Unlock()
		if snap != nil {
			ec.onPartial(snap)
		}
	}

	var scanned int32 // tasks probed (phase 1 for connect; all for single-phase)
	var found int32   // live services (single-phase) or open ports (connect phase 1)

	// feedProbes streams every (host,port) task, bounded by cancellation, the
	// rate token, and memory back-pressure. It round-robins across hosts (full:
	// one random port per host per round via portPermuter; fixed: host-outer,
	// port-inner to match the historical Common ordering).
	feedProbes := func(tasks chan<- probeTask) {
		defer close(tasks)
		var lastMem time.Time
		memWait := func() {
			// Sample ~1×/sec; pause feeding while available memory is low so a
			// wide sweep self-limits before the governor's hard abort.
			now := time.Now()
			if now.Sub(lastMem) < time.Second {
				return
			}
			lastMem = now
			for sysmon.ReadMemory().AvailFrac() < memBackpressureFrac {
				if opts.Done() {
					return
				}
				time.Sleep(200 * time.Millisecond)
			}
		}
		emit := func(host string, port int) bool {
			if opts.Done() {
				return false
			}
			if tokens != nil {
				select {
				case <-tokens:
				case <-rlDone:
					return false
				}
				if opts.Done() {
					return false
				}
			}
			memWait()
			if opts.Done() {
				return false
			}
			// Safe to block here: workers always keep receiving until the channel
			// is closed (they drain-and-skip after cancellation), so this never
			// deadlocks — it is the intended back-pressure that bounds in-flight.
			tasks <- probeTask{host: host, port: port}
			return true
		}
		if ec.full {
			perms := make([]*portPermuter, len(targets))
			for i := range perms {
				perms[i] = newPortPermuter()
			}
			for round := 0; round < fullMaxPort; round++ {
				if opts.Done() {
					return
				}
				for hi, host := range targets {
					port, ok := perms[hi].next()
					if !ok {
						continue
					}
					if !emit(host, port) {
						return
					}
				}
			}
		} else {
			for _, host := range targets {
				if opts.Done() {
					return
				}
				for _, port := range ec.ports {
					if !emit(host, port) {
						return
					}
				}
			}
		}
	}

	hitLog := shared.NewPartialThrottler(750 * time.Millisecond)

	// ======================================================================
	// Single phase: HTTP-probe every task (Common; full/custom directHTTP).
	// ======================================================================
	if !twoPhase {
		var hb chan struct{}
		if !ec.perTask && ec.progress != nil {
			hb = startHeartbeat(ec.progress, "Direct HTTP sweep", &scanned, &found, discTotal, "live")
		}
		probeWork := func(t probeTask) {
			svc := probeHTTP(t.host, t.port, ec.client, opts)
			done := atomic.AddInt32(&scanned, 1)
			if svc != nil {
				atomic.AddInt32(&found, 1)
				addAndPartial(svc)
			}
			if ec.progress == nil {
				return
			}
			if ec.perTask {
				if svc != nil {
					extras := []string{fmt.Sprintf("HTTP %d", svc.StatusCode)}
					if svc.Server != "" {
						extras = append(extras, svc.Server)
					}
					if svc.Title != "" {
						ttl := svc.Title
						if len(ttl) > 40 {
							ttl = ttl[:40] + "…"
						}
						extras = append(extras, "\""+ttl+"\"")
					}
					ec.progress(int(done), fmt.Sprintf("[%d/%d] ✓ %s (%s)", done, discTotal, svc.URL, strings.Join(extras, " · ")))
				} else {
					ec.progress(int(done), fmt.Sprintf("[%d/%d] · no HTTP on %s:%d", done, discTotal, t.host, t.port))
				}
			} else if svc != nil && hitLog.ShouldFire() {
				ec.progress(int(atomic.LoadInt32(&scanned)), fmt.Sprintf("✓ %s (HTTP %d)", svc.URL, svc.StatusCode))
			}
		}
		runPool(ec.probeConc, ec.probeConc, opts, feedProbes, probeWork)
		if hb != nil {
			close(hb)
		}
		// Terminal line (full/custom only — Common relies on the handler's done
		// clamp). Only when we finished on our own: a cancel (governor /
		// killswitch / Stop) already wrote the real terminal reason.
		if ec.resolve && ec.progress != nil && !opts.Done() {
			ec.progress(discTotal, fmt.Sprintf("Direct HTTP sweep done — %d live service(s)", atomic.LoadInt32(&found)))
		}
		return result
	}

	// ======================================================================
	// Two phase (connect): TCP connect sweep → HTTP-probe the open ports.
	// ======================================================================
	connectDialer := shared.BoundDialer(opts, tcpTimeout) // hoisted once (was per-connect)
	var openMu sync.Mutex
	open := make([]probeTask, 0, 1024)
	connectWork := func(t probeTask) {
		atomic.AddInt32(&scanned, 1)
		dialHost := t.host
		if ip := ipCache[t.host]; ip != "" {
			dialHost = ip
		}
		conn, err := connectDialer.Dial("tcp", net.JoinHostPort(dialHost, strconv.Itoa(t.port)))
		if err != nil {
			return
		}
		conn.Close()
		atomic.AddInt32(&found, 1)
		openMu.Lock()
		open = append(open, t)
		openMu.Unlock()
	}
	var hb chan struct{}
	if ec.progress != nil {
		hb = startHeartbeat(ec.progress, "Port sweep", &scanned, &found, discTotal, "open")
	}
	runPool(ec.connConc, ec.connConc, opts, feedProbes, connectWork)
	if hb != nil {
		close(hb)
	}

	// ---- Phase 2: HTTP-probe the discovered open ports -------------------
	p := len(open)
	if p == 0 {
		if ec.progress != nil && !opts.Done() {
			ec.progress(discTotal+reserve, fmt.Sprintf("%s done — 0 open ports", ec.label))
		}
		return result
	}
	if ec.progress != nil {
		ec.progress(discTotal, fmt.Sprintf("%d open port(s) — probing for HTTP services", p))
	}
	var pdone int32
	var plive int32
	p2start := time.Now()
	p2Done := make(chan struct{})
	if ec.progress != nil {
		go func() {
			ticker := time.NewTicker(2 * time.Second)
			defer ticker.Stop()
			for {
				select {
				case <-p2Done:
					return
				case <-ticker.C:
					d := atomic.LoadInt32(&pdone)
					done := discTotal + int(int64(d)*int64(reserve)/int64(p))
					ec.progress(done, fmt.Sprintf("HTTP probe — %d/%d open ports, %d live%s", d, p, atomic.LoadInt32(&plive), etaSuffix(p2start, int(d), p)))
				}
			}
		}()
	}
	probe2Work := func(t probeTask) {
		svc := probeHTTP(t.host, t.port, ec.client, opts)
		atomic.AddInt32(&pdone, 1)
		if svc == nil {
			return
		}
		atomic.AddInt32(&plive, 1)
		addAndPartial(svc)
	}
	runPool(ec.probeConc, ec.probeConc, opts, func(tasks chan<- probeTask) {
		defer close(tasks)
		for _, hp := range open {
			if opts.Done() {
				return
			}
			tasks <- hp
		}
	}, probe2Work)
	close(p2Done)
	if ec.progress != nil && !opts.Done() {
		ec.progress(discTotal+reserve, fmt.Sprintf("%s done — %d live HTTP service(s)", ec.label, len(result.Services)))
	}
	return result
}

// runPool spawns `workers` long-lived goroutines draining a bounded task channel
// fed by `feed` (which runs in its own goroutine and MUST close the channel when
// done). work is called per task; after cancellation workers drain-and-skip so
// the feeder's send never deadlocks. Goroutine count is fixed at workers + 1.
func runPool(workers, buffer int, opts *shared.HTTPOptions, feed func(chan<- probeTask), work func(probeTask)) {
	if workers < 1 {
		workers = 1
	}
	if buffer < 1 {
		buffer = 1
	}
	tasks := make(chan probeTask, buffer)
	go feed(tasks)
	var wg sync.WaitGroup
	wg.Add(workers)
	for i := 0; i < workers; i++ {
		go func() {
			defer wg.Done()
			for t := range tasks {
				if opts.Done() {
					continue // drain-and-skip after cancel (keeps the feeder unblocked)
				}
				work(t)
			}
		}()
	}
	wg.Wait()
}

// startRateLimiter returns a token channel refilled at `rate` tokens/sec (via a
// 20 Hz ticker), closed-safe via the `done` channel. Mirrors the previous
// per-path token bucket, hoisted to one helper.
func startRateLimiter(rate int, done <-chan struct{}) chan struct{} {
	const tickHz = 20
	per := rate / tickHz
	if per < 1 {
		per = 1
	}
	depth := rate
	if depth < per {
		depth = per
	}
	tokens := make(chan struct{}, depth)
	go func() {
		ticker := time.NewTicker(time.Second / tickHz)
		defer ticker.Stop()
		for {
			select {
			case <-done:
				return
			case <-ticker.C:
				for i := 0; i < per; i++ {
					select {
					case tokens <- struct{}{}:
					default:
					}
				}
			}
		}
	}()
	return tokens
}

// startHeartbeat reports a phase's climb ("<label> — done/total probed, N <word>")
// every 2s off the shared atomic counters, so the bar advances without a DB write
// per probe. Returns a channel the caller closes to stop it.
func startHeartbeat(progress ProgressFunc, label string, counter, foundCounter *int32, denom int, word string) chan struct{} {
	hb := make(chan struct{})
	start := time.Now()
	go func() {
		ticker := time.NewTicker(2 * time.Second)
		defer ticker.Stop()
		for {
			select {
			case <-hb:
				return
			case <-ticker.C:
				s := atomic.LoadInt32(counter)
				progress(int(s), fmt.Sprintf("%s — %d/%d probed, %d %s%s", label, s, denom, atomic.LoadInt32(foundCounter), word, etaSuffix(start, int(s), denom)))
			}
		}
	}()
	return hb
}

// portPermuter yields a per-host pseudo-random full permutation of ports
// 1..65535 in O(1) memory (no 64K slice per host). It walks the residues of
// the prime 65537 by a random stride: x -> (x + a) mod 65537, with a coprime
// to 65537 (every a in [1,65536] is — 65537 is prime), which visits all
// residues exactly once before repeating. Residues 0 and 65536 aren't valid
// ports and are skipped. A random start x and random stride a PER HOST mean
// each host is swept in a different, non-sequential order — defeating the
// "ports probed strictly 1,2,3,…" scan signature an IDS/firewall keys on.
type portPermuter struct {
	a, x, emitted int
}

func newPortPermuter() *portPermuter {
	return &portPermuter{a: rand.Intn(65536) + 1, x: rand.Intn(65537)}
}

// next returns the host's next port (1..65535) and true, or 0/false once all
// 65535 ports have been emitted.
func (p *portPermuter) next() (int, bool) {
	for p.emitted < 65535 {
		p.x = (p.x + p.a) % 65537
		if p.x >= 1 && p.x <= 65535 {
			p.emitted++
			return p.x, true
		}
		// p.x == 0 or 65536 → not a port; step again without consuming a slot.
	}
	return 0, false
}

// resolveTargets resolves each hostname target ONCE up front and returns the
// hosts worth sweeping plus a host→IP cache. Two wins for a wide Full sweep:
//   - a host whose DNS does NOT resolve is DROPPED — we don't burn 65535 failed
//     probes (and 65535 failed DNS lookups) on it. Literal IPs pass through.
//   - resolvable hosts are resolved once here; the caller dials every port by the
//     cached IP, so DNS isn't re-hit per port (was a per-probe allocation source).
//
// Fail OPEN: a host is dropped ONLY when the resolver is CONFIDENT it does not
// exist (NXDOMAIN). A flaky resolver — the killswitch-bound resolver with a
// stale source IP after a VPN reconnect, a timing-out or SERVFAILing nameserver
// — returns errors that are NOT NXDOMAIN; those hosts are KEPT (with no cached
// IP, so the dial resolves them normally). This is safe even under the killswitch
// (a bound-resolver hiccup can't false-drop a host), while still honoring "drop
// the ones that genuinely don't resolve".
func resolveTargets(targets []string, opts *shared.HTTPOptions) (keep []string, ipCache map[string]string, dropped int) {
	res := shared.SystemResolver()
	ipCache = make(map[string]string, len(targets))
	sem := make(chan struct{}, 50)
	var wg sync.WaitGroup
	var mu sync.Mutex
	keep = make([]string, 0, len(targets))
	for _, t := range targets {
		if opts != nil && opts.Done() {
			break
		}
		if net.ParseIP(t) != nil {
			keep = append(keep, t) // literal IP — no resolution needed
			continue
		}
		wg.Add(1)
		sem <- struct{}{}
		go func(host string) {
			defer wg.Done()
			defer func() { <-sem }()
			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()
			addrs, err := res.LookupHost(ctx, host)
			if err != nil {
				var derr *net.DNSError
				if errors.As(err, &derr) && derr.IsNotFound {
					return // NXDOMAIN — genuinely unresolvable, drop it
				}
				// any other error → fail open, keep (dial will resolve it)
			} else if len(addrs) == 0 {
				return
			}
			mu.Lock()
			keep = append(keep, host)
			if len(addrs) > 0 {
				ipCache[host] = addrs[0] // resolve once, reuse for every port
			}
			mu.Unlock()
		}(t)
	}
	wg.Wait()
	return keep, ipCache, len(targets) - len(keep)
}

// fmtDur renders a coarse human duration for the ETA (handles hours — a
// 100M-scale sweep's ETA is measured in hours, and the template's own
// formatDuration FuncMap helper isn't reachable from module code).
func fmtDur(d time.Duration) string {
	if d < 0 {
		d = 0
	}
	d = d.Round(time.Second)
	h := d / time.Hour
	m := (d % time.Hour) / time.Minute
	s := (d % time.Minute) / time.Second
	switch {
	case h > 0:
		return fmt.Sprintf("%dh%02dm", h, m)
	case m > 0:
		return fmt.Sprintf("%dm%02ds", m, s)
	default:
		return fmt.Sprintf("%ds", s)
	}
}

// etaSuffix returns " · <rate>/s · ETA <dur>" from the run's average rate, or
// "" until there's enough data (guards against a garbage/div-by-zero ETA on
// the first tick).
func etaSuffix(start time.Time, done, total int) string {
	if done <= 0 || total <= 0 {
		return ""
	}
	elapsed := time.Since(start).Seconds()
	if elapsed <= 0 {
		return ""
	}
	rate := float64(done) / elapsed
	if rate <= 0 {
		return ""
	}
	remaining := total - done
	if remaining < 0 {
		remaining = 0
	}
	eta := time.Duration(float64(remaining)/rate) * time.Second
	return fmt.Sprintf(" · %.0f/s · ETA %s", rate, fmtDur(eta))
}

// probeHTTP tries HTTPS then HTTP on a host:port, returns nil if no HTTP service.
// Audit bug fix: records AT MOST one error per (host,port) — previously each
// scheme failure called opts.RecordError separately, so a single dead port
// consumed two slots of the per-scan ErrorThreshold and tripped the abort
// logic twice as fast as intended (with the default threshold of 3, two
// dead ports could abort the entire scan).
// Scheme probe orders, hoisted to package scope so probeHTTP doesn't allocate a
// fresh 2-string slice on every one of a wide sweep's 100M+ calls. Read-only.
var (
	schemesHTTPSFirst = []string{"https", "http"}
	schemesHTTPFirst  = []string{"http", "https"}
)

func probeHTTP(host string, port int, client *http.Client, opts *shared.HTTPOptions) *ServiceResult {
	// Try HTTPS first for 443-like ports, HTTP first for 80-like ports
	schemes := schemesHTTPSFirst
	if port == 80 || port == 8080 {
		schemes = schemesHTTPFirst
	}

	var firstErr error
	for _, scheme := range schemes {
		svc, err := tryScheme(host, port, scheme, client, opts)
		if svc != nil {
			return svc
		}
		if err != nil && firstErr == nil {
			firstErr = err
		}
	}
	if firstErr != nil && opts != nil {
		opts.RecordError(shared.ClassifyError(firstErr))
	}
	return nil
}

// tryScheme returns (service, err). err is non-nil on transport failure so the
// caller can decide whether to count it toward the per-scan error budget.
// RecordError is NOT called here — see probeHTTP for the rationale.
func tryScheme(host string, port int, scheme string, client *http.Client, opts *shared.HTTPOptions) (*ServiceResult, error) {
	url := fmt.Sprintf("%s://%s:%d", scheme, host, port)
	// Omit default ports in URL display
	if (scheme == "http" && port == 80) || (scheme == "https" && port == 443) {
		url = fmt.Sprintf("%s://%s", scheme, host)
	}

	req, err := http.NewRequest("GET", url, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("User-Agent", "scaNNer/1.0")
	if opts != nil {
		opts.ApplyTo(req)
	}
	req = opts.BindContext(req)

	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	// Capture the raw request/response ONLY now that the port answered — i.e.
	// for a service we're actually going to keep. tryScheme runs once per
	// (host,port,scheme); a wide Full/directHTTP sweep is 100M+ probes, virtually
	// all dead. Dumping the request (httputil.DumpRequest + secret-redaction
	// regex + truncate) BEFORE client.Do meant a full request serialization per
	// DEAD port, every byte of it discarded on the error return above — the
	// dominant allocation churn that drove a 0-live sweep's RSS up into the
	// memory governor's abort threshold. A GET carries no body, so capturing
	// after Do produces the same dump.
	rawReq := shared.CaptureRequest(req)
	rawResp := shared.CaptureResponse(resp)

	// Read body (limited) — CaptureResponse already buffered + restored.
	bodyBytes, _ := io.ReadAll(io.LimitReader(resp.Body, maxBodySize))
	body := string(bodyBytes)

	// Extract title
	title := extractTitle(body)

	redirectURL := ""
	if loc := resp.Header.Get("Location"); loc != "" {
		redirectURL = loc
	}

	// Format headers
	var hdrBuf strings.Builder
	for k, vals := range resp.Header {
		for _, v := range vals {
			hdrBuf.WriteString(k + ": " + v + "\n")
		}
	}

	opts.ReplayHit("GET", url)

	return &ServiceResult{
		Host:            host,
		Port:            port,
		URL:             url,
		Scheme:          scheme,
		StatusCode:      resp.StatusCode,
		Title:           title,
		Server:          resp.Header.Get("Server"),
		ContentType:     resp.Header.Get("Content-Type"),
		ContentLength:   resp.ContentLength,
		RedirectURL:     redirectURL,
		ResponseHeaders: hdrBuf.String(),
		ResponseBody:    body,
		RawRequest:      rawReq,
		RawResponse:     rawResp,
	}, nil
}

var titleRe = regexp.MustCompile(`(?i)<title[^>]*>([^<]+)</title>`)

func extractTitle(body string) string {
	m := titleRe.FindStringSubmatch(body)
	if len(m) > 1 {
		title := strings.TrimSpace(m[1])
		if len(title) > 200 {
			title = title[:200]
		}
		return title
	}
	return ""
}
