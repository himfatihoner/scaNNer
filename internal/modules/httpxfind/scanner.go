package httpxfind

import (
	"crypto/tls"
	"fmt"
	"io"
	"math/rand"
	"net"
	"net/http"
	"regexp"
	"scanner/internal/modules/shared"
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
)

// TotalUpdatePrefix is a sentinel prefix on progress messages used to
// communicate the post-discovery true task count back to the handler.
// The handler intercepts messages starting with this prefix and translates
// them into db.UpdateScanProgressFull, then suppresses the message from
// the UI. Audit fix for the full-mode "100% after first host" bar bug —
// the denominator isn't known until tcpScanAll finishes, so the scan
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
	Services []ServiceResult `json:"services"`
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

// ScanWithPorts is the explicit-port-list variant. The caller supplies
// the exact ports to probe per host (e.g. parsed from a "80,443,8000-8100"
// user input via shared.ExpandPortSpec). An empty list falls back to
// the same default as ModeCommon.
//
// This bypasses tcpScanAll entirely — we trust the operator's list, no
// pre-discovery, so a 1000-port custom list = 1000 probes per host
// (concurrency-bounded). For "do an open-port discovery first" use
// ScanWithConcurrency(..., ModeFull, ...) instead.
func ScanWithPorts(targets []string, customPorts []int, concurrency int, opts *shared.HTTPOptions, onPartial PartialFunc, progress ProgressFunc) *ScanResult {
	return scanCore(targets, ModeCommon, customPorts, concurrency, 0, 0, false, opts, onPartial, progress)
}

// scanCore is the shared body. When customPorts is non-empty it
// overrides both ModeCommon (CommonPorts) and ModeFull (tcp discovery);
// the mode argument is only consulted to choose between common and
// full when no explicit list was supplied.
func scanCore(targets []string, mode ScanMode, customPorts []int, concurrency, tcpConc, tcpRate int, directHTTP bool, opts *shared.HTTPOptions, onPartial PartialFunc, progress ProgressFunc) *ScanResult {
	result := &ScanResult{}
	var mu sync.Mutex

	if concurrency <= 0 {
		concurrency = probeConcLimit
	}
	if concurrency > 1000 {
		// Hard cap — past ~500 the FD limit + per-target rate-limit
		// pushback makes higher numbers slower, not faster.
		concurrency = 1000
	}
	// Full-mode TCP-discovery tuning (Task 0a safety). 0 = module default.
	if tcpConc <= 0 {
		tcpConc = fullScanConc
	}
	if tcpRate < 0 {
		tcpRate = 0 // negative would break the ticker; treat as unlimited
	} else if tcpRate == 0 {
		tcpRate = fullScanRate
	}

	// Build ONE shared http.Transport for the whole scan (audit perf fix).
	// Previously tryScheme allocated a fresh Transport per scheme/port/host
	// — for a ModeFull scan with thousands of open ports that meant
	// thousands of TLS session caches + idle conn pools allocated and
	// leaked for the scan's lifetime. opts.ApplyTransport registers the
	// transport so ScanManager.Cancel can flush its idle pool.
	sharedTransport := &http.Transport{
		TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
		// audit K05/K06: shared.BoundDialer enforces L2 source-IP pinning
		// even when opts is nil (falls back to SetGlobalLocalAddr).
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

	// Full mode is a different shape from the fixed-port modes: an
	// interleaved, per-host-randomized sweep of all 65535 ports (round-robin
	// across hosts, random port order per host — IDS/firewall-evasion), with
	// its own two-phase (or single-phase, when directHTTP) progress model.
	// It owns its whole run and returns here.
	if mode == ModeFull && len(customPorts) == 0 {
		return runFullMode(result, &mu, targets, directHTTP, tcpConc, tcpRate, concurrency, sharedClient, opts, onPartial, progress)
	}

	type probeTask struct {
		host string
		port int
	}

	var tasks []probeTask

	switch {
	case len(customPorts) > 0:
		for _, host := range targets {
			for _, p := range customPorts {
				tasks = append(tasks, probeTask{host: host, port: p})
			}
		}
	default:
		for _, host := range targets {
			for _, p := range CommonPorts {
				tasks = append(tasks, probeTask{host: host, port: p})
			}
		}
	}

	total := len(tasks)
	done := 0
	probeBase := 0
	sem := make(chan struct{}, concurrency)
	var wg sync.WaitGroup

	for _, t := range tasks {
		if opts.Done() {
			break
		}
		wg.Add(1)
		sem <- struct{}{}
		go func(host string, port int) {
			defer wg.Done()
			defer func() { <-sem }()

			if opts.Done() {
				return
			}

			svc := probeHTTP(host, port, sharedClient, opts)

			// Snapshot state under the lock, then call progress() OUTSIDE
			// the lock (audit perf fix). progress() funnels into a
			// synchronous SQLite UPDATE; holding mu across that DB write
			// serialized every probe completion through DB latency.
			mu.Lock()
			done++
			added := false
			if svc != nil {
				result.Services = append(result.Services, *svc)
				added = true
			}
			doneSnap := done
			var snap *ScanResult
			if added && onPartial != nil {
				snap = &ScanResult{Services: append([]ServiceResult(nil), result.Services...)}
			}
			mu.Unlock()

			if progress != nil {
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
					progress(probeBase+doneSnap, fmt.Sprintf("[%d/%d] ✓ %s (%s)", doneSnap, total, svc.URL, strings.Join(extras, " · ")))
				} else {
					progress(probeBase+doneSnap, fmt.Sprintf("[%d/%d] · no HTTP on %s:%d", doneSnap, total, host, port))
				}
			}

			if snap != nil {
				onPartial(snap)
			}
		}(t.host, t.port)
	}

	wg.Wait()
	return result
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

// runFullMode executes a Full-mode sweep: an interleaved round-robin across
// hosts, each host's 65535 ports visited in a per-host-random order
// (portPermuter). Two shapes:
//
//   - connect (default): each (host,port) is a TCP connect probe; the open
//     ports are then HTTP-probed in a second phase.
//   - directHTTP: each (host,port) is an HTTP/HTTPS probe directly — no connect
//     pre-scan — so only ports that actually answer HTTP are recorded, and a
//     firewall that accepts/tarpits every connect can't inflate the result.
//
// Progress (Task 1 — the HTTP-probe phase is now visible in the %):
//   - directHTTP: single phase, denominator = hosts×65535, done = ports probed.
//   - connect: phase 1 (the connect sweep) fills ~86% of the bar; the last ~14%
//     is reserved for phase 2 (HTTP-probing the discovered open ports) so that
//     phase is a visible band instead of a sub-1% sliver stuck at 100%.
func runFullMode(result *ScanResult, mu *sync.Mutex, targets []string, directHTTP bool,
	tcpConc, tcpRate, probeConc int, sharedClient *http.Client, opts *shared.HTTPOptions,
	onPartial PartialFunc, progress ProgressFunc) *ScanResult {

	const maxPort = 65535
	discTotal := len(targets) * maxPort // phase-1 units: one per port probed

	conc := tcpConc
	if conc <= 0 {
		conc = fullScanConc
	}
	rate := tcpRate
	if rate < 0 {
		rate = 0 // unlimited
	} else if rate == 0 {
		rate = fullScanRate
	}

	// Reserve the bar's tail for phase 2 (connect mode only) so HTTP-probing
	// the open ports actually moves the %. The denominator is bumped up front
	// so the bar never jumps backwards when phase 2 begins.
	reserve := 0
	if !directHTTP {
		reserve = discTotal / 6 // ~14% of the bar
		if reserve < 1 {
			reserve = 1
		}
		if progress != nil {
			progress(0, fmt.Sprintf("%s%d", TotalUpdatePrefix, discTotal+reserve))
			progress(0, fmt.Sprintf("Full scan: %d host(s) × 65535 ports, randomized order", len(targets)))
		}
	} else if progress != nil {
		progress(0, fmt.Sprintf("Full scan (direct HTTP/HTTPS): %d host(s) × 65535 ports, randomized order", len(targets)))
	}

	perms := make([]*portPermuter, len(targets))
	for i := range targets {
		perms[i] = newPortPermuter()
	}

	// Token-bucket rate limiter on NEW connections/sec, shared across hosts.
	var tokens chan struct{}
	rlDone := make(chan struct{})
	if rate > 0 {
		const tickHz = 20
		per := rate / tickHz
		if per < 1 {
			per = 1
		}
		depth := rate
		if depth < per {
			depth = per
		}
		tokens = make(chan struct{}, depth)
		go func() {
			ticker := time.NewTicker(time.Second / tickHz)
			defer ticker.Stop()
			for {
				select {
				case <-rlDone:
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
	}

	sem := make(chan struct{}, conc)
	var wg sync.WaitGroup
	var scanned int32
	var found int32
	var openMu sync.Mutex
	type openHP struct {
		host string
		port int
	}
	var open []openHP

	// Heartbeat: report the phase-1 climb (done = ports probed so far) every
	// 2s so the bar advances without a DB write per port.
	hbDone := make(chan struct{})
	if progress != nil {
		go func() {
			ticker := time.NewTicker(2 * time.Second)
			defer ticker.Stop()
			for {
				select {
				case <-hbDone:
					return
				case <-ticker.C:
					s := atomic.LoadInt32(&scanned)
					if directHTTP {
						progress(int(s), fmt.Sprintf("Direct HTTP sweep — %d/%d probed, %d live", s, discTotal, atomic.LoadInt32(&found)))
					} else {
						progress(int(s), fmt.Sprintf("Port sweep — %d/%d probed, %d open", s, discTotal, atomic.LoadInt32(&found)))
					}
				}
			}
		}()
	}

	// Round-robin dispatch: each round emits one (random) port per still-live
	// host, so in-flight probes hit different hosts on scattered ports.
	for round := 0; round < maxPort; round++ {
		if opts.Done() {
			break
		}
		for hi, host := range targets {
			if opts.Done() {
				break
			}
			port, ok := perms[hi].next()
			if !ok {
				continue
			}
			if tokens != nil {
				<-tokens
			}
			wg.Add(1)
			sem <- struct{}{}
			go func(host string, port int) {
				defer wg.Done()
				defer func() { <-sem }()
				defer atomic.AddInt32(&scanned, 1)
				if opts.Done() {
					return
				}
				if directHTTP {
					svc := probeHTTP(host, port, sharedClient, opts)
					if svc == nil {
						return
					}
					atomic.AddInt32(&found, 1)
					mu.Lock()
					result.Services = append(result.Services, *svc)
					var snap *ScanResult
					if onPartial != nil {
						snap = &ScanResult{Services: append([]ServiceResult(nil), result.Services...)}
					}
					mu.Unlock()
					if progress != nil {
						progress(int(atomic.LoadInt32(&scanned)), fmt.Sprintf("✓ %s (HTTP %d)", svc.URL, svc.StatusCode))
					}
					if snap != nil {
						onPartial(snap)
					}
					return
				}
				// connect probe — killswitch-bound dialer so L2 source-IP
				// pinning applies to the port-sweep traffic too.
				conn, err := shared.BoundDialer(nil, tcpTimeout).Dial("tcp", net.JoinHostPort(host, strconv.Itoa(port)))
				if err != nil {
					return
				}
				conn.Close()
				atomic.AddInt32(&found, 1)
				openMu.Lock()
				open = append(open, openHP{host, port})
				openMu.Unlock()
			}(host, port)
		}
	}
	wg.Wait()
	close(hbDone)
	close(rlDone)

	if directHTTP {
		if progress != nil {
			progress(discTotal, fmt.Sprintf("Direct HTTP sweep done — %d live service(s)", atomic.LoadInt32(&found)))
		}
		return result
	}

	// ---- Phase 2 (connect mode): HTTP-probe the discovered open ports. ----
	p := len(open)
	if p == 0 {
		if progress != nil {
			progress(discTotal+reserve, "Port sweep done — 0 open ports")
		}
		return result
	}
	if progress != nil {
		progress(discTotal, fmt.Sprintf("%d open port(s) — probing for HTTP services", p))
	}
	pc := probeConc
	if pc <= 0 {
		pc = probeConcLimit
	}
	psem := make(chan struct{}, pc)
	var pwg sync.WaitGroup
	var pdone int32
	for _, hp := range open {
		if opts.Done() {
			break
		}
		pwg.Add(1)
		psem <- struct{}{}
		go func(host string, port int) {
			defer pwg.Done()
			defer func() { <-psem }()
			svc := probeHTTP(host, port, sharedClient, opts)
			d := atomic.AddInt32(&pdone, 1)
			mu.Lock()
			var snap *ScanResult
			if svc != nil {
				result.Services = append(result.Services, *svc)
				if onPartial != nil {
					snap = &ScanResult{Services: append([]ServiceResult(nil), result.Services...)}
				}
			}
			mu.Unlock()
			if progress != nil {
				// Map the p probes into the reserved [discTotal, discTotal+reserve] band.
				done := discTotal + int(int64(d)*int64(reserve)/int64(p))
				if svc != nil {
					progress(done, fmt.Sprintf("✓ %s (HTTP %d)", svc.URL, svc.StatusCode))
				} else {
					progress(done, fmt.Sprintf("· no HTTP on %s:%d", host, port))
				}
			}
			if snap != nil {
				onPartial(snap)
			}
		}(hp.host, hp.port)
	}
	pwg.Wait()
	if progress != nil {
		progress(discTotal+reserve, fmt.Sprintf("Full scan done — %d live HTTP service(s)", len(result.Services)))
	}
	return result
}

// probeHTTP tries HTTPS then HTTP on a host:port, returns nil if no HTTP service.
// Audit bug fix: records AT MOST one error per (host,port) — previously each
// scheme failure called opts.RecordError separately, so a single dead port
// consumed two slots of the per-scan ErrorThreshold and tripped the abort
// logic twice as fast as intended (with the default threshold of 3, two
// dead ports could abort the entire scan).
func probeHTTP(host string, port int, client *http.Client, opts *shared.HTTPOptions) *ServiceResult {
	// Try HTTPS first for 443-like ports, HTTP first for 80-like ports
	schemes := []string{"https", "http"}
	if port == 80 || port == 8080 {
		schemes = []string{"http", "https"}
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

	rawReq := shared.CaptureRequest(req)

	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

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
