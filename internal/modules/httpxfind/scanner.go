package httpxfind

import (
	"crypto/tls"
	"fmt"
	"io"
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
	return scanCore(targets, mode, nil, concurrency, 0, 0, opts, onPartial, progress)
}

// ScanFull runs Full-mode discovery with explicit TCP-scan tuning (Task 6
// per-module override). tcpConc = concurrent connect()s during discovery
// (0 = default 150); tcpRate = max NEW connections/sec (0 = default 500,
// negative = unlimited). probeConc = HTTP-probe concurrency (0 = default).
func ScanFull(targets []string, probeConc, tcpConc, tcpRate int, opts *shared.HTTPOptions, onPartial PartialFunc, progress ProgressFunc) *ScanResult {
	return scanCore(targets, ModeFull, nil, probeConc, tcpConc, tcpRate, opts, onPartial, progress)
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
	return scanCore(targets, ModeCommon, customPorts, concurrency, 0, 0, opts, onPartial, progress)
}

// scanCore is the shared body. When customPorts is non-empty it
// overrides both ModeCommon (CommonPorts) and ModeFull (tcp discovery);
// the mode argument is only consulted to choose between common and
// full when no explicit list was supplied.
func scanCore(targets []string, mode ScanMode, customPorts []int, concurrency, tcpConc, tcpRate int, opts *shared.HTTPOptions, onPartial PartialFunc, progress ProgressFunc) *ScanResult {
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
	case mode == ModeFull:
		// Phase 1: fast TCP scan to find open ports. Progress is reported in
		// GLOBAL port units — the handler now creates the scan with
		// total = len(targets) × 65535 (the dominant work), so done climbs
		// smoothly across all hosts instead of sitting at an indeterminate
		// spinner for the whole (slow) discovery phase (Task 1).
		for i, host := range targets {
			if opts.Done() {
				return result
			}
			doneBase := i * 65535 // ports fully scanned on earlier hosts
			if progress != nil {
				progress(doneBase, fmt.Sprintf("Port scanning %s (1-65535)", host))
			}
			openPorts := tcpScanAll(host, tcpConc, tcpRate, doneBase, opts, progress)
			for _, p := range openPorts {
				tasks = append(tasks, probeTask{host: host, port: p})
			}
		}
		if progress != nil {
			// Discovery done. The HTTP-probe phase (Phase 2) is a small tail;
			// bump the denominator to (discovery total + probe tasks) so the
			// bar reserves the last sliver for probing instead of already
			// reading 100%. Sentinel carries the FINAL total; the handler maps
			// it to db.UpdateScanProgressFull(scanID, discBase, finalTotal).
			discBase := len(targets) * 65535
			progress(discBase, fmt.Sprintf("%s%d", TotalUpdatePrefix, discBase+len(tasks)))
			progress(discBase, fmt.Sprintf("Found %d open ports, probing for HTTP services", len(tasks)))
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
	// In Full mode the bar's denominator already counts the 65535-port
	// discovery sweep per host; the HTTP-probe phase continues past that
	// base so the bar doesn't restart at 0 (Task 1).
	probeBase := 0
	if mode == ModeFull && len(customPorts) == 0 {
		probeBase = len(targets) * 65535
	}
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

// tcpScanAll does a fast TCP connect scan on all 65535 ports.
// progress (optional) gets heartbeat callbacks roughly every 2 seconds so
// the UI doesn't sit on the same "Port scanning host (1-65535)" line for
// minutes — see audit MEDIUM "Full-mode TCP scan emits no per-port
// progress". Heartbeat messages are NOT prefixed with "$ " so they don't
// pollute the scan's commands column.
func tcpScanAll(host string, conc, rate, doneBase int, opts *shared.HTTPOptions, progress ProgressFunc) []int {
	var openPorts []int
	var mu sync.Mutex
	if conc <= 0 {
		conc = fullScanConc
	}
	sem := make(chan struct{}, conc)
	var wg sync.WaitGroup

	// Rate limiter: cap NEW connect attempts to `rate`/sec (0 = unlimited).
	// This is the primary safety valve — the concurrency bound alone doesn't
	// stop fast-RST/refused ports from letting the loop spin at tens of
	// thousands of new flows/sec, which is what fills a home router's
	// conntrack table and drops the operator's own traffic (Task 0a).
	//
	// Batched token bucket: a per-second ticker resolution (~1ms) can't honour
	// rates above ~1000/s, so instead refill `rate/tickHz` tokens on a coarse
	// tick — any requested rate is met accurately. Bucket depth = 1s burst.
	var tokens chan struct{}
	rlDone := make(chan struct{})
	if rate > 0 {
		const tickHz = 20 // 50ms ticks — well above timer resolution
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
						default: // bucket full — drop
						}
					}
				}
			}
		}()
	}
	defer close(rlDone)

	var scanned int32 // atomic — heartbeat reader counts probes regardless of result
	var openCount int32

	// Heartbeat ticker — surfaces progress every 2s so the UI knows the
	// scan is alive. Reports done in GLOBAL port units (doneBase + scanned)
	// so the % bar advances smoothly across hosts (Task 1). Stopped via
	// hbDone after wg.Wait returns.
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
					o := atomic.LoadInt32(&openCount)
					progress(doneBase+int(s), fmt.Sprintf("TCP scan %s — %d/65535 probed, %d open", host, s, o))
				}
			}
		}()
	}

	for port := 1; port <= 65535; port++ {
		if opts.Done() {
			break
		}
		if tokens != nil {
			<-tokens // pace new-connection dispatch
		}
		wg.Add(1)
		sem <- struct{}{}
		go func(p int) {
			defer wg.Done()
			defer func() { <-sem }()
			defer atomic.AddInt32(&scanned, 1)
			if opts.Done() {
				return
			}
			// JoinHostPort handles IPv6 bracketing — plain Sprintf builds
			// "2001:db8:::443" which Dial cannot parse.
			addr := net.JoinHostPort(host, strconv.Itoa(p))
			// Use the shared bounded dialer so the killswitch's source-IP
			// binding applies to TCP port-probe traffic too. nil opts =
			// global fallback (set by handler.BuildHTTPOptions).
			conn, err := shared.BoundDialer(nil, tcpTimeout).Dial("tcp", addr)
			if err != nil {
				return
			}
			// Defer the Close so a panic between Dial and the mu.Lock
			// section can't leak the half-open socket (audit B55).
			// 65535-port full-mode scans run thousands of these per host;
			// a single unclosed conn per panic over 2 days starves FDs.
			defer conn.Close()
			atomic.AddInt32(&openCount, 1)
			mu.Lock()
			openPorts = append(openPorts, p)
			mu.Unlock()
		}(port)
	}
	wg.Wait()
	close(hbDone)
	// Register this host's completion immediately (don't wait for the next
	// host's "Port scanning" line) so the bar reflects the finished sweep.
	if progress != nil {
		progress(doneBase+int(atomic.LoadInt32(&scanned)), fmt.Sprintf("TCP scan %s done — %d open", host, atomic.LoadInt32(&openCount)))
	}
	return openPorts
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
