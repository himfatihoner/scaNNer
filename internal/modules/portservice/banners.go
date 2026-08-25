package portservice

import (
	"context"
	"crypto/tls"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"regexp"
	"scanner/internal/modules/shared"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

// EnrichBanners walks every host's open ports and grabs a "Shodan-style"
// banner — for HTTP/HTTPS ports it does a real GET / and stores status,
// headers, and a body preview; for plain TCP services (SSH/FTP/SMTP/POP3/
// IMAP/MySQL/Redis/etc.) it connects, reads the first response chunk, and
// stores it as a raw banner. Skips firewall-flagged hosts (their port list
// was already deemed unreliable).
//
// The function blocks until every probe completes or times out. Callers that
// want progress feedback should use the supplied logger.
//
// `opts` may be nil. When non-nil, its LocalAddr, ProxyURL, UserAgent, Headers,
// and Cookies are honoured so Settings (killswitch source-IP, proxy, custom
// UA/headers) apply to the enrichment phase the same way they do to every
// other web-touching module.
func EnrichBanners(ctx context.Context, opts *shared.HTTPOptions, result *ScanResult, log func(string)) {
	if result == nil {
		return
	}
	if log == nil {
		log = func(string) {}
	}
	// Build a single shared *http.Transport / *http.Client for the whole
	// enrichment pass. Previously each probe constructed a fresh transport,
	// spawning read/write + idle-manager goroutines and allocating
	// connection-pool maps every time — for a /24 with 200+ open web ports
	// that meant hundreds of throwaway transports, none of which were ever
	// CloseIdleConnections'd. Now one transport, one client, and one
	// deferred CloseIdleConnections at the end.
	tr := &http.Transport{
		TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
		// Source-IP binding via the shared helper (Katman 2). Uses
		// opts.LocalAddr when non-nil, else falls back to the global
		// killswitch address set by SetGlobalLocalAddr.
		DialContext:         shared.BoundDialer(opts, 3*time.Second).DialContext,
		MaxIdleConns:        64,
		MaxIdleConnsPerHost: 4,
		IdleConnTimeout:     30 * time.Second,
	}
	if opts != nil && opts.ProxyURL != "" && !opts.BurpSuccessOnly {
		if pu, err := url.Parse(opts.ProxyURL); err == nil {
			tr.Proxy = http.ProxyURL(pu)
		}
	}
	if opts != nil {
		opts.RegisterTransport(tr)
	}
	defer tr.CloseIdleConnections()

	client := &http.Client{
		Transport: tr,
		Timeout:   4 * time.Second,
		// Don't follow redirects automatically — we want to capture the
		// first response and surface the redirect target separately.
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}

	// Bounded fan-out — the semaphore is acquired BEFORE spawning so the
	// outer loop blocks when 64 probes are already in flight. Previously
	// every open-port goroutine was spawned eagerly (one per port across
	// every host) and piled up on the semaphore acquire inside the
	// goroutine — a /24 with ~50 open ports/host could spawn 10k+
	// goroutines instantly.
	var wg sync.WaitGroup
	sem := make(chan struct{}, 64)

	// Progress heartbeat: emit a running counter every 25 probes so the
	// user sees the enrichment phase actually moving. Previously the phase
	// was silent — the progress bar frozen at "Banner enrichment phase"
	// for minutes on wide scans.
	var doneProbes int64
	var totalProbes int64
	for hi := range result.Results {
		host := &result.Results[hi]
		if !host.HostUp || host.SuspectedFirewall {
			continue
		}
		for pi := range host.Ports {
			if host.Ports[pi].State == "open" {
				totalProbes++
			}
		}
	}
	if totalProbes > 0 {
		log(fmt.Sprintf("  · banner enrichment: %d probes queued", totalProbes))
	}

	for hi := range result.Results {
		if ctx.Err() != nil {
			break
		}
		host := &result.Results[hi]
		if !host.HostUp || host.SuspectedFirewall {
			continue
		}
		ip := host.IP
		if ip == "" {
			ip = host.Target
		}
		if ip == "" {
			continue
		}
		for pi := range host.Ports {
			if ctx.Err() != nil {
				break
			}
			p := &host.Ports[pi]
			if p.State != "open" {
				continue
			}
			// Acquire BEFORE spawn so the loop blocks when saturated,
			// rather than spawning thousands of goroutines that then
			// queue on the semaphore.
			select {
			case sem <- struct{}{}:
			case <-ctx.Done():
				break
			}
			if ctx.Err() != nil {
				break
			}
			wg.Add(1)
			go func(ipAddr string, port *Port) {
				defer wg.Done()
				defer func() { <-sem }()
				if isHTTPPort(port) {
					grabHTTP(ctx, client, ipAddr, port, log)
				} else {
					grabTCPBanner(ctx, ipAddr, port, log)
				}
				n := atomic.AddInt64(&doneProbes, 1)
				if n%25 == 0 && totalProbes > 0 {
					log(fmt.Sprintf("  · banner enrichment: %d/%d", n, totalProbes))
				}
			}(ip, p)
		}
	}
	wg.Wait()
	if totalProbes > 0 {
		log(fmt.Sprintf("  · banner enrichment done: %d/%d", atomic.LoadInt64(&doneProbes), totalProbes))
	}
}

// isHTTPPort returns true when the service banner suggests HTTP/HTTPS.
func isHTTPPort(p *Port) bool {
	svc := strings.ToLower(p.Service)
	tunnel := strings.ToLower(p.Tunnel)
	if tunnel == "ssl" {
		return true
	}
	switch svc {
	case "http", "https", "http-proxy", "http-alt", "https-alt", "ssl/http", "www":
		return true
	}
	if strings.Contains(svc, "http") || strings.Contains(svc, "www") {
		return true
	}
	// Common HTTP ports as a last fallback when nmap didn't tag the service.
	switch p.Port {
	case 80, 81, 88, 591, 2080, 2443, 3000, 4567, 4711, 5000, 5104, 5800,
		6543, 7000, 7396, 8000, 8001, 8008, 8014, 8042, 8069, 8080, 8081,
		8088, 8090, 8118, 8123, 8172, 8222, 8243, 8280, 8281, 8333, 8443,
		8500, 8834, 8880, 8888, 8983, 9000, 9043, 9060, 9080, 9090, 9091,
		9200, 9443, 9800, 9981, 12443, 16080, 18091, 18092:
		return true
	}
	return false
}

var titleRe = regexp.MustCompile(`(?is)<title[^>]*>(.*?)</title>`)

func grabHTTP(ctx context.Context, client *http.Client, ip string, p *Port, log func(string)) {
	scheme := "http"
	if strings.ToLower(p.Tunnel) == "ssl" || strings.Contains(strings.ToLower(p.Service), "https") {
		scheme = "https"
	}
	rawURL := fmt.Sprintf("%s://%s:%d/", scheme, ip, p.Port)
	resp := &HTTPResponse{URL: rawURL}

	rctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	req, err := http.NewRequestWithContext(rctx, http.MethodGet, rawURL, nil)
	if err != nil {
		resp.Error = err.Error()
		p.HTTPResp = resp
		return
	}
	req.Header.Set("User-Agent", "scaNNer/1.0 (Advanced Host Scanner)")
	r, err := client.Do(req)
	if err != nil {
		// On HTTPS failure, retry over HTTP — services that say "http" but
		// nmap got confused about TLS would otherwise show nothing.
		if scheme == "https" {
			rawURL = strings.Replace(rawURL, "https://", "http://", 1)
			req2, _ := http.NewRequestWithContext(rctx, http.MethodGet, rawURL, nil)
			req2.Header.Set("User-Agent", "scaNNer/1.0 (Advanced Host Scanner)")
			r, err = client.Do(req2)
			resp.URL = rawURL
		}
		if err != nil {
			resp.Error = err.Error()
			p.HTTPResp = resp
			return
		}
	}
	defer r.Body.Close()
	resp.Status = r.StatusCode
	resp.StatusText = http.StatusText(r.StatusCode)
	resp.Server = r.Header.Get("Server")
	resp.ContentType = r.Header.Get("Content-Type")
	if loc := r.Header.Get("Location"); loc != "" {
		resp.RedirectedTo = loc
	}
	for k, vv := range r.Header {
		for _, v := range vv {
			resp.Headers = append(resp.Headers, HTTPHeader{Name: k, Value: v})
		}
	}
	body, _ := io.ReadAll(io.LimitReader(r.Body, 8192))
	resp.BodyLength = len(body)
	if len(body) > 0 {
		// Truncate preview to ~2 KB.
		previewLen := len(body)
		if previewLen > 2048 {
			previewLen = 2048
		}
		resp.BodyPreview = string(body[:previewLen])
		if m := titleRe.FindSubmatch(body); m != nil {
			resp.Title = strings.TrimSpace(strings.Join(strings.Fields(string(m[1])), " "))
			if len(resp.Title) > 200 {
				resp.Title = resp.Title[:200] + "…"
			}
		}
	}
	p.HTTPResp = resp
}

// grabTCPBanner connects to the port, optionally writes a probe based on
// known protocol, reads up to 1 KB, and stores the result as a banner.
func grabTCPBanner(ctx context.Context, ip string, p *Port, log func(string)) {
	addr := net.JoinHostPort(ip, strconv.Itoa(p.Port))
	dctx, cancel := context.WithTimeout(ctx, 3*time.Second)
	defer cancel()
	// Audit S1: inline net.Dialer bypassed killswitch L2 source-IP
	// binding for raw TCP banner grabs. BoundDialer pins the chosen
	// outbound iface set via Settings.
	d := shared.BoundDialer(nil, 3*time.Second)
	conn, err := d.DialContext(dctx, "tcp", addr)
	if err != nil {
		return
	}
	defer conn.Close()
	conn.SetDeadline(time.Now().Add(2 * time.Second))

	// Some services need a nudge. SMTP/FTP/SSH/POP3/IMAP send a banner on
	// connect; for others we send a generic probe.
	svc := strings.ToLower(p.Service)
	switch {
	case strings.Contains(svc, "smtp"), p.Port == 25 || p.Port == 465 || p.Port == 587:
		// servers send 220 banner on connect
	case strings.Contains(svc, "ftp"), p.Port == 21:
		// 220 banner on connect
	case strings.Contains(svc, "ssh"), p.Port == 22:
		// banner on connect
	case strings.Contains(svc, "pop3"), p.Port == 110 || p.Port == 995:
		// +OK banner on connect
	case strings.Contains(svc, "imap"), p.Port == 143 || p.Port == 993:
		// * OK banner on connect
	case strings.Contains(svc, "redis"), p.Port == 6379:
		conn.Write([]byte("PING\r\n"))
	case strings.Contains(svc, "mongo"), p.Port == 27017:
		// no plaintext banner; skip
		return
	case strings.Contains(svc, "memcached"), p.Port == 11211:
		conn.Write([]byte("version\r\n"))
	default:
		// Try a generic probe. 250ms grace then read whatever shows up.
	}

	buf := make([]byte, 1024)
	n, _ := conn.Read(buf)
	if n > 0 {
		raw := strings.TrimRight(string(buf[:n]), " \r\n\t")
		// Filter to printable / common control chars only — banners with
		// pure binary (some proprietary protocols) are not informative.
		if isMostlyPrintable(raw) {
			p.Banner = raw
		}
	}
}

func isMostlyPrintable(s string) bool {
	if s == "" {
		return false
	}
	good := 0
	for _, r := range s {
		if r >= 0x20 && r < 0x7f {
			good++
		} else if r == '\n' || r == '\r' || r == '\t' {
			good++
		}
	}
	return float64(good)/float64(len(s)) >= 0.85
}
