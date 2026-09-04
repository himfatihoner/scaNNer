package techdetect

import (
	"context"
	"crypto/tls"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os/exec"
	"regexp"
	"runtime"
	"scanner/internal/modules/shared"
	"sort"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

// Technology is a single detected tech
type Technology struct {
	Name     string       `json:"name"`
	Category TechCategory `json:"category"`
	Version  string       `json:"version,omitempty"`
	Source   string       `json:"source"` // "fingerprint", "whatweb", "header"
	// Evidence is the specific signal that triggered detection — surfaced
	// in the UI when the user clicks a chip so they can verify it's not a
	// false positive. Examples:
	//   "header:Server matched value 'Apache/2.4.49 (Debian)'"
	//   "body matched substring '/wp-content/'"
	//   "meta name=generator matched 'WordPress 6.4'"
	//   "cookie 'frontend' present"
	Evidence string `json:"evidence,omitempty"`
}

// TargetResult holds all tech for one URL
type TargetResult struct {
	URL          string       `json:"url"`
	StatusCode   int          `json:"status_code"`
	Title        string       `json:"title"`
	Server       string       `json:"server"`
	Technologies []Technology `json:"technologies"`
	Headers      string       `json:"headers"`
	// FaviconMMH3 is the MurmurHash3 hash of the target's /favicon.ico
	// (when reachable). Mirrors Shodan's `http.favicon.hash` field —
	// a high-signal pivot for finding lookalike infrastructure: paste
	// the hash into Shodan or Censys to enumerate every other host
	// serving the same icon (often the same SaaS/CMS deployment).
	FaviconMMH3 int32  `json:"favicon_mmh3,omitempty"`
	FaviconURL  string `json:"favicon_url,omitempty"`
	Error       string `json:"error,omitempty"`
	// Raw HTTP capture of the main page fetch (request + response). Lets
	// the pentester copy the bytes directly into Burp Repeater.
	RawRequest  string `json:"raw_request,omitempty"`
	RawResponse string `json:"raw_response,omitempty"`
}

type ScanResult struct {
	Results []TargetResult `json:"results"`
	// Warnings carries NON-FATAL tool-degradation notes surfaced to the user
	// as an amber banner on the results page. It exists so a missing / broken
	// whatweb (this module's only subprocess engine) is never silently swallowed:
	// the Go-side fingerprints may still have found techs — so this must NOT be
	// a fatal Error — but the user still needs to see that whatweb didn't run.
	// Deduped; only populated on a missing binary or a non-zero exit that
	// produced no output (never on a clean "whatweb ran, found nothing").
	Warnings []string `json:"warnings,omitempty"`
}

type ProgressFunc func(done int, msg string)
type PartialFunc func(*ScanResult)

// Config carries the launch-form knobs beyond the URL list. Aggressive
// gates whatweb's `-a 3` mode (extra probes, POSTs to plugin paths,
// trips WAFs) vs the safer default `-a 1` (passive GETs only).
type Config struct {
	URLs        []string
	Aggressive  bool
	Concurrency int // per-target parallelism; 0 = default (20). Driven by capacity.Recommend.
	// LightCapture CAPS the per-URL raw request/response bytes (the Burp-Repeater
	// capture) to a few KB on each TargetResult. Bulk callers (advancedweb suite
	// over 1000s of hosts) set it so the stored result doesn't balloon to hundreds
	// of MB — a full raw response is up to 256 KB, so 1600 live hosts alone is
	// ~400 MB. The capped dump is still enough to give a CVE finding (matched off a
	// detected technology) a real request+response PoC. Standalone runs keep the
	// full dump.
	LightCapture bool
}

func Scan(urls []string, opts *shared.HTTPOptions, progress ProgressFunc) *ScanResult {
	return ScanWithConfig(Config{URLs: urls}, opts, progress, nil)
}

// ScanWithPartial is the throttled-snapshot entry point added by the
// audit fix — long techdetect scans (50+ URLs) used to show an empty
// results page until the final flush. Now the handler can wire a 2s
// partial that streams completed targets to the DB as they finish.
func ScanWithPartial(urls []string, opts *shared.HTTPOptions, progress ProgressFunc, partial PartialFunc) *ScanResult {
	return ScanWithConfig(Config{URLs: urls}, opts, progress, partial)
}

// ScanWithConfig is the underlying entry point; the older Scan /
// ScanWithPartial wrappers exist for the advancedweb caller that
// doesn't need per-scan launch knobs.
func ScanWithConfig(cfg Config, opts *shared.HTTPOptions, progress ProgressFunc, partial PartialFunc) *ScanResult {
	urls := cfg.URLs
	result := &ScanResult{}
	var mu sync.Mutex
	// Concurrency: per-target work is one GET (15s budget) + body parse, and
	// (aggressive) a whatweb=ruby subprocess — CPU/process-heavy. Driven by
	// capacity.Recommend("techdetect") from the caller (CPU-bound: ~0.4 core
	// per unit), falling back to 20 for the advancedweb caller that passes 0.
	conc := cfg.Concurrency
	if conc <= 0 {
		conc = 20
	}
	sem := make(chan struct{}, conc)
	var wg sync.WaitGroup
	done := 0
	// Dedup set for non-fatal whatweb warnings (guarded by mu) — a missing
	// binary otherwise repeats identically for every target.
	warnSeen := map[string]bool{}

	// Audit fix: per-target snapshot was missing entirely; long scans
	// blanked the UI mid-run. Throttle to 2s; final force-flush below
	// guarantees the terminal result lands.
	throttle := shared.NewPartialThrottler(2 * time.Second)
	pushPartial := func() {
		if partial == nil {
			return
		}
		if !throttle.ShouldFire() {
			return
		}
		mu.Lock()
		snap := &ScanResult{Results: append([]TargetResult(nil), result.Results...), Warnings: append([]string(nil), result.Warnings...)}
		mu.Unlock()
		partial(snap)
	}

	// Reachability preflight: skip TLS-dead targets up front.
	if opts != nil && opts.PreflightEnabled {
		live, dead := shared.FilterReachable(opts.Ctx, opts, urls, opts.PreflightTimeout, 0)
		for t, reason := range dead {
			result.Results = append(result.Results, TargetResult{URL: t, Error: "unreachable — " + reason})
		}
		urls = live
	}

	for _, u := range urls {
		// Cancellation fast-path (audit B42).
		if opts != nil && opts.Done() {
			break
		}
		wg.Add(1)
		sem <- struct{}{}
		go func(target string) {
			defer wg.Done()
			defer func() { <-sem }()
			// Per-target panic isolation — a malformed input or a
			// transient nil-deref in one analyzer must not crash the
			// whole scanner process.
			defer func() {
				if rec := recover(); rec != nil {
					mu.Lock()
					result.Results = append(result.Results, TargetResult{
						URL:   target,
						Error: fmt.Sprintf("panic: %v", rec),
					})
					mu.Unlock()
				}
			}()

			// Audit fix: the initial "Analyzing" progress ping doesn't
			// touch `result` so it doesn't need mu. Snapshot `done`
			// under mu, release, then invoke progress — otherwise all
			// workers serialize on the SQLite UPDATE inside progress().
			mu.Lock()
			curDone := done
			mu.Unlock()
			if progress != nil {
				progress(curDone, fmt.Sprintf("Analyzing %s ...", target))
			}

			// Console crumb sink: emit "$ <command>" lines at the current
			// done count so the live console + "Commands run" panel show the
			// exact whatweb invocation this target triggered.
			var logf func(string)
			if progress != nil {
				logf = func(msg string) { progress(curDone, msg) }
			}
			tr, whatwebErr := detectTech(target, opts, cfg.Aggressive, cfg.LightCapture, logf)

			// Silent-tool-degradation fix: whatweb (this module's only
			// subprocess engine) is missing or exited non-zero with no output.
			// Surface it ONCE as a non-fatal warning — deduped by friendly
			// message, capped — so a broken/absent whatweb is visible even when
			// the Go-side fingerprints still found techs for this or other hosts.
			warn := whatwebWarning(whatwebErr)

			// Same fix at the completion path — snapshot the counters
			// under mu, unlock, then call progress(). progress() is a
			// SQLite UPDATE; holding mu across it effectively
			// serialized the sem=20 workers on the DB write.
			mu.Lock()
			done++
			result.Results = append(result.Results, *tr)
			if warn != "" && !warnSeen[warn] && len(result.Warnings) < maxTechWarnings {
				warnSeen[warn] = true
				result.Warnings = append(result.Warnings, warn)
			}
			d, total, techCount := done, len(urls), len(tr.Technologies)
			mu.Unlock()
			if progress != nil {
				progress(d, fmt.Sprintf("[%d/%d] %s — %d technologies", d, total, target, techCount))
			}
			pushPartial()
		}(u)
	}
	wg.Wait()
	if partial != nil {
		throttle.Force()
		mu.Lock()
		snap := &ScanResult{Results: append([]TargetResult(nil), result.Results...), Warnings: append([]string(nil), result.Warnings...)}
		mu.Unlock()
		partial(snap)
	}
	return result
}

// tdLightRawCap bounds the per-URL raw dump the suite (LightCapture) stores:
// enough for a PoC (request + response headers + a body snippet) without the full
// 256 KB × thousands-of-hosts payload that blew the result cap.
const tdLightRawCap = 4 * 1024

// capTDRaw truncates a raw request/response dump to tdLightRawCap when light is
// on (bulk/suite callers); a standalone scan keeps the full dump.
func capTDRaw(s string, light bool) string {
	if !light || len(s) <= tdLightRawCap {
		return s
	}
	return s[:tdLightRawCap] + "\n... [truncated]"
}

// synthPrefetchedRequest reconstructs the HTTP request line + Host for a
// prefetched (HTTPX-fetched) URL so a CVE PoC built off it isn't empty.
func synthPrefetchedRequest(rawURL string) string {
	u, err := url.Parse(rawURL)
	if err != nil || u.Host == "" {
		return ""
	}
	path := u.RequestURI()
	if path == "" {
		path = "/"
	}
	var b strings.Builder
	b.WriteString("GET " + path + " HTTP/1.1\r\n")
	b.WriteString("Host: " + u.Host + "\r\n")
	b.WriteString("User-Agent: Mozilla/5.0 (compatible; scaNNer/httpx)\r\n")
	b.WriteString("Accept: */*\r\n\r\n")
	return b.String()
}

// synthPrefetchedResponse reconstructs the status line + headers + body HTTPX
// already captured into a raw HTTP response for the PoC evidence.
func synthPrefetchedResponse(p PrefetchedResponse) string {
	var b strings.Builder
	b.WriteString(fmt.Sprintf("HTTP/1.1 %d %s\r\n", p.StatusCode, http.StatusText(p.StatusCode)))
	for _, line := range strings.Split(strings.TrimRight(p.Headers, "\n"), "\n") {
		if line = strings.TrimRight(line, "\r"); line != "" {
			b.WriteString(line + "\r\n")
		}
	}
	b.WriteString("\r\n")
	b.WriteString(p.Body)
	return b.String()
}

// detectTech returns the per-target result plus a NON-NIL whatweb error when
// whatweb failed to run and produced nothing (missing binary / broken exit).
// That error is aggregated by the caller into ScanResult.Warnings — it is
// deliberately NOT written into tr.Error, because the Go-side fingerprints may
// still have found techs for this target and a missing whatweb must not be
// rendered as a fatal per-target failure.
func detectTech(target string, opts *shared.HTTPOptions, aggressive, lightCapture bool, logf func(string)) (*TargetResult, error) {
	tr := &TargetResult{URL: target}

	autoPrefixed := false
	if !strings.HasPrefix(target, "http://") && !strings.HasPrefix(target, "https://") {
		target = "https://" + target
		tr.URL = target
		autoPrefixed = true
	}

	// Fetch the page
	transport := &http.Transport{
		TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
		DialContext:     shared.BoundDialer(nil, 5*time.Second).DialContext,
		// This transport is built per target; bound its idle pool + self-expire
		// idle sockets so they don't accumulate across a large scan's targets.
		IdleConnTimeout:     90 * time.Second,
		MaxIdleConnsPerHost: 4,
	}
	if opts != nil {
		opts.ApplyTransport(transport)
	}
	// The page-fetch timeout honours the per-scan request-timeout override with
	// a 20s floor — the old fixed 15s was killing slow-but-alive sites and
	// mislabelling them as timeouts.
	getTimeout := 20 * time.Second
	if opts != nil && opts.Timeout > getTimeout {
		getTimeout = opts.Timeout
	}
	client := &http.Client{
		Timeout:   getTimeout,
		Transport: transport,
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			if len(via) > 3 {
				return http.ErrUseLastResponse
			}
			return nil
		},
	}

	// fetch builds + issues a GET, recording the raw request bytes.
	fetch := func(u string) (*http.Response, error) {
		req, err := http.NewRequest("GET", u, nil)
		if err != nil || req == nil {
			return nil, fmt.Errorf("invalid target URL")
		}
		req.Header.Set("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36")
		if opts != nil {
			opts.ApplyTo(req)
			req = opts.BindContext(req)
		}
		tr.RawRequest = capTDRaw(shared.CaptureRequest(req), lightCapture)
		return client.Do(req)
	}

	resp, err := fetch(target)
	// E3: if WE forced https:// on a scheme-less target and it failed, retry
	// once over http:// — http-only hosts (IoT panels, dev/internal boxes,
	// legacy appliances) otherwise report nothing.
	if err != nil && autoPrefixed {
		httpURL := "http://" + strings.TrimPrefix(target, "https://")
		if r2, e2 := fetch(httpURL); e2 == nil {
			resp, err, target, tr.URL = r2, nil, httpURL, httpURL
		}
	}

	seen := map[string]bool{}
	headerMap := map[string]string{}
	var respHeader http.Header
	var body, lowerBody string

	// E2: a failed Go GET no longer short-circuits the whole detection — whatweb
	// (below) can still fingerprint the host. We record the error and fall
	// through with resp==nil.
	if err != nil || resp == nil {
		if opts != nil {
			opts.RecordError(shared.ClassifyError(err))
		}
		if err != nil {
			tr.Error = err.Error()
		}
	} else {
		defer resp.Body.Close()
		tr.RawResponse = capTDRaw(shared.CaptureResponse(resp), lightCapture)
		if opts != nil {
			opts.ReplayHit("GET", target)
		}
		// 2 MB cap (was 512 KB). SPA shells inline a large __NEXT_DATA__/__NUXT__
		// blob and e-commerce pages are long; truncating hid tail-of-page markers.
		bodyBytes, _ := io.ReadAll(io.LimitReader(resp.Body, 2*1024*1024))
		body = string(bodyBytes)
		lowerBody = strings.ToLower(body)
		respHeader = resp.Header

		tr.StatusCode = resp.StatusCode
		tr.Server = resp.Header.Get("Server")
		tr.Title = extractTitle(body)
		tr.FaviconMMH3, tr.FaviconURL = fetchFaviconHash(target, body, client, opts)

		var hdrBuf strings.Builder
		for k, vals := range resp.Header {
			for _, v := range vals {
				hdrBuf.WriteString(k + ": " + v + "\n")
				headerMap[strings.ToLower(k)] = v
			}
		}
		tr.Headers = hdrBuf.String()
		var cookieNames []string
		for _, c := range resp.Cookies() {
			cookieNames = append(cookieNames, c.Name)
		}

		// Phase 1: Built-in fingerprinting (root page).
		for i := range Fingerprints {
			fp := &Fingerprints[i]
			if hit, ev := MatchFingerprintWithEvidence(fp, headerMap, cookieNames, body, lowerBody); hit {
				if !seen[fp.Name] {
					seen[fp.Name] = true
					tr.Technologies = append(tr.Technologies, Technology{
						Name: fp.Name, Category: fp.Category, Source: "fingerprint", Evidence: ev,
					})
				}
			}
		}

		// A3: fetch a couple of first-party JS bundles referenced in the HTML and
		// run the body fingerprints over them — SPA framework names + versions
		// (React/Vue/Next/lodash/axios/sentry) live only inside the bundle.
		scanJSBundles(tr, target, body, client, opts, seen)
	}

	// Phase 2: WhatWeb — runs even when the Go GET failed (E2).
	whatwebTechs, whatwebErr := runWhatWeb(target, opts, aggressive, logf)
	for _, wt := range whatwebTechs {
		if !seen[wt.Name] {
			seen[wt.Name] = true
			if wt.Evidence == "" {
				wt.Evidence = "whatweb plugin matched"
			}
			tr.Technologies = append(tr.Technologies, wt)
		} else {
			// Update version if whatweb found one
			if wt.Version != "" {
				for j := range tr.Technologies {
					if tr.Technologies[j].Name == wt.Name && tr.Technologies[j].Version == "" {
						tr.Technologies[j].Version = wt.Version
					}
				}
			}
		}
	}

	// Phase 3/4: header + version enrichment — only when we actually fetched a
	// response (respHeader is nil on a failed GET where only whatweb ran).
	if respHeader != nil {
		enrichFromHeaders(tr, &seen, respHeader)
		enrichVersions(tr, respHeader, body)
	}

	// Collapse same-product duplicates (case-insensitive Name), keeping the
	// versioned entry so CVE matching sees one versioned detection per product.
	tr.Technologies = dedupeTechnologies(tr.Technologies)

	// A host that got fingerprinted is demonstrably alive — clear any stale
	// Go-GET timeout/error so it isn't mislabelled as a timeout. whatweb (which
	// uses its own client, follows redirects, and tolerates slow servers) often
	// succeeds where the plain Go GET timed out; the error only matters when
	// NOTHING was detected at all.
	if len(tr.Technologies) > 0 {
		tr.Error = ""
	}

	return tr, whatwebErr
}

// scanJSBundles fetches up to 2 first-party <script src> bundles referenced in
// the root HTML and runs the body fingerprints + version enrichment over them.
// Modern SPAs ship almost all of their tech signals (framework name + version,
// bundled libs like lodash/axios/sentry) inside the JS bundle, never in the
// root HTML — so this is where most "missing" techs for a React/Vue/Next site
// actually live. Bounded: same registrable host only, ≤2 bundles, 128 KB each,
// honours cancellation. Live path only (advancedweb's prefetched path stays
// network-free).
func scanJSBundles(tr *TargetResult, target, body string, client *http.Client, opts *shared.HTTPOptions, seen map[string]bool) {
	base, err := url.Parse(target)
	if err != nil {
		return
	}
	srcs := scriptSrcRe.FindAllStringSubmatch(body, -1)
	picked := []string{}
	for _, m := range srcs {
		if len(picked) >= 2 {
			break
		}
		raw := strings.TrimSpace(m[1])
		if raw == "" || strings.HasPrefix(raw, "data:") {
			continue
		}
		u, err := url.Parse(raw)
		if err != nil {
			continue
		}
		abs := base.ResolveReference(u)
		if abs.Host != "" && abs.Host != base.Host {
			continue // first-party only
		}
		low := strings.ToLower(abs.Path)
		if !strings.HasSuffix(low, ".js") {
			continue
		}
		// Prefer app/framework bundles over vendor noise.
		if strings.Contains(low, "/_next/") || strings.Contains(low, "/assets/") ||
			strings.Contains(low, "/static/") || strings.Contains(low, "bundle") ||
			strings.Contains(low, "main") || strings.Contains(low, "app") || strings.Contains(low, "chunk") ||
			strings.Contains(low, "runtime") || strings.Contains(low, "index") {
			picked = append(picked, abs.String())
		}
	}
	for _, u := range picked {
		if opts != nil && opts.Done() {
			return
		}
		req, err := http.NewRequest("GET", u, nil)
		if err != nil {
			continue
		}
		if opts != nil {
			opts.ApplyTo(req)
			req = opts.BindContext(req)
		}
		resp, err := client.Do(req)
		if err != nil {
			continue
		}
		if resp.StatusCode < 200 || resp.StatusCode >= 300 {
			resp.Body.Close()
			continue
		}
		raw, _ := io.ReadAll(io.LimitReader(resp.Body, 128*1024))
		resp.Body.Close()
		if len(raw) == 0 {
			continue
		}
		js := string(raw)
		lowerJS := strings.ToLower(js)
		for i := range Fingerprints {
			fp := &Fingerprints[i]
			if fp.HeaderOnly || seen[fp.Name] {
				continue
			}
			if hit, ev := MatchFingerprintWithEvidence(fp, map[string]string{}, nil, js, lowerJS); hit {
				seen[fp.Name] = true
				tr.Technologies = append(tr.Technologies, Technology{
					Name: fp.Name, Category: fp.Category, Source: "js-bundle",
					Evidence: fmt.Sprintf("in bundle %s: %s", u, ev),
				})
			}
		}
		enrichVersions(tr, http.Header{}, js)
	}
}

// scriptSrcRe extracts the src value of every <script src="…"> tag.
var scriptSrcRe = regexp.MustCompile(`(?i)<script[^>]+src=["']([^"']+)["']`)

// PrefetchedResponse is a response already fetched by another module
// (typically HTTPX). Re-using it lets techdetect skip its own network
// round-trip, eliminating the WAF/CDN "second-probe RST" pattern that
// shows up as "connection reset by peer" when a target sits behind
// Cloudflare/Akamai/etc.
type PrefetchedResponse struct {
	URL        string
	StatusCode int
	Headers    string // raw "Key: Value\n..." block
	Body       string
	Server     string
}

// ScanFromPrefetched runs the same fingerprint passes as Scan but
// consumes already-fetched response bodies/headers instead of issuing
// fresh HTTP requests. WhatWeb (subprocess) is intentionally skipped
// here — its extra fetch defeats the whole point. Built-in fingerprints,
// header enrichment, and version mining are all preserved.
func ScanFromPrefetched(responses []PrefetchedResponse, opts *shared.HTTPOptions, progress ProgressFunc) *ScanResult {
	result := &ScanResult{}
	n := len(responses)
	if n == 0 {
		return result
	}

	// analyzePrefetched is pure CPU (no HTTP): it runs the full ~288-entry
	// fingerprint set — each a regex over up to 2 MB of body — per response.
	// The old serial loop pinned a SINGLE core while regex-matching thousands
	// of prefetched HTTPX services, so the whole box looked busy yet the stage
	// crawled. That was the "high CPU, no concurrency, slow" symptom — NOT a
	// depth problem (every fingerprint still runs; we just spread the work
	// across cores). Size the pool to NumCPU (CPU-bound, unlike the network-
	// bound fresh path which uses 20).
	results := make([]*TargetResult, n)
	workers := runtime.NumCPU()
	if workers < 1 {
		workers = 1
	}
	if workers > n {
		workers = n
	}
	sem := make(chan struct{}, workers)
	var wg sync.WaitGroup
	var done int64
	for i := range responses {
		// Honour scan cancellation between dispatches (a large HTTPX dump
		// would otherwise keep queueing work after Stop was clicked).
		if opts != nil && opts.Done() {
			break
		}
		wg.Add(1)
		sem <- struct{}{}
		go func(i int) {
			defer wg.Done()
			defer func() { <-sem }()
			// Per-target panic isolation — one malformed body must not take
			// down the whole prefetched sweep.
			defer func() {
				if rec := recover(); rec != nil {
					results[i] = &TargetResult{
						URL:   responses[i].URL,
						Error: fmt.Sprintf("panic: %v", rec),
					}
				}
			}()
			tr := analyzePrefetched(responses[i])
			results[i] = tr
			d := atomic.AddInt64(&done, 1)
			if progress != nil {
				progress(int(d), fmt.Sprintf("[%d/%d] %s — %d technologies",
					d, n, responses[i].URL, len(tr.Technologies)))
			}
		}(i)
	}
	wg.Wait()

	// Reassemble in input order, skipping the nil slots left by cancellation.
	for _, tr := range results {
		if tr != nil {
			result.Results = append(result.Results, *tr)
		}
	}
	return result
}

// analyzePrefetched is the body of detectTech minus the HTTP fetch.
func analyzePrefetched(p PrefetchedResponse) *TargetResult {
	tr := &TargetResult{URL: p.URL, StatusCode: p.StatusCode, Server: p.Server}

	// The prefetched path makes no HTTP call of its own — it reuses HTTPX's
	// already-captured response. Without reconstructing the raw exchange here,
	// any CVE the matcher derives from this tech detection would carry an EMPTY
	// PoC (the fresh-fetch path fills RawRequest/RawResponse; this one didn't).
	// HTTPX has the status/headers/body, so synthesise a faithful, bounded
	// request/response pair for the evidence.
	tr.RawRequest = capTDRaw(synthPrefetchedRequest(p.URL), true)
	tr.RawResponse = capTDRaw(synthPrefetchedResponse(p), true)

	// Reconstruct header map + http.Header from the raw "Key: Value\n"
	// block. Both shapes are needed: header map for fingerprint matcher,
	// http.Header for the enrichment helpers.
	headerMap := map[string]string{}
	respHeader := http.Header{}
	var hdrBuf strings.Builder
	for _, line := range strings.Split(p.Headers, "\n") {
		line = strings.TrimRight(line, "\r")
		idx := strings.Index(line, ":")
		if idx <= 0 {
			continue
		}
		k := strings.TrimSpace(line[:idx])
		v := strings.TrimSpace(line[idx+1:])
		if k == "" {
			continue
		}
		headerMap[strings.ToLower(k)] = v
		respHeader.Add(k, v)
		hdrBuf.WriteString(k + ": " + v + "\n")
	}
	tr.Headers = hdrBuf.String()
	if tr.Server == "" {
		tr.Server = respHeader.Get("Server")
	}
	tr.Title = extractTitle(p.Body)

	// Cookie names from Set-Cookie headers.
	var cookieNames []string
	for _, sc := range respHeader.Values("Set-Cookie") {
		if i := strings.Index(sc, "="); i > 0 {
			cookieNames = append(cookieNames, strings.TrimSpace(sc[:i]))
		}
	}

	seen := map[string]bool{}

	// Phase 1: Built-in fingerprinting.
	// Lowercase body once and reuse across the ~260-entry fingerprint loop
	// (each call would otherwise allocate a fresh copy of up to 512 KB).
	lowerBody := strings.ToLower(p.Body)
	for i := range Fingerprints {
		fp := &Fingerprints[i]
		if hit, ev := MatchFingerprintWithEvidence(fp, headerMap, cookieNames, p.Body, lowerBody); hit {
			if !seen[fp.Name] {
				seen[fp.Name] = true
				tr.Technologies = append(tr.Technologies, Technology{
					Name:     fp.Name,
					Category: fp.Category,
					Source:   "fingerprint",
					Evidence: ev,
				})
			}
		}
	}
	// Phase 3: header-derived techs with version parsing.
	enrichFromHeaders(tr, &seen, respHeader)
	// Phase 4: version enrichment from header / generator / cookie / body.
	enrichVersions(tr, respHeader, p.Body)
	// Collapse same-product duplicates (case-insensitive Name), keeping the
	// versioned entry so CVE matching sees one versioned detection per product.
	tr.Technologies = dedupeTechnologies(tr.Technologies)
	return tr
}

// nameVersionRe captures `Name/Version` (e.g. "nginx/1.18.0", "Apache/2.4.41 (Ubuntu)").
var nameVersionRe = regexp.MustCompile(`(?i)^([A-Za-z0-9_.+-]+)/([0-9][0-9A-Za-z.\-]*)`)

// generatorMetaRe captures the meta-generator tag. WordPress, Drupal, Joomla,
// Ghost, MediaWiki, Hugo etc. all populate it.
var generatorMetaRe = regexp.MustCompile(`(?i)<meta\s+name=["']generator["']\s+content=["']([^"']+)["']`)

// jsLibRe spots `lib-X.Y.Z[.min].js` and `lib/X.Y.Z/lib.min.js` in HTML.
var jsLibRe = regexp.MustCompile(`(?i)([a-z][a-z0-9_-]+?)[-/]([0-9]+\.[0-9]+(?:\.[0-9]+)?)(?:\.min)?\.js`)

// wpCoreVersionRes are the ONLY body signals whose ?ver=/?v= tracks the
// WordPress CORE version. Deliberately NOT a generic `wp-includes/*?ver=`
// match: WordPress enqueues bundled libraries under wp-includes/ carrying
// THEIR OWN version — e.g. wp-includes/js/jquery/jquery.min.js?ver=3.7.1 is
// jQuery 3.7.1, not WordPress 3.7.1. The old broad regex grabbed the first
// such asset and mis-reported it as core, feeding bogus WordPress core CVEs.
// Tried in order; first hit wins.
var wpCoreVersionRes = []*regexp.Regexp{
	regexp.MustCompile(`(?i)wordpress\.org/\?v=([0-9][0-9A-Za-z.\-]*)`),                                       // RSS / generator link
	regexp.MustCompile(`(?i)wp-emoji-release(?:\.min)?\.js\?ver=([0-9][0-9A-Za-z.\-]*)`),                      // core emoji loader
	regexp.MustCompile(`(?i)wp-includes/css/dist/block-library/style(?:\.min)?\.css\?ver=([0-9][0-9A-Za-z.\-]*)`), // core block-library CSS (WP 5.0+)
}

// iisServerRe pulls the version out of a "Microsoft-IIS/10.0" Server header.
// Emitting a VERSIONED IIS detection (attached to the single canonical
// "Microsoft IIS" fingerprint) lets downstream CVE matching reject
// IIS-6.0-only CVEs (e.g. CVE-2017-7269) against a modern IIS/10.0 box.
var iisServerRe = regexp.MustCompile(`(?i)^Microsoft-IIS/([0-9][0-9A-Za-z.\-]*)`)

// enrichFromHeaders parses Server, X-Powered-By, X-AspNet-Version etc. into
// Technology entries with proper versions. Each emit captures the header
// name + raw value as evidence so the UI can show the matching line.
func enrichFromHeaders(tr *TargetResult, seen *map[string]bool, h http.Header) {
	add := func(name, version, source, evidence string, cat TechCategory) {
		if name == "" {
			return
		}
		if (*seen)[name] {
			if version != "" {
				for j := range tr.Technologies {
					if tr.Technologies[j].Name == name && tr.Technologies[j].Version == "" {
						tr.Technologies[j].Version = version
					}
				}
			}
			return
		}
		(*seen)[name] = true
		tr.Technologies = append(tr.Technologies, Technology{
			Name: name, Version: version, Category: cat, Source: source, Evidence: evidence,
		})
	}

	parsePair := func(headerName, raw, source string, cat TechCategory) {
		raw = strings.TrimSpace(raw)
		if raw == "" {
			return
		}
		ev := fmt.Sprintf("header %q: %q", headerName, raw)
		for _, part := range strings.Split(raw, ",") {
			part = strings.TrimSpace(part)
			if part == "" {
				continue
			}
			if m := nameVersionRe.FindStringSubmatch(part); m != nil {
				add(m[1], m[2], source, ev, cat)
				continue
			}
			add(strings.SplitN(part, " ", 2)[0], "", source, ev, cat)
		}
	}

	// Canonicalize the Microsoft-IIS Server header onto the single
	// "Microsoft IIS" fingerprint so the parsed version (e.g. 10.0 from
	// "Microsoft-IIS/10.0") backfills onto that detection instead of spawning
	// a separate hyphenated "Microsoft-IIS" entry. The generic name/version
	// parser would otherwise emit "Microsoft-IIS" as a distinct product,
	// duplicating the IIS detection and defeating version-aware CVE matching.
	serverHdr := strings.TrimSpace(h.Get("Server"))
	if m := iisServerRe.FindStringSubmatch(serverHdr); m != nil {
		add("Microsoft IIS", m[1], "header:Server", fmt.Sprintf("header %q: %q", "Server", serverHdr), CatServer)
	} else {
		parsePair("Server", serverHdr, "header:Server", CatServer)
	}
	parsePair("X-Powered-By", h.Get("X-Powered-By"), "header:X-Powered-By", CatMisc)
	if v := strings.TrimSpace(h.Get("X-AspNet-Version")); v != "" {
		add("ASP.NET", v, "header:X-AspNet-Version", fmt.Sprintf("header %q: %q", "X-AspNet-Version", v), CatFramework)
	}
	if v := strings.TrimSpace(h.Get("X-AspNetMvc-Version")); v != "" {
		add("ASP.NET MVC", v, "header:X-AspNetMvc-Version", fmt.Sprintf("header %q: %q", "X-AspNetMvc-Version", v), CatFramework)
	}
	if v := strings.TrimSpace(h.Get("X-Generator")); v != "" {
		ev := fmt.Sprintf("header %q: %q", "X-Generator", v)
		if m := regexp.MustCompile(`(?i)^(\S+)\s+([0-9][0-9A-Za-z.\-]*)`).FindStringSubmatch(v); m != nil {
			add(m[1], m[2], "header:X-Generator", ev, CatCMS)
		} else {
			add(strings.SplitN(v, " ", 2)[0], "", "header:X-Generator", ev, CatCMS)
		}
	}
	if v := strings.TrimSpace(h.Get("X-Drupal-Cache")); v != "" {
		add("Drupal", "", "header:X-Drupal-Cache", fmt.Sprintf("header %q: %q", "X-Drupal-Cache", v), CatCMS)
	}
	if v := strings.TrimSpace(h.Get("X-Varnish")); v != "" {
		add("Varnish", "", "header:X-Varnish", fmt.Sprintf("header %q: %q", "X-Varnish", v), CatServer)
	}
	if v := strings.TrimSpace(h.Get("Via")); v != "" {
		if strings.Contains(strings.ToLower(v), "varnish") {
			add("Varnish", extractParenVersion(v), "header:Via", fmt.Sprintf("header %q: %q", "Via", v), CatServer)
		}
	}
	if cf := h.Get("CF-Ray"); cf != "" {
		add("Cloudflare", "", "header:CF-Ray", fmt.Sprintf("header %q present: %q", "CF-Ray", cf), CatCDN)
	}
}

// extractParenVersion pulls "X.Y" out of strings like "(Varnish/6.0)".
func extractParenVersion(s string) string {
	if m := regexp.MustCompile(`/([0-9][0-9A-Za-z.\-]*)`).FindStringSubmatch(s); m != nil {
		return m[1]
	}
	return ""
}

// enrichVersions runs once at the end to backfill versions onto techs that
// have a Name but no Version. Does NOT add new techs (that's Phase 1-3's job).
func enrichVersions(tr *TargetResult, h http.Header, body string) {
	missing := map[string]int{} // tech name (lowered) -> index in tr.Technologies
	for i := range tr.Technologies {
		if tr.Technologies[i].Version == "" {
			missing[strings.ToLower(tr.Technologies[i].Name)] = i
		}
	}
	if len(missing) == 0 {
		return
	}

	candidates := map[string]string{} // lowered name -> version

	// Source A: meta-generator tags  e.g. <meta name="generator" content="WordPress 6.4.2">
	for _, m := range generatorMetaRe.FindAllStringSubmatch(body, -1) {
		raw := strings.TrimSpace(m[1])
		if mm := regexp.MustCompile(`(?i)^(\S+)\s+v?([0-9][0-9A-Za-z.\-]*)`).FindStringSubmatch(raw); mm != nil {
			candidates[strings.ToLower(mm[1])] = mm[2]
		}
	}

	// Source B: JS asset paths   e.g. /jquery-3.6.0.min.js, /vue/2.6.14/vue.js
	for _, m := range jsLibRe.FindAllStringSubmatch(body, -1) {
		name := strings.ToLower(m[1])
		// avoid overly generic words
		if len(name) < 3 || name == "min" || name == "lib" || name == "src" || name == "dist" || name == "bundle" || name == "vendor" || name == "common" || name == "core" {
			continue
		}
		if _, ok := candidates[name]; !ok {
			candidates[name] = m[2]
		}
	}

	// Source C: WordPress CORE version — reliable core-tracking signals only
	// (see wpCoreVersionRes). Don't overwrite a version the generator meta
	// (Source A, most authoritative) already provided. Falling through with
	// NO version is the correct outcome when core can't be pinned: a
	// version-less WordPress simply skips CVE matching instead of matching
	// every CVE for jQuery's version number.
	if _, ok := candidates["wordpress"]; !ok {
		for _, rx := range wpCoreVersionRes {
			if v := rx.FindStringSubmatch(body); len(v) > 1 {
				candidates["wordpress"] = v[1]
				break
			}
		}
	}
	// Source D: PHP version cookie (e.g. PHPSESSID is just a cookie name; no version)
	// — skipped, since PHPSESSID alone gives no version info.

	// Source E: Drupal hint in body  <head>... Drupal 9 ...
	if v := regexp.MustCompile(`(?i)Drupal\.settings|sites/default/files`).FindString(body); v != "" {
		if _, ok := candidates["drupal"]; !ok {
			candidates["drupal"] = "" // hint only — no version, but keep going
		}
	}

	// Apply: backfill versions where we have a match
	for techNameLower, idx := range missing {
		ver, ok := candidates[techNameLower]
		if !ok || ver == "" {
			continue
		}
		tr.Technologies[idx].Version = ver
	}
}

// dedupeTechnologies collapses technologies that share a Name (case-insensitive)
// within a single target into one entry, preferring the entry that carries a
// Version. The per-phase `seen` map only dedupes EXACT name strings, so the same
// product reached under slightly different names (e.g. "Nginx" from a fingerprint
// vs "nginx" from the Server header, or an IIS box surfaced by both a fingerprint
// and header parsing) used to emit multiple rows — each version-less duplicate
// then flooded downstream CVE matching with false positives.
func dedupeTechnologies(techs []Technology) []Technology {
	if len(techs) < 2 {
		return techs
	}
	idx := map[string]int{} // lowered, trimmed name -> index in out
	out := make([]Technology, 0, len(techs))
	for _, t := range techs {
		key := strings.ToLower(strings.TrimSpace(t.Name))
		if key == "" {
			out = append(out, t)
			continue
		}
		if i, ok := idx[key]; ok {
			// Keep the first-seen entry; adopt a Version (and the evidence
			// explaining it) from a duplicate if the kept entry lacks one.
			if out[i].Version == "" && t.Version != "" {
				out[i].Version = t.Version
				if t.Evidence != "" {
					out[i].Evidence = t.Evidence
				}
			}
			continue
		}
		idx[key] = len(out)
		out = append(out, t)
	}
	return out
}

// whatwebExecError turns a failed whatweb spawn into a compact error string,
// preferring the process's stderr (which carries the real reason — an unknown
// flag, a Ruby stack trace, "command not found" inside the killswitch netns)
// over the bare "exit status N". A missing binary in the non-killswitch path
// surfaces as Go's `exec: "whatweb": executable file not found` here, which
// shared.TranslateToolError recognises downstream. Length-capped; stderr rarely
// carries credentials but is bounded regardless.
func whatwebExecError(err error) error {
	if err == nil {
		return nil
	}
	msg := strings.TrimSpace(err.Error())
	var ee *exec.ExitError
	if errors.As(err, &ee) {
		if s := strings.TrimSpace(string(ee.Stderr)); s != "" {
			// Keep the exit-status text too so nothing is lost.
			msg = s + " (" + msg + ")"
		}
	}
	if len(msg) > 300 {
		msg = msg[:300]
	}
	return errors.New(msg)
}

// whatwebWarning converts a whatweb run failure into a single user-facing
// warning line. It prefers shared.TranslateToolError's plain-language
// explanation ("The required tool whatweb is not installed…", "flag provided
// but not defined", etc.); when no rule matches it falls back to the first
// non-empty line of the raw error, trimmed to ~180 chars and prefixed so the
// UI shows which tool degraded. Returns "" for a nil error (no warning).
func whatwebWarning(err error) string {
	if err == nil {
		return ""
	}
	raw := err.Error()
	if friendly, ok := shared.TranslateToolError(raw); ok {
		return friendly
	}
	for _, line := range strings.Split(raw, "\n") {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		if len(line) > 180 {
			line = line[:180] + "…"
		}
		return "whatweb did not run: " + line
	}
	return ""
}

// maxTechWarnings caps how many distinct whatweb warnings a single scan
// accumulates — a missing binary dedups to one line, but a per-host non-zero
// exit whose stderr differs could otherwise flood the banner.
const maxTechWarnings = 12

// runWhatWeb executes whatweb and parses JSON output.
//
// Settings (Burp proxy, custom UA, custom Headers / Cookies) are propagated
// to the whatweb subprocess so an authenticated app fingerprinted via the
// Go-side fetch is also fingerprinted under the same auth/proxy here —
// otherwise this phase would silently bypass the user's Settings and
// expose the unauthenticated origin (and leak around Burp).
//
// The subprocess ctx is derived from the scan's cancellable context
// (opts.Ctx set by BeginScan) — otherwise a click on Stop or a
// killswitch iface-drop left up to 20 in-flight whatweb processes
// running for the full 30 s budget each, still writing to disk and
// still able to leak past the killswitch after the scan was cancelled.
// When opts / opts.Ctx are nil (e.g. tests) we fall back to Background.
// The error return is NON-NIL only when whatweb genuinely failed to run and
// produced nothing to parse — a missing binary or a non-zero exit with no
// output — so the caller can surface a "whatweb didn't run" warning. A genuine
// Stop / killswitch / per-target-deadline cancellation returns (nil, nil): that
// is not a broken tool. A clean run that simply found no techs also returns a
// nil error (STAY QUIET on success-with-zero-results).
func runWhatWeb(target string, opts *shared.HTTPOptions, aggressive bool, logf func(string)) ([]Technology, error) {
	parent := context.Background()
	if opts != nil && opts.Ctx != nil {
		parent = opts.Ctx
	}
	// Aggression drives BOTH the argv and the per-target time budget:
	//   -a 1 (default): a single passive GET — fast, one request, the way this
	//     module used to run. Combined with the Go-side fingerprints + JS-bundle
	//     scan + version extraction, this already covers the common stack.
	//   -a 3 (opt-in "Aggressive WhatWeb probe" checkbox): fires follow-up
	//     requests against matched plugin paths for deeper version strings —
	//     MUCH slower (5-20x the requests per host) and can trip WAFs.
	// Forcing -a 3 for everyone (a prior change) is what made Tech Detection
	// crawl vs. "finishing almost instantly". Honour the flag again, and give
	// -a 1 a tighter deadline so one dead host can't park a worker for 30s.
	aLevel := "1"
	budget := 25 * time.Second
	if aggressive {
		aLevel = "3"
		budget = 60 * time.Second
	}
	// Honour a larger per-scan request-timeout override — a slow-but-alive site
	// was being killed at the old 12s default and mislabelled as a timeout.
	if opts != nil && opts.Timeout > 0 && opts.Timeout > budget {
		budget = opts.Timeout
	}
	ctx, cancel := context.WithTimeout(parent, budget)
	defer cancel()
	args := []string{"--color=never", "--log-json=-", "-q", "-a", aLevel, "--no-errors"}
	if opts != nil {
		if opts.UserAgent != "" {
			args = append(args, "--user-agent="+opts.UserAgent)
		}
		// whatweb's --proxy takes host[:port]; --proxy-user takes user:pass.
		// Strip the scheme and embedded creds out of opts.ProxyURL.
		if opts.ProxyURL != "" && !opts.BurpSuccessOnly {
			if pu, perr := url.Parse(opts.ProxyURL); perr == nil && pu.Host != "" {
				args = append(args, "--proxy="+pu.Host)
				if pu.User != nil {
					if pw, hasPw := pu.User.Password(); hasPw {
						args = append(args, "--proxy-user="+pu.User.Username()+":"+pw)
					}
				}
			}
		}
		// Custom headers — whatweb's --header flag is repeatable.
		// Sort for deterministic argv (helps reproducibility / tests).
		if len(opts.Headers) > 0 {
			keys := make([]string, 0, len(opts.Headers))
			for k := range opts.Headers {
				keys = append(keys, k)
			}
			sort.Strings(keys)
			for _, k := range keys {
				args = append(args, "--header", k+": "+opts.Headers[k])
			}
		}
		// Cookies — whatweb expects a single "k=v; k2=v2" string.
		if len(opts.Cookies) > 0 {
			ckKeys := make([]string, 0, len(opts.Cookies))
			for k := range opts.Cookies {
				ckKeys = append(ckKeys, k)
			}
			sort.Strings(ckKeys)
			var ck strings.Builder
			for i, k := range ckKeys {
				if i > 0 {
					ck.WriteString("; ")
				}
				ck.WriteString(k)
				ck.WriteString("=")
				ck.WriteString(opts.Cookies[k])
			}
			args = append(args, "--cookie="+ck.String())
		}
	}
	args = append(args, target)

	// Surface the exact whatweb command as a console crumb before running it.
	// Redact credential-bearing args (proxy password, session cookie) in the
	// displayed string only — the real args slice is unchanged.
	if logf != nil {
		disp := make([]string, len(args))
		for i, a := range args {
			switch {
			case strings.HasPrefix(a, "--proxy-user="):
				disp[i] = "--proxy-user=***"
			case strings.HasPrefix(a, "--cookie="):
				disp[i] = "--cookie=***"
			default:
				disp[i] = a
			}
		}
		logf("$ " + shared.FormatCommand("whatweb", disp))
	}

	cmd := shared.Command(ctx, "whatweb", args...)
	out, err := cmd.Output()
	if err != nil {
		// whatweb exits non-zero on 4xx/5xx targets, plugin hiccups, and when
		// our deadline kills it — but it usually already wrote valid JSON to
		// stdout first. The old code threw ALL of that away, AND swallowed a
		// missing-binary error so a broken whatweb looked identical to a clean
		// "no techs found" (silent tool degradation).
		//
		// A genuine Stop / killswitch (parent ctx cancelled) OR our own
		// per-target deadline (derived ctx expired) is not a broken tool —
		// discard silently.
		if ctx.Err() != nil || (opts != nil && opts.Ctx != nil && opts.Ctx.Err() == context.Canceled) {
			return nil, nil
		}
		// Something ELSE went wrong. If whatweb still wrote JSON, parse it (the
		// {-prefix + json.Unmarshal guards below make a truncated tail safe).
		// If it produced NOTHING, this is a real failure — a missing binary or
		// a non-zero exit with no output — so return the error for the caller
		// to surface as a warning.
		if len(out) == 0 {
			return nil, whatwebExecError(err)
		}
	}

	var techs []Technology

	// WhatWeb JSON: one JSON object per line
	for _, line := range strings.Split(string(out), "\n") {
		line = strings.TrimSpace(line)
		if line == "" || !strings.HasPrefix(line, "{") {
			continue
		}
		var entry map[string]interface{}
		if json.Unmarshal([]byte(line), &entry) != nil {
			continue
		}

		plugins, ok := entry["plugins"].(map[string]interface{})
		if !ok {
			continue
		}

		for name, info := range plugins {
			// Skip whatweb's generic page-metadata / header plugins — they are
			// not technologies and just clutter the result (they surfaced as
			// fake "techs" like Title/Script/HTML5 with -a 3).
			if whatwebNoise[name] {
				continue
			}
			t := Technology{
				Name:     name,
				Category: categorizeWhatWeb(name),
				Source:   "whatweb",
			}
			if infoMap, ok := info.(map[string]interface{}); ok {
				if ver, ok := infoMap["version"].([]interface{}); ok && len(ver) > 0 {
					t.Version = fmt.Sprintf("%v", ver[0])
				}
				if str, ok := infoMap["string"].([]interface{}); ok && len(str) > 0 {
					if t.Version == "" {
						t.Version = fmt.Sprintf("%v", str[0])
					}
				}
			}
			techs = append(techs, t)
		}
	}
	return techs, nil
}

// whatwebNoise lists whatweb "plugins" that are page metadata or raw headers,
// not technologies — filtered out so the result shows real stack, not clutter.
var whatwebNoise = map[string]bool{
	"IP": true, "Country": true, "HTTPServer": true, "Title": true, "Script": true,
	"MetaGenerator": true, "UncommonHeaders": true, "HTML5": true, "X-UA-Compatible": true,
	"Open-Graph-Protocol": true, "Meta-Author": true, "Meta-Refresh": true, "Meta-Keywords": true,
	"Meta-Description": true, "Frame": true, "IFrame": true, "Cookies": true, "PasswordField": true,
	"Email": true, "RedirectLocation": true, "HttpOnly": true, "Strict-Transport-Security": true,
	"X-Frame-Options": true, "X-Content-Type-Options": true, "Content-Security-Policy": true,
	"Access-Control-Allow-Origin": true, "X-XSS-Protection": true, "Via-Proxy": true,
	"Allow": true, "Content-Language": true, "probably-not": true, "JavaScript": true,
}

func categorizeWhatWeb(name string) TechCategory {
	n := strings.ToLower(name)
	switch {
	case strings.Contains(n, "wordpress") || strings.Contains(n, "joomla") || strings.Contains(n, "drupal") || strings.Contains(n, "magento"):
		return CatCMS
	case strings.Contains(n, "jquery") || strings.Contains(n, "modernizr") || strings.Contains(n, "underscore"):
		return CatJS
	case strings.Contains(n, "bootstrap") || strings.Contains(n, "tailwind"):
		return CatUI
	case strings.Contains(n, "nginx") || strings.Contains(n, "apache") || strings.Contains(n, "iis") || strings.Contains(n, "litespeed"):
		return CatServer
	case strings.Contains(n, "php") || strings.Contains(n, "asp") || strings.Contains(n, "python") || strings.Contains(n, "java"):
		return CatLanguage
	case strings.Contains(n, "google") || strings.Contains(n, "analytics") || strings.Contains(n, "tag-manager"):
		return CatAnalytics
	case strings.Contains(n, "cloudflare") || strings.Contains(n, "akamai") || strings.Contains(n, "fastly"):
		return CatCDN
	default:
		return CatMisc
	}
}

func extractTitle(body string) string {
	lower := strings.ToLower(body)
	start := strings.Index(lower, "<title")
	if start < 0 {
		return ""
	}
	start = strings.Index(lower[start:], ">")
	if start < 0 {
		return ""
	}
	startAbs := strings.Index(lower, "<title") + start + 1
	end := strings.Index(lower[startAbs:], "</title>")
	if end < 0 {
		return ""
	}
	title := strings.TrimSpace(body[startAbs : startAbs+end])
	if len(title) > 200 {
		title = title[:200]
	}
	return title
}

// fetchFaviconHash mirrors Shodan's http.favicon.hash technique:
// fetch the site's favicon, base64-encode it with 76-char line wrap
// (the same encoding Shodan uses), then MurmurHash3 the result.
// Returns the hash + the URL that was successfully fetched.
//
// We try, in order:
//  1. <link rel="icon" href="..."> declared in the HTML
//  2. The standard /favicon.ico fallback
//
// If neither responds with a 2xx, hash is 0 and URL is empty —
// the caller treats that as "no favicon to fingerprint".
func fetchFaviconHash(target, body string, client *http.Client, opts *shared.HTTPOptions) (int32, string) {
	candidates := []string{}
	// 1. Parse declared <link rel="icon"|"shortcut icon" href="...">
	low := strings.ToLower(body)
	for _, rel := range []string{`rel="icon"`, `rel='icon'`, `rel="shortcut icon"`, `rel='shortcut icon'`} {
		idx := 0
		for {
			pos := strings.Index(low[idx:], rel)
			if pos < 0 {
				break
			}
			// Look outward for href= within the same <link> tag.
			start := strings.LastIndex(low[:idx+pos], "<link")
			end := strings.Index(low[idx+pos:], ">")
			if start >= 0 && end > 0 {
				tag := body[start : idx+pos+end+1]
				if href := extractHref(tag); href != "" {
					candidates = append(candidates, resolveURL(target, href))
				}
			}
			idx += pos + len(rel)
		}
	}
	// 2. Standard fallback
	candidates = append(candidates, resolveURL(target, "/favicon.ico"))

	for _, u := range candidates {
		req, err := http.NewRequest("GET", u, nil)
		if err != nil {
			continue
		}
		if opts != nil {
			opts.ApplyTo(req)
		}
		req = opts.BindContext(req)
		resp, err := client.Do(req)
		if err != nil {
			continue
		}
		if resp.StatusCode < 200 || resp.StatusCode >= 300 {
			resp.Body.Close()
			continue
		}
		raw, err := io.ReadAll(io.LimitReader(resp.Body, 256*1024))
		resp.Body.Close()
		if err != nil || len(raw) == 0 {
			continue
		}
		// Shodan-style: base64 with 76-char line wrap + trailing newline.
		enc := base64.StdEncoding.EncodeToString(raw)
		var wrapped strings.Builder
		for i := 0; i < len(enc); i += 76 {
			end := i + 76
			if end > len(enc) {
				end = len(enc)
			}
			wrapped.WriteString(enc[i:end])
			wrapped.WriteByte('\n')
		}
		return mmh3HashBytes([]byte(wrapped.String())), u
	}
	return 0, ""
}

// extractHref pulls the href attribute value out of a tag fragment.
func extractHref(tag string) string {
	low := strings.ToLower(tag)
	idx := strings.Index(low, "href=")
	if idx < 0 {
		return ""
	}
	idx += 5
	if idx >= len(tag) {
		return ""
	}
	quote := tag[idx]
	if quote == '"' || quote == '\'' {
		end := strings.IndexByte(tag[idx+1:], quote)
		if end > 0 {
			return tag[idx+1 : idx+1+end]
		}
	}
	end := strings.IndexAny(tag[idx:], " \t>")
	if end > 0 {
		return tag[idx : idx+end]
	}
	return tag[idx:]
}

// resolveURL joins a relative href against a base URL.
func resolveURL(base, href string) string {
	if strings.HasPrefix(href, "http://") || strings.HasPrefix(href, "https://") {
		return href
	}
	bu, err := url.Parse(base)
	if err != nil {
		return href
	}
	hu, err := url.Parse(href)
	if err != nil {
		return href
	}
	return bu.ResolveReference(hu).String()
}

// mmh3HashBytes is a pure-Go MurmurHash3 x86 32-bit impl matching the
// Python `mmh3.hash(bytes, signed=True)` output Shodan documents.
// Signed int32 so the value matches Shodan's display (which can be
// negative).
func mmh3HashBytes(key []byte) int32 {
	const (
		c1 uint32 = 0xcc9e2d51
		c2 uint32 = 0x1b873593
	)
	var h uint32 = 0
	length := len(key)
	nblocks := length / 4
	for i := 0; i < nblocks; i++ {
		k := uint32(key[i*4]) | uint32(key[i*4+1])<<8 | uint32(key[i*4+2])<<16 | uint32(key[i*4+3])<<24
		k *= c1
		k = (k << 15) | (k >> 17)
		k *= c2
		h ^= k
		h = (h << 13) | (h >> 19)
		h = h*5 + 0xe6546b64
	}
	tailStart := nblocks * 4
	var k1 uint32
	switch length & 3 {
	case 3:
		k1 ^= uint32(key[tailStart+2]) << 16
		fallthrough
	case 2:
		k1 ^= uint32(key[tailStart+1]) << 8
		fallthrough
	case 1:
		k1 ^= uint32(key[tailStart])
		k1 *= c1
		k1 = (k1 << 15) | (k1 >> 17)
		k1 *= c2
		h ^= k1
	}
	h ^= uint32(length)
	h ^= h >> 16
	h *= 0x85ebca6b
	h ^= h >> 13
	h *= 0xc2b2ae35
	h ^= h >> 16
	return int32(h)
}
