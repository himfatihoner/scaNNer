package secheaders

import (
	"crypto/tls"
	"fmt"
	"io"
	"net/http"
	"scanner/internal/modules/shared"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

// Severity for header findings
type Severity string

const (
	SevHigh   Severity = "HIGH"
	SevMedium Severity = "MEDIUM"
	SevLow    Severity = "LOW"
	SevInfo   Severity = "INFO"
	SevPass   Severity = "PASS"
)

// HeaderCheck defines what to look for in a specific header
type HeaderCheck struct {
	Name        string
	Severity    Severity // severity if MISSING
	Required    bool
	Description string
	CheckFn     func(value string) *HeaderFinding // nil = OK
}

// HeaderFinding is one issue with a header
type HeaderFinding struct {
	Header      string   `json:"header"`
	Severity    Severity `json:"severity"`
	Status      string   `json:"status"` // "Missing", "Insecure", "Weak", "Present"
	Value       string   `json:"value"`
	Description string   `json:"description"`
	Recommend   string   `json:"recommend"`
}

// ProbeResult is the method tester output for one request. Findings is
// the per-probe analysis — each probe gets its own header evaluation so
// the UI can show how, e.g., a POST response's CSP differs from GET's.
type ProbeResult struct {
	Method      string            `json:"method"`
	ContentType string            `json:"content_type"`
	Variant     string            `json:"variant"`
	StatusCode  int               `json:"status_code"`
	Headers     map[string]string `json:"headers"`
	Findings    []HeaderFinding   `json:"findings,omitempty"`
	RawRequest  string            `json:"raw_request,omitempty"`
	RawResponse string            `json:"raw_response,omitempty"`
}

// URLResult holds all findings for one URL
type URLResult struct {
	URL      string          `json:"url"`
	Probes   []ProbeResult   `json:"probes"` // all 200 OK probes
	Findings []HeaderFinding `json:"findings"`
	Score    int             `json:"score"` // 0-100 security score
	Grade    string          `json:"grade"` // A+, A, B, C, D, F
	Error    string          `json:"error,omitempty"`
}

type ScanResult struct {
	Results []URLResult `json:"results"`
}

type ProgressFunc func(done int, msg string)
type PartialFunc func(*ScanResult)

// --- Content-type variants (reused from httpmethods logic) ---

type variant struct {
	Method      string
	ContentType string
	Label       string
	Body        string
}

var probeVariants = []variant{
	{"GET", "", "GET", ""},
	{"HEAD", "", "HEAD", ""},
	{"POST", "", "POST No Body", ""},
	{"POST", "application/x-www-form-urlencoded", "POST Form", "key=value"},
	{"POST", "application/json", "POST JSON", `{"key":"value"}`},
	{"POST", "application/xml", "POST XML", `<?xml version="1.0"?><r><k>v</k></r>`},
	{"PUT", "", "PUT No Body", ""},
	{"PUT", "application/json", "PUT JSON", `{"key":"value"}`},
	{"PATCH", "application/json", "PATCH JSON", `{"key":"updated"}`},
	{"DELETE", "", "DELETE", ""},
	{"OPTIONS", "", "OPTIONS", ""},
}

// --- Header checks database ---

var headerChecks = []HeaderCheck{
	{
		Name: "Strict-Transport-Security", Severity: SevHigh, Required: true,
		Description: "HSTS forces browsers to use HTTPS, preventing downgrade attacks and cookie hijacking.",
		CheckFn: func(v string) *HeaderFinding {
			if v == "" {
				return &HeaderFinding{Severity: SevHigh, Status: "Missing", Description: "HSTS header is missing. Site is vulnerable to SSL stripping attacks.", Recommend: "Strict-Transport-Security: max-age=31536000; includeSubDomains; preload"}
			}
			if !strings.Contains(v, "max-age") {
				return &HeaderFinding{Severity: SevMedium, Status: "Weak", Value: v, Description: "HSTS present but missing max-age directive.", Recommend: "Add max-age=31536000"}
			}
			if strings.Contains(v, "max-age=0") {
				return &HeaderFinding{Severity: SevHigh, Status: "Insecure", Value: v, Description: "HSTS max-age is 0, effectively disabling HSTS.", Recommend: "Set max-age to at least 31536000 (1 year)"}
			}
			// Check max-age value
			if !strings.Contains(v, "includeSubDomains") {
				return &HeaderFinding{Severity: SevLow, Status: "Weak", Value: v, Description: "HSTS does not include subdomains.", Recommend: "Add includeSubDomains"}
			}
			return &HeaderFinding{Severity: SevPass, Status: "Present", Value: v, Description: "HSTS properly configured."}
		},
	},
	{
		Name: "Content-Security-Policy", Severity: SevHigh, Required: true,
		Description: "CSP prevents XSS, clickjacking, and code injection by specifying allowed content sources.",
		CheckFn: func(v string) *HeaderFinding {
			if v == "" {
				return &HeaderFinding{Severity: SevHigh, Status: "Missing", Description: "CSP header is missing. Site is more vulnerable to XSS attacks.", Recommend: "Content-Security-Policy: default-src 'self'; script-src 'self'"}
			}
			lower := strings.ToLower(v)
			if strings.Contains(lower, "unsafe-inline") && strings.Contains(lower, "unsafe-eval") {
				return &HeaderFinding{Severity: SevMedium, Status: "Weak", Value: v, Description: "CSP allows both unsafe-inline and unsafe-eval, significantly reducing XSS protection.", Recommend: "Remove 'unsafe-inline' and 'unsafe-eval' where possible"}
			}
			if strings.Contains(lower, "unsafe-inline") {
				return &HeaderFinding{Severity: SevLow, Status: "Weak", Value: v, Description: "CSP allows 'unsafe-inline'. Consider using nonces or hashes instead.", Recommend: "Replace 'unsafe-inline' with nonce-based CSP"}
			}
			if strings.Contains(lower, "*") && strings.Contains(lower, "script-src") {
				return &HeaderFinding{Severity: SevMedium, Status: "Weak", Value: v, Description: "CSP script-src uses wildcard, allowing scripts from any origin.", Recommend: "Restrict script-src to specific trusted domains"}
			}
			return &HeaderFinding{Severity: SevPass, Status: "Present", Value: v, Description: "CSP policy is set."}
		},
	},
	{
		Name: "X-Frame-Options", Severity: SevMedium, Required: true,
		Description: "Prevents clickjacking by controlling whether the site can be framed.",
		CheckFn: func(v string) *HeaderFinding {
			if v == "" {
				return &HeaderFinding{Severity: SevMedium, Status: "Missing", Description: "X-Frame-Options missing. Site may be vulnerable to clickjacking.", Recommend: "X-Frame-Options: DENY or SAMEORIGIN"}
			}
			upper := strings.ToUpper(v)
			if upper == "DENY" || upper == "SAMEORIGIN" {
				return &HeaderFinding{Severity: SevPass, Status: "Present", Value: v, Description: "Clickjacking protection enabled."}
			}
			if strings.HasPrefix(upper, "ALLOW-FROM") {
				return &HeaderFinding{Severity: SevLow, Status: "Weak", Value: v, Description: "ALLOW-FROM is deprecated and not supported by modern browsers.", Recommend: "Use CSP frame-ancestors instead"}
			}
			return &HeaderFinding{Severity: SevLow, Status: "Weak", Value: v, Description: "Unrecognized X-Frame-Options value.", Recommend: "Use DENY or SAMEORIGIN"}
		},
	},
	{
		Name: "X-Content-Type-Options", Severity: SevMedium, Required: true,
		Description: "Prevents MIME-sniffing attacks by forcing the browser to respect the declared Content-Type.",
		CheckFn: func(v string) *HeaderFinding {
			if v == "" {
				return &HeaderFinding{Severity: SevMedium, Status: "Missing", Description: "X-Content-Type-Options missing. Browser may MIME-sniff responses.", Recommend: "X-Content-Type-Options: nosniff"}
			}
			if strings.ToLower(v) == "nosniff" {
				return &HeaderFinding{Severity: SevPass, Status: "Present", Value: v, Description: "MIME-sniffing prevention enabled."}
			}
			return &HeaderFinding{Severity: SevLow, Status: "Weak", Value: v, Description: "Invalid value. Should be 'nosniff'."}
		},
	},
	{
		Name: "Referrer-Policy", Severity: SevMedium, Required: true,
		Description: "Controls how much referrer information is sent with requests, protecting user privacy.",
		CheckFn: func(v string) *HeaderFinding {
			if v == "" {
				return &HeaderFinding{Severity: SevMedium, Status: "Missing", Description: "Referrer-Policy missing. Full URL may leak in Referer header.", Recommend: "Referrer-Policy: strict-origin-when-cross-origin"}
			}
			lower := strings.ToLower(v)
			if lower == "unsafe-url" {
				return &HeaderFinding{Severity: SevHigh, Status: "Insecure", Value: v, Description: "unsafe-url sends full URL as referrer to all origins, leaking sensitive paths.", Recommend: "Use strict-origin-when-cross-origin or no-referrer"}
			}
			if lower == "no-referrer" || lower == "strict-origin-when-cross-origin" || lower == "same-origin" || lower == "strict-origin" || lower == "origin-when-cross-origin" {
				return &HeaderFinding{Severity: SevPass, Status: "Present", Value: v, Description: "Referrer policy configured."}
			}
			return &HeaderFinding{Severity: SevInfo, Status: "Present", Value: v, Description: "Referrer policy set."}
		},
	},
	{
		Name: "Permissions-Policy", Severity: SevLow, Required: false,
		Description: "Controls which browser features the site can use (camera, microphone, geolocation, etc.).",
		CheckFn: func(v string) *HeaderFinding {
			if v == "" {
				return &HeaderFinding{Severity: SevLow, Status: "Missing", Description: "Permissions-Policy missing. Browser features are not restricted.", Recommend: "Permissions-Policy: camera=(), microphone=(), geolocation=()"}
			}
			return &HeaderFinding{Severity: SevPass, Status: "Present", Value: v, Description: "Permissions policy configured."}
		},
	},
	{
		Name: "X-XSS-Protection", Severity: SevInfo, Required: false,
		Description: "Legacy XSS filter. Modern browsers have deprecated this in favor of CSP.",
		CheckFn: func(v string) *HeaderFinding {
			if v == "" {
				return &HeaderFinding{Severity: SevInfo, Status: "Missing", Description: "X-XSS-Protection not set. Not critical if CSP is properly configured.", Recommend: "X-XSS-Protection: 0 (recommended to disable legacy filter, rely on CSP)"}
			}
			if v == "0" {
				return &HeaderFinding{Severity: SevPass, Status: "Present", Value: v, Description: "XSS filter disabled (correct modern practice when CSP is used)."}
			}
			if strings.Contains(v, "1") && strings.Contains(v, "mode=block") {
				return &HeaderFinding{Severity: SevPass, Status: "Present", Value: v, Description: "Legacy XSS filter enabled with block mode."}
			}
			return &HeaderFinding{Severity: SevInfo, Status: "Present", Value: v, Description: "XSS protection header set."}
		},
	},
	{
		Name: "Cross-Origin-Opener-Policy", Severity: SevLow, Required: false,
		Description: "Isolates the browsing context, preventing cross-origin attacks like Spectre.",
		CheckFn: func(v string) *HeaderFinding {
			if v == "" {
				return &HeaderFinding{Severity: SevLow, Status: "Missing", Description: "COOP not set. Window may be accessible by cross-origin documents.", Recommend: "Cross-Origin-Opener-Policy: same-origin"}
			}
			return &HeaderFinding{Severity: SevPass, Status: "Present", Value: v, Description: "COOP configured."}
		},
	},
	{
		Name: "Cross-Origin-Resource-Policy", Severity: SevLow, Required: false,
		Description: "Prevents other origins from reading resources, protecting against side-channel attacks.",
		CheckFn: func(v string) *HeaderFinding {
			if v == "" {
				return &HeaderFinding{Severity: SevLow, Status: "Missing", Description: "CORP not set.", Recommend: "Cross-Origin-Resource-Policy: same-origin"}
			}
			return &HeaderFinding{Severity: SevPass, Status: "Present", Value: v, Description: "CORP configured."}
		},
	},
	{
		Name: "Cross-Origin-Embedder-Policy", Severity: SevLow, Required: false,
		Description: "Ensures all resources are loaded with CORS or CORP headers.",
		CheckFn: func(v string) *HeaderFinding {
			if v == "" {
				return &HeaderFinding{Severity: SevLow, Status: "Missing", Description: "COEP not set.", Recommend: "Cross-Origin-Embedder-Policy: require-corp"}
			}
			return &HeaderFinding{Severity: SevPass, Status: "Present", Value: v, Description: "COEP configured."}
		},
	},
	{
		Name: "Cache-Control", Severity: SevInfo, Required: false,
		Description: "Controls caching behavior. Sensitive pages should not be cached.",
		CheckFn: func(v string) *HeaderFinding {
			if v == "" {
				return &HeaderFinding{Severity: SevInfo, Status: "Missing", Description: "Cache-Control not set. Default caching behavior applies.", Recommend: "Cache-Control: no-store for sensitive pages"}
			}
			return &HeaderFinding{Severity: SevPass, Status: "Present", Value: v, Description: "Cache control configured."}
		},
	},
	{
		Name: "X-Permitted-Cross-Domain-Policies", Severity: SevInfo, Required: false,
		Description: "Controls Flash/PDF cross-domain data loading.",
		CheckFn: func(v string) *HeaderFinding {
			if v == "" {
				return &HeaderFinding{Severity: SevInfo, Status: "Missing", Description: "Not set. Flash/Acrobat may load cross-domain data.", Recommend: "X-Permitted-Cross-Domain-Policies: none"}
			}
			if strings.ToLower(v) == "none" {
				return &HeaderFinding{Severity: SevPass, Status: "Present", Value: v, Description: "Cross-domain policies restricted."}
			}
			return &HeaderFinding{Severity: SevInfo, Status: "Present", Value: v, Description: "Policy set."}
		},
	},
	{
		// CORS audit. Three failure modes worth flagging:
		//   * = wildcard origin (information disclosure if credentials)
		//   null = always exploitable from a sandboxed iframe/data: URL
		//   reflected request origin — silent attacker-controlled access
		Name: "Access-Control-Allow-Origin", Severity: SevHigh, Required: false,
		Description: "Cross-Origin Resource Sharing — who can read responses cross-origin.",
		CheckFn: func(v string) *HeaderFinding {
			if v == "" {
				return &HeaderFinding{Severity: SevInfo, Status: "Missing", Description: "No CORS header — endpoint is same-origin only."}
			}
			switch v {
			case "*":
				return &HeaderFinding{Severity: SevMedium, Status: "Wildcard", Value: v, Description: "Wildcard origin. OK for public read-only APIs; dangerous if combined with Access-Control-Allow-Credentials.", Recommend: "Restrict to an explicit allowlist of trusted origins."}
			case "null":
				return &HeaderFinding{Severity: SevHigh, Status: "Insecure", Value: v, Description: "null origin is always exploitable from a sandboxed iframe or data: URL.", Recommend: "Never return Access-Control-Allow-Origin: null."}
			}
			// Heuristic for likely reflection: header echoes back a single concrete origin.
			if strings.HasPrefix(v, "http://") || strings.HasPrefix(v, "https://") {
				return &HeaderFinding{Severity: SevLow, Status: "Present", Value: v, Description: "Single explicit origin. Verify the server doesn't reflect arbitrary Origin headers — try sending Origin: https://evil.example and re-checking.", Recommend: "Allowlist origins server-side; never reflect the request Origin verbatim."}
			}
			return &HeaderFinding{Severity: SevInfo, Status: "Present", Value: v, Description: "CORS configured."}
		},
	},
	{
		Name: "Access-Control-Allow-Credentials", Severity: SevHigh, Required: false,
		Description: "Whether responses to credentialed cross-origin requests are readable. Lethal in combo with reflected origin.",
		CheckFn: func(v string) *HeaderFinding {
			if v == "" {
				return &HeaderFinding{Severity: SevPass, Status: "Absent", Description: "Credentials not allowed cross-origin."}
			}
			if strings.EqualFold(v, "true") {
				return &HeaderFinding{Severity: SevMedium, Status: "Enabled", Value: v, Description: "Credentialed CORS allowed. Make sure Access-Control-Allow-Origin is a strict allowlist — never wildcard or reflected.", Recommend: "Combine with explicit origin allowlist only."}
			}
			return &HeaderFinding{Severity: SevInfo, Status: "Present", Value: v}
		},
	},
}

// cookieChecks audit each Set-Cookie line individually for missing
// attributes (HttpOnly, Secure, SameSite) and weak prefixes. They're
// applied per-probe inside analyzeURL because Set-Cookie can repeat and
// our header map joins them with ", " — we re-split there.
var cookieChecks = []struct {
	Name string
}{
	{"Set-Cookie"},
}

// --- Scanner ---

// ProbesPerURL returns how many HTTP probes analyzeURL fires for one target —
// used to size the global progress denominator.
func ProbesPerURL() int { return len(probeVariants) }

// ProbesForMethods returns how many probe variants are emitted when the
// caller restricts to a subset of methods. Used to size the progress
// denominator in the handler before the scan starts.
func ProbesForMethods(methods []string) int {
	if len(methods) == 0 {
		return len(probeVariants)
	}
	allowed := map[string]bool{}
	for _, m := range methods {
		allowed[strings.ToUpper(strings.TrimSpace(m))] = true
	}
	n := 0
	for _, v := range probeVariants {
		if allowed[v.Method] {
			n++
		}
	}
	if n == 0 {
		return 1 // matches the GET fallback inside analyzeURL
	}
	return n
}

func Scan(urls []string, opts *shared.HTTPOptions, concurrency int, methods []string, progress ProgressFunc, partial PartialFunc) *ScanResult {
	if concurrency <= 0 {
		concurrency = 3
	}
	// Default to GET only if the caller doesn't specify — keeps the old
	// behaviour for any code path that hasn't been updated yet.
	if len(methods) == 0 {
		methods = []string{"GET"}
	}
	allowed := map[string]bool{}
	for _, m := range methods {
		allowed[strings.ToUpper(strings.TrimSpace(m))] = true
	}
	result := &ScanResult{}
	var mu sync.Mutex
	sem := make(chan struct{}, concurrency)
	var wg sync.WaitGroup

	// Audit fix: build one *http.Client for the whole scan so keepalive
	// connections are shared across URLs on the same host and idle-conn
	// pools don't multiply per-URL. NewHTTPClient wires proxy / user
	// Timeout / LocalAddr / redirect policy / idle-conn caps for free and
	// RegisterTransport's the transport with `opts` so Cancel + FinishScan
	// close its idle pool (previously each per-URL transport leaked its
	// keepalive sockets until GC, minutes later).
	var client *http.Client
	if opts != nil {
		client = opts.NewHTTPClient()
	} else {
		client = &http.Client{
			Timeout: 15 * time.Second,
			Transport: &http.Transport{
				TLSClientConfig:     &tls.Config{InsecureSkipVerify: true},
				DialContext:         shared.BoundDialer(nil, 5*time.Second).DialContext,
				MaxIdleConns:        100,
				MaxIdleConnsPerHost: 50,
				IdleConnTimeout:     90 * time.Second,
			},
			CheckRedirect: func(req *http.Request, via []*http.Request) error {
				return http.ErrUseLastResponse
			},
		}
	}

	// Audit fix: previously the module had no partial flush, so a scan
	// that took 5+ minutes to complete left the user staring at an empty
	// results page and lost ALL data on cancel/crash. Throttled at 2s.
	throttle := shared.NewPartialThrottler(2 * time.Second)
	pushPartial := func() {
		if partial == nil {
			return
		}
		if !throttle.ShouldFire() {
			return
		}
		mu.Lock()
		snap := &ScanResult{Results: append([]URLResult(nil), result.Results...)}
		mu.Unlock()
		partial(snap)
	}

	// Audit fix: probesDone is now atomic. Previously the `mu` mutex was
	// held around the progress callback — which writes to SQLite — blocking
	// every other worker's ability to append its result for the duration
	// of the DB write. Atomic reads make the progress path lock-free.
	var probesDone atomic.Int64
	// Audit fix: probesPer must match the FILTERED variant count so it
	// stays consistent with the handler's totalProbes = len(urls) *
	// ProbesForMethods(methods) denominator. Using ProbesPerURL()
	// (unfiltered = 11) made the progress bar overshoot wildly — e.g.
	// GET-only + 10 URLs reported done=110/total=10 → 1100% until the UI
	// clamped at 'done'. Mirror the same accounting analyzeURL uses.
	probesPerInt := 0
	for _, v := range probeVariants {
		if allowed[v.Method] {
			probesPerInt++
		}
	}
	if probesPerInt == 0 {
		probesPerInt = 1 // matches the GET fallback inside analyzeURL
	}
	probesPer := int64(probesPerInt)

	// Reachability preflight: skip TLS-dead targets up front.
	if opts != nil && opts.PreflightEnabled {
		live, dead := shared.FilterReachable(opts.Ctx, opts, urls, opts.PreflightTimeout, concurrency)
		for t, reason := range dead {
			result.Results = append(result.Results, URLResult{URL: t, Error: "unreachable — " + reason})
		}
		urls = live
	}

	for _, u := range urls {
		// Cancellation fast-path (audit B43).
		if opts != nil && opts.Done() {
			break
		}
		wg.Add(1)
		sem <- struct{}{}
		go func(target string) {
			defer wg.Done()
			defer func() { <-sem }()

			tr := analyzeURL(target, allowed, opts, client, func(msg string) {
				if progress != nil {
					progress(int(probesDone.Load()), msg)
				}
			})

			// Each URL contributes probesPer units to total work, regardless of
			// how many probes returned 200. Bump the counter by the full slot.
			cur := probesDone.Add(probesPer)
			mu.Lock()
			result.Results = append(result.Results, *tr)
			mu.Unlock()
			if progress != nil {
				progress(int(cur), fmt.Sprintf("%s — Grade: %s (%d/100)", target, tr.Grade, tr.Score))
			}
			pushPartial()
		}(u)
	}
	wg.Wait()
	// Final flush so the terminal result always reaches the handler.
	if partial != nil {
		throttle.Force()
		mu.Lock()
		snap := &ScanResult{Results: append([]URLResult(nil), result.Results...)}
		mu.Unlock()
		partial(snap)
	}
	return result
}

func analyzeURL(target string, allowedMethods map[string]bool, opts *shared.HTTPOptions, client *http.Client, logFn func(string)) *URLResult {
	tr := &URLResult{URL: target}

	if !strings.HasPrefix(target, "http://") && !strings.HasPrefix(target, "https://") {
		target = "https://" + target
		tr.URL = target
	}

	// Audit fix: fast-path cancel check before firing any probes for this
	// URL. Without it, a Cancel between URL goroutines still builds one
	// full request-per-variant and burns a client.Do RTT each.
	if opts != nil && opts.Done() {
		return tr
	}

	// Phase 1: Probe the user-selected method/content-type variants,
	// keep only 200 OK. Filter probeVariants by allowedMethods set —
	// only methods the user ticked on the form get fired.
	activeVariants := make([]variant, 0, len(probeVariants))
	for _, v := range probeVariants {
		if allowedMethods[v.Method] {
			activeVariants = append(activeVariants, v)
		}
	}
	if len(activeVariants) == 0 {
		// Degraded fallback — no method matched (shouldn't happen in
		// normal flow). At least probe GET so we still produce data.
		activeVariants = []variant{{"GET", "", "GET", ""}}
	}
	logFn(fmt.Sprintf("[%s] Probing %d method variants...", target, len(activeVariants)))

	// Audit fix: was sequential — 11 HTTP probes × concurrency=3 URLs
	// meant a 30-URL scan spent 30s+ in serial RTTs per URL. Fan-out
	// the variants in parallel; bounded by the variants count so a
	// pathological response won't oversaturate.
	var probeMu sync.Mutex
	var probeWG sync.WaitGroup
	for _, v := range activeVariants {
		// Audit fix: skip building any further probes once the scan has
		// been cancelled. Without this the per-URL fan-out still queues
		// N goroutines that each build a request and call client.Do
		// (which returns immediately with a context error, but only
		// after allocating the request struct + a CaptureRequest pass).
		if opts != nil && opts.Done() {
			break
		}
		probeWG.Add(1)
		go func(v variant) {
			defer probeWG.Done()
			var body io.Reader
			if v.Body != "" {
				body = strings.NewReader(v.Body)
			}
			req, err := http.NewRequest(v.Method, target, body)
			if err != nil {
				return
			}
			req.Header.Set("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36")
			if v.ContentType != "" {
				req.Header.Set("Content-Type", v.ContentType)
			}
			if opts != nil {
				opts.ApplyTo(req)
			}
			req = opts.BindContext(req)

			rawReq := shared.CaptureRequest(req)

			resp, err := client.Do(req)
			if err != nil {
				opts.RecordError(shared.ClassifyError(err))
				return
			}
			// Audit fix: filter non-200 responses BEFORE capturing the raw
			// body/headers. shared.CaptureResponse buffers up to 256 KB of
			// body plus a full header dump into a strings.Builder — doing
			// that for every 405/404/301 that we then discard was wasted
			// CPU + GC pressure. For rejected probes just drain a small
			// cap (so we can keepalive) and move on.
			if resp.StatusCode != 200 {
				io.Copy(io.Discard, io.LimitReader(resp.Body, 64*1024))
				resp.Body.Close()
				return
			}
			rawResp := shared.CaptureResponse(resp)
			// CaptureResponse already drained + closed + replaced the body
			// with a small NopCloser — no need to re-drain here.

			headers := map[string]string{}
			for k, vals := range resp.Header {
				headers[k] = strings.Join(vals, ", ")
			}

			probeMu.Lock()
			tr.Probes = append(tr.Probes, ProbeResult{
				Method:      v.Method,
				ContentType: v.ContentType,
				Variant:     v.Label,
				StatusCode:  resp.StatusCode,
				Headers:     headers,
				RawRequest:  rawReq,
				RawResponse: rawResp,
			})
			probeMu.Unlock()
		}(v)
	}
	probeWG.Wait()

	if len(tr.Probes) == 0 {
		logFn(fmt.Sprintf("[%s] No 200 OK responses received", target))
		tr.Grade = "N/A"
		return tr
	}

	opts.ReplayHit("GET", target)
	logFn(fmt.Sprintf("[%s] %d probes returned 200 OK, analyzing headers...", target, len(tr.Probes)))

	// Phase 2a: Per-probe analysis — evaluate every header check against
	// each probe individually. Lets the UI show "GET passes HSTS but
	// POST is missing it", which the worst-case-only aggregate hid.
	for i := range tr.Probes {
		probe := &tr.Probes[i]
		for _, check := range headerChecks {
			f := check.CheckFn(probe.Headers[check.Name])
			f.Header = check.Name
			probe.Findings = append(probe.Findings, *f)
		}
		// Cookie attribute audit. The Headers map joins multiple
		// Set-Cookie lines with ", " (Go's stdlib behaviour); we re-
		// split on cookie boundaries and audit each cookie for the
		// big three: HttpOnly, Secure, SameSite. Also flag prefix
		// hardening (__Host-, __Secure-) and overly broad Domain=.
		if rawCookie := probe.Headers["Set-Cookie"]; rawCookie != "" {
			for _, c := range splitCookieHeader(rawCookie) {
				probe.Findings = append(probe.Findings, auditCookie(c)...)
			}
		}
	}

	// Phase 2b: Aggregate worst-case across probes for the URL-level
	// score and the legacy findings table.
	for _, check := range headerChecks {
		worstFinding := evaluateHeader(check, tr.Probes)
		worstFinding.Header = check.Name
		tr.Findings = append(tr.Findings, *worstFinding)
	}

	// Phase 2c: Roll cookie findings up into the URL-level tr.Findings
	// list, deduped by Status+Value so the same Set-Cookie observed on
	// GET and POST doesn't count twice. Without this the dashboard
	// severity_count, calculateScore's grade, the worst-case results
	// table, and the Export findings section all silently missed
	// HttpOnly / Secure / SameSite / SameSite=None-without-Secure hits —
	// even though auditCookie can emit SevHigh for session cookies.
	seenCookieFindings := map[string]bool{}
	for i := range tr.Probes {
		for _, f := range tr.Probes[i].Findings {
			if f.Header != "Set-Cookie" {
				continue
			}
			key := f.Status + "|" + f.Value
			if seenCookieFindings[key] {
				continue
			}
			seenCookieFindings[key] = true
			tr.Findings = append(tr.Findings, f)
		}
	}

	// Phase 3: Check for information leak headers
	leakHeaders := []string{"Server", "X-Powered-By", "X-AspNet-Version", "X-AspNetMvc-Version"}
	for _, hdr := range leakHeaders {
		for _, probe := range tr.Probes {
			if val, ok := probe.Headers[hdr]; ok && val != "" {
				tr.Findings = append(tr.Findings, HeaderFinding{
					Header:      hdr,
					Severity:    SevInfo,
					Status:      "Exposed",
					Value:       val,
					Description: fmt.Sprintf("Server exposes %s header, revealing technology information.", hdr),
					Recommend:   fmt.Sprintf("Remove or suppress the %s header.", hdr),
				})
				break // one finding per leak header is enough
			}
		}
	}

	// Phase 4: Check if any probe has different headers than others (inconsistency)
	if len(tr.Probes) > 1 {
		for _, check := range headerChecks {
			if !check.Required {
				continue
			}
			vals := map[string]bool{}
			for _, probe := range tr.Probes {
				vals[probe.Headers[check.Name]] = true
			}
			if len(vals) > 1 {
				tr.Findings = append(tr.Findings, HeaderFinding{
					Header:      check.Name,
					Severity:    SevMedium,
					Status:      "Inconsistent",
					Description: fmt.Sprintf("%s header varies across different HTTP methods/content-types. This may indicate misconfiguration.", check.Name),
					Recommend:   "Ensure security headers are consistent across all response types.",
				})
			}
		}
	}

	// Score
	tr.Score, tr.Grade = calculateScore(tr.Findings)
	return tr
}

// evaluateHeader checks one header across all probes, returns worst finding
func evaluateHeader(check HeaderCheck, probes []ProbeResult) *HeaderFinding {
	var worst *HeaderFinding

	for _, probe := range probes {
		val := probe.Headers[check.Name]
		finding := check.CheckFn(val)
		if finding == nil {
			continue
		}
		if worst == nil || severityRank(finding.Severity) > severityRank(worst.Severity) {
			worst = finding
		}
	}

	if worst == nil {
		return &HeaderFinding{Severity: SevPass, Status: "Present", Description: "Header properly configured."}
	}
	return worst
}

func severityRank(s Severity) int {
	switch s {
	case SevHigh:
		return 4
	case SevMedium:
		return 3
	case SevLow:
		return 2
	case SevInfo:
		return 1
	case SevPass:
		return 0
	}
	return 0
}

func calculateScore(findings []HeaderFinding) (int, string) {
	score := 100
	for _, f := range findings {
		switch f.Severity {
		case SevHigh:
			score -= 20
		case SevMedium:
			score -= 10
		case SevLow:
			score -= 5
		}
	}
	if score < 0 {
		score = 0
	}

	grade := "F"
	switch {
	case score >= 95:
		grade = "A+"
	case score >= 85:
		grade = "A"
	case score >= 75:
		grade = "B"
	case score >= 60:
		grade = "C"
	case score >= 40:
		grade = "D"
	}
	return score, grade
}

// splitCookieHeader takes the joined Set-Cookie header value (Go's
// stdlib glues multiple Set-Cookie lines with ", ") and yields one
// raw cookie string per entry. Naive split on "," would chop the
// Expires= attribute (which contains a comma in its date format);
// we split only on cookie boundaries — "name=value" appearing after
// a known cookie attribute terminator.
func splitCookieHeader(raw string) []string {
	// Heuristic: cookies are joined by ", " followed by something that
	// looks like a new cookie (token=...). We anchor on that.
	parts := strings.Split(raw, ", ")
	out := []string{}
	cur := ""
	for _, p := range parts {
		// If p starts with what looks like a new cookie (token before
		// "="), treat the previous cur as a finished cookie.
		if eq := strings.IndexByte(p, '='); eq > 0 && !strings.ContainsAny(p[:eq], " ;") {
			if cur != "" {
				out = append(out, strings.TrimSpace(cur))
			}
			cur = p
		} else if cur != "" {
			cur += ", " + p
		} else {
			cur = p
		}
	}
	if cur != "" {
		out = append(out, strings.TrimSpace(cur))
	}
	return out
}

// auditCookie inspects one Set-Cookie line for missing security
// attributes (HttpOnly, Secure, SameSite) and weak/dangerous patterns
// (overly broad Domain=, missing __Host-/__Secure- prefix on
// session-looking cookies). Returns 0+ findings.
func auditCookie(cookie string) []HeaderFinding {
	var out []HeaderFinding
	lower := strings.ToLower(cookie)
	name := cookie
	if eq := strings.IndexByte(cookie, '='); eq > 0 {
		name = cookie[:eq]
	}
	hasHttpOnly := strings.Contains(lower, "httponly")
	hasSecure := strings.Contains(lower, "secure")
	hasSameSite := strings.Contains(lower, "samesite=")
	looksLikeSession := false
	nameLower := strings.ToLower(strings.TrimSpace(name))
	for _, s := range []string{"session", "sessid", "auth", "token", "jwt", "phpsessid", "jsessionid"} {
		if strings.Contains(nameLower, s) {
			looksLikeSession = true
			break
		}
	}
	sev := SevLow
	if looksLikeSession {
		sev = SevHigh
	}
	if !hasHttpOnly {
		out = append(out, HeaderFinding{
			Header: "Set-Cookie", Severity: sev, Status: "Missing HttpOnly", Value: cookie,
			Description: "Cookie '" + name + "' has no HttpOnly flag — accessible to JavaScript, vulnerable to XSS-based theft.",
			Recommend:   "Add HttpOnly attribute.",
		})
	}
	if !hasSecure {
		out = append(out, HeaderFinding{
			Header: "Set-Cookie", Severity: sev, Status: "Missing Secure", Value: cookie,
			Description: "Cookie '" + name + "' missing Secure flag — sent over plaintext HTTP.",
			Recommend:   "Add Secure attribute (cookie only sent over HTTPS).",
		})
	}
	if !hasSameSite {
		out = append(out, HeaderFinding{
			Header: "Set-Cookie", Severity: SevMedium, Status: "Missing SameSite", Value: cookie,
			Description: "Cookie '" + name + "' missing SameSite — cross-site request will include it (CSRF surface).",
			Recommend:   "Add SameSite=Lax (or Strict for high-value cookies).",
		})
	} else if strings.Contains(lower, "samesite=none") && !hasSecure {
		out = append(out, HeaderFinding{
			Header: "Set-Cookie", Severity: SevHigh, Status: "SameSite=None without Secure", Value: cookie,
			Description: "Cookie '" + name + "' is SameSite=None but Secure flag is missing. Modern browsers ignore SameSite=None unless Secure is also set — effectively no cross-site protection.",
			Recommend:   "Add Secure attribute or use SameSite=Lax.",
		})
	}
	if looksLikeSession && !strings.HasPrefix(name, "__Host-") && !strings.HasPrefix(name, "__Secure-") {
		out = append(out, HeaderFinding{
			Header: "Set-Cookie", Severity: SevLow, Status: "No security prefix", Value: cookie,
			Description: "Session-like cookie '" + name + "' could use __Host- or __Secure- prefix to enforce Secure/Path/Domain at the browser level.",
			Recommend:   "Rename to __Host-" + name + " (no Domain, Path=/, Secure).",
		})
	}
	if d := cookieAttrValue(cookie, "Domain"); d != "" && strings.HasPrefix(d, ".") {
		out = append(out, HeaderFinding{
			Header: "Set-Cookie", Severity: SevLow, Status: "Broad Domain", Value: cookie,
			Description: "Cookie '" + name + "' has Domain=" + d + " — also sent to all subdomains, expanding attack surface.",
			Recommend:   "Use the most specific host; consider __Host- prefix for app-isolated cookies.",
		})
	}
	return out
}

// cookieAttrValue pulls the value of one attribute from a Set-Cookie
// line (case-insensitive attr match, value up to next "; ").
func cookieAttrValue(cookie, attr string) string {
	lowerAttr := strings.ToLower(attr) + "="
	for _, part := range strings.Split(cookie, ";") {
		p := strings.TrimSpace(part)
		if strings.HasPrefix(strings.ToLower(p), lowerAttr) {
			return p[len(lowerAttr):]
		}
	}
	return ""
}
