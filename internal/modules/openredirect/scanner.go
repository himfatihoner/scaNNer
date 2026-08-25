package openredirect

import (
	"context"
	"crypto/tls"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"regexp"
	"strings"
	"sync"
	"time"

	"scanner/internal/modules/shared"
)

// DefaultParams is the list of query parameters known to drive redirects.
// Order matters — common ones first so we hit fast.
var DefaultParams = []string{
	"url", "next", "return", "redirect", "redirect_uri", "redirect_url",
	"redir", "goto", "dest", "destination", "continue", "callback",
	"return_to", "returnTo", "returnUrl", "back", "ref", "page",
	"target", "rurl", "forward", "from", "checkout_url", "image_url",
	"go", "u",
}

// PayloadVariants — each is built from a fixed evil host so we can detect
// successful redirects by matching the Location header against this host.
// Variants exercise common parser bugs.
func payloadVariants(evilHost string) []string {
	return []string{
		"https://" + evilHost,
		"//" + evilHost,
		"\\\\" + evilHost,
		"https:" + evilHost,
		"%2F%2F" + evilHost,
		"/\\" + evilHost,
		"\\/\\/" + evilHost,
		"https://example.com@" + evilHost,
		"https://" + evilHost + "?victim.com",
		"//google.com%2F@" + evilHost,
	}
}

const evilHostDefault = "scanner-oob-detector.example"

type Finding struct {
	URL         string `json:"url"`
	Parameter   string `json:"parameter"`
	Payload     string `json:"payload"`
	StatusCode  int    `json:"status_code"`
	Location    string `json:"location"`
	HowMatched  string `json:"how_matched"`
	Severity    string `json:"severity"`
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
	URLs        []string
	Params      []string // optional override; if empty, DefaultParams used
	EvilHost    string   // optional override of evilHost
	Concurrency int
	Timeout     time.Duration
	StopOnHit   bool // stop testing a param once any variant lands a redirect
}

type ProgressFunc func(done int, msg string)
type PartialFunc func(*ScanResult)

func Scan(ctx context.Context, cfg Config, opts *shared.HTTPOptions, progress ProgressFunc, partial PartialFunc) *ScanResult {
	if cfg.Concurrency <= 0 {
		cfg.Concurrency = 5
	}
	if cfg.Timeout <= 0 {
		cfg.Timeout = 8 * time.Second
	}
	if cfg.EvilHost == "" {
		cfg.EvilHost = evilHostDefault
	}
	params := cfg.Params
	if len(params) == 0 {
		params = DefaultParams
	}
	result := &ScanResult{}
	var mu sync.Mutex
	sem := make(chan struct{}, cfg.Concurrency)
	var wg sync.WaitGroup
	done := 0
	// Audit S2: per-URL deep-copy + handler-marshal was O(N²). Throttle 2s.
	throttle := shared.NewPartialThrottler(2 * time.Second)

	// Audit perf: hoist the HTTP client + transport out of probeURL so the
	// idle-connection pool is shared across all URLs and only one Transport
	// is registered with opts (was N per scan, each with its own idle pool).
	client := newClient(cfg.Timeout, opts)

	for _, u := range cfg.URLs {
		if ctx.Err() != nil {
			break
		}
		wg.Add(1)
		sem <- struct{}{}
		go func(target string) {
			defer wg.Done()
			defer func() { <-sem }()
			ur := probeURL(ctx, target, params, cfg.EvilHost, cfg.StopOnHit, opts, client)
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

func probeURL(ctx context.Context, target string, params []string, evilHost string, stopOnHit bool, opts *shared.HTTPOptions, client *http.Client) URLResult {
	ur := URLResult{URL: target}
	u, err := url.Parse(target)
	if err != nil {
		ur.Error = "invalid URL: " + err.Error()
		return ur
	}

	for _, param := range params {
		if ctx.Err() != nil {
			break
		}
		paramHit := false
		for _, payload := range payloadVariants(evilHost) {
			ur.Tested++
			probeURL := injectParam(*u, param, payload)
			req, err := http.NewRequestWithContext(ctx, "GET", probeURL, nil)
			if err != nil {
				continue
			}
			req.Header.Set("User-Agent", "Mozilla/5.0 scaNNer/OpenRedirect")
			if opts != nil {
				opts.ApplyTo(req)
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

			var (
				how     string
				matched bool
				loc     string
			)
			switch {
			case isRedirectStatus(resp.StatusCode):
				loc = resp.Header.Get("Location")
				how, matched = classify(loc, evilHost)
				// Drain & close — CaptureResponse already read+restored,
				// but we still want to release the connection cleanly.
				io.Copy(io.Discard, resp.Body)
				resp.Body.Close()
			case resp.StatusCode == 200:
				// Read up to 64 KiB and scan for meta-refresh / JS-based
				// redirects that point at the evil host. CaptureResponse
				// already buffered the body and restored a fresh reader,
				// so we can re-read it here without losing rawResp.
				body, _ := io.ReadAll(io.LimitReader(resp.Body, 64*1024))
				resp.Body.Close()
				how, loc, matched = scanBodyForRedirect(body, evilHost)
			default:
				io.Copy(io.Discard, resp.Body)
				resp.Body.Close()
			}
			if !matched {
				continue
			}
			f := Finding{
				URL:         probeURL,
				Parameter:   param,
				Payload:     payload,
				StatusCode:  resp.StatusCode,
				Location:    loc,
				HowMatched:  how,
				Severity:    "HIGH",
				RawRequest:  rawReq,
				RawResponse: rawResp,
			}
			ur.Findings = append(ur.Findings, f)
			// BurpSuccessOnly contract: confirmed hits must be replayed
			// through the configured proxy so the operator sees them in
			// Burp history. No-op when BurpSuccessOnly is off.
			if opts != nil {
				opts.ReplayHit("GET", probeURL)
			}
			paramHit = true
			if stopOnHit {
				break
			}
		}
		_ = paramHit
	}
	return ur
}

func injectParam(u url.URL, key, value string) string {
	q := u.Query()
	q.Set(key, value)
	u.RawQuery = q.Encode()
	return u.String()
}

func isRedirectStatus(code int) bool {
	return code == 301 || code == 302 || code == 303 || code == 307 || code == 308
}

// classify decides whether the Location header is a successful redirect to
// our evil host (with bypass-friendly parsing) and returns a short label
// explaining the match style.
func classify(loc, evilHost string) (string, bool) {
	if loc == "" {
		return "", false
	}
	lower := strings.ToLower(loc)
	host := strings.ToLower(evilHost)

	// Strict: starts with scheme + host.
	if strings.HasPrefix(lower, "http://"+host) || strings.HasPrefix(lower, "https://"+host) {
		return "scheme://host prefix", true
	}
	// Scheme-only (no slashes) parser-bypass. Must be AFTER the "://"
	// checks above because "http:" is a prefix of "http://" and the more
	// specific match should win the label.
	if strings.HasPrefix(lower, "http:"+host) || strings.HasPrefix(lower, "https:"+host) {
		return "scheme:host (no slashes)", true
	}
	// Protocol-relative.
	if strings.HasPrefix(lower, "//"+host) {
		return "// protocol-relative", true
	}
	// Backslash variant some servers normalize.
	if strings.HasPrefix(lower, "\\\\"+host) || strings.HasPrefix(lower, "/\\"+host) {
		return "backslash protocol", true
	}
	// userinfo@host bypass (browsers ignore userinfo).
	if strings.Contains(lower, "@"+host) {
		return "userinfo @host bypass", true
	}
	return "", false
}

// Body-level detectors for 200 OK responses that redirect via meta-refresh
// or client-side JS. Pre-compiled so we don't re-parse on every probe.
var (
	metaRefreshRe = regexp.MustCompile(`(?is)<meta\s+http-equiv\s*=\s*["']?refresh["']?[^>]*content\s*=\s*["']\s*\d+\s*;\s*url\s*=\s*([^"'>\s]+)`)
	jsLocationRe  = regexp.MustCompile(`(?is)(?:window\.location(?:\.href|\.replace|\.assign)?|document\.location|location\.replace|location\.assign|location\.href|location)\s*(?:=|\(\s*)\s*["']([^"']+)["']`)
)

// scanBodyForRedirect inspects a 200-OK body for meta-refresh and JS
// location redirects pointing at evilHost. Returns the how-matched label,
// the redirect target, and whether a match was found.
func scanBodyForRedirect(body []byte, evilHost string) (string, string, bool) {
	if len(body) == 0 || evilHost == "" {
		return "", "", false
	}
	host := strings.ToLower(evilHost)
	if m := metaRefreshRe.FindSubmatch(body); m != nil {
		target := strings.TrimSpace(string(m[1]))
		if redirectTargetsHost(target, host) {
			return "meta-refresh", target, true
		}
	}
	if m := jsLocationRe.FindSubmatch(body); m != nil {
		target := strings.TrimSpace(string(m[1]))
		if redirectTargetsHost(target, host) {
			return "js-redirect", target, true
		}
	}
	return "", "", false
}

// redirectTargetsHost returns true if target string resolves to a redirect
// pointing at host. Reuses the same bypass-aware matching as classify().
func redirectTargetsHost(target, host string) bool {
	if target == "" {
		return false
	}
	lower := strings.ToLower(target)
	if strings.HasPrefix(lower, "http://"+host) || strings.HasPrefix(lower, "https://"+host) {
		return true
	}
	// Scheme-only (no slashes) parser-bypass — mirrors classify().
	if strings.HasPrefix(lower, "http:"+host) || strings.HasPrefix(lower, "https:"+host) {
		return true
	}
	if strings.HasPrefix(lower, "//"+host) {
		return true
	}
	if strings.HasPrefix(lower, "\\\\"+host) || strings.HasPrefix(lower, "/\\"+host) {
		return true
	}
	if strings.Contains(lower, "@"+host) {
		return true
	}
	return false
}

func newClient(timeout time.Duration, opts *shared.HTTPOptions) *http.Client {
	transport := &http.Transport{
		TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
		DialContext:     shared.BoundDialer(nil, timeout).DialContext,
	}
	if opts != nil {
		opts.ApplyTransport(transport)
	}
	return &http.Client{
		Timeout:   timeout,
		Transport: transport,
		// Do NOT follow redirects — we need to see the Location header.
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}
}
