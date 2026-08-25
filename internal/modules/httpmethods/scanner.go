package httpmethods

import (
	"crypto/tls"
	"fmt"
	"io"
	"net/http"
	"net/http/httputil"
	"scanner/internal/modules/shared"
	"strings"
	"sync"
	"time"
)

// ContentVariant defines a Content-Type + body pair to test
type ContentVariant struct {
	ContentType string `json:"content_type"`
	Label       string `json:"label"` // short display name
	Body        string `json:"-"`     // request body (not stored in results)
}

// Variants per method — body-accepting methods get multiple content-types.
// TRACE includes a tracer header so we can detect XST (Cross-Site Tracing)
// when the server reflects it back. WebDAV methods (PROPFIND/MKCOL/COPY/
// MOVE/LOCK/UNLOCK) probe for misconfigured WebDAV which leaks listings
// or accepts file writes. PUT gets an "upload probe" variant that
// tries to write an .html file and looks for a 200/201/204 success.
var methodVariants = map[string][]ContentVariant{
	"GET":     {{Label: "No Body"}},
	"HEAD":    {{Label: "No Body"}},
	"DELETE":  {{Label: "No Body"}, {ContentType: "application/json", Label: "JSON", Body: `{"id":1}`}},
	"OPTIONS": {{Label: "No Body"}},
	"TRACE": {
		// Custom header echoed back in a successful TRACE response =
		// XST surface (older browsers / plugin contexts). We sniff for
		// "X-XST-Marker: scaNNer-trace" anywhere in the response body.
		{Label: "XST Probe", ContentType: "X-XST-Marker: scaNNer-trace"},
	},
	"CONNECT": {{Label: "No Body"}},
	// WebDAV methods. PROPFIND with depth=0 is the standard
	// "is WebDAV alive" probe — a 207 Multi-Status response confirms it.
	"PROPFIND": {{Label: "Depth 0", ContentType: "application/xml", Body: `<?xml version="1.0"?><a:propfind xmlns:a="DAV:"><a:prop><a:resourcetype/></a:prop></a:propfind>`}},
	"MKCOL":    {{Label: "WebDAV mkdir"}},
	"COPY":     {{Label: "WebDAV copy", ContentType: "Destination: /scanner-copy-test"}},
	"MOVE":     {{Label: "WebDAV move", ContentType: "Destination: /scanner-move-test"}},
	"LOCK":     {{Label: "WebDAV lock", ContentType: "application/xml", Body: `<?xml version="1.0"?><lockinfo xmlns="DAV:"><lockscope><exclusive/></lockscope><locktype><write/></locktype></lockinfo>`}},
	"UNLOCK":   {{Label: "WebDAV unlock"}},
	"POST": {
		{Label: "No Body"},
		{ContentType: "application/x-www-form-urlencoded", Label: "Form", Body: "key=value&test=1"},
		{ContentType: "application/json", Label: "JSON", Body: `{"key":"value","test":1}`},
		{ContentType: "application/xml", Label: "XML", Body: `<?xml version="1.0"?><root><key>value</key></root>`},
		{ContentType: "multipart/form-data; boundary=----scaNNer", Label: "Multipart", Body: "------scaNNer\r\nContent-Disposition: form-data; name=\"file\"; filename=\"test.txt\"\r\nContent-Type: text/plain\r\n\r\ntest\r\n------scaNNer--\r\n"},
		{ContentType: "text/plain", Label: "Plain Text", Body: "test data"},
	},
	"PUT": {
		{Label: "No Body"},
		{ContentType: "application/x-www-form-urlencoded", Label: "Form", Body: "key=value"},
		{ContentType: "application/json", Label: "JSON", Body: `{"key":"value"}`},
		{ContentType: "application/xml", Label: "XML", Body: `<?xml version="1.0"?><root><key>value</key></root>`},
		{ContentType: "application/octet-stream", Label: "Binary", Body: "BINARYDATA"},
		{ContentType: "text/plain", Label: "Plain Text", Body: "test data"},
	},
	"PATCH": {
		{Label: "No Body"},
		{ContentType: "application/json", Label: "JSON", Body: `{"key":"updated"}`},
		{ContentType: "application/json-patch+json", Label: "JSON Patch", Body: `[{"op":"replace","path":"/key","value":"updated"}]`},
		{ContentType: "application/x-www-form-urlencoded", Label: "Form", Body: "key=updated"},
		{ContentType: "application/xml", Label: "XML", Body: `<?xml version="1.0"?><root><key>updated</key></root>`},
	},
}

var dangerousSet = map[string]bool{
	"PUT": true, "DELETE": true, "TRACE": true, "CONNECT": true,
	"PROPFIND": true, "MKCOL": true, "COPY": true, "MOVE": true,
	"LOCK": true, "UNLOCK": true,
}

// MethodResult holds the response for one method+variant test
type MethodResult struct {
	Method      string `json:"method"`
	ContentType string `json:"content_type"` // request content-type used
	Variant     string `json:"variant"`      // short label
	StatusCode  int    `json:"status_code"`
	Status      string `json:"status"`
	Size        int64  `json:"size"`
	RespCT      string `json:"resp_content_type"` // response content-type
	Allow       string `json:"allow"`
	Dangerous   bool   `json:"dangerous"`
	Note        string `json:"note,omitempty"` // free-form annotation (e.g. "XST confirmed")
	Error       string `json:"error,omitempty"`
	RawRequest  string `json:"raw_request,omitempty"`
	RawResponse string `json:"raw_response,omitempty"`
}

// truncateRaw caps a raw HTTP dump to maxBytes, appending an ellipsis marker.

// methodClientTimeout honors a per-scan / global request-timeout override
// (opts.Timeout, set by the handler's applyHTTPTuning) with a 15s fallback.
func methodClientTimeout(opts *shared.HTTPOptions) time.Duration {
	if opts != nil && opts.Timeout > 0 {
		return opts.Timeout
	}
	return 15 * time.Second
}

func truncateRaw(s string, max int) string {
	if len(s) <= max {
		return s
	}
	return s[:max] + "\n\n... [truncated " + fmt.Sprintf("%d", len(s)-max) + " bytes]"
}

type URLResult struct {
	URL     string         `json:"url"`
	Methods []MethodResult `json:"methods"`
	Error   string         `json:"error,omitempty"`
}

type ScanResult struct {
	Results []URLResult `json:"results"`
}

type ProgressFunc func(done int, msg string)

// PartialFunc fires after each variant test so the UI can stream results live.
type PartialFunc func(*ScanResult)

// TotalTestsPerURL returns the precise number of (method, variant) probes that
// testURL will perform per URL — used to size the progress denominator so the
// dashboard percentage tracks individual probes, not URL count.
func TotalTestsPerURL() int {
	n := 0
	for _, method := range []string{"GET", "HEAD", "POST", "PUT", "DELETE", "PATCH", "OPTIONS", "TRACE", "CONNECT", "PROPFIND", "MKCOL", "COPY", "MOVE", "LOCK", "UNLOCK"} {
		v := methodVariants[method]
		if v == nil {
			n++
		} else {
			n += len(v)
		}
	}
	return n
}

func Scan(urls []string, opts *shared.HTTPOptions, progress ProgressFunc) *ScanResult {
	return ScanWithPartial(urls, opts, 3, progress, nil)
}

func ScanWithPartial(urls []string, opts *shared.HTTPOptions, concurrency int, progress ProgressFunc, partial PartialFunc) *ScanResult {
	if concurrency <= 0 {
		concurrency = 3
	}
	result := &ScanResult{}
	var mu sync.Mutex
	// inProgress holds URL → live URLResult pointers for URLs whose tests are
	// still running. Live snapshots merge these with completed results so the
	// UI sees rows fill in row-by-row.
	inProgress := map[string]*URLResult{}
	sem := make(chan struct{}, concurrency)
	var wg sync.WaitGroup

	// Track cumulative individual tests done across all URLs for percentage.
	testsDone := 0
	testsPerURL := TotalTestsPerURL()

	// Audit fix: build ONE transport for the entire scan. Previously
	// testURLInto allocated a fresh http.Transport per URL — each one
	// got its own idle conn pool and was RegisterTransport'd via
	// ApplyTransport, so opts.transports grew to size N and FinishScan's
	// CloseIdleConnections walked N transports. One shared transport
	// reuses TCP connections across URLs targeting the same host and
	// keeps the cleanup pool flat.
	sharedTransport := &http.Transport{
		TLSClientConfig:     &tls.Config{InsecureSkipVerify: true},
		DialContext:         shared.BoundDialer(opts, 5*time.Second).DialContext,
		MaxIdleConns:        100,
		MaxIdleConnsPerHost: 50,
		IdleConnTimeout:     90 * time.Second,
	}
	if opts != nil {
		opts.ApplyTransport(sharedTransport)
	}
	sharedClient := &http.Client{
		Timeout:   methodClientTimeout(opts),
		Transport: sharedTransport,
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}

	// Audit S2: per-URL pushPartial was the canonical O(N²) site —
	// every completed URL would deep-copy every prior URL's result and
	// the handler would marshal it. Throttle to 2s at the source; the
	// final result is always flushed via Force()+pushPartial() at scan end.
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
		// Append in-progress URLResults (deep-copied to avoid concurrent mutation)
		for _, ur := range inProgress {
			cp := URLResult{URL: ur.URL, Methods: append([]MethodResult(nil), ur.Methods...)}
			snap.Results = append(snap.Results, cp)
		}
		mu.Unlock()
		partial(snap)
	}

	// Reachability preflight: skip TLS-dead targets up front.
	if opts != nil && opts.PreflightEnabled {
		live, dead := shared.FilterReachable(opts.Ctx, opts, urls, opts.PreflightTimeout, concurrency)
		for t, reason := range dead {
			result.Results = append(result.Results, URLResult{URL: t, Error: "unreachable — " + reason})
		}
		urls = live
	}

	for _, u := range urls {
		// Cancellation fast-path (audit B39). Without this check, a
		// cancelled scan kept queueing every URL in the list — each
		// goroutine still ran testURLInto which itself respects opts,
		// but we wasted goroutine churn and held the wg open until they
		// all returned. Now we abandon the queue the moment cancel hits.
		if opts != nil && opts.Done() {
			break
		}
		wg.Add(1)
		sem <- struct{}{}
		go func(targetURL string) {
			defer wg.Done()
			defer func() { <-sem }()

			urlResult := &URLResult{URL: targetURL}
			mu.Lock()
			inProgress[targetURL] = urlResult
			startCount := testsDone
			mu.Unlock()

			// Audit fix: do NOT hold mu while calling progress() — the
			// handler's progress callback issues a SQLite UPDATE which
			// blocks every other URL worker behind one fsync. Snapshot
			// the counter under mu, release, then fire the callback.
			if progress != nil {
				progress(startCount, fmt.Sprintf("Testing %s (%d probes per URL)", targetURL, testsPerURL))
			}

			testURLInto(urlResult, sharedClient, &mu, opts, func(method, variant string, code int, danger bool) {
				mu.Lock()
				testsDone++
				cur := testsDone
				mu.Unlock()
				if progress != nil {
					mark := "✓"
					if code == 405 || code == 501 || code == 415 {
						mark = "·"
					}
					if danger {
						mark = "⚠"
					}
					progress(cur, fmt.Sprintf("%s %s %s [%s] → %d", targetURL, mark, method, variant, code))
				}
				pushPartial()
			})

			mu.Lock()
			delete(inProgress, targetURL)
			result.Results = append(result.Results, *urlResult)
			cur := testsDone
			mu.Unlock()
			if progress != nil {
				dangerous := 0
				allowed := 0
				for _, m := range urlResult.Methods {
					if m.Status == "Allowed" {
						allowed++
					}
					if m.Dangerous && m.Status == "Allowed" {
						dangerous++
					}
				}
				progress(cur, fmt.Sprintf("%s done — %d tests, %d allowed, %d dangerous", targetURL, len(urlResult.Methods), allowed, dangerous))
			}
			pushPartial()
		}(u)
	}
	wg.Wait()
	// Final snapshot is mandatory — the throttle may have skipped the
	// last per-URL pushPartial, but the handler still flushes its DB
	// write after Scan returns with the full marshaled result.
	throttle.Force()
	pushPartial()
	return result
}

// perVariantLog fires after each method+variant test completes
type perVariantLog func(method, variant string, code int, dangerous bool)

// testURL is kept for backward compatibility (e.g. external callers) — it
// delegates to testURLInto with a freshly allocated URLResult + transport.
func testURL(targetURL string, opts *shared.HTTPOptions, onVariant perVariantLog) *URLResult {
	transport := &http.Transport{
		TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
		DialContext:     shared.BoundDialer(opts, 5*time.Second).DialContext,
	}
	if opts != nil {
		opts.ApplyTransport(transport)
	}
	client := &http.Client{
		Timeout:   methodClientTimeout(opts),
		Transport: transport,
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}
	r := &URLResult{URL: targetURL}
	var mu sync.Mutex
	testURLInto(r, client, &mu, opts, onVariant)
	return r
}

// testURLInto runs the variant probes against targetURL and appends each
// MethodResult to result.Methods as it completes — onVariant fires AFTER the
// append, so live partial snapshots can pick up the new row safely. mu is
// the shared mutex that ScanWithPartial uses to guard inProgress snapshots
// from racing with the per-variant append into result.Methods (audit fix).
func testURLInto(result *URLResult, client *http.Client, mu *sync.Mutex, opts *shared.HTTPOptions, onVariant perVariantLog) {
	targetURL := result.URL
	if !strings.HasPrefix(targetURL, "http://") && !strings.HasPrefix(targetURL, "https://") {
		targetURL = "https://" + targetURL
		result.URL = targetURL
	}

	// Test each method with its variants
	methods := []string{"GET", "HEAD", "POST", "PUT", "DELETE", "PATCH", "OPTIONS", "TRACE", "CONNECT", "PROPFIND", "MKCOL", "COPY", "MOVE", "LOCK", "UNLOCK"}
	replayed := false
	for _, method := range methods {
		// Audit fix: respect cancel between methods so a killswitch trip
		// doesn't keep blasting variants for an already-cancelled scan.
		if opts != nil && opts.Done() {
			return
		}
		variants := methodVariants[method]
		if variants == nil {
			variants = []ContentVariant{{Label: "No Body"}}
		}
		for _, v := range variants {
			// Audit fix: also short-circuit between variants — a slow
			// 15s timeout TRACE probe should not run after cancel.
			if opts != nil && opts.Done() {
				return
			}
			mr := testVariant(client, targetURL, method, v, opts)
			// Audit fix: hold mu around the append because pushPartial()
			// iterates inProgress[targetURL].Methods under the same mu
			// from other goroutines. Without locking here, the slice
			// grow during append races with the copy in pushPartial.
			if mu != nil {
				mu.Lock()
			}
			result.Methods = append(result.Methods, mr)
			if mu != nil {
				mu.Unlock()
			}
			if onVariant != nil {
				onVariant(mr.Method, mr.Variant, mr.StatusCode, mr.Dangerous && mr.Status == "Allowed")
			}
			if !replayed && mr.StatusCode > 0 {
				// URL is reachable — replay once so Burp sees a valid entry for it.
				opts.ReplayHit("GET", targetURL)
				replayed = true
			}
		}
	}
}

func testVariant(client *http.Client, targetURL, method string, v ContentVariant, opts *shared.HTTPOptions) MethodResult {
	mr := MethodResult{
		Method:      method,
		ContentType: v.ContentType,
		Variant:     v.Label,
		Dangerous:   dangerousSet[method],
	}

	var body io.Reader
	if v.Body != "" {
		body = strings.NewReader(v.Body)
	}

	req, err := http.NewRequest(method, targetURL, body)
	if err != nil {
		mr.Status = "Error"
		mr.Error = err.Error()
		return mr
	}
	req.Header.Set("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36")
	req.Header.Set("Accept", "*/*")
	if v.ContentType != "" {
		req.Header.Set("Content-Type", v.ContentType)
	}
	// Audit fix: PROPFIND without Depth: gets a 400 from any standards-
	// compliant WebDAV server (RFC 4918 §9.1) — the module's WebDAV probe
	// was therefore a false negative. "Depth: 0" asks for just the
	// resource itself, matching the body's xmlns:a="DAV:" prop request.
	if method == "PROPFIND" {
		req.Header.Set("Depth", "0")
	}
	// Audit fix: TRACE XST detection was promised by ContentType field
	// "X-XST-Marker: scaNNer-trace" but the code never actually sent it
	// as a request header. Servers vulnerable to XST echo every header
	// back in the response body — without the marker in the REQUEST,
	// there's nothing to detect. Set a custom header on TRACE probes.
	if method == "TRACE" {
		req.Header.Set("X-XST-Marker", "scaNNer-trace")
	}
	if opts != nil {
		opts.ApplyTo(req)
	}
	req = opts.BindContext(req)

	if dump, err := httputil.DumpRequestOut(req, true); err == nil {
		// Audit fix: redact Authorization / Cookie / API-key values
		// from the persisted dump. opts.ApplyTo just injected the
		// user-supplied credentials into the request and DumpRequestOut
		// serializes every header verbatim — without redaction those
		// land in scan.Result JSON and render verbatim in the UI.
		mr.RawRequest = truncateRaw(shared.RedactSecretHeaders(string(dump)), 4*1024)
	}

	resp, err := client.Do(req)
	if err != nil {
		mr.Status = "Error"
		mr.Error = simplifyError(err.Error())
		return mr
	}
	defer resp.Body.Close()

	rawResp := ""
	if dump, err := httputil.DumpResponse(resp, true); err == nil {
		// Redact Set-Cookie / token-bearing response headers too.
		rawResp = shared.RedactSecretHeaders(string(dump))
		mr.RawResponse = truncateRaw(rawResp, 16*1024)
	} else {
		// Fallback: at least keep headers readable
		io.Copy(io.Discard, resp.Body)
	}

	mr.StatusCode = resp.StatusCode
	mr.Size = resp.ContentLength
	mr.RespCT = resp.Header.Get("Content-Type")

	// Audit fix: actually look for XST reflection. If the server echoed
	// our request header back in the TRACE response body, that's XST.
	if method == "TRACE" && strings.Contains(rawResp, "X-XST-Marker: scaNNer-trace") {
		mr.Note = "XST confirmed — server echoed X-XST-Marker in TRACE response"
		mr.Dangerous = true
	}

	if allow := resp.Header.Get("Allow"); allow != "" {
		mr.Allow = allow
	}

	switch {
	case resp.StatusCode >= 200 && resp.StatusCode < 300:
		// Real success — the dangerous method actually executed.
		mr.Status = "Allowed"
	case resp.StatusCode >= 300 && resp.StatusCode < 400:
		// Redirect — the operation didn't actually happen, the server is
		// punting elsewhere. Don't flag this as dangerous.
		mr.Status = "Redirect"
		mr.Dangerous = false
	case resp.StatusCode == 405:
		mr.Status = "Not Allowed"
		mr.Dangerous = false
	case resp.StatusCode == 501:
		mr.Status = "Not Implemented"
		mr.Dangerous = false
	case resp.StatusCode == 403:
		mr.Status = "Forbidden"
		mr.Dangerous = false
	case resp.StatusCode == 415:
		mr.Status = "Unsupported Media Type"
		mr.Dangerous = false
	default:
		mr.Status = fmt.Sprintf("%d", resp.StatusCode)
		if resp.StatusCode >= 400 {
			mr.Dangerous = false
		}
	}

	return mr
}

func simplifyError(e string) string {
	if strings.Contains(e, "connection refused") {
		return "Connection refused"
	}
	if strings.Contains(e, "timeout") || strings.Contains(e, "Timeout") {
		return "Timeout"
	}
	if strings.Contains(e, "no such host") {
		return "DNS resolution failed"
	}
	if len(e) > 80 {
		return e[:80]
	}
	return e
}
