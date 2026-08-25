package shared

import (
	"context"
	"crypto/tls"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"sort"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

// HTTPOptions holds user-supplied custom headers and cookies for web modules
type HTTPOptions struct {
	Headers         map[string]string `json:"headers,omitempty"`
	Cookies         map[string]string `json:"cookies,omitempty"`
	ProxyURL        string            `json:"proxy_url,omitempty"`
	UserAgent       string            `json:"user_agent,omitempty"`
	BurpSuccessOnly bool              `json:"burp_success_only,omitempty"` // when true, probe traffic skips the proxy — confirmed hits are replayed via ReplayHit
	Timeout         time.Duration     `json:"-"`
	Ctx             context.Context   `json:"-"` // cancellation context for all requests

	// Outbound-binding killswitch fields. NetworkInterface is the name
	// the user picked in Settings; LocalAddr is the IPv4 we resolved
	// from that name. When LocalAddr is non-nil, every net.Dialer in
	// the scanner pipeline must bind its source IP to it so traffic
	// originates from the pinned interface.
	//
	// Both default to zero values — empty NetworkInterface + nil
	// LocalAddr means default routing (no binding enforced).
	NetworkInterface string       `json:"network_interface,omitempty"`
	LocalAddr        *net.TCPAddr `json:"-"`

	// Reachability preflight. When PreflightEnabled is true, web modules run
	// FilterReachable over their targets first and skip any that can't complete
	// a TCP+TLS handshake (a host that resets/times out the TLS handshake would
	// otherwise make the tool grind through thousands of failing requests). A
	// bad/invalid certificate still counts as reachable (the handshake completes
	// under InsecureSkipVerify). PreflightTimeout caps each probe (0 = default).
	PreflightEnabled bool          `json:"-"`
	PreflightTimeout time.Duration `json:"-"`

	// Error tracking — set by the handler before launching a scan. RecordError
	// increments an in-options counter and, once it crosses ErrorThreshold (default 3),
	// fires OnWarning so the UI can surface the issue to the user.
	OnWarning      func(message string) `json:"-"`
	ErrorThreshold int                  `json:"-"`
	errMu          sync.Mutex
	errCount       int
	errSources     map[string]int

	// transports holds every http.Transport built via NewHTTPClient /
	// ApplyTransport for the lifetime of this scan, so FinishScan / Cancel
	// can flush their idle-connection pools deterministically (rather than
	// waiting for GC). Tracked here because each module constructs its own
	// client and the handler has no direct handle otherwise.
	transportsMu sync.Mutex
	transports   []*http.Transport
	// root points at the scan-registered original when this is a WithCtx-derived
	// copy; RegisterTransport funnels into root so the copy's transports land in
	// the pool scanmgr actually flushes on finish/cancel. nil on the original.
	root *HTTPOptions
}

// ClassifyError reduces a raw error to a short category used in user-facing
// warnings (e.g. "timeout", "connection refused", "DNS"). Empty when err is nil.
func ClassifyError(err error) string {
	if err == nil {
		return ""
	}
	s := err.Error()
	low := strings.ToLower(s)
	switch {
	case strings.Contains(low, "context canceled"), strings.Contains(low, "context deadline"):
		return ""
	case strings.Contains(low, "timeout"), strings.Contains(low, "deadline exceeded"):
		return "timeout"
	case strings.Contains(low, "connection refused"):
		return "connection refused"
	case strings.Contains(low, "no such host"), strings.Contains(low, "dns"):
		return "DNS lookup failure"
	case strings.Contains(low, "tls"), strings.Contains(low, "x509"), strings.Contains(low, "certificate"):
		return "TLS/cert error"
	case strings.Contains(low, "connection reset"):
		return "connection reset"
	case strings.Contains(low, "eof"):
		return "unexpected EOF"
	default:
		return "network error"
	}
}

// ResetErrors clears the running error counter and source breakdown.
// Suite-style callers (e.g. advancedweb) invoke this at stage boundaries
// so errors from the previous stage (DNS lookups, say) don't visually
// bleed into the next stage's warning summary. Safe to call concurrently.
func (o *HTTPOptions) ResetErrors() {
	if o == nil {
		return
	}
	o.errMu.Lock()
	o.errCount = 0
	o.errSources = nil
	o.errMu.Unlock()
}

// RecordError bumps the per-scan error counter. Once the count exceeds
// ErrorThreshold (default 3), OnWarning fires with a summary message every time
// so the UI can keep the count current. Safe to call concurrently.
func (o *HTTPOptions) RecordError(source string) {
	if o == nil || source == "" {
		return
	}
	o.errMu.Lock()
	if o.errSources == nil {
		o.errSources = map[string]int{}
	}
	o.errCount++
	o.errSources[source]++
	threshold := o.ErrorThreshold
	if threshold <= 0 {
		threshold = 3
	}
	over := o.errCount > threshold
	count := o.errCount
	cb := o.OnWarning
	srcs := make([]string, 0, len(o.errSources))
	for k, v := range o.errSources {
		srcs = append(srcs, fmt.Sprintf("%s×%d", k, v))
	}
	o.errMu.Unlock()
	if !over || cb == nil {
		return
	}
	sort.Strings(srcs)
	cb(fmt.Sprintf("%d errors so far — %s", count, strings.Join(srcs, ", ")))
}

// ErrorSummary returns the total recorded probe-error count and a sorted
// human breakdown ("connection refused×42, timeout×18"). Discovery stages use
// it to explain a "0 live services" result: a pile of refused/timeout/DNS
// errors means the targets were UNREACHABLE from the scanner (down, firewalled,
// geo-blocked, or no route), not that the hosts genuinely run no services.
func (o *HTTPOptions) ErrorSummary() (int, string) {
	if o == nil {
		return 0, ""
	}
	o.errMu.Lock()
	defer o.errMu.Unlock()
	if o.errCount == 0 {
		return 0, ""
	}
	srcs := make([]string, 0, len(o.errSources))
	for k, v := range o.errSources {
		srcs = append(srcs, fmt.Sprintf("%s×%d", k, v))
	}
	sort.Strings(srcs)
	return o.errCount, strings.Join(srcs, ", ")
}

// Done returns whether the scan has been cancelled
func (o *HTTPOptions) Done() bool {
	if o == nil || o.Ctx == nil {
		return false
	}
	select {
	case <-o.Ctx.Done():
		return true
	default:
		return false
	}
}

// BindContext attaches the scan context to an http.Request (so Client.Do can be cancelled)
func (o *HTTPOptions) BindContext(req *http.Request) *http.Request {
	if o == nil || o.Ctx == nil {
		return req
	}
	return req.WithContext(o.Ctx)
}

// ApplyTo injects custom headers, cookies, and user-agent into an http.Request
func (o *HTTPOptions) ApplyTo(req *http.Request) {
	if o == nil {
		return
	}
	if o.UserAgent != "" {
		req.Header.Set("User-Agent", o.UserAgent)
	}
	for k, v := range o.Headers {
		if k != "" && v != "" {
			req.Header.Set(k, v)
		}
	}
	for name, val := range o.Cookies {
		if name != "" && val != "" {
			req.AddCookie(&http.Cookie{Name: name, Value: val})
		}
	}
}

// ApplyTransport modifies an existing http.Transport to use the proxy from options.
// Call this on every transport created in web modules so global proxy settings work.
// When BurpSuccessOnly is set, probe traffic bypasses the proxy; use ReplayHit on
// confirmed findings to push only successful results through. The transport is also
// registered for cleanup at scan-end via CloseIdleConnections().
func (o *HTTPOptions) ApplyTransport(t *http.Transport) {
	if o == nil {
		return
	}
	o.RegisterTransport(t)
	if o.ProxyURL == "" || o.BurpSuccessOnly {
		return
	}
	if u, err := url.Parse(o.ProxyURL); err == nil {
		t.Proxy = http.ProxyURL(u)
	}
}

// RegisterTransport remembers a transport so CloseIdleConnections() can
// flush its TCP pool when the scan ends. Safe to call repeatedly with
// the same transport; nils are ignored.
func (o *HTTPOptions) RegisterTransport(t *http.Transport) {
	if o == nil || t == nil {
		return
	}
	// A WithCtx-derived copy funnels registration into the scan-registered
	// original, so its transports are flushed by scanmgr's CloseIdleConnections
	// on finish/cancel instead of leaking until GC.
	if o.root != nil {
		o.root.RegisterTransport(t)
		return
	}
	o.transportsMu.Lock()
	defer o.transportsMu.Unlock()
	for _, existing := range o.transports {
		if existing == t {
			return
		}
	}
	o.transports = append(o.transports, t)
}

// WithCtx returns a shallow copy of this HTTPOptions whose Ctx field
// has been swapped for the supplied context. Public scalar/slice/map
// fields (Headers, Cookies, NetworkInterface, LocalAddr, etc.) are
// copied by value so the killswitch's source-IP binding is preserved.
// Crucially, the returned copy funnels transport registration back into
// the scan-registered original (via the `root` link + RegisterTransport):
// any http.Transport registered through the derived copy ends up in the
// original's cleanup pool, so scanmgr's CloseIdleConnections() on the
// original still flushes every socket at scan end. Use this when a stage
// needs a derived deadline / cancellation but must remain attached to the
// parent scan for transport accounting (advancedweb stage 10 deadline copy).
// Returns nil when o is nil.
func (o *HTTPOptions) WithCtx(ctx context.Context) *HTTPOptions {
	if o == nil {
		return nil
	}
	cp := &HTTPOptions{
		Headers:          o.Headers,
		Cookies:          o.Cookies,
		ProxyURL:         o.ProxyURL,
		UserAgent:        o.UserAgent,
		BurpSuccessOnly:  o.BurpSuccessOnly,
		Timeout:          o.Timeout,
		Ctx:              ctx,
		NetworkInterface: o.NetworkInterface,
		LocalAddr:        o.LocalAddr,
		OnWarning:        o.OnWarning,
		ErrorThreshold:   o.ErrorThreshold,
	}
	// Point at the ultimate scan-registered root (collapse WithCtx chains) so
	// RegisterTransport on the copy lands in the root's pool. sync.Mutex is not
	// copyable, so we funnel through the root rather than alias the slice/mutex.
	if o.root != nil {
		cp.root = o.root
	} else {
		cp.root = o
	}
	return cp
}

// CloseIdleConnections drops every TCP socket held in the idle pool of
// each transport this option set has handed out. Called at scan
// termination (done / error / cancelled) so we don't leak sockets to
// the target between runs. Safe to call multiple times; subsequent
// calls are no-ops once the slice is drained.
func (o *HTTPOptions) CloseIdleConnections() {
	if o == nil {
		return
	}
	o.transportsMu.Lock()
	transports := o.transports
	o.transports = nil
	o.transportsMu.Unlock()
	for _, t := range transports {
		if t != nil {
			t.CloseIdleConnections()
		}
	}
}

// replayHitSem caps the number of in-flight ReplayHit goroutines
// (audit B22). Without this, a chatty scan could spawn thousands of
// fire-and-forget replay goroutines — each holding an HTTP client +
// proxy conn — and over the 2-day audit window goroutine count climbed
// into the tens of thousands. 32 in-flight is enough for a busy scan
// to feed Burp without ever queueing visibly to the operator.
var replayHitSem = make(chan struct{}, 32)

// ReplayHit pushes a single confirmed URL through the configured proxy so the
// user's interception proxy (e.g. Burp) observes only successful findings.
// No-op if no proxy is configured or BurpSuccessOnly is disabled.
// Method defaults to GET when empty. Fire-and-forget: runs in its own goroutine,
// errors are swallowed, and the scan ctx aborts it on cancel.
func (o *HTTPOptions) ReplayHit(method, targetURL string) {
	if o == nil || !o.BurpSuccessOnly || o.ProxyURL == "" || targetURL == "" {
		return
	}
	if method == "" {
		method = http.MethodGet
	}
	proxyParsed, err := url.Parse(o.ProxyURL)
	if err != nil {
		return
	}
	// Acquire a replay slot. If the queue is full, abandon the replay
	// rather than block the calling scanner goroutine (replay is
	// best-effort — losing a few when the proxy is slow is fine).
	select {
	case replayHitSem <- struct{}{}:
	default:
		return
	}
	go func() {
		defer func() { <-replayHitSem }()
		client := &http.Client{
			Timeout: 10 * time.Second,
			Transport: &http.Transport{
				Proxy:           http.ProxyURL(proxyParsed),
				TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
				// Source binding propagates from o (the scan's options)
				// — replay traffic must obey the same killswitch rule
				// as the original probe.
				DialContext: BoundDialer(o, 5*time.Second).DialContext,
			},
			CheckRedirect: func(req *http.Request, via []*http.Request) error {
				return http.ErrUseLastResponse
			},
		}
		req, err := http.NewRequest(method, targetURL, nil)
		if err != nil {
			return
		}
		if o.Ctx != nil {
			req = req.WithContext(o.Ctx)
		}
		o.ApplyTo(req)
		resp, err := client.Do(req)
		if err != nil {
			return
		}
		resp.Body.Close()
	}()
}

// globalLocalAddr is the process-wide outbound-binding fallback. When
// the user pins an interface in Settings, the handler calls
// SetGlobalLocalAddr; every BoundDialer call thereafter uses this
// address unless the caller's opts explicitly override it.
//
// Why a package-level atomic instead of threading opts through every
// dialer call site: there are 24+ inline `(&net.Dialer{...}).DialContext`
// sites scattered across the modules. Most of them live in helper
// functions whose signatures don't currently accept opts. Adding opts
// to all 24 would force signature changes in dozens of intermediate
// callers — and any one missed would silently leak through the default
// route, which is exactly what the killswitch is supposed to prevent.
// A single package-level fallback is the safer pattern: every dialer
// honors it by construction.
var globalLocalAddr atomic.Pointer[net.TCPAddr]

// SetGlobalLocalAddr installs the process-wide outbound-binding source
// address. Called by handlers.BuildHTTPOptions on each scan launch so
// the latest Settings value is picked up. Pass nil to clear (default
// routing).
func SetGlobalLocalAddr(addr *net.TCPAddr) {
	globalLocalAddr.Store(addr)
}

// GlobalLocalAddr returns the current process-wide binding (or nil).
// Exposed for the runtime iface monitor's killswitch check.
func GlobalLocalAddr() *net.TCPAddr {
	return globalLocalAddr.Load()
}

// BoundDialer builds a net.Dialer whose source IP is pinned to the
// interface the user selected in Settings. Resolution order:
//
//  1. opts.LocalAddr (per-scan override — usually wins for clarity).
//  2. globalLocalAddr (process-wide fallback set by handler).
//  3. nil — stdlib default, no binding (the user picked "Default
//     (system routing)" in Settings).
//
// Every Go-side outbound origination (HTTP client transports, raw
// net.Dial sites in module scanners) must build its Dialer through
// this helper instead of inline `&net.Dialer{}`. Centralizing means a
// single edit changes the binding behavior across all outbound sites.
//
// LocalAddr on a net.Dialer is consulted at dial-time and passed
// straight to the kernel's bind() syscall. No CAP_NET_RAW or root
// needed for outbound source binding.
func BoundDialer(opts *HTTPOptions, timeout time.Duration) *net.Dialer {
	// ControlContext runs the process-wide network throttle before each connect
	// (no-op unless the health governor has installed a throttle). It's a
	// per-connection pre-connect hook that respects the dial's context, so a
	// throttled connect still cancels immediately on scan Stop.
	d := &net.Dialer{Timeout: timeout, ControlContext: throttleControl}
	if opts != nil && opts.LocalAddr != nil {
		d.LocalAddr = opts.LocalAddr
		return d
	}
	if g := globalLocalAddr.Load(); g != nil {
		d.LocalAddr = g
	}
	return d
}

// NewHTTPClient creates an http.Client with proxy and timeout from options.
// The transport is registered with the options so its idle pool is closed
// at scan termination.
func (o *HTTPOptions) NewHTTPClient() *http.Client {
	timeout := 10 * time.Second
	if o != nil && o.Timeout > 0 {
		timeout = o.Timeout
	}

	transport := &http.Transport{
		TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
		// Source-IP binding via BoundDialer — see helper docs. Nil
		// LocalAddr = no binding (default mode), so this is safe even
		// when the killswitch isn't engaged.
		DialContext:     BoundDialer(o, 5*time.Second).DialContext,
		// Idle conn caps (audit B48). Without these the default unlimited
		// pool plus typical scanner traffic (thousands of distinct hosts)
		// kept ~10k stale keepalive conns open over a 2-day run, each
		// burning a goroutine in Go's HTTP machinery. 100 conns / 50 per
		// host is enough for any realistic concurrent scan; older idle
		// conns are recycled after 90 seconds.
		MaxIdleConns:        100,
		MaxIdleConnsPerHost: 50,
		IdleConnTimeout:     90 * time.Second,
	}

	if o != nil && o.ProxyURL != "" && !o.BurpSuccessOnly {
		if proxyURL, err := url.Parse(o.ProxyURL); err == nil {
			transport.Proxy = http.ProxyURL(proxyURL)
		}
	}
	o.RegisterTransport(transport)

	return &http.Client{
		Timeout:   timeout,
		Transport: transport,
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}
}

// Preset suggestions shown in the UI
type HeaderPreset struct {
	Name        string `json:"name"`
	Value       string `json:"value"`
	Description string `json:"description"`
	Category    string `json:"category"` // "auth", "common", "proxy", "debug"
}

type CookiePreset struct {
	Name        string `json:"name"`
	Placeholder string `json:"placeholder"`
	Description string `json:"description"`
	Category    string `json:"category"`
}

var HeaderPresets = []HeaderPreset{
	// Auth
	{Name: "Authorization", Value: "Bearer <token>", Description: "JWT / OAuth Bearer token", Category: "auth"},
	{Name: "Authorization", Value: "Basic <base64>", Description: "HTTP Basic authentication", Category: "auth"},
	{Name: "X-API-Key", Value: "<api-key>", Description: "API key header", Category: "auth"},
	{Name: "X-Auth-Token", Value: "<token>", Description: "Custom auth token", Category: "auth"},
	// Common
	{Name: "Accept", Value: "application/json", Description: "Request JSON responses", Category: "common"},
	{Name: "Accept-Language", Value: "en-US,en;q=0.9", Description: "Language preference", Category: "common"},
	{Name: "Referer", Value: "https://example.com", Description: "Referer header", Category: "common"},
	{Name: "Origin", Value: "https://example.com", Description: "CORS origin header", Category: "common"},
	{Name: "User-Agent", Value: "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36", Description: "Custom User-Agent", Category: "common"},
	// Proxy / Forward
	{Name: "X-Forwarded-For", Value: "127.0.0.1", Description: "Spoofed client IP (proxy bypass)", Category: "proxy"},
	{Name: "X-Real-IP", Value: "127.0.0.1", Description: "Real IP (nginx)", Category: "proxy"},
	{Name: "X-Forwarded-Host", Value: "localhost", Description: "Forwarded host header", Category: "proxy"},
	{Name: "X-Original-URL", Value: "/admin", Description: "URL override (IIS/nginx bypass)", Category: "proxy"},
	{Name: "X-Rewrite-URL", Value: "/admin", Description: "URL rewrite bypass", Category: "proxy"},
	// Debug
	{Name: "X-Custom-IP-Authorization", Value: "127.0.0.1", Description: "IP-based auth bypass", Category: "debug"},
	{Name: "X-Requested-With", Value: "XMLHttpRequest", Description: "AJAX request indicator", Category: "debug"},
	{Name: "X-Debug", Value: "1", Description: "Debug mode trigger", Category: "debug"},
}

var CookiePresets = []CookiePreset{
	{Name: "session", Placeholder: "<session-id>", Description: "Generic session cookie", Category: "auth"},
	{Name: "PHPSESSID", Placeholder: "<session-id>", Description: "PHP session", Category: "auth"},
	{Name: "JSESSIONID", Placeholder: "<session-id>", Description: "Java session", Category: "auth"},
	{Name: "ASP.NET_SessionId", Placeholder: "<session-id>", Description: "ASP.NET session", Category: "auth"},
	{Name: "connect.sid", Placeholder: "<session-id>", Description: "Express.js session", Category: "auth"},
	{Name: "token", Placeholder: "<jwt-token>", Description: "JWT token cookie", Category: "auth"},
	{Name: "csrf_token", Placeholder: "<csrf-token>", Description: "CSRF protection token", Category: "security"},
	{Name: "_csrf", Placeholder: "<csrf-token>", Description: "CSRF token (Rails/Express)", Category: "security"},
	{Name: "laravel_session", Placeholder: "<session-id>", Description: "Laravel session", Category: "auth"},
	{Name: "wordpress_logged_in", Placeholder: "<cookie-value>", Description: "WordPress auth cookie", Category: "auth"},
}

// ParseFormHeaders extracts custom headers from form data (header_name[] + header_value[])
func ParseFormHeaders(r *http.Request) map[string]string {
	names := r.Form["header_name"]
	values := r.Form["header_value"]
	result := map[string]string{}
	for i := 0; i < len(names) && i < len(values); i++ {
		if names[i] != "" && values[i] != "" {
			result[names[i]] = values[i]
		}
	}
	return result
}

// ParseFormCookies extracts custom cookies from form data (cookie_name[] + cookie_value[])
func ParseFormCookies(r *http.Request) map[string]string {
	names := r.Form["cookie_name"]
	values := r.Form["cookie_value"]
	result := map[string]string{}
	for i := 0; i < len(names) && i < len(values); i++ {
		if names[i] != "" && values[i] != "" {
			result[names[i]] = values[i]
		}
	}
	return result
}

// ParseHTTPOptions extracts both headers and cookies from form data
func ParseHTTPOptions(r *http.Request) *HTTPOptions {
	h := ParseFormHeaders(r)
	c := ParseFormCookies(r)
	if len(h) == 0 && len(c) == 0 {
		return nil
	}
	return &HTTPOptions{Headers: h, Cookies: c}
}
