package paramdisc

import (
	"bytes"
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"io"
	"net/http"
	"net/http/httputil"
	"net/url"
	"strings"
	"sync"
	"time"

	"scanner/internal/modules/shared"
)

// Hit is a parameter that caused a measurable response differential.
type Hit struct {
	Name        string `json:"name"`
	Method      string `json:"method"` // GET | POST
	StatusDiff  bool   `json:"status_diff"`
	StatusCode  int    `json:"status_code"`
	LengthDiff  int    `json:"length_diff"`
	Reflected   bool   `json:"reflected"`
	Note        string `json:"note,omitempty"`
	RawRequest  string `json:"raw_request,omitempty"`
	RawResponse string `json:"raw_response,omitempty"`
}

type TargetResult struct {
	URL          string `json:"url"`
	Method       string `json:"method"`
	BaselineCode int    `json:"baseline_code"`
	BaselineSize int    `json:"baseline_size"`
	Tested       int    `json:"tested"`
	Hits         []Hit  `json:"hits"`
	Error        string `json:"error,omitempty"`
}

type ScanResult struct {
	Results []TargetResult `json:"results"`
}

type Config struct {
	URLs        []string
	Method      string // GET | POST | both
	Wordlist    []string
	Concurrency int
}

type ProgressFunc func(done int, msg string)
type PartialFunc func(*ScanResult)

// DefaultParams is a curated mid-size wordlist (~600 entries). Big enough to
// cover the high-value parameters that bug-bounty tools (Arjun, ParamSpider)
// typically hit on, small enough to finish in a few minutes per URL.
// Users can paste their own list to override.
var DefaultParams = []string{
	// --- Identity / auth ---
	"id", "ID", "Id", "user", "user_id", "userId", "userid", "uid", "uuid", "guid",
	"name", "username", "user_name", "userName", "login", "loginid", "login_id",
	"email", "e_mail", "mail", "email_address", "user_email", "account", "accountid", "account_id",
	"password", "passwd", "pass", "pwd", "secret", "old_password", "new_password", "password1", "password2",
	"token", "auth", "auth_token", "authToken", "access_token", "accessToken", "refresh_token", "id_token",
	"api_key", "apikey", "api-key", "apiKey", "key", "client_id", "client_secret", "client-id",
	"session", "sessionid", "sessionId", "session_id", "sid", "phpsessid", "jsessionid", "aspsessionid",
	"csrf", "csrftoken", "csrf_token", "_csrf", "_token", "xsrf", "xsrf_token", "antiforgery",
	"otp", "code", "verify", "verification_code", "captcha", "challenge", "answer", "response",
	"role", "is_admin", "admin", "is_root", "is_superuser", "permission", "permissions", "level", "access",
	"hash", "checksum", "signature", "sig", "nonce", "state",
	"oauth_token", "oauth_verifier", "oauth_consumer_key", "oauth_signature",
	"jwt", "bearer", "Authorization",

	// --- Query / search / pagination ---
	"q", "query", "search", "search_query", "searchTerm", "term", "terms", "keyword", "keywords",
	"s", "filter", "filters", "where", "criteria", "criterion", "match", "tag", "tags",
	"page", "pageNum", "page_num", "pageNumber", "p", "paged", "pg", "n",
	"limit", "max", "max_results", "maxResults", "count", "size", "per_page", "perPage", "pageSize",
	"offset", "skip", "start", "startIndex", "from_index", "to_index",
	"sort", "sortby", "sort_by", "sortBy", "sortField", "sort_field", "order", "order_by", "orderby", "orderBy",
	"asc", "desc", "direction", "dir", "reverse",

	// --- Categorization / segmentation ---
	"type", "kind", "category", "cat", "categoryid", "category_id", "subcategory", "sub_category",
	"section", "subsection", "topic", "subject", "channel", "stream",
	"group", "groupid", "group_id", "team", "teamid", "team_id", "org", "orgid", "org_id", "organization",
	"tenant", "tenantId", "tenant_id", "company", "companyid", "company_id", "client", "clientid",
	"site", "siteid", "site_id", "domain", "domainid", "subdomain", "host", "hostid", "host_id", "ip",
	"location", "loc", "region", "country", "city", "state", "zip", "zipcode", "postal", "postalcode",
	"lang", "language", "locale", "currency", "tz", "timezone",

	// --- Time / range ---
	"date", "datetime", "timestamp", "ts", "year", "month", "day", "hour", "minute",
	"time", "from", "to", "since", "until", "after", "before", "start_date", "end_date",
	"start", "end", "begin", "duration", "expires", "expiry", "valid_until", "ttl",

	// --- Output / format / callback ---
	"format", "fmt", "output", "out", "type", "ext", "extension", "encoding",
	"callback", "jsonp", "json", "xml", "yaml", "csv", "html", "text", "raw", "pretty",
	"indent", "fields", "include_fields", "exclude_fields", "select", "fields[]",
	"version", "ver", "v", "api_version", "apiVersion",

	// --- Redirect / URL fields (open-redirect candidates) ---
	"redirect", "redirect_uri", "redirect_url", "redirectUrl", "redirectUri",
	"return", "returnUrl", "return_to", "returnTo", "returnUri", "return_url",
	"next", "next_page", "back", "back_url", "continue", "continue_to", "destination", "dest",
	"goto", "go", "follow", "out", "outgoing", "exit", "u", "uri", "url", "target", "targetUrl",
	"href", "link", "loc", "ref", "referer", "referrer", "origin", "source", "src",
	"forward", "forwardTo", "forwardUrl", "callback_url", "checkout_url", "success_url", "cancel_url",

	// --- File / path (LFI / SSRF candidates) ---
	"file", "filename", "filepath", "file_path", "path", "fullpath", "fpath",
	"dir", "directory", "folder", "subdir", "subfolder", "doc", "document", "docid", "doc_id",
	"image", "img", "picture", "photo", "avatar", "thumbnail", "thumb", "icon", "logo",
	"video", "audio", "media", "asset", "attachment", "upload", "uploaded", "uploadedFile",
	"include", "inc", "require", "load", "import", "module", "view", "template", "tpl",
	"page_id", "page_name", "screen", "tab", "panel", "wizard_step",

	// --- Action / command (RCE candidates) ---
	"action", "act", "cmd", "command", "exec", "execute", "run", "do", "task", "operation", "op",
	"method", "func", "function", "call", "rpc", "endpoint", "service",
	"event", "trigger", "handler", "process", "procedure",

	// --- Debug / development ---
	"debug", "debugger", "dev", "development", "test", "testing", "trace", "verbose", "log", "logging",
	"profile", "profiling", "benchmark", "performance",
	"_debug", "_dev", "_test", "_trace", "_log",
	"sandbox", "preview", "draft", "published", "status", "state",

	// --- Data payloads ---
	"data", "payload", "body", "content", "value", "values", "input", "inputs", "params", "parameters",
	"args", "arguments", "options", "opts", "config", "configuration", "settings", "preferences", "prefs",
	"meta", "metadata", "extra", "extras", "info", "details", "attrs", "attributes", "properties", "props",

	// --- Common framework / underscore prefixed ---
	"_method", "_token", "_format", "_action", "_route", "_controller", "_locale", "_csrf",
	"_wpnonce", "_ga", "_fbclid", "_gclid", "utm_source", "utm_medium", "utm_campaign", "utm_term", "utm_content",
	"hl", "gl", "ie", "oe", "fb", "li",

	// --- WordPress / common CMS ---
	"post", "post_id", "post_type", "p", "page_id", "cat", "tag_id", "author", "author_id",
	"preview_id", "preview_nonce", "wpnonce", "ver", "rest_route",
	"node", "nid", "vid", "tid", "uid_drupal",

	// --- E-commerce / orders ---
	"product", "product_id", "productId", "sku", "variant", "variant_id",
	"order", "order_id", "orderid", "orderId", "cart", "cart_id", "basket", "basket_id",
	"price", "amount", "total", "subtotal", "tax", "discount", "coupon", "voucher", "promo", "promo_code",
	"qty", "quantity", "shipping", "shipping_method", "payment", "payment_method",
	"billing", "billing_address", "shipping_address", "address", "address1", "address2",

	// --- Misc commonly-tested ---
	"show", "hide", "render", "view_mode", "mode", "context", "scope", "env", "environment",
	"feature", "features", "enabled", "disabled", "enable", "disable", "active", "inactive",
	"visible", "hidden", "public", "private", "shared", "protected",
	"is_active", "is_enabled", "is_visible", "is_public", "is_deleted", "deleted", "archived",
	"flag", "flags", "tag", "label", "labels", "color", "theme", "style",

	// --- Headers as params ---
	"X-Forwarded-For", "X-Real-IP", "X-Originating-IP", "X-Remote-IP", "X-Host", "X-Forwarded-Host",

	// --- API / RPC ---
	"jsonrpc", "method", "id", "params", "rpc_method",
	"graphql", "operationName", "variables", "query", "extensions",

	// --- Single-letter / short ---
	"a", "b", "c", "d", "e", "f", "g", "h", "i", "j", "k", "l", "m",
	"n", "o", "q", "r", "s", "t", "u", "v", "w", "x", "y", "z",
	"q1", "q2", "p1", "p2", "v1", "v2",

	// --- Less common but classic ---
	"dest", "destination", "target_url", "img_src", "image_url", "video_url", "audio_url",
	"proxy", "proxy_host", "proxy_port", "proxy_user", "proxy_pass",
	"ssl", "tls", "verify", "verify_ssl", "insecure", "skip_verify",
	"timeout", "delay", "interval", "retry", "retries", "max_retries",
	"webhook", "webhook_url", "webhook_secret", "ws", "websocket",
	"feed", "rss", "atom", "sitemap", "robots",
	"locale_code", "country_code", "currency_code", "language_code",
	"src_id", "dst_id", "from_id", "to_id", "parent_id", "child_id", "ancestor_id", "descendant_id",
	"prev", "next_token", "page_token", "continuation_token", "cursor",
	"version_id", "revision", "rev", "build", "build_id",

	// --- Database / SQL related ---
	"table", "tablename", "table_name", "column", "field", "schema",
	"db", "database", "dbname", "db_name", "connection", "conn", "datasource",

	// --- Common tracking / analytics ---
	"sid", "tid", "cid", "vid", "ev", "event_id", "session_id", "visitor_id", "device_id",
	"user_agent", "ua", "fp", "fingerprint", "browser",

	// --- Misc verbs (state-changing) ---
	"create", "update", "delete", "remove", "edit", "save", "submit", "send", "post", "put",
	"upload", "download", "share", "publish", "unpublish", "approve", "reject", "block", "unblock",
	"ban", "unban", "kick", "invite", "join", "leave", "cancel", "confirm",

	// --- Test bait names ---
	"foo", "bar", "baz", "qux", "test1", "abc", "xyz", "tmp", "temp",
}

func Scan(ctx interface {
	Done() <-chan struct{}
	Err() error
}, cfg Config, opts *shared.HTTPOptions, progress ProgressFunc, partial PartialFunc) *ScanResult {
	out := &ScanResult{}
	if cfg.Concurrency <= 0 {
		cfg.Concurrency = 30
	}
	if len(cfg.Wordlist) == 0 {
		cfg.Wordlist = DefaultParams
	}
	// Audit: the curated DefaultParams list contained ~32 duplicates across
	// sections (id, query, method, p, _csrf, ...). Each duplicate wastes a
	// full HTTP probe and inflates the "Tested" counter. Dedupe in-place,
	// preserving first-occurrence order, before launching probes.
	cfg.Wordlist = uniqueParams(cfg.Wordlist)
	method := strings.ToUpper(cfg.Method)
	if method != "GET" && method != "POST" && method != "BOTH" {
		method = "GET"
	}

	var mu sync.Mutex
	done := 0
	// Audit S2: throttle pushPartial — was fired per-URL per-method.
	throttle := shared.NewPartialThrottler(2 * time.Second)
	pushPartial := func() {
		if partial == nil {
			return
		}
		if !throttle.ShouldFire() {
			return
		}
		mu.Lock()
		snap := &ScanResult{Results: append([]TargetResult(nil), out.Results...)}
		mu.Unlock()
		partial(snap)
	}

	// Audit fix: hoist the HTTP client to the scan level so its
	// underlying *http.Transport (and idle-conn pool) is reused across
	// every URL/method — one Transport per scan, not one per target.
	// NewHTTPClient also registers the transport with opts so
	// CloseIdleConnections() fires at scan end.
	client := opts.NewHTTPClient()

	for _, u := range cfg.URLs {
		if ctx.Err() != nil {
			break
		}
		methods := []string{method}
		if method == "BOTH" {
			methods = []string{"GET", "POST"}
		}
		for _, m := range methods {
			if progress != nil {
				progress(done, fmt.Sprintf("Calibrating %s %s ...", m, u))
			}
			tr := scanTarget(ctx, u, m, cfg.Wordlist, cfg.Concurrency, client, opts, func(msg string) {
				mu.Lock()
				cur := done
				mu.Unlock()
				if progress != nil {
					progress(cur, fmt.Sprintf("%s %s · %s", m, u, msg))
				}
			})
			mu.Lock()
			done++
			out.Results = append(out.Results, *tr)
			cur := done
			mu.Unlock()
			if progress != nil {
				progress(cur, fmt.Sprintf("[%d] %s %s — %d hits / %d tested", cur, m, u, len(tr.Hits), tr.Tested))
			}
			pushPartial()
		}
	}
	throttle.Force()
	pushPartial()
	return out
}

func scanTarget(ctx interface {
	Done() <-chan struct{}
	Err() error
}, target, method string, wordlist []string, concurrency int, client *http.Client, opts *shared.HTTPOptions, log func(string)) *TargetResult {
	tr := &TargetResult{URL: target, Method: method}

	// Baseline: send the canonical request without any extra param.
	baselineCode, baselineBody := probe(client, method, target, "", "", opts)
	if baselineCode == 0 {
		tr.Error = "baseline request failed"
		return tr
	}
	tr.BaselineCode = baselineCode
	tr.BaselineSize = len(baselineBody)
	if log != nil {
		log(fmt.Sprintf("baseline %d, %d bytes", baselineCode, len(baselineBody)))
	}

	// Audit fix (F1/F6): a single noise sample under-calibrates dynamic
	// pages (rotating banners, CSRF tokens, timestamps). Send several
	// noise probes with different random names/values, take the maximum
	// observed size delta, and treat status codes as stable only if
	// every sample returned the same status. If the noise probes all
	// fail (dropped by WAF/rate-limiter), fall back to a conservative
	// floor so length-diff isn't unreachable.
	const noiseSamples = 4
	noiseDelta := 0
	noiseCodes := map[int]int{}
	noiseFail := 0
	for i := 0; i < noiseSamples; i++ {
		if ctx.Err() != nil {
			break
		}
		nCode, nBody := probe(client, method, target, randHex(10), randHex(8), opts)
		if nCode == 0 {
			noiseFail++
			continue
		}
		noiseCodes[nCode]++
		if d := abs(len(nBody) - tr.BaselineSize); d > noiseDelta {
			noiseDelta = d
		}
	}
	// Apply a 1.5x safety margin, plus a floor of 32 bytes so trivial
	// per-request variance doesn't fire hits.
	noiseDelta = noiseDelta + noiseDelta/2
	if noiseDelta < 32 {
		noiseDelta = 32
	}
	// Status codes are stable only if every successful noise probe
	// returned the same code AND that code matches baseline. If the
	// server flickers between statuses, skip the status-diff check.
	statusStable := len(noiseCodes) <= 1
	if len(noiseCodes) == 1 {
		for c := range noiseCodes {
			if c != baselineCode {
				statusStable = false
			}
		}
	}
	if noiseFail == noiseSamples {
		// Noise floor is undefined — widen the length threshold and
		// disable status-diff to avoid a flood of false positives.
		statusStable = false
		if noiseDelta < 128 {
			noiseDelta = 128
		}
		if log != nil {
			log(fmt.Sprintf("noise calibration failed for %s, using fallback threshold", target))
		}
	} else if !statusStable && log != nil {
		log("noise status flapped; status-diff signalling disabled for this target")
	}

	var (
		mu  sync.Mutex
		wg  sync.WaitGroup
		sem = make(chan struct{}, concurrency)
	)

	for _, name := range wordlist {
		if ctx.Err() != nil {
			break
		}
		wg.Add(1)
		sem <- struct{}{}
		go func(p string) {
			defer wg.Done()
			defer func() { <-sem }()
			value := randHex(8)
			// Audit fix (F7): use the cheap probe (no httputil dumps)
			// in the hot path — dumps run only for confirmed hits
			// via a second capture-enabled call below. Prior code
			// dumped ~600 probes × N targets even though 99% were
			// discarded, wasting CPU + allocations.
			code, body := probe(client, method, target, p, value, opts)
			mu.Lock()
			tr.Tested++
			mu.Unlock()
			if code == 0 {
				return
			}
			lenDelta := abs(len(body) - tr.BaselineSize)
			interesting := false
			hit := Hit{Name: p, Method: method, StatusCode: code}
			// Status code differs from baseline → likely interesting
			// (only trusted when the noise calibration confirmed
			// stability, otherwise this would fire on every jittery
			// endpoint).
			if statusStable && code != baselineCode {
				hit.StatusDiff = true
				interesting = true
			}
			// Length delta exceeds the noise delta by at least 8 bytes
			if lenDelta > noiseDelta+8 {
				hit.LengthDiff = lenDelta
				interesting = true
			}
			// Value reflected back in body
			if value != "" && strings.Contains(body, value) {
				hit.Reflected = true
				hit.Note = "value reflected in response"
				interesting = true
			}
			if interesting {
				// Re-issue with capture only for confirmed hits.
				_, _, rawReq, rawResp := probeFull(client, method, target, p, value, opts)
				hit.RawRequest = truncateRaw(rawReq, 4*1024)
				hit.RawResponse = truncateRaw(rawResp, 16*1024)
				mu.Lock()
				tr.Hits = append(tr.Hits, hit)
				mu.Unlock()
				if log != nil {
					log("✓ " + p)
				}
			}
		}(name)
	}
	wg.Wait()
	return tr
}

func truncateRaw(s string, max int) string {
	if len(s) <= max {
		return s
	}
	return s[:max] + "\n\n... [truncated " + fmt.Sprintf("%d", len(s)-max) + " bytes]"
}

// probe is the body-only path used by baseline + noise + hot-loop
// worker calls (fast, skips httputil dumps entirely).
func probe(client *http.Client, method, target, paramName, paramValue string, opts *shared.HTTPOptions) (int, string) {
	code, body, _, _ := probeImpl(client, method, target, paramName, paramValue, opts, false)
	return code, body
}

// probeFull behaves like probe but also returns Burp-format raw request/response
// dumps. Callers should only keep the dumps on confirmed hits to keep memory
// usage and stored-result size sane.
func probeFull(client *http.Client, method, target, paramName, paramValue string, opts *shared.HTTPOptions) (int, string, string, string) {
	return probeImpl(client, method, target, paramName, paramValue, opts, true)
}

// probeImpl is the shared HTTP path. capture=false skips the
// DumpRequestOut/DumpResponse work entirely so the hot loop (hundreds
// of probes per target) doesn't pay for raw serialization that would
// only be kept for the <1% that become hits.
func probeImpl(client *http.Client, method, target, paramName, paramValue string, opts *shared.HTTPOptions, capture bool) (int, string, string, string) {
	var reqURL string = target
	var bodyReader io.Reader
	method = strings.ToUpper(method)
	// Audit fix (F3/F5): URL-encode param name and value before
	// concatenating so wordlist entries like "fields[]", "X-Forwarded-For"
	// or values containing '&' '=' '#' '+' don't corrupt the URL / body
	// and get parsed as extra parameters by the receiving server. The
	// server sees the same decoded key either way.
	if method == "GET" {
		if paramName != "" {
			sep := "?"
			if strings.Contains(target, "?") {
				sep = "&"
			}
			reqURL = target + sep + url.QueryEscape(paramName) + "=" + url.QueryEscape(paramValue)
		}
	} else {
		if paramName != "" {
			form := url.Values{paramName: {paramValue}}
			bodyReader = strings.NewReader(form.Encode())
		}
	}
	req, err := http.NewRequest(method, reqURL, bodyReader)
	if err != nil {
		return 0, "", "", ""
	}
	req.Header.Set("User-Agent", "scaNNer-ParamDisc/1.0")
	if method == "POST" {
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	}
	if opts != nil {
		opts.ApplyTo(req)
	}
	req = opts.BindContext(req)

	// Audit: DumpRequestOut emits every header attached by opts.ApplyTo,
	// including Authorization / Cookie / X-Api-Key configured in Settings.
	// Strip those values before the dump ever leaves this function so they
	// can't be persisted to scans.result. Same goes for the response side
	// (Set-Cookie etc.).
	var rawReq string
	if capture {
		if dump, err := httputil.DumpRequestOut(req, true); err == nil {
			rawReq = shared.RedactSecretHeaders(string(dump))
		}
	}

	resp, err := client.Do(req)
	if err != nil {
		opts.RecordError(shared.ClassifyError(err))
		return 0, "", rawReq, ""
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 256*1024))

	var rawResp string
	if capture {
		// Rebuild the body so DumpResponse can serialize the bytes we just read.
		resp.Body = io.NopCloser(bytes.NewReader(body))
		if dump, err := httputil.DumpResponse(resp, true); err == nil {
			rawResp = shared.RedactSecretHeaders(string(dump))
		}
	}
	return resp.StatusCode, string(body), rawReq, rawResp
}

// uniqueParams returns names with duplicates removed, preserving the order
// of first occurrence. Used to dedupe DefaultParams (which historically had
// ~32 dupes across curated sections) and any user-supplied wordlist.
func uniqueParams(in []string) []string {
	seen := make(map[string]bool, len(in))
	out := make([]string, 0, len(in))
	for _, p := range in {
		if p == "" {
			continue
		}
		if seen[p] {
			continue
		}
		seen[p] = true
		out = append(out, p)
	}
	return out
}

func randHex(n int) string {
	b := make([]byte, n)
	rand.Read(b)
	return hex.EncodeToString(b)
}

func abs(n int) int {
	if n < 0 {
		return -n
	}
	return n
}
