package corsscan

import (
	"context"
	"crypto/tls"
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"

	"scanner/internal/modules/shared"
)

// Severity ranks per finding.
const (
	SevCritical = "CRITICAL"
	SevHigh     = "HIGH"
	SevMedium   = "MEDIUM"
	SevLow      = "LOW"
	SevInfo     = "INFO"
)

// Finding is one CORS misconfiguration the scanner observed.
type Finding struct {
	Severity       string `json:"severity"`
	Title          string `json:"title"`
	Detail         string `json:"detail,omitempty"`
	RequestOrigin  string `json:"request_origin"`
	RequestMethod  string `json:"request_method,omitempty"` // "OPTIONS" for preflight findings
	ResponseACAO   string `json:"response_acao"`
	ResponseACAC   string `json:"response_acac,omitempty"`
	AllowedMethods string `json:"allowed_methods,omitempty"` // from Access-Control-Allow-Methods
	AllowedHeaders string `json:"allowed_headers,omitempty"` // from Access-Control-Allow-Headers
	RawRequest     string `json:"raw_request,omitempty"`
	RawResponse    string `json:"raw_response,omitempty"`
}

// URLResult is the bundle of CORS findings for a single target URL.
type URLResult struct {
	URL      string    `json:"url"`
	Findings []Finding `json:"findings"`
	Error    string    `json:"error,omitempty"`
}

type ScanResult struct {
	Results []URLResult `json:"results"`
}

type Config struct {
	URLs        []string
	Concurrency int
	Timeout     time.Duration
}

type ProgressFunc func(done int, msg string)
type PartialFunc func(*ScanResult)

func Scan(ctx context.Context, cfg Config, opts *shared.HTTPOptions, progress ProgressFunc, partial PartialFunc) *ScanResult {
	if cfg.Concurrency <= 0 {
		cfg.Concurrency = 5
	}
	if cfg.Timeout <= 0 {
		cfg.Timeout = 10 * time.Second
	}
	result := &ScanResult{}
	var mu sync.Mutex
	sem := make(chan struct{}, cfg.Concurrency)
	var wg sync.WaitGroup
	done := 0
	// Audit S2: throttle per-URL partial snapshot+marshal to 2s.
	throttle := shared.NewPartialThrottler(2 * time.Second)

	// Reachability preflight: skip TLS-dead targets up front.
	if opts != nil && opts.PreflightEnabled {
		live, dead := shared.FilterReachable(ctx, opts, cfg.URLs, opts.PreflightTimeout, cfg.Concurrency)
		for t, reason := range dead {
			result.Results = append(result.Results, URLResult{URL: t, Error: "unreachable — " + reason})
		}
		cfg.URLs = live
	}

	for _, u := range cfg.URLs {
		if ctx.Err() != nil {
			break
		}
		wg.Add(1)
		sem <- struct{}{}
		go func(target string) {
			defer wg.Done()
			defer func() { <-sem }()
			ur := probeURL(ctx, target, cfg.Timeout, opts)
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
	// Final force-flush so the terminal result always reaches the UI.
	if partial != nil {
		throttle.Force()
		mu.Lock()
		snap := &ScanResult{Results: append([]URLResult(nil), result.Results...)}
		mu.Unlock()
		partial(snap)
	}
	return result
}

// probeURL fires a battery of CORS probes against one URL.
//
// Test cases (each with the Origin header set to a different value):
//   - Reflected: random.tld
//   - Wildcard subdomain trust: evil.<host>
//   - Suffix attach: <host>.evil.com
//   - Prefix attach: evil<host>
//   - Null origin
//   - http vs https scheme swap
//   - Comma injection
//   - Lower/uppercase + trailing-dot variants
//
// Each is classified by inspecting Access-Control-Allow-Origin (ACAO) +
// Access-Control-Allow-Credentials (ACAC) on the response.
func probeURL(ctx context.Context, target string, timeout time.Duration, opts *shared.HTTPOptions) URLResult {
	ur := URLResult{URL: target}

	host := hostOf(target)
	if host == "" {
		ur.Error = "invalid URL"
		return ur
	}

	tests := buildTests(host)

	client := newClient(timeout, opts)
	for _, t := range tests {
		req, err := http.NewRequestWithContext(ctx, "GET", target, nil)
		if err != nil {
			continue
		}
		req.Header.Set("Origin", t.origin)
		req.Header.Set("User-Agent", "Mozilla/5.0 scaNNer/CORS")
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
		resp.Body.Close()

		acao := strings.TrimSpace(resp.Header.Get("Access-Control-Allow-Origin"))
		acac := strings.TrimSpace(resp.Header.Get("Access-Control-Allow-Credentials"))

		f := classify(t, acao, acac)
		if f == nil {
			continue
		}
		f.RequestOrigin = t.origin
		f.ResponseACAO = acao
		f.ResponseACAC = acac
		f.RawRequest = rawReq
		f.RawResponse = rawResp
		ur.Findings = append(ur.Findings, *f)
	}

	// Audit fix: also run an OPTIONS preflight probe. Browsers issue
	// OPTIONS with Access-Control-Request-Method / -Request-Headers
	// before any "non-simple" cross-origin fetch (PUT, DELETE, JSON body,
	// Authorization header, etc). Servers often allow simple-request
	// reflection but tighten preflight — or vice-versa. Probing only
	// simple GET misses both directions.
	for _, t := range tests {
		req, err := http.NewRequestWithContext(ctx, "OPTIONS", target, nil)
		if err != nil {
			continue
		}
		req.Header.Set("Origin", t.origin)
		req.Header.Set("Access-Control-Request-Method", "PUT")
		req.Header.Set("Access-Control-Request-Headers", "Authorization, Content-Type")
		req.Header.Set("User-Agent", "Mozilla/5.0 scaNNer/CORS")
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
		resp.Body.Close()

		acao := strings.TrimSpace(resp.Header.Get("Access-Control-Allow-Origin"))
		acac := strings.TrimSpace(resp.Header.Get("Access-Control-Allow-Credentials"))
		acam := strings.TrimSpace(resp.Header.Get("Access-Control-Allow-Methods"))
		acah := strings.TrimSpace(resp.Header.Get("Access-Control-Allow-Headers"))

		f := classify(t, acao, acac)
		if f == nil {
			continue
		}
		// Tag preflight findings so the UI can show them distinctly.
		f.Title = "[preflight] " + f.Title
		f.RequestOrigin = t.origin
		f.ResponseACAO = acao
		f.ResponseACAC = acac
		f.RequestMethod = "OPTIONS"
		f.AllowedMethods = acam
		f.AllowedHeaders = acah
		f.RawRequest = rawReq
		f.RawResponse = rawResp
		ur.Findings = append(ur.Findings, *f)
	}

	if opts != nil {
		opts.ReplayHit("GET", target)
	}
	return ur
}

type test struct {
	name   string
	origin string
}

func buildTests(host string) []test {
	return []test{
		{"reflection", "https://attacker-evil-" + randStamp() + ".example"},
		{"subdomain-attach", "https://evil." + host},
		{"suffix-attach", "https://" + host + ".attacker.example"},
		{"prefix-attach", "https://" + host + "attacker.example"},
		{"null-origin", "null"},
		{"scheme-swap-http", "http://" + host},
		{"comma-injection", "https://" + host + ",attacker.example"},
		{"trailing-dot", "https://" + host + "."},
		// Audit MEDIUM fix: the look-alike attack is about whether the server
		// treats a confusable variant of its OWN domain as legitimate (e.g.
		// `api.examp1e.c0m` instead of `api.example.com`). The previous
		// `<swap>.attacker.example` form was attacker-owned and only ever
		// matched servers that reflect ANY origin (covered by `reflection`).
		// Probing the bare swapped host catches naive substring / loose-host
		// allowlists.
		{"unicode-look-alike", "https://" + asciiSwap(host)},
	}
}

func classify(t test, acao, acac string) *Finding {
	if acao == "" {
		return nil
	}
	credentialsOn := strings.EqualFold(acac, "true")

	// Wildcard with credentials is illegal but some buggy servers emit
	// the header anyway. Browsers reject, but reverse-proxies may not.
	if acao == "*" {
		if credentialsOn {
			return &Finding{
				Severity: SevHigh,
				Title:    "Wildcard ACAO with credentials enabled",
				Detail:   "Access-Control-Allow-Origin: * combined with Access-Control-Allow-Credentials: true is forbidden by spec but still emitted — fetch() in cookie-auth context behaves unpredictably.",
			}
		}
		return &Finding{
			Severity: SevLow,
			Title:    "Wildcard ACAO",
			Detail:   "Access-Control-Allow-Origin: * is OK for public APIs but ensures no cookie/auth context is shared. Verify no credentials-bearing endpoints sit on this host.",
		}
	}

	// Audit MEDIUM fix: previous host-portion fallback compared
	// (acao, t.origin) twice — identical to the primary check. Implement
	// what the comment promised: derive the origin's host via url.Parse
	// and also match when the server reflected only the host portion
	// (e.g. ACAO returned `evil.victim.com` without the scheme). Per
	// RFC 6454 §7.1 host comparison is case-insensitive.
	acaoTrimmed := strings.TrimSpace(acao)
	originTrimmed := strings.TrimSpace(t.origin)
	reflected := strings.EqualFold(acaoTrimmed, originTrimmed)
	if !reflected {
		if u, err := url.Parse(originTrimmed); err == nil && u.Host != "" {
			originHost := u.Host
			// Match against host-only and host-without-scheme variants.
			if strings.EqualFold(acaoTrimmed, originHost) ||
				strings.EqualFold(acaoTrimmed, strings.TrimPrefix(strings.TrimPrefix(originTrimmed, "https://"), "http://")) {
				reflected = true
			}
		}
	}

	switch t.name {
	case "reflection":
		if reflected {
			sev := SevMedium
			detail := "Server reflects any Origin into Access-Control-Allow-Origin."
			if credentialsOn {
				sev = SevCritical
				detail = "Server reflects arbitrary Origin AND sets Access-Control-Allow-Credentials: true — any site can read authenticated responses cross-origin."
			}
			return &Finding{Severity: sev, Title: "Arbitrary origin reflection", Detail: detail}
		}
	case "subdomain-attach":
		if reflected {
			sev := SevHigh
			detail := "Server trusts any subdomain. XSS on a single subdomain leads to full CORS bypass."
			if credentialsOn {
				sev = SevCritical
			}
			return &Finding{Severity: sev, Title: "Wildcard subdomain trust", Detail: detail}
		}
	case "suffix-attach":
		if reflected {
			return &Finding{Severity: SevHigh, Title: "Suffix-based regex bypass",
				Detail: "Server trusts `<original-host>.<attacker-domain>` — likely uses an unanchored regex like `endsWith(host)`. Attacker can serve from `victim.com.attacker.tld`."}
		}
	case "prefix-attach":
		if reflected {
			return &Finding{Severity: SevHigh, Title: "Prefix-based regex bypass",
				Detail: "Server trusts `<original-host><attacker-tld>` — likely uses `startsWith(host)`. Attacker registers `victim.com.attacker.tld` or similar."}
		}
	case "null-origin":
		if strings.EqualFold(acao, "null") {
			sev := SevHigh
			detail := "Server returns Access-Control-Allow-Origin: null — sandboxed iframes / data: URIs / file:// pages can produce null Origin and read responses."
			if credentialsOn {
				sev = SevCritical
			}
			return &Finding{Severity: sev, Title: "Null origin trusted", Detail: detail}
		}
	case "scheme-swap-http":
		if reflected {
			return &Finding{Severity: SevMedium, Title: "http origin trusted on https endpoint",
				Detail: "MITM on the user's network can downgrade and read responses, even though TLS is in use on the API."}
		}
	case "comma-injection":
		if reflected {
			return &Finding{Severity: SevHigh, Title: "Comma in Origin not rejected",
				Detail: "Server accepts comma-separated origin values — some legacy proxies/regex matchers will treat substring as match."}
		}
	case "trailing-dot":
		if reflected {
			return &Finding{Severity: SevMedium, Title: "Trailing-dot bypass",
				Detail: "Server reflects `https://victim.com.` — host parsers often canonicalize away the trailing dot, regex doesn't."}
		}
	case "unicode-look-alike":
		if reflected {
			return &Finding{Severity: SevMedium, Title: "Look-alike domain accepted",
				Detail: "Server reflects an ASCII-confusable origin (e.g. swapped characters). Likely uses a naive substring check."}
		}
	}
	return nil
}

func hostOf(target string) string {
	u, err := url.Parse(target)
	if err != nil {
		return ""
	}
	return u.Hostname()
}

func asciiSwap(host string) string {
	// Replace `o` with `0`, `l` with `1`. Crude but enough for proof.
	r := strings.NewReplacer("o", "0", "l", "1")
	return r.Replace(host)
}

func randStamp() string {
	return fmt.Sprintf("%d", time.Now().UnixNano())
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
	return &http.Client{
		Timeout:   timeout,
		Transport: transport,
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}
}
