package takeover

import (
	"context"
	"crypto/tls"
	"fmt"
	"io"
	"net"
	"net/http"
	"strings"
	"sync"
	"time"

	"scanner/internal/modules/shared"
)

// Signature describes one third-party service's dangling-CNAME fingerprint.
// A subdomain whose CNAME ends in CNAMESuffix AND whose HTTP response body
// contains BodyMatch (and the upstream returned a status from Status set, if
// non-empty) is flagged as a probable takeover candidate.
type Signature struct {
	Service     string   // human label, e.g. "AWS S3"
	CNAMESuffix []string // any of these as CNAME tail → candidate provider
	BodyMatch   []string // case-insensitive body substrings (any one)
	Status      []int    // HTTP statuses that strengthen the case (empty = any)
	Severity    string   // CRITICAL | HIGH | MEDIUM | LOW
	Note        string   // remediation hint
}

// Built-in signatures — sourced from the public can-i-take-over-xyz project
// (60+ providers). We focus on the most frequently weaponized ones.
var Signatures = []Signature{
	{
		Service: "AWS S3",
		// Trailing-label fragments. matchSignature now does a strict suffix
		// check (HasSuffix on "."+suf, or full equality) so e.g. "s3.amazonaws.com"
		// matches "mybucket.s3.amazonaws.com" but NOT "mybucket.s3.amazonaws.com.evil.tld".
		// The website-hosting endpoint family has many regional variants
		// (s3-website-us-east-1.amazonaws.com, s3-website.eu-west-1.amazonaws.com,
		// s3-website.us-gov-west-1.amazonaws.com, ...), all ending in .amazonaws.com.
		// We list the most common families; the generic ".amazonaws.com" suffix is
		// intentionally NOT included because it would over-match (every AWS service).
		CNAMESuffix: []string{
			"s3.amazonaws.com",
			"s3.dualstack.amazonaws.com",
			"s3-website-us-east-1.amazonaws.com",
			"s3-website-us-east-2.amazonaws.com",
			"s3-website-us-west-1.amazonaws.com",
			"s3-website-us-west-2.amazonaws.com",
			"s3-website-eu-west-1.amazonaws.com",
			"s3-website-eu-west-2.amazonaws.com",
			"s3-website-eu-west-3.amazonaws.com",
			"s3-website-eu-central-1.amazonaws.com",
			"s3-website-eu-north-1.amazonaws.com",
			"s3-website-ap-south-1.amazonaws.com",
			"s3-website-ap-southeast-1.amazonaws.com",
			"s3-website-ap-southeast-2.amazonaws.com",
			"s3-website-ap-northeast-1.amazonaws.com",
			"s3-website-ap-northeast-2.amazonaws.com",
			"s3-website-sa-east-1.amazonaws.com",
			"s3-website-ca-central-1.amazonaws.com",
			"s3-website.us-east-2.amazonaws.com",
			"s3-website.us-west-1.amazonaws.com",
			"s3-website.us-west-2.amazonaws.com",
			"s3-website.eu-west-1.amazonaws.com",
			"s3-website.eu-west-2.amazonaws.com",
			"s3-website.eu-west-3.amazonaws.com",
			"s3-website.eu-central-1.amazonaws.com",
			"s3-website.eu-north-1.amazonaws.com",
			"s3-website.ap-south-1.amazonaws.com",
			"s3-website.ap-southeast-1.amazonaws.com",
			"s3-website.ap-southeast-2.amazonaws.com",
			"s3-website.ap-northeast-1.amazonaws.com",
			"s3-website.ap-northeast-2.amazonaws.com",
			"s3-website.sa-east-1.amazonaws.com",
			"s3-website.ca-central-1.amazonaws.com",
		},
		BodyMatch: []string{"NoSuchBucket", "The specified bucket does not exist"},
		Severity:  "CRITICAL",
		Note:      "Register the bucket name in your AWS account before an attacker does.",
	},
	{
		Service:     "GitHub Pages",
		CNAMESuffix: []string{"github.io", "github.map.fastly.net"},
		BodyMatch:   []string{"There isn't a GitHub Pages site here", "For root URLs (like http://example.com/) you must provide an index.html file"},
		Status:      []int{404},
		Severity:    "HIGH",
		Note:        "Create a repo in your org named like the subdomain and configure Pages.",
	},
	{
		Service:     "Heroku",
		CNAMESuffix: []string{"herokuapp.com", "herokudns.com"},
		BodyMatch:   []string{"No such app", "herokucdn.com/error-pages/no-such-app.html"},
		Severity:    "HIGH",
		Note:        "Re-create the Heroku app and bind the custom domain to your account.",
	},
	{
		Service:     "Azure",
		CNAMESuffix: []string{"azurewebsites.net", "cloudapp.net", "cloudapp.azure.com", "trafficmanager.net", "blob.core.windows.net", "azureedge.net", "azurefd.net"},
		BodyMatch:   []string{"404 Web Site not found", "This webpage is not available", "Error 404 - Web app not found"},
		Severity:    "HIGH",
		Note:        "Provision a new Azure resource with the same name and bind the domain.",
	},
	{
		Service:     "Cloudfront",
		CNAMESuffix: []string{"cloudfront.net"},
		BodyMatch:   []string{"Bad request. We can't connect to the server for this app or website", "Code: NoSuchDistribution"},
		Severity:    "HIGH",
		Note:        "Take over by creating a CloudFront distribution with this alternate domain name (CNAME).",
	},
	{
		Service:     "Fastly",
		CNAMESuffix: []string{"fastly.net"},
		BodyMatch:   []string{"Fastly error: unknown domain"},
		Severity:    "HIGH",
		Note:        "Add the domain to your Fastly service.",
	},
	{
		Service:     "Shopify",
		CNAMESuffix: []string{"myshopify.com"},
		BodyMatch:   []string{"Sorry, this shop is currently unavailable"},
		Severity:    "MEDIUM",
		Note:        "Acquire the Shopify shop name and re-attach the domain.",
	},
	{
		Service:     "Tumblr",
		CNAMESuffix: []string{"domains.tumblr.com"},
		BodyMatch:   []string{"There's nothing here", "Whatever you were looking for doesn't currently exist at this address"},
		Severity:    "MEDIUM",
		Note:        "Tumblr no longer accepts new vanity domains, but the dangling CNAME is still misconfiguration.",
	},
	{
		Service:     "Squarespace",
		CNAMESuffix: []string{"squarespace.com"},
		BodyMatch:   []string{"No Such Account", "You're Almost There"},
		Severity:    "MEDIUM",
		Note:        "Add the domain to your Squarespace site.",
	},
	{
		Service:     "Bitbucket",
		CNAMESuffix: []string{"bitbucket.io"},
		BodyMatch:   []string{"Repository not found"},
		Severity:    "HIGH",
		Note:        "Create the matching Bitbucket repo and enable Pages.",
	},
	{
		Service:     "Surge.sh",
		CNAMESuffix: []string{"surge.sh"},
		BodyMatch:   []string{"project not found"},
		Severity:    "HIGH",
		Note:        "Re-deploy under your Surge account.",
	},
	{
		Service:     "Pantheon",
		CNAMESuffix: []string{"pantheonsite.io"},
		BodyMatch:   []string{"The gods are wise", "404 error unknown site"},
		Severity:    "HIGH",
		Note:        "Re-provision the Pantheon site and re-attach the domain.",
	},
	{
		Service:     "Tilda",
		CNAMESuffix: []string{"tilda.ws"},
		BodyMatch:   []string{"Please renew your subscription"},
		Severity:    "MEDIUM",
		Note:        "Re-attach to a paid Tilda subscription.",
	},
	{
		Service:     "WP Engine",
		CNAMESuffix: []string{"wpengine.com"},
		BodyMatch:   []string{"The site you were looking for couldn't be found"},
		Severity:    "HIGH",
		Note:        "Add domain to a WP Engine install.",
	},
	{
		Service:     "Vercel",
		CNAMESuffix: []string{"vercel.app", "now.sh", "vercel-dns.com"},
		BodyMatch:   []string{"The deployment could not be found on Vercel", "DEPLOYMENT_NOT_FOUND"},
		Severity:    "HIGH",
		Note:        "Re-deploy to Vercel with the same project name.",
	},
	{
		Service:     "Netlify",
		CNAMESuffix: []string{"netlify.app", "netlify.com"},
		BodyMatch:   []string{"Not Found - Request ID:"},
		Status:      []int{404},
		Severity:    "MEDIUM",
		Note:        "Netlify validates domain ownership; takeover requires DNS poisoning. Still misconfiguration.",
	},
	{
		Service:     "Readme.io",
		CNAMESuffix: []string{"readme.io"},
		BodyMatch:   []string{"Project doesnt exist... yet!"},
		Severity:    "HIGH",
		Note:        "Create the project on readme.io and bind the domain.",
	},
	{
		Service:     "Statuspage",
		CNAMESuffix: []string{"statuspage.io"},
		BodyMatch:   []string{"You are being redirected"},
		Severity:    "LOW",
		Note:        "Atlassian Statuspage typically requires email verification; verify before flagging as exploitable.",
	},
	{
		Service:     "Helpjuice",
		CNAMESuffix: []string{"helpjuice.com"},
		BodyMatch:   []string{"We could not find what you're looking for"},
		Severity:    "MEDIUM",
	},
	{
		Service:     "Help Scout",
		CNAMESuffix: []string{"helpscoutdocs.com"},
		BodyMatch:   []string{"No settings were found for this company"},
		Severity:    "MEDIUM",
	},
	{
		Service:     "Ghost",
		CNAMESuffix: []string{"ghost.io"},
		BodyMatch:   []string{"The thing you were looking for is no longer here, or never was"},
		Severity:    "MEDIUM",
	},
	{
		Service:     "Strikingly",
		CNAMESuffix: []string{"s.strikinglydns.com"},
		BodyMatch:   []string{"page not found", "But if you're looking to build your own website"},
		Severity:    "MEDIUM",
	},
	{
		Service:     "Unbounce",
		CNAMESuffix: []string{"unbouncepages.com"},
		BodyMatch:   []string{"The requested URL was not found on this server"},
		Severity:    "MEDIUM",
	},
	{
		Service:     "Webflow",
		CNAMESuffix: []string{"proxy.webflow.com", "proxy-ssl.webflow.com"},
		BodyMatch:   []string{"The page you are looking for doesn't exist or has been moved"},
		Severity:    "MEDIUM",
	},
	{
		Service:     "Wordpress.com",
		CNAMESuffix: []string{"wordpress.com"},
		BodyMatch:   []string{"Do you want to register"},
		Severity:    "MEDIUM",
	},
	{
		Service:     "Zendesk",
		CNAMESuffix: []string{"zendesk.com"},
		BodyMatch:   []string{"Help Center Closed"},
		Severity:    "MEDIUM",
	},
}

// Finding is one takeover candidate.
type Finding struct {
	Subdomain      string `json:"subdomain"`
	CNAME          string `json:"cname"`
	IPs            []string `json:"ips,omitempty"`
	Service        string `json:"service"`
	Severity       string `json:"severity"`
	HTTPStatus     int    `json:"http_status"`
	BodySnippet    string `json:"body_snippet,omitempty"`
	MatchedPattern string `json:"matched_pattern,omitempty"`
	Note           string `json:"note,omitempty"`
}

// HostResult holds the per-subdomain probe outcome (vulnerable or not).
type HostResult struct {
	Subdomain string   `json:"subdomain"`
	CNAME     string   `json:"cname"`
	IPs       []string `json:"ips,omitempty"`
	Status    string   `json:"status"`            // "no_cname", "resolved_normal", "unreachable", "candidate", "vulnerable"
	Note      string   `json:"note,omitempty"`    // why status was assigned
	Finding   *Finding `json:"finding,omitempty"` // present when status="vulnerable"
}

type ScanResult struct {
	Results  []HostResult `json:"results"`
	Findings []Finding    `json:"findings"`
}

type Config struct {
	Subdomains  []string
	Concurrency int
	Timeout     time.Duration
}

type ProgressFunc func(done int, msg string)
type PartialFunc func(*ScanResult)

func Scan(ctx context.Context, cfg Config, opts *shared.HTTPOptions, progress ProgressFunc, partial PartialFunc) *ScanResult {
	if cfg.Concurrency <= 0 {
		cfg.Concurrency = 10
	}
	if cfg.Timeout <= 0 {
		cfg.Timeout = 10 * time.Second
	}
	result := &ScanResult{}
	var mu sync.Mutex
	sem := make(chan struct{}, cfg.Concurrency)
	var wg sync.WaitGroup
	done := 0
	// Audit S2: per-subdomain partial copied Results+Findings — quadratic
	// at 1000+ subdomain inputs. Throttle to 2s; final flush after wg.Wait.
	throttle := shared.NewPartialThrottler(2 * time.Second)

	// Audit MEDIUM: build the HTTP transport + client ONCE for the whole
	// scan instead of one transport per scheme per subdomain. Previous
	// pattern registered ~2*N transports with opts, each with its own
	// idle-conn pool retained until FinishScan.
	sharedTransport := &http.Transport{
		TLSClientConfig:     &tls.Config{InsecureSkipVerify: true},
		DialContext:         shared.BoundDialer(opts, cfg.Timeout).DialContext,
		MaxIdleConns:        100,
		MaxIdleConnsPerHost: 50,
		IdleConnTimeout:     90 * time.Second,
	}
	if opts != nil {
		opts.ApplyTransport(sharedTransport)
	}
	sharedClient := &http.Client{
		Timeout:   cfg.Timeout,
		Transport: sharedTransport,
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			if len(via) > 5 {
				return http.ErrUseLastResponse
			}
			return nil
		},
	}

dispatch:
	for _, sd := range cfg.Subdomains {
		// Audit MEDIUM: select on the semaphore send so ctx.Done wakes
		// the dispatcher immediately. Previously a blocking `sem <- {}`
		// could stall for up to `Timeout` seconds per probe before the
		// dispatcher noticed cancellation.
		select {
		case <-ctx.Done():
			break dispatch
		case sem <- struct{}{}:
		}
		wg.Add(1)
		go func(sub string) {
			defer wg.Done()
			defer func() { <-sem }()
			hr := probe(ctx, sub, cfg.Timeout, opts, sharedClient)
			mu.Lock()
			result.Results = append(result.Results, hr)
			if hr.Finding != nil {
				result.Findings = append(result.Findings, *hr.Finding)
			}
			done++
			cur := done
			mu.Unlock()
			if progress != nil {
				progress(cur, fmt.Sprintf("[%d/%d] %s — %s", cur, len(cfg.Subdomains), sub, hr.Status))
			}
			if partial != nil && throttle.ShouldFire() {
				mu.Lock()
				snap := &ScanResult{
					Results:  append([]HostResult(nil), result.Results...),
					Findings: append([]Finding(nil), result.Findings...),
				}
				mu.Unlock()
				partial(snap)
			}
		}(sd)
	}
	wg.Wait()
	if partial != nil {
		throttle.Force()
		mu.Lock()
		snap := &ScanResult{
			Results:  append([]HostResult(nil), result.Results...),
			Findings: append([]Finding(nil), result.Findings...),
		}
		mu.Unlock()
		partial(snap)
	}
	return result
}

// probe runs the full take-over check pipeline for a single subdomain.
// Audit MEDIUM: takes the scan ctx + a shared *http.Client so DNS/HTTP
// obey cancellation and the transport isn't reallocated per probe.
func probe(ctx context.Context, sub string, timeout time.Duration, opts *shared.HTTPOptions, client *http.Client) HostResult {
	hr := HostResult{Subdomain: sub}

	cname, err := resolveCNAME(ctx, sub, timeout)
	if err != nil || cname == "" {
		hr.Status = "no_cname"
		hr.Note = "No CNAME record"
		return hr
	}
	hr.CNAME = cname

	if ctx.Err() != nil {
		hr.Status = "no_cname"
		hr.Note = "cancelled"
		return hr
	}

	// Check IP resolution — if the CNAME ultimately resolves to IPs the
	// service is likely still alive and registered.
	ips, _ := lookupHost(ctx, sub, timeout)
	hr.IPs = ips

	// Match CNAME against signatures.
	matched := matchSignature(cname)
	if matched == nil {
		hr.Status = "resolved_normal"
		hr.Note = "CNAME does not match any takeover provider signature"
		return hr
	}

	if ctx.Err() != nil {
		hr.Status = "no_cname"
		hr.Note = "cancelled"
		return hr
	}

	// Highest-confidence signal: the CNAME target itself doesn't resolve.
	// subjack/subzy/nuclei treat "CNAME matches provider AND target is NXDOMAIN"
	// as a confirmed takeover with no HTTP body needed — an attacker can register
	// the dangling name on the provider and claim the subdomain.
	cnameIPs, cnameErr := lookupHost(ctx, cname, timeout)
	if cnameErr != nil || len(cnameIPs) == 0 {
		f := Finding{
			Subdomain:      sub,
			CNAME:          cname,
			IPs:            ips,
			Service:        matched.Service,
			Severity:       matched.Severity,
			MatchedPattern: "cname-target-nxdomain",
			Note: fmt.Sprintf("CNAME → %s but the target does not resolve (dangling). %s",
				matched.Service, matched.Note),
		}
		hr.Finding = &f
		hr.Status = "vulnerable"
		hr.Note = fmt.Sprintf("Confirmed takeover: CNAME → %s and target is NXDOMAIN/unresolved", matched.Service)
		return hr
	}

	// HTTP probe both schemes.
	status, body, used, err := httpProbe(ctx, sub, timeout, opts, client)
	if err != nil {
		hr.Status = "unreachable"
		hr.Note = fmt.Sprintf("CNAME → %s (%s) but HTTP probe failed: %v", cname, matched.Service, err)
		// We still keep this as a candidate worth manual review.
		f := Finding{
			Subdomain:      sub,
			CNAME:          cname,
			IPs:            ips,
			Service:        matched.Service,
			Severity:       "LOW",
			MatchedPattern: "cname-only (no HTTP)",
			Note:           matched.Note,
		}
		hr.Finding = &f
		hr.Status = "candidate"
		return hr
	}

	// Status filter (if signature defines specific statuses).
	if len(matched.Status) > 0 {
		ok := false
		for _, s := range matched.Status {
			if s == status {
				ok = true
				break
			}
		}
		if !ok {
			hr.Status = "resolved_normal"
			hr.Note = fmt.Sprintf("CNAME → %s but HTTP status %d not in takeover signature", matched.Service, status)
			return hr
		}
	}

	// Body fingerprint match.
	lowerBody := strings.ToLower(body)
	var hit string
	for _, pat := range matched.BodyMatch {
		if strings.Contains(lowerBody, strings.ToLower(pat)) {
			hit = pat
			break
		}
	}
	if hit == "" {
		hr.Status = "resolved_normal"
		hr.Note = fmt.Sprintf("CNAME → %s but body doesn't match takeover signature (HTTP %d via %s)", matched.Service, status, used)
		return hr
	}

	// Confirmed candidate.
	f := Finding{
		Subdomain:      sub,
		CNAME:          cname,
		IPs:            ips,
		Service:        matched.Service,
		Severity:       matched.Severity,
		HTTPStatus:     status,
		BodySnippet:    snippet(body, hit, 240),
		MatchedPattern: hit,
		Note:           matched.Note,
	}
	hr.Finding = &f
	hr.Status = "vulnerable"
	hr.Note = fmt.Sprintf("Probable takeover: %s (matched %q in body)", matched.Service, hit)
	return hr
}

// matchSignature does a strict trailing-label match so attacker-controlled
// names like "mybucket.s3.amazonaws.com.evil.tld" do NOT match the S3 signature.
// A signature suffix matches when the CNAME equals it exactly OR ends in "."+suffix.
func matchSignature(cname string) *Signature {
	c := strings.ToLower(strings.TrimSuffix(cname, "."))
	for i := range Signatures {
		s := &Signatures[i]
		for _, suf := range s.CNAMESuffix {
			sufLower := strings.ToLower(strings.TrimSuffix(suf, "."))
			if sufLower == "" {
				continue
			}
			if c == sufLower || strings.HasSuffix(c, "."+sufLower) {
				return s
			}
		}
	}
	return nil
}

// boundResolver returns a *net.Resolver whose underlying Dial uses
// shared.BoundDialer so DNS traffic obeys the killswitch's source-IP
// binding (Layer 2). When the killswitch is dormant, BoundDialer
// returns a plain dialer, so this is safe in default mode too.
// PreferGo forces Go's resolver path so our Dial is actually invoked
// (the cgo resolver would bypass it).
func boundResolver(timeout time.Duration) *net.Resolver {
	return &net.Resolver{
		PreferGo: true,
		Dial: func(ctx context.Context, network, address string) (net.Conn, error) {
			return shared.BoundDialer(nil, timeout).DialContext(ctx, network, address)
		},
	}
}

// Audit MEDIUM: resolveCNAME/lookupHost now take the scan ctx so a Cancel
// propagates to in-flight DNS lookups instead of blocking for up to
// `timeout` per probe. The parent ctx is combined with a per-lookup
// deadline via context.WithTimeout.
func resolveCNAME(ctx context.Context, host string, timeout time.Duration) (string, error) {
	res := boundResolver(timeout)
	lctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	cname, err := res.LookupCNAME(lctx, host)
	if err != nil {
		return "", err
	}
	cname = strings.TrimSuffix(cname, ".")
	if strings.EqualFold(cname, host) {
		return "", nil
	}
	return cname, nil
}

func lookupHost(ctx context.Context, host string, timeout time.Duration) ([]string, error) {
	res := boundResolver(timeout)
	lctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	return res.LookupHost(lctx, host)
}

// httpProbe tries HTTPS then HTTP, returns (status, body, scheme, err).
// Audit MEDIUM: reuses the shared *http.Client built once in Scan() so we
// don't leak one transport per scheme per subdomain into opts.transports.
func httpProbe(ctx context.Context, host string, timeout time.Duration, opts *shared.HTTPOptions, client *http.Client) (int, string, string, error) {
	for _, scheme := range []string{"https", "http"} {
		url := scheme + "://" + host + "/"
		req, err := http.NewRequestWithContext(ctx, "GET", url, nil)
		if err != nil {
			continue
		}
		req.Header.Set("User-Agent", "Mozilla/5.0 scaNNer/Takeover")
		if opts != nil {
			opts.ApplyTo(req)
		}
		resp, err := client.Do(req)
		if err != nil {
			continue
		}
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 128*1024))
		resp.Body.Close()
		return resp.StatusCode, string(body), scheme, nil
	}
	return 0, "", "", fmt.Errorf("both http and https probes failed")
}

func snippet(body, hit string, span int) string {
	low := strings.ToLower(body)
	idx := strings.Index(low, strings.ToLower(hit))
	if idx < 0 {
		if len(body) > span {
			return body[:span] + "..."
		}
		return body
	}
	start := idx - 60
	if start < 0 {
		start = 0
	}
	end := idx + len(hit) + 100
	if end > len(body) {
		end = len(body)
	}
	s := body[start:end]
	s = strings.ReplaceAll(s, "\n", " ")
	s = strings.ReplaceAll(s, "\r", " ")
	if len(s) > span {
		s = s[:span] + "..."
	}
	return s
}
