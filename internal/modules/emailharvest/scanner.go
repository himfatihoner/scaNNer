package emailharvest

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"scanner/internal/modules/shared"
	"sort"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

type DomainResult struct {
	Domain    string   `json:"domain"`
	Sources   []string `json:"sources"`
	Emails    []string `json:"emails"`
	Hosts     []string `json:"hosts"`
	IPs       []string `json:"ips"`
	Error     string   `json:"error,omitempty"`
	RawOutput string   `json:"raw_output,omitempty"`

	// Optional enrichment populated when the matching toggle is on.
	DNSAuth     *DNSAuthInfo `json:"dns_auth,omitempty"`
	Breaches    []BreachInfo `json:"breaches,omitempty"`
	BreachError string       `json:"breach_error,omitempty"`
}

// DNSAuthInfo captures email-authentication DNS records.
type DNSAuthInfo struct {
	MX            []MXRecord   `json:"mx,omitempty"`
	SPF           string       `json:"spf,omitempty"`
	SPFFinding    string       `json:"spf_finding,omitempty"` // hard fail / soft fail / missing / etc.
	DMARC         string       `json:"dmarc,omitempty"`
	DMARCFinding  string       `json:"dmarc_finding,omitempty"`
	DKIMSelectors []DKIMRecord `json:"dkim_selectors,omitempty"`
	MailProvider  string       `json:"mail_provider,omitempty"` // best-effort guess from MX hostnames
}

type MXRecord struct {
	Host string `json:"host"`
	Pref uint16 `json:"pref"`
}

type DKIMRecord struct {
	Selector string `json:"selector"`
	Record   string `json:"record"`
}

// BreachInfo is one entry from HIBP's domain breach API (no key required).
type BreachInfo struct {
	Name        string   `json:"name"`
	Title       string   `json:"title"`
	BreachDate  string   `json:"breach_date,omitempty"`
	PwnCount    int      `json:"pwn_count,omitempty"`
	DataClasses []string `json:"data_classes,omitempty"`
	IsVerified  bool     `json:"is_verified,omitempty"`
	IsSensitive bool     `json:"is_sensitive,omitempty"`
	Description string   `json:"description,omitempty"`
}

type ScanResult struct {
	Results []DomainResult `json:"results"`
}

type Config struct {
	Domains     []string
	Sources     []string // e.g. "crtsh", "hackertarget"
	Limit       int
	Concurrency int

	// Enrichment toggles
	DNSAuth   bool   // resolve MX/SPF/DMARC/DKIM records
	HIBPCheck bool   // query HIBP /breaches?domain=X for breach list
	HIBPKey   string // optional pwned-1 API key for per-account check (premium)

	// HTTP options for Go-side HTTP calls (HIBP). When non-nil, BoundDialer +
	// transport registration is wired so the killswitch's interface pinning
	// applies and cancel-time CloseIdleConnections drains pooled sockets.
	HTTPOpts *shared.HTTPOptions
}

type ProgressFunc func(done int, msg string)
type PartialFunc func(*ScanResult)

// AllSources lists theHarvester sources that work without API keys in
// theHarvester 4.10+. Older names like anubis/threatminer/bing/sitedossier
// were removed upstream and would cause "Invalid source." failures.
var AllSources = []string{
	"crtsh", "hackertarget", "rapiddns", "urlscan", "duckduckgo",
	"otx", "yahoo", "baidu", "dnsdumpster", "certspotter",
	"commoncrawl", "subdomaincenter", "waybackarchive", "threatcrowd", "robtex",
}

// DefaultSources are pre-ticked in the UI and used when the user submits no
// source selections. Single source of truth so the template and Scan() can't
// drift apart (an earlier "anubis" reference lingered in the form long after
// the scanner stopped accepting it).
var DefaultSources = []string{"crtsh", "hackertarget", "duckduckgo", "otx", "rapiddns"}

func Scan(ctx context.Context, cfg Config, progress ProgressFunc, partial PartialFunc) *ScanResult {
	if ctx == nil {
		ctx = context.Background()
	}
	if cfg.Limit <= 0 {
		cfg.Limit = 200
	}
	if cfg.Concurrency <= 0 {
		cfg.Concurrency = 2
	}
	if len(cfg.Sources) == 0 {
		cfg.Sources = append([]string(nil), DefaultSources...)
	}
	out := &ScanResult{}
	var mu sync.Mutex
	sem := make(chan struct{}, cfg.Concurrency)
	var wg sync.WaitGroup
	// Audit B/M findings: `done` was a plain int read lock-free at the goroutine
	// entry and written under `mu` elsewhere — a textbook data race that -race
	// would trip on every scan. Atomic eliminates the race AND lets the
	// progress callback (which does SQLite I/O) run outside the result lock.
	var done atomic.Int64

	// Audit S2: throttle per-domain partial snapshot+marshal to 2s.
	throttle := shared.NewPartialThrottler(2 * time.Second)
	pushPartial := func() {
		if partial == nil {
			return
		}
		if !throttle.ShouldFire() {
			return
		}
		mu.Lock()
		snap := &ScanResult{Results: append([]DomainResult(nil), out.Results...)}
		mu.Unlock()
		partial(snap)
	}

	for _, d := range cfg.Domains {
		if ctx.Err() != nil {
			break
		}
		wg.Add(1)
		sem <- struct{}{}
		go func(domain string) {
			defer wg.Done()
			defer func() { <-sem }()
			if progress != nil {
				progress(int(done.Load()), fmt.Sprintf("Harvesting %s ...", domain))
			}
			tr := harvest(ctx, domain, cfg, progress, int(done.Load()))

			// Enrichment phases (after main theHarvester run). progress is
			// invoked outside any locks because the handler-supplied callback
			// performs a SQLite UpdateScanProgress which can block on WAL fsync
			// (up to busy_timeout, ~5s) — holding mu across it would stall
			// every other harvest goroutine's final result-append.
			if cfg.DNSAuth {
				if progress != nil {
					progress(int(done.Load()), fmt.Sprintf("[%s] resolving MX/SPF/DMARC/DKIM ...", domain))
				}
				tr.DNSAuth = lookupDNSAuth(ctx, domain)
			}
			if cfg.HIBPCheck {
				if progress != nil {
					progress(int(done.Load()), fmt.Sprintf("[%s] checking HIBP breaches ...", domain))
				}
				breaches, err := queryHIBPBreaches(ctx, domain, cfg.HIBPKey, cfg.HTTPOpts)
				if err != nil {
					tr.BreachError = err.Error()
				}
				tr.Breaches = breaches
			}

			cur := int(done.Add(1))
			mu.Lock()
			out.Results = append(out.Results, *tr)
			mu.Unlock()
			if progress != nil {
				summary := fmt.Sprintf("[%d/%d] %s — %d emails, %d hosts", cur, len(cfg.Domains), domain, len(tr.Emails), len(tr.Hosts))
				if tr.DNSAuth != nil {
					summary += fmt.Sprintf(", %d MX, SPF=%s, DMARC=%s", len(tr.DNSAuth.MX), boolStr(tr.DNSAuth.SPF != ""), boolStr(tr.DNSAuth.DMARC != ""))
				}
				if len(tr.Breaches) > 0 {
					summary += fmt.Sprintf(", %d HIBP breaches", len(tr.Breaches))
				}
				progress(cur, summary)
			}
			pushPartial()
		}(d)
	}
	wg.Wait()
	throttle.Force()
	pushPartial()
	return out
}

func harvest(ctx context.Context, domain string, cfg Config, progress ProgressFunc, done int) *DomainResult {
	dr := &DomainResult{Domain: domain, Sources: cfg.Sources}

	// theHarvester emits structured JSON when -f points to a json path.
	// Use a temp file we can read after the process exits.
	tmp, err := os.CreateTemp("", "harvest-*.json")
	if err != nil {
		dr.Error = "tempfile: " + err.Error()
		return dr
	}
	tmp.Close()
	defer os.Remove(tmp.Name())
	defer os.Remove(strings.TrimSuffix(tmp.Name(), ".json") + ".xml")

	args := []string{
		"-d", domain,
		"-b", strings.Join(cfg.Sources, ","),
		"-l", fmt.Sprintf("%d", cfg.Limit),
		"-f", strings.TrimSuffix(tmp.Name(), ".json"),
	}
	// Per-call timeout (audit B15). theHarvester routinely hangs on
	// dead source APIs (Google, Bing, etc. rate-limit + unanswered
	// HTTPS connections). Without this 5-minute cap a single harvest
	// could pin a goroutine + tempfile for hours. We derive from the
	// caller's ctx so an outer cancel still wins immediately.
	harvCtx, harvCancel := context.WithTimeout(ctx, 5*time.Minute)
	defer harvCancel()
	if progress != nil {
		progress(done, "$ "+shared.FormatCommand("theHarvester", args))
	}
	cmd := shared.Command(harvCtx, "theHarvester", args...)
	out, err := cmd.CombinedOutput()
	dr.RawOutput = truncate(string(out), 32*1024)
	if err != nil && len(out) == 0 {
		dr.Error = "theHarvester failed: " + err.Error()
		return dr
	}
	if strings.Contains(string(out), "Invalid source.") {
		// Extract the offending source set from "The following engines are not supported: {...}"
		bad := ""
		if i := strings.Index(string(out), "not supported:"); i >= 0 {
			line := string(out)[i:]
			if nl := strings.Index(line, "\n"); nl > 0 {
				line = line[:nl]
			}
			bad = strings.TrimSpace(strings.TrimPrefix(line, "not supported:"))
		}
		dr.Error = "theHarvester rejected one or more sources" + func() string {
			if bad != "" {
				return " (" + bad + ")"
			}
			return ""
		}() + " — try unticking the unsupported source"
		return dr
	}

	// Try to parse the JSON file (newer theHarvester versions). Fall back to
	// regex-extracting from stdout if the file isn't there.
	if data, err := os.ReadFile(tmp.Name()); err == nil && len(data) > 0 {
		var parsed struct {
			Emails []string `json:"emails"`
			Hosts  []string `json:"hosts"`
			IPs    []string `json:"ips"`
		}
		if err := json.Unmarshal(data, &parsed); err == nil {
			dr.Emails = dedupe(parsed.Emails)
			dr.Hosts = dedupe(parsed.Hosts)
			dr.IPs = dedupe(parsed.IPs)
		}
	}
	// Audit M-findings: previous fallback only checked Emails+Hosts and
	// then clobbered dr.IPs with regex matches even when the JSON parse
	// had already returned trustworthy IPs. Promote each field's fallback
	// independently so structured-JSON data is never overwritten by
	// stdout-regex noise.
	rawOut := string(out)
	if len(dr.Emails) == 0 {
		dr.Emails = extractEmails(rawOut, domain)
	}
	if len(dr.Hosts) == 0 {
		dr.Hosts = extractHosts(rawOut, domain)
	}
	if len(dr.IPs) == 0 {
		dr.IPs = extractIPs(rawOut)
	}
	if filepath.IsAbs(tmp.Name()) {
		// nothing — handled by defer
	}
	return dr
}

var emailRE = regexp.MustCompile(`(?i)[A-Z0-9._%+\-]+@[A-Z0-9.\-]+\.[A-Z]{2,}`)
var ipRE = regexp.MustCompile(`\b(?:\d{1,3}\.){3}\d{1,3}\b`)
var hostRE = regexp.MustCompile(`(?i)\b(?:[a-z0-9](?:[a-z0-9\-]{0,61}[a-z0-9])?\.)+[a-z]{2,}\b`)

func extractEmails(s, domain string) []string {
	matches := emailRE.FindAllString(s, -1)
	domain = strings.ToLower(domain)
	out := map[string]bool{}
	for _, m := range matches {
		m = strings.ToLower(m)
		if strings.HasSuffix(m, "@"+domain) || strings.Contains(m, "."+domain) {
			out[m] = true
		}
	}
	return mapKeys(out)
}

func extractHosts(s, domain string) []string {
	matches := hostRE.FindAllString(s, -1)
	domain = strings.ToLower(domain)
	out := map[string]bool{}
	for _, m := range matches {
		m = strings.ToLower(m)
		if (m == domain || strings.HasSuffix(m, "."+domain)) && !strings.Contains(m, "@") {
			out[m] = true
		}
	}
	return mapKeys(out)
}

func extractIPs(s string) []string {
	out := map[string]bool{}
	for _, m := range ipRE.FindAllString(s, -1) {
		out[m] = true
	}
	return mapKeys(out)
}

func dedupe(in []string) []string {
	seen := map[string]bool{}
	out := []string{}
	for _, s := range in {
		s = strings.TrimSpace(s)
		if s == "" || seen[s] {
			continue
		}
		seen[s] = true
		out = append(out, s)
	}
	return out
}

func mapKeys(m map[string]bool) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	return out
}

func truncate(s string, max int) string {
	if len(s) <= max {
		return s
	}
	return s[:max] + "\n... [truncated]"
}

// --- DNS authentication enrichment ---

// commonDKIMSelectors covers the selectors that mainstream providers and most
// self-hosted setups actually use. We TXT-probe each one in parallel.
var commonDKIMSelectors = []string{
	"default", "selector1", "selector2", "google", "mail", "email",
	"s1", "s2", "k1", "k2", "dkim", "smtp", "mxvault", "mailo",
	"mailjet", "sendgrid", "amazonses", "mta",
}

func lookupDNSAuth(ctx context.Context, domain string) *DNSAuthInfo {
	info := &DNSAuthInfo{}
	resolver := &net.Resolver{}
	dnsCtx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()

	// MX
	if mxs, err := resolver.LookupMX(dnsCtx, domain); err == nil {
		for _, mx := range mxs {
			info.MX = append(info.MX, MXRecord{
				Host: strings.TrimSuffix(mx.Host, "."),
				Pref: mx.Pref,
			})
		}
		sort.Slice(info.MX, func(i, j int) bool { return info.MX[i].Pref < info.MX[j].Pref })
		info.MailProvider = guessMailProvider(info.MX)
	}

	// SPF: TXT on the apex, look for "v=spf1"
	if txts, err := resolver.LookupTXT(dnsCtx, domain); err == nil {
		for _, t := range txts {
			low := strings.ToLower(t)
			if strings.HasPrefix(low, "v=spf1") {
				info.SPF = t
				info.SPFFinding = analyzeSPF(t)
				break
			}
		}
	}
	if info.SPF == "" {
		info.SPFFinding = "missing — domain accepts mail from anyone"
	}

	// DMARC: TXT on _dmarc.<domain>
	if txts, err := resolver.LookupTXT(dnsCtx, "_dmarc."+domain); err == nil {
		for _, t := range txts {
			if strings.HasPrefix(strings.ToLower(t), "v=dmarc1") {
				info.DMARC = t
				info.DMARCFinding = analyzeDMARC(t)
				break
			}
		}
	}
	if info.DMARC == "" {
		info.DMARCFinding = "missing — no policy advertised"
	}

	// DKIM: probe common selectors
	var mu sync.Mutex
	var wg sync.WaitGroup
	sem := make(chan struct{}, 8)
	for _, sel := range commonDKIMSelectors {
		wg.Add(1)
		sem <- struct{}{}
		go func(selector string) {
			defer wg.Done()
			defer func() { <-sem }()
			selCtx, cancelSel := context.WithTimeout(ctx, 4*time.Second)
			defer cancelSel()
			recs, err := resolver.LookupTXT(selCtx, selector+"._domainkey."+domain)
			if err != nil || len(recs) == 0 {
				return
			}
			for _, r := range recs {
				if strings.Contains(strings.ToLower(r), "v=dkim1") || strings.Contains(strings.ToLower(r), "k=") {
					mu.Lock()
					info.DKIMSelectors = append(info.DKIMSelectors, DKIMRecord{Selector: selector, Record: r})
					mu.Unlock()
					return
				}
			}
		}(sel)
	}
	wg.Wait()
	sort.Slice(info.DKIMSelectors, func(i, j int) bool {
		return info.DKIMSelectors[i].Selector < info.DKIMSelectors[j].Selector
	})
	return info
}

// analyzeSPF picks out the qualifier on the catch-all to flag weak policies.
func analyzeSPF(record string) string {
	r := strings.ToLower(record)
	switch {
	case strings.Contains(r, "-all"):
		return "hard fail (-all) — strict, recommended"
	case strings.Contains(r, "~all"):
		return "soft fail (~all) — partial protection"
	case strings.Contains(r, "?all"):
		return "neutral (?all) — no protection"
	case strings.Contains(r, "+all"):
		return "permissive (+all) — anyone can spoof, dangerous"
	}
	return "no terminating mechanism"
}

func analyzeDMARC(record string) string {
	r := strings.ToLower(record)
	switch {
	case strings.Contains(r, "p=reject"):
		return "p=reject — strict, recommended"
	case strings.Contains(r, "p=quarantine"):
		return "p=quarantine — moderate"
	case strings.Contains(r, "p=none"):
		return "p=none — monitoring only, no enforcement"
	}
	return "policy not parseable"
}

// guessMailProvider does a best-effort lookup against MX hostnames.
func guessMailProvider(mxs []MXRecord) string {
	for _, m := range mxs {
		host := strings.ToLower(m.Host)
		switch {
		case strings.HasSuffix(host, ".outlook.com") || strings.Contains(host, "protection.outlook.com"):
			return "Microsoft 365 / Exchange Online"
		case strings.HasSuffix(host, ".google.com") || strings.HasSuffix(host, ".googlemail.com"):
			return "Google Workspace"
		case strings.Contains(host, "mimecast"):
			return "Mimecast"
		case strings.Contains(host, "proofpoint"):
			return "Proofpoint"
		case strings.Contains(host, "zoho"):
			return "Zoho Mail"
		case strings.Contains(host, "yandex"):
			return "Yandex 360"
		case strings.Contains(host, "amazonses"):
			return "Amazon SES"
		case strings.Contains(host, "sendgrid"):
			return "SendGrid"
		case strings.Contains(host, "mailgun"):
			return "Mailgun"
		case strings.Contains(host, "fastmail"):
			return "Fastmail"
		}
	}
	return ""
}

// --- HIBP enrichment ---

// queryHIBPBreaches uses Have I Been Pwned's free /breaches?domain= endpoint
// to list every breach that involved the domain. No API key required.
// If hibpKey is supplied the request is still the domain-level /breaches call
// (the same endpoint accepts auth and returns the same shape); per-account
// /breachedaccount/{email} lookups are deliberately not issued here because
// the HIBP free-tier rate-limit (one request / 6 s) would extend a multi-email
// scan to many minutes. The UI text in emailharvest.html no longer promises
// "premium per-account endpoints available" — it advertises the key as
// configured-and-used for /breaches.
func queryHIBPBreaches(ctx context.Context, domain, hibpKey string, opts *shared.HTTPOptions) ([]BreachInfo, error) {
	httpCtx, cancel := context.WithTimeout(ctx, 20*time.Second)
	defer cancel()
	endpoint := "https://haveibeenpwned.com/api/v3/breaches?domain=" + url.QueryEscape(domain)
	req, err := http.NewRequestWithContext(httpCtx, "GET", endpoint, nil)
	if err != nil {
		// Audit M finding: previous code discarded this error then dereferenced
		// req on the next line — a control-char/whitespace-bearing domain could
		// nil-panic the whole goroutine.
		return nil, fmt.Errorf("hibp request build: %w", err)
	}
	req.Header.Set("User-Agent", "scaNNer-EmailHarvester/1.0")
	if hibpKey != "" {
		req.Header.Set("hibp-api-key", hibpKey)
	}
	// Audit S1/M findings: build the client via shared.HTTPOptions when we have
	// one so killswitch L2 source-IP binding AND scan-cancel idle-pool flushing
	// both apply. Fall back to a BoundDialer-only client if the caller didn't
	// pass opts (preserves prior behaviour for tests / direct callers).
	var client *http.Client
	if opts != nil {
		client = opts.NewHTTPClient()
	} else {
		client = &http.Client{
			Timeout: 25 * time.Second,
			Transport: &http.Transport{
				DialContext: shared.BoundDialer(nil, 10*time.Second).DialContext,
			},
		}
	}
	resp, err := client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("hibp: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode == 404 {
		return nil, nil // no breaches recorded for this domain
	}
	if resp.StatusCode == 429 {
		return nil, fmt.Errorf("hibp rate-limited (429) — wait ~6 seconds and retry")
	}
	if resp.StatusCode != 200 {
		return nil, fmt.Errorf("hibp returned HTTP %d", resp.StatusCode)
	}
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 4*1024*1024))

	// HIBP returns either an array of breach objects (with key) or a list of
	// names (without key). Try the rich shape first, fall back to []string.
	var rich []struct {
		Name        string   `json:"Name"`
		Title       string   `json:"Title"`
		BreachDate  string   `json:"BreachDate"`
		PwnCount    int      `json:"PwnCount"`
		DataClasses []string `json:"DataClasses"`
		IsVerified  bool     `json:"IsVerified"`
		IsSensitive bool     `json:"IsSensitive"`
		Description string   `json:"Description"`
	}
	if err := json.Unmarshal(body, &rich); err == nil && len(rich) > 0 {
		out := make([]BreachInfo, 0, len(rich))
		for _, b := range rich {
			out = append(out, BreachInfo{
				Name:        b.Name,
				Title:       b.Title,
				BreachDate:  b.BreachDate,
				PwnCount:    b.PwnCount,
				DataClasses: b.DataClasses,
				IsVerified:  b.IsVerified,
				IsSensitive: b.IsSensitive,
				Description: b.Description,
			})
		}
		return out, nil
	}
	var names []string
	if err := json.Unmarshal(body, &names); err == nil {
		out := make([]BreachInfo, 0, len(names))
		for _, n := range names {
			out = append(out, BreachInfo{Name: n, Title: n})
		}
		return out, nil
	}
	return nil, nil
}

func boolStr(b bool) string {
	if b {
		return "✓"
	}
	return "✗"
}
