package leakscan

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"time"

	"scanner/internal/modules/shared"
)

// newLeakClient builds a bounded HTTP client for every Pastebin / Wayback /
// GitHub call. Audit S1: the previous package-level `leakHTTPClient` used
// the stdlib default dialer, bypassing the killswitch L2 source-IP binding —
// when the killswitch was armed, GitHub/Pastebin queries leaked over the
// host's default route. shared.BoundDialer consults the global pinned addr
// (set by SetGlobalLocalAddr in handlers.BuildHTTPOptions) so traffic
// honors the chosen outbound interface even though we don't have an
// HTTPOptions per request here. The bounded transport limits keep idle
// conn growth in check (audit B46).
func newLeakClient() *http.Client {
	return &http.Client{
		Timeout: 20 * time.Second,
		Transport: &http.Transport{
			MaxIdleConns:        20,
			MaxIdleConnsPerHost: 5,
			IdleConnTimeout:     60 * time.Second,
			DialContext:         shared.BoundDialer(nil, 10*time.Second).DialContext,
		},
	}
}

// Match is one suspicious string found in a GitHub file.
type Match struct {
	Pattern string `json:"pattern"`
	Sample  string `json:"sample"` // first 200 chars around the match
}

type Hit struct {
	Repo    string  `json:"repo"`     // user/repo
	Path    string  `json:"path"`     // file path inside the repo
	HTMLURL string  `json:"html_url"` // browser URL
	RawURL  string  `json:"raw_url"`  // raw.githubusercontent.com URL
	Snippet string  `json:"snippet,omitempty"`
	Matches []Match `json:"matches,omitempty"`
}

type QueryResult struct {
	Query string `json:"query"`
	Hits  []Hit  `json:"hits"`
	// HitCount is the number of Hit rows actually stored (i.e. the rows
	// the UI will render). Previously this conflated with GitHub's
	// `total_count` which is the unbounded upstream total — see
	// TotalAvailable for that value.
	HitCount int `json:"hit_count"`
	// TotalAvailable is the upstream-reported total result count
	// (currently only populated for GitHub Code Search). Templates can
	// render "showing N of M" when this is > HitCount.
	TotalAvailable int    `json:"total_available,omitempty"`
	MatchCount     int    `json:"match_count"`
	Error          string `json:"error,omitempty"`
	// Raw HTTP capture of the source-API query (GitHub Code Search etc.)
	// One entry per source so reports can prove the exact request.
	RawRequest  string `json:"raw_request,omitempty"`
	RawResponse string `json:"raw_response,omitempty"`
}

type ScanResult struct {
	Results []QueryResult `json:"results"`
}

type Config struct {
	Queries       []string // free-form keywords or full GitHub search queries
	GitHubToken   string   // optional — boosts rate limit and access
	MaxFiles      int      // cap files we fetch per query
	FetchSnippets bool     // download raw file (limited) and run secret regex
	// Source toggles. GitHub is the default; the others widen the
	// search surface to historical / public-paste / archive content
	// where leaked secrets often survive long after the original
	// upload was deleted from GitHub.
	IncludePastebin bool // Pastebin public search via scrape API
	IncludeWayback  bool // Wayback Machine CDX API for historical URLs
}

type ProgressFunc func(done int, msg string)
type PartialFunc func(*ScanResult)

// Built-in secret regexes. Compact list — focus on high-signal patterns.
var secretPatterns = []struct {
	Name string
	RE   *regexp.Regexp
}{
	{"AWS Access Key", regexp.MustCompile(`AKIA[0-9A-Z]{16}`)},
	{"AWS Secret Key", regexp.MustCompile(`(?i)aws(.{0,20})?(secret|access)?[=:][\s'"]*([A-Za-z0-9/+=]{40})`)},
	{"GitHub Token", regexp.MustCompile(`gh[pousr]_[A-Za-z0-9]{36,}`)},
	{"GitHub Fine-grained", regexp.MustCompile(`github_pat_[A-Za-z0-9_]{82}`)},
	{"GitLab Token", regexp.MustCompile(`glpat-[A-Za-z0-9_\-]{20,}`)},
	{"Slack Token", regexp.MustCompile(`xox[baprs]-[A-Za-z0-9-]{10,}`)},
	{"Stripe Live Key", regexp.MustCompile(`sk_live_[A-Za-z0-9]{24,}`)},
	{"Google API Key", regexp.MustCompile(`AIza[0-9A-Za-z_\-]{35}`)},
	{"Mailgun API Key", regexp.MustCompile(`key-[a-z0-9]{32}`)},
	{"SendGrid Key", regexp.MustCompile(`SG\.[A-Za-z0-9_\-]{22}\.[A-Za-z0-9_\-]{43}`)},
	{"Heroku API Key", regexp.MustCompile(`(?i)heroku(.{0,20})?[=:][\s'"]*([0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12})`)},
	{"JWT", regexp.MustCompile(`eyJ[A-Za-z0-9_\-]{10,}\.eyJ[A-Za-z0-9_\-]{10,}\.[A-Za-z0-9_\-]+`)},
	{"Private Key", regexp.MustCompile(`-----BEGIN (RSA |OPENSSH |EC |DSA |PGP )?PRIVATE KEY-----`)},
	{"Password Assignment", regexp.MustCompile(`(?i)\b(password|passwd|pwd|secret|api_key|apikey|token)\s*[:=]\s*["'][^"'\s]{6,}["']`)},
	{"Generic Authorization", regexp.MustCompile(`(?i)\bauthorization\s*[:=]\s*["']?(?:bearer|basic)\s+[A-Za-z0-9._\-]{16,}`)},
}

func Scan(ctx context.Context, cfg Config, progress ProgressFunc, partial PartialFunc) *ScanResult {
	return ScanWithClient(ctx, cfg, nil, progress, partial)
}

// ScanWithClient is the same as Scan but accepts a caller-provided HTTP
// client. Handlers pass an opts-bound client built via
// shared.HTTPOptions.NewHTTPClient so the transport pool is registered
// with the ScanManager (idle pool flush on cancel) and the dialer honors
// the killswitch (audit MEDIUM). If client is nil, a fallback per-scan
// bounded client is built locally — but that client is not registered
// with HTTPOptions, so prefer the caller-provided form.
func ScanWithClient(ctx context.Context, cfg Config, client *http.Client, progress ProgressFunc, partial PartialFunc) *ScanResult {
	if ctx == nil {
		ctx = context.Background()
	}
	if cfg.MaxFiles <= 0 {
		cfg.MaxFiles = 30
	}
	out := &ScanResult{}
	var mu sync.Mutex
	done := 0

	// Audit S2: throttle per-query partial snapshot+marshal to 2s.
	throttle := shared.NewPartialThrottler(2 * time.Second)
	pushPartial := func() {
		if partial == nil {
			return
		}
		if !throttle.ShouldFire() {
			return
		}
		mu.Lock()
		snap := &ScanResult{Results: append([]QueryResult(nil), out.Results...)}
		mu.Unlock()
		partial(snap)
	}

	// Use the caller-provided client when available (registered with
	// HTTPOptions so cancel can flush idle conns). Fallback to the
	// local builder for direct Scan() callers (e.g. tests / CLI use).
	if client == nil {
		client = newLeakClient()
	}

	for _, q := range cfg.Queries {
		if ctx.Err() != nil {
			break
		}
		if progress != nil {
			progress(done, "querying GitHub for: "+q)
		}
		qr := searchGitHub(ctx, client, q, cfg)
		// Optional broadening: Pastebin public listings and Wayback
		// CDX. Both contribute additional Hit entries to the same
		// query result so the UI shows them in one table per query.
		if cfg.IncludePastebin {
			if progress != nil {
				progress(done, "querying Pastebin for: "+q)
			}
			extra := searchPastebin(ctx, client, q, cfg.MaxFiles)
			qr.Hits = append(qr.Hits, extra...)
			qr.HitCount += len(extra)
		}
		if cfg.IncludeWayback {
			if progress != nil {
				progress(done, "querying Wayback Machine for: "+q)
			}
			extra := searchWayback(ctx, client, q, cfg.MaxFiles)
			qr.Hits = append(qr.Hits, extra...)
			qr.HitCount += len(extra)
		}
		if cfg.FetchSnippets && qr.Error == "" {
			// Audit MEDIUM (perf): run per-hit fetchRaw concurrently
			// behind a bounded semaphore matching MaxIdleConnsPerHost.
			// Each goroutine writes back to its own index — no shared
			// slice growth — so this is race-free without a per-hit
			// mutex. The previous sequential loop turned a 30-file
			// query into a 30 * round-trip-time wall-clock wait even
			// though the transport already supports 5 parallel conns.
			limit := cfg.MaxFiles
			if limit > len(qr.Hits) {
				limit = len(qr.Hits)
			}
			sem := make(chan struct{}, 5)
			var wg sync.WaitGroup
			var matchMu sync.Mutex
			for i := 0; i < limit; i++ {
				if ctx.Err() != nil {
					break
				}
				wg.Add(1)
				sem <- struct{}{}
				go func(idx int) {
					defer wg.Done()
					defer func() { <-sem }()
					if ctx.Err() != nil {
						return
					}
					body := fetchRaw(ctx, client, qr.Hits[idx].RawURL, cfg.GitHubToken)
					if body == "" {
						return
					}
					qr.Hits[idx].Snippet = trimSnippet(body, 4000)
					ms := matchSecrets(body)
					qr.Hits[idx].Matches = ms
					matchMu.Lock()
					qr.MatchCount += len(ms)
					matchMu.Unlock()
				}(i)
			}
			wg.Wait()
		}
		mu.Lock()
		done++
		out.Results = append(out.Results, qr)
		cur := done
		mu.Unlock()
		if progress != nil {
			progress(cur, fmt.Sprintf("[%d/%d] %s — %d files, %d secret matches", cur, len(cfg.Queries), q, qr.HitCount, qr.MatchCount))
		}
		pushPartial()
	}
	throttle.Force()
	pushPartial()
	return out
}

func searchGitHub(ctx context.Context, client *http.Client, q string, cfg Config) QueryResult {
	qr := QueryResult{Query: q}
	endpoint := "https://api.github.com/search/code?per_page=50&q=" + urlEncode(q)
	req, err := http.NewRequestWithContext(ctx, "GET", endpoint, nil)
	if err != nil {
		// Audit MEDIUM: NewRequestWithContext can return (nil, err)
		// on a malformed URL — the subsequent req.Header.Set would
		// nil-deref and take down the scan goroutine. Surface as an
		// error on the query result instead.
		qr.Error = "build request: " + err.Error()
		return qr
	}
	req.Header.Set("Accept", "application/vnd.github+json")
	req.Header.Set("X-GitHub-Api-Version", "2022-11-28")
	if cfg.GitHubToken != "" {
		req.Header.Set("Authorization", "Bearer "+cfg.GitHubToken)
	}
	qr.RawRequest = shared.CaptureRequest(req)
	resp, err := client.Do(req)
	if err != nil {
		qr.Error = "request failed: " + err.Error()
		return qr
	}
	// Audit MEDIUM (perf): drain any unread suffix so the connection
	// can be returned to the idle pool instead of being closed.
	defer func() { io.Copy(io.Discard, resp.Body); resp.Body.Close() }()
	qr.RawResponse = shared.CaptureResponse(resp)
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 1024*1024))
	// Audit MEDIUM: honor GitHub rate-limit headers. When the remaining
	// budget is exhausted GitHub returns 403 with X-RateLimit-Remaining:0
	// and X-RateLimit-Reset:<unix-epoch>. Sleep until the reset (capped)
	// so later queries in the same scan don't all 403. On 429 / Retry-After
	// honor that header instead.
	if remaining := resp.Header.Get("X-RateLimit-Remaining"); remaining == "0" {
		if reset := resp.Header.Get("X-RateLimit-Reset"); reset != "" {
			if n, perr := strconv.ParseInt(reset, 10, 64); perr == nil {
				wait := time.Until(time.Unix(n, 0))
				if wait > 0 && wait <= 90*time.Second {
					select {
					case <-time.After(wait):
					case <-ctx.Done():
					}
				}
			}
		}
	}
	if resp.StatusCode == 429 || resp.StatusCode == 403 {
		if ra := resp.Header.Get("Retry-After"); ra != "" {
			if n, perr := strconv.Atoi(ra); perr == nil && n > 0 && n <= 60 {
				select {
				case <-time.After(time.Duration(n) * time.Second):
				case <-ctx.Done():
				}
			}
		}
	}
	if resp.StatusCode == 401 || resp.StatusCode == 403 {
		qr.Error = fmt.Sprintf("GitHub returned %d (rate-limited or auth required) — set a token in the form to raise the limit", resp.StatusCode)
		return qr
	}
	if resp.StatusCode == 422 {
		qr.Error = "GitHub Code Search requires authentication for unscoped queries. Provide a token."
		return qr
	}
	if resp.StatusCode != 200 {
		qr.Error = fmt.Sprintf("GitHub %d: %s", resp.StatusCode, truncate(string(body), 200))
		return qr
	}
	var parsed struct {
		TotalCount int `json:"total_count"`
		Items      []struct {
			Path       string `json:"path"`
			HTMLURL    string `json:"html_url"`
			Repository struct {
				FullName string `json:"full_name"`
				HTMLURL  string `json:"html_url"`
			} `json:"repository"`
		} `json:"items"`
	}
	if err := json.Unmarshal(body, &parsed); err != nil {
		qr.Error = "parse: " + err.Error()
		return qr
	}
	for i, it := range parsed.Items {
		if i >= cfg.MaxFiles {
			break
		}
		raw := strings.Replace(it.HTMLURL, "github.com", "raw.githubusercontent.com", 1)
		raw = strings.Replace(raw, "/blob/", "/", 1)
		qr.Hits = append(qr.Hits, Hit{
			Repo:    it.Repository.FullName,
			Path:    it.Path,
			HTMLURL: it.HTMLURL,
			RawURL:  raw,
		})
	}
	// Audit MEDIUM: HitCount now reflects the number of files actually
	// stored (and therefore renderable), not GitHub's unbounded
	// `total_count` for the whole query. The template's per-query
	// "{{.HitCount}} files" now matches the rows we draw. TotalAvailable
	// preserves the upstream count so callers / templates can render
	// "showing N of M results" if they want.
	qr.HitCount = len(qr.Hits)
	qr.TotalAvailable = parsed.TotalCount
	return qr
}

func fetchRaw(ctx context.Context, client *http.Client, url, token string) string {
	req, err := http.NewRequestWithContext(ctx, "GET", url, nil)
	if err != nil {
		// Audit MEDIUM: avoid nil-deref panic on malformed URL.
		return ""
	}
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	resp, err := client.Do(req)
	if err != nil {
		return ""
	}
	// Audit MEDIUM (perf): drain to allow keepalive conn reuse —
	// resp.Body.Close() does NOT drain unread bytes, so any file
	// larger than the 256 KB cap would otherwise force the transport
	// to close the underlying connection.
	defer func() { io.Copy(io.Discard, resp.Body); resp.Body.Close() }()
	if resp.StatusCode != 200 {
		return ""
	}
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 256*1024))
	return string(body)
}

func matchSecrets(body string) []Match {
	var out []Match
	for _, p := range secretPatterns {
		matches := p.RE.FindAllStringIndex(body, 5)
		for _, idx := range matches {
			start := idx[0] - 40
			if start < 0 {
				start = 0
			}
			end := idx[1] + 40
			if end > len(body) {
				end = len(body)
			}
			sample := strings.ReplaceAll(body[start:end], "\n", " ")
			out = append(out, Match{Pattern: p.Name, Sample: trimSnippet(sample, 200)})
		}
	}
	return out
}

func urlEncode(s string) string {
	// Audit fix: the previous hand-rolled replacer only handled 5 chars
	// (" ", "&", "#", "?", "+") and silently corrupted any GitHub search
	// query containing quotes, brackets, colons, equals, or slashes —
	// exactly the syntax pentesters reach for (`"API_KEY="`, `path:.env`,
	// `language:python`, etc.). url.QueryEscape applies RFC 3986
	// percent-encoding which GitHub's API handles natively.
	return url.QueryEscape(s)
}

func trimSnippet(s string, max int) string {
	if len(s) <= max {
		return s
	}
	return s[:max] + "..."
}

func truncate(s string, max int) string { return trimSnippet(s, max) }

// searchPastebin scrapes pastebin's public search results for a single
// query term. Pastebin's official scrape API requires a paid account;
// we use the public listing instead — bounded to ~50 most recent
// public pastes containing the query. Best-effort: rate-limit friendly,
// returns empty on any HTTP error.
func searchPastebin(ctx context.Context, client *http.Client, query string, maxResults int) []Hit {
	url := "https://psbdmp.ws/api/v3/search/" + queryEscape(query)
	req, err := http.NewRequestWithContext(ctx, "GET", url, nil)
	if err != nil {
		return nil
	}
	resp, err := client.Do(req)
	if err != nil || resp.StatusCode != 200 {
		if resp != nil {
			io.Copy(io.Discard, resp.Body)
			resp.Body.Close()
		}
		return nil
	}
	// Audit MEDIUM (perf): drain on exit so the connection is reusable.
	defer func() { io.Copy(io.Discard, resp.Body); resp.Body.Close() }()
	var payload struct {
		Data []struct {
			ID   string `json:"id"`
			Date string `json:"date"`
			Size int    `json:"size"`
		} `json:"data"`
	}
	// Audit MEDIUM (perf): cap upstream response at 2 MB — psbdmp.ws is a
	// third-party endpoint, a misbehaving/malicious response of hundreds
	// of MB would otherwise pin RAM and stall the JSON decoder.
	if err := json.NewDecoder(io.LimitReader(resp.Body, 2*1024*1024)).Decode(&payload); err != nil {
		return nil
	}
	hits := make([]Hit, 0, len(payload.Data))
	for i, p := range payload.Data {
		if i >= maxResults {
			break
		}
		hits = append(hits, Hit{
			Repo:    "pastebin.com",
			Path:    p.ID,
			HTMLURL: "https://pastebin.com/" + p.ID,
			RawURL:  "https://pastebin.com/raw/" + p.ID,
		})
	}
	return hits
}

// searchWayback queries the Wayback Machine CDX API for any historical
// URL containing the query string. Useful for finding endpoints that
// once leaked secrets in query strings or response bodies but have
// since been removed from the live site.
func searchWayback(ctx context.Context, client *http.Client, query string, maxResults int) []Hit {
	url := "http://web.archive.org/cdx/search/cdx?url=*" + queryEscape(query) + "*&output=json&limit=" + intStr(maxResults) + "&filter=statuscode:200"
	req, err := http.NewRequestWithContext(ctx, "GET", url, nil)
	if err != nil {
		return nil
	}
	resp, err := client.Do(req)
	if err != nil || resp.StatusCode != 200 {
		if resp != nil {
			io.Copy(io.Discard, resp.Body)
			resp.Body.Close()
		}
		return nil
	}
	// Audit MEDIUM (perf): drain on exit so the connection is reusable.
	defer func() { io.Copy(io.Discard, resp.Body); resp.Body.Close() }()
	// CDX returns JSON like: [["urlkey","timestamp","original","mimetype","statuscode","digest","length"], [...], ...]
	// Audit MEDIUM (perf): cap upstream response at 4 MB — web.archive.org
	// is a third-party endpoint and the CDX result set can be unboundedly
	// large for permissive URL patterns. limit is already requested but
	// not enforced server-side.
	var rows [][]string
	if err := json.NewDecoder(io.LimitReader(resp.Body, 4*1024*1024)).Decode(&rows); err != nil || len(rows) < 2 {
		return nil
	}
	hits := []Hit{}
	for _, row := range rows[1:] { // skip header
		if len(row) < 3 {
			continue
		}
		original := row[2]
		ts := row[1]
		hits = append(hits, Hit{
			Repo:    "web.archive.org",
			Path:    original,
			HTMLURL: "https://web.archive.org/web/" + ts + "/" + original,
			RawURL:  "https://web.archive.org/web/" + ts + "if_/" + original,
		})
	}
	return hits
}

func queryEscape(s string) string {
	r := strings.NewReplacer(" ", "%20", "&", "%26", "?", "%3F", "#", "%23")
	return r.Replace(s)
}

func intStr(n int) string { return fmt.Sprintf("%d", n) }
