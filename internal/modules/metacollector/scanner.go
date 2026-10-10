package metacollector

import (
	"context"
	"fmt"
	"net/url"
	"os"
	"strconv"
	"strings"
	"sync/atomic"
	"time"

	"scanner/internal/modules/shared"
)

// TotalUpdatePrefix is a sentinel prefix on a progress message: the handler
// reads the trailing integer as the new progress denominator (so the bar shows
// the real document count once search completes) and does NOT forward it as a
// visible line. Mirrors httpxfind.TotalUpdatePrefix.
const TotalUpdatePrefix = "__TOTAL__:"

// Config is the per-scan configuration (built by the handler from the launch
// form + Settings). Zero values are filled with the meta-collector defaults.
type Config struct {
	Domains     []string
	SerperKey   string
	Split       bool
	Filetypes   []string
	MaxPerHost  int
	MaxFileMB   int
	Concurrency int
	PerHost     int
	ScanBody    bool
	HTTPOpts    *shared.HTTPOptions
}

// Finding is one classified metadata value — the single source of truth from
// which every report/aggregation view is computed.
type Finding struct {
	Category string `json:"category"`
	Value    string `json:"value"`
	Tag      string `json:"tag"`
	DocURL   string `json:"doc_url"`
}

// Document is one discovered file and its download/extraction state.
type Document struct {
	URL        string `json:"url"`
	Filetype   string `json:"filetype"`
	FQDN       string `json:"fqdn"`
	Status     string `json:"status"` // found | downloaded | failed | skipped | extracted
	Title      string `json:"title,omitempty"`
	SHA256     string `json:"sha256,omitempty"`
	Size       int64  `json:"size,omitempty"`
	HTTPStatus int    `json:"http_status,omitempty"`
	Error      string `json:"error,omitempty"`
	LocalPath  string `json:"-"` // transient: the per-scan temp path, never persisted
}

// ScanResult is the persisted module output.
type ScanResult struct {
	Provider    string         `json:"provider"`
	Domains     []string       `json:"domains"`
	Documents   []Document     `json:"documents"`
	Findings    []Finding      `json:"findings"`
	StatusCount map[string]int `json:"status_count"`
	Warnings    []string       `json:"warnings,omitempty"`
	Stopped     string         `json:"stopped,omitempty"` // non-fatal search-stop reason (credits/auth/transient)
	StartedAt   string         `json:"started_at"`
}

type ProgressFunc func(done int, msg string)
type PartialFunc func(*ScanResult)

func applyDefaults(cfg *Config) {
	if len(cfg.Filetypes) == 0 {
		cfg.Filetypes = DefaultFiletypes
	}
	if cfg.MaxPerHost <= 0 {
		cfg.MaxPerHost = 300
	}
	if cfg.MaxFileMB <= 0 {
		cfg.MaxFileMB = 50
	}
	if cfg.Concurrency <= 0 {
		cfg.Concurrency = 10
	}
	if cfg.PerHost <= 0 {
		cfg.PerHost = 2
	}
}

// Scan runs the full pipeline: search → download → extract → classify. It never
// returns nil, surfaces missing tools / search stops as warnings, and always
// pushes at least one partial before returning.
func Scan(ctx context.Context, cfg Config, progress ProgressFunc, partial PartialFunc) *ScanResult {
	applyDefaults(&cfg)
	startedAt := time.Now().UTC().Format(time.RFC3339)
	res := &ScanResult{Provider: "serper", Domains: cfg.Domains, StatusCount: map[string]int{}, StartedAt: startedAt}

	if progress == nil {
		progress = func(int, string) {}
	}
	if partial == nil {
		partial = func(*ScanResult) {}
	}

	var docs []*Document
	var findings []Finding
	var warnings []string
	stopped := ""

	// Panic-safety: a malformed document must not crash the scan; return partial.
	defer func() {
		if rec := recover(); rec != nil {
			warnings = append(warnings, fmt.Sprintf("internal error: %v", rec))
			res.Warnings = warnings
			res.Stopped = stopped
			partial(res)
		}
	}()

	tl := resolveTools()
	if tl.exiftool == "" {
		warnings = append(warnings, "exiftool not found on PATH — metadata extraction is unavailable; install libimage-exiftool-perl.")
	}
	if cfg.ScanBody && tl.pdftotext == "" {
		warnings = append(warnings, "pdftotext not found — PDF body-text harvesting (emails/UNC paths) skipped; install poppler-utils.")
	}
	if cfg.ScanBody && tl.soffice == "" {
		warnings = append(warnings, "soffice (LibreOffice) not found — legacy .doc/.xls/.ppt body-text harvesting skipped (metadata still extracted).")
	}

	tmp, err := os.MkdirTemp("", "metacollector-")
	if err != nil {
		warnings = append(warnings, "cannot create temp working dir: "+err.Error())
		res.Warnings = warnings
		partial(res)
		return res
	}
	defer os.RemoveAll(tmp)

	// ---- 1) SEARCH ----
	client := newSerperClient(cfg)
	seen := map[string]bool{}
	for i, domain := range cfg.Domains {
		if ctx.Err() != nil {
			break
		}
		domain = strings.TrimSpace(domain)
		if domain == "" {
			continue
		}
		found, stop := searchHost(ctx, client, cfg, domain, progress, func(sr searchResult, ft string) {
			if seen[sr.URL] {
				return
			}
			seen[sr.URL] = true
			docs = append(docs, &Document{
				URL:      sr.URL,
				Filetype: ft,
				FQDN:     fqdnOf(sr.URL),
				Status:   "found",
				Title:    sr.Title,
			})
		})
		progress(i+1, fmt.Sprintf("%s: %d documents found", domain, found))
		if stop != nil {
			stopped = stop.Error()
			warnings = append(warnings, "search stopped: "+stopped)
			break // mirror pipeline.do_search: stop searching, proceed with what we have
		}
	}
	res.Documents = derefDocs(docs)
	res.Warnings = warnings
	res.Stopped = stopped
	recount(res, docs)
	partial(res)

	n := len(docs)
	if n == 0 || ctx.Err() != nil {
		res.Findings = findings
		recount(res, docs)
		partial(res)
		return res
	}

	// Switch the progress denominator to the real work: download (n) + extract (n).
	progress(0, TotalUpdatePrefix+strconv.Itoa(2*n))

	// ---- 2) DOWNLOAD ----
	var dlDone int64
	downloadAll(ctx, cfg, docs, tmp, func() {
		d := atomic.AddInt64(&dlDone, 1)
		progress(int(d), fmt.Sprintf("$ download — %d/%d documents", d, n))
	})
	res.Documents = derefDocs(docs)
	recount(res, docs)
	partial(res)

	// ---- 3) EXTRACT + CLASSIFY ----
	var exDone int64
	findings = extractAll(ctx, cfg, docs, tmp, tl, func() {
		e := atomic.AddInt64(&exDone, 1)
		progress(n+int(e), fmt.Sprintf("$ exiftool — extracting %d/%d", e, n))
	})

	res.Documents = derefDocs(docs)
	res.Findings = findings
	res.Warnings = warnings
	res.Stopped = stopped
	recount(res, docs)
	progress(2*n, "metadata extraction complete")
	partial(res)
	return res
}

// searchHost runs the dorks for one domain, calling emit for every unique
// result. Returns the count found and a non-nil stop error if the search
// terminated early (credits/auth/transient) — caller treats it as non-fatal.
func searchHost(ctx context.Context, client *serperClient, cfg Config, domain string,
	progress ProgressFunc, emit func(searchResult, string)) (int, error) {
	found := 0
	add := func(results []searchResult, ft string) {
		for _, r := range results {
			ftype := ft
			if ftype == "" {
				ftype = urlExt(r.URL)
			}
			emit(r, ftype)
			found++
		}
	}

	if cfg.Split {
		// Preflight: skip a host that returns nothing for a bare site: probe.
		progress(0, "$ serper site:"+domain)
		probe, err := client.searchPage(ctx, "site:"+domain, 1)
		if err != nil {
			return found, err
		}
		if len(probe) == 0 {
			return found, nil
		}
		for _, q := range perFiletypeQueries(domain, cfg.Filetypes) {
			if ctx.Err() != nil {
				return found, nil
			}
			progress(0, "$ serper "+q.Query)
			results, err := client.paginate(ctx, q.Query, cfg.MaxPerHost)
			add(results, q.Filetype)
			if err != nil {
				return found, err
			}
		}
		return found, nil
	}

	query := combinedQuery(domain, cfg.Filetypes)
	progress(0, "$ serper "+query)
	results, err := client.paginate(ctx, query, cfg.MaxPerHost)
	add(results, "")
	return found, err
}

// urlExt returns the lowercased extension of a URL's last path segment, or ""
// (mirrors pipeline._url_ext for combined-mode filetype inference).
func urlExt(rawURL string) string {
	u, err := url.Parse(rawURL)
	if err != nil {
		return ""
	}
	p := u.Path
	last := p
	if i := strings.LastIndex(p, "/"); i >= 0 {
		last = p[i+1:]
	}
	if i := strings.LastIndex(last, "."); i >= 0 {
		return strings.ToLower(last[i+1:])
	}
	return ""
}

func derefDocs(docs []*Document) []Document {
	out := make([]Document, 0, len(docs))
	for _, d := range docs {
		out = append(out, *d)
	}
	return out
}

func recount(res *ScanResult, docs []*Document) {
	sc := map[string]int{}
	for _, d := range docs {
		sc[d.Status]++
	}
	res.StatusCount = sc
}
