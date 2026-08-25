package cvematch

import (
	"compress/gzip"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"sync"
	"time"

	"scanner/internal/modules/shared"
)

// NVD JSON 2.0 feed endpoints. Annual dumps live under feeds/; the
// "modified" feed contains every CVE record changed in the last 8 days.
// "recent" is the same content set published in the last 8 days. We use
// "modified" for incremental refresh (it includes both new + updated).
//
// Feed file structure (gzipped): one JSON document with a top-level
// `vulnerabilities` array; each element is `{ "cve": { ... } }`.
const (
	feedBaseURL     = "https://nvd.nist.gov/feeds/json/cve/2.0"
	feedFileFormat  = feedBaseURL + "/nvdcve-2.0-%s.json.gz" // %s = year or "modified"
	feedTimeoutEach = 5 * time.Minute
)

// FeedProgress fires periodically during download + parse with the
// current sub-phase ("download" or "parse") and progress counters.
type FeedProgress func(stage string, current, total int64)

// NVDFeed is the minimal shape we parse out of the NVD JSON. The full
// schema has hundreds of fields; we only need what feeds the CVE Matcher
// (id, descriptions, CVSS, affected CPE ranges, references, dates).
type NVDFeed struct {
	// Pagination fields — present on the REST API response, absent (zero) on the
	// gz feed files. Let the same struct decode both.
	TotalResults    int `json:"totalResults"`
	ResultsPerPage  int `json:"resultsPerPage"`
	StartIndex      int `json:"startIndex"`
	Vulnerabilities []struct {
		CVE struct {
			ID           string `json:"id"`
			Published    string `json:"published"`
			LastModified string `json:"lastModified"`
			Descriptions []struct {
				Lang  string `json:"lang"`
				Value string `json:"value"`
			} `json:"descriptions"`
			Metrics struct {
				CVSSMetricV31 []struct {
					CVSSData struct {
						BaseScore    float64 `json:"baseScore"`
						BaseSeverity string  `json:"baseSeverity"`
					} `json:"cvssData"`
				} `json:"cvssMetricV31"`
				CVSSMetricV30 []struct {
					CVSSData struct {
						BaseScore    float64 `json:"baseScore"`
						BaseSeverity string  `json:"baseSeverity"`
					} `json:"cvssData"`
				} `json:"cvssMetricV30"`
				CVSSMetricV2 []struct {
					CVSSData struct {
						BaseScore float64 `json:"baseScore"`
					} `json:"cvssData"`
					BaseSeverity string `json:"baseSeverity"`
				} `json:"cvssMetricV2"`
			} `json:"metrics"`
			Configurations []struct {
				Nodes []struct {
					Operator string `json:"operator"`
					CPEMatch []struct {
						Criteria              string `json:"criteria"`
						Vulnerable            bool   `json:"vulnerable"`
						VersionStartIncluding string `json:"versionStartIncluding"`
						VersionStartExcluding string `json:"versionStartExcluding"`
						VersionEndIncluding   string `json:"versionEndIncluding"`
						VersionEndExcluding   string `json:"versionEndExcluding"`
					} `json:"cpeMatch"`
				} `json:"nodes"`
			} `json:"configurations"`
			References []struct {
				URL string `json:"url"`
			} `json:"references"`
		} `json:"cve"`
	} `json:"vulnerabilities"`
}

// CVERow is one (product, version-range) tuple ready for DB insertion.
// One NVD CVE typically expands into multiple CVERows (one per affected
// CPE match).
type CVERow struct {
	CVEID       string
	ProductKey  string // "vendor:product" e.g. "apache:http_server"
	ProductName string // user-friendly: "Apache HTTP Server"
	VersionLo   string
	VersionHi   string
	LoInc       bool
	HiInc       bool
	Severity    string
	CVSS        float64
	Description string
	Reference   string
	PublishedAt time.Time
	ModifiedAt  time.Time
}

// UnanalyzedCVE is a CVE the NVD feed carried with NO configurations block —
// i.e. NVD has received but not yet analyzed it, so it has no CPE ranges and
// produces zero cve_records rows. These are the newest CVEs (the exact ones a
// pentester wants); the refresh enriches them from the CVE.org/MITRE CNA record,
// which already carries structured affected product+version data at publication.
type UnanalyzedCVE struct {
	CVEID       string
	Description string
	Severity    string
	CVSS        float64
	Reference   string
	PublishedAt time.Time
	ModifiedAt  time.Time
}

// DownloadFeed is a convenience wrapper for callers that don't need
// byte-level progress reporting.
func DownloadFeed(ctx context.Context, year string) ([]CVERow, error) {
	rows, _, err := DownloadFeedWithProgress(ctx, year, nil)
	return rows, err
}

// DownloadFeedWithProgress fetches one NVD feed (year or "modified")
// and parses it into CVERows. The progress callback fires periodically
// with (stage="download", bytes_done, bytes_total) and once after
// parsing with stage="parse".
//
// NVD's annual dumps are ~10-50 MB compressed (50-200 MB uncompressed).
// The "modified" feed is ~1-5 MB.
func DownloadFeedWithProgress(ctx context.Context, year string, progress FeedProgress) ([]CVERow, []UnanalyzedCVE, error) {
	url := fmt.Sprintf(feedFileFormat, year)
	req, err := http.NewRequestWithContext(ctx, "GET", url, nil)
	if err != nil {
		return nil, nil, fmt.Errorf("build request: %w", err)
	}
	req.Header.Set("User-Agent", "scaNNer-CVE-Matcher/1.0 (+pentest tool)")

	// Audit B53: NVD is a critical security data source. Keep TLS
	// verification ON (Go's default — no InsecureSkipVerify) and use a
	// bounded transport so multi-feed syncs don't pile up idle conns
	// against nvd.nist.gov. The CA chain is the standard system roots;
	// we don't pin a specific public-key fingerprint because NIST
	// rotates intermediate certs without notice (full pinning here
	// would require monthly maintenance and break trust on every
	// rotation).
	client := &http.Client{
		Timeout: feedTimeoutEach,
		Transport: &http.Transport{
			MaxIdleConns:        4,
			MaxIdleConnsPerHost: 2,
			IdleConnTimeout:     60 * time.Second,
			// TLSClientConfig left nil → Go uses system roots with
			// hostname verification ON. Explicitly defensive: any
			// future maintainer who adds InsecureSkipVerify here
			// should re-read this comment.
			// Audit S1/K06: pin dialer to killswitch outbound iface so
			// NVD-feed downloads honor the chosen interface. BoundDialer
			// with nil reads global LocalAddr set by Settings save.
			DialContext: shared.BoundDialer(nil, 15*time.Second).DialContext,
		},
	}
	resp, err := client.Do(req)
	if err != nil {
		return nil, nil, fmt.Errorf("fetch %s: %w", url, err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		return nil, nil, fmt.Errorf("NVD feed %s returned HTTP %d", year, resp.StatusCode)
	}

	// Wrap the response in a counting reader so we can stream byte
	// progress to the UI while gzip+json are pulling data through.
	totalBytes := resp.ContentLength
	cr := &countingReader{r: resp.Body}
	stopProgressCh := make(chan struct{})
	// Audit B36: wrap close() in sync.Once so any defensive future
	// refactor that adds an extra close path can't panic with
	// "close of closed channel". Today the function has three close
	// sites — one per code path — but a future maintainer adding
	// error handling in the wrong place is a real risk.
	var stopOnce sync.Once
	stopProgress := func() {
		stopOnce.Do(func() { close(stopProgressCh) })
	}
	if progress != nil {
		progress("download", 0, totalBytes)
		go func() {
			t := time.NewTicker(750 * time.Millisecond)
			defer t.Stop()
			for {
				select {
				case <-stopProgressCh:
					return
				case <-ctx.Done():
					return
				case <-t.C:
					progress("download", cr.count, totalBytes)
				}
			}
		}()
	}

	// Audit fix: bound both the compressed and decompressed streams so a
	// hostile/corrupt feed can't OOM us via a gzip bomb or an
	// unexpectedly huge JSON body. NVD annual feeds are ~50 MB compressed
	// and ~200 MB uncompressed as of 2026; the caps are generous multi-
	// year headroom while still refusing a "feed is 20 GB" attack.
	const (
		maxCompressedBytes   = 512 * 1024 * 1024        // 512 MiB compressed
		maxDecompressedBytes = 2 * 1024 * 1024 * 1024   // 2 GiB decompressed
		maxVulnerabilities   = 5_000_000                // hard cap on record count
	)
	limitedCompressed := io.LimitReader(cr, maxCompressedBytes+1)

	// Streaming gzip → JSON decode. Avoids loading the full ~200 MB
	// uncompressed feed into memory.
	gz, err := gzip.NewReader(limitedCompressed)
	if err != nil {
		stopProgress()
		return nil, nil, fmt.Errorf("gunzip: %w", err)
	}
	defer gz.Close()

	limitedGz := io.LimitReader(gz, maxDecompressedBytes+1)
	var feed NVDFeed
	if err := json.NewDecoder(limitedGz).Decode(&feed); err != nil {
		stopProgress()
		return nil, nil, fmt.Errorf("decode JSON: %w", err)
	}
	// Explicit trip-check: if the JSON decoder exactly consumed the cap
	// without hitting EOF, the feed is over the size limit — refuse it
	// rather than proceeding with a truncated document.
	if cr.count > maxCompressedBytes {
		stopProgress()
		return nil, nil, fmt.Errorf("NVD feed %s exceeds %d MiB compressed cap — refusing to parse", year, maxCompressedBytes/(1024*1024))
	}
	if len(feed.Vulnerabilities) > maxVulnerabilities {
		stopProgress()
		return nil, nil, fmt.Errorf("NVD feed %s contains %d records — exceeds %d cap", year, len(feed.Vulnerabilities), maxVulnerabilities)
	}
	stopProgress()
	if progress != nil {
		progress("parse", int64(len(feed.Vulnerabilities)), int64(len(feed.Vulnerabilities)))
	}

	out, unanalyzed := parseNVDFeed(&feed)
	return out, unanalyzed, nil
}

// parseNVDFeed converts an NVD 2.0 payload — from an annual/"modified" gz feed OR
// the REST API (both use the same `vulnerabilities` shape) — into version-bounded
// CVERows plus the unanalyzed (CPE-less) CVEs queued for CNA enrichment.
func parseNVDFeed(feed *NVDFeed) ([]CVERow, []UnanalyzedCVE) {
	out := make([]CVERow, 0, len(feed.Vulnerabilities)*3) // each CVE → ~3 CPE rows avg
	var unanalyzed []UnanalyzedCVE
	for _, v := range feed.Vulnerabilities {
		c := v.CVE
		desc := pickEnglishDescription(c.Descriptions)
		sev, cvss := pickSeverity(c.Metrics)
		pub, _ := time.Parse(time.RFC3339, strings.TrimSuffix(c.Published, "Z")+"Z")
		mod, _ := time.Parse(time.RFC3339, strings.TrimSuffix(c.LastModified, "Z")+"Z")
		ref := ""
		if len(c.References) > 0 {
			ref = c.References[0].URL
		}

		// No configurations at all → NVD hasn't analyzed this CVE yet (status
		// "Received"/"Awaiting Analysis"). It yields no CPE rows, so record it for
		// CNA enrichment from CVE.org rather than silently dropping the newest CVEs.
		if len(c.Configurations) == 0 {
			unanalyzed = append(unanalyzed, UnanalyzedCVE{
				CVEID: c.ID, Description: desc, Severity: sev, CVSS: cvss,
				Reference: ref, PublishedAt: pub, ModifiedAt: mod,
			})
		}

		// Expand each CPE-match entry into one row. Skip rows where
		// vulnerable=false (those are "fixed in" markers).
		for _, conf := range c.Configurations {
			for _, node := range conf.Nodes {
				for _, m := range node.CPEMatch {
					if !m.Vulnerable {
						continue
					}
					pk, pn := parseCPE(m.Criteria)
					if pk == "" {
						continue
					}
					lo, hi, loInc, hiInc, exactVer := normalizeRange(m)
					// If neither start nor end is set, the cpe24 might
					// have an exact version baked in (cpe:2.3:a:vendor:
					// product:VERSION). Use that.
					if lo == "" && hi == "" && exactVer != "" && exactVer != "*" && exactVer != "-" {
						lo, hi = exactVer, exactVer
						loInc, hiInc = true, true
					}
					out = append(out, CVERow{
						CVEID:       c.ID,
						ProductKey:  pk,
						ProductName: pn,
						VersionLo:   lo,
						VersionHi:   hi,
						LoInc:       loInc,
						HiInc:       hiInc,
						Severity:    sev,
						CVSS:        cvss,
						Description: desc,
						Reference:   ref,
						PublishedAt: pub,
						ModifiedAt:  mod,
					})
				}
			}
		}
	}
	return out, unanalyzed
}

// parseCPE extracts (vendor:product, productName) from a CPE 2.3 string.
// Example input: cpe:2.3:a:apache:http_server:2.4.49:*:*:*:*:*:*:*
// Returns ("apache:http_server", "Apache HTTP Server").
// Returns ("", "") for non-application CPEs (we skip OS / hardware).
func parseCPE(s string) (key string, name string) {
	parts := strings.Split(s, ":")
	if len(parts) < 5 {
		return "", ""
	}
	if parts[0] != "cpe" || parts[1] != "2.3" {
		return "", ""
	}
	// part[2] = type: a=application, o=os, h=hardware. We want apps.
	if parts[2] != "a" {
		return "", ""
	}
	vendor := strings.ToLower(parts[3])
	product := strings.ToLower(parts[4])
	if vendor == "" || vendor == "*" || product == "" || product == "*" {
		return "", ""
	}
	key = vendor + ":" + product
	// Title-case for display. _ → space.
	name = titleCaseProduct(vendor) + " " + titleCaseProduct(product)
	return key, name
}

// normalizeRange picks the lo/hi version bounds and whether each is
// inclusive. Returns ("", "", true, true, exactVer) if no range is
// specified — caller may fall back to the exact-version slot.
func normalizeRange(m struct {
	Criteria              string `json:"criteria"`
	Vulnerable            bool   `json:"vulnerable"`
	VersionStartIncluding string `json:"versionStartIncluding"`
	VersionStartExcluding string `json:"versionStartExcluding"`
	VersionEndIncluding   string `json:"versionEndIncluding"`
	VersionEndExcluding   string `json:"versionEndExcluding"`
}) (lo, hi string, loInc, hiInc bool, exactVer string) {
	if m.VersionStartIncluding != "" {
		lo = m.VersionStartIncluding
		loInc = true
	} else if m.VersionStartExcluding != "" {
		lo = m.VersionStartExcluding
		loInc = false
	}
	if m.VersionEndIncluding != "" {
		hi = m.VersionEndIncluding
		hiInc = true
	} else if m.VersionEndExcluding != "" {
		hi = m.VersionEndExcluding
		hiInc = false
	}
	parts := strings.Split(m.Criteria, ":")
	if len(parts) >= 6 {
		exactVer = parts[5]
	}
	return
}

// pickEnglishDescription returns the en-language description or the
// first one if no English is present.
func pickEnglishDescription(d []struct {
	Lang  string `json:"lang"`
	Value string `json:"value"`
}) string {
	for _, x := range d {
		if x.Lang == "en" {
			return x.Value
		}
	}
	if len(d) > 0 {
		return d[0].Value
	}
	return ""
}

// pickSeverity returns (severity-label, base-score). Prefers CVSS 3.1
// > 3.0 > 2.0.
func pickSeverity(m struct {
	CVSSMetricV31 []struct {
		CVSSData struct {
			BaseScore    float64 `json:"baseScore"`
			BaseSeverity string  `json:"baseSeverity"`
		} `json:"cvssData"`
	} `json:"cvssMetricV31"`
	CVSSMetricV30 []struct {
		CVSSData struct {
			BaseScore    float64 `json:"baseScore"`
			BaseSeverity string  `json:"baseSeverity"`
		} `json:"cvssData"`
	} `json:"cvssMetricV30"`
	CVSSMetricV2 []struct {
		CVSSData struct {
			BaseScore float64 `json:"baseScore"`
		} `json:"cvssData"`
		BaseSeverity string `json:"baseSeverity"`
	} `json:"cvssMetricV2"`
}) (string, float64) {
	if len(m.CVSSMetricV31) > 0 {
		return strings.ToUpper(m.CVSSMetricV31[0].CVSSData.BaseSeverity), m.CVSSMetricV31[0].CVSSData.BaseScore
	}
	if len(m.CVSSMetricV30) > 0 {
		return strings.ToUpper(m.CVSSMetricV30[0].CVSSData.BaseSeverity), m.CVSSMetricV30[0].CVSSData.BaseScore
	}
	if len(m.CVSSMetricV2) > 0 {
		return strings.ToUpper(m.CVSSMetricV2[0].BaseSeverity), m.CVSSMetricV2[0].CVSSData.BaseScore
	}
	return "UNKNOWN", 0
}

func titleCaseProduct(s string) string {
	// "apache" → "Apache", "http_server" → "HTTP Server", "openssh" → "Openssh"
	s = strings.ReplaceAll(s, "_", " ")
	if s == "" {
		return s
	}
	parts := strings.Split(s, " ")
	for i, p := range parts {
		if p == "" {
			continue
		}
		// Common acronym fast-path.
		switch strings.ToLower(p) {
		case "http", "https", "ssh", "ftp", "iis", "sql", "tls", "ssl", "dns", "smb", "smtp", "pop", "imap":
			parts[i] = strings.ToUpper(p)
		default:
			parts[i] = strings.ToUpper(p[:1]) + p[1:]
		}
	}
	return strings.Join(parts, " ")
}

// CleanReader closes any leftover state. No-op currently — kept so the
// downloader can be wrapped in a context-aware cleanup later.
var _ io.Reader = (*strings.Reader)(nil)

// countingReader wraps an io.Reader and tracks total bytes read, used
// for streaming download progress reporting.
type countingReader struct {
	r     io.Reader
	count int64
}

func (c *countingReader) Read(p []byte) (int, error) {
	n, err := c.r.Read(p)
	c.count += int64(n)
	return n, err
}
