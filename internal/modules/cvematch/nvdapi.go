package cvematch

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"time"

	"scanner/internal/modules/shared"
)

// The REST API (as opposed to the static gz feeds) is what lets the "quick"
// refresh pull EXACTLY the CVEs modified since our newest record — closing any
// gap since the last refresh, however long — instead of a fixed 8-day window.
const (
	nvdAPIBase     = "https://services.nvd.nist.gov/rest/json/cves/2.0"
	nvdAPIPageSize = 2000                 // NVD max resultsPerPage
	nvdAPIWindow   = 120 * 24 * time.Hour // NVD max lastMod date range per request
	nvdAPIReqDelay = 6 * time.Second      // ~5 req / 30s ceiling without an API key
	nvdAPIMaxPages = 500                  // runaway guard (500 × 2000 = 1M CVEs)
)

func nvdAPIClient() *http.Client {
	return &http.Client{
		Timeout: 60 * time.Second,
		Transport: &http.Transport{
			MaxIdleConns:        4,
			MaxIdleConnsPerHost: 2,
			IdleConnTimeout:     60 * time.Second,
			// Pin to the killswitch outbound iface like the feed downloader.
			DialContext: shared.BoundDialer(nil, 15*time.Second).DialContext,
		},
	}
}

// nvdAPITime renders a time in the extended ISO-8601 form NVD requires.
func nvdAPITime(t time.Time) string {
	return t.UTC().Format("2006-01-02T15:04:05.000")
}

// FetchModifiedSince pulls every CVE modified in (since, now] from the NVD REST
// API — chunked into ≤120-day windows, paginated, and rate-limited to stay under
// the keyless 5-requests/30s ceiling. Returns the same (rows, unanalyzed) the gz
// feed parser produces. A zero/future `since` falls back to the last 8 days.
func FetchModifiedSince(ctx context.Context, since time.Time, progress FeedProgress) ([]CVERow, []UnanalyzedCVE, error) {
	now := time.Now().UTC()
	if since.IsZero() || !since.Before(now) {
		since = now.Add(-8 * 24 * time.Hour)
	}
	client := nvdAPIClient()
	var allRows []CVERow
	var allUnan []UnanalyzedCVE
	reqCount := 0
	fetched := 0

	for winStart := since; winStart.Before(now); {
		winEnd := winStart.Add(nvdAPIWindow)
		if winEnd.After(now) {
			winEnd = now
		}
		for startIndex, pages := 0, 0; pages < nvdAPIMaxPages; pages++ {
			if err := ctx.Err(); err != nil {
				return allRows, allUnan, err
			}
			// Rate-limit between requests (skip before the very first).
			if reqCount > 0 {
				select {
				case <-time.After(nvdAPIReqDelay):
				case <-ctx.Done():
					return allRows, allUnan, ctx.Err()
				}
			}
			feed, err := fetchNVDPage(ctx, client, winStart, winEnd, startIndex)
			reqCount++
			if err != nil {
				return nil, nil, err
			}
			rows, unan := parseNVDFeed(feed)
			allRows = append(allRows, rows...)
			allUnan = append(allUnan, unan...)
			fetched += len(feed.Vulnerabilities)
			if progress != nil {
				progress("download", int64(fetched), int64(fetched)) // running count; total unknown across windows
			}
			startIndex += nvdAPIPageSize
			if len(feed.Vulnerabilities) == 0 || startIndex >= feed.TotalResults {
				break
			}
		}
		winStart = winEnd
	}
	return allRows, allUnan, nil
}

// fetchNVDPage retrieves one page of the REST API for a lastMod window, retrying
// transient failures (network blips, 403/429 rate-limit, 5xx) with backoff.
func fetchNVDPage(ctx context.Context, client *http.Client, start, end time.Time, startIndex int) (*NVDFeed, error) {
	q := url.Values{}
	q.Set("lastModStartDate", nvdAPITime(start))
	q.Set("lastModEndDate", nvdAPITime(end))
	q.Set("resultsPerPage", fmt.Sprintf("%d", nvdAPIPageSize))
	q.Set("startIndex", fmt.Sprintf("%d", startIndex))
	reqURL := nvdAPIBase + "?" + q.Encode()

	var lastErr error
	for attempt := 1; attempt <= 4; attempt++ {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		if attempt > 1 {
			// NVD rate-limit / transient backoff — longer than the steady cadence.
			select {
			case <-time.After(time.Duration(attempt) * 10 * time.Second):
			case <-ctx.Done():
				return nil, ctx.Err()
			}
		}
		req, err := http.NewRequestWithContext(ctx, "GET", reqURL, nil)
		if err != nil {
			return nil, fmt.Errorf("build request: %w", err)
		}
		req.Header.Set("User-Agent", "scaNNer-CVE-Matcher/1.0 (+pentest tool)")
		resp, err := client.Do(req)
		if err != nil {
			lastErr = err
			continue
		}
		if resp.StatusCode == http.StatusForbidden || resp.StatusCode == http.StatusTooManyRequests || resp.StatusCode >= 500 {
			resp.Body.Close()
			lastErr = fmt.Errorf("NVD API HTTP %d", resp.StatusCode)
			continue
		}
		if resp.StatusCode != 200 {
			resp.Body.Close()
			return nil, fmt.Errorf("NVD API HTTP %d", resp.StatusCode)
		}
		var feed NVDFeed
		err = json.NewDecoder(io.LimitReader(resp.Body, 256*1024*1024)).Decode(&feed)
		resp.Body.Close()
		if err != nil {
			lastErr = fmt.Errorf("decode: %w", err)
			continue
		}
		return &feed, nil
	}
	return nil, fmt.Errorf("NVD API page failed after retries: %w", lastErr)
}
