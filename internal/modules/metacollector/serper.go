package metacollector

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"

	"scanner/internal/modules/shared"
)

const serperEndpoint = "https://google.serper.dev/search"

// searchResult is one organic hit from Serper.
type searchResult struct {
	URL      string
	Title    string
	Snippet  string
	Position int
}

// stopKind classifies a terminal search condition (mirrors meta-collector's
// SearchAPIError.kind). A stop is NON-FATAL: the scan proceeds to download +
// extract whatever was already found, and the reason is surfaced as a warning.
type stopKind string

const (
	stopCredits    stopKind = "credits"
	stopAuth       stopKind = "auth"
	stopBadRequest stopKind = "badrequest"
	stopTransient  stopKind = "transient"
)

// serperStop is a terminal (non-retryable, or retries-exhausted) search error.
type serperStop struct {
	Kind    stopKind
	Status  int
	Message string
}

func (e *serperStop) Error() string { return e.Message }

// serperClient talks to google.serper.dev through the killswitch-bound transport.
type serperClient struct {
	key    string
	client *http.Client
	gl     string
	hl     string
}

func newSerperClient(cfg Config) *serperClient {
	// A dedicated client: 30s total timeout (meta-collector's default), no
	// redirect-follow needed for an API POST, killswitch-bound dialer + proxy.
	tr := &http.Transport{
		TLSClientConfig:       &tls.Config{InsecureSkipVerify: true},
		DialContext:           shared.BoundDialer(cfg.HTTPOpts, 15*time.Second).DialContext,
		MaxIdleConns:          10,
		MaxIdleConnsPerHost:   4,
		IdleConnTimeout:       30 * time.Second,
		ResponseHeaderTimeout: 30 * time.Second,
	}
	if cfg.HTTPOpts != nil {
		cfg.HTTPOpts.ApplyTransport(tr) // proxy + register for idle-pool flush on cancel
	}
	return &serperClient{
		key:    cfg.SerperKey,
		gl:     "us",
		hl:     "en",
		client: &http.Client{Transport: tr, Timeout: 30 * time.Second},
	}
}

// searchPage fetches one page, with up to 5 attempts of exponential backoff
// (1,2,4,8,16s capped at 30s) on transient errors (network / timeout / 429 /
// 5xx). A permanent 4xx (not 429) returns a *serperStop immediately (no retry).
func (c *serperClient) searchPage(ctx context.Context, query string, page int) ([]searchResult, error) {
	const maxAttempts = 5
	var lastErr error
	for attempt := 0; attempt < maxAttempts; attempt++ {
		if attempt > 0 {
			// exponential backoff: 1,2,4,8,16 capped at 30s, ctx-aware.
			d := time.Duration(1<<uint(attempt-1)) * time.Second
			if d > 30*time.Second {
				d = 30 * time.Second
			}
			select {
			case <-ctx.Done():
				return nil, &serperStop{Kind: stopTransient, Message: "search cancelled"}
			case <-time.After(d):
			}
		}
		results, retryable, err := c.doSearch(ctx, query, page)
		if err == nil {
			return results, nil
		}
		lastErr = err
		if stop, ok := err.(*serperStop); ok && !retryable {
			return nil, stop // permanent: credits / auth / badrequest
		}
		if ctx.Err() != nil {
			return nil, &serperStop{Kind: stopTransient, Message: "search cancelled"}
		}
		// retryable transient (network / timeout / 429 / 5xx) → loop
	}
	// retries exhausted
	msg := "Serper unreachable / transient error (retries exhausted)"
	if lastErr != nil {
		msg = fmt.Sprintf("%s: %v", msg, lastErr)
	}
	return nil, &serperStop{Kind: stopTransient, Message: msg}
}

// doSearch performs a single HTTP request. Returns (results, retryable, err).
func (c *serperClient) doSearch(ctx context.Context, query string, page int) ([]searchResult, bool, error) {
	body, _ := json.Marshal(map[string]interface{}{
		"q": query, "gl": c.gl, "hl": c.hl, "num": 10, "page": page, "autocorrect": false,
	})
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, serperEndpoint, bytes.NewReader(body))
	if err != nil {
		return nil, false, &serperStop{Kind: stopBadRequest, Message: err.Error()}
	}
	req.Header.Set("X-API-KEY", c.key)
	req.Header.Set("Content-Type", "application/json")
	resp, err := c.client.Do(req)
	if err != nil {
		return nil, true, err // network/timeout → retryable
	}
	defer resp.Body.Close()
	raw, _ := io.ReadAll(io.LimitReader(resp.Body, 4<<20))

	if resp.StatusCode >= 400 {
		return nil, retryableStatus(resp.StatusCode), classifyHTTPError(resp.StatusCode, raw)
	}

	var parsed struct {
		Organic []struct {
			Link     string `json:"link"`
			Title    string `json:"title"`
			Snippet  string `json:"snippet"`
			Position int    `json:"position"`
		} `json:"organic"`
	}
	if err := json.Unmarshal(raw, &parsed); err != nil {
		return nil, true, err // malformed body → treat as transient
	}
	out := make([]searchResult, 0, len(parsed.Organic))
	for _, o := range parsed.Organic {
		if o.Link == "" {
			continue
		}
		out = append(out, searchResult{URL: o.Link, Title: o.Title, Snippet: o.Snippet, Position: o.Position})
	}
	return out, false, nil
}

// retryableStatus reports whether an HTTP status should be retried: 429 and 5xx
// are transient; every other 4xx is permanent.
func retryableStatus(status int) bool {
	return status == http.StatusTooManyRequests || status >= 500
}

// classifyHTTPError maps a >=400 response to a *serperStop (for permanent 4xx)
// mirroring meta-collector's _raise_for_error. For 429/5xx it returns a generic
// error so the retry loop fires; retryableStatus decides retryability.
func classifyHTTPError(status int, body []byte) error {
	msg := ""
	var j struct {
		Message string `json:"message"`
	}
	if json.Unmarshal(body, &j) == nil {
		msg = j.Message
	}
	if msg == "" {
		msg = strings.TrimSpace(string(body))
		if len(msg) > 200 {
			msg = msg[:200]
		}
	}
	low := strings.ToLower(msg)
	if retryableStatus(status) {
		return fmt.Errorf("HTTP %d: %s", status, msg)
	}
	switch {
	case strings.Contains(low, "credit") || strings.Contains(low, "quota"):
		return &serperStop{Kind: stopCredits, Status: status,
			Message: fmt.Sprintf("Serper API credits exhausted (HTTP %d: %s). Add credits or a new key in Settings.", status, firstNonEmptyStr(msg, "Not enough credits"))}
	case status == http.StatusUnauthorized || status == http.StatusForbidden ||
		strings.Contains(low, "unauthor") || strings.Contains(low, "api key") || strings.Contains(low, "forbidden"):
		return &serperStop{Kind: stopAuth, Status: status,
			Message: fmt.Sprintf("Serper API key rejected (HTTP %d: %s). Check the key in Settings.", status, firstNonEmptyStr(msg, "unauthorized"))}
	default:
		return &serperStop{Kind: stopBadRequest, Status: status,
			Message: fmt.Sprintf("Serper request refused (HTTP %d): %s", status, msg)}
	}
}

func firstNonEmptyStr(a, b string) string {
	if strings.TrimSpace(a) != "" {
		return a
	}
	return b
}

// paginate accumulates results across pages until maxResults, stopping on an
// empty page, a page that adds no new URLs, or a short page (< page_size).
// Returns the collected results and a stop error if the search terminated
// early (credits/auth/transient) — callers treat that as non-fatal.
func (c *serperClient) paginate(ctx context.Context, query string, maxResults int) ([]searchResult, error) {
	return paginateWith(maxResults, 10, func(page int) ([]searchResult, error) {
		if ctx.Err() != nil {
			return nil, &serperStop{Kind: stopTransient, Message: "search cancelled"}
		}
		return c.searchPage(ctx, query, page)
	})
}

// paginateWith is the pure pagination loop (fetch is injected so it's testable
// without HTTP). Stop conditions: empty page, no new URLs (dedupe), short page.
func paginateWith(maxResults, pageSize int, fetch func(page int) ([]searchResult, error)) ([]searchResult, error) {
	seen := map[string]bool{}
	var out []searchResult
	page := 1
	for len(out) < maxResults {
		results, err := fetch(page)
		if err != nil {
			return out, err
		}
		if len(results) == 0 {
			break
		}
		fresh := 0
		for _, r := range results {
			if seen[r.URL] {
				continue
			}
			seen[r.URL] = true
			out = append(out, r)
			fresh++
		}
		if fresh == 0 { // repeat results → Google ceiling reached
			break
		}
		if len(results) < pageSize { // last page
			break
		}
		page++
	}
	if len(out) > maxResults {
		out = out[:maxResults]
	}
	return out, nil
}
