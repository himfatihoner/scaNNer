package assetdisc

import (
	"context"
	"crypto/tls"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"

	"scanner/internal/modules/shared"
)

type Asset struct {
	Source    string   `json:"source"` // "shodan", "censys"
	IP        string   `json:"ip"`
	Port      int      `json:"port,omitempty"`
	Hostname  string   `json:"hostname,omitempty"`
	OS        string   `json:"os,omitempty"`
	ASN       string   `json:"asn,omitempty"`
	Org       string   `json:"org,omitempty"`
	Country   string   `json:"country,omitempty"`
	Product   string   `json:"product,omitempty"`
	Banner    string   `json:"banner,omitempty"`
	Domains   []string `json:"domains,omitempty"`
	Discovered time.Time `json:"discovered"`
}

type QueryResult struct {
	Source   string  `json:"source"`
	Query    string  `json:"query"`
	Assets   []Asset `json:"assets"`
	Total    int     `json:"total"`
	Error    string  `json:"error,omitempty"`
	RateInfo string  `json:"rate_info,omitempty"`
}

type ScanResult struct {
	Queries []QueryResult `json:"queries"`
}

type Config struct {
	Queries       []string // generic queries; supports "org:Foo", "ssl:bar", "hostname:baz", etc.
	UseShodan     bool
	UseCensys     bool
	ShodanKey     string
	CensysID      string
	CensysSecret  string
	MaxPerQuery   int
	// MaxPages caps the number of API pages fetched per query. Default 1.
	// Shodan/Censys page cursors are followed up to this cap. Each Shodan
	// page beyond 1 costs a query credit on paid plans; the form warns.
	MaxPages      int
	Timeout       time.Duration
}

type ProgressFunc func(done int, msg string)
type PartialFunc func(*ScanResult)

func Scan(ctx context.Context, cfg Config, opts *shared.HTTPOptions, progress ProgressFunc, partial PartialFunc) *ScanResult {
	if cfg.Timeout <= 0 {
		cfg.Timeout = 20 * time.Second
	}
	if cfg.MaxPerQuery <= 0 {
		cfg.MaxPerQuery = 100
	}
	if cfg.MaxPages <= 0 {
		cfg.MaxPages = 1
	}
	result := &ScanResult{}
	var mu sync.Mutex
	client := newClient(cfg.Timeout, opts)
	done := 0
	// Audit S2: throttle per-query partial snapshot+marshal to 2s.
	throttle := shared.NewPartialThrottler(2 * time.Second)
	emit := func(qr QueryResult) {
		mu.Lock()
		result.Queries = append(result.Queries, qr)
		done++
		cur := done
		mu.Unlock()
		if progress != nil {
			progress(cur, fmt.Sprintf("%s — %s — %d assets", qr.Source, qr.Query, len(qr.Assets)))
		}
		if partial != nil && throttle.ShouldFire() {
			mu.Lock()
			snap := &ScanResult{Queries: append([]QueryResult(nil), result.Queries...)}
			mu.Unlock()
			partial(snap)
		}
	}

	for _, q := range cfg.Queries {
		if ctx.Err() != nil {
			break
		}
		if cfg.UseShodan {
			if cfg.ShodanKey == "" {
				emit(QueryResult{Source: "shodan", Query: q, Error: "no Shodan API key in Settings"})
			} else {
				emit(queryShodan(ctx, client, q, cfg.ShodanKey, cfg.MaxPerQuery, cfg.MaxPages))
			}
		}
		if cfg.UseCensys {
			if cfg.CensysID == "" || cfg.CensysSecret == "" {
				emit(QueryResult{Source: "censys", Query: q, Error: "no Censys ID/Secret in Settings"})
			} else {
				emit(queryCensys(ctx, client, q, cfg.CensysID, cfg.CensysSecret, cfg.MaxPerQuery, cfg.MaxPages))
			}
		}
	}
	if partial != nil {
		throttle.Force()
		mu.Lock()
		snap := &ScanResult{Queries: append([]QueryResult(nil), result.Queries...)}
		mu.Unlock()
		partial(snap)
	}
	return result
}

func queryShodan(ctx context.Context, client *http.Client, q, key string, maxAssets, maxPages int) QueryResult {
	qr := QueryResult{Source: "shodan", Query: q}
	if maxPages < 1 {
		maxPages = 1
	}
	// Audit M1: page through Shodan results. Shodan returns 100 hits per
	// page; iterate until we hit the per-query cap, the reported Total,
	// or an empty page. `&page=N` is the pagination cursor.
	for page := 1; page <= maxPages; page++ {
		if ctx.Err() != nil {
			break
		}
		if len(qr.Assets) >= maxAssets {
			break
		}
		endpoint := "https://api.shodan.io/shodan/host/search?key=" + url.QueryEscape(key) + "&query=" + url.QueryEscape(q) + "&minify=true"
		if page > 1 {
			endpoint += fmt.Sprintf("&page=%d", page)
		}
		req, _ := http.NewRequestWithContext(ctx, "GET", endpoint, nil)
		resp, err := client.Do(req)
		if err != nil {
			qr.Error = err.Error()
			return qr
		}
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 512*1024))
		resp.Body.Close()
		if resp.StatusCode != 200 {
			qr.Error = fmt.Sprintf("Shodan %d: %s", resp.StatusCode, truncate(string(body), 240))
			return qr
		}
		var parsed struct {
			Total   int `json:"total"`
			Matches []struct {
				IP       interface{} `json:"ip"`
				IPStr    string      `json:"ip_str"`
				Port     int         `json:"port"`
				Hostnames []string   `json:"hostnames"`
				OS       string      `json:"os"`
				Org      string      `json:"org"`
				ISP      string      `json:"isp"`
				ASN      string      `json:"asn"`
				Location struct {
					CountryName string `json:"country_name"`
				} `json:"location"`
				Product  string      `json:"product"`
				Data     string      `json:"data"`
				Domains  []string    `json:"domains"`
			} `json:"matches"`
		}
		if err := json.Unmarshal(body, &parsed); err != nil {
			qr.Error = "Shodan: parse error: " + err.Error()
			return qr
		}
		if page == 1 {
			qr.Total = parsed.Total
		}
		if len(parsed.Matches) == 0 {
			break
		}
		for _, m := range parsed.Matches {
			if len(qr.Assets) >= maxAssets {
				break
			}
			ipStr := m.IPStr
			if ipStr == "" {
				ipStr = fmt.Sprintf("%v", m.IP)
			}
			host := ""
			if len(m.Hostnames) > 0 {
				host = m.Hostnames[0]
			}
			qr.Assets = append(qr.Assets, Asset{
				Source:    "shodan",
				IP:        ipStr,
				Port:      m.Port,
				Hostname:  host,
				OS:        m.OS,
				Org:       m.Org,
				ASN:       m.ASN,
				Country:   m.Location.CountryName,
				Product:   m.Product,
				Banner:    truncate(m.Data, 200),
				Domains:   m.Domains,
				Discovered: time.Now(),
			})
		}
		if qr.Total > 0 && len(qr.Assets) >= qr.Total {
			break
		}
	}
	return qr
}

func queryCensys(ctx context.Context, client *http.Client, q, id, secret string, maxAssets, maxPages int) QueryResult {
	qr := QueryResult{Source: "censys", Query: q}
	if maxPages < 1 {
		maxPages = 1
	}
	creds := base64.StdEncoding.EncodeToString([]byte(id + ":" + secret))
	cursor := ""
	// Audit M1: follow Censys v2 cursor via result.links.next until we
	// hit the per-query cap, an empty next cursor, or the page cap.
	hosts := 0
	for page := 1; page <= maxPages; page++ {
		if ctx.Err() != nil {
			break
		}
		if len(qr.Assets) >= maxAssets {
			break
		}
		perPage := 100
		remaining := maxAssets - hosts
		if remaining < perPage && remaining > 0 {
			perPage = remaining
		}
		var body string
		if cursor == "" {
			body = fmt.Sprintf(`{"q":%q,"per_page":%d}`, q, perPage)
		} else {
			body = fmt.Sprintf(`{"q":%q,"per_page":%d,"cursor":%q}`, q, perPage, cursor)
		}
		req, _ := http.NewRequestWithContext(ctx, "POST", "https://search.censys.io/api/v2/hosts/search", strings.NewReader(body))
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("Authorization", "Basic "+creds)
		resp, err := client.Do(req)
		if err != nil {
			qr.Error = err.Error()
			return qr
		}
		respBody, _ := io.ReadAll(io.LimitReader(resp.Body, 512*1024))
		resp.Body.Close()
		if resp.StatusCode != 200 {
			qr.Error = fmt.Sprintf("Censys %d: %s", resp.StatusCode, truncate(string(respBody), 240))
			return qr
		}
		var parsed struct {
			Code   int `json:"code"`
			Result struct {
				Total   int `json:"total"`
				Hits []struct {
					IP        string   `json:"ip"`
					Services  []struct {
						Port             int    `json:"port"`
						ServiceName      string `json:"service_name"`
						TransportProto   string `json:"transport_protocol"`
						ExtendedServiceName string `json:"extended_service_name"`
					} `json:"services"`
					DNS struct {
						Names []string `json:"names"`
					} `json:"dns"`
					OperatingSystem struct {
						Product string `json:"product"`
					} `json:"operating_system"`
					Location struct {
						Country string `json:"country"`
					} `json:"location"`
					AutonomousSystem struct {
						ASN  int    `json:"asn"`
						Name string `json:"name"`
					} `json:"autonomous_system"`
				} `json:"hits"`
				Links struct {
					Next string `json:"next"`
					Prev string `json:"prev"`
				} `json:"links"`
			} `json:"result"`
		}
		if err := json.Unmarshal(respBody, &parsed); err != nil {
			qr.Error = "Censys: parse error: " + err.Error()
			return qr
		}
		if page == 1 {
			qr.Total = parsed.Result.Total
		}
		if len(parsed.Result.Hits) == 0 {
			break
		}
		for _, h := range parsed.Result.Hits {
			if hosts >= maxAssets {
				break
			}
			hosts++
			host := ""
			if len(h.DNS.Names) > 0 {
				host = h.DNS.Names[0]
			}
			// For each service emit a row
			if len(h.Services) == 0 {
				qr.Assets = append(qr.Assets, Asset{
					Source:    "censys",
					IP:        h.IP,
					Hostname:  host,
					OS:        h.OperatingSystem.Product,
					Country:   h.Location.Country,
					ASN:       fmt.Sprintf("AS%d %s", h.AutonomousSystem.ASN, h.AutonomousSystem.Name),
					Domains:   h.DNS.Names,
					Discovered: time.Now(),
				})
			}
			for _, svc := range h.Services {
				qr.Assets = append(qr.Assets, Asset{
					Source:    "censys",
					IP:        h.IP,
					Port:      svc.Port,
					Hostname:  host,
					OS:        h.OperatingSystem.Product,
					Country:   h.Location.Country,
					ASN:       fmt.Sprintf("AS%d %s", h.AutonomousSystem.ASN, h.AutonomousSystem.Name),
					Product:   svc.ExtendedServiceName,
					Banner:    svc.ServiceName,
					Domains:   h.DNS.Names,
					Discovered: time.Now(),
				})
			}
		}
		cursor = parsed.Result.Links.Next
		if cursor == "" {
			break
		}
	}
	return qr
}

func newClient(timeout time.Duration, opts *shared.HTTPOptions) *http.Client {
	transport := &http.Transport{
		TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
		DialContext:     shared.BoundDialer(nil, timeout).DialContext,
	}
	if opts != nil {
		opts.ApplyTransport(transport)
	}
	return &http.Client{Timeout: timeout, Transport: transport}
}

func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n] + "..."
}
func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}
