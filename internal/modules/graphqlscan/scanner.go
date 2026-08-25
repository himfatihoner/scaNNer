package graphqlscan

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"sync"
	"time"

	"scanner/internal/modules/shared"
)

// CommonEndpoints is the list of paths the scanner tries when the user
// provides only a base URL.
var CommonEndpoints = []string{
	"/graphql", "/graphiql", "/v1/graphql", "/api/graphql", "/api/v1/graphql",
	"/query", "/api/query", "/playground", "/graphql/console",
	"/.netlify/functions/graphql", "/index.php?graphql",
}

type Finding struct {
	Title       string `json:"title"`
	Severity    string `json:"severity"`
	Detail      string `json:"detail"`
	Evidence    string `json:"evidence,omitempty"`
	RawRequest  string `json:"raw_request,omitempty"`
	RawResponse string `json:"raw_response,omitempty"`
}

// EndpointResult is per-discovered-endpoint output.
type EndpointResult struct {
	URL              string    `json:"url"`
	Status           int       `json:"status"`
	IsGraphQL        bool      `json:"is_graphql"`
	IntrospectionOn  bool      `json:"introspection_on"`
	SchemaTypeCount  int       `json:"schema_type_count,omitempty"`
	QueryFields      []string  `json:"query_fields,omitempty"`
	MutationFields   []string  `json:"mutation_fields,omitempty"`
	SubscriptionFlds []string  `json:"subscription_fields,omitempty"`
	Findings         []Finding `json:"findings"`
	Error            string    `json:"error,omitempty"`
}

type ScanResult struct {
	Endpoints []EndpointResult `json:"endpoints"`
}

type Config struct {
	BaseURLs        []string
	CustomEndpoints []string
	Concurrency     int
	Timeout         time.Duration
}

type ProgressFunc func(done int, msg string)
type PartialFunc func(*ScanResult)

func Scan(ctx context.Context, cfg Config, opts *shared.HTTPOptions, progress ProgressFunc, partial PartialFunc) *ScanResult {
	if cfg.Concurrency <= 0 {
		cfg.Concurrency = 4
	}
	if cfg.Timeout <= 0 {
		cfg.Timeout = 10 * time.Second
	}
	candidates := buildCandidates(cfg.BaseURLs, cfg.CustomEndpoints)

	result := &ScanResult{}
	var mu sync.Mutex
	sem := make(chan struct{}, cfg.Concurrency)
	var wg sync.WaitGroup
	done := 0
	// Audit S2: throttle per-endpoint partial snapshot+marshal to 2s.
	throttle := shared.NewPartialThrottler(2 * time.Second)

	for _, c := range candidates {
		if ctx.Err() != nil {
			break
		}
		wg.Add(1)
		sem <- struct{}{}
		go func(target string) {
			defer wg.Done()
			defer func() { <-sem }()
			er := probe(ctx, target, cfg.Timeout, opts)
			mu.Lock()
			result.Endpoints = append(result.Endpoints, er)
			done++
			cur := done
			mu.Unlock()
			if progress != nil {
				progress(cur, fmt.Sprintf("[%d/%d] %s — gql=%v findings=%d", cur, len(candidates), target, er.IsGraphQL, len(er.Findings)))
			}
			if partial != nil && throttle.ShouldFire() {
				mu.Lock()
				snap := &ScanResult{Endpoints: append([]EndpointResult(nil), result.Endpoints...)}
				mu.Unlock()
				partial(snap)
			}
		}(c)
	}
	wg.Wait()
	if partial != nil {
		throttle.Force()
		mu.Lock()
		snap := &ScanResult{Endpoints: append([]EndpointResult(nil), result.Endpoints...)}
		mu.Unlock()
		partial(snap)
	}
	return result
}

func buildCandidates(bases, custom []string) []string {
	seen := map[string]bool{}
	var out []string
	add := func(u string) {
		u = strings.TrimSpace(u)
		if u == "" || seen[u] {
			return
		}
		seen[u] = true
		out = append(out, u)
	}
	endpoints := CommonEndpoints
	if len(custom) > 0 {
		endpoints = custom
	}
	for _, base := range bases {
		base = strings.TrimSpace(base)
		base = strings.TrimRight(base, "/")
		if base == "" {
			continue
		}
		// If user passed a URL that already has a path, treat as-is.
		if strings.Contains(strings.TrimPrefix(strings.TrimPrefix(base, "http://"), "https://"), "/") {
			add(base)
			continue
		}
		for _, ep := range endpoints {
			// Custom endpoints from the textarea may omit the leading slash;
			// normalise so `https://host` + `graphql` doesn't produce
			// `https://hostgraphql`. CommonEndpoints already begin with '/'.
			if !strings.HasPrefix(ep, "/") {
				ep = "/" + ep
			}
			add(base + ep)
		}
	}
	return out
}

const introspectionQuery = `query IntrospectionQuery { __schema { queryType { name } mutationType { name } subscriptionType { name } types { name kind fields { name } } } }`

func probe(ctx context.Context, target string, timeout time.Duration, opts *shared.HTTPOptions) EndpointResult {
	er := EndpointResult{URL: target}
	client := newClient(timeout, opts)

	// Step 1: Try GET to see if endpoint exists / is GraphiQL.
	getStatus, getBody := doRequest(ctx, client, "GET", target, "", "", opts)
	er.Status = getStatus

	// Step 2: POST a simple `{__typename}` query — if response has "data"
	// the endpoint speaks GraphQL.
	body := `{"query":"{__typename}"}`
	postStatus, postBody, postRawReq, postRawResp := doRequestFull(ctx, client, "POST", target, "application/json", body, opts)

	if isGQL(postStatus, postBody) {
		er.IsGraphQL = true
	} else if strings.Contains(strings.ToLower(getBody), "graphiql") || strings.Contains(strings.ToLower(getBody), "graphql playground") {
		er.IsGraphQL = true
		er.Findings = append(er.Findings, Finding{
			Severity: "HIGH",
			Title:    "GraphiQL / Playground exposed",
			Detail:   "Browser-based GraphQL IDE accessible on a production endpoint. Anyone can craft queries interactively.",
		})
	}

	if !er.IsGraphQL {
		return er
	}

	// Step 3: Introspection probe.
	intrBody := `{"query":` + jsonString(introspectionQuery) + `}`
	intrStatus, intrResp, intrRawReq, intrRawResp := doRequestFull(ctx, client, "POST", target, "application/json", intrBody, opts)
	if intrStatus == 200 && strings.Contains(intrResp, `"__schema"`) {
		er.IntrospectionOn = true
		parseSchema(&er, intrResp)
		er.Findings = append(er.Findings, Finding{
			Severity:    "HIGH",
			Title:       "Introspection enabled",
			Detail:      fmt.Sprintf("Schema disclosed: %d types, %d query fields, %d mutation fields. Disable introspection in production.", er.SchemaTypeCount, len(er.QueryFields), len(er.MutationFields)),
			Evidence:    truncate(intrResp, 400),
			RawRequest:  intrRawReq,
			RawResponse: intrRawResp,
		})
	}

	// Step 4: GET-based query (CSRF — no preflight, no Content-Type
	// requirement → can be triggered from arbitrary origin).
	getQ := target + "?query=" + urlEscape("{__typename}")
	gqlGetStatus, gqlGetBody, gqlGetRawReq, gqlGetRawResp := doRequestFull(ctx, client, "GET", getQ, "", "", opts)
	if isGQL(gqlGetStatus, gqlGetBody) {
		er.Findings = append(er.Findings, Finding{
			Severity:    "MEDIUM",
			Title:       "GraphQL accepts GET queries",
			Detail:      "Server processes GraphQL queries via GET. This enables CSRF and cache poisoning since requests need no special Content-Type.",
			RawRequest:  gqlGetRawReq,
			RawResponse: gqlGetRawResp,
		})
	}

	// Step 5: Suggestion / field-name leak via deliberately wrong field.
	badQ := `{"query":"{ thisFieldDoesNotExist }"}`
	suggStatus, suggResp, _, _ := doRequestFull(ctx, client, "POST", target, "application/json", badQ, opts)
	if suggStatus == 200 || suggStatus == 400 {
		lr := strings.ToLower(suggResp)
		if strings.Contains(lr, "did you mean") || strings.Contains(lr, "suggestion") {
			er.Findings = append(er.Findings, Finding{
				Severity: "MEDIUM",
				Title:    "Field name suggestions leak schema",
				Detail:   "Server returns 'Did you mean...' on unknown fields. Even with introspection disabled, attackers can enumerate the schema brute-force.",
				Evidence: truncate(suggResp, 300),
			})
		}
	}

	// Step 6: Batching enabled (DoS / auth bypass risk).
	batchBody := `[{"query":"{__typename}"},{"query":"{__typename}"}]`
	bStatus, bResp, _, _ := doRequestFull(ctx, client, "POST", target, "application/json", batchBody, opts)
	if bStatus == 200 && strings.HasPrefix(strings.TrimSpace(bResp), "[") && strings.Count(bResp, "__typename") >= 2 {
		er.Findings = append(er.Findings, Finding{
			Severity: "MEDIUM",
			Title:    "Query batching enabled",
			Detail:   "Server processes JSON-array of queries in a single request — useful for bulk-bypass of rate limits and brute-forcing auth mutations.",
			Evidence: truncate(bResp, 300),
		})
	}

	// Step 7: Alias overload (auth brute-force amplification).
	aliasQ := `{"query":"{ a:__typename b:__typename c:__typename d:__typename e:__typename }"}`
	aStatus, aResp, _, _ := doRequestFull(ctx, client, "POST", target, "application/json", aliasQ, opts)
	if aStatus == 200 && strings.Count(aResp, "Query") >= 3 {
		er.Findings = append(er.Findings, Finding{
			Severity: "LOW",
			Title:    "Alias overload accepted",
			Detail:   "Server allows arbitrary numbers of aliases on a single query — attackers can fold N rate-limited mutations into one request.",
			Evidence: truncate(aResp, 200),
		})
	}

	// Mark probe as raw exchange anchor for the headline finding.
	_ = postRawReq
	_ = postRawResp
	if opts != nil {
		opts.ReplayHit("POST", target)
	}
	return er
}

func doRequest(ctx context.Context, client *http.Client, method, url, ct, body string, opts *shared.HTTPOptions) (int, string) {
	s, b, _, _ := doRequestFull(ctx, client, method, url, ct, body, opts)
	return s, b
}

func doRequestFull(ctx context.Context, client *http.Client, method, url, ct, body string, opts *shared.HTTPOptions) (int, string, string, string) {
	var reqBody io.Reader
	if body != "" {
		reqBody = bytes.NewReader([]byte(body))
	}
	req, err := http.NewRequestWithContext(ctx, method, url, reqBody)
	if err != nil {
		return 0, "", "", ""
	}
	req.Header.Set("User-Agent", "Mozilla/5.0 scaNNer/GraphQL")
	if ct != "" {
		req.Header.Set("Content-Type", ct)
	}
	if opts != nil {
		opts.ApplyTo(req)
	}
	rawReq := shared.CaptureRequest(req)
	resp, err := client.Do(req)
	if err != nil {
		if opts != nil {
			opts.RecordError(shared.ClassifyError(err))
		}
		return 0, "", rawReq, ""
	}
	rawResp := shared.CaptureResponse(resp)
	defer resp.Body.Close()
	bb, _ := io.ReadAll(io.LimitReader(resp.Body, 256*1024))
	return resp.StatusCode, string(bb), rawReq, rawResp
}

func isGQL(status int, body string) bool {
	if status == 0 || body == "" {
		return false
	}
	// Audit MEDIUM fix: production GraphQL APIs (Hasura, Apollo, AWS AppSync)
	// commonly return 401/403/422 with a valid GraphQL error envelope. Previous
	// strict 200/400 whitelist silently discarded auth-gated endpoints — the
	// most realistic prod targets — as non-GraphQL. Widen the whitelist so the
	// body signature (data/errors/__typename markers) is what actually decides.
	switch status {
	case 200, 400, 401, 403, 422:
		// allowed — fall through to body check
	default:
		return false
	}
	low := strings.ToLower(body)
	return strings.Contains(low, `"data"`) || strings.Contains(low, `"errors"`) || strings.Contains(low, `"__typename"`)
}

func parseSchema(er *EndpointResult, body string) {
	var resp struct {
		Data struct {
			Schema struct {
				QueryType        struct{ Name string }
				MutationType     struct{ Name string }
				SubscriptionType struct{ Name string }
				Types            []struct {
					Name   string
					Kind   string
					Fields []struct {
						Name string
					}
				}
			} `json:"__schema"`
		}
	}
	if err := json.Unmarshal([]byte(body), &resp); err != nil {
		return
	}
	er.SchemaTypeCount = len(resp.Data.Schema.Types)
	queryName := resp.Data.Schema.QueryType.Name
	mutName := resp.Data.Schema.MutationType.Name
	subName := resp.Data.Schema.SubscriptionType.Name
	for _, t := range resp.Data.Schema.Types {
		if t.Name == queryName {
			for _, f := range t.Fields {
				er.QueryFields = append(er.QueryFields, f.Name)
			}
		} else if t.Name == mutName {
			for _, f := range t.Fields {
				er.MutationFields = append(er.MutationFields, f.Name)
			}
		} else if t.Name == subName {
			for _, f := range t.Fields {
				er.SubscriptionFlds = append(er.SubscriptionFlds, f.Name)
			}
		}
	}
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
			if len(via) > 5 {
				return http.ErrUseLastResponse
			}
			return nil
		},
	}
}

func jsonString(s string) string {
	b, _ := json.Marshal(s)
	return string(b)
}

func urlEscape(s string) string {
	r := strings.NewReplacer(" ", "%20", "{", "%7B", "}", "%7D", "\"", "%22")
	return r.Replace(s)
}

func truncate(s string, max int) string {
	if len(s) <= max {
		return s
	}
	return s[:max] + "..."
}
