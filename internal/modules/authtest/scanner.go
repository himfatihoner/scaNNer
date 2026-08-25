package authtest

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"io"
	"math"
	"net/http"
	"net/url"
	"regexp"
	"strings"
	"sync"
	"time"

	"scanner/internal/modules/shared"
)

type Finding struct {
	Severity    string `json:"severity"`
	Title       string `json:"title"`
	Detail      string `json:"detail"`
	Evidence    string `json:"evidence,omitempty"`
	RawRequest  string `json:"raw_request,omitempty"`
	RawResponse string `json:"raw_response,omitempty"`
}

type Attempt struct {
	Username   string `json:"username"`
	Password   string `json:"password"`
	StatusCode int    `json:"status_code"`
	BodyLen    int    `json:"body_len"`
	Outcome    string `json:"outcome"`
}

type URLResult struct {
	LoginURL string    `json:"login_url"`
	Method   string    `json:"method"`
	Findings []Finding `json:"findings"`
	Attempts []Attempt `json:"attempts,omitempty"`
	Error    string    `json:"error,omitempty"`
}

type ScanResult struct {
	Results []URLResult `json:"results"`
}

// AttackMode mirrors Burp Intruder's attack types. Each mode produces a
// different (username, password) sequence from the user/pass lists.
type AttackMode string

const (
	// ModeSniper varies a single field while holding the other fixed.
	// With 1 user × N passwords: classic single-user brute. With M users
	// × 1 password: reverse — same password against many users. Choose
	// which field varies via SniperField ("password" default).
	ModeSniper AttackMode = "sniper"

	// ModeBatteringRam puts the SAME value into both username and
	// password slots. Common case: try identical strings (admin/admin,
	// root/root, etc.) — easy way to catch default credentials when the
	// vendor sets user==pass.
	ModeBatteringRam AttackMode = "batteringram"

	// ModePitchfork zips the two lists. usernames[i] is tried with
	// passwords[i] — they don't cross. Use when you have leaked
	// (user, pass) pairs from a breach and want to credential-stuff.
	ModePitchfork AttackMode = "pitchfork"

	// ModeClusterBomb is the cartesian product — every user × every
	// password. The loudest mode, fastest to find ANY weak credential
	// across multiple accounts. Use when you don't care about lockouts.
	ModeClusterBomb AttackMode = "clusterbomb"

	// ModePasswordSpray rotates by password — each password tried against
	// EVERY user, then move to the next password. Designed to evade
	// per-account lockout policies: a single user only sees one bad
	// attempt before the run moves on, far below typical 3-5 lockout
	// thresholds. Pair with DelayPerUser ≥ 30s for true low-and-slow.
	ModePasswordSpray AttackMode = "spray"
)

type Config struct {
	LoginURL      string   // POST endpoint
	Method        string   // POST default
	UserField     string   // form field for username (default "username")
	PassField     string   // default "password"
	Usernames     []string // small list (≤ 20)
	Passwords     []string // small list (≤ 20)
	ExtraFields   map[string]string
	FailMarker    string // substring in response body indicating "invalid"
	SuccessMarker string // substring indicating success (e.g. "Welcome")
	TestSession   bool   // also do session-fixation probe (GET → POST)
	ResetURL      string // optional password-reset URL for token entropy check
	Concurrency   int    // honored by ClusterBomb; spray/pitchfork are serial by design
	Timeout       time.Duration

	// Attack control (Burp Intruder semantics, see AttackMode docs above).
	Mode         AttackMode
	SniperField  string        // "username" | "password" — which slot varies under ModeSniper
	DelayPerUser time.Duration // wait after EACH USERNAME's full pass sweep finishes (anti-lockout)
	DelayPerPass time.Duration // wait between individual login attempts (rate-limit friendly)
	MaxAttempts  int           // hard cap so a runaway 1000×1000 cluster-bomb can't ddos

	// Audit MEDIUM fix: support JSON login bodies for SPA/API endpoints
	// (Okta/Auth0/Cognito/most modern stacks respond 400/415 to a form
	// POST). BodyEncoding switches tryLogin between form and JSON; when
	// "json", JSONTemplate is rendered with {USER} / {PASS} placeholders
	// that are automatically JSON-escaped (embedded quotes/newlines are
	// safe). Empty encoding falls back to form for back-compat with
	// pre-fix saved configs.
	BodyEncoding string // "form" (default, back-compat) | "json"
	JSONTemplate string // e.g. `{"username":"{USER}","password":"{PASS}"}`
}

type ProgressFunc func(done int, msg string)
type PartialFunc func(*ScanResult)

// AttackPairCount returns the number of (user, pass) attempts that
// buildAttackPairs would produce for cfg. Exposed so the handler can
// pre-compute a per-mode-accurate progress bar total instead of using
// the ClusterBomb cartesian as a stand-in. Audit MEDIUM fix.
func AttackPairCount(cfg Config) int {
	return len(buildAttackPairs(cfg))
}

// maskCredential redacts a password before it lands in a Finding.Detail
// string. The plaintext stays in the local Attempt row (which is gated
// behind the results page details panel and can be hidden), but the
// SUCCESS finding — which can be exported as JSON/CSV and is the most
// visible artifact — only carries a mask. Audit MEDIUM fix for
// "CRITICAL finding leaks plaintext credentials".
func maskCredential(s string) string {
	if len(s) <= 2 {
		return "***"
	}
	if len(s) <= 5 {
		return string(s[0]) + strings.Repeat("*", len(s)-1)
	}
	return string(s[0]) + strings.Repeat("*", len(s)-2) + string(s[len(s)-1])
}

// jsonEscape returns the JSON-escaped inner value of s (no surrounding
// quotes), so a credential containing " / \ / newlines can be safely
// inlined into a JSONTemplate placeholder. Audit MEDIUM fix companion:
// prevents template rendering from producing invalid JSON when the
// credential contains structural chars.
func jsonEscape(s string) string {
	b, err := json.Marshal(s)
	if err != nil || len(b) < 2 {
		return s
	}
	return string(b[1 : len(b)-1])
}

// redactJSONBody scrubs the JSON pass field out of a captured raw HTTP
// request dump for the JSON body path (analog of redactFormBody). Runs
// two passes: first the field-aware regex `"passField"\s*:\s*"..."`
// (handles the common case where the JSON key matches cfg.PassField);
// then a raw substring scrub as a belt-and-braces measure so the
// plaintext value can't leak even if the template uses a different key.
// Header lines above the blank-line separator are left untouched.
func redactJSONBody(raw, passField, passValue string) string {
	if raw == "" {
		return raw
	}
	idx := strings.Index(raw, "\r\n\r\n")
	sep := "\r\n\r\n"
	if idx < 0 {
		idx = strings.Index(raw, "\n\n")
		sep = "\n\n"
		if idx < 0 {
			return raw
		}
	}
	head, body := raw[:idx], raw[idx+len(sep):]
	if passField != "" {
		re := regexp.MustCompile(`"` + regexp.QuoteMeta(passField) + `"\s*:\s*"[^"\\]*(?:\\.[^"\\]*)*"`)
		body = re.ReplaceAllString(body, `"`+passField+`":"***REDACTED***"`)
	}
	if passValue != "" {
		body = strings.ReplaceAll(body, jsonEscape(passValue), "***REDACTED***")
		body = strings.ReplaceAll(body, passValue, "***REDACTED***")
	}
	return head + sep + body
}

// redactFormBody scrubs the password value out of a captured raw HTTP
// request body. CaptureRequest already redacts secret HEADERS, but the
// login form body itself carries the plaintext and that ends up in
// Finding.RawRequest → scans.result JSON → exports + UI. The replace is
// targeted at the named pass field (URL-encoded form), so legitimate
// username / extra-field values stay visible for the operator.
func redactFormBody(raw, passField string) string {
	if raw == "" || passField == "" {
		return raw
	}
	// httputil.DumpRequest emits headers, then a blank line, then body.
	// We only rewrite content past the blank line so we don't touch
	// any header that happens to contain the same token.
	idx := strings.Index(raw, "\r\n\r\n")
	if idx < 0 {
		idx = strings.Index(raw, "\n\n")
		if idx < 0 {
			return raw
		}
	}
	head, body := raw[:idx], raw[idx:]
	values, err := url.ParseQuery(strings.TrimLeft(body, "\r\n"))
	if err != nil || values.Get(passField) == "" {
		return raw
	}
	values.Set(passField, "***REDACTED***")
	// Rebuild — preserve a single blank-line separator.
	sep := "\r\n\r\n"
	if strings.HasPrefix(body, "\n\n") {
		sep = "\n\n"
	}
	return head + sep + values.Encode()
}

func Scan(ctx context.Context, cfg Config, opts *shared.HTTPOptions, progress ProgressFunc, partial PartialFunc) *ScanResult {
	if cfg.Method == "" {
		cfg.Method = "POST"
	}
	if cfg.UserField == "" {
		cfg.UserField = "username"
	}
	if cfg.PassField == "" {
		cfg.PassField = "password"
	}
	if cfg.Concurrency <= 0 {
		cfg.Concurrency = 3
	}
	if cfg.Timeout <= 0 {
		cfg.Timeout = 12 * time.Second
	}

	result := &ScanResult{}
	ur := URLResult{LoginURL: cfg.LoginURL, Method: cfg.Method}
	result.Results = []URLResult{ur}

	// Audit S2: ClusterBomb fan-out fires partial per attempt; with 1000+
	// attempts each marshals the full Attempts slice. Throttle at source
	// to 2s; the final attempt always flushes via Force() at scan end.
	throttle := shared.NewPartialThrottler(2 * time.Second)
	emit := func(updateFn func(*URLResult)) {
		updateFn(&result.Results[0])
		if partial != nil && throttle.ShouldFire() {
			snap := &ScanResult{Results: []URLResult{result.Results[0]}}
			partial(snap)
		}
	}

	client := newClient(cfg.Timeout, opts)
	totalAttempts := 0
	// Baseline a known-bad attempt to learn the failure response shape.
	if progress != nil {
		progress(0, "Baseline failed-login probe...")
	}
	baselineStatus, baselineLen, baselineBody, _, _ := tryLogin(ctx, client, cfg, "definitely-nonexistent-user-"+nanoID(), "wrong-pass-"+nanoID(), opts)
	emit(func(u *URLResult) {
		u.Attempts = append(u.Attempts, Attempt{
			Username: "baseline-bad-user", Password: "***",
			StatusCode: baselineStatus, BodyLen: baselineLen, Outcome: "baseline",
		})
	})
	totalAttempts++

	if cfg.FailMarker == "" {
		// Try to infer a fail marker from the baseline body.
		if m := inferFailMarker(baselineBody); m != "" {
			cfg.FailMarker = m
			emit(func(u *URLResult) {
				u.Findings = append(u.Findings, Finding{
					Severity: "INFO", Title: "Failure marker inferred",
					Detail:   "Used baseline-failed response to derive a heuristic 'invalid' string.",
					Evidence: m,
				})
			})
		}
	}

	// User-enumeration probe: same wrong password against each user.
	if len(cfg.Usernames) > 0 {
		if progress != nil {
			progress(totalAttempts, "User-enumeration probes...")
		}
		probeUserEnum(ctx, client, cfg, baselineStatus, baselineLen, baselineBody, opts, emit, &totalAttempts, progress)
	}

	// Build the (user, pass) attack sequence based on the selected Burp-
	// Intruder-style mode. Each mode shapes the iteration order DIFFERENTLY
	// — that's the whole point of the option (anti-lockout, credential
	// stuffing, default-cred test, etc.).
	pairs := buildAttackPairs(cfg)
	if cfg.MaxAttempts > 0 && len(pairs) > cfg.MaxAttempts {
		pairs = pairs[:cfg.MaxAttempts]
		emit(func(u *URLResult) {
			u.Findings = append(u.Findings, Finding{
				Severity: "INFO", Title: "Attempt cap reached",
				Detail: fmt.Sprintf("Truncated to MaxAttempts=%d to avoid runaway probing.", cfg.MaxAttempts),
			})
		})
	}

	if len(pairs) > 0 {
		var mu sync.Mutex
		hits := 0

		runOne := func(user, pass, label string) {
			st, ln, body, rawReq, rawResp := tryLogin(ctx, client, cfg, user, pass, opts)
			// Audit MEDIUM fix: tryLogin returned (0, 0, "", "", "") on
			// request-build errors / cancelled scans. Treat status==0 as a
			// transient error rather than a success/fail data point — the
			// classifier's 200-vs-401 fallback could otherwise misfire,
			// and the userenum signature aggregation would lump errors
			// into a fake bucket.
			if st == 0 {
				mu.Lock()
				totalAttempts++
				cur := totalAttempts
				result.Results[0].Attempts = append(result.Results[0].Attempts, Attempt{
					Username: user, Password: maskCredential(pass),
					StatusCode: 0, BodyLen: 0, Outcome: "error",
				})
				mu.Unlock()
				if progress != nil {
					progress(cur, fmt.Sprintf("[%d] %s — %s — error", cur, label, user))
				}
				return
			}
			mu.Lock()
			totalAttempts++
			cur := totalAttempts
			// Audit MEDIUM fix: the cracked password used to be persisted
			// verbatim into the Attempt row (and from there into scan
			// result JSON / CSV exports / the rendered HTML page).
			// Replace with a mask — operators who NEED the plaintext can
			// still get it from the RawRequest panel (also redacted) and
			// from the SUCCESS finding Detail (also masked).
			at := Attempt{Username: user, Password: maskCredential(pass), StatusCode: st, BodyLen: ln}
			ok := loginLooksSuccessful(cfg, st, ln, body, baselineStatus, baselineLen)
			if ok {
				at.Outcome = "SUCCESS"
				hits++
				result.Results[0].Findings = append(result.Results[0].Findings, Finding{
					Severity: "CRITICAL", Title: "Weak credentials accepted",
					Detail:     fmt.Sprintf("Login as %s / %s succeeded (mode=%s).", user, maskCredential(pass), label),
					Evidence:   fmt.Sprintf("HTTP %d, body %d bytes", st, ln),
					RawRequest: rawReq, RawResponse: rawResp,
				})
			} else {
				at.Outcome = "fail"
			}
			result.Results[0].Attempts = append(result.Results[0].Attempts, at)
			mu.Unlock()
			if progress != nil {
				progress(cur, fmt.Sprintf("[%d] %s — %s — %s", cur, label, user, at.Outcome))
			}
			if partial != nil && throttle.ShouldFire() {
				// Audit MEDIUM fix: shallow-copying result.Results[0] still
				// shares the Attempts and Findings backing arrays with the
				// live URLResult, so another ClusterBomb goroutine's append
				// could race with json.Marshal walking snap. Deep-copy both
				// slices while still holding mu so the emitted snapshot is
				// a fully independent value the caller can serialize safely
				// once mu is released.
				mu.Lock()
				attemptsCopy := append([]Attempt(nil), result.Results[0].Attempts...)
				findingsCopy := append([]Finding(nil), result.Results[0].Findings...)
				snap := &ScanResult{Results: []URLResult{{
					LoginURL: result.Results[0].LoginURL,
					Method:   result.Results[0].Method,
					Findings: findingsCopy,
					Attempts: attemptsCopy,
					Error:    result.Results[0].Error,
				}}}
				mu.Unlock()
				partial(snap)
			}
		}

		// Cluster Bomb keeps the original concurrent firing (loud + fast).
		// Every other mode runs serially so DelayPerPass / DelayPerUser
		// actually slow the run — concurrency would defeat the delay.
		if cfg.Mode == ModeClusterBomb {
			sem := make(chan struct{}, cfg.Concurrency)
			var wg sync.WaitGroup
			for _, p := range pairs {
				if ctx.Err() != nil {
					break
				}
				wg.Add(1)
				sem <- struct{}{}
				go func(user, pass string) {
					defer wg.Done()
					defer func() { <-sem }()
					runOne(user, pass, "clusterbomb")
				}(p.User, p.Pass)
			}
			wg.Wait()
		} else {
			lastUser := ""
			// Audit MEDIUM fix: bare `break` inside `select { case
			// <-ctx.Done(): break }` exits ONLY the select, NOT the
			// outer for-loop, so a cancellation during a delay would
			// still fire one more login attempt. Use a labeled break to
			// exit the loop on context cancellation.
		serialLoop:
			for _, p := range pairs {
				if ctx.Err() != nil {
					break serialLoop
				}
				// Anti-lockout boundary: when the username changes (spray
				// mode flips here per-password, brute modes per-account),
				// wait DelayPerUser before the next account is touched.
				if lastUser != "" && p.User != lastUser && cfg.DelayPerUser > 0 {
					select {
					case <-ctx.Done():
						break serialLoop
					case <-time.After(cfg.DelayPerUser):
					}
				}
				lastUser = p.User
				runOne(p.User, p.Pass, string(cfg.Mode))
				if cfg.DelayPerPass > 0 {
					select {
					case <-ctx.Done():
						break serialLoop
					case <-time.After(cfg.DelayPerPass):
					}
				}
			}
		}
		_ = hits
	}

	// Session fixation probe.
	if cfg.TestSession {
		if progress != nil {
			progress(totalAttempts, "Session fixation probe...")
		}
		// Audit MEDIUM fix: pass real baseline status/len so the
		// session-fixation probe's success classifier doesn't misfire on
		// any 302/200 (the previous baselineStatus=0 short-circuited the
		// 200-vs-401 fallback but ALSO short-circuited the 302/303
		// check the wrong way).
		probeSessionFixation(ctx, client, cfg, opts, emit, baselineStatus, baselineLen)
	}

	// Password reset entropy probe.
	if cfg.ResetURL != "" {
		if progress != nil {
			progress(totalAttempts, "Password reset entropy probe...")
		}
		probeResetEntropy(ctx, client, cfg, opts, emit)
	}

	// Force-fire final partial so the throttle's last skipped frame
	// isn't the user's terminal view.
	if partial != nil {
		throttle.Force()
		snap := &ScanResult{Results: []URLResult{result.Results[0]}}
		partial(snap)
	}
	return result
}

// loginLooksSuccessful is the central success-classifier used by brute and
// enumeration. Heuristic:
//   - explicit SuccessMarker matches → SUCCESS
//   - FailMarker present → FAIL
//   - status changes (302/303 from a 200 baseline OR 200 from a 401 baseline) → SUCCESS
//   - body length differs significantly (Δ ≥ 20%) → SUCCESS hint
func loginLooksSuccessful(cfg Config, status, bodyLen int, body string, baselineStatus, baselineLen int) bool {
	low := strings.ToLower(body)
	if cfg.SuccessMarker != "" && strings.Contains(low, strings.ToLower(cfg.SuccessMarker)) {
		return true
	}
	if cfg.FailMarker != "" && strings.Contains(low, strings.ToLower(cfg.FailMarker)) {
		return false
	}
	if (status == 302 || status == 303) && baselineStatus != status {
		return true
	}
	if status == 200 && (baselineStatus == 401 || baselineStatus == 403) {
		return true
	}
	if baselineLen > 0 && bodyLen > 0 {
		delta := math.Abs(float64(bodyLen-baselineLen)) / float64(baselineLen)
		if delta > 0.2 {
			return true
		}
	}
	return false
}

func probeUserEnum(ctx context.Context, client *http.Client, cfg Config, baselineStatus, baselineLen int, baselineBody string, opts *shared.HTTPOptions, emit func(func(*URLResult)), totalAttempts *int, progress ProgressFunc) {
	type signature struct {
		status int
		len    int
		body   string
	}
	var sigs []signature
	for _, user := range cfg.Usernames {
		st, ln, body, _, _ := tryLogin(ctx, client, cfg, user, "wrong-pass-fixed-"+nanoID(), opts)
		*totalAttempts++
		cur := *totalAttempts
		emit(func(u *URLResult) {
			u.Attempts = append(u.Attempts, Attempt{
				Username: user, Password: "***fixed-wrong***",
				StatusCode: st, BodyLen: ln, Outcome: "userenum",
			})
		})
		if progress != nil {
			progress(cur, fmt.Sprintf("[%d] userenum: %s — HTTP %d (body %d)", cur, user, st, ln))
		}
		sigs = append(sigs, signature{status: st, len: ln, body: body})
	}
	// If status codes or body lengths cluster into ≥2 buckets, that's a
	// user-enum oracle.
	statusBuckets := map[int]int{}
	lenBuckets := map[int]int{}
	for _, s := range sigs {
		statusBuckets[s.status]++
		// Bucket lengths in 64-byte chunks to absorb minor noise.
		lenBuckets[s.len/64]++
	}
	if len(statusBuckets) > 1 || len(lenBuckets) > 1 {
		emit(func(u *URLResult) {
			u.Findings = append(u.Findings, Finding{
				Severity: "MEDIUM", Title: "Username enumeration possible",
				Detail: fmt.Sprintf("Failed-login responses differ between valid/invalid usernames (status buckets=%d, length buckets=%d). An attacker can enumerate valid accounts.", len(statusBuckets), len(lenBuckets)),
			})
		})
	}
}

func probeSessionFixation(ctx context.Context, client *http.Client, cfg Config, opts *shared.HTTPOptions, emit func(func(*URLResult)), baselineStatus, baselineLen int) {
	// Step 1: GET the login URL to receive a session cookie pre-auth.
	req, err := http.NewRequestWithContext(ctx, "GET", cfg.LoginURL, nil)
	if err != nil {
		return
	}
	req.Header.Set("User-Agent", "Mozilla/5.0 scaNNer/Auth")
	if opts != nil {
		opts.ApplyTo(req)
	}
	resp1, err := client.Do(req)
	if err != nil {
		return
	}
	cookie1 := extractSessionCookie(resp1)
	io.Copy(io.Discard, resp1.Body)
	resp1.Body.Close()
	if cookie1 == "" {
		return
	}
	// Step 2: log in with a valid credential (if user supplied any usernames + passwords).
	if len(cfg.Usernames) == 0 || len(cfg.Passwords) == 0 {
		return
	}
	st, _, body, rawReq, rawResp := tryLogin(ctx, client, cfg, cfg.Usernames[0], cfg.Passwords[0], opts)
	if !loginLooksSuccessful(cfg, st, len(body), body, baselineStatus, baselineLen) {
		return // need a successful login to evaluate session ID stability.
	}
	// Re-probe cookie post-login.
	req2, _ := http.NewRequestWithContext(ctx, "GET", cfg.LoginURL, nil)
	if opts != nil {
		opts.ApplyTo(req2)
	}
	resp2, err := client.Do(req2)
	if err != nil {
		return
	}
	cookie2 := extractSessionCookie(resp2)
	io.Copy(io.Discard, resp2.Body)
	resp2.Body.Close()
	if cookie1 == cookie2 && cookie2 != "" {
		emit(func(u *URLResult) {
			u.Findings = append(u.Findings, Finding{
				Severity: "HIGH", Title: "Session fixation",
				Detail:     "Session cookie does not rotate on successful authentication. An attacker who plants a known session ID in the victim's browser pre-login retains access after the victim authenticates.",
				Evidence:   "Pre-auth and post-auth Set-Cookie values match: " + truncate(cookie1, 60),
				RawRequest: rawReq, RawResponse: rawResp,
			})
		})
	}
}

func probeResetEntropy(ctx context.Context, client *http.Client, cfg Config, opts *shared.HTTPOptions, emit func(func(*URLResult))) {
	if len(cfg.Usernames) == 0 {
		return
	}
	// Request password reset for each user; collect tokens emitted in
	// the Location header / Set-Cookie / response body.
	var tokens []string
	for _, user := range cfg.Usernames[:min(3, len(cfg.Usernames))] {
		form := url.Values{}
		form.Set("email", user)
		form.Set(cfg.UserField, user)
		req, _ := http.NewRequestWithContext(ctx, "POST", cfg.ResetURL, strings.NewReader(form.Encode()))
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		if opts != nil {
			opts.ApplyTo(req)
		}
		resp, err := client.Do(req)
		if err != nil {
			continue
		}
		bb, _ := io.ReadAll(io.LimitReader(resp.Body, 64*1024))
		resp.Body.Close()
		body := string(bb)
		if t := extractToken(body); t != "" {
			tokens = append(tokens, t)
		}
		if loc := resp.Header.Get("Location"); loc != "" {
			if t := extractToken(loc); t != "" {
				tokens = append(tokens, t)
			}
		}
	}
	if len(tokens) < 2 {
		return
	}
	// Heuristic: tokens shorter than 10 chars OR with shared prefix > 50% → weak.
	avgLen := 0
	for _, t := range tokens {
		avgLen += len(t)
	}
	avgLen /= len(tokens)
	commonPrefix := lcp(tokens)
	if avgLen < 10 {
		emit(func(u *URLResult) {
			u.Findings = append(u.Findings, Finding{
				Severity: "HIGH", Title: "Weak password-reset tokens (short)",
				Detail:   fmt.Sprintf("Captured tokens average %d chars — too short to resist brute force.", avgLen),
				Evidence: strings.Join(tokens, " · "),
			})
		})
	} else if len(commonPrefix) > avgLen/2 {
		emit(func(u *URLResult) {
			u.Findings = append(u.Findings, Finding{
				Severity: "HIGH", Title: "Weak password-reset tokens (low entropy)",
				Detail:   fmt.Sprintf("Captured tokens share a %d-char common prefix — likely include timestamp / sequential counter.", len(commonPrefix)),
				Evidence: strings.Join(tokens, " · "),
			})
		})
	}
}

// tryLogin posts a login form and returns status, body length, body, raw req, raw resp.
func tryLogin(ctx context.Context, client *http.Client, cfg Config, user, pass string, opts *shared.HTTPOptions) (int, int, string, string, string) {
	// Audit MEDIUM fix: allow JSON login bodies (SPA / API / SSO stacks
	// answer 400/415 to a form POST). Body encoding is chosen by
	// cfg.BodyEncoding; the JSON path renders cfg.JSONTemplate with the
	// {USER} / {PASS} placeholders, using json.Marshal to escape the
	// values so any quotes / control chars in a credential can't produce
	// a malformed body.
	var (
		bodyStr     string
		contentType = "application/x-www-form-urlencoded"
	)
	if strings.EqualFold(cfg.BodyEncoding, "json") {
		tmpl := cfg.JSONTemplate
		if strings.TrimSpace(tmpl) == "" {
			tmpl = `{"username":"{USER}","password":"{PASS}"}`
		}
		bodyStr = strings.NewReplacer(
			"{USER}", jsonEscape(user),
			"{PASS}", jsonEscape(pass),
		).Replace(tmpl)
		contentType = "application/json"
	} else {
		form := url.Values{}
		form.Set(cfg.UserField, user)
		form.Set(cfg.PassField, pass)
		for k, v := range cfg.ExtraFields {
			form.Set(k, v)
		}
		bodyStr = form.Encode()
	}
	method := cfg.Method
	if method == "" {
		method = "POST"
	}
	req, err := http.NewRequestWithContext(ctx, method, cfg.LoginURL, strings.NewReader(bodyStr))
	if err != nil {
		return 0, 0, "", "", ""
	}
	req.Header.Set("Content-Type", contentType)
	req.Header.Set("User-Agent", "Mozilla/5.0 scaNNer/Auth")
	if opts != nil {
		opts.ApplyTo(req)
	}
	rawReq := shared.CaptureRequest(req)
	// Audit MEDIUM fix: CaptureRequest redacts secret HEADERS but the
	// login form body still carries the plaintext password verbatim.
	// Scrub the pass field out of the body before the dump is stored in
	// Finding.RawRequest → scans.result JSON / exports / UI. JSON-encoded
	// bodies need their own field-aware scrub since form parsing can't
	// touch them.
	if strings.EqualFold(cfg.BodyEncoding, "json") {
		rawReq = redactJSONBody(rawReq, cfg.PassField, pass)
	} else {
		rawReq = redactFormBody(rawReq, cfg.PassField)
	}
	resp, err := client.Do(req)
	if err != nil {
		if opts != nil {
			opts.RecordError(shared.ClassifyError(err))
		}
		return 0, 0, "", rawReq, ""
	}
	rawResp := shared.CaptureResponse(resp)
	bb, _ := io.ReadAll(io.LimitReader(resp.Body, 256*1024))
	resp.Body.Close()
	return resp.StatusCode, len(bb), string(bb), rawReq, rawResp
}

func extractSessionCookie(resp *http.Response) string {
	for _, c := range resp.Cookies() {
		ln := strings.ToLower(c.Name)
		if strings.Contains(ln, "sess") || strings.Contains(ln, "sid") || strings.Contains(ln, "auth") || strings.Contains(ln, "token") {
			return c.Name + "=" + c.Value
		}
	}
	if len(resp.Cookies()) > 0 {
		c := resp.Cookies()[0]
		return c.Name + "=" + c.Value
	}
	return ""
}

func inferFailMarker(body string) string {
	for _, candidate := range []string{
		"invalid credentials", "incorrect password", "login failed",
		"hatalı", "geçersiz", "wrong username", "user not found",
	} {
		if strings.Contains(strings.ToLower(body), candidate) {
			return candidate
		}
	}
	return ""
}

func extractToken(s string) string {
	// Very heuristic: prefer last token-like value after `=` or `/`.
	for _, sep := range []string{"token=", "code=", "key=", "/reset/", "/confirm/"} {
		if i := strings.Index(s, sep); i >= 0 {
			rest := s[i+len(sep):]
			end := strings.IndexAny(rest, "&\"' \r\n\t<>")
			if end == -1 {
				end = len(rest)
			}
			if end > 4 {
				return rest[:end]
			}
		}
	}
	return ""
}

func lcp(strs []string) string {
	if len(strs) == 0 {
		return ""
	}
	min := strs[0]
	for _, s := range strs[1:] {
		i := 0
		for i < len(min) && i < len(s) && min[i] == s[i] {
			i++
		}
		min = min[:i]
		if min == "" {
			break
		}
	}
	return min
}

func newClient(timeout time.Duration, opts *shared.HTTPOptions) *http.Client {
	transport := &http.Transport{
		TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
		DialContext:     shared.BoundDialer(nil, timeout).DialContext,
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

// credentialPair is one (username, password) tuple in the attack sequence.
type credentialPair struct {
	User string
	Pass string
}

// maxAttackPairs is a hard ceiling on the in-memory attempt sequence to
// prevent scanner OOM from an extreme list × list combination. With the
// handler-level cap at 5000 entries per list, a ClusterBomb at the limit
// would otherwise pre-allocate 25M credentialPair structs (~600 MB).
// Audit MEDIUM fix: clamp the pre-alloc; if cfg.MaxAttempts is set
// lower, Scan() further trims the slice to honor the explicit cap.
const maxAttackPairs = 1_000_000

// clampPairCount returns the capacity to pre-allocate, never exceeding
// maxAttackPairs. Callers still append within their inner loops, so the
// returned value is purely an allocation hint.
func clampPairCount(n int) int {
	if n < 0 {
		return 0
	}
	if n > maxAttackPairs {
		return maxAttackPairs
	}
	return n
}

// buildAttackPairs materializes the attack sequence per the selected
// AttackMode. Each mode owns a distinct iteration pattern — see the
// AttackMode constant docs for the rationale of each.
func buildAttackPairs(cfg Config) []credentialPair {
	users := cfg.Usernames
	passes := cfg.Passwords
	if len(users) == 0 && len(passes) == 0 {
		return nil
	}
	switch cfg.Mode {

	case ModeBatteringRam:
		// Same value goes into BOTH slots. Source = the longer of the two
		// lists, then dedup.
		src := users
		if len(passes) > len(src) {
			src = passes
		}
		seen := map[string]bool{}
		out := make([]credentialPair, 0, len(src))
		for _, v := range src {
			if seen[v] {
				continue
			}
			seen[v] = true
			out = append(out, credentialPair{User: v, Pass: v})
		}
		return out

	case ModePitchfork:
		// Zip — usernames[i] with passwords[i]. Stops at the shorter list.
		n := len(users)
		if len(passes) < n {
			n = len(passes)
		}
		out := make([]credentialPair, 0, n)
		for i := 0; i < n; i++ {
			out = append(out, credentialPair{User: users[i], Pass: passes[i]})
		}
		return out

	case ModeSniper:
		// One field varies, the other stays fixed. SniperField picks
		// which one varies.
		field := cfg.SniperField
		if field == "" {
			field = "password"
		}
		if field == "username" {
			// Each username × the FIRST password (fixed). Mostly used
			// for reverse-spray ("which accounts accept admin123?").
			if len(passes) == 0 {
				return nil
			}
			fixedPass := passes[0]
			out := make([]credentialPair, 0, len(users))
			for _, u := range users {
				out = append(out, credentialPair{User: u, Pass: fixedPass})
			}
			return out
		}
		// password sniper — fixed user × every password (classic brute).
		if len(users) == 0 {
			return nil
		}
		fixedUser := users[0]
		out := make([]credentialPair, 0, len(passes))
		for _, p := range passes {
			out = append(out, credentialPair{User: fixedUser, Pass: p})
		}
		return out

	case ModePasswordSpray:
		// For EACH password, try EVERY user before moving to the next
		// password. This produces a sequence where every individual user
		// only sees N attempts spaced across the entire run — minimizing
		// lockout-policy triggering.
		out := make([]credentialPair, 0, clampPairCount(len(users)*len(passes)))
		for _, p := range passes {
			for _, u := range users {
				if len(out) >= maxAttackPairs {
					return out
				}
				out = append(out, credentialPair{User: u, Pass: p})
			}
		}
		return out

	default:
		// Cluster Bomb (and unset Mode) — full cartesian, per-user inner
		// loop. This is the historical default.
		out := make([]credentialPair, 0, clampPairCount(len(users)*len(passes)))
		for _, u := range users {
			for _, p := range passes {
				if len(out) >= maxAttackPairs {
					return out
				}
				out = append(out, credentialPair{User: u, Pass: p})
			}
		}
		return out
	}
}

func nanoID() string { return fmt.Sprintf("%x", time.Now().UnixNano()) }
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
