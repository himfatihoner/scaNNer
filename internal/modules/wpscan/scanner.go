package wpscan

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"regexp"
	"scanner/internal/modules/shared"
	"strings"
	"sync"
	"time"
)

// Default knobs for the per-scan Config. These mirror the values that used
// to be hard-coded inside ScanWithSpeed / runWPScan. Callers (handler,
// advancedweb) may override them via Config but the defaults stay backward-
// compatible with the previous behaviour.
const (
	defaultMaxConcurrent = 2  // wpscan processes in flight at once
	defaultMaxThreads    = 30 // wpscan --max-threads value per process
)

// Speed controls how aggressively wpscan probes plugin/theme paths.
//
//	"fast"       → passive detection only — equivalent to a bare `wpscan --url X`
//	               (~15-60s/site). Misses plugins that don't show in HTML.
//	"normal"     → mixed plugin detection + vulnerable plugin/theme enum
//	               (~5-15min/site). Default of older builds.
//	"aggressive" → full enum (vp,vt,cb,dbe) + mixed detection
//	               (30-60min+/site). What we used to do unconditionally.
type Speed string

const (
	SpeedFast       Speed = "fast"
	SpeedNormal     Speed = "normal"
	SpeedAggressive Speed = "aggressive"
)

// updateMu serialises `wpscan --update` so concurrent scans don't all race
// each other into running the update at the same time. updatedAt records when
// the last *successful* update finished; if the last attempt was successful
// and recent (<24h ago) we skip re-running.
//
// Audit fix (was sync.Once): the previous implementation cached the very first
// attempt's error for the entire process lifetime. A cancel that fired before
// the update started would poison every subsequent scan with "context
// canceled" — and a transient network failure during the first update would
// be replayed as the same error forever. Now: errors are returned directly
// (never cached), and a successful update is cached for 24h to avoid the
// redundant cost.
var (
	updateMu  sync.Mutex
	updatedAt time.Time
)

const dbUpdateCacheTTL = 24 * time.Hour

// ensureDBUpdated runs `wpscan --update` lazily. If a recent successful update
// is cached, returns nil immediately. Otherwise re-attempts. Errors are not
// cached — every scan re-evaluates on the next call. Safe under concurrency.
func ensureDBUpdated(ctx context.Context, log func(string)) error {
	// Audit B61: bail out if the user already cancelled the scan before we
	// even reached the (slow) `wpscan --update` step. Returned directly,
	// never cached, so a cancelled scan can't poison future scans.
	if ctx != nil && ctx.Err() != nil {
		return ctx.Err()
	}
	updateMu.Lock()
	defer updateMu.Unlock()
	// Another scan may have just finished a successful update while we
	// were waiting on the mutex — re-check under the lock.
	if !updatedAt.IsZero() && time.Since(updatedAt) < dbUpdateCacheTTL {
		return nil
	}
	if ctx != nil && ctx.Err() != nil {
		return ctx.Err()
	}
	updateArgs := []string{"--update", "--no-banner"}
	if log != nil {
		log("WPScan: updating local vulnerability database (wpscan --update)")
		log("$ " + shared.FormatCommand("wpscan", updateArgs))
	}
	cmd := shared.Command(ctx, "wpscan", updateArgs...)
	out, err := cmd.CombinedOutput()
	if err != nil {
		// Don't cache the error — a transient failure (network blip,
		// killswitch flicker, cancel) must not poison future scans.
		return fmt.Errorf("wpscan --update failed: %w (output: %s)", err, strings.TrimSpace(string(out)))
	}
	updatedAt = time.Now()
	return nil
}

// looksStale checks if wpscan output contains the stale-database warning that
// otherwise stalls or silently degrades the scan.
func looksStale(output []byte) bool {
	s := strings.ToLower(string(output))
	return strings.Contains(s, "not updated the database") ||
		strings.Contains(s, "database is outdated") ||
		strings.Contains(s, "you may want to update")
}

// looks429 detects the WPScan vulnerability database API rate-limit
// rejection (audit B72). wpscan's CLI surfaces it in two flavors —
// HTTP 429 in the raw JSON error and a sentence in the banner — so
// match both.
func looks429(output []byte) bool {
	s := strings.ToLower(string(output))
	return strings.Contains(s, "http 429") ||
		strings.Contains(s, "api limit has been reached") ||
		strings.Contains(s, "too many requests")
}

// abortStatus maps a hint message to one of the canonical Status values.
func abortStatus(hint string) string {
	low := strings.ToLower(hint)
	switch {
	case strings.Contains(low, "wordpress"):
		return "not_wordpress"
	case strings.Contains(low, "down") ||
		strings.Contains(low, "connect") ||
		strings.Contains(low, "dns") ||
		strings.Contains(low, "access") ||
		strings.Contains(low, "invalid"):
		return "unreachable"
	}
	return "error"
}

// detectAbortHint scans wpscan's raw output for unreachable / not-WordPress
// signals that surface as plain text (sometimes before any JSON is emitted).
// Returns the matched message or empty string.
func detectAbortHint(raw string) string {
	low := strings.ToLower(raw)
	patterns := []struct {
		marker  string
		message string
	}{
		{"does not seem to be running wordpress", "The remote site does not appear to be running WordPress"},
		{"not running wordpress", "Target is not running WordPress"},
		{"the wordpress version could not be detected", "WordPress detected but version unreadable"},
		{"target seems to be down", "Target seems to be down"},
		{"could not connect", "Could not connect to target"},
		{"connection refused", "Connection refused by target"},
		{"name or service not known", "DNS resolution failed for target"},
		{"unable to access", "Unable to access target"},
		{"url supplied seems to be invalid", "The supplied URL appears invalid"},
		{"the remote website is up, but does not seem to be running wordpress", "Target is reachable but is not running WordPress"},
	}
	for _, p := range patterns {
		if strings.Contains(low, p.marker) {
			return p.message
		}
	}
	return ""
}

// setWPScanParseError populates tr.Error + tr.Status when wpscan produced
// output we couldn't parse as JSON (non-zero exit with a raw message, an
// unsupported flag, a missing binary that still wrote to stderr, etc.). It
// checks, in order: an unreachable/not-WordPress abort hint; the shared
// tool-error catalog (which recognises missing binaries, API rate-limits and
// "flag provided but not defined"); and finally the first non-empty line of
// wpscan's own output — so a version/flag drift ("invalid option: --foo")
// stays visible instead of being flattened to a generic "Failed to parse"
// message. Always sets a non-empty Status so the results card renders the
// "Scan failed" branch (an Error with no Status renders an empty card body).
func setWPScanParseError(tr *TargetResult, output string) {
	if hint := detectAbortHint(output); hint != "" {
		tr.Error = hint
		tr.Status = abortStatus(hint)
		return
	}
	if friendly, ok := shared.TranslateToolError(output); ok {
		tr.Error = friendly
		tr.Status = "error"
		return
	}
	if line := firstNonEmptyLine(output); line != "" {
		tr.Error = "Failed to parse WPScan output: " + line
	} else {
		tr.Error = "Failed to parse WPScan output"
	}
	tr.Status = "error"
}

// firstNonEmptyLine returns the first non-blank line of s, trimmed and capped
// to ~180 chars so a noisy wpscan dump can't bloat the result blob. wpscan
// stderr rarely carries credentials, but the length cap bounds it regardless.
func firstNonEmptyLine(s string) string {
	for _, line := range strings.Split(s, "\n") {
		if line = strings.TrimSpace(line); line != "" {
			if len(line) > 180 {
				line = line[:180] + "…"
			}
			return line
		}
	}
	return ""
}

// --- WPScan JSON output structs ---

type RawOutput struct {
	Banner       map[string]interface{} `json:"banner"`
	TargetURL    string                 `json:"target_url"`
	EffectiveURL string                 `json:"effective_url"`
	Interesting  []RawInteresting       `json:"interesting_findings"`
	Version      *RawVersion            `json:"version"`
	MainTheme    *RawTheme              `json:"main_theme"`
	Plugins      map[string]*RawPlugin  `json:"plugins"`
	Vulns        []RawVuln              `json:"vulnerabilities"`
	StopReason   string                 `json:"stop_reason"`
	ScanAborted  string                 `json:"scan_aborted"`
}

type RawInteresting struct {
	URL                string   `json:"url"`
	Type               string   `json:"type"`
	ToS                string   `json:"to_s"`
	References         RawRefs  `json:"references"`
	InterestingEntries []string `json:"interesting_entries"`
}

type RawVersion struct {
	Number          string    `json:"number"`
	Status          string    `json:"status"`
	Confidence      int       `json:"confidence"`
	Vulnerabilities []RawVuln `json:"vulnerabilities"`
}

type RawTheme struct {
	Slug            string      `json:"slug"`
	Location        string      `json:"location"`
	LatestVersion   string      `json:"latest_version"`
	LastUpdated     string      `json:"last_updated"`
	Version         *RawItemVer `json:"version"`
	Vulnerabilities []RawVuln   `json:"vulnerabilities"`
}

type RawPlugin struct {
	Slug            string      `json:"slug"`
	Location        string      `json:"location"`
	LatestVersion   string      `json:"latest_version"`
	LastUpdated     string      `json:"last_updated"`
	Version         *RawItemVer `json:"version"`
	Vulnerabilities []RawVuln   `json:"vulnerabilities"`
}

type RawItemVer struct {
	Number     string `json:"number"`
	Confidence int    `json:"confidence"`
}

type RawVuln struct {
	Title       string  `json:"title"`
	Description string  `json:"description"`
	FixedIn     string  `json:"fixed_in"`
	References  RawRefs `json:"references"`
}

type RawRefs struct {
	CVE       []string `json:"cve"`
	WPVDB     []string `json:"wpvdb"`
	URL       []string `json:"url"`
	ExploitDB []string `json:"exploitdb"`
}

// --- Cleaned result structs ---

type Finding struct {
	Severity    string   `json:"severity"` // CRITICAL, HIGH, MEDIUM, LOW, INFO
	Category    string   `json:"category"` // core, plugin, theme, config, info
	Title       string   `json:"title"`
	Description string   `json:"description"`
	CVEs        []string `json:"cves"`
	References  []string `json:"references"`
	FixedIn     string   `json:"fixed_in,omitempty"`
}

type TargetResult struct {
	URL          string    `json:"url"`
	EffectiveURL string    `json:"effective_url"`
	WPVersion    string    `json:"wp_version"`
	WPStatus     string    `json:"wp_status"`
	Theme        string    `json:"theme"`
	PluginCount  int       `json:"plugin_count"`
	Findings     []Finding `json:"findings"`
	Error        string    `json:"error,omitempty"`

	// Status flags so the UI can distinguish "unreachable" / "not WordPress"
	// from "scanned cleanly with no findings".
	Reachable   bool   `json:"reachable"`
	IsWordPress bool   `json:"is_wordpress"`
	Status      string `json:"status"` // "unreachable" | "not_wordpress" | "scanned" | "error"
}

// wpscanOutputCap bounds the wpscan subprocess output the module keeps in
// memory. Audit fix: wpscan with aggressive enumeration can emit tens of
// megabytes of JSON per target (heavily-modded sites); with two processes
// running concurrently that peaks at hundreds of MB of resident buffer per
// scan, and previously every target's full output was ALSO copied into
// TargetResult.RawJSON so it hit the 50MB result blob cap and got dropped
// wholesale. We cap the buffer here; anything larger is truncated and the
// truncated bytes are silently discarded (wpscan's JSON is emitted at the
// end of the run so if truncation triggers we can't parse it — that's a
// hard error).
const wpscanOutputCap = 32 * 1024 * 1024 // 32 MiB per invocation

type ScanResult struct {
	Results []TargetResult `json:"results"`
}

type ProgressFunc func(done int, msg string)

// PartialFunc receives in-progress snapshots of the result as each target
// finishes. The handler buffers and flushes at most one snapshot every ~2s,
// so the UI doesn't blank out during aggressive multi-host runs (which can
// take 30–60min/site).
type PartialFunc func(*ScanResult)

// HTTPParams carries the per-scan HTTP knobs that wpscan supports natively.
// The handler builds this from Settings (proxy / UA) + per-scan form fields
// (cookie string, http-auth, custom headers) so auth-gated WP sites can be
// scanned end-to-end. Empty fields are skipped on the wpscan command line.
type HTTPParams struct {
	Proxy        string   // e.g. http://127.0.0.1:8080
	UserAgent    string   // when empty, wpscan's --random-user-agent is used
	CookieString string   // e.g. wordpress_logged_in_xxx=...; foo=bar
	HTTPAuth     string   // user:pass for basic-auth gated sites
	Headers      []string // each entry is "Name: Value" (one --headers flag per entry)
}

// Config bundles every per-scan knob into a single immutable value that
// flows from the handler into runWPScan. The previous design used a
// package-level `var APIToken` that two concurrent scans mutated under
// race; that's gone now — the token lives on Config and stays scoped to
// one scan's goroutines.
type Config struct {
	URLs          []string
	Speed         Speed
	APIToken      string // WPVulnDB token (passed via WPSCAN_API_TOKEN env, never argv)
	HTTPParams    HTTPParams
	MaxConcurrent int // 0 → defaultMaxConcurrent
	MaxThreads    int // 0 → defaultMaxThreads
	// Opts carries the scan's HTTPOptions for the reachability preflight (wpscan
	// itself shells out). nil is safe — preflight is skipped.
	Opts *shared.HTTPOptions
}

func Scan(ctx context.Context, urls []string, progress ProgressFunc) *ScanResult {
	return ScanWithSpeed(ctx, urls, SpeedFast, progress, nil)
}

// ScanWithSpeed is the legacy entry point retained for callers that don't
// thread a Config yet (advancedweb). It uses zero defaults for token and
// HTTP params.
func ScanWithSpeed(ctx context.Context, urls []string, speed Speed, progress ProgressFunc, partial PartialFunc) *ScanResult {
	return ScanWithConfig(ctx, Config{URLs: urls, Speed: speed}, progress, partial)
}

// ScanWithToken is the prior explicit-token entry kept as a thin shim so
// callers (and any out-of-tree users) keep compiling. New code should
// build a Config directly.
func ScanWithToken(ctx context.Context, urls []string, speed Speed, token string, httpParams HTTPParams, progress ProgressFunc, partial PartialFunc) *ScanResult {
	return ScanWithConfig(ctx, Config{
		URLs:       urls,
		Speed:      speed,
		APIToken:   token,
		HTTPParams: httpParams,
	}, progress, partial)
}

// ScanWithConfig is the canonical entry point. Everything per-scan lives
// on cfg so concurrent scans can't bleed state into each other.
func ScanWithConfig(ctx context.Context, cfg Config, progress ProgressFunc, partial PartialFunc) *ScanResult {
	if ctx == nil {
		ctx = context.Background()
	}
	maxConcurrent := cfg.MaxConcurrent
	if maxConcurrent <= 0 {
		maxConcurrent = defaultMaxConcurrent
	}
	maxThreads := cfg.MaxThreads
	if maxThreads <= 0 {
		maxThreads = defaultMaxThreads
	}
	result := &ScanResult{}
	var mu sync.Mutex
	sem := make(chan struct{}, maxConcurrent)
	var wg sync.WaitGroup
	done := 0

	logFn := func(msg string) {
		mu.Lock()
		defer mu.Unlock()
		if progress != nil {
			progress(done, msg)
		}
	}

	// Reachability preflight: skip TLS-dead targets before spawning wpscan.
	if cfg.Opts != nil && cfg.Opts.PreflightEnabled {
		live, dead := shared.FilterReachable(ctx, cfg.Opts, cfg.URLs, cfg.Opts.PreflightTimeout, maxConcurrent)
		for t, reason := range dead {
			result.Results = append(result.Results, TargetResult{URL: t, Status: "unreachable", Error: "unreachable — " + reason})
		}
		cfg.URLs = live
	}

	for _, u := range cfg.URLs {
		if ctx.Err() != nil {
			break
		}
		wg.Add(1)
		sem <- struct{}{}
		go func(target string) {
			defer wg.Done()
			defer func() { <-sem }()

			if ctx.Err() != nil {
				return
			}

			mu.Lock()
			if progress != nil {
				progress(done, fmt.Sprintf("Scanning %s ...", target))
			}
			mu.Unlock()

			tr := runWPScan(ctx, target, cfg.Speed, cfg.APIToken, cfg.HTTPParams, maxThreads, logFn)

			mu.Lock()
			done++
			result.Results = append(result.Results, *tr)
			if progress != nil {
				progress(done, fmt.Sprintf("[%d/%d] Completed %s — %d findings", done, len(cfg.URLs), target, len(tr.Findings)))
			}
			// Emit a partial snapshot while holding the lock so the
			// handler can marshal it without racing the next append.
			// The handler's 2s throttle keeps this cheap even under N
			// fast-completing targets.
			if partial != nil {
				snap := ScanResult{Results: append([]TargetResult(nil), result.Results...)}
				partial(&snap)
			}
			mu.Unlock()
		}(u)
	}
	wg.Wait()
	return result
}

func runWPScan(ctx context.Context, target string, speed Speed, apiToken string, httpParams HTTPParams, maxThreads int, log func(string)) *TargetResult {
	tr := &TargetResult{URL: target}

	// Default to https:// — modern WordPress installs are HSTS-enforced
	// and http:// either gets a 301 (wasted RT) or a flat connection
	// refused on hosts that don't bind :80 at all. Users who actually
	// want http:// can paste the full URL.
	if !strings.HasPrefix(target, "http://") && !strings.HasPrefix(target, "https://") {
		target = "https://" + target
		tr.URL = target
	}

	if maxThreads <= 0 {
		maxThreads = defaultMaxThreads
	}

	// Base args — same across speeds.
	args := []string{
		"--url", target,
		"--format", "json",
		"--no-banner",
		// Scan targets routinely have invalid/self-signed/expired certs — wpscan
		// verifies TLS by default and aborts on a bad cert, so disable the check
		// (curl -k semantics) or the whole scan fails on a cert problem.
		"--disable-tls-checks",
		"--max-threads", fmt.Sprintf("%d", maxThreads),
		"--request-timeout", "30",
		"--connect-timeout", "10",
	}

	// Per-scan HTTP knobs. When the user supplies a UA we use it verbatim
	// (drop --random-user-agent so wpscan doesn't override). Otherwise keep
	// the random UA to dodge naive WAF fingerprinting.
	if ua := strings.TrimSpace(httpParams.UserAgent); ua != "" {
		args = append(args, "--user-agent", ua)
	} else {
		args = append(args, "--random-user-agent")
	}
	if px := strings.TrimSpace(httpParams.Proxy); px != "" {
		args = append(args, "--proxy", px)
	}
	if cs := strings.TrimSpace(httpParams.CookieString); cs != "" {
		args = append(args, "--cookie-string", cs)
	}
	if ha := strings.TrimSpace(httpParams.HTTPAuth); ha != "" {
		args = append(args, "--http-auth", ha)
	}
	for _, hdr := range httpParams.Headers {
		hdr = strings.TrimSpace(hdr)
		if hdr != "" {
			args = append(args, "--headers", hdr)
		}
	}

	// Speed-specific args. Fast mirrors `wpscan --url X` defaults so it stays
	// in the 15-60s ballpark; Normal does targeted vuln enum; Aggressive is
	// the old behavior.
	switch speed {
	case SpeedAggressive:
		// Most aggressive: everything wpscan exposes, with aggressive HTTP
		// probing for both plugin discovery and version detection.
		//   ap  = all plugins · at = all themes · cb = config backups
		//   dbe = db exports · u  = user enum   · tt = timthumbs · m = media IDs
		args = append(args,
			"--enumerate", "ap,at,cb,dbe,u,tt,m",
			"--plugins-detection", "aggressive",
			"--plugins-version-detection", "aggressive",
		)
	case SpeedNormal:
		// More aggressive than mode 1: adds themes + db exports, switches
		// plugin discovery from passive to mixed (parses HTML AND probes
		// known plugin paths).
		args = append(args,
			"--enumerate", "ap,at,cb,dbe,u",
			"--plugins-detection", "mixed",
		)
	default: // SpeedFast — wpscan's defaults + user enumeration.
		// `wpscan --url X --api-token Y` already uses --enumerate ap,cb and
		// --plugins-detection passive by default, so we only add `u` to pull
		// in user enumeration alongside the defaults.
		args = append(args,
			"--enumerate", "ap,cb,u",
			"--plugins-detection", "passive",
		)
	}

	// Per-scan token — passed via env (WPSCAN_API_TOKEN) instead of the
	// command line so it doesn't show up in `ps -ef` / /proc/<pid>/cmdline
	// on shared pentest boxes, nor in any progress crumb that logs argv.
	// wpscan's cli_options.rb accepts this env name natively.
	tok := strings.TrimSpace(apiToken)

	runOnce := func() ([]byte, error) {
		// Surface the exact command as a console crumb (the WPVulnDB API
		// token is passed via the WPSCAN_API_TOKEN env, not argv, so it
		// never appears here; --http-auth / --cookie-string values are
		// masked by redactWPScanArgs).
		if log != nil {
			log("$ " + shared.FormatCommand("wpscan", redactWPScanArgs(args)))
		}
		// Audit B63: CommandContext binds the subprocess to ctx, so a
		// cancel propagates SIGKILL to the wpscan child automatically.
		// A scan-restart cancels the old scan's ctx (handled by
		// ScanManager), which terminates any in-flight wpscan within
		// ~50 ms. No additional explicit Process.Kill goroutine
		// needed — Go's exec package already does this internally.
		cmd := shared.Command(ctx, "wpscan", args...)
		if tok != "" {
			cmd.Env = append(os.Environ(), "WPSCAN_API_TOKEN="+tok)
		}
		// Audit fix: cap stdout+stderr to wpscanOutputCap so a runaway
		// wpscan run on a heavily-modded site can't OOM the scanner
		// (previously CombinedOutput() would happily buffer arbitrary
		// bytes). Both streams share the same capped buffer, which
		// mirrors CombinedOutput's merge semantics.
		buf := &cappedBuffer{cap: wpscanOutputCap}
		cmd.Stdout = buf
		cmd.Stderr = buf
		err := cmd.Run()
		if buf.truncated {
			// Preserve the truncated bytes but flag the error so the
			// parser fallback knows we won't have valid JSON.
			return buf.buf.Bytes(), fmt.Errorf("wpscan output exceeded %d bytes cap (truncated): %w", wpscanOutputCap, err)
		}
		return buf.buf.Bytes(), err
	}

	output, err := runOnce()

	// Stale local DB: wpscan prepends a non-JSON warning that breaks parsing
	// and skips checks. Update once per process and retry this target.
	if looksStale(output) {
		if log != nil {
			log("WPScan database is stale — refreshing before retrying " + target)
		}
		if upErr := ensureDBUpdated(ctx, log); upErr != nil {
			tr.Error = upErr.Error()
			// Any non-empty Error must carry a Status or the results card
			// renders an empty body (no "Scan failed" branch fires) and the
			// reason is silently swallowed — the bug we're eliminating.
			tr.Status = "error"
			return tr
		}
		output, err = runOnce()
	}

	// HTTP 429 backoff (audit B72). wpscan.com's API rate-limits free
	// tokens after ~25 requests / 24 h. Without backoff the rest of the
	// target list is hammered uselessly with the same rejection. Detect
	// the 429 marker in the output, pause once, then retry.
	if looks429(output) {
		if log != nil {
			log("WPScan API hit rate-limit — backing off for 60s before retrying " + target)
		}
		select {
		case <-time.After(60 * time.Second):
		case <-ctx.Done():
			tr.Error = "cancelled while backing off WPScan API"
			tr.Status = "error"
			return tr
		}
		output, err = runOnce()
	}

	// wpscan exits non-zero when vulnerabilities found — that's OK
	// Only fail if we can't parse the output
	if len(output) == 0 && err != nil {
		if hint := detectAbortHint(err.Error()); hint != "" {
			tr.Error = hint
			tr.Status = abortStatus(hint)
		} else if friendly, ok := shared.TranslateToolError(err.Error()); ok {
			// Missing wpscan binary ("executable file not found"), an
			// unsupported flag ("flag provided but not defined"), or a TLS /
			// network failure — surface the catalog's actionable reason
			// instead of a bare "WPScan execution failed: exec: …".
			tr.Error = friendly
			tr.Status = "error"
		} else {
			tr.Error = fmt.Sprintf("WPScan execution failed: %v", err)
			tr.Status = "error"
		}
		return tr
	}

	// Audit fix: no longer stash the full wpscan JSON on the TargetResult.
	// The RawJSON field was never referenced by any handler/template but
	// each per-target copy could easily push the whole ScanResult past
	// the 50 MB result blob cap, causing the entire scan to be dropped.
	// Debugging can rely on the `$ wpscan …` command crumb + the parsed
	// findings instead.

	var raw RawOutput
	if err := json.Unmarshal(output, &raw); err != nil {
		// Try to find JSON in output (wpscan sometimes prints text before JSON)
		jsonStart := strings.Index(string(output), "{")
		if jsonStart > 0 {
			if err2 := json.Unmarshal(output[jsonStart:], &raw); err2 != nil {
				setWPScanParseError(tr, string(output))
				return tr
			}
		} else {
			setWPScanParseError(tr, string(output))
			return tr
		}
	}

	tr.EffectiveURL = raw.EffectiveURL

	// Detect "site unreachable" / "not WordPress" — wpscan signals these via
	// scan_aborted (or a stop_reason / textual marker in stderr-prefixed output).
	abortReason := strings.TrimSpace(raw.ScanAborted)
	if abortReason == "" && raw.StopReason != "" && !strings.EqualFold(raw.StopReason, "finished") {
		abortReason = raw.StopReason
	}
	if abortReason == "" {
		// Fallback to text matches in raw output (covers cases where wpscan
		// printed the message before any JSON was emitted).
		abortReason = detectAbortHint(string(output))
	}
	if abortReason != "" {
		tr.Error = abortReason
		low := strings.ToLower(abortReason)
		switch {
		case strings.Contains(low, "not running wordpress") ||
			strings.Contains(low, "does not seem to be running wordpress") ||
			strings.Contains(low, "not detected wordpress"):
			tr.Status = "not_wordpress"
		case strings.Contains(low, "seems to be down") ||
			strings.Contains(low, "site is offline") ||
			strings.Contains(low, "could not connect") ||
			strings.Contains(low, "name or service not known") ||
			strings.Contains(low, "unable to access") ||
			strings.Contains(low, "url supplied seems to be invalid"):
			tr.Status = "unreachable"
		default:
			tr.Status = "error"
		}
		// No usable scan happened — bail before populating WP-specific fields.
		return tr
	}

	// At this point wpscan completed and confirmed WordPress was detected.
	tr.Reachable = true
	tr.IsWordPress = true
	tr.Status = "scanned"

	// WordPress version
	if raw.Version != nil {
		tr.WPVersion = raw.Version.Number
		tr.WPStatus = raw.Version.Status
		if raw.Version.Status == "insecure" {
			tr.Findings = append(tr.Findings, Finding{
				Severity: "HIGH", Category: "core",
				Title:       fmt.Sprintf("WordPress %s (Insecure)", raw.Version.Number),
				Description: "This WordPress version is known to be insecure",
			})
		}
		for _, v := range raw.Version.Vulnerabilities {
			tr.Findings = append(tr.Findings, vulnToFinding(v, "core"))
		}
	}

	// Theme
	if raw.MainTheme != nil {
		tr.Theme = raw.MainTheme.Slug
		if raw.MainTheme.Version != nil {
			tr.Theme += " " + raw.MainTheme.Version.Number
		}
		for _, v := range raw.MainTheme.Vulnerabilities {
			tr.Findings = append(tr.Findings, vulnToFinding(v, "theme"))
		}
	}

	// Plugins
	tr.PluginCount = len(raw.Plugins)
	for _, p := range raw.Plugins {
		for _, v := range p.Vulnerabilities {
			tr.Findings = append(tr.Findings, vulnToFinding(v, "plugin"))
		}
	}

	// Interesting findings
	for _, i := range raw.Interesting {
		tr.Findings = append(tr.Findings, Finding{
			Severity:    "INFO",
			Category:    "info",
			Title:       i.ToS,
			Description: i.URL,
			References:  i.References.URL,
		})
	}

	// Top-level vulns
	for _, v := range raw.Vulns {
		tr.Findings = append(tr.Findings, vulnToFinding(v, "core"))
	}

	return tr
}

// criticalPatternRe matches vuln titles that describe an unauthenticated /
// remotely-exploitable class of bug that has no vendor patch (yet). When
// FixedIn is empty AND the title matches, we bump severity to CRITICAL so
// the dashboard's CRITICAL branch actually fires (previously wpscan only
// ever emitted HIGH/MEDIUM, which quietly disabled the red bg-red-500/5
// section of the results template).
var criticalPatternRe = regexp.MustCompile(`(?i)\b(RCE|remote code execution|SQL ?injection|SQLi|authentication bypass|auth bypass|privilege escalation|priv esc|arbitrary file upload|unrestricted file upload|unauthenticated file upload|deserialization|command injection)\b`)

func vulnToFinding(v RawVuln, category string) Finding {
	// Baseline: unpatched = HIGH, patched = MEDIUM (updater can mitigate).
	severity := "HIGH"
	if v.FixedIn != "" {
		severity = "MEDIUM"
	} else if criticalPatternRe.MatchString(v.Title) {
		// No fix + high-impact bug class → CRITICAL.
		severity = "CRITICAL"
	}

	var cves []string
	for _, c := range v.References.CVE {
		cves = append(cves, "CVE-"+c)
	}

	var refs []string
	refs = append(refs, v.References.URL...)
	for _, w := range v.References.WPVDB {
		refs = append(refs, "https://wpscan.com/vulnerability/"+w)
	}
	for _, e := range v.References.ExploitDB {
		refs = append(refs, "https://www.exploit-db.com/exploits/"+e)
	}

	// Prefer wpscan's raw vulnerability description (populated when the
	// WPVulnDB API token is present). Fall back to the previous "Fixed
	// in: X" crumb so the UI still has something to show for free-tier
	// scans that don't include descriptions.
	desc := strings.TrimSpace(v.Description)
	if desc == "" {
		if v.FixedIn != "" {
			desc = fmt.Sprintf("Fixed in: %s", v.FixedIn)
		}
	}

	return Finding{
		Severity:    severity,
		Category:    category,
		Title:       v.Title,
		Description: desc,
		CVEs:        cves,
		References:  refs,
		FixedIn:     v.FixedIn,
	}
}

// redactWPScanArgs masks credential-bearing values in a copy of args so the
// "$ wpscan …" console crumb doesn't leak them. Currently the basic-auth
// user:pass (--http-auth) and the session token (--cookie-string) are
// replaced with ***. The real argv passed to wpscan is untouched, and the
// WPVulnDB API token never appears here at all — it travels via the
// WPSCAN_API_TOKEN env var, not the command line.
func redactWPScanArgs(args []string) []string {
	out := make([]string, len(args))
	copy(out, args)
	for i := 0; i < len(out)-1; i++ {
		switch out[i] {
		case "--http-auth", "--cookie-string":
			out[i+1] = "***"
		}
	}
	return out
}

// cappedBuffer is an io.Writer that appends to an internal bytes.Buffer up
// to `cap` bytes, then silently discards further writes and sets truncated
// to true. Used to bound wpscan's subprocess output.
type cappedBuffer struct {
	buf       bytes.Buffer
	cap       int
	truncated bool
}

func (c *cappedBuffer) Write(p []byte) (int, error) {
	remain := c.cap - c.buf.Len()
	if remain <= 0 {
		c.truncated = true
		return len(p), nil
	}
	if len(p) > remain {
		if _, err := c.buf.Write(p[:remain]); err != nil {
			return 0, err
		}
		c.truncated = true
		return len(p), nil
	}
	return c.buf.Write(p)
}

// Compile-time check that cappedBuffer satisfies io.Writer.
var _ io.Writer = (*cappedBuffer)(nil)
