package nuclei

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/url"
	"os"
	"os/exec"
	"scanner/internal/modules/shared"
	"strings"
	"sync"
	"time"
)

// rawFinding mirrors the fields nuclei emits per JSONL line that we care about.
type rawFinding struct {
	TemplateID   string   `json:"template-id"`
	TemplateURL  string   `json:"template-url"`
	TemplatePath string   `json:"template-path"`
	Type         string   `json:"type"`
	Host         string   `json:"host"`
	MatchedAt    string   `json:"matched-at"`
	ExtractedRes []string `json:"extracted-results"`
	Request      string   `json:"request"`
	Response     string   `json:"response"`
	Info         struct {
		Name           string                 `json:"name"`
		Severity       string                 `json:"severity"`
		Description    string                 `json:"description"`
		Reference      []string               `json:"reference"`
		Tags           []string               `json:"tags"`
		Author         []string               `json:"author"`
		Classification map[string]interface{} `json:"classification"`
	} `json:"info"`
	CurlCommand string `json:"curl-command"`
}

// Finding is the cleaned-up per-result row we store/render.
type Finding struct {
	TemplateID  string   `json:"template_id"`
	Name        string   `json:"name"`
	Severity    string   `json:"severity"` // critical, high, medium, low, info, unknown
	Type        string   `json:"type"`
	Host        string   `json:"host"`
	MatchedAt   string   `json:"matched_at"`
	Description string   `json:"description,omitempty"`
	Tags        []string `json:"tags,omitempty"`
	CVEs        []string `json:"cves,omitempty"`
	CWEs        []string `json:"cwes,omitempty"`
	References  []string `json:"references,omitempty"`
	Extracted   []string `json:"extracted,omitempty"`
	// Raw HTTP capture for Burp replay. Populated when the user enabled
	// "include req/resp" in the scan form (passes -include-rr-all to
	// nuclei) and nuclei was able to record the bytes.
	RawRequest  string `json:"raw_request,omitempty"`
	RawResponse string `json:"raw_response,omitempty"`
	CurlCommand string `json:"curl_command,omitempty"`
}

// TargetResult bundles findings per target URL.
type TargetResult struct {
	URL        string    `json:"url"`
	Findings   []Finding `json:"findings"`
	Error      string    `json:"error,omitempty"`
	ExitInfo   string    `json:"exit_info,omitempty"`
	TemplateCt int       `json:"template_count,omitempty"`
}

type ScanResult struct {
	Results []TargetResult `json:"results"`
	// Truncated is true when nuclei was killed by its own wall-clock cap
	// (MaxDuration) before finishing — the run is INCOMPLETE and any
	// findings are only from the URLs/templates it reached. Callers MUST
	// surface this instead of reporting a clean completion.
	Truncated bool `json:"truncated,omitempty"`
	// TruncateReason is an operator-facing explanation + remedy when
	// Truncated is true.
	TruncateReason string `json:"truncate_reason,omitempty"`
}

// defaultNucleiMaxDuration is the fallback wall-clock cap when
// ScanConfig.MaxDuration is 0. nuclei's own -timeout only bounds a single
// HTTP call, not the whole run, so this guards against a run pinning
// resources indefinitely. It is intentionally a HARD cap: a full-template
// scan (severity incl. info) over hundreds of hosts can legitimately take
// many hours and WILL hit this — which is exactly why we now report the
// truncation honestly instead of pretending the scan completed.
const defaultNucleiMaxDuration = 90 * time.Minute

// Batching: for large URL sets nuclei-over-everything-at-once routinely hits
// the single-process wall-clock cap and gets killed mid-run, leaving a
// truncated blob with almost no cleanly-attributed findings. Instead we run
// nuclei on chunks of defaultNucleiBatchSize URLs — each chunk completes on
// its own, so finished hosts have COMPLETE results and partials stream in as
// chunks land.
//
// IMPORTANT: batching runs EVERY chunk to completion — there is NO total
// wall-clock budget that could throw away scanning work. (An earlier version
// added a 4h total cap; it defeated the whole point by killing large scans
// partway through. Removed.) The only bound is a very generous PER-CHUNK
// safety cap so a single pathological batch — one hung template on one host —
// can't stall the whole run forever; when it trips, only THAT chunk is
// skipped and the run continues. nuclei's own -timeout already bounds each
// individual request, so this rarely fires.
const (
	defaultNucleiBatchSize   = 10               // chunk size once len(urls) exceeds it
	defaultNucleiPerBatchCap = 45 * time.Minute // safety cap for a SINGLE stuck chunk (skips just that chunk)
)

type ProgressFunc func(done int, msg string)
type PartialFunc func(*ScanResult)

// ScanConfig captures user-tunable parameters from the run form.
type ScanConfig struct {
	Severity         []string // critical, high, medium, low, info — nil = all
	Tags             []string // comma-separated tag filters; nil = none
	TemplateIDs      []string // optional explicit -t selectors
	ExcludeTags      []string // -exclude-tags — templates whose tags match are dropped
	ExcludeTemplates []string // -exclude-templates — template IDs/paths dropped
	RateLimit        int      // 0 = nuclei default
	Concurrency      int      // 0 = nuclei default
	BulkSize         int      // -bulk-size (hosts scanned in parallel per template); 0 = nuclei default
	BatchSize        int      // run nuclei on chunks of this many URLs; 0 = default 10 (only batches when len(urls) exceeds it)
	UpdateTemplates  bool     // run `nuclei -ut` once before scanning
	DAST             bool     // -dast — enables the fuzz/DAST template set
	AutomaticScan    bool     // -as — auto-select templates from wappalyzer stack detection
	// Opts carries the scan's HTTPOptions (killswitch binding + reachability
	// preflight settings). nuclei shells out and doesn't use opts for its own
	// requests, but the reachability preflight needs a dialer; nil is safe
	// (BoundDialer falls back to the global binding, preflight is skipped).
	Opts *shared.HTTPOptions
	// MaxDuration is the hard wall-clock cap on the nuclei subprocess. 0
	// uses the built-in default (defaultNucleiMaxDuration). When the cap
	// is hit nuclei is killed and the result is flagged Truncated so the
	// caller can report the run as INCOMPLETE rather than a clean finish.
	MaxDuration time.Duration

	// HTTP authentication / wire-level knobs surfaced via the form +
	// global Settings. Empty values mean "leave nuclei to its defaults".
	// Headers + Cookies are forwarded via repeated -H flags (cookies are
	// flattened into a single Cookie header). ProxyURL maps to nuclei
	// -proxy, UserAgent to a User-Agent header, FollowRedirects to -fr,
	// SNIHost to -sni.
	CustomHeaders   map[string]string
	Cookies         map[string]string
	ProxyURL        string
	UserAgent       string
	FollowRedirects bool
	SNIHost         string
}

// Aggressiveness levels — a single knob that maps to nuclei's throughput
// flags (rate-limit / concurrency / bulk-size). Shared by the standalone
// module handler and the advancedweb suite so both mean the same thing.
const (
	LevelPolite     = "polite"     // gentle: slow, low parallelism — fragile targets / stay-quiet
	LevelNormal     = "normal"     // balanced default (≈ nuclei's own defaults)
	LevelAggressive = "aggressive" // loud + fast: high rate + parallelism
)

// LevelSettings maps an aggressiveness level to concrete (rate-limit,
// concurrency, bulk-size) numbers. Unknown/empty = normal.
func LevelSettings(level string) (rateLimit, concurrency, bulkSize int) {
	switch level {
	case LevelPolite:
		return 25, 10, 10
	case LevelAggressive:
		return 500, 50, 50
	default: // LevelNormal
		return 150, 25, 25
	}
}

// Scan runs nuclei against each URL sequentially (nuclei itself is heavily
// concurrent internally — running multiple in parallel just thrashes disk).
// Scan now runs ONE nuclei process across the entire URL list via -l <file>
// instead of spawning a separate process per URL. nuclei is heavily parallel
// internally (default 25 worker templates × URL pool), so a single batched
// invocation is a 5-50× speedup vs the old per-URL loop. Progress is driven
// off the JSONL `host` field so the UI still updates per-target.
// Scan runs nuclei over urls. For sets larger than the batch size it splits
// them into chunks and runs one nuclei process per chunk (see the batching
// rationale on defaultNucleiBatchSize) — finished chunks yield complete
// results and stream in as partials, and no single chunk can hang the run.
// Small sets run as a single process exactly as before.
func Scan(ctx context.Context, urls []string, cfg ScanConfig, progress ProgressFunc, partial PartialFunc) *ScanResult {
	if ctx == nil {
		ctx = context.Background()
	}
	if len(urls) == 0 {
		return &ScanResult{}
	}

	// Reachability preflight: drop TLS-dead targets so nuclei never execs against
	// them (a host that resets TLS would otherwise dominate the run with errors).
	// Skipped targets become explicit "unreachable" rows in the final result.
	var deadRows []TargetResult
	if cfg.Opts != nil && cfg.Opts.PreflightEnabled {
		live, dead := shared.FilterReachable(ctx, cfg.Opts, urls, cfg.Opts.PreflightTimeout, cfg.Concurrency)
		for t, reason := range dead {
			deadRows = append(deadRows, TargetResult{URL: t, Error: "unreachable — " + reason})
		}
		urls = live
	}
	if len(urls) == 0 {
		return &ScanResult{Results: deadRows}
	}

	batchSize := cfg.BatchSize
	if batchSize <= 0 {
		batchSize = defaultNucleiBatchSize
	}
	total := len(urls)

	// Small set → single process, exact legacy behaviour (its own cfg.MaxDuration
	// or the 90m default, its own TruncateReason).
	if total <= batchSize {
		res := scanChunk(ctx, urls, cfg, progress, partial, 0, total)
		res.Results = append(deadRows, res.Results...)
		return res
	}

	// Large set → batch. NO total wall-clock budget: every chunk runs to
	// completion so a big scan is never thrown away partway through. An
	// OPTIONAL total budget applies only if the caller explicitly set
	// cfg.MaxDuration (or the parent ctx carries a deadline) — the default
	// (0) means "run them all, however long it takes".
	var deadline time.Time
	hasDeadline := false
	if cfg.MaxDuration > 0 {
		deadline = time.Now().Add(cfg.MaxDuration)
		hasDeadline = true
	}
	if d, ok := ctx.Deadline(); ok {
		if !hasDeadline || d.Before(deadline) {
			deadline = d
			hasDeadline = true
		}
	}

	merged := &ScanResult{}
	// Wrap partial so the handler always sees the FULL accumulated result
	// (finished chunks + the live chunk), not just one chunk's snapshot.
	partialWrap := func(chunkSnap *ScanResult) {
		if partial == nil {
			return
		}
		snap := &ScanResult{Results: make([]TargetResult, 0, len(merged.Results)+len(chunkSnap.Results))}
		snap.Results = append(snap.Results, merged.Results...)
		snap.Results = append(snap.Results, chunkSnap.Results...)
		partial(snap)
	}

	completed := 0 // URLs in chunks that finished cleanly
	skipped := 0   // URLs in chunks skipped by the per-chunk safety cap / error
	outOfTime := false
	var chunkReasons []string
	for start := 0; start < total; start += batchSize {
		if ctx.Err() != nil { // user cancel
			break
		}
		if hasDeadline && !time.Now().Before(deadline) { // explicit budget exhausted
			merged.Truncated = true
			outOfTime = true
			break
		}
		end := start + batchSize
		if end > total {
			end = total
		}
		chunk := urls[start:end]

		// Per-chunk SAFETY cap only — bounds one stuck batch, never the whole
		// run. Capped further by an explicit deadline if the caller set one.
		chunkCap := defaultNucleiPerBatchCap
		if hasDeadline {
			if r := time.Until(deadline); r < chunkCap {
				chunkCap = r
			}
		}
		ccfg := cfg
		ccfg.MaxDuration = chunkCap
		if start > 0 {
			ccfg.UpdateTemplates = false // only refresh templates once, on the first chunk
		}

		cr := scanChunk(ctx, chunk, ccfg, progress, partialWrap, start, total)
		merged.Results = append(merged.Results, cr.Results...)
		if cr.Truncated {
			merged.Truncated = true
			skipped += len(chunk)
			// A stuck / crashed / oversized chunk is skipped — the run CONTINUES
			// with the remaining chunks. Only an explicit total budget (if any)
			// stops the loop, checked at the top of the next iteration.
			if cr.TruncateReason != "" {
				chunkReasons = append(chunkReasons, cr.TruncateReason)
			}
			continue
		}
		completed += len(chunk)
	}

	if merged.Truncated {
		if outOfTime {
			merged.TruncateReason = fmt.Sprintf(
				"nuclei ran in batches of %d and completed %d of %d URL(s) before the explicit time budget you set ran out (%d finding(s)). Finished hosts have COMPLETE results; %d URL(s) were not scanned.",
				batchSize, completed, total, countFindings(merged), total-completed)
		} else {
			reason := "a batch did not complete"
			if len(chunkReasons) > 0 {
				reason = chunkReasons[0]
			}
			merged.TruncateReason = fmt.Sprintf(
				"nuclei ran all %d URL(s) in batches of %d; %d URL(s) in %d skipped batch(es) did not complete (%s). Everything else finished — %d finding(s).",
				total, batchSize, skipped, (skipped+batchSize-1)/batchSize, reason, countFindings(merged))
		}
	}
	if progress != nil {
		if merged.Truncated {
			progress(total, fmt.Sprintf("⚠ nuclei · %d/%d URL(s) fully scanned · %d finding(s)", completed, total, countFindings(merged)))
		} else {
			progress(total, fmt.Sprintf("nuclei · done · %d finding(s) across %d URL(s) (batched %d at a time)", countFindings(merged), total, batchSize))
		}
	}
	merged.Results = append(deadRows, merged.Results...)
	return merged
}

// countFindings totals findings across all result rows.
func countFindings(r *ScanResult) int {
	n := 0
	for _, tr := range r.Results {
		n += len(tr.Findings)
	}
	return n
}

// scanChunk runs ONE nuclei process over urls and reports progress in the
// caller's global URL space: done is reported as doneBase + (this chunk's
// progress), out of doneTotal. For a single-chunk scan doneBase=0 and
// doneTotal=len(urls), i.e. the original behaviour.
// nucleiTemplateFlag picks the right selector flag for a template reference.
// nuclei's -t takes template FILES/DIRS/URLs; a bare template ID (e.g.
// "CVE-2025-32355") must go through -id, or nuclei treats it as a missing path
// and aborts with "no templates provided for scan". Paths (with a slash or a
// .yaml/.yml suffix) and URLs keep -t; everything else is treated as an ID.
func nucleiTemplateFlag(sel string) string {
	if strings.Contains(sel, "/") || strings.HasSuffix(sel, ".yaml") || strings.HasSuffix(sel, ".yml") {
		return "-t"
	}
	return "-id"
}

func scanChunk(ctx context.Context, urls []string, cfg ScanConfig, progress ProgressFunc, partial PartialFunc, doneBase, doneTotal int) *ScanResult {
	if ctx == nil {
		ctx = context.Background()
	}
	result := &ScanResult{}
	if len(urls) == 0 {
		return result
	}

	if cfg.UpdateTemplates {
		// Skip the (slow) template update if the scan is already cancelled
		// — and surface the error instead of swallowing it (audit B58).
		if ctx.Err() == nil {
			if progress != nil {
				progress(0, "Updating Nuclei templates...")
			}
			// Audit fix: -ut (singular) was deprecated in nuclei v3; the
		// modern equivalent is -update-templates / -ut (alias kept but
		// emits a deprecation warning). Use the long form for clarity
		// and forward-compat with nuclei v4+.
		if err := shared.Command(ctx, "nuclei", "-update-templates", "-silent").Run(); err != nil && ctx.Err() == nil {
				// Don't fail the whole scan — fall through and run with
				// whatever templates already exist on disk — but emit a
				// progress note so the operator sees the warning.
				if progress != nil {
					progress(0, "Nuclei template update failed (continuing with cached templates): "+err.Error())
				}
			}
		}
	}

	// Pre-seed result rows so even URLs nuclei produces no findings for
	// still appear (with empty Findings) — gives the host detail page
	// something to attach error/exit info to.
	//
	// Audit fix (URL mis-attribution): nuclei normalizes hosts in its
	// JSONL output — default ports get stripped (https://x.com:443 →
	// https://x.com), hostnames may be lowercased, redirects may swap
	// scheme. We keep BOTH the original URL string (for exact matches +
	// display) and a normalized form (for fuzzy lookups) so we don't
	// silently dump every unattributable finding into urls[0].
	urlIdx := map[string]int{}
	urlSeen := map[string]bool{}
	urlNormIdx := map[string]int{} // normalized URL → result index
	for _, u := range urls {
		if _, ok := urlIdx[u]; ok {
			continue
		}
		urlIdx[u] = len(result.Results)
		if n := normalizeURL(u); n != "" {
			if _, ok := urlNormIdx[n]; !ok {
				urlNormIdx[n] = len(result.Results)
			}
		}
		result.Results = append(result.Results, TargetResult{URL: u})
	}

	// Write the URL list to a temp file. -l <file> lets nuclei run them
	// all in one process with full template parallelism.
	tmp, err := os.CreateTemp("", "nuclei-urls-*.txt")
	if err != nil {
		// Fallback: still produce empty rows, surface error on first.
		// Flag INCOMPLETE (mirrors the write-error path just below) so a
		// disk failure that stops nuclei ever running isn't reported as
		// a clean "done · 0 findings".
		if len(result.Results) > 0 {
			result.Results[0].Error = "nuclei tempfile: " + err.Error()
		}
		result.Truncated = true
		result.TruncateReason = "could not create the target-list temp file (" + err.Error() + ") — nuclei was not run."
		return result
	}
	defer os.Remove(tmp.Name())
	// Check write/close errors: a partial write (e.g. /tmp full) would hand
	// nuclei a truncated URL list and silently skip the rest of the hosts.
	writeErr := error(nil)
	for _, u := range urls {
		if _, e := tmp.WriteString(u + "\n"); e != nil {
			writeErr = e
			break
		}
	}
	if e := tmp.Close(); e != nil && writeErr == nil {
		writeErr = e
	}
	if writeErr != nil {
		if len(result.Results) > 0 {
			result.Results[0].Error = "nuclei target list write failed: " + writeErr.Error()
		}
		result.Truncated = true
		result.TruncateReason = "could not write the full target list to disk (" + writeErr.Error() + ") — nuclei was not run against all hosts."
		return result
	}

	args := []string{
		"-l", tmp.Name(),
		"-jsonl",
		"-silent",
		"-disable-update-check",
		"-no-color",
		// Periodic run stats to stderr ("Requests: N/M ...") so a long
		// single-URL scan reports live progress instead of sitting frozen.
		"-stats", "-stats-interval", "5",
		// Include the raw request + response in each JSONL line so the
		// UI can surface them for Burp replay / evidence in reports.
		// REGRESSION FIX: a prior audit batch changed this to the
		// hallucinated flag "-include-rr-all", which nuclei v3.x rejects
		// ("flag provided but not defined") → nuclei exits status 2
		// instantly and every scan reported 0 findings. The real flag is
		// "-include-rr" (aliased "-irr"); it is marked deprecated in favor
		// of the inverse "-omit-raw" but still works and raw is on by
		// default. Matches the other invocation site below (line ~557).
		"-include-rr",
		// Per-template timeout (seconds) — without this a single slow
		// template can stall the whole batch. Default is 5; we keep it
		// explicit and honor it.
		"-timeout", "5",
		// Retries: nuclei default is 1, leave it but explicit.
		"-retries", "1",
	}
	if len(cfg.Severity) > 0 {
		args = append(args, "-severity", strings.Join(cfg.Severity, ","))
	}
	if len(cfg.Tags) > 0 {
		args = append(args, "-tags", strings.Join(cfg.Tags, ","))
	}
	for _, t := range cfg.TemplateIDs {
		t = strings.TrimSpace(t)
		if t == "" {
			continue
		}
		args = append(args, nucleiTemplateFlag(t), t)
	}
	if cfg.RateLimit > 0 {
		args = append(args, "-rl", fmt.Sprintf("%d", cfg.RateLimit))
	}
	if cfg.Concurrency > 0 {
		args = append(args, "-c", fmt.Sprintf("%d", cfg.Concurrency))
	}
	if cfg.BulkSize > 0 {
		args = append(args, "-bulk-size", fmt.Sprintf("%d", cfg.BulkSize))
	}
	// Audit Q9 fix: expose nuclei's flagship features that were declared
	// on ScanConfig but never actually forwarded to argv:
	//   -exclude-tags   drop noisy tags (tech-detect, ssl, dns)
	//   -exclude-templates drop specific IDs/paths from a CVE-focused run
	//   -dast           enable the DAST/fuzz template set
	//   -as             automatic-scan (wappalyzer-style template autoselect)
	for _, tag := range cfg.ExcludeTags {
		tag = strings.TrimSpace(tag)
		if tag == "" {
			continue
		}
		args = append(args, "-exclude-tags", tag)
	}
	for _, t := range cfg.ExcludeTemplates {
		t = strings.TrimSpace(t)
		if t == "" {
			continue
		}
		args = append(args, "-exclude-templates", t)
	}
	if cfg.DAST {
		args = append(args, "-dast")
	}
	if cfg.AutomaticScan {
		args = append(args, "-as")
	}

	// Audit fix: nuclei was the only web-tier module with no HTTP-auth
	// knobs surfaced. Forward headers, cookies, UA, proxy, follow-redirects
	// and SNI override so authenticated and proxy-routed scans work.
	for name, val := range cfg.CustomHeaders {
		name = strings.TrimSpace(name)
		if name == "" {
			continue
		}
		args = append(args, "-H", name+": "+val)
	}
	if len(cfg.Cookies) > 0 {
		var parts []string
		for k, v := range cfg.Cookies {
			k = strings.TrimSpace(k)
			if k == "" {
				continue
			}
			parts = append(parts, k+"="+v)
		}
		if len(parts) > 0 {
			args = append(args, "-H", "Cookie: "+strings.Join(parts, "; "))
		}
	}
	if ua := strings.TrimSpace(cfg.UserAgent); ua != "" {
		args = append(args, "-H", "User-Agent: "+ua)
	}
	if px := strings.TrimSpace(cfg.ProxyURL); px != "" {
		args = append(args, "-proxy", px)
	}
	if cfg.FollowRedirects {
		args = append(args, "-fr")
	}
	if sni := strings.TrimSpace(cfg.SNIHost); sni != "" {
		args = append(args, "-sni", sni)
	}

	// Emit the exact command line so it lands in the scan's "Commands
	// run" panel alongside the nmap commands. The "$ " prefix is the
	// convention db.UpdateScanProgress uses to persist a line.
	// Secrets in -H Authorization/Cookie and -proxy credentials are
	// redacted before the line is persisted.
	// Emit the crumb only once (first chunk) — batched runs would otherwise
	// flood the panel with one identical line per chunk — and report it at
	// doneBase (not 0) so it never yanks the bar backward on a later chunk.
	if progress != nil && doneBase == 0 {
		quoted := make([]string, 0, len(args)+1)
		quoted = append(quoted, "nuclei")
		for i, a := range args {
			redacted := redactCmdArg(a, i, args)
			if strings.ContainsAny(redacted, " \t\"'") {
				quoted = append(quoted, "'"+strings.ReplaceAll(redacted, "'", "'\\''")+"'")
			} else {
				quoted = append(quoted, redacted)
			}
		}
		progress(doneBase, "$ "+strings.Join(quoted, " "))
	}

	// Hard wall-clock cap (audit B14): nuclei has been known to hang
	// indefinitely when a template stalls on a slow target — its own
	// -timeout flag only bounds individual HTTP calls, not the overall
	// run. The cap guarantees the process can't pin /tmp + FDs forever.
	// Caller's ctx cancel still wins immediately via WithTimeout
	// composition. When THIS cap fires (not a parent cancel) the run is
	// flagged Truncated below so it's reported as INCOMPLETE.
	hardDeadline := cfg.MaxDuration
	if hardDeadline <= 0 {
		hardDeadline = defaultNucleiMaxDuration
	}
	if d, ok := ctx.Deadline(); ok && time.Until(d) < hardDeadline {
		// Parent already enforces a tighter bound — don't widen it.
		hardDeadline = time.Until(d)
	}
	runCtx, runCancel := context.WithTimeout(ctx, hardDeadline)
	defer runCancel()
	cmd := shared.Command(runCtx, "nuclei", args...)
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		// Silent-degradation fix: a failed launch produced NO results.
		// Flag the run INCOMPLETE so the handler fires MarkScanError and
		// the red INCOMPLETE banner shows, instead of a silent
		// "done · 0 findings".
		result.Truncated = true
		result.TruncateReason = "nuclei could not be launched (stdout pipe: " + err.Error() + ") — no targets were scanned."
		if len(result.Results) > 0 {
			result.Results[0].Error = "stdout pipe: " + err.Error()
		}
		return result
	}
	stderr, _ := cmd.StderrPipe()
	if err := cmd.Start(); err != nil {
		// FD leak fix (audit B26): when Start() fails, the OS-allocated
		// pipe FDs from StdoutPipe / StderrPipe are still open. Without
		// these Close calls the scanner accumulates FDs every time a
		// nuclei binary is missing / OOM-killed at start, which over 2
		// days surfaces as 'too many open files'.
		stdout.Close()
		if stderr != nil {
			stderr.Close()
		}
		// Silent-degradation fix: a failed Start (most often a missing
		// nuclei binary) produced NO results. Flag the run INCOMPLETE +
		// give the operator a real reason so the handler fires
		// MarkScanError and the red INCOMPLETE banner shows — instead of
		// a silent "done · 0 findings". errors.Is(exec.ErrNotFound)
		// names the missing-tool case explicitly; otherwise fall back to
		// the shared translator, then the raw error.
		result.Truncated = true
		if errors.Is(err, exec.ErrNotFound) {
			result.TruncateReason = "nuclei is not installed or not on the scanner's PATH — install ProjectDiscovery nuclei and re-run."
		} else if friendly, ok := shared.TranslateToolError(err.Error()); ok {
			result.TruncateReason = "nuclei could not start: " + friendly
		} else {
			result.TruncateReason = "nuclei could not start: " + err.Error()
		}
		if len(result.Results) > 0 {
			result.Results[0].Error = "nuclei start: " + err.Error()
		}
		return result
	}

	// Drain stderr concurrently — pipe-buffer deadlock fix. Also (audit
	// B80) sniff for template-version compatibility warnings: nuclei
	// silently skips templates targeted at a newer schema than the
	// installed binary. We surface a single progress message when
	// >5% of templates are skipped this way so the operator knows the
	// scan is incomplete.
	//
	// Audit fix (progress reset): the advisory progress() call below
	// used to pass done=0, which DB.UpdateScanProgress writes to the
	// progress_done column verbatim — making the visible bar lurch
	// backward from whatever % the stdout loop had advanced to. Track
	// the last emitted seenCount (under mu) and forward it as the
	// advisory's done arg so the bar holds steady.
	// Hoisted so the stderr goroutine can share the same lock as the
	// stdout consumer below (avoids "undefined: mu" build error when the
	// stderr goroutine references urlSeen at line 349).
	var mu sync.Mutex
	var processed int
	// curFrac is this chunk's fraction complete (0..1), taken from nuclei's
	// own "-stats" Requests: N/M line — the only accurate real-time signal.
	// BOTH the stderr stats reader and the stdout finding loop drive the bar
	// off it (guarded by mu) so they can't fight each other. done is reported
	// in global URL units: doneBase + len(urls)*curFrac.
	var curFrac float64
	emitProgress := func(msg string) {
		if progress == nil {
			return
		}
		mu.Lock()
		frac := curFrac
		mu.Unlock()
		done := doneBase + int(float64(len(urls))*frac)
		if done > doneTotal-1 {
			done = doneTotal - 1
		}
		if done < doneBase {
			done = doneBase
		}
		progress(done, msg)
	}
	// stderrTail captures nuclei's own fatal/error lines so a non-zero exit
	// can be reported with the REAL reason instead of a guess.
	var stderrTail []string
	stderrDone := make(chan struct{})
	if stderr != nil {
		go func() {
			defer close(stderrDone)
			b := bufio.NewScanner(stderr)
			b.Buffer(make([]byte, 1024*1024), 4*1024*1024)
			templateSkips := 0
			templateTotal := 0
			for b.Scan() {
				line := b.Text()
				// Lines look like: "Templates: 1234, Skipped: 67"
				if strings.Contains(line, "Templates:") && strings.Contains(line, "Skipped:") {
					// Crude parse — sufficient to compute a ratio.
					fmt.Sscanf(line, "Templates: %d, Skipped: %d", &templateTotal, &templateSkips)
				}
				// Lines look like: "could not load template <name>: ..."
				if strings.Contains(line, "could not load template") {
					templateSkips++
				}
				// Capture fatal/error lines so a non-zero exit is reported with
				// nuclei's actual message, not a generic OOM guess.
				ll := strings.ToLower(line)
				if strings.Contains(line, "[FTL]") || strings.Contains(line, "[ERR]") ||
					strings.Contains(ll, "could not run") || strings.Contains(ll, "no templates") ||
					strings.Contains(ll, "fatal") || strings.Contains(ll, "no inputs") {
					mu.Lock()
					if len(stderrTail) < 20 {
						stderrTail = append(stderrTail, strings.TrimSpace(line))
					}
					mu.Unlock()
				}
				// -stats emits "Requests: N/M (P%) ..." periodically. This is
				// the accurate completion signal: convert the request ratio into
				// this chunk's fraction and drive the bar off it. (The old code
				// parsed N/M but then passed done=len(urlSeen) — the count of
				// URLs that happened to yield a finding — so the bar sat near 0
				// the whole run and only the log text showed the real %.)
				if idx := strings.Index(line, "Requests:"); idx >= 0 && progress != nil {
					var reqDone, reqTotal int
					if _, e := fmt.Sscanf(line[idx:], "Requests: %d/%d", &reqDone, &reqTotal); e == nil && reqTotal > 0 {
						mu.Lock()
						curFrac = float64(reqDone) / float64(reqTotal)
						mu.Unlock()
						emitProgress(fmt.Sprintf("→ Nuclei: %d/%d requests (%d%%)", reqDone, reqTotal, reqDone*100/reqTotal))
					}
				}
			}
			if templateTotal > 50 && templateSkips*100/templateTotal > 5 {
				emitProgress(fmt.Sprintf("⚠ Nuclei skipped %d/%d templates (%d%%) — update nuclei + templates: 'nuclei -ut -ut'",
					templateSkips, templateTotal, templateSkips*100/templateTotal))
			}
		}()
	} else {
		close(stderrDone)
	}

	// Stream JSONL — every line is one finding. Match each finding to the
	// originating URL by Host/MatchedAt prefix. (mu + processed hoisted
	// above the stderr goroutine so both goroutines share the same lock.)
	// Audit S2: partial() was called per-finding — with 1000+ nuclei
	// findings each marshals the full Results tree. Throttle to 2s; the
	// final result is force-flushed below after cmd.Wait returns.
	throttle := shared.NewPartialThrottler(2 * time.Second)
	scanner := bufio.NewScanner(stdout)
	// Each JSONL finding embeds the full raw request+response (-include-rr),
	// so a single line can be large. Cap at 32 MiB — big enough for any
	// realistic finding, and scanner.Err() below detects the overflow case
	// so we never silently drop the rest of the stream (previously a >4MB
	// line stopped the scanner and every later finding was lost, still
	// reported as a clean "done").
	scanner.Buffer(make([]byte, 1024*1024), 32*1024*1024)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || !strings.HasPrefix(line, "{") {
			continue
		}
		var raw rawFinding
		if json.Unmarshal([]byte(line), &raw) != nil {
			continue
		}
		f := convertFinding(raw)

		// Find which input URL this finding belongs to. nuclei prints the
		// host as scheme://host:port, sometimes with a trailing path.
		//
		// Audit S10 fix: the previous implementation iterated all urlIdx
		// entries doing two HasPrefix + an equality check per finding
		// (O(N*M) — 500 URLs × 5000 findings ≈ 2.5M string comparisons).
		// Try the O(1) exact-key lookups first (covering the common case
		// where nuclei echoes the input URL as-is) and only fall back to
		// the prefix walk when neither hits.
		matchURL := ""
		if f.Host != "" {
			if _, ok := urlIdx[f.Host]; ok {
				matchURL = f.Host
			}
		}
		if matchURL == "" && f.MatchedAt != "" {
			if _, ok := urlIdx[f.MatchedAt]; ok {
				matchURL = f.MatchedAt
			}
		}
		if matchURL == "" {
			for u := range urlIdx {
				if f.Host == u || strings.HasPrefix(f.MatchedAt, u) || strings.HasPrefix(f.Host, u) {
					if len(u) > len(matchURL) {
						matchURL = u
					}
				}
			}
		}
		// Audit fix: previously the fallback silently attributed every
		// unmatched finding to urls[0] — wrong whenever nuclei
		// normalized the URL (default-port stripped, lowercased host,
		// redirect-followed scheme). Try a normalized lookup first; if
		// that still misses, fall through to a synthetic per-host
		// bucket so the operator sees attribution failures.
		if matchURL == "" {
			for _, c := range []string{f.MatchedAt, f.Host} {
				if n := normalizeURL(c); n != "" {
					if idx, ok := urlNormIdx[n]; ok {
						matchURL = urls[idx]
						break
					}
				}
			}
		}
		mu.Lock()
		if matchURL == "" {
			// Still no match — synthesize a bucket so the finding is
			// surfaced rather than poisoning urls[0].
			unattributed := f.Host
			if unattributed == "" {
				unattributed = f.MatchedAt
			}
			if unattributed == "" {
				unattributed = "(unattributed)"
			}
			if _, ok := urlIdx[unattributed]; !ok {
				urlIdx[unattributed] = len(result.Results)
				result.Results = append(result.Results, TargetResult{URL: unattributed})
			}
			matchURL = unattributed
		}
		idx := urlIdx[matchURL]
		result.Results[idx].Findings = append(result.Results[idx].Findings, f)
		processed++
		// Track which URLs have appeared in findings so progress emits
		// in URL units (matching handler's total = len(urls)). Without
		// this, the handler shows N findings / M URLs, which can hit
		// >100% on chatty templates.
		if !urlSeen[matchURL] {
			urlSeen[matchURL] = true
		}
		seenCount := len(urlSeen)
		mu.Unlock()
		if processed%5 == 0 {
			// Drive the bar off the same request-fraction the stderr stats
			// reader maintains (via emitProgress) so findings and stats can't
			// pull the bar in opposite directions; the message still carries the
			// live finding / URLs-with-hits counts.
			emitProgress(fmt.Sprintf("nuclei · %d URL(s) with hits · %d finding(s) so far", seenCount, processed))
		}
		if partial != nil && throttle.ShouldFire() {
			mu.Lock()
			snap := cloneScanResult(result)
			mu.Unlock()
			partial(snap)
		}
	}
	<-stderrDone
	// Final flush — throttle may have skipped the last per-finding partial.
	if partial != nil {
		throttle.Force()
		mu.Lock()
		snap := cloneScanResult(result)
		mu.Unlock()
		partial(snap)
	}
	// If the stdout scanner stopped on an error (most likely a JSONL line
	// exceeding the 32MB buffer), findings after that point were dropped —
	// the run is INCOMPLETE even though nuclei may exit 0. Detect it.
	streamErr := scanner.Err()

	waitErr := cmd.Wait()
	// Distinguish OUR hard-deadline kill from a user cancel and from a
	// clean exit. runCtx.Err()==DeadlineExceeded while the PARENT ctx is
	// still live means nuclei ran out of its wall-clock budget — the run
	// is INCOMPLETE, not "done". This was previously invisible (the old
	// code only checked the parent ctx), so a killed 90-minute run was
	// reported as a clean "done · 0 findings" — the bug the operator hit.
	truncated := runCtx.Err() == context.DeadlineExceeded && ctx.Err() == nil
	switch {
	case truncated:
		result.Truncated = true
		result.TruncateReason = fmt.Sprintf(
			"nuclei stopped at the %s time cap — INCOMPLETE. It scanned only part of the %d URL(s) (%d finding(s) so far). A full-template scan (with 'low'/'info' severity) over this many hosts can take many hours. To get a complete run: scan fewer hosts, drop 'low'+'info' severity, raise the rate limit, or run the standalone Nuclei module with a longer budget.",
			hardDeadline.Round(time.Minute), len(urls), processed)
	case streamErr != nil:
		result.Truncated = true
		result.TruncateReason = fmt.Sprintf(
			"nuclei output stream ended early (%v) after %d finding(s) — remaining findings were dropped. A single finding's raw request+response exceeded the read buffer. Re-run with fewer/again, or disable raw-capture.",
			streamErr, processed)
	case waitErr != nil && ctx.Err() == nil:
		// Abnormal termination that is NOT a user cancel and NOT our own time
		// cap. Distinguish the two very different causes instead of always
		// blaming OOM: a SIGNAL kill (ExitCode()==-1) is the OS out-of-memory
		// killer / a crash on a huge scan; a plain non-zero EXIT (e.g. status
		// 1, fast) is nuclei itself erroring out — no templates, no inputs,
		// all targets unreachable — for which we now surface nuclei's OWN
		// stderr rather than guessing "OOM". (The bug: a 1-second exit-status-1
		// over unreachable hosts was reported as "most often the OOM killer on
		// a very large scan".)
		result.Truncated = true
		signalKilled := false
		var ee *exec.ExitError
		if errors.As(waitErr, &ee) && ee.ExitCode() == -1 {
			signalKilled = true
		}
		mu.Lock()
		tail := strings.Join(stderrTail, "; ")
		mu.Unlock()
		switch {
		case signalKilled:
			result.TruncateReason = fmt.Sprintf(
				"nuclei was killed by the OS (signal) after %d finding(s) — most often the out-of-memory killer on a very large scan (SIGKILL) or a crash. Reduce the host count / severity, check available memory, and confirm nuclei is up to date.",
				processed)
		case tail != "":
			if friendly, ok := shared.TranslateToolError(tail); ok {
				result.TruncateReason = fmt.Sprintf("nuclei exited (%v) after %d finding(s): %s", waitErr, processed, friendly)
			} else {
				result.TruncateReason = fmt.Sprintf("nuclei exited (%v) after %d finding(s): %s", waitErr, processed, tail)
			}
		default:
			result.TruncateReason = fmt.Sprintf(
				"nuclei exited (%v) after %d finding(s) with no diagnostic output — usually every target was unreachable, or the seed list was empty. Verify the targets are reachable (and the killswitch interface is up) and that templates are installed (nuclei -update-templates).",
				waitErr, processed)
		}
		if len(result.Results) > 0 {
			result.Results[0].ExitInfo = waitErr.Error()
		}
	}
	if progress != nil {
		switch {
		case result.Truncated:
			progress(doneBase+len(urls), fmt.Sprintf("⚠ nuclei INCOMPLETE · %d finding(s) so far across %d URL(s)", processed, len(urls)))
		case processed == 0:
			// A clean exit with zero findings is ambiguous: genuinely no
			// vulns, OR the targets were unreachable / templates failed to
			// load. Say so instead of an unqualified "done · 0 findings"
			// that reads as a confident all-clear.
			progress(doneBase+len(urls), fmt.Sprintf("nuclei · done · 0 findings across %d URL(s) — if unexpected, verify the targets were reachable and templates loaded", len(urls)))
		default:
			progress(doneBase+len(urls), fmt.Sprintf("nuclei · done · %d finding(s) across %d URL(s)", processed, len(urls)))
		}
	}
	return result
}

func cloneScanResult(r *ScanResult) *ScanResult {
	out := &ScanResult{Results: make([]TargetResult, len(r.Results))}
	for i, tr := range r.Results {
		c := tr
		c.Findings = append([]Finding(nil), tr.Findings...)
		out.Results[i] = c
	}
	return out
}

// runNuclei invokes the nuclei CLI for a single target and parses JSONL output.
func runNuclei(ctx context.Context, target string, cfg ScanConfig, onFinding func(Finding)) *TargetResult {
	tr := &TargetResult{URL: target}
	if !strings.HasPrefix(target, "http://") && !strings.HasPrefix(target, "https://") {
		target = "https://" + target
		tr.URL = target
	}

	args := []string{
		"-target", target,
		"-jsonl",
		"-silent",
		"-disable-update-check",
		"-no-color",
		"-include-rr",
	}
	if len(cfg.Severity) > 0 {
		args = append(args, "-severity", strings.Join(cfg.Severity, ","))
	}
	if len(cfg.Tags) > 0 {
		args = append(args, "-tags", strings.Join(cfg.Tags, ","))
	}
	for _, t := range cfg.TemplateIDs {
		t = strings.TrimSpace(t)
		if t == "" {
			continue
		}
		args = append(args, nucleiTemplateFlag(t), t)
	}
	if cfg.RateLimit > 0 {
		args = append(args, "-rl", fmt.Sprintf("%d", cfg.RateLimit))
	}
	if cfg.Concurrency > 0 {
		args = append(args, "-c", fmt.Sprintf("%d", cfg.Concurrency))
	}
	if cfg.BulkSize > 0 {
		args = append(args, "-bulk-size", fmt.Sprintf("%d", cfg.BulkSize))
	}

	cmd := shared.Command(ctx, "nuclei", args...)
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		tr.Error = "stdout pipe: " + err.Error()
		return tr
	}
	stderr, _ := cmd.StderrPipe()
	if err := cmd.Start(); err != nil {
		tr.Error = "nuclei start: " + err.Error()
		return tr
	}

	// CRITICAL: drain stderr CONCURRENTLY with the stdout scanner loop.
	// The default Linux pipe buffer is ~64 KB. nuclei often emits noisy
	// stderr lines (template version warnings, retry notices, etc.). If we
	// only read stdout synchronously and don't pull anything from stderr,
	// the stderr buffer fills, nuclei's stderr write blocks, the process
	// stops writing stdout, our `for scanner.Scan()` never sees EOF, and
	// the whole goroutine deadlocks forever — leaving the scan stuck in
	// "running" status. Reading both pipes in parallel is the standard
	// fix for this Go exec gotcha.
	stderrDone := make(chan struct{})
	if stderr != nil {
		go func() {
			defer close(stderrDone)
			b := bufio.NewScanner(stderr)
			b.Buffer(make([]byte, 1024*1024), 4*1024*1024)
			for b.Scan() {
				_ = b.Text()
			}
		}()
	} else {
		close(stderrDone)
	}

	// Read findings as they stream in so the UI can update live.
	scanner := bufio.NewScanner(stdout)
	scanner.Buffer(make([]byte, 1024*1024), 4*1024*1024)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || !strings.HasPrefix(line, "{") {
			continue
		}
		var raw rawFinding
		if json.Unmarshal([]byte(line), &raw) != nil {
			continue
		}
		f := convertFinding(raw)
		tr.Findings = append(tr.Findings, f)
		if onFinding != nil {
			onFinding(f)
		}
	}
	// Ensure stderr drain finished too — protects cmd.Wait from racing
	// against an unread pipe.
	<-stderrDone

	if err := cmd.Wait(); err != nil {
		// nuclei exits non-zero when it finds nothing or hits warnings — only
		// surface as error if we got zero findings AND a non-cancellation reason.
		if ctx.Err() == nil && len(tr.Findings) == 0 {
			tr.ExitInfo = err.Error()
		}
	}
	return tr
}

func convertFinding(r rawFinding) Finding {
	f := Finding{
		TemplateID:  r.TemplateID,
		Name:        strings.TrimSpace(r.Info.Name),
		Severity:    strings.ToLower(strings.TrimSpace(r.Info.Severity)),
		Type:        r.Type,
		Host:        r.Host,
		MatchedAt:   r.MatchedAt,
		Description: strings.TrimSpace(r.Info.Description),
		Tags:        r.Info.Tags,
		References:  r.Info.Reference,
		Extracted:   r.ExtractedRes,
		RawRequest:  r.Request,
		RawResponse: r.Response,
		CurlCommand: r.CurlCommand,
	}
	if f.Severity == "" {
		f.Severity = "unknown"
	}
	if r.Info.Classification != nil {
		if v, ok := r.Info.Classification["cve-id"]; ok {
			f.CVEs = stringSlice(v)
		}
		if v, ok := r.Info.Classification["cwe-id"]; ok {
			f.CWEs = stringSlice(v)
		}
	}
	return f
}

// stringSlice flattens nuclei's "x: ['a','b']" or "x: 'a'" classification fields.
func stringSlice(v interface{}) []string {
	switch t := v.(type) {
	case string:
		if t == "" {
			return nil
		}
		return []string{t}
	case []interface{}:
		out := make([]string, 0, len(t))
		for _, x := range t {
			if s, ok := x.(string); ok && s != "" {
				out = append(out, s)
			}
		}
		return out
	}
	return nil
}

// normalizeURL returns a comparable form of a URL/host so prefix matches
// survive nuclei's own normalization. Strips default ports (:80 for http,
// :443 for https), lowercases the host, drops the trailing slash on the
// path. Returns "" if the input is empty or unparseable as a URL — bare
// hostnames without a scheme are accepted too (treated as scheme-less).
func normalizeURL(s string) string {
	s = strings.TrimSpace(s)
	if s == "" {
		return ""
	}
	// url.Parse accepts both scheme-less and full URLs; if there's no
	// scheme it puts the host in Path. Add a synthetic scheme for the
	// parser, then drop it from the comparable key.
	withScheme := s
	if !strings.Contains(s, "://") {
		withScheme = "https://" + s
	}
	u, err := url.Parse(withScheme)
	if err != nil || u.Host == "" {
		return strings.ToLower(strings.TrimRight(s, "/"))
	}
	host := strings.ToLower(u.Host)
	// Strip default ports.
	scheme := strings.ToLower(u.Scheme)
	if h, p, ok := strings.Cut(host, ":"); ok {
		if (scheme == "http" && p == "80") || (scheme == "https" && p == "443") {
			host = h
		}
	}
	path := strings.TrimRight(u.Path, "/")
	// Keep scheme out of the key — nuclei may follow http→https redirects
	// and re-emit the post-redirect URL.
	out := host + path
	if u.RawQuery != "" {
		out += "?" + u.RawQuery
	}
	return out
}

// redactCmdArg redacts secrets in the command line we print to the
// scan's "Commands run" panel. Targets -H Authorization/Cookie/api-key
// values and credentials embedded in -proxy URLs. Other args pass through
// unchanged. i is the arg's index in argv so we can detect the -flag
// before it.
func redactCmdArg(a string, i int, args []string) string {
	prev := ""
	if i > 0 {
		prev = args[i-1]
	}
	if prev == "-H" {
		if idx := strings.Index(a, ":"); idx > 0 {
			name := strings.ToLower(strings.TrimSpace(a[:idx]))
			switch name {
			case "authorization", "proxy-authorization", "cookie",
				"x-api-key", "x-auth-token", "api-key",
				"x-amz-security-token", "x-vault-token", "x-csrf-token":
				return a[:idx] + ": [REDACTED]"
			}
		}
	}
	if prev == "-proxy" {
		if u, err := url.Parse(a); err == nil && u.User != nil {
			u.User = url.UserPassword(u.User.Username(), "REDACTED")
			return u.String()
		}
	}
	return a
}

// SeverityRank maps severity strings to a numeric priority for sorting.
func SeverityRank(s string) int {
	switch strings.ToLower(s) {
	case "critical":
		return 5
	case "high":
		return 4
	case "medium":
		return 3
	case "low":
		return 2
	case "info":
		return 1
	default:
		return 0
	}
}
