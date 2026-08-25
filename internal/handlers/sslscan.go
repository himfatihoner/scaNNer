package handlers

import (
	"context"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"scanner/internal/models"
	"scanner/internal/modules/shared"
	"scanner/internal/modules/sslscan"
)

// normalizeSSLTarget reduces a target-list entry to the bare host the SSL/TLS
// tools expect. A URL-list is a common input, and sslscan/nmap can't scan
// "https://host/path:443"; ExpandTargets also mis-reads a "://"/"/path" entry as
// a (failed) CIDR and passes the raw URL straight through. So here we strip the
// scheme, userinfo, path and any URL port down to the hostname, while leaving
// CIDRs ("10.0.0.0/24"), hyphen-ranges and bare host[:no-slash] untouched for
// the expander. Port selection stays with the module's ports field.
func normalizeSSLTarget(raw string) string {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return ""
	}
	if strings.Contains(raw, "://") {
		if u, err := url.Parse(raw); err == nil {
			if h := u.Hostname(); h != "" {
				return h
			}
		}
	}
	// Scheme-less "host/path" (e.g. "apphost.example.com/giris"): strip the path,
	// but never mangle a CIDR whose prefix is a real IP ("10.0.0.0/24").
	if i := strings.IndexByte(raw, '/'); i > 0 && net.ParseIP(raw[:i]) == nil {
		return raw[:i]
	}
	return raw
}

// SSLScanMaxTasks caps the total scan workload (targets × ports) to keep
// an unauthenticated POST from spinning up an O(N²) JSON-marshal storm.
// See audit M-DoS: a single request with `0.0.0.0/16` × `1-65535` would
// peg CPU and silently truncate the 50MB result column.
const SSLScanMaxTasks = 50_000

// SSLScanMaxPorts caps the number of distinct ports a single scan may
// target. Mirrors the same DoS-bounding intent as SSLScanMaxTasks but
// applies before target expansion so we reject obvious foot-guns early.
const SSLScanMaxPorts = 1024

// SSLScanConfig is the JSON config stored with a scan
type SSLScanConfig struct {
	Targets []string `json:"targets"`
	Ports   []int    `json:"ports"`
	// StartTLS selects the plaintext-to-TLS upgrade dance. Values:
	//   ""|"none"  → dial TLS directly (default 443 behaviour)
	//   "auto"     → per-port default (25/587→smtp, 143→imap, 110→pop3,
	//                389→ldap, 21→ftp, 5432→postgres)
	//   explicit   → smtp|imap|pop3|ftp|ldap|postgres
	StartTLS string `json:"starttls,omitempty"`
}

// allowedStartTLS lists the values the form is permitted to submit.
// Anything else is coerced to "" (direct TLS) to keep the module surface
// stable if the UI drifts.
var allowedStartTLS = map[string]bool{
	"":         true,
	"none":     true,
	"auto":     true,
	"smtp":     true,
	"imap":     true,
	"pop3":     true,
	"ftp":      true,
	"ldap":     true,
	"postgres": true,
}

// SSLScanPage renders the SSL/TLS scanner page
func (h *Handler) SSLScanPage(w http.ResponseWriter, r *http.Request) {
	data := h.baseData(r, "SSL/TLS Scanner - scaNNer", "sslscan")
	ws := data["ActiveWorkspace"].(*models.Workspace)

	targets, _ := h.db.ListTargets(ws.ID, "")
	data["WSTargets"] = targets
	data["WSTargetGroups"] = h.groupTargetsByList(ws.ID)

	scans, _ := h.db.ListScansLite(ws.ID, "sslscan")
	data["Scans"] = scans

	h.render(w, "layout", data)
}

// SSLScanRun starts a new SSL/TLS scan
func (h *Handler) SSLScanRun(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Redirect(w, r, "/modules/sslscan", http.StatusSeeOther)
		return
	}

	r.ParseForm()
	ws := h.activeWorkspace(r)

	var rawTargets []string
	if manual := strings.TrimSpace(r.FormValue("manual_targets")); manual != "" {
		for _, line := range strings.Split(manual, "\n") {
			line = strings.TrimSpace(line)
			if line == "" {
				continue
			}
			rawTargets = append(rawTargets, line)
		}
	}
	if selected := r.Form["targets"]; len(selected) > 0 {
		rawTargets = append(rawTargets, selected...)
	}

	// Normalize URL-list entries (https://host/path → host) before expansion —
	// otherwise the raw URL reaches sslscan/nmap and every finding is missed.
	for i, t := range rawTargets {
		rawTargets[i] = normalizeSSLTarget(t)
	}

	// Use the shared expander for CIDR / hyphen-range handling — mirrors
	// smbenum.go:77 and friends. Cap CIDR expansion at 256 (a /24) to
	// match the codebase-wide default; anything larger passes through as
	// a single literal target (silently unscannable) so users see zero
	// findings for it rather than the scanner burning 10+h serially on
	// a mis-typed /16. Users needing wider blocks split them across runs.
	targets := shared.ExpandTargets(rawTargets, 256)

	if len(targets) == 0 {
		http.Redirect(w, r, "/modules/sslscan?error=no_targets", http.StatusSeeOther)
		return
	}

	// Default set: 443 (HTTPS) + the common STARTTLS service ports. With
	// STARTTLS=auto each negotiates the right way (443 dials TLS directly,
	// the rest do the plaintext upgrade dance). Used only when the form's
	// ports field is empty.
	ports := []int{443, 25, 587, 143, 110, 21, 389, 5432}
	if portStr := strings.TrimSpace(r.FormValue("ports")); portStr != "" {
		ports = parsePorts(portStr)
		if len(ports) == 0 {
			http.Redirect(w, r, "/modules/sslscan?error=invalid_ports", http.StatusSeeOther)
			return
		}
		if len(ports) > SSLScanMaxPorts {
			http.Redirect(w, r, "/modules/sslscan?error=too_many_ports", http.StatusSeeOther)
			return
		}
	}

	// Total tasks = targets * ports. Reject obvious DoS-shaped requests
	// up-front rather than burning a goroutine + DB row that would just
	// be silently truncated by the 50MB result-column cap.
	totalTasks := len(targets) * len(ports)
	if totalTasks > SSLScanMaxTasks {
		http.Redirect(w, r, "/modules/sslscan?error=too_many_tasks", http.StatusSeeOther)
		return
	}

	// STARTTLS mode: allowlisted so a hostile form post can't smuggle in
	// arbitrary strings that ResolveStartTLS would pass through unfiltered.
	startTLS := strings.ToLower(strings.TrimSpace(r.FormValue("starttls")))
	if !allowedStartTLS[startTLS] {
		startTLS = ""
	}

	cfgJSON, _ := json.Marshal(SSLScanConfig{Targets: targets, Ports: ports, StartTLS: startTLS})
	scan, err := h.db.CreateScan(ws.ID, "sslscan", string(cfgJSON), totalTasks)
	if err != nil {
		http.Redirect(w, r, "/modules/sslscan?error=db_error", http.StatusSeeOther)
		return
	}
	// Sequential scanning: if the operator ticked "start after the current
	// scan finishes" and this workspace is busy, park this run as queued.
	if h.queueIfSequential(w, r, scan) {
		return
	}

	// Build HTTPOptions and register with BeginScan so cancel can flush
	// idle transports, and killswitch warnings propagate to the UI.
	// The module itself is TLS-only (no net/http), so opts.Ctx is the
	// only field actually consumed downstream — but registration means
	// Cancel() closes any pooled TCP connections our BoundDialer opened.
	//
	// Per-scan HTTP tuning: applyHTTPTuning reads req_timeout / max_concurrent
	// from the http_tuning form partial, sets opts.Timeout (override or the
	// global Web default), and returns the effective concurrency. Blank fields
	// inherit Settings. The rate-limit return is unused — this module has no
	// request-rate concept.
	opts := h.BuildHTTPOptions(r)
	conc, _ := h.applyHTTPTuning(r, opts)
	opts = h.BeginScan(scan.ID, opts)
	go h.runSSLScanWithTuning(scan.ID, targets, ports, startTLS, conc, opts.Timeout, opts.Ctx)

	http.Redirect(w, r, "/modules/sslscan/results/"+scan.ID, http.StatusSeeOther)
}

// SSLScanResults shows the results of a specific scan
func (h *Handler) SSLScanResults(w http.ResponseWriter, r *http.Request) {
	scanID := strings.TrimPrefix(r.URL.Path, "/modules/sslscan/results/")
	if scanID == "" {
		http.Redirect(w, r, "/modules/sslscan", http.StatusSeeOther)
		return
	}

	scan, err := h.db.GetScan(scanID)
	if err != nil {
		http.NotFound(w, r)
		return
	}

	data := h.baseData(r, "Scan Results - scaNNer", "sslscan_results")

	var cfg SSLScanConfig
	json.Unmarshal([]byte(scan.Config), &cfg)

	var results []*sslscan.HostResult
	json.Unmarshal([]byte(scan.Result), &results)

	// Sort
	sortMode := r.URL.Query().Get("sort")
	if sortMode == "" {
		sortMode = "severity"
	}
	sortSSLResults(results, sortMode)

	counts := map[sslscan.Severity]int{}
	for _, hr := range results {
		for _, f := range hr.Findings {
			counts[f.Severity]++
		}
	}

	data["Scan"] = scan
	data["Config"] = cfg
	data["Results"] = results
	data["SortMode"] = sortMode
	data["CriticalCount"] = counts[sslscan.SevCritical]
	data["HighCount"] = counts[sslscan.SevHigh]
	data["MediumCount"] = counts[sslscan.SevMedium]
	data["LowCount"] = counts[sslscan.SevLow]
	data["InfoCount"] = counts[sslscan.SevInfo]
	data["TotalFindings"] = counts[sslscan.SevCritical] + counts[sslscan.SevHigh] + counts[sslscan.SevMedium] + counts[sslscan.SevLow] + counts[sslscan.SevInfo]

	h.renderResults(w, r, "sslscan_results_inner", data)
}

// SSLScanStatus returns scan status + progress as JSON (for polling)
func (h *Handler) SSLScanStatus(w http.ResponseWriter, r *http.Request) {
	scanID := strings.TrimPrefix(r.URL.Path, "/modules/sslscan/status/")
	scan, err := h.db.GetScan(scanID)
	if err != nil {
		http.NotFound(w, r)
		return
	}
	h.writeScanStatus(w, scan)
}

// runSSLScan is the restart-path entry point. A replayed scan has no HTTP
// Request to read per-scan http_tuning overrides from, so it inherits the
// effective concurrency + timeout from Settings (the natural "blank = inherit"
// behaviour) and delegates to runSSLScanWithTuning. The live-launch path
// (SSLScanRun) calls runSSLScanWithTuning directly with the operator's
// per-scan overrides already applied to opts by applyHTTPTuning.
func (h *Handler) runSSLScan(scanID string, targets []string, ports []int, startTLS string, ctx context.Context) {
	s := h.db.GetSettings()
	timeout := time.Duration(s.EffectiveWebTimeout()) * time.Second
	h.runSSLScanWithTuning(scanID, targets, ports, startTLS, s.EffectiveWebMaxConcurrent(), timeout, ctx)
}

// runSSLScanWithTuning executes the scan in background with progress tracking,
// using the caller-supplied concurrency and per-request timeout.
//
// Audit (perf): the previous version held a global mutex across
// json.Marshal(allResults) + UpdateScanResult on EVERY host completion.
// With N hosts that's O(N²) marshal volume and SQLite write storms,
// serialising the entire scan into one host-at-a-time pipeline. The
// fix follows the framework's standard 2-second flush ticker pattern
// (see smbenum.go runSMBEnum): workers only hold mu briefly around
// `done++ / append`, and a single background goroutine snapshots,
// marshals, and writes at most every 2 s.
func (h *Handler) runSSLScanWithTuning(scanID string, targets []string, ports []int, startTLS string, concurrency int, timeout time.Duration, ctx context.Context) {
	if !h.db.MarkRunning(scanID) {
		return
	}
	defer h.FinishScan(scanID)

	// This module spawns up to THREE external tools (nmap + sslscan + openssl)
	// per host. The web concurrency can be set very high (e.g. 999) for
	// lightweight Go HTTP requests, but at that value sslscan fans out to
	// thousands of concurrent subprocesses and exhausts the machine (PIDs / FDs
	// / memory) — the HTTP server starves and the whole app hangs. Cap at a
	// subprocess-safe worker count regardless of the web setting.
	const sslscanMaxConcurrency = 20
	if concurrency > sslscanMaxConcurrency {
		concurrency = sslscanMaxConcurrency
	}
	if concurrency < 1 {
		concurrency = 1
	}

	// Authoritative progress total = tasks (targets × ports), matching the
	// per-task `done` counter below. CreateScan/restart/resume may have stamped
	// a TARGET-count total (e.g. a resume sets it to remaining targets), which
	// made progress overshoot 100% (done counts host:port units). Set it here so
	// the bar is always accurate regardless of how the row was created.
	h.db.UpdateScanProgressFull(scanID, 0, len(targets)*len(ports), "")

	var allResults []*sslscan.HostResult
	var mu sync.Mutex
	var done int
	sem := make(chan struct{}, concurrency)
	var wg sync.WaitGroup

	// The standalone SSL/TLS module ALWAYS keeps full per-host evidence + PoC,
	// regardless of target count (operator decision — the PoC must be captured
	// for every host). advancedweb's bulk stage is the light path; this module
	// is the thorough one.

	// 2-second flush ticker: snapshots allResults under mu, marshals
	// once outside the lock, writes once. This is the only path that
	// calls UpdateScanResult during the run; the final flush happens
	// after wg.Wait below.
	doneCh := make(chan struct{})
	defer close(doneCh)
	go func() {
		t := time.NewTicker(2 * time.Second)
		defer t.Stop()
		for {
			select {
			case <-doneCh:
				return
			case <-t.C:
				mu.Lock()
				snap := make([]*sslscan.HostResult, len(allResults))
				copy(snap, allResults)
				mu.Unlock()
				if len(snap) == 0 {
					continue
				}
				b, err := json.Marshal(snap)
				if err == nil {
					h.db.UpdateScanResult(scanID, string(b))
				}
			}
		}
	}()

	for _, target := range targets {
		// Bail out early if cancelled before dispatching remaining work
		if ctx.Err() != nil {
			break
		}
		for _, port := range ports {
			if ctx.Err() != nil {
				break
			}
			wg.Add(1)
			sem <- struct{}{}
			go func(t string, p int) {
				defer wg.Done()
				defer func() { <-sem }()

				// Skip if cancelled
				if ctx.Err() != nil {
					mu.Lock()
					done++
					curDone := done
					mu.Unlock()
					h.db.UpdateScanProgressBatched(scanID, curDone, fmt.Sprintf("Cancelled %s:%d", t, p))
					return
				}

				// Pre-scan progress message. Read `done` under mu to
				// avoid the data race with other workers' `done++`.
				mu.Lock()
				curDoneStart := done
				mu.Unlock()
				// Batched: at scale (e.g. 1492 targets × 8 ports = ~12k tasks ×
				// 41 workers) the un-batched UpdateScanProgress issued two write
				// transactions PER TASK (progress + a full console_log rewrite),
				// saturating the SQLite connection pool and starving the HTTP
				// server ("database is locked" → UI hangs). The batcher coalesces
				// these into one flush per 500 ms.
				h.db.UpdateScanProgressBatched(scanID, curDoneStart, fmt.Sprintf("Scanning %s:%d", t, p))

				result := sslscan.ScanHostOpts(ctx, t, p, timeout, startTLS)

				// Brief critical section — only the slice append +
				// counter, NOT the marshal or DB result write.
				mu.Lock()
				done++
				curDone := done
				// Keep EVERY reachable host (port responded), not just the ones
				// with TLS — so the results page shows the full picture of what
				// was scanned and what came back (TLS hosts with findings AND
				// reachable-but-no-TLS hosts). Only closed/unreachable ports are
				// dropped (they'd be thousands of "connection failed" rows).
				if result.Reachable {
					allResults = append(allResults, result)
				}
				mu.Unlock()

				// Progress message outside the lock (batched — see above).
				switch {
				case result.HasTLS:
					h.db.UpdateScanProgressBatched(scanID, curDone, fmt.Sprintf("Found TLS on %s:%d", t, p))
				case result.Reachable:
					h.db.UpdateScanProgressBatched(scanID, curDone, fmt.Sprintf("No TLS on %s:%d (reachable)", t, p))
				default:
					h.db.UpdateScanProgressBatched(scanID, curDone, fmt.Sprintf("Unreachable %s:%d", t, p))
				}
			}(target, port)
		}
	}

	wg.Wait()

	// Final flush: take a snapshot under mu so we don't race with the
	// ticker goroutine, then write the authoritative result.
	mu.Lock()
	final := make([]*sslscan.HostResult, len(allResults))
	copy(final, allResults)
	mu.Unlock()
	resultJSON, _ := json.Marshal(final)
	h.db.UpdateScanResult(scanID, string(resultJSON))

	// Hard-failure surfacing: if every attempted unit errored, mark the scan
	// failed with a translated reason rather than a silent "done" with zero
	// findings. Note: `final` only retains HasTLS hosts, so a unit surfaces an
	// error here only if an error-bearing result reaches the slice.
	if ctx.Err() == nil {
		var errs []string
		for _, u := range final {
			if u.Error != "" {
				errs = append(errs, u.Error)
			}
		}
		h.markHardFailure(scanID, errs, len(targets)*len(ports))
	}
}

// parsePorts parses a port specification ("443", "443,8443", "1-1000").
//
// Audit: the previous version silently capped a range at 1000 ports
// (`if end-start > 1000 { end = start + 1000 }`), so a user typing
// `1-65535` got only 1-1001 with no warning. We now keep the full
// requested range here and let the handler enforce SSLScanMaxPorts
// — that way the user gets an explicit `?error=too_many_ports`
// rejection instead of silent scope truncation. Returning an empty
// slice still means "unparseable" so the caller's `invalid_ports`
// redirect remains correct.
func parsePorts(s string) []int {
	var ports []int
	seen := map[int]bool{}

	for _, part := range strings.Split(s, ",") {
		part = strings.TrimSpace(part)
		if strings.Contains(part, "-") {
			bounds := strings.SplitN(part, "-", 2)
			start, err1 := strconv.Atoi(strings.TrimSpace(bounds[0]))
			end, err2 := strconv.Atoi(strings.TrimSpace(bounds[1]))
			if err1 != nil || err2 != nil || start < 1 || end > 65535 || start > end {
				continue
			}
			// Hard upper bound — anything beyond SSLScanMaxPorts in a
			// single range would just be rejected by the handler anyway.
			// Stop early so we don't allocate a 65k-element slice.
			for p := start; p <= end; p++ {
				if !seen[p] {
					ports = append(ports, p)
					seen[p] = true
				}
				if len(ports) > SSLScanMaxPorts {
					return ports
				}
			}
		} else {
			p, err := strconv.Atoi(part)
			if err == nil && p >= 1 && p <= 65535 && !seen[p] {
				ports = append(ports, p)
				seen[p] = true
			}
			if len(ports) > SSLScanMaxPorts {
				return ports
			}
		}
	}
	return ports
}

// sortSSLResults sorts host results and their findings.
// "severity" = most vulnerable hosts first (by highest finding severity, then by finding count desc)
// "alpha"    = alphabetical by host:port
func sortSSLResults(results []*sslscan.HostResult, mode string) {
	// Sort findings within each host by severity desc
	for _, hr := range results {
		sort.Slice(hr.Findings, func(i, j int) bool {
			si := sslscan.SeverityScore(hr.Findings[i].Severity)
			sj := sslscan.SeverityScore(hr.Findings[j].Severity)
			if si != sj {
				return si > sj
			}
			return hr.Findings[i].Title < hr.Findings[j].Title
		})
	}

	switch mode {
	case "alpha":
		sort.Slice(results, func(i, j int) bool {
			if results[i].Host != results[j].Host {
				return results[i].Host < results[j].Host
			}
			return results[i].Port < results[j].Port
		})
	default: // "severity"
		sort.Slice(results, func(i, j int) bool {
			si := maxSeverityScore(results[i])
			sj := maxSeverityScore(results[j])
			if si != sj {
				return si > sj
			}
			// Same max severity: more findings first
			if len(results[i].Findings) != len(results[j].Findings) {
				return len(results[i].Findings) > len(results[j].Findings)
			}
			return results[i].Host < results[j].Host
		})
	}
}

func maxSeverityScore(hr *sslscan.HostResult) int {
	max := 0
	for _, f := range hr.Findings {
		s := sslscan.SeverityScore(f.Severity)
		if s > max {
			max = s
		}
	}
	return max
}
