package handlers

import (
	"encoding/json"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"time"

	"scanner/internal/models"
	"scanner/internal/modules/authtest"
	"scanner/internal/modules/shared"
)

// authtestMaxListEntries caps imported usernames/passwords per scan.
// Audit MEDIUM fix: a 10 MB upload of one-line-each entries could yield
// ~100k strings and a cluster-bomb pre-alloc of ~10^10 credentialPair —
// scanner OOM. 5000 entries × 5000 entries is still 25M attempts, which
// the MaxAttempts cap (and the user) should refuse before it runs, but
// at least the in-memory allocation can't blow the process.
const authtestMaxListEntries = 5000

func (h *Handler) AuthTestPage(w http.ResponseWriter, r *http.Request) {
	data := h.baseData(r, "Auth Tester - scaNNer", "authtest")
	ws := data["ActiveWorkspace"].(*models.Workspace)
	scans, _ := h.db.ListScansLite(ws.ID, "authtest")
	data["Scans"] = scans
	h.render(w, "layout", data)
}

func (h *Handler) AuthTestRun(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Redirect(w, r, "/modules/authtest", http.StatusSeeOther)
		return
	}
	// 10 MB cap on uploaded wordlists — anything bigger would be a misuse
	// of the auth tester (use brutef + hydra for huge wordlists).
	r.ParseMultipartForm(10 << 20)
	ws := h.activeWorkspace(r)

	loginURL := strings.TrimSpace(r.FormValue("login_url"))
	if loginURL == "" {
		// Use canonical no_login code so the form_error banner renders the
		// friendly "Login URL is required." message (see friendlyFormError
		// FuncMap in handlers.go). Audit MEDIUM fix: previous no_login_url
		// fell through to the verbatim "Submission rejected: no_login_url"
		// fallback which was less friendly.
		http.Redirect(w, r, "/modules/authtest?error=no_login", http.StatusSeeOther)
		return
	}
	if !strings.HasPrefix(loginURL, "http") {
		loginURL = "https://" + loginURL
	}

	// readLinesFromFormOrFile lets the user either paste a textarea OR
	// upload a file for username/password lists. File wins when both are
	// supplied (uploading is the more explicit gesture).
	readLinesFromFormOrFile := func(textName, fileName string) []string {
		// Try uploaded file first.
		if f, _, err := r.FormFile(fileName); err == nil {
			defer f.Close()
			b := readLines(f)
			if len(b) > 0 {
				return b
			}
		}
		// Fallback to textarea.
		var out []string
		for _, line := range strings.Split(r.FormValue(textName), "\n") {
			line = strings.TrimSpace(line)
			if line != "" {
				out = append(out, line)
			}
		}
		return out
	}

	parseDuration := func(name string) time.Duration {
		v := strings.TrimSpace(r.FormValue(name))
		if v == "" {
			return 0
		}
		// Accept "30s", "2m", "1h" or bare seconds ("30").
		if d, err := time.ParseDuration(v); err == nil {
			return d
		}
		if n, err := strconv.Atoi(v); err == nil && n > 0 {
			return time.Duration(n) * time.Second
		}
		return 0
	}

	mode := authtest.AttackMode(strings.TrimSpace(r.FormValue("mode")))
	if mode == "" {
		mode = authtest.ModeClusterBomb // back-compat: old form had no mode
	}
	maxAttempts := 0
	if v := strings.TrimSpace(r.FormValue("max_attempts")); v != "" {
		if n, err := strconv.Atoi(v); err == nil && n > 0 {
			maxAttempts = n
		}
	}
	// Per-scan HTTP tuning (req_timeout / max_concurrent) from the
	// http_tuning form partial: applyHTTPTuning sets opts.Timeout (override
	// or the global Web default) and returns the effective concurrency.
	// ClusterBomb honors concurrency; spray/pitchfork/etc. run serially.
	opts := h.BuildHTTPOptions(r)
	conc, _ := h.applyHTTPTuning(r, opts)

	users := readLinesFromFormOrFile("usernames", "usernames_file")
	passes := readLinesFromFormOrFile("passwords", "passwords_file")
	// Audit MEDIUM fix: cap wordlist sizes so a huge upload can't OOM the
	// scanner with a cartesian pre-alloc. Soft-truncate and surface the
	// limit in the launch redirect via the form_error banner.
	listTruncated := false
	if len(users) > authtestMaxListEntries {
		users = users[:authtestMaxListEntries]
		listTruncated = true
	}
	if len(passes) > authtestMaxListEntries {
		passes = passes[:authtestMaxListEntries]
		listTruncated = true
	}

	cfg := authtest.Config{
		LoginURL:      loginURL,
		Method:        strings.ToUpper(strings.TrimSpace(r.FormValue("method"))),
		UserField:     strings.TrimSpace(r.FormValue("user_field")),
		PassField:     strings.TrimSpace(r.FormValue("pass_field")),
		Usernames:     users,
		Passwords:     passes,
		FailMarker:    strings.TrimSpace(r.FormValue("fail_marker")),
		SuccessMarker: strings.TrimSpace(r.FormValue("success_marker")),
		TestSession:   r.FormValue("test_session") == "on",
		ResetURL:      strings.TrimSpace(r.FormValue("reset_url")),
		Mode:          mode,
		SniperField:   strings.TrimSpace(r.FormValue("sniper_field")),
		DelayPerUser:  parseDuration("delay_per_user"),
		DelayPerPass:  parseDuration("delay_per_pass"),
		MaxAttempts:   maxAttempts,
		Concurrency:   conc,
		Timeout:       opts.Timeout,
		// Audit MEDIUM fix: expose form/json body encoding + template so
		// modern SPA / API / SSO login endpoints (which reject
		// application/x-www-form-urlencoded with 400/415) can be tested
		// without shelling out to Burp. JSONTemplate uses {USER} / {PASS}
		// placeholders that scanner.go json-escapes at render time.
		BodyEncoding: strings.ToLower(strings.TrimSpace(r.FormValue("body_encoding"))),
		JSONTemplate: strings.TrimSpace(r.FormValue("json_template")),
	}
	if cfg.Method == "" {
		cfg.Method = "POST"
	}

	// Audit MEDIUM fix: progress total was a ClusterBomb-only formula, so
	// every other mode produced a wildly wrong fraction (bar appeared
	// stalled). Compute the attack-pair count per mode and add the
	// userenum / baseline / optional probe attempts to match what Scan()
	// will actually do.
	attempts := authtest.AttackPairCount(cfg)
	if cfg.MaxAttempts > 0 && cfg.MaxAttempts < attempts {
		attempts = cfg.MaxAttempts
	}
	total := attempts + len(cfg.Usernames) /* userenum */ + 1 /* baseline */
	if cfg.TestSession {
		total += 2
	}
	if cfg.ResetURL != "" {
		total += 3
	}

	// Audit MEDIUM fix: redact passwords before serializing the launch
	// config into scans.config — Restart replays the JSON, and the
	// plaintext list shouldn't sit in SQLite forever (DB backups, log
	// snapshots, workspace exports). The persisted cfg keeps the COUNT
	// (so Restart's UI can show "10 passwords were used"); the
	// in-memory cfg used by the running goroutine still has them.
	persistCfg := cfg
	if len(persistCfg.Passwords) > 0 {
		masked := make([]string, len(persistCfg.Passwords))
		for i := range persistCfg.Passwords {
			masked[i] = "***REDACTED***"
		}
		persistCfg.Passwords = masked
	}
	cfgJSON, _ := json.Marshal(persistCfg)
	scan, err := h.db.CreateScan(ws.ID, "authtest", string(cfgJSON), total)
	if err != nil {
		http.Redirect(w, r, "/modules/authtest?error=db_error", http.StatusSeeOther)
		return
	}
	// Sequential scanning: if the operator ticked "start after the current
	// scan finishes" and this workspace is busy, park this run as queued.
	if h.queueIfSequential(w, r, scan) {
		return
	}
	go h.runAuthTest(scan.ID, cfg, opts)
	if listTruncated {
		http.Redirect(w, r, "/modules/authtest/results/"+scan.ID+"?warn=list_truncated", http.StatusSeeOther)
		return
	}
	http.Redirect(w, r, "/modules/authtest/results/"+scan.ID, http.StatusSeeOther)
}

func (h *Handler) AuthTestResults(w http.ResponseWriter, r *http.Request) {
	scanID := strings.TrimPrefix(r.URL.Path, "/modules/authtest/results/")
	scan, err := h.db.GetScan(scanID)
	if err != nil {
		http.NotFound(w, r)
		return
	}
	data := h.baseData(r, "Auth Test Results - scaNNer", "authtest_results")
	var result authtest.ScanResult
	json.Unmarshal([]byte(scan.Result), &result)
	data["Scan"] = scan
	data["Results"] = result.Results
	h.renderResults(w, r, "authtest_results_inner", data)
}

func (h *Handler) AuthTestStatus(w http.ResponseWriter, r *http.Request) {
	scanID := strings.TrimPrefix(r.URL.Path, "/modules/authtest/status/")
	scan, err := h.db.GetScan(scanID)
	if err != nil {
		http.NotFound(w, r)
		return
	}
	h.writeScanStatus(w, scan)
}

func (h *Handler) runAuthTest(scanID string, cfg authtest.Config, opts *shared.HTTPOptions) {
	if !h.db.MarkRunning(scanID) {
		return
	}
	opts = h.BeginScan(scanID, opts)
	defer h.FinishScan(scanID)

	// Audit MEDIUM fix: mirror the canonical partial-flush pattern
	// (smbenum.go:151) so a 50×50 cluster-bomb (= 2500 attempts) does NOT
	// hammer SQLite with 2500 full-result blob writes. The closure only
	// updates `latest` under the mutex; a 2s ticker pushes the most
	// recent snapshot. The final UpdateScanResult after Scan() returns
	// flushes the terminal state.
	var latest []byte
	var mu sync.Mutex
	doneCh := make(chan struct{})
	defer close(doneCh) // panic-safe ticker shutdown
	go func() {
		t := time.NewTicker(2 * time.Second)
		defer t.Stop()
		for {
			select {
			case <-doneCh:
				return
			case <-t.C:
				mu.Lock()
				b := latest
				mu.Unlock()
				if b != nil {
					h.db.UpdateScanResult(scanID, string(b))
				}
			}
		}
	}()

	result := authtest.Scan(opts.Ctx, cfg, opts,
		func(done int, msg string) { h.db.UpdateScanProgress(scanID, done, msg) },
		func(p *authtest.ScanResult) {
			b, err := json.Marshal(p)
			if err == nil {
				mu.Lock()
				latest = b
				mu.Unlock()
			}
		})
	resultJSON, _ := json.Marshal(result)
	h.db.UpdateScanResult(scanID, string(resultJSON))

	// Hard-failure surfacing: if every unit errored, mark the scan failed
	// with a translated reason rather than a silent "done" with zero findings.
	if opts.Ctx.Err() == nil {
		var errs []string
		for _, u := range result.Results {
			if u.Error != "" {
				errs = append(errs, u.Error)
			}
		}
		h.markHardFailure(scanID, errs, len(result.Results))
	}
}
