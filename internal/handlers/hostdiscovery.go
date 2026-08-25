package handlers

import (
	"encoding/json"
	"net/http"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"time"

	"scanner/internal/models"
	"scanner/internal/modules/hostdiscovery"
	"scanner/internal/modules/shared"
)

// targetTokenRe accepts IPv4 / IPv6 (loose) / CIDR / hyphen-range / hostname.
// We deliberately keep this permissive enough for what nmap accepts but strict
// enough to drop garbage / control characters that snuck past TrimSpace.
// shared.SafeTarget further hardens against shell/flag injection at scan
// dispatch time, so this is the per-line shape gate.
var targetTokenRe = regexp.MustCompile(`^[A-Za-z0-9._:\-/]+$`)

// hostDiscoveryMaxTargets bounds the number of post-expansion hosts a single
// submission may produce. One /16 worth (65 536) keeps the worst case at
// roughly 2× nmap subprocesses × concurrency, which is recoverable; beyond
// that a single request can take a host out of service.
const hostDiscoveryMaxTargets = 65536

// hostDiscoveryMaxTargetLines caps how many entries cfg.Targets may contain
// before expansion. Prevents the expand step itself from running away when
// a user pastes a megabyte of /16 lines.
const hostDiscoveryMaxTargetLines = 256

// hostDiscoveryMaxManualBytes caps the raw textarea size BEFORE splitting,
// so we never spend memory tokenising 50 MB of newlines.
const hostDiscoveryMaxManualBytes = 64 * 1024

type hostDiscoveryConfig struct {
	Targets     []string `json:"targets"`
	Scope       string   `json:"scope"`
	PortSpec    string   `json:"port_spec,omitempty"`
	Concurrency int      `json:"concurrency,omitempty"` // 0 → fall back to global Settings
}

func (h *Handler) HostDiscoveryPage(w http.ResponseWriter, r *http.Request) {
	data := h.baseData(r, "Host Discovery - scaNNer", "hostdiscovery")
	ws := data["ActiveWorkspace"].(*models.Workspace)
	scans, _ := h.db.ListScansLite(ws.ID, "hostdiscovery")
	data["Scans"] = scans
	targets, _ := h.db.ListTargets(ws.ID, "")
	data["WSTargets"] = targets
	data["WSTargetGroups"] = h.groupTargetsByList(ws.ID)
	// Audit Q03: surface the global "Network max concurrent" setting as the
	// initial slider/number value so the per-scan form doesn't silently
	// override a deliberate global cap with the old hardcoded default.
	defConc := h.db.GetSettings().EffectiveNetworkMaxConcurrent()
	if defConc < 1 {
		defConc = 10
	}
	if defConc > 50 {
		defConc = 50
	}
	data["DefaultConcurrency"] = defConc
	h.render(w, "layout", data)
}

// parseHostDiscoveryForm parses the launch form. Returns (config, errorCode)
// where errorCode is a friendlyFormError key when the submission must be
// rejected outright (e.g. malformed target token). Empty errorCode means OK.
func parseHostDiscoveryForm(r *http.Request) (hostDiscoveryConfig, string) {
	cfg := hostDiscoveryConfig{}
	addLine := func(line string) string {
		line = strings.TrimSpace(line)
		if line == "" {
			return ""
		}
		// Audit S/Q: cap per-line length (DNS hostname max is 253) and
		// reject anything containing characters outside the target alphabet.
		// shared.SafeTarget runs a stricter shell/flag check later; this is
		// just the shape gate. We allow up to 256 to cover dotted-CIDR.
		if len(line) > 256 {
			return "bad_target"
		}
		if !targetTokenRe.MatchString(line) {
			return "bad_target"
		}
		cfg.Targets = append(cfg.Targets, line)
		return ""
	}
	for _, t := range r.Form["targets"] {
		if code := addLine(t); code != "" {
			return cfg, code
		}
	}
	raw := r.FormValue("manual_targets")
	if len(raw) > hostDiscoveryMaxManualBytes {
		return cfg, "too_many_targets"
	}
	for _, line := range strings.Split(raw, "\n") {
		if code := addLine(line); code != "" {
			return cfg, code
		}
	}
	cfg.Scope = strings.ToLower(strings.TrimSpace(r.FormValue("scope")))
	if cfg.Scope == "" {
		cfg.Scope = "common"
	}
	cfg.PortSpec = strings.TrimSpace(r.FormValue("port_spec"))
	if v, err := strconv.Atoi(strings.TrimSpace(r.FormValue("concurrency"))); err == nil && v >= 1 && v <= 50 {
		cfg.Concurrency = v
	}
	return cfg, ""
}

func (h *Handler) HostDiscoveryRun(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Redirect(w, r, "/modules/hostdiscovery", http.StatusSeeOther)
		return
	}
	r.ParseForm()
	ws := h.activeWorkspace(r)
	cfg, parseErr := parseHostDiscoveryForm(r)
	if parseErr != "" {
		http.Redirect(w, r, "/modules/hostdiscovery?error="+parseErr, http.StatusSeeOther)
		return
	}
	if len(cfg.Targets) == 0 {
		http.Redirect(w, r, "/modules/hostdiscovery?error=no_targets", http.StatusSeeOther)
		return
	}
	// Audit S/Q: cap raw target line count to bound the pre-expand cost.
	if len(cfg.Targets) > hostDiscoveryMaxTargetLines {
		http.Redirect(w, r, "/modules/hostdiscovery?error=too_many_targets", http.StatusSeeOther)
		return
	}
	if (cfg.Scope == "custom" || cfg.Scope == "range") && cfg.PortSpec != "" && !shared.ValidPortSpec(cfg.PortSpec) {
		http.Redirect(w, r, "/modules/hostdiscovery?error=bad_ports", http.StatusSeeOther)
		return
	}

	// Reject obviously oversize CIDRs (anything wider than /16, i.e. more
	// than 65 536 hosts) up front rather than silently capping them
	// inside ExpandTargets — the previous behaviour passed a `/8` through
	// the scanner as a single string and reported "1 target" while
	// quietly limiting the actual sweep. Now the user gets an explicit
	// error so they can split the range themselves.
	for _, t := range cfg.Targets {
		if slash := strings.IndexByte(t, '/'); slash >= 0 {
			// Parse the bits portion. Non-numeric → let ExpandTargets
			// handle it (probably noop). We only care about valid bit
			// counts that point to a huge block.
			if bits, err := strconv.Atoi(t[slash+1:]); err == nil && bits >= 0 && bits < 16 {
				http.Redirect(w, r, "/modules/hostdiscovery?error=cidr_too_large", http.StatusSeeOther)
				return
			}
		}
	}

	// Progress total = expanded host count so a /24 reports as 256, not 1.
	// cfg.Targets stays as-is (CIDR / range strings) so nmap still gets the
	// efficient batched form. The scanner increments done by len(rows) per
	// target so progress lands accurately.
	// Audit S/Q: also enforce an aggregate cap on the expanded host count
	// — without this a user could submit hundreds of /16 entries and each
	// would spawn 2 nmap subprocesses with full -p- sweeps.
	expanded := shared.ExpandTargets(cfg.Targets, 65536)
	if len(expanded) > hostDiscoveryMaxTargets {
		http.Redirect(w, r, "/modules/hostdiscovery?error=too_many_targets", http.StatusSeeOther)
		return
	}
	totalHosts := len(expanded)
	if totalHosts < len(cfg.Targets) {
		totalHosts = len(cfg.Targets)
	}

	cfgJSON, _ := json.Marshal(cfg)
	scan, err := h.db.CreateScan(ws.ID, "hostdiscovery", string(cfgJSON), totalHosts)
	if err != nil {
		http.Redirect(w, r, "/modules/hostdiscovery?error=db_error", http.StatusSeeOther)
		return
	}
	if h.queueIfSequential(w, r, scan) {
		return
	}
	go h.runHostDiscovery(scan.ID, cfg)
	http.Redirect(w, r, "/modules/hostdiscovery/results/"+scan.ID, http.StatusSeeOther)
}

func (h *Handler) HostDiscoveryResults(w http.ResponseWriter, r *http.Request) {
	scanID := strings.TrimPrefix(r.URL.Path, "/modules/hostdiscovery/results/")
	scan, err := h.db.GetScan(scanID)
	if err != nil {
		http.NotFound(w, r)
		return
	}
	data := h.baseData(r, "Host Discovery Results - scaNNer", "hostdiscovery_results")
	var result hostdiscovery.ScanResult
	json.Unmarshal([]byte(scan.Result), &result)

	upHosts, downHosts, filteredHosts, totalPorts := 0, 0, 0, 0
	for _, tr := range result.Results {
		if !tr.HostUp {
			downHosts++
		} else {
			upHosts++
			if tr.IcmpFiltered {
				filteredHosts++
			}
			totalPorts += tr.OpenCount
		}
	}
	data["Scan"] = scan
	data["Results"] = result.Results
	data["UpHosts"] = upHosts
	data["DownHosts"] = downHosts
	data["FilteredHosts"] = filteredHosts
	data["TotalPorts"] = totalPorts
	h.renderResults(w, r, "hostdiscovery_results_inner", data)
}

func (h *Handler) HostDiscoveryStatus(w http.ResponseWriter, r *http.Request) {
	scanID := strings.TrimPrefix(r.URL.Path, "/modules/hostdiscovery/status/")
	scan, err := h.db.GetScan(scanID)
	if err != nil {
		http.NotFound(w, r)
		return
	}
	h.writeScanStatus(w, scan)
}

func (h *Handler) runHostDiscovery(scanID string, cfg hostDiscoveryConfig) {
	if !h.db.MarkRunning(scanID) {
		return
	}
	ctx := h.scanMgr.Register(scanID)
	defer h.FinishScan(scanID)

	// Concurrency precedence: per-scan form value > global setting >
	// hardcoded default. Hard cap is 50 to match portservice (above this
	// the user needs `ulimit -n 65535` and dedicated infra).
	settings := h.db.GetSettings()
	concurrency := cfg.Concurrency
	if concurrency <= 0 {
		concurrency = settings.EffectiveNetworkMaxConcurrent()
	}
	if concurrency <= 0 {
		concurrency = 10
	}
	if concurrency > 50 {
		concurrency = 50
	}

	scanCfg := hostdiscovery.Config{
		Targets:     cfg.Targets,
		Scope:       hostdiscovery.Scope(cfg.Scope),
		PortSpec:    cfg.PortSpec,
		Concurrency: concurrency,
	}

	// Live result saver. Audit B08: the ticker must be stopped (and any
	// in-flight tick fully drained) BEFORE the final UpdateScanResult call
	// below, otherwise a late tick can clobber the canonical final JSON
	// with a stale snapshot. We use a WaitGroup so the deferred shutdown
	// blocks until the goroutine actually returns.
	var latest []byte
	var mu sync.Mutex
	doneCh := make(chan struct{})
	var tickerWG sync.WaitGroup
	tickerWG.Add(1)
	go func() {
		defer tickerWG.Done()
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

	result := hostdiscovery.Scan(ctx, scanCfg,
		func(done int, msg string) { h.db.UpdateScanProgress(scanID, done, msg) },
		func(p *hostdiscovery.ScanResult) {
			b, err := json.Marshal(p)
			if err == nil {
				mu.Lock()
				latest = b
				mu.Unlock()
			}
		})
	// Shut the ticker down and wait for it to fully exit before writing
	// the canonical final result.
	close(doneCh)
	tickerWG.Wait()
	resJSON, _ := json.Marshal(result)
	h.db.UpdateScanResult(scanID, string(resJSON))

	// Hard-failure surfacing: if every unit errored, mark the scan failed
	// with a translated reason rather than a silent "done" with zero findings.
	if ctx.Err() == nil {
		var errs []string
		for _, tr := range result.Results {
			if tr.Error != "" {
				errs = append(errs, tr.Error)
			}
		}
		h.markHardFailure(scanID, errs, len(cfg.Targets))
	}
}
