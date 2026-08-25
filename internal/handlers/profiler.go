package handlers

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"sync"
	"time"

	"scanner/internal/capacity"
	"scanner/internal/sysmon"
)

// Profiling harness (module calibration). For each module it sweeps concurrency
// against the active workspace's targets, samples sysmon to a steady state,
// derives the per-concurrency resource cost + the knee, and writes a measured
// capacity.Profile (persisted to DATA_DIR/module_profiles.json + applied live
// via capacity.SetMeasured).
//
// It launches each run through the REAL run route over localhost with the
// concurrency pinned via capacity.SetForced — so any module that reads
// capacity.Recommend (web tier, techdetect, nuclei) is swept without per-module
// wiring, at the exact concurrency being measured. Config-heavy modules
// (wordlist / templates / auth) are omitted here and stay measured:false until
// added to calibSpecs.

// calibSpec describes how to launch a module for profiling.
type calibSpec struct {
	targetField string     // run-form field carrying the target list
	extra       url.Values // required constant form params
	sweep       []int      // concurrency levels to measure
}

// calibSpecs: modules that run against a bare target/URL list. Extendable.
var calibSpecs = map[string]calibSpec{
	"sslscan":     {targetField: "manual_targets", extra: url.Values{"ports": {"443"}, "starttls": {"none"}}, sweep: []int{5, 10, 20}},
	// aggressive_whatweb=on so the CPU-heavy whatweb(ruby) subprocess actually
	// spawns — the whole point of profiling techdetect (default mode is a light
	// Go GET and would mis-measure it as ports-bound).
	"techdetect":  {targetField: "urls", extra: url.Values{"aggressive_whatweb": {"on"}}, sweep: []int{5, 10, 20, 40}},
	"spider":      {targetField: "urls", extra: url.Values{"max_depth": {"1"}, "max_pages": {"25"}}, sweep: []int{5, 10, 20, 40, 80}},
	"secheaders":  {targetField: "urls", sweep: []int{5, 10, 20, 40, 80}},
	"wafdetect":   {targetField: "manual_targets", sweep: []int{5, 10, 20, 40, 80}},
	"corsscan":    {targetField: "urls", sweep: []int{5, 10, 20, 40, 80}},
	"httpmethods": {targetField: "urls", sweep: []int{5, 10, 20, 40, 80}},
	"graphqlscan": {targetField: "urls", sweep: []int{5, 10, 20, 40}},
	"openredirect": {targetField: "urls", sweep: []int{5, 10, 20, 40, 80}},
	"httpxfind":   {targetField: "targets", extra: url.Values{"mode": {"quick"}}, sweep: []int{20, 50, 100, 150}},
	// nuclei: NO nuclei_level in extra — a level preset pins -c to a fixed number
	// (aggressive=50) and would ignore the swept SetForced value, so leaving the
	// level empty routes -c through capacity.Recommend (which SetForced pins) and
	// makes the sweep actually vary nuclei's worker concurrency. tags=tech keeps
	// each bounded measurement window network-bound and fast (light tech-detect
	// templates) instead of loading the entire CVE corpus; update_templates is
	// deliberately omitted so a window measures request throughput, not a git pull.
	"nuclei": {targetField: "urls", extra: url.Values{"tags": {"tech"}}, sweep: []int{10, 25, 50, 80}},
}

// levelResult is one concurrency level's measurement.
type levelResult struct {
	Conc        int     `json:"conc"`
	PortsDelta  int     `json:"ports_delta"`  // ephemeral ports above baseline
	FinWait2    int     `json:"fin_wait2"`
	CPUDelta    float64 `json:"cpu_delta"`    // busy-core delta (cores*cpu_frac)
	LoadDelta   float64 `json:"load_delta"`
	Throughput  float64 `json:"throughput"`   // progress units/sec
	ErrRate     float64 `json:"err_rate"`
	CeilingHit  bool    `json:"ceiling_hit"`
}

type moduleCalib struct {
	Module  string        `json:"module"`
	Levels  []levelResult `json:"levels"`
	Optimal int           `json:"optimal_conc"`
	Done    bool          `json:"done"`
	Err     string        `json:"err,omitempty"`
}

type calibJob struct {
	mu       sync.Mutex
	running  bool
	stopReq  bool
	started  time.Time
	current  string // module currently being profiled
	curLevel int
	modules  []moduleCalib
	logLines []string
}

func (j *calibJob) stopped() bool {
	j.mu.Lock()
	defer j.mu.Unlock()
	return j.stopReq
}

var calib = &calibJob{}

func (j *calibJob) log(format string, a ...any) {
	line := time.Now().Format("15:04:05") + " " + fmt.Sprintf(format, a...)
	j.mu.Lock()
	j.logLines = append(j.logLines, line)
	if len(j.logLines) > 400 {
		j.logLines = j.logLines[len(j.logLines)-400:]
	}
	j.mu.Unlock()
}

// CalibrateStart kicks off (or reports) a calibration run over the active
// workspace's targets. POST ?modules=a,b (default: all in calibSpecs).
func (h *Handler) CalibrateStart(w http.ResponseWriter, r *http.Request) {
	if r.URL.Query().Get("stop") == "1" {
		calib.mu.Lock()
		calib.stopReq = true
		calib.mu.Unlock()
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{"stopping": true})
		return
	}
	calib.mu.Lock()
	if calib.running {
		calib.mu.Unlock()
		http.Error(w, "calibration already running", http.StatusConflict)
		return
	}
	ws := h.activeWorkspace(r)
	if ws == nil {
		calib.mu.Unlock()
		http.Error(w, "no active workspace", http.StatusBadRequest)
		return
	}
	targets := h.calibTargets(ws.ID)
	if len(targets) < 3 {
		calib.mu.Unlock()
		http.Error(w, "need at least 3 targets in the active workspace to calibrate", http.StatusBadRequest)
		return
	}
	// Enough to keep the semaphore saturated for the measurement window without
	// launching against the entire (possibly 1800+) list each level.
	if len(targets) > 1000 {
		targets = targets[:1000]
	}
	mods := parseCalibModules(r.URL.Query().Get("modules"))
	calib.running = true
	calib.stopReq = false
	calib.started = time.Now()
	calib.modules = nil
	calib.logLines = nil
	calib.mu.Unlock()

	go h.runCalibration(ws.ID, ws.Name, targets, mods)
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(map[string]any{"started": true, "modules": mods, "targets": len(targets)})
}

// CalibrateStatus returns the live calibration progress.
func (h *Handler) CalibrateStatus(w http.ResponseWriter, r *http.Request) {
	calib.mu.Lock()
	defer calib.mu.Unlock()
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(map[string]any{
		"running": calib.running,
		"current": calib.current,
		"level":   calib.curLevel,
		"modules": calib.modules,
		"log":     strings.Join(calib.logLines, "\n"),
	})
}

func parseCalibModules(q string) []string {
	if strings.TrimSpace(q) == "" {
		out := make([]string, 0, len(calibSpecs))
		for m := range calibSpecs {
			out = append(out, m)
		}
		sort.Strings(out)
		return out
	}
	var out []string
	for _, m := range strings.Split(q, ",") {
		if m = strings.TrimSpace(m); m != "" {
			if _, ok := calibSpecs[m]; ok {
				out = append(out, m)
			}
		}
	}
	return out
}

// calibTargets pulls the active workspace's target values (hostnames/URLs).
func (h *Handler) calibTargets(wsID string) []string {
	rows, _ := h.db.ListTargets(wsID, "")
	var out []string
	for _, t := range rows {
		if v := strings.TrimSpace(t.Value); v != "" {
			out = append(out, v)
		}
	}
	return out
}

// runCalibration is the sequential orchestrator (one module at a time; clean
// port pool between runs is essential to the measurement).
func (h *Handler) runCalibration(wsID, wsName string, targets []string, mods []string) {
	defer func() {
		capacity.ClearForced()
		calib.mu.Lock()
		calib.running = false
		calib.current = ""
		calib.mu.Unlock()
		h.persistProfiles()
	}()

	calib.log("calibration start: %d modules, %d targets (ws %s)", len(mods), len(targets), wsName)

	for _, mod := range mods {
		if calib.stopped() {
			calib.log("stopped by operator")
			break
		}
		spec, ok := calibSpecs[mod]
		if !ok {
			continue
		}
		calib.mu.Lock()
		calib.current = mod
		calib.mu.Unlock()
		mc := moduleCalib{Module: mod}

		for _, c := range spec.sweep {
			if calib.stopped() {
				break
			}
			calib.mu.Lock()
			calib.curLevel = c
			calib.mu.Unlock()
			lr, err := h.measureLevel(wsID, mod, spec, targets, c)
			if err != nil {
				calib.log("%s @conc %d: error: %v", mod, c, err)
				continue
			}
			mc.Levels = append(mc.Levels, lr)
			calib.log("%s @conc %d: ports+%d fw2=%d cpu+%.1f tput=%.1f/s err=%.2f/s%s",
				mod, c, lr.PortsDelta, lr.FinWait2, lr.CPUDelta, lr.Throughput, lr.ErrRate, ceilMark(lr.CeilingHit))
			if lr.CeilingHit {
				break // don't push past a resource ceiling
			}
		}

		prof := deriveProfile(mod, mc.Levels)
		mc.Optimal = prof.OptimalConc
		mc.Done = true
		if len(mc.Levels) > 0 {
			capacity.SetMeasured(prof)
			calib.log("%s: measured optimal=%d ports/conc=%.1f cpu/conc=%.3f (%s-bound)",
				mod, prof.OptimalConc, prof.PortsPerConc, prof.CPUFracPerConc, prof.Dominant)
		}
		calib.mu.Lock()
		calib.modules = append(calib.modules, mc)
		calib.mu.Unlock()
		h.persistProfiles()
	}
	calib.log("calibration complete")
}

func ceilMark(hit bool) string {
	if hit {
		return " [CEILING]"
	}
	return ""
}

// measureLevel launches the module at concurrency c, samples sysmon to steady
// state, then stops + drains, returning the level's aggregates.
func (h *Handler) measureLevel(wsID, mod string, spec calibSpec, targets []string, c int) (levelResult, error) {
	limits := sysmon.ReadLimits()
	// warm-up = fin_timeout (ports fill by Little's law), bounded.
	warm := time.Duration(limits.FinTimeout) * time.Second
	if warm < 12*time.Second {
		warm = 12 * time.Second
	}
	if warm > 30*time.Second {
		warm = 30 * time.Second
	}
	window := 20 * time.Second

	base := sysmon.SampleOnce()
	capacity.SetForced(mod, c)
	defer capacity.SetForced(mod, 0)

	scanID, err := h.launchForProfiling(wsID, mod, spec, targets)
	if err != nil {
		return levelResult{}, err
	}
	// ensure teardown
	defer func() {
		h.stopAndDeleteScan(scanID)
		h.drainPorts(limits, base.Ephemeral)
	}()

	sampler := sysmon.NewSampler()
	sampler.Sample()
	deadline := time.Now().Add(warm + window)
	warmUntil := time.Now().Add(warm)
	var ports, fw2 []int
	var cpu, load []float64
	// Throughput over the WHOLE post-warmup window: (progress at end − progress
	// at window start) / elapsed. Per-500ms deltas are mostly 0 (a target
	// completes every ~1-2s), so their median would read 0 even under real work.
	winStartDone := -1
	var winStartT, lastT time.Time
	var lastDone int
	for time.Now().Before(deadline) {
		if calib.stopped() {
			break
		}
		time.Sleep(500 * time.Millisecond)
		s := sampler.Sample()
		now := time.Now()
		done := h.scanProgress(scanID)
		if now.After(warmUntil) {
			ports = append(ports, s.Ephemeral-base.Ephemeral)
			fw2 = append(fw2, s.States.FinWait2)
			cpu = append(cpu, (s.CPUBusyFrac-base.CPUBusyFrac)*float64(max(limits.Cores, 1)))
			load = append(load, s.Load1-base.Load1)
			if winStartDone < 0 {
				winStartDone, winStartT = done, now
			}
			lastDone, lastT = done, now
		}
	}
	var tput float64
	if winStartDone >= 0 {
		if secs := lastT.Sub(winStartT).Seconds(); secs > 0 && lastDone >= winStartDone {
			tput = float64(lastDone-winStartDone) / secs
		}
	}

	lr := levelResult{
		Conc:       c,
		PortsDelta: medianI(ports),
		FinWait2:   medianI(fw2),
		CPUDelta:   medianF(cpu),
		LoadDelta:  medianF(load),
		Throughput: tput,
	}
	// ceiling heuristics: ports > 60% of pool, or load > cores, or cpu delta ~ cores.
	if usable := limits.UsablePorts(); usable > 0 && lr.PortsDelta > int(0.6*float64(usable)) {
		lr.CeilingHit = true
	}
	if limits.Cores > 0 && lr.LoadDelta > float64(limits.Cores) {
		lr.CeilingHit = true
	}
	return lr, nil
}

// launchForProfiling POSTs the module's run form over localhost and returns the
// created scan ID. Concurrency is already pinned via capacity.SetForced.
func (h *Handler) launchForProfiling(wsID, mod string, spec calibSpec, targets []string) (string, error) {
	form := url.Values{}
	for k, v := range spec.extra {
		form[k] = v
	}
	form.Set(spec.targetField, strings.Join(targets, "\n"))
	base := h.selfBaseURL()
	req, _ := http.NewRequest(http.MethodPost, base+"/modules/"+mod+"/run", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.AddCookie(&http.Cookie{Name: activeWSCookie, Value: wsID})
	client := &http.Client{
		Timeout: 15 * time.Second,
		CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
	}
	resp, err := client.Do(req)
	if err != nil {
		return "", err
	}
	defer func() { _, _ = io.Copy(io.Discard, resp.Body); resp.Body.Close() }()
	loc := resp.Header.Get("Location")
	if id := extractUUID(loc); id != "" {
		return id, nil
	}
	return "", fmt.Errorf("no scan id from launch (status %d, loc %q)", resp.StatusCode, loc)
}

func (h *Handler) selfBaseURL() string {
	port := os.Getenv("PORT")
	if port == "" {
		port = "9090"
	}
	return "http://127.0.0.1:" + port
}

func (h *Handler) scanProgress(scanID string) int {
	if s, err := h.db.GetScan(scanID); err == nil && s != nil {
		return s.ProgressDone
	}
	return 0
}

func (h *Handler) stopAndDeleteScan(scanID string) {
	if scanID == "" {
		return
	}
	h.scanMgr.Cancel(scanID)
	h.db.UpdateScanStatus(scanID, "cancelled")
	// remove the profiling scan row so it doesn't clutter the workspace history.
	h.db.DeleteScan(scanID)
}

// drainPorts waits until the ephemeral pool returns near the pre-run baseline
// so the next level starts clean (bounded by ~fin_timeout+5s).
func (h *Handler) drainPorts(limits sysmon.Limits, baseline int) {
	wait := time.Duration(limits.FinTimeout+5) * time.Second
	if wait > 40*time.Second {
		wait = 40 * time.Second
	}
	deadline := time.Now().Add(wait)
	for time.Now().Before(deadline) {
		if sysmon.SampleOnce().Ephemeral <= baseline+50 {
			return
		}
		time.Sleep(time.Second)
	}
}

// deriveProfile turns level measurements into a capacity.Profile: the knee is
// the largest level with a real throughput gain and no ceiling; coefficients
// are the per-concurrency resource cost at the knee.
func deriveProfile(mod string, levels []levelResult) capacity.Profile {
	p := capacity.ProfileFor(mod) // start from the class default (class, caps)
	p.Module = mod
	if len(levels) == 0 {
		return p
	}
	// knee: last level with >=15% throughput gain over the previous and no ceiling.
	knee := levels[0]
	for i, lr := range levels {
		if lr.CeilingHit {
			break
		}
		if i == 0 {
			knee = lr
			continue
		}
		prev := levels[i-1].Throughput
		if prev > 0 && lr.Throughput < prev*1.15 {
			break // throughput flattened → previous level is the knee
		}
		knee = lr
	}
	limits := sysmon.ReadLimits()
	if knee.Conc > 0 {
		if knee.PortsDelta > 0 {
			p.PortsPerConc = float64(knee.PortsDelta) / float64(knee.Conc)
		}
		if knee.CPUDelta > 0 {
			p.CPUFracPerConc = knee.CPUDelta / float64(knee.Conc)
		}
	}
	p.MeasuredFin = limits.FinTimeout
	p.OptimalConc = knee.Conc
	p.Throughput = knee.Throughput
	// dominant resource = whichever ceiling is nearest at the knee.
	p.Dominant = "ports"
	if knee.CPUDelta*2 > float64(max(limits.Cores, 1)) {
		p.Dominant = "cpu"
	}
	// raise MaxSafe to at least the measured knee so the formula can use it.
	if knee.Conc > p.MaxSafe {
		p.MaxSafe = knee.Conc
	}
	p.Measured = true
	return p
}

// LoadPersistedProfiles merges DATA_DIR/module_profiles.json (written by prior
// calibration runs) over the embedded seed. Call once at startup.
func LoadPersistedProfiles() {
	dir := os.Getenv("DATA_DIR")
	if dir == "" {
		dir = "data"
	}
	data, err := os.ReadFile(filepath.Join(dir, "module_profiles.json"))
	if err != nil {
		return
	}
	var f struct {
		Profiles []capacity.Profile `json:"profiles"`
	}
	if json.Unmarshal(data, &f) == nil && len(f.Profiles) > 0 {
		capacity.LoadOverrides(f.Profiles)
	}
}

// persistProfiles writes all measured profiles to DATA_DIR/module_profiles.json.
func (h *Handler) persistProfiles() {
	dir := os.Getenv("DATA_DIR")
	if dir == "" {
		dir = "data"
	}
	path := filepath.Join(dir, "module_profiles.json")
	data, err := json.MarshalIndent(map[string]any{
		"schema_version": 1,
		"profiles":       capacity.MeasuredProfiles(),
	}, "", "  ")
	if err != nil {
		return
	}
	_ = os.WriteFile(path, data, 0644)
}

// --- small helpers ---

var uuidRe = regexp.MustCompile(`[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}`)

// extractUUID returns the first UUID found in s (the scan id in a results URL).
func extractUUID(s string) string { return uuidRe.FindString(s) }

func medianI(xs []int) int {
	if len(xs) == 0 {
		return 0
	}
	s := append([]int(nil), xs...)
	sort.Ints(s)
	return s[len(s)/2]
}

func medianF(xs []float64) float64 {
	if len(xs) == 0 {
		return 0
	}
	s := append([]float64(nil), xs...)
	sort.Float64s(s)
	return s[len(s)/2]
}
