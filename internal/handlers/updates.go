package handlers

import (
	"context"
	"encoding/json"
	"net/http"
	"os/exec"
	"strings"
	"sync"
	"time"

	"scanner/internal/models"
	"scanner/internal/modules/shared"
)

// Settings → "Updates" area. One place to update the data the scanning tools
// rely on: the CVE database (NVD), Nuclei templates, and the WPScan database;
// plus an optional daily/weekly auto-updater. The critical rule (user): an
// update must NOT run while a scan that USES that tool is active — per-tool
// scan-wait. A blocked update is deferred and runs the moment its consumer
// scans drain (woken by kickUpdateQueue() from FinishScan); the user can cancel
// a queued or running update.

// updateSource is one updatable thing. CVE delegates to the existing CVE
// refresh engine (cvedb.go); nuclei/wpscan shell out via shared.Command.
type updateSource struct {
	Key         string
	DisplayName string
	Consumers   []string // module names whose RUNNING scans this update must wait for
	lastKey     string   // settings-KV key holding the RFC3339 last-success time
	toolBin     string   // nuclei/wpscan: the binary (PATH-resolved)
	cmdArgs     []string // nuclei/wpscan: update subcommand
	isCVE       bool
}

// updateSources is the registry. NOTE: Consumers must stay in sync with which
// modules actually use each tool during a scan — if a module starts/stops using
// nuclei/wpscan/the CVE DB, update the relevant list here.
func updateSources() []updateSource {
	return []updateSource{
		{Key: "cvedb", DisplayName: "CVE Database (NVD)", Consumers: []string{"cvematch", "techdetect", "advancedweb"}, lastKey: "cve_db_last_refresh", isCVE: true},
		{Key: "nuclei", DisplayName: "Nuclei templates", Consumers: []string{"nuclei", "portservice", "advancedweb"}, lastKey: "update_last_nuclei", toolBin: "nuclei", cmdArgs: []string{"-update-templates", "-silent"}},
		{Key: "wpscan", DisplayName: "WPScan database", Consumers: []string{"wpscan", "advancedweb"}, lastKey: "update_last_wpscan", toolBin: "wpscan", cmdArgs: []string{"--update", "--no-banner"}},
	}
}

func findUpdateSource(key string) (updateSource, bool) {
	for _, s := range updateSources() {
		if s.Key == key {
			return s, true
		}
	}
	return updateSource{}, false
}

func (s updateSource) available() bool {
	if s.isCVE {
		return true
	}
	_, err := exec.LookPath(s.toolBin)
	return err == nil
}

type updateRunState struct {
	running  bool
	queued   bool // deferred: waiting for a consumer scan to finish
	finished time.Time
	err      string
	lastLine string // last output line (nuclei/wpscan)
	cancel   context.CancelFunc
}

type updateManager struct {
	mu    sync.Mutex
	state map[string]*updateRunState
	kick  chan struct{}
}

var updateMgr = &updateManager{state: map[string]*updateRunState{}, kick: make(chan struct{}, 1)}

func (m *updateManager) ensure(key string) *updateRunState {
	st := m.state[key]
	if st == nil {
		st = &updateRunState{}
		m.state[key] = st
	}
	return st
}

// kickUpdateQueue nudges the update scheduler to run a drain pass now (e.g. the
// moment a scan finishes). Safe from any goroutine; coalesces.
func kickUpdateQueue() {
	select {
	case updateMgr.kick <- struct{}{}:
	default:
	}
}

// relevantScanRunning reports whether any running/pending scan belongs to a
// module that consumes this source's tool (the per-tool scan-wait gate).
func (h *Handler) relevantScanRunning(src updateSource) bool {
	return anyModuleIn(h.db.RunningScanModules(), src.Consumers)
}

// anyModuleIn reports whether any module in `running` is also in `consumers`.
func anyModuleIn(running, consumers []string) bool {
	if len(running) == 0 || len(consumers) == 0 {
		return false
	}
	set := make(map[string]bool, len(running))
	for _, m := range running {
		set[m] = true
	}
	for _, c := range consumers {
		if set[c] {
			return true
		}
	}
	return false
}

func (h *Handler) updateIsRunning(src updateSource) bool {
	if src.isCVE {
		cveRefresh.mu.Lock()
		r := cveRefresh.running
		cveRefresh.mu.Unlock()
		return r
	}
	updateMgr.mu.Lock()
	defer updateMgr.mu.Unlock()
	return updateMgr.ensure(src.Key).running
}

func (h *Handler) updateQueued(key string) bool {
	updateMgr.mu.Lock()
	defer updateMgr.mu.Unlock()
	return updateMgr.ensure(key).queued
}

// startUpdate launches the update immediately. Caller must have already cleared
// the per-tool scan-wait.
func (h *Handler) startUpdate(src updateSource) {
	if h.updateIsRunning(src) {
		return
	}
	if src.isCVE {
		// Modified-only quick refresh; runCVERefresh self-manages the cveRefresh
		// running flag, cancel func, and the last-refresh timestamp.
		go h.runCVERefresh("", true, false)
		return
	}
	updateMgr.mu.Lock()
	st := updateMgr.ensure(src.Key)
	st.running = true
	st.queued = false
	st.err = ""
	st.lastLine = ""
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Minute)
	st.cancel = cancel
	bin, args, lastKey := src.toolBin, append([]string(nil), src.cmdArgs...), src.lastKey
	updateMgr.mu.Unlock()
	go func() {
		defer cancel()
		out, err := shared.Command(ctx, bin, args...).CombinedOutput()
		updateMgr.mu.Lock()
		st.running = false
		st.finished = time.Now()
		st.cancel = nil
		st.lastLine = lastNonEmptyLine(string(out))
		if err != nil {
			st.err = err.Error()
			if st.lastLine != "" {
				st.err = st.lastLine + " (" + err.Error() + ")"
			}
		} else {
			h.db.SetSetting(lastKey, time.Now().UTC().Format(time.RFC3339))
		}
		updateMgr.mu.Unlock()
	}()
}

// tryRunUpdate runs the source now, or DEFERS it (queued) if a consumer scan is
// active. Returns a short status string for the UI.
func (h *Handler) tryRunUpdate(src updateSource) string {
	if !src.available() {
		return "unavailable"
	}
	if h.updateIsRunning(src) {
		return "busy"
	}
	if h.relevantScanRunning(src) {
		updateMgr.mu.Lock()
		updateMgr.ensure(src.Key).queued = true
		updateMgr.mu.Unlock()
		return "deferred"
	}
	h.startUpdate(src)
	return "started"
}

// processUpdateQueue runs any queued source whose consumer scans have drained.
func (h *Handler) processUpdateQueue() {
	for _, src := range updateSources() {
		if !h.updateQueued(src.Key) {
			continue
		}
		if h.relevantScanRunning(src) {
			continue // still blocked
		}
		updateMgr.mu.Lock()
		updateMgr.ensure(src.Key).queued = false
		updateMgr.mu.Unlock()
		if src.available() {
			h.startUpdate(src)
		}
	}
}

func lastNonEmptyLine(s string) string {
	lines := strings.Split(strings.TrimRight(s, "\n"), "\n")
	for i := len(lines) - 1; i >= 0; i-- {
		if t := strings.TrimSpace(lines[i]); t != "" {
			return t
		}
	}
	return ""
}

// --- auto-update scheduler ---

// StartUpdateScheduler launches the background auto-updater (mirrors
// StartScheduledScans). It also drains deferred updates when scans finish (woken
// by kickUpdateQueue). Started once at boot.
func (h *Handler) StartUpdateScheduler() {
	go func() {
		time.Sleep(20 * time.Second) // warmup, don't race init
		tick := time.NewTicker(60 * time.Second)
		defer tick.Stop()
		h.updateSchedulerPass()
		for {
			select {
			case <-tick.C:
			case <-updateMgr.kick:
			}
			h.updateSchedulerPass()
		}
	}()
}

func (h *Handler) updateSchedulerPass() {
	if MemoryPressure() {
		return
	}
	h.processUpdateQueue() // run anything whose consumer scans drained
	s := h.db.GetSettings()
	if !s.UpdateAutoEnabled {
		return
	}
	now := time.Now()
	next := h.updateNextRun()
	if next.IsZero() {
		h.setUpdateNextRun(computeUpdateNext(s, now)) // seed
		return
	}
	if now.Before(next) {
		return
	}
	// Due: queue each enabled+available source (runs now or defers per scan-wait).
	for _, src := range updateSources() {
		if updateSourceEnabled(s, src.Key) && src.available() {
			h.tryRunUpdate(src)
		}
	}
	h.setUpdateNextRun(computeUpdateNext(s, now))
}

func updateSourceEnabled(s models.AppSettings, key string) bool {
	switch key {
	case "cvedb":
		return s.UpdateCVEEnabled
	case "nuclei":
		return s.UpdateNucleiEnabled
	case "wpscan":
		return s.UpdateWpscanEnabled
	}
	return false
}

// computeUpdateNext returns the next auto-update fire time (server local clock),
// reusing the scheduled-scan time helpers.
func computeUpdateNext(s models.AppSettings, from time.Time) time.Time {
	days := allWeekdays()
	if s.EffectiveUpdateCadence() == "weekly" {
		wd := ((s.UpdateWeekday % 7) + 7) % 7
		days = map[time.Weekday]bool{time.Weekday(wd): true}
	}
	n, err := nextClock(from, s.EffectiveUpdateTime(), days)
	if err != nil || n == nil {
		return time.Time{}
	}
	return *n
}

func (h *Handler) updateNextRun() time.Time {
	v := h.db.GetSetting("update_next_run")
	if v == "" {
		return time.Time{}
	}
	t, err := time.Parse(time.RFC3339, v)
	if err != nil {
		return time.Time{}
	}
	return t
}

func (h *Handler) setUpdateNextRun(t time.Time) {
	if t.IsZero() {
		h.db.SetSetting("update_next_run", "")
		return
	}
	h.db.SetSetting("update_next_run", t.UTC().Format(time.RFC3339))
}

// reseedUpdateNextRun recomputes next_run from current settings (call after a
// settings save so a changed time/cadence takes effect immediately).
func (h *Handler) reseedUpdateNextRun() {
	s := h.db.GetSettings()
	if !s.UpdateAutoEnabled {
		h.setUpdateNextRun(time.Time{})
		return
	}
	h.setUpdateNextRun(computeUpdateNext(s, time.Now()))
}

// --- HTTP handlers ---

func (h *Handler) UpdateRun(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "POST only", http.StatusMethodNotAllowed)
		return
	}
	src, ok := findUpdateSource(r.FormValue("source"))
	if !ok {
		http.Error(w, "unknown source", http.StatusBadRequest)
		return
	}
	status := h.tryRunUpdate(src)
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]any{"status": status, "source": src.Key})
}

func (h *Handler) UpdateCancel(w http.ResponseWriter, r *http.Request) {
	src, ok := findUpdateSource(r.FormValue("source"))
	if !ok {
		http.Error(w, "unknown source", http.StatusBadRequest)
		return
	}
	// Drop a deferred (queued) update.
	updateMgr.mu.Lock()
	updateMgr.ensure(src.Key).queued = false
	updateMgr.mu.Unlock()
	// Cancel a running one.
	if src.isCVE {
		cveRefresh.mu.Lock()
		if cveRefresh.cancel != nil {
			cveRefresh.cancel()
			cveRefresh.err = "cancelled by user"
		}
		cveRefresh.mu.Unlock()
	} else {
		updateMgr.mu.Lock()
		if c := updateMgr.ensure(src.Key).cancel; c != nil {
			c()
		}
		updateMgr.mu.Unlock()
	}
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]any{"cancelled": true, "source": src.Key})
}

func (h *Handler) UpdateStatus(w http.ResponseWriter, r *http.Request) {
	out := make([]map[string]any, 0, 3)
	for _, src := range updateSources() {
		m := map[string]any{"key": src.Key, "name": src.DisplayName, "available": src.available()}
		if src.isCVE {
			cveRefresh.mu.Lock()
			m["running"] = cveRefresh.running
			m["error"] = cveRefresh.err
			cveRefresh.mu.Unlock()
			m["queued"] = h.updateQueued(src.Key)
			if lr := h.db.CVECacheLastRefresh(); !lr.IsZero() {
				m["last"] = lr.UTC().Format(time.RFC3339)
			}
		} else {
			updateMgr.mu.Lock()
			st := updateMgr.ensure(src.Key)
			m["running"] = st.running
			m["queued"] = st.queued
			m["error"] = st.err
			m["last_line"] = st.lastLine
			updateMgr.mu.Unlock()
			if v := h.db.GetSetting(src.lastKey); v != "" {
				m["last"] = v
			}
		}
		out = append(out, m)
	}
	resp := map[string]any{"sources": out}
	if nr := h.updateNextRun(); !nr.IsZero() {
		resp["next_run"] = nr.UTC().Format(time.RFC3339)
	}
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(resp)
}
