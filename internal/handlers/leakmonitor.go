package handlers

import (
	"bufio"
	"log"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"
)

// leakLogPath is <DATA_DIR>/leakwatch.log (where scripts/leakwatch.py writes).
func leakLogPath() string {
	return filepath.Join(lrDataDir(), "leakwatch.log")
}

// leakAlertState is the process-wide "a DNS leak was detected" flag. It is
// driven by the leak-watch log (scripts/leakwatch.py) and surfaced live in the
// header banner via /api/health. When it trips, the monitor also cancels every
// running scan — a leak mid-scan is exactly when to stop, mirroring a killswitch
// trip. Cleared by an admin via /leak-report/ack once handled.
type leakAlertState struct {
	mu     sync.Mutex
	active bool
	detail string
	ts     string
	count  int
}

var leakAlert leakAlertState

func (l *leakAlertState) trip(detail, ts string) {
	l.mu.Lock()
	l.active = true
	l.detail = detail
	l.ts = ts
	l.count++
	l.mu.Unlock()
}

func (l *leakAlertState) snapshot() (active bool, detail, ts string, count int) {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.active, l.detail, l.ts, l.count
}

func (l *leakAlertState) clear() {
	l.mu.Lock()
	l.active = false
	l.mu.Unlock()
}

// StartLeakMonitor tails <DATA_DIR>/leakwatch.log; on a NEW "LEAK" line it trips
// the header banner AND cancels running scans (marking them errored with the
// reason). Only lines written AFTER the monitor starts count, so a restart
// doesn't re-alert on historical entries. If the log doesn't exist yet
// (leakwatch not installed) it just idles — no error. Started once at boot.
func (h *Handler) StartLeakMonitor() {
	go func() {
		path := leakLogPath()
		var offset int64
		if fi, err := os.Stat(path); err == nil {
			offset = fi.Size() // start at EOF: only new leaks alert
		}
		ticker := time.NewTicker(4 * time.Second)
		defer ticker.Stop()
		for range ticker.C {
			f, err := os.Open(path)
			if err != nil {
				continue // log not created yet — leakwatch service not installed
			}
			fi, err := f.Stat()
			if err != nil {
				f.Close()
				continue
			}
			if fi.Size() < offset {
				offset = 0 // rotated / truncated — reread from the start
			}
			if _, err := f.Seek(offset, 0); err != nil {
				f.Close()
				continue
			}
			sc := bufio.NewScanner(f)
			sc.Buffer(make([]byte, 0, 64*1024), 1024*1024)
			for sc.Scan() {
				line := sc.Text()
				offset += int64(len(line)) + 1
				if !strings.Contains(line, " LEAK ") { // ignore STATE/UNPROTECTED/etc.
					continue
				}
				ts, detail := parseLeakLine(line)
				h.onLeak(ts, detail)
			}
			f.Close()
		}
	}()
}

func parseLeakLine(line string) (ts, detail string) {
	fields := strings.Fields(line)
	if len(fields) > 0 {
		ts = fields[0]
	}
	var parts []string
	for _, f := range fields {
		for _, k := range []string{"iface=", "query=", "target=", "vpn="} {
			if strings.HasPrefix(f, k) {
				parts = append(parts, f)
			}
		}
	}
	detail = strings.Join(parts, " ")
	if detail == "" {
		detail = line
	}
	return ts, detail
}

// onLeak trips the banner and stops running scans. CancelAll is idempotent —
// a burst of LEAK lines from one leaking scan cancels once, then no-ops.
func (h *Handler) onLeak(ts, detail string) {
	leakAlert.trip(detail, ts)
	reason := "DNS leak detected — scan stopped (" + detail + ")"
	log.Printf("⚠ LEAK detected: %s — cancelling running scans", detail)
	for _, id := range h.scanMgr.CancelAll(reason) {
		h.db.MarkScanError(id, reason)
	}
}

// LeakAck clears the header leak banner (admin-only, gated by the /leak-report
// prefix in authorizePath). Same-origin POST — no CSRF token needed.
func (h *Handler) LeakAck(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	leakAlert.clear()
	w.WriteHeader(http.StatusNoContent)
}
