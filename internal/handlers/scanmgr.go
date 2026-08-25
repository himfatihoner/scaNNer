package handlers

import (
	"context"
	"strings"
	"sync"

	"scanner/internal/modules/shared"
)

// ScanManager tracks active scan cancellation contexts and per-scan warnings.
type ScanManager struct {
	mu       sync.Mutex
	active   map[string]context.CancelFunc
	warnings map[string]string              // scanID -> latest warning message (sticky until scan ends)
	skipped  map[string]map[string]struct{} // scanID -> set of URL prefixes the user marked as skip
	// opts tracks the HTTPOptions handed to each scan so we can flush
	// its transport idle pools when the scan terminates — Cancel() and
	// Unregister() both walk this map. Module scanners construct their
	// own clients; without explicit cleanup their idle TCP connections
	// linger until Go's GC runs, which can be minutes.
	opts map[string]*shared.HTTPOptions
	// paused marks scans the connectivity monitor cancelled for a PAUSE (not a
	// user Stop or a killswitch error). FinishScan consults WasPaused to stamp
	// 'paused' (preserving partial results) instead of 'done'/'error'. Cleared
	// on Unregister/Cancel so a subsequent resume starts clean.
	paused map[string]bool
}

func NewScanManager() *ScanManager {
	return &ScanManager{
		active:   make(map[string]context.CancelFunc),
		warnings: make(map[string]string),
		skipped:  make(map[string]map[string]struct{}),
		opts:     make(map[string]*shared.HTTPOptions),
		paused:   make(map[string]bool),
	}
}

// RegisterOpts associates a scan with the HTTPOptions instance the
// handler built for it. Idempotent — last call wins per scanID.
func (m *ScanManager) RegisterOpts(scanID string, opts *shared.HTTPOptions) {
	if scanID == "" || opts == nil {
		return
	}
	m.mu.Lock()
	m.opts[scanID] = opts
	m.mu.Unlock()
}

// Register creates a cancellable context for a scan, returns it + stores cancel
func (m *ScanManager) Register(scanID string) context.Context {
	m.mu.Lock()
	defer m.mu.Unlock()
	if cancel, ok := m.active[scanID]; ok {
		cancel()
	}
	ctx, cancel := context.WithCancel(context.Background())
	m.active[scanID] = cancel
	return ctx
}

// Cancel aborts a scan and all its in-flight requests, and closes the
// idle TCP pool of every transport the scan's HTTPOptions handed out
// — so a stopped scan doesn't leave sockets parked open against the
// target waiting for GC.
func (m *ScanManager) Cancel(scanID string) bool {
	m.mu.Lock()
	cancel, ok := m.active[scanID]
	opts := m.opts[scanID]
	if ok {
		cancel()
		delete(m.active, scanID)
	}
	delete(m.opts, scanID)
	delete(m.paused, scanID) // a user Stop overrides any pending pause flag
	m.mu.Unlock()
	if opts != nil {
		opts.CloseIdleConnections()
	}
	return ok
}

// Unregister removes a scan from tracking (on completion / error /
// post-cancel cleanup). Also closes any lingering idle transports the
// scan held — defer FinishScan in the handlers funnels through here.
func (m *ScanManager) Unregister(scanID string) {
	m.mu.Lock()
	cancel, ok := m.active[scanID]
	opts := m.opts[scanID]
	if ok {
		cancel()
		delete(m.active, scanID)
	}
	delete(m.warnings, scanID)
	delete(m.skipped, scanID)
	delete(m.opts, scanID)
	delete(m.paused, scanID)
	m.mu.Unlock()
	if opts != nil {
		opts.CloseIdleConnections()
	}
}

// PauseAll pauses every running scan (connectivity monitor). Like CancelAll it
// cancels each context (subprocesses get SIGKILL, in-flight HTTP aborts), but
// it FIRST marks each scan paused so the run goroutine's FinishScan stamps
// 'paused' — preserving the partial result for resume — instead of 'done'.
// Returns the paused scan IDs.
func (m *ScanManager) PauseAll(reason string) []string {
	m.mu.Lock()
	paused := make([]string, 0, len(m.active))
	doomedOpts := make([]*shared.HTTPOptions, 0, len(m.active))
	for id, cancel := range m.active {
		m.paused[id] = true
		cancel()
		paused = append(paused, id)
		if opts, ok := m.opts[id]; ok {
			doomedOpts = append(doomedOpts, opts)
		}
		m.warnings[id] = reason
		delete(m.active, id)
		delete(m.opts, id)
	}
	m.mu.Unlock()
	for _, o := range doomedOpts {
		o.CloseIdleConnections()
	}
	return paused
}

// WasPaused reports whether PauseAll flagged this scan for a pause (checked by
// FinishScan before it stamps the terminal status).
func (m *ScanManager) WasPaused(scanID string) bool {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.paused[scanID]
}

// SkipPath marks a URL prefix as user-cancelled for a scan. Modules that
// support runtime skipping (currently direnum) consult IsSkipped before
// recursing into subdirectories or before firing in-flight requests.
//
// Audit fix: cap the per-scan skip set so a misbehaving / hostile caller
// cannot grow it without bound (each entry is a heap-allocated string
// key). 1024 covers any realistic scan — a typical site has a few
// dozen distinct directories — while keeping the upper bound finite.
const maxSkipPathsPerScan = 1024

func (m *ScanManager) SkipPath(scanID, urlPrefix string) {
	urlPrefix = strings.TrimSpace(urlPrefix)
	if scanID == "" || urlPrefix == "" {
		return
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	set, ok := m.skipped[scanID]
	if !ok {
		set = map[string]struct{}{}
		m.skipped[scanID] = set
	}
	if _, dup := set[urlPrefix]; !dup && len(set) >= maxSkipPathsPerScan {
		return
	}
	set[urlPrefix] = struct{}{}
}

// IsSkipped reports whether the given URL falls under any path the user
// has marked skip for this scan. A skip on `https://t/admin/` also
// matches `https://t/admin/users/` so a skipped subtree stays skipped
// at deeper recursion levels.
func (m *ScanManager) IsSkipped(scanID, fullURL string) bool {
	m.mu.Lock()
	defer m.mu.Unlock()
	set, ok := m.skipped[scanID]
	if !ok || len(set) == 0 {
		return false
	}
	if _, hit := set[fullURL]; hit {
		return true
	}
	for prefix := range set {
		if strings.HasPrefix(fullURL, prefix) {
			return true
		}
	}
	return false
}

// SkippedPaths returns a copy of the URL prefixes marked skip for a scan
// (used by the UI to render which dirs are already cancelled).
func (m *ScanManager) SkippedPaths(scanID string) []string {
	m.mu.Lock()
	defer m.mu.Unlock()
	set, ok := m.skipped[scanID]
	if !ok {
		return nil
	}
	out := make([]string, 0, len(set))
	for p := range set {
		out = append(out, p)
	}
	return out
}

// SetWarning stores the latest user-visible warning for a scan.
func (m *ScanManager) SetWarning(scanID, msg string) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.warnings[scanID] = msg
}

// Warning returns the current warning string for a scan ("" if none).
func (m *ScanManager) Warning(scanID string) string {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.warnings[scanID]
}

// WarnAll sets (or, with msg=="", clears) the warning on every active scan.
// Used by the network-health governor to surface/clear the "network degraded —
// throttled" banner across all running scans at once.
func (m *ScanManager) WarnAll(msg string) {
	m.mu.Lock()
	defer m.mu.Unlock()
	for id := range m.active {
		if msg == "" {
			delete(m.warnings, id)
		} else {
			m.warnings[id] = msg
		}
	}
}

// ActiveIDs returns a snapshot of every scan ID the manager currently
// considers live. Used by the orphan reaper to compute the
// "running-in-DB but not driven by any goroutine" set — those rows are
// the ones a periodic janitor needs to flip to error.
//
// The slice is a copy; callers can mutate it freely. Order is undefined
// (Go map iteration).
func (m *ScanManager) ActiveIDs() []string {
	m.mu.Lock()
	defer m.mu.Unlock()
	ids := make([]string, 0, len(m.active))
	for id := range m.active {
		ids = append(ids, id)
	}
	return ids
}

// PerfAggregate is a live roll-up across active scans for the performance
// monitor: the number of registered (running) scans and the total probe-error
// count summed over their HTTPOptions. The monitor differentiates the error
// total over time to derive a live error rate.
func (m *ScanManager) PerfAggregate() (active, errors int) {
	m.mu.Lock()
	defer m.mu.Unlock()
	active = len(m.active)
	for _, o := range m.opts {
		if n, _ := o.ErrorSummary(); n > 0 {
			errors += n
		}
	}
	return active, errors
}

// CancelAll triggers the killswitch: every currently-registered scan
// gets its context cancelled and its transport idle pool flushed. Used
// by the runtime iface monitor when the pinned outbound interface
// drops (e.g. VPN disconnect). Returns the number of scans cancelled,
// along with the slice of their IDs so the caller can stamp a status
// message on each DB row.
func (m *ScanManager) CancelAll(reason string) []string {
	m.mu.Lock()
	cancelled := make([]string, 0, len(m.active))
	doomedOpts := make([]*shared.HTTPOptions, 0, len(m.active))
	for id, cancel := range m.active {
		cancel()
		cancelled = append(cancelled, id)
		if opts, ok := m.opts[id]; ok {
			doomedOpts = append(doomedOpts, opts)
		}
		m.warnings[id] = reason
		delete(m.active, id)
		delete(m.opts, id)
	}
	m.mu.Unlock()
	// CloseIdleConnections outside the lock — they may take a few ms.
	for _, o := range doomedOpts {
		o.CloseIdleConnections()
	}
	return cancelled
}
