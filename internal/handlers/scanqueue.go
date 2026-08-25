package handlers

import (
	"log"
	"net/http"
	"time"

	"scanner/internal/models"
)

// Sequential scanning ("start after the current scan finishes"). A launch form
// can tick name="run_sequential"; the Run handler then parks the scan as
// ScanQueued instead of dispatching it. This scheduler replays queued scans
// FIFO — at most one per workspace at a time — via the same dispatchRestart
// config-replay the Restart button uses, so a queued run is byte-for-byte the
// run the operator configured.

// scanQueueKick wakes the scheduler immediately (e.g. the moment a scan
// finishes) instead of waiting for the next tick. Buffered depth-1 +
// non-blocking so a kick never blocks the caller and many kicks coalesce into
// one pending pass.
var scanQueueKick = make(chan struct{}, 1)

// kickScanQueue nudges the scheduler to run a dispatch pass now. Safe from any
// goroutine; drops the kick if a pass is already pending.
func kickScanQueue() {
	select {
	case scanQueueKick <- struct{}{}:
	default:
	}
}

// StartScanQueue launches the sequential-scan scheduler goroutine. It ticks
// every few seconds AND wakes on kickScanQueue() (fired by FinishScan), so the
// next queued scan starts within ~1s of the previous one finishing rather than
// up to a full tick later. Started once at boot (cmd/scanner/main.go).
func (h *Handler) StartScanQueue() {
	go func() {
		tick := time.NewTicker(4 * time.Second)
		defer tick.Stop()
		// One pass at boot: a queued scan left over from a previous process
		// (queued survives the orphan sweep) should dispatch as soon as its
		// workspace is idle, without waiting for a fresh kick.
		h.dispatchQueuedScans()
		for {
			select {
			case <-tick.C:
			case <-scanQueueKick:
			}
			h.dispatchQueuedScans()
		}
	}()
}

// dispatchQueuedScans runs one scheduler pass. For each queued scan (oldest
// first) it starts that scan iff its workspace has no running/pending scan and
// we haven't already started one for that workspace this pass. Claiming
// (queued→pending) is atomic, so overlapping passes can't double-dispatch; the
// freshly-claimed row counts as active on the next pass, holding FIFO order
// within a workspace.
func (h *Handler) dispatchQueuedScans() {
	queued, err := h.db.ListQueuedScans()
	if err != nil || len(queued) == 0 {
		return
	}
	startedWS := map[string]bool{}
	for _, s := range queued {
		if startedWS[s.WorkspaceID] {
			continue // already started one for this ws this pass — preserve FIFO
		}
		if h.db.CountActiveScans(s.WorkspaceID) > 0 {
			continue // workspace busy — wait for it to drain
		}
		if !h.db.ClaimQueuedScan(s.ID) {
			continue // another pass already claimed it
		}
		startedWS[s.WorkspaceID] = true
		log.Printf("scan-queue: dispatching queued %s scan %s (ws %s)", s.Module, s.ID, s.WorkspaceID)
		h.dispatchRestart(s.ID, s.Module, s.Config)
	}
}

// queueIfSequential implements the "start after the current scan finishes"
// checkbox (form field run_sequential). A module's Run handler calls it right
// after CreateScan and BEFORE dispatching:
//
//	scan, err := h.db.CreateScan(...)
//	if err != nil { ... }
//	if h.queueIfSequential(w, r, scan) { return }
//	// ... normal BeginScan + go run + redirect
//
// If the box is ticked AND the workspace already has a running/pending scan,
// the just-created row is parked as queued (the scheduler dispatches it later),
// the caller is redirected to the results page, and it returns true so the
// handler stops. If nothing is active there is nothing to wait behind, so it
// returns false and the handler runs the scan immediately.
func (h *Handler) queueIfSequential(w http.ResponseWriter, r *http.Request, scan *models.Scan) bool {
	if scan == nil || scan.ID == "" {
		return false
	}
	if r.FormValue("run_sequential") == "" {
		return false
	}
	if h.db.CountActiveScans(scan.WorkspaceID) == 0 {
		return false // no previous scan to wait for → run now
	}
	h.db.MarkScanQueued(scan.ID, "Queued — waiting for the active scan in this workspace to finish")
	kickScanQueue()
	http.Redirect(w, r, resultsURL(scan.Module, scan.ID), http.StatusSeeOther)
	return true
}
