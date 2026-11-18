package handlers

import (
	"log"
	"time"

	"scanner/internal/models"
)

// Scheduled-scan runner. A boot-time goroutine (mirrors StartScanQueue) that
// ticks on the server clock and fires every due schedule by replaying its stored
// config through the same CreateScan → dispatchRestart seam the Restart button
// and the sequential queue use. Started once in cmd/scanner/main.go. Like the
// other heartbeat loops it dies with the process (no explicit stop).

// StartScheduledScans launches the schedule runner. ~30s cadence is plenty —
// schedules fire on minute/hour/day boundaries, not seconds.
func (h *Handler) StartScheduledScans() {
	go func() {
		tick := time.NewTicker(30 * time.Second)
		defer tick.Stop()
		h.dispatchDueSchedules() // one pass at boot (catch up anything missed while down)
		for range tick.C {
			h.dispatchDueSchedules()
		}
	}()
}

// dispatchDueSchedules runs one pass: every enabled schedule whose next_run has
// arrived is fired (unless its previous run is still active, or memory is under
// pressure), then its next_run is advanced / the one-time schedule disabled.
func (h *Handler) dispatchDueSchedules() {
	now := time.Now()
	due, err := h.db.ListDueScheduledScans(now)
	if err != nil || len(due) == 0 {
		return
	}
	for _, s := range due {
		if MemoryPressure() {
			// Hold new scans until the governor clears; next_run stays due so the
			// next tick retries.
			return
		}
		// Overlap guard: never stack a schedule on top of its own still-running
		// previous fire. Skip this occurrence and advance to the next slot.
		if s.LastScanID != "" {
			if prev, gerr := h.db.GetScan(s.LastScanID); gerr == nil && prev != nil {
				switch prev.Status {
				case models.ScanRunning, models.ScanPending, models.ScanPaused, models.ScanQueued:
					log.Printf("scheduler: schedule %s (%s) skipped — previous scan %s still %s",
						s.ID, s.Module, prev.ID, prev.Status)
					h.advanceSchedule(s, now, "skipped_overlap", "")
					continue
				}
			}
		}
		// Fire: new scan row from the stored config, then the generic dispatch.
		scan, cerr := h.db.CreateScan(s.WorkspaceID, s.Module, s.Config, s.TotalTargets)
		if cerr != nil {
			log.Printf("scheduler: CreateScan for schedule %s failed: %v", s.ID, cerr)
			h.advanceSchedule(s, now, "error", "")
			continue
		}
		h.db.AddAudit(models.AuditEntry{
			Username:    "scheduler",
			Category:    models.AuditScan,
			Action:      "scan.scheduled",
			Module:      s.Module,
			WorkspaceID: s.WorkspaceID,
			ScanID:      scan.ID,
		})
		log.Printf("scheduler: firing schedule %s (%s, ws %s) → scan %s", s.ID, s.Module, s.WorkspaceID, scan.ID)
		h.dispatchRestart(scan.ID, s.Module, s.Config)
		h.advanceSchedule(s, now, "launched", scan.ID)
	}
}

// advanceSchedule records the outcome of one fire: a one-time schedule disables
// itself; a recurring one gets its next_run recomputed (and disables itself if
// the spec becomes invalid). scanID != "" means a scan was actually launched (it
// is stamped as last_scan_id); "" means the occurrence was skipped.
func (h *Handler) advanceSchedule(s models.ScheduledScan, now time.Time, status, scanID string) {
	if s.Kind == models.ScheduleOnce {
		if scanID != "" {
			h.db.RecordScheduleRun(s.ID, scanID, now, nil, false, status)
		} else {
			h.db.AdvanceSchedule(s.ID, nil, false, status)
		}
		return
	}
	next, err := computeNextRun(s, now)
	if err != nil {
		log.Printf("scheduler: schedule %s next-run error: %v — disabling", s.ID, err)
		h.db.AdvanceSchedule(s.ID, nil, false, "error")
		return
	}
	if scanID != "" {
		h.db.RecordScheduleRun(s.ID, scanID, now, next, true, status)
	} else {
		h.db.AdvanceSchedule(s.ID, next, true, status)
	}
}
