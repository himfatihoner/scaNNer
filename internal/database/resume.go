package database

import (
	"encoding/json"
	"sync"

	"scanner/internal/models"
)

// Resume-base registry (Task 0b/0c). When a paused scan is resumed, the handler
// stashes the already-completed result rows here and re-dispatches the module
// on ONLY the remaining targets. UpdateScanResult then merges the module's
// (remaining-only) writes with this base so the persisted result holds
// old+new — every module gets lossless same-row resume without a bespoke
// resume runner. Cleared when the resumed run finalizes.
var (
	resumeMu    sync.Mutex
	resumeBases = map[string]string{}
)

// SetResumeBase records the completed-rows blob to prepend to every subsequent
// UpdateScanResult for this scan.
func (d *DB) SetResumeBase(scanID, baseResultJSON string) {
	resumeMu.Lock()
	resumeBases[scanID] = baseResultJSON
	resumeMu.Unlock()
}

// ClearResumeBase removes the stash (call when the resumed run finalizes).
func (d *DB) ClearResumeBase(scanID string) {
	resumeMu.Lock()
	delete(resumeBases, scanID)
	resumeMu.Unlock()
}

func (d *DB) getResumeBase(scanID string) string {
	resumeMu.Lock()
	defer resumeMu.Unlock()
	return resumeBases[scanID]
}

// ResumeToPending flips a paused scan back to pending and resets its progress to
// the remaining count, so the re-dispatched run<Module> (which calls MarkRunning
// pending→running and reports done 0..len(remaining)) drives a clean bar.
// Returns false if the row wasn't paused (another trigger already resumed it).
func (d *DB) ResumeToPending(id string, remainingTotal int) bool {
	res, err := d.Exec(
		`UPDATE scans SET status = ?, progress_total = ?, progress_done = 0, finished_at = NULL
		   WHERE id = ? AND status = ?`,
		models.ScanPending, remainingTotal, id, models.ScanPaused)
	if err != nil {
		return false
	}
	n, _ := res.RowsAffected()
	return n > 0
}

// mergeResultArrays concatenates the array-valued fields of the resume base
// (completed rows) with the live remaining-only result, so a resumed scan's
// stored result holds old+new. Scalar fields take the NEW value (e.g.
// truncated/truncate_reason). Handles both shapes in use: an object with array
// fields ({"results":[...]} / {"services":[...]}) and a top-level JSON array
// (sslscan []HostResult). Falls back to the current blob on any parse trouble
// so it can never corrupt a result.
func mergeResultArrays(base, cur string) string {
	if base == "" {
		return cur
	}
	// Top-level array shape.
	var baseArr, curArr []json.RawMessage
	if json.Unmarshal([]byte(base), &baseArr) == nil && json.Unmarshal([]byte(cur), &curArr) == nil {
		merged := append(append([]json.RawMessage{}, baseArr...), curArr...)
		if b, err := json.Marshal(merged); err == nil {
			return string(b)
		}
		return cur
	}
	// Object-with-array-fields shape.
	var baseObj, curObj map[string]json.RawMessage
	if json.Unmarshal([]byte(base), &baseObj) != nil || json.Unmarshal([]byte(cur), &curObj) != nil {
		return cur
	}
	out := map[string]json.RawMessage{}
	for k, v := range curObj {
		out[k] = v // new scalars/arrays win by default
	}
	for k, bv := range baseObj {
		cv, ok := curObj[k]
		if !ok {
			out[k] = bv
			continue
		}
		var ba, ca []json.RawMessage
		if json.Unmarshal(bv, &ba) == nil && json.Unmarshal(cv, &ca) == nil {
			if mb, err := json.Marshal(append(append([]json.RawMessage{}, ba...), ca...)); err == nil {
				out[k] = mb
			}
		}
	}
	if b, err := json.Marshal(out); err == nil {
		return string(b)
	}
	return cur
}

// resumeMergeIfActive is called at the top of UpdateScanResult: if a resume
// base is registered for this scan, merge the incoming (remaining-only) result
// with the completed base. No-op for normal scans.
func (d *DB) resumeMergeIfActive(scanID, result string) string {
	base := d.getResumeBase(scanID)
	if base == "" {
		return result
	}
	return mergeResultArrays(base, result)
}
