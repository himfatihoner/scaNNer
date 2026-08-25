package shared

import "sync"

// ProgressTracker wraps a progress emit callback with the three
// safety nets every module needs but few implement:
//
//  1. Clamping — done is capped at total so the UI bar never overshoots
//     (which then visually "snaps back" to 100% when the stage ends).
//  2. Monotonic — done never decreases. Modules that re-scan items or
//     restart phases were producing % values that went backward.
//  3. Message coalescing — empty msg keeps the last non-empty one so
//     transient blank progress ticks don't blank out the status line.
//
// Each module's Scan() takes its own progress callback shape; this
// helper produces a closure compatible with the common
// `func(done int, msg string)` signature. The caller passes the
// upfront total once, then the closure is handed to the scanner.
//
// Lifted from advancedweb/scanner.go where the same pattern lived as
// `stageProgress`. Centralizing here so standalone handlers can use
// the same monotonic clamp behavior the suite stages already enjoy.
type ProgressTracker struct {
	// mu guards the mutable counters. Update() is called concurrently by
	// worker-pool scanners (techdetect's fresh sem=20 path and its
	// parallelized prefetched path both fan Update across goroutines), so
	// the lastDone/lastMsg reads-writes below must be serialized.
	mu       sync.Mutex
	total    int
	lastDone int
	lastMsg  string
	emit     func(done, total int, msg string)
}

// NewProgressTracker builds a tracker that calls `emit` on every
// progress update. emit receives the clamped (done, total, msg).
// total <= 0 means "unknown" — the closure passes done through but
// emit sees total=0 so the UI can render an indeterminate state.
func NewProgressTracker(total int, emit func(done, total int, msg string)) *ProgressTracker {
	return &ProgressTracker{total: total, emit: emit}
}

// Update is the closure-shaped progress callback. Pass this directly
// to scanner.Scan(progress, ...) signatures expecting (done, msg).
func (p *ProgressTracker) Update(done int, msg string) {
	p.mu.Lock()
	if p.total > 0 && done > p.total {
		done = p.total
	}
	if done < p.lastDone {
		done = p.lastDone // monotonic
	}
	p.lastDone = done
	if msg != "" {
		p.lastMsg = msg
	}
	total, emitMsg := p.total, p.lastMsg
	emit := p.emit
	p.mu.Unlock()
	// Call emit OUTSIDE the lock: emit typically grabs the stage's resultMu
	// (and may do a SQLite write), so holding p.mu across it would serialize
	// every worker on this tracker for the whole downstream write.
	if emit != nil {
		emit(done, total, emitMsg)
	}
}

// SetTotal lets the caller update the total mid-scan when it's
// discovered later (e.g. HTTPX learns the real port count only after
// the initial TCP scan). The closure keeps clamping behavior intact.
func (p *ProgressTracker) SetTotal(total int) {
	if total < 0 {
		return
	}
	p.mu.Lock()
	p.total = total
	if p.lastDone > total && total > 0 {
		p.lastDone = total
	}
	p.mu.Unlock()
}

// Snapshot returns the current (done, total, msg) without emitting.
// Useful for partial-save flows that want to peek without triggering
// another UI update.
func (p *ProgressTracker) Snapshot() (int, int, string) {
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.lastDone, p.total, p.lastMsg
}
