package shared

import (
	"sync"
	"sync/atomic"
	"time"
)

// PartialThrottler rate-limits expensive partial-result callbacks at the
// source. Audit S2: every scaNNer module called `partial(snap)` per URL
// completion, where snap was a deep-copy of the entire result slice.
// With N URLs that's O(N) snapshots each costing O(N) copy + O(N) JSON
// marshal in the handler — total O(N²) hot-path work. The 2-second
// ticker in the handler rate-limits DB writes, but the marshal already
// happened. Throttling at the source drops everything inside the gap.
//
// Usage:
//
//	t := shared.NewPartialThrottler(2 * time.Second)
//	pushPartial := func() {
//	    if !t.ShouldFire() {
//	        return
//	    }
//	    // expensive snapshot + partial(snap) ...
//	}
//
// ShouldFire is goroutine-safe; concurrent calls during the cooldown
// window all see false. A pending Force() guarantees the next call
// returns true (used so the final result after Scan returns is never
// skipped).
type PartialThrottler struct {
	interval time.Duration
	last     atomic.Int64 // unix nanos of last fired call
	force    atomic.Bool  // one-shot bypass; cleared on consume
	mu       sync.Mutex   // serializes near-tie ShouldFire races
}

// NewPartialThrottler builds a throttler that fires at most once per
// `interval`. An interval <= 0 falls back to 2 seconds (matches the
// existing handler-side ticker convention).
func NewPartialThrottler(interval time.Duration) *PartialThrottler {
	if interval <= 0 {
		interval = 2 * time.Second
	}
	return &PartialThrottler{interval: interval}
}

// ShouldFire returns true if at least `interval` has elapsed since the
// last fire (or if Force was called since the last fire). Callers that
// get true should proceed to do the expensive snapshot+partial work;
// false means another goroutine already won the slot or the cooldown
// hasn't elapsed.
//
// The first call after construction always fires (zero-value last).
func (p *PartialThrottler) ShouldFire() bool {
	if p.force.Swap(false) {
		p.last.Store(time.Now().UnixNano())
		return true
	}
	now := time.Now().UnixNano()
	last := p.last.Load()
	if last == 0 || now-last >= int64(p.interval) {
		// Serialize the CAS so two goroutines hitting the gap at the
		// same nanosecond don't both fire. The mutex is uncontended
		// outside that narrow race.
		p.mu.Lock()
		defer p.mu.Unlock()
		// Re-read inside the lock — another goroutine may have just won.
		last = p.last.Load()
		if last == 0 || now-last >= int64(p.interval) {
			p.last.Store(now)
			return true
		}
	}
	return false
}

// Force schedules the next ShouldFire call to return true regardless of
// the interval. Use at scan end so the final result snapshot always
// reaches the handler.
func (p *PartialThrottler) Force() {
	p.force.Store(true)
}
