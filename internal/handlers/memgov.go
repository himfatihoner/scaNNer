package handlers

// Memory governor — the scanner's self-preservation against the kernel
// OOM-killer. A wide scan (e.g. an all-port httpx over ~1800 hosts) can balloon
// resident memory until the kernel SIGKILLs the process; on restart the still-
// "running" scan row gets the generic MarkOrphanedScans "server restarted"
// message, hiding the true cause. This monitor samples system memory every
// second and acts BEFORE that happens, leaving a clear memory-specific reason
// on the aborted scan instead.

import (
	"fmt"
	"log"
	"runtime"
	"runtime/debug"
	"runtime/pprof"
	"sync/atomic"
	"time"

	"scanner/internal/sysmon"
)

const (
	// 500ms (was 1s): a wide sweep can grow the resident set by GBs/sec, so a
	// 1s tick sometimes read "still OK" and the kernel OOM-killer fired before
	// the next sample — leaving the misleading orphan "server restarted" instead
	// of a clean governed abort. Sampling twice as often gives the governor a
	// real chance to abort BEFORE the kernel does.
	memGovInterval   = 500 * time.Millisecond
	memGovSoftAvail  = 0.18 // MemAvailable below this fraction → reclaim + hold new scans
	// 0.12 (was 0.09): abort with more headroom below the kernel OOM point. On a
	// 32 GB box 0.09 leaves only ~2.9 GB when we start aborting — a fast sweep can
	// cross that to zero within a tick or two. 0.12 (~3.8 GB) buys the abort +
	// FreeOSMemory time to actually release before the kernel steps in.
	memGovHardAvail  = 0.12 // below this → abort running scans before the OOM-killer
	memGovClearAvail = 0.28 // recover above this to clear the pressure state (hysteresis)
)

// memPressure is set while the governor sees low memory; dispatchQueuedScans
// consults it so no NEW scan is launched into a memory-starved box.
var memPressure atomic.Bool

// MemoryPressure reports whether the governor currently sees low available RAM.
func MemoryPressure() bool { return memPressure.Load() }

// StartMemoryGovernor launches the memory self-preservation loop. Two tiers,
// both keyed off MemAvailable (the kernel's own allocatable-without-swap
// estimate — the best OOM predictor, and it also covers off-heap growth from
// scan subprocesses that GOMEMLIMIT can't see):
//
//   - SOFT (avail < memGovSoftAvail): force-reclaim OS memory (GC +
//     FreeOSMemory) and raise memPressure so the queue holds NEW scans.
//   - HARD (avail < memGovHardAvail): abort every RUNNING scan with a clear
//     memory reason, so the operator sees the real cause, not "server restarted".
func (h *Handler) StartMemoryGovernor() {
	if sysmon.ReadMemory().TotalBytes <= 0 {
		return // non-Linux / unreadable — nothing to govern
	}
	go func() {
		tick := time.NewTicker(memGovInterval)
		defer tick.Stop()
		soft := false
		for range tick.C {
			m := sysmon.ReadMemory()
			if m.TotalBytes <= 0 {
				continue
			}
			avail := m.AvailFrac()
			pct := int(avail * 100)

			switch {
			case avail < memGovHardAvail:
				// Critical — abort running scans before the kernel does it for us.
				// Attach a self-diagnosing breakdown so a repeat failure tells us
				// WHAT ballooned without needing a profiler or logs on the box:
				//   - high Go-heap MB  → in-process buffers/results (GOMEMLIMIT's job)
				//   - RSS ≫ heap       → off-heap: goroutine stacks, cgo/DNS OS threads,
				//                         socket buffers — which GOMEMLIMIT can't bound
				//   - huge goroutine/thread counts → a concurrency/leak problem
				// runFullMode's terminal "done" progress is guarded by !opts.Done(),
				// so this reason survives in progress_msg instead of being overwritten.
				var ms runtime.MemStats
				runtime.ReadMemStats(&ms)
				ngo := runtime.NumGoroutine()
				nthr := pprof.Lookup("threadcreate").Count()
				reason := fmt.Sprintf("Scan aborted — the server was almost out of memory (%d%% RAM free; RSS %d MB, Go heap %d MB, %d goroutines, %d OS threads). Narrow the scope: fewer hosts, a smaller port range, or a lower \"Max concurrent\". [If RSS ≫ Go heap the growth is off-heap: sockets / DNS threads / goroutine stacks.]",
					pct, m.RSSBytes>>20, ms.HeapInuse>>20, ngo, nthr)
				if ids := h.scanMgr.CancelAll(reason); len(ids) > 0 {
					log.Printf("⚠ MEMORY CRITICAL: %d%% free — aborted %d scan(s); RSS %dMB heap %dMB goroutines %d threads %d",
						pct, len(ids), m.RSSBytes>>20, ms.HeapInuse>>20, ngo, nthr)
					for _, id := range ids {
						h.db.MarkScanError(id, reason)
					}
				}
				runtime.GC()
				debug.FreeOSMemory()
				memPressure.Store(true)
				soft = true

			case avail < memGovSoftAvail:
				if !soft {
					log.Printf("⚠ MEMORY LOW: %d%% RAM free — reclaiming and holding new scans", pct)
				}
				runtime.GC()
				debug.FreeOSMemory()
				memPressure.Store(true)
				soft = true

			default:
				if soft && avail > memGovClearAvail {
					log.Printf("MEMORY: %d%% RAM free — pressure cleared", pct)
					memPressure.Store(false)
					soft = false
				}
			}
		}
	}()
}
