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
	"sync/atomic"
	"time"

	"scanner/internal/sysmon"
)

const (
	memGovInterval   = 1 * time.Second
	memGovSoftAvail  = 0.18 // MemAvailable below this fraction → reclaim + hold new scans
	memGovHardAvail  = 0.09 // below this → abort running scans before the OOM-killer
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
				reason := fmt.Sprintf("Scan aborted — the server was almost out of memory (%d%% RAM free; scanner using %d MB). Narrow the scope: scan fewer hosts or a smaller port range at once.",
					pct, m.RSSBytes>>20)
				if ids := h.scanMgr.CancelAll(reason); len(ids) > 0 {
					log.Printf("⚠ MEMORY CRITICAL: %d%% RAM free — aborted %d scan(s) before OOM", pct, len(ids))
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
