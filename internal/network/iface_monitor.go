package network

import (
	"context"
	"log"
	"sync"
	"sync/atomic"
	"time"
)

// CancelAllFn is the contract the scan manager satisfies: cancel every
// running scan with a reason string and return the IDs that were aborted.
// Defined locally so the network package doesn't import handlers (which
// would create a cycle).
type CancelAllFn func(reason string) []string

// MarkScanErrorFn is the contract the DB layer satisfies: stamp a row
// with status=error + a message. Used by the monitor to leave a paper
// trail on every scan it kills.
type MarkScanErrorFn func(scanID, message string)

// Monitor watches the pinned outbound interface and triggers scaNNer's
// app-layer killswitch when it drops:
//
//   - The interface vanishes (link removed, e.g. tun0 deleted).
//   - The interface is no longer UP (admin down or VPN session ended).
//   - The primary IPv4 no longer matches the value cached when settings
//     were saved (VPN reconnect with a new lease).
//
// Any of those conditions abort every running scan via the provided
// CancelAllFn so that subprocess scanners (nmap, nuclei) which had
// their -e flag set to the now-dead interface get SIGKILL'd before
// their next dial attempt. Without the monitor, a long-running scan
// would either silently keep trying to use a dead interface (best
// case — scan stalls) or, if the OS auto-failed-over to the default
// route, leak through it (worst case — exactly what the killswitch
// is supposed to prevent).
//
// Only one Monitor runs at a time per process; calling Start again
// replaces the previous tick loop atomically.
type Monitor struct {
	mu         sync.Mutex
	cancel     context.CancelFunc
	iface      string
	expectIPv4 string
	cancelAll  CancelAllFn
	markErr    MarkScanErrorFn
}

// monitor is the process-singleton instance.
var monitor = &Monitor{}
var monitorRunning atomic.Bool

// StartMonitor (re)launches the killswitch watcher. Call from
// cmd/scanner/main.go at startup AND from handlers.SettingsSave so a
// settings change picks up the new iface. Passing iface="" stops any
// running monitor — that's the default mode.
func StartMonitor(iface, expectIPv4 string, cancelAll CancelAllFn, markErr MarkScanErrorFn) {
	monitor.mu.Lock()
	defer monitor.mu.Unlock()
	// Stop the previous loop, if any.
	if monitor.cancel != nil {
		monitor.cancel()
		monitor.cancel = nil
	}
	if iface == "" {
		monitorRunning.Store(false)
		return
	}
	ctx, cancel := context.WithCancel(context.Background())
	monitor.cancel = cancel
	monitor.iface = iface
	monitor.expectIPv4 = expectIPv4
	monitor.cancelAll = cancelAll
	monitor.markErr = markErr
	monitorRunning.Store(true)
	go monitor.loop(ctx)
}

// IsMonitoring reports whether the killswitch monitor is currently
// running (i.e. the user has pinned a non-default interface).
func IsMonitoring() bool { return monitorRunning.Load() }

// loop polls the pinned interface every 2s. Faster polling would catch
// drops sooner but burn syscalls; slower would let a VPN-drop window
// of traffic leak through. 2s is the sweet spot — bounded leakage
// (typically zero, since in-flight subprocess dials would be the only
// outbound during that window) without polling spam.
func (m *Monitor) loop(ctx context.Context) {
	ticker := time.NewTicker(2 * time.Second)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			m.mu.Lock()
			iface, ip := m.iface, m.expectIPv4
			cancelAll := m.cancelAll
			markErr := m.markErr
			m.mu.Unlock()

			// Two checks per tick:
			//   1. Target interface is still UP + still has expectedIP.
			//   2. Namespace state (veth, iptables rules, ns exists) is
			//      intact. The namespace HealthCheck only runs if the
			//      killswitch is active (default-mode monitors skip it).
			var trigger string
			if err := CheckInterfaceUp(iface, ip); err != nil {
				trigger = "interface check failed: " + err.Error()
			} else if IsActive() {
				if err := HealthCheck(iface, ip); err != nil {
					trigger = "namespace health failed: " + err.Error()
				}
			}
			if trigger != "" {
				log.Printf("killswitch: %s — aborting all running scans", trigger)
				if cancelAll != nil {
					reason := "Interface " + iface + " went down — scan aborted by killswitch"
					killed := cancelAll(reason)
					if markErr != nil {
						for _, id := range killed {
							markErr(id, "killswitch: "+trigger)
						}
					}
				}
				// Stop polling — operator must restore the interface and
				// re-save Settings (which triggers a fresh StartMonitor).
				// Continuing the tick loop would spam logs.
				monitorRunning.Store(false)
				return
			}
		}
	}
}
