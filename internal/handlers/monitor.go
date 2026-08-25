package handlers

import (
	"encoding/json"
	"net/http"
	"sync"
	"time"

	"scanner/internal/modules/shared"
	"scanner/internal/sysmon"
)

// Live performance monitor: a background sampler feeds a ring buffer of OS
// resource pressure (ephemeral ports, socket states, load, CPU) correlated
// with live scan throughput + error rate. The dashboard polls
// /monitor/metrics.json every 2 s and renders it with the existing
// renderLineChart engine. This is the "network infrastructure" view that lets
// the operator see, in real time, how intense and how healthy a scan is.

const (
	perfSampleInterval = 2 * time.Second
	perfRingSize       = 300 // ~10 min at 2 s
	// Port-usage fractions that flip the health badge.
	perfPortDegrade  = 0.50
	perfPortSaturate = 0.75
	// Dynamic backstop: when the ephemeral-port pool crosses ON, space out new
	// connections process-wide until it drains below OFF (hysteresis avoids
	// flapping). This is the safety net if a per-module estimate is too high.
	perfPortThrottleOn   = 0.75
	perfPortThrottleOff  = 0.55
	perfThrottleInterval = 50 * time.Millisecond // ~20 new connects/sec while engaged
	perfThrottleDelay    = 40 * time.Millisecond
)

// perfSample is one ring-buffer row (JSON-tagged for the dashboard poll).
type perfSample struct {
	T           int64   `json:"t"`            // unix milliseconds
	Ephemeral   int     `json:"ephemeral"`    // ephemeral ports in use (machine-wide)
	PortPct     float64 `json:"port_pct"`     // 0..100 of the ephemeral range
	FinWait2    int     `json:"fin_wait2"`
	TimeWait    int     `json:"time_wait"`
	Estab       int     `json:"estab"`
	EphScanner  int     `json:"eph_scanner"` // ephemeral ports held by scaNNer's own process tree
	EphOther    int     `json:"eph_other"`   // ephemeral ports held by OTHER applications
	Load1       float64 `json:"load1"`
	CPUBusy     float64 `json:"cpu_busy"`     // 0..100
	Throughput  float64 `json:"throughput"`   // scan progress units/sec across active scans
	ErrRate     float64 `json:"err_rate"`     // errors/sec across active scans
	ActiveScans int     `json:"active_scans"`
	Health      string  `json:"health"`       // HEALTHY | DEGRADED | SATURATED
}

// perfMonitor holds the ring buffer. Package-level singleton so it needs no
// change to the Handler struct; the sampler goroutine (a Handler method)
// closes over h.db + h.scanMgr and writes here.
type perfMonitor struct {
	mu     sync.RWMutex
	ring   []perfSample
	head   int
	filled bool
	limits sysmon.Limits
}

var perfMon = &perfMonitor{ring: make([]perfSample, perfRingSize)}

func (p *perfMonitor) push(s perfSample, l sysmon.Limits) {
	p.mu.Lock()
	p.ring[p.head] = s
	p.head = (p.head + 1) % perfRingSize
	if p.head == 0 {
		p.filled = true
	}
	p.limits = l
	p.mu.Unlock()
}

// snapshot returns the buffered samples oldest→newest plus the current limits.
func (p *perfMonitor) snapshot() ([]perfSample, sysmon.Limits) {
	p.mu.RLock()
	defer p.mu.RUnlock()
	out := make([]perfSample, 0, perfRingSize)
	if p.filled {
		out = append(out, p.ring[p.head:]...)
	}
	out = append(out, p.ring[:p.head]...)
	return out, p.limits
}

// StartPerfMonitor launches the background sampler. Called once at boot beside
// StartConnectivityMonitor. Cheap (a handful of /proc reads + one DB query per
// 2 s tick).
func (h *Handler) StartPerfMonitor() {
	perfMon.limits = sysmon.ReadLimits()
	go func() {
		s := sysmon.NewSampler()
		s.Sample() // prime the CPU delta
		var prevDone, prevErr int
		var prevT time.Time
		portThrottled := false
		tick := time.NewTicker(perfSampleInterval)
		defer tick.Stop()
		for range tick.C {
			snap := s.Sample()
			limits := sysmon.ReadLimits() // re-read so a mid-session sysctl change is reflected
			done, active := h.db.RunningProgress()
			_, errs := h.scanMgr.PerfAggregate()

			now := time.Now()
			var tput, erate float64
			if !prevT.IsZero() {
				if dt := now.Sub(prevT).Seconds(); dt > 0 {
					if d := done - prevDone; d > 0 {
						tput = float64(d) / dt
					}
					if e := errs - prevErr; e > 0 {
						erate = float64(e) / dt
					}
				}
			}
			prevDone, prevErr, prevT = done, errs, now

			portFrac := snap.PortUsage(limits)
			health := "HEALTHY"
			switch {
			case portFrac >= perfPortSaturate || (limits.Cores > 0 && snap.Load1 > float64(limits.Cores)*1.5):
				health = "SATURATED"
			case portFrac >= perfPortDegrade || (limits.Cores > 0 && snap.Load1 > float64(limits.Cores)):
				health = "DEGRADED"
			}

			// Dynamic port-exhaustion backstop (hysteresis). Coordinates with the
			// connectivity governor via the two-source throttle: stricter wins.
			if !portThrottled && portFrac >= perfPortThrottleOn {
				shared.SetPortThrottle(perfThrottleInterval, perfThrottleDelay)
				portThrottled = true
			} else if portThrottled && portFrac < perfPortThrottleOff {
				shared.SetPortThrottle(0, 0)
				portThrottled = false
			}

			perfMon.push(perfSample{
				T:           now.UnixMilli(),
				Ephemeral:   snap.Ephemeral,
				PortPct:     portFrac * 100,
				FinWait2:    snap.States.FinWait2,
				TimeWait:    snap.States.TimeWait,
				Estab:       snap.States.Estab,
				EphScanner:  snap.EphemeralScanner,
				EphOther:    snap.EphemeralOther,
				Load1:       snap.Load1,
				CPUBusy:     snap.CPUBusyFrac * 100,
				Throughput:  tput,
				ErrRate:     erate,
				ActiveScans: active,
				Health:      health,
			}, limits)
		}
	}()
}

// MonitorMetrics serves the live ring buffer for the dashboard poll.
func (h *Handler) MonitorMetrics(w http.ResponseWriter, r *http.Request) {
	samples, limits := perfMon.snapshot()
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(map[string]any{
		"limits": map[string]any{
			"usable_ports":  limits.UsablePorts(),
			"port_lo":       limits.PortRangeLo,
			"port_hi":       limits.PortRangeHi,
			"fin_timeout":   limits.FinTimeout,
			"tw_reuse":      limits.TWReuse,
			"conntrack_max": limits.ConntrackMax,
			"nofile":        limits.NoFile,
			"cores":         limits.Cores,
		},
		"samples": samples,
	})
}
