package shared

import (
	"context"
	"sync"
	"sync/atomic"
	"syscall"
	"time"
)

// Process-wide adaptive network throttle. The network-health governor
// (internal/handlers/connectivity.go) installs a throttle when it detects the
// operator's link/VPN degrading mid-scan; every BoundDialer honors it "by
// construction" via ControlContext, so ALL Go-side outbound connections slow
// down from a single place — no per-module change. Mirrors the globalLocalAddr
// process-wide-value pattern in httpopt.go.

type netThrottle struct {
	mu       sync.Mutex
	next     time.Time
	interval time.Duration // minimum spacing between new connections
	delay    time.Duration // extra fixed pause per new connection
}

var networkThrottle atomic.Pointer[netThrottle]

// Two independent throttle DEMANDS feed the single installed throttle: the
// network-health governor (link/VPN degraded) and the port-pressure monitor
// (ephemeral pool nearing exhaustion). The effective throttle is the STRICTER
// of the two (largest spacing + largest delay), so one source clearing never
// unthrottles while the other still demands it.
type throttleDemand struct {
	interval time.Duration
	delay    time.Duration
}

const (
	throttleSrcNetwork = 0
	throttleSrcPorts   = 1
)

var (
	demandMu sync.Mutex
	demands  [2]throttleDemand
)

func setThrottleSource(idx int, interval, delay time.Duration) {
	demandMu.Lock()
	demands[idx] = throttleDemand{interval: interval, delay: delay}
	var eff throttleDemand
	for _, d := range demands {
		if d.interval > eff.interval {
			eff.interval = d.interval
		}
		if d.delay > eff.delay {
			eff.delay = d.delay
		}
	}
	demandMu.Unlock()
	if eff.interval <= 0 && eff.delay <= 0 {
		networkThrottle.Store(nil)
		return
	}
	networkThrottle.Store(&netThrottle{interval: eff.interval, delay: eff.delay})
}

// SetNetworkThrottle installs (or clears) the network-health governor's throttle
// demand (source 0). interval spaces out new connections (rate limit); delay
// adds a fixed pause per connection. interval<=0 && delay<=0 clears this source.
func SetNetworkThrottle(interval, delay time.Duration) {
	setThrottleSource(throttleSrcNetwork, interval, delay)
}

// SetPortThrottle installs (or clears) the port-pressure monitor's throttle
// demand (source 1), engaged when the ephemeral-port pool nears exhaustion.
func SetPortThrottle(interval, delay time.Duration) {
	setThrottleSource(throttleSrcPorts, interval, delay)
}

// NetworkThrottled reports whether a throttle is currently installed.
func NetworkThrottled() bool { return networkThrottle.Load() != nil }

// throttleExemptKey marks a dial context that must bypass the throttle — used by
// the connectivity health probe so its own dials measure the REAL network, not
// the throttled one (otherwise a heavy throttle could make the probe time out
// and never detect recovery).
type throttleExemptKey struct{}

// WithoutThrottle returns a context whose dials bypass the network throttle.
func WithoutThrottle(ctx context.Context) context.Context {
	return context.WithValue(ctx, throttleExemptKey{}, true)
}

// throttleGate blocks (respecting ctx) to enforce the current throttle before a
// connection proceeds. Fast path (no throttle installed) returns immediately.
func throttleGate(ctx context.Context) error {
	t := networkThrottle.Load()
	if t == nil {
		return nil
	}
	if ctx != nil && ctx.Value(throttleExemptKey{}) != nil {
		return nil
	}
	t.mu.Lock()
	now := time.Now()
	start := t.next
	if start.Before(now) {
		start = now
	}
	t.next = start.Add(t.interval)
	t.mu.Unlock()
	wait := time.Until(start) + t.delay
	if wait <= 0 {
		return nil
	}
	tm := time.NewTimer(wait)
	defer tm.Stop()
	select {
	case <-tm.C:
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}

// throttleControl is the net.Dialer.ControlContext hook BoundDialer installs on
// every dialer so the throttle applies to all Go-side outbound connections.
func throttleControl(ctx context.Context, network, address string, c syscall.RawConn) error {
	return throttleGate(ctx)
}
