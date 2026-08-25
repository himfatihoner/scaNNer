package handlers

import (
	"testing"
	"time"
)

func TestClassifyNetHealth(t *testing.T) {
	cases := []struct {
		name string
		s    netSample
		want netHealth
	}{
		{"all-good", netSample{reachable: 3, dnsOK: true, dnsLatency: 100 * time.Millisecond}, netHealthy},
		{"nothing-reachable", netSample{reachable: 0}, netDown},
		{"majority-down", netSample{reachable: 1, dnsOK: true, dnsLatency: 100 * time.Millisecond}, netDegraded},
		{"dns-failing", netSample{reachable: 3, dnsOK: false, dnsLatency: connDNSTimeout}, netDegraded},
		// The exact VPN-drop incident: TCP still works, but the system resolver
		// stalls ~8s on dead nameservers → must be DEGRADED, not healthy.
		{"dns-slow-incident", netSample{reachable: 3, dnsOK: true, dnsLatency: 8 * time.Second}, netDegraded},
	}
	for _, c := range cases {
		if got := classify(c.s); got != c.want {
			t.Errorf("%s: classify(%+v) = %v, want %v", c.name, c.s, got, c.want)
		}
	}
}
