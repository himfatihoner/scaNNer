package httpxfind

import (
	"context"
	"os"
	"testing"
	"time"

	"scanner/internal/modules/shared"
)

// TestRealNetDiagnostic points every public entrypoint the advancedweb suite
// uses at benign public hosts over the real network, to tell an ENGINE fault
// from an ENVIRONMENT one (killswitch/VPN/stale bound source IP, blocked egress).
// Skipped by default (needs outbound network):
//
//	HTTPXFIND_REALNET=1 go test -run TestRealNetDiagnostic -v ./internal/modules/httpxfind/
func TestRealNetDiagnostic(t *testing.T) {
	if os.Getenv("HTTPXFIND_REALNET") == "" {
		t.Skip("set HTTPXFIND_REALNET=1 to run the real-network engine diagnostic")
	}
	hosts := []string{"example.com", "scanme.nmap.org"}
	newOpts := func() *shared.HTTPOptions {
		return &shared.HTTPOptions{Ctx: context.Background(), Timeout: 8 * time.Second}
	}

	// 1) resolveTargets must KEEP resolvable hosts (a wrong drop here = instant 0-live).
	keep, ipc, dropped := resolveTargets(hosts, newOpts())
	t.Logf("[resolveTargets] kept=%v dropped=%d ipCache=%v", keep, dropped, ipc)
	if len(keep) == 0 {
		t.Fatalf("resolveTargets dropped ALL hosts — this alone causes instant 0-live in full/custom mode")
	}

	// 2) Common mode (advancedweb's DEFAULT httpx path: ScanWithConcurrency).
	o := newOpts()
	r := ScanWithConcurrency(hosts, ModeCommon, 8, o, nil, nil)
	n, brk := o.ErrorSummary()
	t.Logf("[ScanWithConcurrency/common] live=%d errors=%d(%s)", len(r.Services), n, brk)
	if len(r.Services) == 0 {
		t.Fatalf("common mode found 0 live over real net")
	}

	// 3) Custom ports, direct (advancedweb's custom-port path).
	o = newOpts()
	r = ScanWithPorts(hosts, []int{80, 443}, 8, 0, true, o, nil, nil)
	t.Logf("[ScanWithPorts/direct] live=%d", len(r.Services))
	if len(r.Services) == 0 {
		t.Fatalf("custom-direct found 0 live over real net")
	}

	// 4) Custom ports, connect-first two-phase.
	o = newOpts()
	r = ScanWithPorts(hosts, []int{80, 443}, 8, 0, false, o, nil, nil)
	t.Logf("[ScanWithPorts/connect] live=%d", len(r.Services))
	if len(r.Services) == 0 {
		t.Fatalf("custom-connect found 0 live over real net")
	}
	t.Log("ALL PATHS OK — engine probes correctly; a 0-live scan here is environment (killswitch/VPN/egress), not the engine")
}
