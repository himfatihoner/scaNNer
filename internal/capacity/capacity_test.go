package capacity

import (
	"testing"

	"scanner/internal/sysmon"
)

// baseline limits = this session's dev VM.
func baseLimits() sysmon.Limits {
	return sysmon.Limits{PortRangeLo: 32768, PortRangeHi: 60999, FinTimeout: 60, TWReuse: 2, Cores: 8, NoFile: 524288}
}

func TestSSLScanStaysCapped(t *testing.T) {
	// socket/port-bound but subprocess-capped at 20; port + cpu ceilings are both
	// far above 20, so the cap binds — in isolation sslscan should stay 20.
	if got := Recommend("sslscan", baseLimits()); got != 20 {
		t.Errorf("sslscan @baseline = %d, want 20 (subprocess cap)", got)
	}
	// Tuned limits (wider range, faster recycle) raise the port ceiling ~8x but
	// the 20 cap still binds — the payoff is a safer per-module port footprint.
	tuned := baseLimits()
	tuned.PortRangeLo, tuned.PortRangeHi, tuned.FinTimeout = 10000, 65535, 15
	if got := Recommend("sslscan", tuned); got != 20 {
		t.Errorf("sslscan @tuned = %d, want 20", got)
	}
}

func TestTechDetectCPUBound(t *testing.T) {
	// cpu_frac 0.40, safety 0.75 → floor(0.75*cores/0.40).
	cases := map[int]int{8: 15, 4: 7, 2: 3}
	for cores, want := range cases {
		l := baseLimits()
		l.Cores = cores
		if got := Recommend("techdetect", l); got != want {
			t.Errorf("techdetect @%d cores = %d, want %d", cores, got, want)
		}
	}
	// techdetect is port-independent: quartering fin_timeout must NOT change it.
	l := baseLimits()
	l.FinTimeout = 15
	if got := Recommend("techdetect", l); got != 15 {
		t.Errorf("techdetect with fin=15 = %d, want 15 (cpu-bound, port-independent)", got)
	}
}

func TestSocketLightDefault(t *testing.T) {
	// spider is un-measured → class default socket_light (MaxSafe 64). On 8
	// cores the cpu ceiling (300) and port ceiling (~1235) both exceed 64.
	if got := Recommend("spider", baseLimits()); got != 64 {
		t.Errorf("spider @baseline = %d, want 64 (class-default cap)", got)
	}
	// A tiny box: cpu ceiling 0.75*2/0.02=75 still > 64, so still 64.
	l := baseLimits()
	l.Cores = 2
	if got := Recommend("spider", l); got != 64 {
		t.Errorf("spider @2 cores = %d, want 64", got)
	}
}

func TestSingleClassIsOne(t *testing.T) {
	if got := Recommend("cvematch", baseLimits()); got != 1 {
		t.Errorf("cvematch = %d, want 1 (single-shot)", got)
	}
}

func TestMeasuredFlag(t *testing.T) {
	if !Measured("sslscan") || !Measured("techdetect") {
		t.Error("sslscan/techdetect should be measured (seeded)")
	}
	if Measured("spider") {
		t.Error("spider should NOT be measured yet")
	}
}

func TestUnknownModuleFallsBackSafely(t *testing.T) {
	// An unregistered module falls back to socket_light; must not panic or 0.
	if got := Recommend("does-not-exist", baseLimits()); got < 1 {
		t.Errorf("unknown module = %d, want >=1", got)
	}
}

func TestSetMeasuredOverridesLive(t *testing.T) {
	SetMeasured(Profile{Module: "spider", Class: ClassSocketLight, PortsPerConc: 20, CPUFracPerConc: 0.02, MeasuredFin: 60, MaxSafe: 100, MinConc: 2})
	if !Measured("spider") {
		t.Fatal("spider should be measured after SetMeasured")
	}
	// port ceiling now 0.35*28232/20 = 494; cpu 300; cap 100 → 100.
	if got := Recommend("spider", baseLimits()); got != 100 {
		t.Errorf("spider after SetMeasured = %d, want 100", got)
	}
}
