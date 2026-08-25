package sysmon

import "testing"

// realistic /proc/net/tcp fixture. Port range assumed 32768..60999.
// Rows (state hex → meaning, local port hex → dec):
//
//	E7C4=59332 ESTAB(01)      in-range   → ephemeral
//	C001=49153 FIN_WAIT2(05)  in-range   → ephemeral
//	D002=53250 TIME_WAIT(06)  in-range   → ephemeral
//	0400=1024  SYN_SENT(02)   below range→ not ephemeral
//	1F90=8080  LISTEN(0A)     in-range   → NOT counted (server bind)
const tcpFixture = `  sl  local_address rem_address   st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode
   0: 0100007F:E7C4 08080808:01BB 01 00000000:00000000 00:00000000 00000000  1000        0 111 1 0000
   1: 0100007F:C001 08080808:01BB 05 00000000:00000000 00:00000000 00000000  1000        0 222 1 0000
   2: 0100007F:D002 08080808:01BB 06 00000000:00000000 00:00000000 00000000  1000        0 333 1 0000
   3: 0100007F:0400 08080808:01BB 02 00000000:00000000 00:00000000 00000000  1000        0 444 1 0000
   4: 0100007F:1F90 00000000:0000 0A 00000000:00000000 00:00000000 00000000  1000        0 555 1 0000
`

func TestCountTCPStates(t *testing.T) {
	st, eph, esc, eo := countTCPStates(tcpFixture, 32768, 60999, nil)
	if st.Total != 5 {
		t.Errorf("Total = %d, want 5", st.Total)
	}
	if st.Estab != 1 || st.FinWait2 != 1 || st.TimeWait != 1 || st.SynSent != 1 || st.Listen != 1 {
		t.Errorf("state histogram wrong: %+v", st)
	}
	if eph != 3 {
		t.Errorf("ephemeral = %d, want 3 (ESTAB+FIN_WAIT2+TIME_WAIT in range, LISTEN excluded, low port excluded)", eph)
	}
	// nil owner set → every owned ephemeral falls to "other".
	if esc != 0 || eo != 3 {
		t.Errorf("nil owner set: scanner=%d other=%d, want 0 and 3", esc, eo)
	}
}

func TestCountTCPStatesOwnerSplit(t *testing.T) {
	// inode 111 = the ESTAB row; treat it as scaNNer-owned. The other two
	// ephemeral holders (inodes 222, 333) are then "other".
	_, eph, esc, eo := countTCPStates(tcpFixture, 32768, 60999, map[uint64]bool{111: true})
	if eph != 3 || esc != 1 || eo != 2 {
		t.Errorf("owner split: eph=%d scanner=%d other=%d, want 3/1/2", eph, esc, eo)
	}
}

func TestCountTCPStatesHeaderOnly(t *testing.T) {
	st, eph, _, _ := countTCPStates("  sl  local_address rem_address   st\n", 32768, 60999, nil)
	if st.Total != 0 || eph != 0 {
		t.Errorf("header-only should yield zero, got total=%d eph=%d", st.Total, eph)
	}
}

func TestCPUTotals(t *testing.T) {
	// user=100 nice=0 system=50 idle=800 iowait=50 irq=0 softirq=0 ...
	idle, total := cpuTotals("cpu  100 0 50 800 50 0 0 0 0 0\ncpu0 50 0 25 400 25 0 0 0 0 0\n")
	if idle != 850 { // idle(800)+iowait(50)
		t.Errorf("idle = %d, want 850", idle)
	}
	if total != 1000 {
		t.Errorf("total = %d, want 1000", total)
	}
}

func TestParseLoad1(t *testing.T) {
	if got := parseLoad1("21.89 20.24 12.52 5/2439 998877\n"); got != 21.89 {
		t.Errorf("load1 = %v, want 21.89", got)
	}
	if got := parseLoad1(""); got != 0 {
		t.Errorf("empty load = %v, want 0", got)
	}
}

func TestParsePortRange(t *testing.T) {
	lo, hi := parsePortRange("32768\t60999\n")
	if lo != 32768 || hi != 60999 {
		t.Errorf("port range = %d..%d, want 32768..60999", lo, hi)
	}
}

func TestParseFirstInt(t *testing.T) {
	if got := parseFirstInt("60\n"); got != 60 {
		t.Errorf("= %d, want 60", got)
	}
	if got := parseFirstInt(""); got != 0 {
		t.Errorf("empty = %d, want 0", got)
	}
}

func TestCountChildPPID(t *testing.T) {
	// comm with spaces + nested parens must not break the split-after-last-')'
	lines := []string{
		"100 (systemd) S 0 100 100 0 -1 ...",
		"1234 (scanner) S 100 1234 1234 0 -1 ...",
		"5678 (ruby (with) parens) R 1234 5678 5678 0 -1 ...",
		"5679 (nmap) R 1234 5679 5679 0 -1 ...",
		"9999 (bash) S 100 9999 9999 0 -1 ...",
	}
	if n := countChildPPID(lines, 1234); n != 2 {
		t.Errorf("children of 1234 = %d, want 2", n)
	}
	if n := countChildPPID(lines, 100); n != 2 {
		t.Errorf("children of 100 = %d, want 2", n)
	}
	if n := countChildPPID(lines, 42); n != 0 {
		t.Errorf("children of 42 = %d, want 0", n)
	}
}

func TestUsablePortsAndUsage(t *testing.T) {
	l := Limits{PortRangeLo: 32768, PortRangeHi: 60999}
	if u := l.UsablePorts(); u != 28232 {
		t.Errorf("UsablePorts = %d, want 28232", u)
	}
	s := Snapshot{Ephemeral: 14116}
	if f := s.PortUsage(l); f < 0.49 || f > 0.51 {
		t.Errorf("PortUsage = %v, want ~0.5", f)
	}
	// zero/invalid limits must not divide by zero
	if (Snapshot{Ephemeral: 10}).PortUsage(Limits{}) != 0 {
		t.Error("PortUsage with empty limits should be 0")
	}
}
