// Package sysmon samples OS network/resource pressure from /proc — all
// unprivileged reads — and reads the system's network limits. It is the
// measurement foundation for the adaptive per-module concurrency governor
// (internal/capacity) and the live performance dashboard.
//
// Why a separate package (mirrors internal/scanstats): the sampler is needed
// by both the handlers layer (dashboard, governor) and the capacity formula,
// and it must stay dependency-light. The PARSING functions here take raw file
// contents as input so they unit-test on any platform; the thin per-OS glue
// (collect_linux.go / collect_other.go) does the os.ReadFile + syscall work.
//
// Caveat: /proc/net/tcp reflects the process's current network namespace. When
// the killswitch netns is armed the scanner's sockets live in scanner-ns, so
// machine-wide counts would be scoped to that namespace; the killswitch is
// dormant in normal use, where scans share the host netns and counts are
// correct.
package sysmon

import (
	"strconv"
	"strings"
)

// SocketStates is a machine-wide TCP socket-state histogram. FinWait2 +
// TimeWait are the states that hold an ephemeral source port after the local
// side closes — the port-exhaustion driver observed in the field.
type SocketStates struct {
	Estab     int
	SynSent   int
	FinWait1  int
	FinWait2  int
	TimeWait  int
	CloseWait int
	Listen    int
	Other     int
	Total     int
}

// Snapshot is one instantaneous sample of OS resource pressure. All socket /
// port / load / conntrack figures are machine-wide; Threads / FDsOpen /
// ChildProcs are scoped to the scanner process tree.
type Snapshot struct {
	Ephemeral     int          // TCP sockets whose LOCAL port is in the ephemeral range (machine-wide)
	// EphemeralScanner / EphemeralOther split the ephemeral-port holders by the
	// process that owns the socket: those owned by the scaNNer process tree
	// (scanner + spawned tools: nmap, whatweb, nuclei, …) vs those owned by any
	// OTHER application on the box. Ownerless kernel-held sockets (TIME_WAIT /
	// FIN_WAIT2, inode 0) count toward neither, so Scanner+Other <= Ephemeral.
	EphemeralScanner int
	EphemeralOther   int
	States        SocketStates // machine-wide TCP socket-state histogram
	Load1         float64      // 1-minute load average
	CPUBusyFrac   float64      // 0..1 busy across all cores since the previous Sample (0 on first call)
	Threads       int          // threads in this (scanner) process
	FDsOpen       int          // open file descriptors in this process
	ChildProcs    int          // direct child processes of this process (spawned tools)
	ConntrackUsed int          // nf_conntrack_count (0 if the module is absent)
}

// Limits are the system network/resource ceilings — the capacity formula's L1.
type Limits struct {
	PortRangeLo  int    // net.ipv4.ip_local_port_range low
	PortRangeHi  int    // net.ipv4.ip_local_port_range high
	FinTimeout   int    // net.ipv4.tcp_fin_timeout (seconds)
	TWReuse      int    // net.ipv4.tcp_tw_reuse (0/1/2)
	ConntrackMax int    // net.netfilter.nf_conntrack_max (0 = no conntrack module)
	NoFile       uint64 // RLIMIT_NOFILE soft limit
	Cores        int    // logical CPUs (runtime.NumCPU)
}

// UsablePorts is the size of the ephemeral port range (0 if unreadable).
func (l Limits) UsablePorts() int {
	if l.PortRangeLo > 0 && l.PortRangeHi >= l.PortRangeLo {
		return l.PortRangeHi - l.PortRangeLo + 1
	}
	return 0
}

// PortUsage returns ephemeral ports in use as a fraction 0..1 of the range.
func (s Snapshot) PortUsage(l Limits) float64 {
	if u := l.UsablePorts(); u > 0 {
		return float64(s.Ephemeral) / float64(u)
	}
	return 0
}

// Sampler produces Snapshots on a timer. It retains the previous /proc/stat
// CPU totals so each Sample reports the busy fraction over the interval since
// the last call. Use one Sampler per goroutine (not safe for concurrent use).
type Sampler struct {
	prevIdle  uint64
	prevTotal uint64
	haveCPU   bool
}

// NewSampler returns a ready Sampler.
func NewSampler() *Sampler { return &Sampler{} }

// Sample takes one measurement. CPUBusyFrac is the fraction busy since the
// previous Sample (0 on the first call, or on non-Linux where collect is a
// stub).
func (s *Sampler) Sample() Snapshot {
	snap, idle, total := collect()
	if s.haveCPU && total > s.prevTotal {
		dt := total - s.prevTotal
		di := idle - s.prevIdle
		if dt > 0 {
			busy := 1 - float64(di)/float64(dt)
			if busy < 0 {
				busy = 0
			}
			snap.CPUBusyFrac = busy
		}
	}
	s.prevIdle, s.prevTotal, s.haveCPU = idle, total, true
	return snap
}

// SampleOnce is a convenience one-shot sample (CPUBusyFrac is always 0 since
// there is no prior interval). Prefer a persistent Sampler for CPU accuracy.
func SampleOnce() Snapshot {
	snap, _, _ := collect()
	return snap
}

// ReadLimits reads the current system limits (L1). Cheap; safe to call on
// demand (e.g. at every scan launch, so a mid-session sysctl change is seen).
func ReadLimits() Limits { return readLimits() }

// ---- pure parsers (unit-tested with fixtures; no I/O) ----

// parseLoad1 extracts the 1-minute load average from /proc/loadavg contents.
func parseLoad1(s string) float64 {
	f := strings.Fields(s)
	if len(f) == 0 {
		return 0
	}
	v, _ := strconv.ParseFloat(f[0], 64)
	return v
}

// cpuTotals parses the aggregate "cpu " line of /proc/stat and returns
// (idle+iowait, total) jiffies. Returns (0,0) if the line is absent.
func cpuTotals(s string) (idle, total uint64) {
	for _, line := range strings.Split(s, "\n") {
		if !strings.HasPrefix(line, "cpu ") {
			continue
		}
		// fields after "cpu": user nice system idle iowait irq softirq steal ...
		for i, f := range strings.Fields(line)[1:] {
			v, err := strconv.ParseUint(f, 10, 64)
			if err != nil {
				continue
			}
			total += v
			if i == 3 || i == 4 { // idle, iowait
				idle += v
			}
		}
		return idle, total
	}
	return 0, 0
}

// parsePortRange parses "lo\thi" from ip_local_port_range contents.
func parsePortRange(s string) (lo, hi int) {
	f := strings.Fields(s)
	if len(f) >= 2 {
		lo, _ = strconv.Atoi(f[0])
		hi, _ = strconv.Atoi(f[1])
	}
	return
}

// parseFirstInt parses the leading integer of a sysctl file's contents.
func parseFirstInt(s string) int {
	f := strings.Fields(s)
	if len(f) == 0 {
		return 0
	}
	n, _ := strconv.Atoi(f[0])
	return n
}

// countTCPStates parses /proc/net/tcp or /proc/net/tcp6 contents, tallying
// sockets by state and how many hold a LOCAL port in [lo,hi]. A row is:
//
//	sl  local_address rem_address   st tx_queue:rx_queue ...
//	0: 0100007F:1F90 00000000:0000 0A ...
//
// field[1] = local addr:port(hex), field[3] = state(hex), field[9] = socket
// inode. The header row and any malformed row are skipped (their hex parses
// fail). scannerInodes (may be nil) is the set of socket inodes owned by the
// scaNNer process tree; each ephemeral holder is attributed to scanner vs other
// by inode membership (inode 0 = kernel-held, e.g. TIME_WAIT — attributed to
// neither).
func countTCPStates(s string, lo, hi int, scannerInodes map[uint64]bool) (states SocketStates, ephemeral, ephemeralScanner, ephemeralOther int) {
	for _, line := range strings.Split(s, "\n") {
		fields := strings.Fields(line)
		if len(fields) < 4 {
			continue
		}
		local := fields[1]
		colon := strings.IndexByte(local, ':')
		if colon < 0 {
			continue
		}
		port, err := strconv.ParseInt(local[colon+1:], 16, 32)
		if err != nil { // header line ("local_address") or garbage
			continue
		}
		st, err := strconv.ParseInt(fields[3], 16, 16)
		if err != nil {
			continue
		}
		states.Total++
		switch st {
		case 0x01:
			states.Estab++
		case 0x02:
			states.SynSent++
		case 0x04:
			states.FinWait1++
		case 0x05:
			states.FinWait2++
		case 0x06:
			states.TimeWait++
		case 0x08:
			states.CloseWait++
		case 0x0A:
			states.Listen++
		default:
			states.Other++
		}
		// A LISTEN socket on an ephemeral port is a server bind, not a
		// consumed outbound source port, so don't count it toward exhaustion.
		if st != 0x0A && lo > 0 && int(port) >= lo && int(port) <= hi {
			ephemeral++
			// Owner attribution via the socket inode (field[9]). inode 0 =
			// kernel-held (TIME_WAIT/FIN_WAIT2 after close) with no owning
			// process — left out of both buckets.
			if len(fields) >= 10 {
				if inode, e := strconv.ParseUint(fields[9], 10, 64); e == nil && inode != 0 {
					if scannerInodes[inode] {
						ephemeralScanner++
					} else {
						ephemeralOther++
					}
				}
			}
		}
	}
	return states, ephemeral, ephemeralScanner, ephemeralOther
}

// mergeStates adds b into a (for combining tcp + tcp6).
func mergeStates(a, b SocketStates) SocketStates {
	a.Estab += b.Estab
	a.SynSent += b.SynSent
	a.FinWait1 += b.FinWait1
	a.FinWait2 += b.FinWait2
	a.TimeWait += b.TimeWait
	a.CloseWait += b.CloseWait
	a.Listen += b.Listen
	a.Other += b.Other
	a.Total += b.Total
	return a
}

// countChildPPID counts, from concatenated /proc/<pid>/stat contents joined by
// '\n', how many processes have ppid == parent. Each stat line is:
//
//	pid (comm) state ppid pgrp ...
//
// comm can contain spaces and parens, so we split after the LAST ')'.
func countChildPPID(statLines []string, parent int) int {
	n := 0
	for _, line := range statLines {
		rp := strings.LastIndexByte(line, ')')
		if rp < 0 || rp+2 > len(line) {
			continue
		}
		rest := strings.Fields(line[rp+1:]) // state ppid pgrp ...
		if len(rest) >= 2 {
			if ppid, err := strconv.Atoi(rest[1]); err == nil && ppid == parent {
				n++
			}
		}
	}
	return n
}
