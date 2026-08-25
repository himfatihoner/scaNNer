//go:build linux

package sysmon

import (
	"os"
	"runtime"
	"strconv"
	"strings"
	"syscall"
)

func readFileStr(path string) string {
	b, err := os.ReadFile(path)
	if err != nil {
		return ""
	}
	return string(b)
}

// collect gathers one raw snapshot plus the current /proc/stat CPU jiffie
// totals (idle+iowait, total) so the Sampler can compute a busy fraction from
// the delta. CPUBusyFrac is left 0 here — the Sampler fills it.
func collect() (Snapshot, uint64, uint64) {
	var snap Snapshot

	lo, hi := parsePortRange(readFileStr("/proc/sys/net/ipv4/ip_local_port_range"))

	// One /proc scan builds both the direct-child count AND the full scaNNer
	// process tree (self + all descendants: nmap, whatweb, nuclei, …). The
	// tree's socket inodes let us attribute each /proc/net/tcp row to scaNNer
	// vs other applications.
	self := os.Getpid()
	statLines, ppid := readProcStats()
	snap.ChildProcs = countChildPPID(statLines, self)
	scannerInodes := socketInodes(descendants(ppid, self))

	st4, eph4, es4, eo4 := countTCPStates(readFileStr("/proc/net/tcp"), lo, hi, scannerInodes)
	st6, eph6, es6, eo6 := countTCPStates(readFileStr("/proc/net/tcp6"), lo, hi, scannerInodes)
	snap.States = mergeStates(st4, st6)
	snap.Ephemeral = eph4 + eph6
	snap.EphemeralScanner = es4 + es6
	snap.EphemeralOther = eo4 + eo6

	snap.Load1 = parseLoad1(readFileStr("/proc/loadavg"))
	idle, total := cpuTotals(readFileStr("/proc/stat"))

	snap.Threads = parseThreads(readFileStr("/proc/self/status"))
	snap.FDsOpen = countDirEntries("/proc/self/fd")
	snap.ConntrackUsed = parseFirstInt(readFileStr("/proc/sys/net/netfilter/nf_conntrack_count"))

	return snap, idle, total
}

func parseThreads(status string) int {
	for _, line := range strings.Split(status, "\n") {
		if strings.HasPrefix(line, "Threads:") {
			return parseFirstInt(strings.TrimPrefix(line, "Threads:"))
		}
	}
	return 0
}

func countDirEntries(path string) int {
	entries, err := os.ReadDir(path)
	if err != nil {
		return 0
	}
	return len(entries)
}

// readProcStats reads every /proc/<pid>/stat once, returning the raw stat
// lines (for countChildPPID) and a pid->ppid map (for the descendant walk) —
// so a single /proc directory scan feeds both the child count and the process
// tree. A stat line is "pid (comm) state ppid pgrp ..."; comm can contain
// spaces and ')', so the ppid is read after the LAST ')'.
func readProcStats() (lines []string, ppid map[int]int) {
	ppid = map[int]int{}
	entries, err := os.ReadDir("/proc")
	if err != nil {
		return nil, ppid
	}
	lines = make([]string, 0, 256)
	for _, e := range entries {
		if !e.IsDir() {
			continue
		}
		pid, err := strconv.Atoi(e.Name())
		if err != nil {
			continue
		}
		s := readFileStr("/proc/" + e.Name() + "/stat")
		if s == "" {
			continue
		}
		lines = append(lines, s)
		if rp := strings.LastIndexByte(s, ')'); rp >= 0 && rp+2 <= len(s) {
			if f := strings.Fields(s[rp+1:]); len(f) >= 2 {
				if pp, err := strconv.Atoi(f[1]); err == nil {
					ppid[pid] = pp
				}
			}
		}
	}
	return lines, ppid
}

// descendants returns root plus every pid transitively parented by it (the
// scaNNer process tree). BFS over the inverted ppid map.
func descendants(ppid map[int]int, root int) map[int]bool {
	children := map[int][]int{}
	for pid, pp := range ppid {
		children[pp] = append(children[pp], pid)
	}
	out := map[int]bool{root: true}
	queue := []int{root}
	for len(queue) > 0 {
		p := queue[0]
		queue = queue[1:]
		for _, c := range children[p] {
			if !out[c] {
				out[c] = true
				queue = append(queue, c)
			}
		}
	}
	return out
}

// socketInodes collects the socket inodes held by the given pids, from their
// /proc/<pid>/fd/* symlinks that point at "socket:[<inode>]". Only same-uid
// processes' fd dirs are readable — which is exactly the scaNNer tree (its
// tools run as the same user); other apps' sockets simply aren't matched and
// fall to the "other" bucket, as intended.
func socketInodes(pids map[int]bool) map[uint64]bool {
	inodes := map[uint64]bool{}
	for pid := range pids {
		dir := "/proc/" + strconv.Itoa(pid) + "/fd"
		entries, err := os.ReadDir(dir)
		if err != nil {
			continue
		}
		for _, e := range entries {
			link, err := os.Readlink(dir + "/" + e.Name())
			if err != nil {
				continue
			}
			if strings.HasPrefix(link, "socket:[") && strings.HasSuffix(link, "]") {
				if n, err := strconv.ParseUint(link[8:len(link)-1], 10, 64); err == nil {
					inodes[n] = true
				}
			}
		}
	}
	return inodes
}

func readLimits() Limits {
	l := Limits{Cores: runtime.NumCPU()}
	l.PortRangeLo, l.PortRangeHi = parsePortRange(readFileStr("/proc/sys/net/ipv4/ip_local_port_range"))
	l.FinTimeout = parseFirstInt(readFileStr("/proc/sys/net/ipv4/tcp_fin_timeout"))
	l.TWReuse = parseFirstInt(readFileStr("/proc/sys/net/ipv4/tcp_tw_reuse"))
	l.ConntrackMax = parseFirstInt(readFileStr("/proc/sys/net/netfilter/nf_conntrack_max"))
	var rl syscall.Rlimit
	if err := syscall.Getrlimit(syscall.RLIMIT_NOFILE, &rl); err == nil {
		l.NoFile = rl.Cur
	}
	return l
}
