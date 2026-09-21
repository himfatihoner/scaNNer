//go:build !linux

package sysmon

import "runtime"

// collect is a stub on non-Linux platforms: no /proc, so a zero Snapshot.
func collect() (Snapshot, uint64, uint64) { return Snapshot{}, 0, 0 }

// readLimits reports only the CPU count off Linux; network sysctls are absent.
func readLimits() Limits { return Limits{Cores: runtime.NumCPU()} }

// readMemory is a stub off Linux (no /proc): a zero MemStat, which AvailFrac
// treats as "not under pressure".
func readMemory() MemStat { return MemStat{} }
