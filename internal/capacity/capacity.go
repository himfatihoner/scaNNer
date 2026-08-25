// Package capacity computes a recommended concurrency for each scanner module
// from (a) the module's resource profile — how much of each scarce resource
// one unit of concurrency costs — and (b) the machine's live system limits
// (internal/sysmon). It replaces the old flat, one-size-fits-all
// EffectiveWebMaxConcurrent default with a per-module, machine-aware value, so
// a socket/port-bound module (sslscan) and a CPU-bound one (techdetect) are
// each throttled by the resource that actually binds them.
//
// Two sources of truth:
//   - CLASS DEFAULTS (this file): every module is assigned an ExecClass with
//     conservative default coefficients. Used until a module is calibrated.
//   - MEASURED OVERRIDES (profiles.json, go:embed): coefficients written by the
//     profiling harness (Phase 4). A module present here is "measured"; the UI
//     flags the rest so the operator knows what still needs calibration.
package capacity

import (
	"sync"
	"sync/atomic"

	"scanner/internal/sysmon"
)

// ExecClass groups modules by how they consume resources, which sets the
// dominant-resource formula and conservative default coefficients.
type ExecClass string

const (
	ClassSocketLight ExecClass = "socket_light" // pure Go-HTTP, cheap per connection (spider, corsscan, …)
	ClassSocketHeavy ExecClass = "socket_heavy" // subprocess-per-host holding many sockets (sslscan)
	ClassCPUHeavy    ExecClass = "cpu_heavy"    // heavy subprocess per target (techdetect=whatweb, wpscan)
	ClassNetScan     ExecClass = "net_scan"     // nmap/host-scan subprocess per target (portservice, smbenum, …)
	ClassToolRate    ExecClass = "tool_rate"    // self-parallelizing tool with a rate flag (nuclei, dnsenum)
	ClassBrute       ExecClass = "brute"        // credential brute (hydra -t)
	ClassSingle      ExecClass = "single"       // single-shot / API / CPU-internal (cvematch, jwt, oob, …)
)

// Profile is one module's resource cost model. Zero-valued coefficients are
// treated as "this resource does not bind me" and skipped by the formula.
type Profile struct {
	Module         string    `json:"module"`
	Class          ExecClass `json:"class"`
	Dominant       string    `json:"dominant_resource"`     // ports|cpu|fd|none (informational)
	PortsPerConc   float64   `json:"ports_per_conc_unit"`   // ephemeral ports held per concurrency unit (steady state)
	CPUFracPerConc float64   `json:"cpu_frac_per_conc_unit"` // fraction of one core per concurrency unit
	FDsPerConc     float64   `json:"fds_per_conc_unit"`     // open fds per concurrency unit
	MeasuredFin    int       `json:"measured_fin_timeout"`  // tcp_fin_timeout at measurement (L0); scales the port ceiling
	OptimalConc    int       `json:"measured_optimal_conc"` // the knee found during profiling (informational)
	MaxSafe        int       `json:"max_safe_conc"`         // hard ceiling the formula may only LOWER
	MinConc        int       `json:"min_conc"`
	Throughput     float64   `json:"throughput_at_optimal,omitempty"`
	Measured       bool      `json:"measured"`
	Notes          string    `json:"notes,omitempty"`
}

// Formula tunables. Safety factors keep each resource off its ceiling;
// globalPortM divides the port budget so several concurrently-running modules
// can't collectively exhaust the ephemeral range (the dynamic SetNetworkThrottle
// backstop covers any residual under-estimate). See the design doc.
const (
	safetyPort       = 0.70
	defaultCPUBudget = 0.75 // fraction of cores the scanner may use; operator-overridable
	safetyFD         = 0.60
	globalPortM      = 2.0 // expected concurrent port-consuming modules
	baseFin          = 60  // fallback baseline tcp_fin_timeout when a profile omits MeasuredFin
	portFallbck      = 28000
)

// cpuBudget is the fraction of cores CPU-bound modules may consume — the
// Settings "CPU budget (% of cores)" value. Read on every Recommend (hot path),
// so it's an atomic. SetCPUBudget installs it from Settings at startup + on save.
var cpuBudget atomic.Value // float64

// SetCPUBudget sets the CPU headroom fraction (0<frac<=1). Out-of-range resets
// to the default. Lowering it shrinks CPU-bound modules' recommended concurrency.
func SetCPUBudget(frac float64) {
	if frac <= 0 || frac > 1 {
		frac = defaultCPUBudget
	}
	cpuBudget.Store(frac)
}

func currentCPUBudget() float64 {
	if v, ok := cpuBudget.Load().(float64); ok && v > 0 {
		return v
	}
	return defaultCPUBudget
}

// moduleClass assigns every registered module to an ExecClass. Modules absent
// here fall back to ClassSocketLight (a safe web default).
var moduleClass = map[string]ExecClass{
	// pure Go-HTTP (web tier) — cheap sockets
	"spider": ClassSocketLight, "direnum": ClassSocketLight, "secheaders": ClassSocketLight,
	"paramdisc": ClassSocketLight, "httpmethods": ClassSocketLight, "wafdetect": ClassSocketLight,
	"corsscan": ClassSocketLight, "openredirect": ClassSocketLight, "sstiscan": ClassSocketLight,
	"takeover": ClassSocketLight, "graphqlscan": ClassSocketLight, "authtest": ClassSocketLight,
	"cachepoison": ClassSocketLight, "httpxfind": ClassSocketLight, "advancedweb": ClassSocketLight,
	// subprocess-per-host, socket/port heavy
	"sslscan": ClassSocketHeavy,
	// heavy subprocess per target, CPU bound
	"techdetect": ClassCPUHeavy, "wpscan": ClassCPUHeavy,
	// nmap / host-scan subprocess per target (network tier)
	"portservice": ClassNetScan, "hostdiscovery": ClassNetScan, "smbenum": ClassNetScan,
	"snmpenum": ClassNetScan, "whoisinfo": ClassNetScan,
	// self-parallel tool with a rate flag
	"nuclei": ClassToolRate, "dnsenum": ClassToolRate,
	// credential brute
	"brutef": ClassBrute,
	// single-shot / API / CPU-internal — concurrency knob is irrelevant
	"cvematch": ClassSingle, "jwt": ClassSingle, "oob": ClassSingle, "leakscan": ClassSingle,
	"assetdisc": ClassSingle, "concurtest": ClassSingle, "emailharvest": ClassSingle,
	"adpentest": ClassSingle,
}

// classDefault returns the conservative default Profile for a class. These are
// deliberately modest for un-calibrated modules (MaxSafe is low); the profiling
// harness raises MaxSafe + refines coefficients per module.
func classDefault(class ExecClass) Profile {
	switch class {
	case ClassSocketHeavy:
		return Profile{Class: class, Dominant: "ports", PortsPerConc: 47.5, CPUFracPerConc: 0.05, MeasuredFin: baseFin, MaxSafe: 20, MinConc: 1}
	case ClassCPUHeavy:
		return Profile{Class: class, Dominant: "cpu", PortsPerConc: 7, CPUFracPerConc: 0.40, MeasuredFin: baseFin, MaxSafe: 20, MinConc: 1}
	case ClassNetScan:
		return Profile{Class: class, Dominant: "cpu", CPUFracPerConc: 0.20, MaxSafe: 16, MinConc: 1}
	case ClassToolRate:
		return Profile{Class: class, Dominant: "cpu", CPUFracPerConc: 0.15, MaxSafe: 40, MinConc: 2}
	case ClassBrute:
		return Profile{Class: class, Dominant: "none", MaxSafe: 32, MinConc: 1}
	case ClassSingle:
		return Profile{Class: class, Dominant: "none", MaxSafe: 1, MinConc: 1}
	default: // ClassSocketLight
		return Profile{Class: ClassSocketLight, Dominant: "ports", PortsPerConc: 8, CPUFracPerConc: 0.02, MeasuredFin: baseFin, MaxSafe: 64, MinConc: 4}
	}
}

// ProfileFor returns a module's effective profile: the measured override if one
// exists, else the class default (with Module/Class filled in).
func ProfileFor(module string) Profile {
	if p, ok := measuredProfile(module); ok {
		if p.MinConc <= 0 {
			p.MinConc = 1
		}
		return p
	}
	class, ok := moduleClass[module]
	if !ok {
		class = ClassSocketLight
	}
	p := classDefault(class)
	p.Module = module
	return p
}

// Measured reports whether a module has a calibrated (measured) profile.
func Measured(module string) bool {
	_, ok := measuredProfile(module)
	return ok
}

// IsModule reports whether name is a known scanner module (has an ExecClass).
func IsModule(name string) bool {
	_, ok := moduleClass[name]
	return ok
}

// Recommend computes the recommended concurrency for a module under live
// system limits, bounded by the module's own MaxSafe. It is the minimum of the
// per-resource ceilings the module is subject to. During calibration a forced
// override (SetForced) short-circuits it so the profiler can sweep concurrency.
func Recommend(module string, l sysmon.Limits) int {
	if c := forcedConc(module); c > 0 {
		return c
	}
	return recommendFor(ProfileFor(module), l)
}

// Forced-concurrency override used ONLY by the profiling harness: while
// calibrating a module it pins Recommend(module) to the swept level, so any
// module that reads Recommend (web tier, techdetect, nuclei…) launches at the
// exact concurrency being measured without per-module wiring.
var (
	forcedMu   sync.RWMutex
	forcedByID = map[string]int{}
)

// SetForced pins Recommend(module) to c (c<=0 clears just this module).
func SetForced(module string, c int) {
	forcedMu.Lock()
	if c <= 0 {
		delete(forcedByID, module)
	} else {
		forcedByID[module] = c
	}
	forcedMu.Unlock()
}

// ClearForced removes all forced overrides (end of a calibration run).
func ClearForced() {
	forcedMu.Lock()
	forcedByID = map[string]int{}
	forcedMu.Unlock()
}

func forcedConc(module string) int {
	forcedMu.RLock()
	defer forcedMu.RUnlock()
	return forcedByID[module]
}

func recommendFor(p Profile, l sysmon.Limits) int {
	if p.MaxSafe <= 0 {
		return maxi(p.MinConc, 1)
	}
	best := p.MaxSafe

	// PORT-bound ceiling: budget of ephemeral ports (safety-scaled, divided
	// across expected concurrent modules), scaled by fin_timeout recycling
	// (a shorter fin_timeout frees ports faster → higher ceiling).
	if p.PortsPerConc > 0 {
		usable := l.UsablePorts()
		if usable <= 0 {
			usable = portFallbck
		}
		finBase := p.MeasuredFin
		if finBase <= 0 {
			finBase = baseFin
		}
		finRatio := 1.0
		if l.FinTimeout > 0 {
			finRatio = float64(finBase) / float64(l.FinTimeout)
		}
		budget := safetyPort / globalPortM * float64(usable) * finRatio
		if c := int(budget / p.PortsPerConc); c < best {
			best = c
		}
	}

	// CPU-bound ceiling: cores × safety / cores-per-conc. Port-independent.
	if p.CPUFracPerConc > 0 {
		cores := l.Cores
		if cores <= 0 {
			cores = 1
		}
		if c := int(currentCPUBudget() * float64(cores) / p.CPUFracPerConc); c < best {
			best = c
		}
	}

	// FD-bound ceiling.
	if p.FDsPerConc > 0 && l.NoFile > 0 {
		if c := int(safetyFD * float64(l.NoFile) / p.FDsPerConc); c < best {
			best = c
		}
	}

	return clampi(best, maxi(p.MinConc, 1), p.MaxSafe)
}

func maxi(a, b int) int {
	if a > b {
		return a
	}
	return b
}

func clampi(v, lo, hi int) int {
	if v < lo {
		return lo
	}
	if v > hi {
		return hi
	}
	return v
}
