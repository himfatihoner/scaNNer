package capacity

import (
	_ "embed"
	"encoding/json"
	"sync"
)

// profiles.json is the seed of MEASURED module profiles, baked in at build
// time. The profiling harness (Phase 4) calls SetMeasured at runtime to add /
// refine entries and persists them so a rebuild carries them forward.
//
//go:embed profiles.json
var profilesJSON []byte

type profilesFile struct {
	SchemaVersion int                `json:"schema_version"`
	MeasuredAt    map[string]any     `json:"measured_at"`
	Modules       map[string]Profile `json:"modules"`
}

var (
	ovMu      sync.RWMutex
	overrides map[string]Profile
	ovInit    sync.Once
)

func ensureLoaded() {
	ovInit.Do(func() {
		overrides = map[string]Profile{}
		var f profilesFile
		if json.Unmarshal(profilesJSON, &f) == nil {
			for name, p := range f.Modules {
				if !p.Measured {
					continue
				}
				p.Module = name
				overrides[name] = p
			}
		}
	})
}

func measuredProfile(module string) (Profile, bool) {
	ensureLoaded()
	ovMu.RLock()
	defer ovMu.RUnlock()
	p, ok := overrides[module]
	return p, ok
}

// SetMeasured installs or replaces a module's measured profile at runtime
// (called by the profiling harness). Persisting it to disk is the caller's job.
func SetMeasured(p Profile) {
	ensureLoaded()
	if p.MinConc <= 0 {
		p.MinConc = 1
	}
	p.Measured = true
	ovMu.Lock()
	overrides[p.Module] = p
	ovMu.Unlock()
}

// LoadOverrides merges a set of measured profiles (e.g. read from a
// runtime-writable data file) over the embedded seed.
func LoadOverrides(ps []Profile) {
	ensureLoaded()
	ovMu.Lock()
	for _, p := range ps {
		if p.Module == "" {
			continue
		}
		p.Measured = true
		if p.MinConc <= 0 {
			p.MinConc = 1
		}
		overrides[p.Module] = p
	}
	ovMu.Unlock()
}

// MeasuredProfiles returns a copy of all currently-installed measured profiles
// (for persistence + UI listing).
func MeasuredProfiles() []Profile {
	ensureLoaded()
	ovMu.RLock()
	defer ovMu.RUnlock()
	out := make([]Profile, 0, len(overrides))
	for _, p := range overrides {
		out = append(out, p)
	}
	return out
}
