package hashcat

// Module is the standalone hashcat password-cracking module. Unlike every
// other scan module it has NO network targets — the "target" is the set of
// hashes the operator submits, and all work is local CPU (or GPU). It runs a
// single hashcat process per scan and derives live progress from
// `--status-json`. See internal/modules/adpentest/phase_crack.go for the
// in-AD-pentest crack path this generalizes.
type Module struct{}

func (m *Module) Name() string        { return "hashcat" }
func (m *Module) DisplayName() string { return "Hashcat" }
func (m *Module) Description() string {
	return "Crack password hashes with hashcat — search the algorithm by name (no -m codes to memorize), pick famous rule sets and wordlists or a brute-force mask, cap CPU usage, and watch live crack progress."
}

// Category is "network" so the module sits beside the other offensive /
// credential tooling (brutef) under the Network filter — it has no network
// traffic of its own, but that's where operators look for it.
func (m *Module) Category() string { return "network" }
func (m *Module) Icon() string     { return "🔓" }
