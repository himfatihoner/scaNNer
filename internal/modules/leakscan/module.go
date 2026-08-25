package leakscan

type Module struct{}

func (m *Module) Name() string        { return "leakscan" }
func (m *Module) DisplayName() string { return "GitHub Leak Scanner" }
func (m *Module) Description() string {
	return "Searches public GitHub code for the target keyword (domain / company / API path) and runs secret-pattern regexes (AWS keys, GitHub tokens, JWTs, private keys, passwords) against each hit."
}
func (m *Module) Category() string { return "recon" }
func (m *Module) Icon() string     { return "🔓" }
