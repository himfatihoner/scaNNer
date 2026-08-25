package brutef

type Module struct{}

func (m *Module) Name() string        { return "brutef" }
func (m *Module) DisplayName() string { return "Service Brute Forcer" }
func (m *Module) Description() string {
	return "Hydra-powered credential brute-force for SSH, FTP, and RDP. Pick protocol, supply username and password lists, and let it stream successful logins as they're found."
}
func (m *Module) Category() string { return "network" }
func (m *Module) Icon() string     { return "🔑" }
