package hostdiscovery

type Module struct{}

func (m *Module) Name() string        { return "hostdiscovery" }
func (m *Module) DisplayName() string { return "Host Discovery" }
func (m *Module) Description() string {
	return "Fast nmap-powered host discovery and port scan. Pick common, custom, range, or full port scope; runs both ping and -Pn so you see whether ICMP replies were silenced."
}
func (m *Module) Category() string { return "network" }
func (m *Module) Icon() string     { return "📡" }
