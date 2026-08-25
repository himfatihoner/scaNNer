package portservice

type Module struct{}

func (m *Module) Name() string        { return "portservice" }
func (m *Module) DisplayName() string { return "Advanced Host Scanner" }
func (m *Module) Description() string {
	return "Aggressive multi-phase scan: parallel port discovery (with + without ping), firewall detection, -A version + script scan with service-aware extra NSE scripts, follow-up pass for newly-detected services, then Nuclei vulnerability scan against open HTTP services."
}
func (m *Module) Category() string { return "network" }
func (m *Module) Icon() string     { return "🛰️" }
