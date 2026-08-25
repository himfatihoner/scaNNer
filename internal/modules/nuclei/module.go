package nuclei

type Module struct{}

func (m *Module) Name() string        { return "nuclei" }
func (m *Module) DisplayName() string { return "Nuclei" }
func (m *Module) Description() string {
	return "Template-driven vulnerability scanner powered by ProjectDiscovery's Nuclei. Runs CVE checks, exposure detection, default-credentials, and misconfiguration templates against web targets."
}
func (m *Module) Category() string { return "web" }
func (m *Module) Icon() string     { return "🌋" }
