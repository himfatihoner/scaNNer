package wpscan

type Module struct{}

func (m *Module) Name() string        { return "wpscan" }
func (m *Module) DisplayName() string { return "WPScan" }
func (m *Module) Description() string {
	return "WordPress vulnerability scanner powered by WPScan. Detects vulnerable plugins, themes, core version issues, and misconfigurations."
}
func (m *Module) Category() string { return "web" }
func (m *Module) Icon() string     { return "🔵" }
