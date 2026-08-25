package httpxfind

// Module implements modules.Module
type Module struct{}

func (m *Module) Name() string        { return "httpxfind" }
func (m *Module) DisplayName() string { return "HTTPX Finder" }
func (m *Module) Description() string {
	return "Discover HTTP/HTTPS services on targets. Scan common ports or all ports to find web servers, capture response details."
}
func (m *Module) Category() string { return "recon" }
func (m *Module) Icon() string     { return "🌐" }
