package corsscan

type Module struct{}

func (m *Module) Name() string        { return "corsscan" }
func (m *Module) DisplayName() string { return "CORS Misconfig" }
func (m *Module) Description() string {
	return "Probe CORS handling for origin reflection, null-origin trust, arbitrary-subdomain regex bypass, and Access-Control-Allow-Credentials with wildcard."
}
func (m *Module) Category() string { return "web" }
func (m *Module) Icon() string     { return "🌍" }
