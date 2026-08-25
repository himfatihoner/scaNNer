package secheaders

type Module struct{}

func (m *Module) Name() string        { return "secheaders" }
func (m *Module) DisplayName() string { return "Security Headers" }
func (m *Module) Description() string {
	return "Analyze HTTP security headers across all method/content-type combinations that return 200 OK. Detect missing, misconfigured, and insecure headers."
}
func (m *Module) Category() string { return "web" }
func (m *Module) Icon() string     { return "🔐" }
