package openredirect

type Module struct{}

func (m *Module) Name() string        { return "openredirect" }
func (m *Module) DisplayName() string { return "Open Redirect" }
func (m *Module) Description() string {
	return "Fuzz redirect-candidate parameters (next, url, redirect, return, goto, dest) with external-host payloads and bypass variants to find open-redirect vulnerabilities."
}
func (m *Module) Category() string { return "web" }
func (m *Module) Icon() string     { return "↪️" }
