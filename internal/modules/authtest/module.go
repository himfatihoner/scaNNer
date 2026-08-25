package authtest

type Module struct{}

func (m *Module) Name() string        { return "authtest" }
func (m *Module) DisplayName() string { return "Auth Tester" }
func (m *Module) Description() string {
	return "Probe login flows for username enumeration, weak credential acceptance, password reset token entropy, and session fixation."
}
func (m *Module) Category() string { return "web" }
func (m *Module) Icon() string     { return "🔐" }
