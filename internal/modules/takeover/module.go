package takeover

type Module struct{}

func (m *Module) Name() string        { return "takeover" }
func (m *Module) DisplayName() string { return "Subdomain Takeover" }
func (m *Module) Description() string {
	return "Detect dangling subdomain CNAMEs that point at deprovisioned third-party services (S3, GitHub Pages, Heroku, etc.) and are vulnerable to takeover."
}
func (m *Module) Category() string { return "recon" }
func (m *Module) Icon() string     { return "🪂" }
