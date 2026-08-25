package emailharvest

type Module struct{}

func (m *Module) Name() string        { return "emailharvest" }
func (m *Module) DisplayName() string { return "Email Harvester" }
func (m *Module) Description() string {
	return "Wraps theHarvester to collect emails, hostnames, and IPs for a target domain from public sources (crtsh, hackertarget, urlscan, baidu, bing, duckduckgo, etc.)."
}
func (m *Module) Category() string { return "recon" }
func (m *Module) Icon() string     { return "📧" }
