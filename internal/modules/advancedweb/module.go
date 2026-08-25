package advancedweb

type Module struct{}

func (m *Module) Name() string        { return "advancedweb" }
func (m *Module) DisplayName() string { return "Advanced Web Application Scanner" }
func (m *Module) Description() string {
	return "Chains 10 web-focused modules in sequence — WHOIS, DNS, HTTPX, SSL/TLS, WAF, tech detection, Nuclei, directory + spider cross-feed, HTTP methods, security headers — into a single unified report. Modules are user-selectable; later stages consume earlier-stage output (DNS subdomains feed HTTPX, tech detection feeds DirEnum profile selection, etc.)."
}
func (m *Module) Category() string { return "web" }
func (m *Module) Icon() string     { return "🧪" }
