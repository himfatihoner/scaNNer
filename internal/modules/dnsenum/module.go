package dnsenum

type Module struct{}

func (m *Module) Name() string        { return "dnsenum" }
func (m *Module) DisplayName() string { return "DNS Enumerator" }
func (m *Module) Description() string {
	return "Advanced subdomain enumeration using puredns, subfinder, amass, recon-ng, and authoritative NS brute-forcing with multiple speed profiles."
}
func (m *Module) Category() string { return "recon" }
func (m *Module) Icon() string     { return "🔎" }
