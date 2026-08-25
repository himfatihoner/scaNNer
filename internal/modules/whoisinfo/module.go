package whoisinfo

type Module struct{}

func (m *Module) Name() string        { return "whoisinfo" }
func (m *Module) DisplayName() string { return "WHOIS / ASN Lookup" }
func (m *Module) Description() string {
	return "Domain or IP WHOIS lookup combined with ASN/BGP discovery: registrar info, owner, dates, ASN number, organization, and the full prefix list for the AS."
}
func (m *Module) Category() string { return "recon" }
func (m *Module) Icon() string     { return "📜" }
