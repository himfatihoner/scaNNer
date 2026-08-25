package assetdisc

type Module struct{}

func (m *Module) Name() string        { return "assetdisc" }
func (m *Module) DisplayName() string { return "Asset Discovery" }
func (m *Module) Description() string {
	return "Discover internet-facing assets bound to an organization, ASN, or domain via Shodan and Censys (uses Settings → API keys)."
}
func (m *Module) Category() string { return "recon" }
func (m *Module) Icon() string     { return "🛰️" }
