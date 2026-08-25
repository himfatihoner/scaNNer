package cvematch

type Module struct{}

func (m *Module) Name() string        { return "cvematch" }
func (m *Module) DisplayName() string { return "CVE Matcher" }
func (m *Module) Description() string {
	return "Match detected technologies + versions against a curated CVE database to surface known vulnerabilities (e.g. Apache 2.4.49 → CVE-2021-41773)."
}
func (m *Module) Category() string { return "vuln" }
func (m *Module) Icon() string     { return "🩻" }
