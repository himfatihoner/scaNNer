package sslscan

// Module implements the modules.Module interface
type Module struct{}

func (m *Module) Name() string        { return "sslscan" }
func (m *Module) DisplayName() string { return "SSL/TLS Scanner" }
func (m *Module) Description() string {
	return "Thorough SSL/TLS audit using nmap NSE + sslscan + openssl: vulnerable protocols (SSLv2/v3, POODLE/DROWN), weak/anonymous cipher suites, Heartbleed, CRIME, Logjam, and certificate issues with CVE references and severity scoring."
}
func (m *Module) Category() string { return "network" }
func (m *Module) Icon() string     { return "🔒" }
