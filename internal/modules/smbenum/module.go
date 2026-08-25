package smbenum

type Module struct{}

func (m *Module) Name() string        { return "smbenum" }
func (m *Module) DisplayName() string { return "SMB Enum" }
func (m *Module) Description() string {
	return "SMB enumeration via enum4linux + nmap smb-* scripts. Lists shares, users, OS info, sessions, password policy, and known SMB vulnerabilities."
}
func (m *Module) Category() string { return "network" }
func (m *Module) Icon() string     { return "📁" }
