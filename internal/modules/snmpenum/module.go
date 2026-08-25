package snmpenum

type Module struct{}

func (m *Module) Name() string        { return "snmpenum" }
func (m *Module) DisplayName() string { return "SNMP Enum" }
func (m *Module) Description() string {
	return "SNMP enumeration: brute-force community strings with onesixtyone, then walk system info, interfaces, processes, software, and users via snmpwalk."
}
func (m *Module) Category() string { return "network" }
func (m *Module) Icon() string     { return "📶" }
