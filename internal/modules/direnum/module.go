package direnum

type Module struct{}

func (m *Module) Name() string        { return "direnum" }
func (m *Module) DisplayName() string { return "Directory Enumerator" }
func (m *Module) Description() string {
	return "Brute-force directories and files with technology-aware wordlists, smart false-positive filtering, and customizable scan intensity."
}
func (m *Module) Category() string { return "web" }
func (m *Module) Icon() string     { return "📂" }
