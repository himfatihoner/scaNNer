package sstiscan

type Module struct{}

func (m *Module) Name() string        { return "sstiscan" }
func (m *Module) DisplayName() string { return "SSTI Probe" }
func (m *Module) Description() string {
	return "Detect server-side template injection across Jinja2 / Twig / ERB / Mustache / Velocity / FreeMarker / Pug engines using engine-specific arithmetic markers."
}
func (m *Module) Category() string { return "web" }
func (m *Module) Icon() string     { return "🧪" }
