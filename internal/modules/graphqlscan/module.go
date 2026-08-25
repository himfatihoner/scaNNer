package graphqlscan

type Module struct{}

func (m *Module) Name() string        { return "graphqlscan" }
func (m *Module) DisplayName() string { return "GraphQL Scanner" }
func (m *Module) Description() string {
	return "Probe GraphQL endpoints for introspection exposure, schema dump, and common abuse patterns (batching, alias overload, CSRF-over-GET, field suggestions)."
}
func (m *Module) Category() string { return "web" }
func (m *Module) Icon() string     { return "📊" }
