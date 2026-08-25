package paramdisc

type Module struct{}

func (m *Module) Name() string        { return "paramdisc" }
func (m *Module) DisplayName() string { return "Parameter Discovery" }
func (m *Module) Description() string {
	return "Arjun-style hidden parameter discovery. Sends candidate query/POST parameters and flags those that change the response (length, status, reflection)."
}
func (m *Module) Category() string { return "web" }
func (m *Module) Icon() string     { return "🧪" }
