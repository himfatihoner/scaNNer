package concurtest

type Module struct{}

func (m *Module) Name() string        { return "concurtest" }
func (m *Module) DisplayName() string { return "Concurrency Tester" }
func (m *Module) Description() string {
	return "Probe a target's concurrency tolerance with three scenarios — a level-by-level ramp test, a sustained-load test, and a burst test — to find the practical request-rate ceiling before timeouts, throttling, or rate-limit responses kick in."
}
func (m *Module) Category() string { return "web" }
func (m *Module) Icon() string     { return "⚡" }
