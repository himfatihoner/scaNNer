package httpmethods

// Module implements modules.Module
type Module struct{}

func (m *Module) Name() string        { return "httpmethods" }
func (m *Module) DisplayName() string { return "HTTP Method Tester" }
func (m *Module) Description() string {
	return "Test 15 HTTP methods — GET, HEAD, POST, PUT, DELETE, PATCH, OPTIONS, TRACE, CONNECT plus WebDAV (PROPFIND, MKCOL, COPY, MOVE, LOCK, UNLOCK) — against target URLs across content-type variants (30 probes per URL) and detect allowed/dangerous methods."
}
func (m *Module) Category() string { return "web" }
func (m *Module) Icon() string     { return "📡" }
