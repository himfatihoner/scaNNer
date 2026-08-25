package cachepoison

type Module struct{}

func (m *Module) Name() string        { return "cachepoison" }
func (m *Module) DisplayName() string { return "Cache & Smuggle" }
func (m *Module) Description() string {
	return "Probe web cache poisoning (Host / X-Forwarded-Host / X-Forwarded-Scheme / unkeyed headers) and HTTP request smuggling (CL.TE, TE.CL, TE.TE)."
}
func (m *Module) Category() string { return "web" }
func (m *Module) Icon() string     { return "💥" }
