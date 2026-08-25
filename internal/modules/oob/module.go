package oob

type Module struct{}

func (m *Module) Name() string        { return "oob" }
func (m *Module) DisplayName() string { return "OOB Collaborator (local)" }
func (m *Module) Description() string {
	return "Local HTTP callback listener for proving blind SSRF/XXE/SSTI — ONLY usable when the target can reach scaNNer's host (lab, CTF, VPN-tunneled engagement, or public-IP self-host). For public-target tests use Interactsh (oast.fun) or Burp Collaborator instead."
}
func (m *Module) Category() string { return "recon" }
func (m *Module) Icon() string     { return "📡" }
