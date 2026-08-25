package techdetect

type Module struct{}

func (m *Module) Name() string        { return "techdetect" }
func (m *Module) DisplayName() string { return "Tech Detector" }
func (m *Module) Description() string {
	return "Detect web technologies, frameworks, CMS, servers, CDNs, analytics, and JavaScript libraries using WhatWeb and header/body fingerprinting."
}
func (m *Module) Category() string { return "recon" }
func (m *Module) Icon() string     { return "🧬" }
