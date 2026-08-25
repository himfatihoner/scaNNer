package wafdetect

type Module struct{}

func (m *Module) Name() string        { return "wafdetect" }
func (m *Module) DisplayName() string { return "WAF Detector" }
func (m *Module) Description() string {
	return "Detect Web Application Firewalls using header analysis, cookie inspection, error page fingerprinting, and payload-based probing."
}
func (m *Module) Category() string { return "recon" }
func (m *Module) Icon() string     { return "🛡️" }
