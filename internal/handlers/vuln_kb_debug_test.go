package handlers

import (
	"strings"
	"testing"
)

// TestDebugModeClass verifies ASP.NET/app debug-mode findings classify to the
// dedicated KB class and get a concrete remediation instead of the generic one.
func TestDebugModeClass(t *testing.T) {
	titles := []string{
		"ASP.NET Debug Mode Enabled",
		"Microsoft ASPX/ASP.NET Debugging Enabled",
		"Debug mode enabled",
		"HTTP TRACE.AXD detected (trace.axd)",
	}
	for _, ti := range titles {
		if c := classifyVuln("nuclei", ti, false); c != "debug-mode" {
			t.Errorf("classifyVuln(%q) = %q, want debug-mode", ti, c)
		}
	}
	for _, lang := range []string{"tr", "en"} {
		rem := kbTextFor("debug-mode", lang).Remediation
		if !strings.Contains(rem, `debug="false"`) {
			t.Errorf("%s debug-mode remediation not specific (no compilation debug=false): %q", lang, rem)
		}
		if rem == kbTextFor("generic", lang).Remediation {
			t.Errorf("%s debug-mode still resolves to the generic remediation", lang)
		}
	}
}
