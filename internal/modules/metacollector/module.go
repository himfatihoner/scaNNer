// Package metacollector is a FOCA-style document-metadata OSINT module. It
// Google-dorks a domain for public documents via the Serper.dev search API,
// downloads them, extracts metadata (exiftool + body text) and classifies it
// into FOCA categories (users, software, OS, printers, internal paths, emails,
// servers, company, dates, GPS). It is a faithful Go port of the standalone
// meta-collector project; exiftool/pdftotext/soffice remain external binaries
// invoked through shared.Command (killswitch-aware), while search and document
// downloads go through shared.HTTPOptions/BoundDialer so all traffic stays on
// the pinned outbound interface. The report is rendered separately by the
// handler (internal/handlers/metacollector_report.go).
package metacollector

// Module implements modules.Module.
type Module struct{}

func (m *Module) Name() string        { return "metacollector" }
func (m *Module) DisplayName() string { return "Google Metadata Collector (Serper.dev)" }
func (m *Module) Description() string {
	return "FOCA-style document-metadata OSINT: Google-dorks a domain for public documents via the " +
		"Serper.dev API, downloads them, and extracts metadata (authors, software, internal paths, " +
		"emails, servers, dates, GPS) with exiftool. Requires a Serper API key in Settings."
}
func (m *Module) Category() string { return "recon" }
func (m *Module) Icon() string     { return "📄" }
