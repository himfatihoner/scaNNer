package handlers

import (
	"net/http"
	"os"
	"path/filepath"
)

// ToolsPage renders the offline utility toolbox: an embedded CyberChef, a
// Burp-style Comparer, a URL encoder/decoder, and an ASP.NET ViewState decoder.
// Everything runs client-side — no scan traffic, no external calls — so it is
// available to any authenticated user (no admin gate in authorizePath).
//
// CyberChef is self-hosted under web/static/cyberchef/ (fully offline). We probe
// for its entry file so the page can show a clear "not installed" hint instead of
// a broken iframe if the build was stripped from a deploy.
func (h *Handler) ToolsPage(w http.ResponseWriter, r *http.Request) {
	data := h.baseData(r, "Tools - scaNNer", "tools")
	// Serve the directory form (/static/cyberchef/) so Go's FileServer returns
	// index.html directly instead of 301-redirecting /index.html → ./.
	data["CyberChefReady"] = fileExists(filepath.Join("web", "static", "cyberchef", "index.html"))
	data["CyberChefSrc"] = "/static/cyberchef/"
	h.render(w, "layout", data)
}

func fileExists(p string) bool {
	info, err := os.Stat(p)
	return err == nil && !info.IsDir()
}
