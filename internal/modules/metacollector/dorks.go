package metacollector

import "strings"

// DefaultFiletypes is the exact document-type universe meta-collector dorks for,
// in the original order (dorks.py / config.py). Office (OLE + OOXML),
// OpenOffice/LibreOffice, RTF/PostScript/InDesign, then images (EXIF/XMP).
var DefaultFiletypes = []string{
	"pdf", "doc", "docx", "xls", "xlsx", "ppt", "pptx", "pps",
	"odt", "ods", "odp", "odg", "sxw",
	"rtf", "ps", "eps", "indd",
	"jpg", "jpeg", "tiff", "png", "svg",
}

// combinedQuery builds one dork covering every filetype:
//
//	site:<fqdn> (filetype:pdf OR filetype:doc OR ...)
func combinedQuery(fqdn string, fts []string) string {
	parts := make([]string, 0, len(fts))
	for _, ft := range fts {
		parts = append(parts, "filetype:"+ft)
	}
	return "site:" + fqdn + " (" + strings.Join(parts, " OR ") + ")"
}

// filetypeQuery is one (filetype, query) dork pair in split mode.
type filetypeQuery struct {
	Filetype string
	Query    string
}

// perFiletypeQueries returns one dork per filetype — site:<fqdn> filetype:<ft> —
// so the search ceiling is raised (split mode, the most thorough).
func perFiletypeQueries(fqdn string, fts []string) []filetypeQuery {
	out := make([]filetypeQuery, 0, len(fts))
	for _, ft := range fts {
		out = append(out, filetypeQuery{Filetype: ft, Query: "site:" + fqdn + " filetype:" + ft})
	}
	return out
}
