package advancedweb

import (
	"strings"

	"scanner/internal/modules/techdetect"
)

// techNameToProfile maps lowercase substrings found in techdetect's
// Technology.Name to the direnum profile id. The list intentionally
// stays narrow — only well-defined platforms with curated wordlists
// in direnum's TechProfile registry. Substring matching keeps
// "ASP.NET 4.7" → "asp" and "Apache/2.4 (Ubuntu)" → "apache" working.
var techNameToProfile = []struct {
	needle string
	id     string
}{
	{"wordpress", "wordpress"},
	{"drupal", "drupal"},
	{"joomla", "joomla"},
	// Note: "asp" is intentionally before "asp.net" because the substring
	// search would match either; both should map to the same profile.
	{"aspx", "asp"},
	{"asp.net", "asp"},
	{"iis", "asp"},
	{"php", "php"},
	{"tomcat", "java"},
	{"jboss", "java"},
	{"spring", "java"},
	{"java", "java"},
	{"django", "python"},
	{"flask", "python"},
	{"fastapi", "python"},
	{"python", "python"},
	{"express", "node"},
	{"next.js", "node"},
	{"node.js", "node"},
	{"nodejs", "node"},
	{"coldfusion", "coldfusion"},
	{"apache", "apache"},
}

// TechToDirenumProfiles inspects the techdetect output and returns the
// list of direnum profile ids the orchestrator should pass to direnum.
// Always includes "general" so a baseline wordlist runs even when no
// platform was identified. Order is preserved: most-specific first
// (general always last so it doesn't override the active profile's
// extension list inside direnum's resolveProfiles).
func TechToDirenumProfiles(techs []techdetect.Technology) []string {
	out := []string{}
	seen := map[string]bool{}
	for _, t := range techs {
		needle := strings.ToLower(t.Name)
		for _, m := range techNameToProfile {
			if strings.Contains(needle, m.needle) {
				if !seen[m.id] {
					out = append(out, m.id)
					seen[m.id] = true
				}
				break
			}
		}
	}
	if !seen["general"] {
		out = append(out, "general")
	}
	return out
}
