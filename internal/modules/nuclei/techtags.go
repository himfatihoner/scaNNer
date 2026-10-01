package nuclei

import (
	"net/url"
	"sort"
	"strings"
)

// Technology-aware tagging: map detected technology names (from techdetect /
// whatweb — e.g. "Microsoft IIS", "WordPress", "Apache HTTP Server") to the
// nuclei template tags that select that stack's templates (e.g. "iis",
// "wordpress", "apache"). This lets nuclei run the RIGHT templates per host
// instead of every template against every target. See TechTags.

// genericBaselineTags are added to every tech-tagged group so stack-agnostic
// findings (exposed panels, misconfigurations, default logins, generic
// exposures) aren't missed when the scan is narrowed to a host's stack. Bare
// "cve" is deliberately excluded: stack tags (e.g. "iis") already pull that
// stack's CVE templates, and adding bare "cve" would run ~every template and
// defeat the targeting. Tune here if you want broader/narrower generic coverage.
var genericBaselineTags = []string{"exposure", "misconfig", "default-login", "panel"}

// techNucleiTag maps a NORMALIZED technology name (see normTech) to the nuclei
// tag(s) that select its templates. Keys are lowercase, alphanumerics only, so
// "Microsoft IIS" / "Microsoft-IIS" both collapse to "microsoftiis". Only tags
// that actually exist in the nuclei template corpus are used; unknown techs map
// to nothing (the host then just gets the user's tags / a full scan).
var techNucleiTag = map[string][]string{
	// Web servers
	"microsoftiis":      {"iis"},
	"iis":               {"iis"},
	"nginx":             {"nginx"},
	"apache":            {"apache"},
	"apachehttpserver":  {"apache"},
	"httpd":             {"apache"},
	"apachetomcat":      {"tomcat"},
	"tomcat":            {"tomcat"},
	"litespeed":         {"litespeed"},
	"openresty":         {"nginx"},
	// Languages / runtimes
	"php":    {"php"},
	"java":   {"java"},
	"python": {"python"},
	"ruby":   {"ruby"},
	"nodejs": {"nodejs"},
	"node":   {"nodejs"},
	// Frameworks
	"laravel":        {"laravel"},
	"symfony":        {"symfony"},
	"rubyonrails":    {"rails"},
	"rails":          {"rails"},
	"spring":         {"spring"},
	"springboot":     {"springboot", "spring"},
	"struts":         {"struts"},
	"apachestruts":   {"struts"},
	"thinkphp":       {"thinkphp"},
	"fastjson":       {"fastjson"},
	"aspnet":         {"aspnet"},
	// CMS / e-commerce
	"wordpress":   {"wordpress"},
	"wp":          {"wordpress"},
	"woocommerce": {"woocommerce", "wordpress"},
	"joomla":      {"joomla"},
	"drupal":      {"drupal"},
	"magento":     {"magento"},
	"prestashop":  {"prestashop"},
	"sitecore":    {"sitecore"},
	"vbulletin":   {"vbulletin"},
	"typo3":       {"typo3"},
	"ghost":       {"ghost"},
	// App servers / middleware
	"weblogic":     {"weblogic"},
	"oracleweblogic": {"weblogic"},
	"jboss":        {"jboss"},
	"wildfly":      {"jboss"},
	"wso2":         {"wso2"},
	"coldfusion":   {"coldfusion"},
	"adobecoldfusion": {"coldfusion"},
	// Dev / ops / data
	"jenkins":      {"jenkins"},
	"gitlab":       {"gitlab"},
	"gitea":        {"gitea"},
	"grafana":      {"grafana"},
	"prometheus":   {"prometheus"},
	"solr":         {"solr"},
	"apachesolr":   {"solr"},
	"kafka":        {"kafka"},
	"docker":       {"docker"},
	"kubernetes":   {"kubernetes"},
	"k8s":          {"kubernetes"},
	"nexus":        {"nexus"},
	"nexusrepository": {"nexus"},
	"geoserver":    {"geoserver"},
	"phpmyadmin":   {"phpmyadmin"},
	// Collaboration / ITSM
	"confluence":   {"confluence"},
	"jira":         {"jira"},
	"servicenow":   {"servicenow"},
	"glpi":         {"glpi"},
	"nagios":       {"nagios"},
	"manageengine": {"manageengine"},
	"odoo":         {"odoo"},
	"zimbra":       {"zimbra"},
	"sharepoint":   {"sharepoint"},
	"microsoftsharepoint": {"sharepoint"},
	// Enterprise / network / vendor
	"citrix":       {"citrix"},
	"netscaler":    {"citrix"},
	"citrixadc":    {"citrix"},
	"fortinet":     {"fortinet"},
	"fortigate":    {"fortinet"},
	"fortios":      {"fortinet"},
	"ivanti":       {"ivanti"},
	"sonicwall":    {"sonicwall"},
	"zyxel":        {"zyxel"},
	"cisco":        {"cisco"},
	"vmware":       {"vmware"},
	"vcenter":      {"vcenter"},
	"vmwarevcenter": {"vcenter"},
	"oracle":       {"oracle"},
	"sap":          {"sap"},
	"solarwinds":   {"solarwinds"},
}

// normTech normalizes a technology name to the techNucleiTag key form: lowercase,
// alphanumerics only ("Microsoft IIS" / "Microsoft-IIS" → "microsoftiis",
// "Node.js" → "nodejs", "ASP.NET" → "aspnet").
func normTech(name string) string {
	var b strings.Builder
	for _, r := range strings.ToLower(name) {
		if (r >= 'a' && r <= 'z') || (r >= '0' && r <= '9') {
			b.WriteRune(r)
		}
	}
	return b.String()
}

// TechTags maps a list of detected technology names to the deduped, sorted set of
// nuclei tags that select their templates. Names with no known mapping are
// dropped. Returns nil when nothing maps (caller treats the host as "no stack").
func TechTags(names []string) []string {
	set := map[string]bool{}
	for _, n := range names {
		for _, tag := range techNucleiTag[normTech(n)] {
			set[tag] = true
		}
	}
	if len(set) == 0 {
		return nil
	}
	out := make([]string, 0, len(set))
	for t := range set {
		out = append(out, t)
	}
	sort.Strings(out)
	return out
}

// effectiveTagSet is the sorted, deduped tag-set a target should be scanned with:
// the operator's own tags ALWAYS apply; if the target has a detected stack
// (TagsByTarget keyed by full URL or bare host) its stack tags plus the generic
// baseline are added. A target with no detected stack gets just the user's tags
// (→ a full scan when the user set none). Used to group targets for per-stack
// nuclei runs.
func effectiveTagSet(cfg ScanConfig, target string) []string {
	set := map[string]bool{}
	addAll := func(ts []string) {
		for _, t := range ts {
			if t = strings.TrimSpace(strings.ToLower(t)); t != "" {
				set[t] = true
			}
		}
	}
	addAll(cfg.Tags)
	tt := cfg.TagsByTarget[target]
	if len(tt) == 0 {
		if h := hostOf(target); h != "" {
			tt = cfg.TagsByTarget[h]
		}
	}
	if len(tt) > 0 {
		addAll(tt)
		addAll(genericBaselineTags)
	}
	if len(set) == 0 {
		return nil
	}
	out := make([]string, 0, len(set))
	for t := range set {
		out = append(out, t)
	}
	sort.Strings(out)
	return out
}

// hostOf extracts the lowercase host (no scheme/port/path) from a target URL or
// bare host string, for matching TagsByTarget keyed by host.
func hostOf(raw string) string {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return ""
	}
	if !strings.Contains(raw, "://") {
		raw = "https://" + raw
	}
	u, err := url.Parse(raw)
	if err != nil || u.Host == "" {
		return ""
	}
	return strings.ToLower(u.Hostname())
}
