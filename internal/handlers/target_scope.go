package handlers

import (
	"net"
	"net/http"
	"strings"

	"scanner/internal/models"
)

// This file implements per-user, per-workspace target scoping:
//   - a "may add targets" permission (users.can_add_targets), and
//   - an allowed-domain allowlist per (user, workspace).
// Enforcement happens centrally in AuthMiddleware for both the target-add routes
// and the module run routes, so a scoped user can neither add nor SCAN a target
// outside their allowed domains — even by typing it straight into a module form.
// An empty allowlist for a (user, workspace) means unrestricted (opt-in scoping);
// admins always bypass.

// targetFormFields are the host/domain/URL-bearing form fields across every
// module run form and the target-add forms (from the full handler audit).
// Search-query fields (e.g. "queries") are intentionally excluded — they are
// keywords, not host targets.
var targetFormFields = []string{
	"targets", "domains", "subdomains", "urls", "target", "domain",
	"manual_targets", "manual_domains", "base_domain", "target_url",
	"login_url", "reset_url", "manual", "value",
	// adpentest's DC IP and dnsenum's reverse-PTR CIDR are also scanner
	// outbound targets and must be scope-checked. (evil_host/sni_host/
	// listen_addr/url are payload-collaborator, TLS-SNI, local-bind, or
	// Burp-forward fields — NOT scan targets — so they are deliberately
	// excluded to avoid breaking those modules.)
	"dc_ip", "reverse_cidr",
}

// isTargetAddPath matches the routes that introduce NEW target values (gated by
// the can_add_targets permission for non-admins).
func isTargetAddPath(p string) bool {
	switch p {
	case "/targets/add", "/targets/bulk", "/modules/assetdisc/promote":
		return true
	}
	return strings.HasPrefix(p, "/modules/dnsenum/import/")
}

// isTargetScopePath matches routes whose submitted targets must fall inside the
// user's allowed-domain scope: module launches plus the direct target-add forms.
func isTargetScopePath(p string) bool {
	return isRunPath(p) || p == "/targets/add" || p == "/targets/bulk"
}

// splitTargets breaks a textarea/CSV value into individual entries.
func splitTargets(v string) []string {
	fields := strings.FieldsFunc(v, func(c rune) bool {
		return c == '\n' || c == '\r' || c == ',' || c == ' ' || c == '\t' || c == ';'
	})
	out := make([]string, 0, len(fields))
	for _, f := range fields {
		if f = strings.TrimSpace(f); f != "" {
			out = append(out, f)
		}
	}
	return out
}

// candidateTargets pulls every host/domain/URL string a request submits, from
// the known target fields plus any target_list_ids (resolved to member values).
func (h *Handler) candidateTargets(r *http.Request, ws *models.Workspace) []string {
	// Parse both urlencoded and multipart bodies (bulk-add uses multipart).
	if r.MultipartForm == nil {
		_ = r.ParseMultipartForm(32 << 20)
	}
	_ = r.ParseForm()
	var out []string
	for _, f := range targetFormFields {
		for _, v := range r.Form[f] {
			out = append(out, splitTargets(v)...)
		}
	}
	if ws != nil {
		for _, lid := range r.Form["target_list_ids"] {
			if lid = strings.TrimSpace(lid); lid == "" {
				continue
			}
			members, _ := h.db.ListTargetsInList(lid)
			for _, m := range members {
				out = append(out, m.Value)
			}
		}
	}
	return out
}

// domainInScope reports whether a single target string falls within the allowed
// patterns. A pattern is a domain (matches the host itself and any subdomain,
// via exact / suffix / eTLD+1) or an IP/CIDR (matches IP membership). An IP
// target requires an IP/CIDR pattern, so a domain-only allowlist denies IPs.
func domainInScope(target string, patterns []string) bool {
	t := strings.ToLower(strings.TrimSpace(target))
	if t == "" {
		return true
	}
	if ip, isIP := targetIP(t); isIP {
		for _, p := range patterns {
			if ipPatternMatches(ip, strings.TrimSpace(p)) {
				return true
			}
		}
		return false
	}
	host := normalizeAsset(t) // strip scheme/port/path → bare host
	if host == "" {
		host = t
	}
	base := baseDomain(host)
	for _, p := range patterns {
		p = strings.ToLower(strings.TrimSpace(p))
		if p == "" || isIPPattern(p) {
			continue // IP/CIDR pattern can't match a domain
		}
		if host == p || strings.HasSuffix(host, "."+p) || base == p {
			return true
		}
	}
	return false
}

// targetIP extracts a single IP when the target's host is a literal IP
// ("1.2.3.4", "1.2.3.4:80", "http://1.2.3.4/x", "10.0.0.0/24" → base IP).
func targetIP(t string) (net.IP, bool) {
	host := normalizeAsset(t)
	if host == "" {
		host = t
	}
	if i := strings.IndexByte(host, '/'); i >= 0 {
		host = host[:i]
	}
	if ip := net.ParseIP(host); ip != nil {
		return ip, true
	}
	return nil, false
}

func isIPPattern(p string) bool {
	if strings.Contains(p, "/") {
		_, _, err := net.ParseCIDR(p)
		return err == nil
	}
	return net.ParseIP(p) != nil
}

func ipPatternMatches(ip net.IP, pattern string) bool {
	if strings.Contains(pattern, "/") {
		_, n, err := net.ParseCIDR(pattern)
		return err == nil && n.Contains(ip)
	}
	pip := net.ParseIP(pattern)
	return pip != nil && pip.Equal(ip)
}

// scopeViolation checks every candidate target in a request against the user's
// allowlist for the effective workspace. Returns (offending, true) on the first
// out-of-scope target. Empty allowlist or admin → never a violation.
func (h *Handler) scopeViolation(r *http.Request, user *models.User) (string, bool) {
	if user == nil || user.IsAdmin() {
		return "", false
	}
	ws := h.effectiveWorkspace(r, user)
	if ws == nil {
		return "", false
	}
	patterns := h.db.UserWorkspaceDomains(user.ID, ws.ID)
	if len(patterns) == 0 {
		return "", false
	}
	for _, c := range h.candidateTargets(r, ws) {
		if !domainInScope(c, patterns) {
			return c, true
		}
	}
	return "", false
}
