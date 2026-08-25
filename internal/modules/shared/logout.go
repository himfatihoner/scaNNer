package shared

import "strings"

// logoutPatterns are substrings that indicate a logout/signout/terminate-session endpoint
// Matching is case-insensitive and substring-based so variants are caught
var logoutPatterns = []string{
	"logout",
	"log-out",
	"log_out",
	"signout",
	"sign-out",
	"sign_out",
	"log-off",
	"logoff",
	"signoff",
	"sign-off",
	"session-end",
	"end-session",
	"endsession",
	"session_end",
	"end_session",
	"session-kill",
	"kill-session",
	"terminate",
	"revoke",
	"disconnect",
	"deauth",
	"unauth",
	"destroy-session",
	"destroy_session",
	"close-session",
	"expire-session",
	"sso-logout",
	"sso_logout",
	"oauth/logout",
	"saml/logout",
	"slo",
	"goodbye",
	"quitter",
	"quit-session",
}

// IsLogoutPath returns true if the path (or any segment of it) looks like a logout endpoint
func IsLogoutPath(path string) bool {
	if path == "" {
		return false
	}
	lower := strings.ToLower(path)
	for _, p := range logoutPatterns {
		if strings.Contains(lower, p) {
			return true
		}
	}
	return false
}
