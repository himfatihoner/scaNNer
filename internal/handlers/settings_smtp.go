package handlers

import (
	"net/http"
	"net/url"
	"strings"

	"scanner/internal/models"
)

// smtpTLSMode normalizes the TLS-mode form value to a known option.
func smtpTLSMode(v string) string {
	switch strings.ToLower(strings.TrimSpace(v)) {
	case "ssl":
		return "ssl"
	case "none":
		return "none"
	default:
		return "starttls"
	}
}

// SMTPTest sends a probe e-mail using the currently saved SMTP settings so the
// admin can confirm delivery. It lives in its own tiny form (not the main
// settings form) so it works regardless of the running-scan save lock.
func (h *Handler) SMTPTest(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Redirect(w, r, "/settings", http.StatusSeeOther)
		return
	}
	to := strings.TrimSpace(r.FormValue("test_to"))
	s := h.db.GetSettings()
	if to == "" {
		to = s.SMTPFrom
	}
	if to == "" {
		http.Redirect(w, r, "/settings?smtp_ok=0&smtp_result="+url.QueryEscape("Enter a recipient (or set a From address).")+"#smtp", http.StatusSeeOther)
		return
	}
	err := sendMail(s, to, "scaNNer SMTP test", "This is a test message from scaNNer. If you received it, SMTP is working.")
	if err != nil {
		h.audit(r, h.currentUser(r), models.AuditAdmin, "smtp.test_fail", err.Error())
		http.Redirect(w, r, "/settings?smtp_ok=0&smtp_result="+url.QueryEscape("SMTP test failed: "+err.Error())+"#smtp", http.StatusSeeOther)
		return
	}
	h.audit(r, h.currentUser(r), models.AuditAdmin, "smtp.test_ok", "to "+to)
	http.Redirect(w, r, "/settings?smtp_ok=1&smtp_result="+url.QueryEscape("Test e-mail sent to "+to)+"#smtp", http.StatusSeeOther)
}
