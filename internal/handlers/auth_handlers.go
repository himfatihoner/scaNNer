package handlers

import (
	"encoding/base64"
	"net/http"
	"net/url"
	"strings"
	"time"

	qrcode "github.com/skip2/go-qrcode"

	"scanner/internal/auth"
	"scanner/internal/models"
)

// loginFailMsg is the SINGLE message shown for every password-stage failure
// (unknown user, wrong password, disabled, or locked out). Using one message
// prevents username enumeration via a lockout-response differential.
const loginFailMsg = "Invalid username or password, or the account is temporarily locked. If you keep trying, the account may be locked for a while."

// This file holds the login / two-factor / logout / account handlers. The
// templates (login.html, twofactor.html, account.html) render standalone pages
// so they don't depend on the authenticated sidebar layout.

const totpIssuer = "scaNNer"

// EnsureAdminUser bootstraps the first admin account with a random password when
// the users table is empty. Returns (username, plaintextPassword, created). The
// caller prints the password once — it is never stored in plaintext or shown
// again (the account is flagged must-change-password).
func (h *Handler) EnsureAdminUser() (string, string, bool, error) {
	if h.db.AnyUsersExist() {
		return "", "", false, nil
	}
	password, err := auth.GeneratePassword(20)
	if err != nil {
		return "", "", false, err
	}
	hash, err := auth.HashPassword(password)
	if err != nil {
		return "", "", false, err
	}
	u := &models.User{
		Username:           "admin",
		Role:               models.RoleAdmin,
		IsActive:           true,
		MustChangePassword: true,
		PasswordHash:       hash,
	}
	if _, err := h.db.CreateUser(u); err != nil {
		return "", "", false, err
	}
	return "admin", password, true, nil
}

// safeNext returns a same-site redirect target ("/" if the supplied next is
// missing or looks off-site).
func safeNext(next string) string {
	// Must be a local, absolute path — no scheme/host, and none of the tricks a
	// browser normalizes into an off-site URL (//host, /\host, CR/LF, tab).
	if next == "" || !strings.HasPrefix(next, "/") {
		return "/"
	}
	if strings.HasPrefix(next, "//") || strings.HasPrefix(next, "/\\") {
		return "/"
	}
	if strings.ContainsAny(next, "\\\r\n\t") {
		return "/"
	}
	if u, err := url.Parse(next); err != nil || u.Scheme != "" || u.Host != "" {
		return "/"
	}
	return next
}

// LoginPage renders the login form (or bounces an already-authenticated user).
func (h *Handler) LoginPage(w http.ResponseWriter, r *http.Request) {
	if u, s := h.resolveSession(r); u != nil && s.State == models.SessionActive {
		http.Redirect(w, r, "/", http.StatusSeeOther)
		return
	}
	h.render(w, "login_page", map[string]interface{}{
		"Title": "Sign in - scaNNer",
		"Next":  r.URL.Query().Get("next"),
		"Error": r.URL.Query().Get("error"),
	})
}

func (h *Handler) renderLoginError(w http.ResponseWriter, next, msg string) {
	w.WriteHeader(http.StatusUnauthorized)
	h.render(w, "login_page", map[string]interface{}{
		"Title": "Sign in - scaNNer",
		"Next":  next,
		"Error": msg,
	})
}

// LoginSubmit verifies username+password, applies lockout, and either logs the
// user in or hands off to the 2FA step.
func (h *Handler) LoginSubmit(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Redirect(w, r, "/login", http.StatusSeeOther)
		return
	}
	username := strings.TrimSpace(r.FormValue("username"))
	password := r.FormValue("password")
	next := safeNext(r.FormValue("next"))

	user, err := h.db.GetUserByUsername(username)
	if err != nil {
		// Unknown user: burn a bcrypt comparison so timing can't distinguish
		// "no such user" from "wrong password".
		auth.CheckPassword(auth.DummyHash, password)
		h.audit(r, nil, models.AuditAccess, "login.fail", "unknown user: "+username)
		h.renderLoginError(w, next, loginFailMsg)
		return
	}
	now := time.Now()
	if !user.IsActive {
		h.renderLoginError(w, next, loginFailMsg)
		return
	}
	if user.LoginLocked(now) {
		h.audit(r, user, models.AuditAccess, "login.locked", "attempt during lockout")
		h.renderLoginError(w, next, loginFailMsg)
		return
	}
	if !auth.CheckPassword(user.PasswordHash, password) {
		locked := h.db.RegisterFailedLogin(user.ID, maxLoginAttempts, loginLockWindow)
		if locked {
			h.audit(r, user, models.AuditAccess, "login.locked", "5 failed password attempts")
		} else {
			h.audit(r, user, models.AuditAccess, "login.fail", "bad password")
		}
		h.renderLoginError(w, next, loginFailMsg)
		return
	}

	// Password OK. If the account requires 2FA and is enrolled, hand off.
	if user.TwoFactorRequired && user.TwoFactorEnrolled && user.TwoFactorMethod != models.TwoFactorNone {
		sess, err := h.issueSession(w, r, user.ID, models.SessionPending2FA, pendingTTL)
		if err != nil {
			h.renderLoginError(w, next, "Could not start session. Try again.")
			return
		}
		if user.TwoFactorMethod == models.TwoFactorEmail {
			if err := h.sendEmailOTP(sess.ID, user); err != nil {
				h.db.DeleteSession(sess.ID)
				h.clearSessionCookie(w)
				h.renderLoginError(w, next, "Could not send your e-mail code: "+err.Error())
				return
			}
		}
		h.audit(r, user, models.AuditAccess, "login.password_ok", "awaiting 2FA")
		http.Redirect(w, r, "/login/2fa?next="+safeNext(next), http.StatusSeeOther)
		return
	}

	// No 2FA (or required-but-not-enrolled → the middleware will force
	// enrollment on the account page): full login.
	if _, err := h.issueSession(w, r, user.ID, models.SessionActive, sessionTTL); err != nil {
		h.renderLoginError(w, next, "Could not start session. Try again.")
		return
	}
	h.db.ClearLoginFailures(user.ID)
	h.audit(r, user, models.AuditAccess, "login.success", "")
	http.Redirect(w, r, next, http.StatusSeeOther)
}

// sendEmailOTP generates a code, stores its hash on the pending session, and
// mails it.
func (h *Handler) sendEmailOTP(sessHash string, user *models.User) error {
	code, err := auth.GenerateEmailOTP()
	if err != nil {
		return err
	}
	if err := h.db.SetSessionOTP(sessHash, auth.HashToken(code), time.Now().Add(emailOTPTTL)); err != nil {
		return err
	}
	s := h.db.GetSettings()
	body := "Your scaNNer sign-in code is: " + code + "\n\nIt expires in 10 minutes.\nIf you did not try to sign in, ignore this message."
	return sendMail(s, user.Email, "scaNNer sign-in code", body)
}

// TwoFactorPage renders the 2FA challenge for a pending session.
func (h *Handler) TwoFactorPage(w http.ResponseWriter, r *http.Request) {
	user, sess := h.resolveSession(r)
	if user == nil || sess.State != models.SessionPending2FA {
		http.Redirect(w, r, "/login", http.StatusSeeOther)
		return
	}
	h.render(w, "twofactor_page", map[string]interface{}{
		"Title":  "Two-factor - scaNNer",
		"Method": user.TwoFactorMethod,
		"Next":   r.URL.Query().Get("next"),
		"Error":  r.URL.Query().Get("error"),
	})
}

// TwoFactorSubmit verifies the code, applies lockout, and completes login.
func (h *Handler) TwoFactorSubmit(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Redirect(w, r, "/login/2fa", http.StatusSeeOther)
		return
	}
	user, sess := h.resolveSession(r)
	if user == nil || sess.State != models.SessionPending2FA {
		http.Redirect(w, r, "/login", http.StatusSeeOther)
		return
	}
	next := safeNext(r.FormValue("next"))
	code := strings.TrimSpace(r.FormValue("code"))
	now := time.Now()

	if user.TwoFactorLocked(now) {
		h.render2FAError(w, user.TwoFactorMethod, next, "Two-factor temporarily locked. Try again later.")
		return
	}

	ok := false
	var totpStep int64
	switch user.TwoFactorMethod {
	case models.TwoFactorTOTP:
		// One-time use: accept only a step strictly newer than the last one we
		// accepted for this user, so a captured code can't be replayed.
		if step, good := auth.VerifyTOTPStep(user.TwoFactorSecret, code); good && step > user.TwoFactorLastStep {
			ok = true
			totpStep = step
		}
	case models.TwoFactorEmail:
		if sess.OTPHash != "" && sess.OTPExpires != nil && sess.OTPExpires.After(now) {
			ok = auth.ConstantTimeEqual(auth.HashToken(code), sess.OTPHash)
		}
	}

	if !ok {
		locked := h.db.RegisterFailed2FA(user.ID, max2FAAttempts, twoFALockWindow)
		if locked {
			h.audit(r, user, models.AuditAccess, "2fa.locked", "5 failed 2FA attempts")
			h.db.DeleteSession(sess.ID)
			h.clearSessionCookie(w)
			http.Redirect(w, r, "/login?error="+"Too many failed codes. Locked for 4 minutes.", http.StatusSeeOther)
			return
		}
		h.audit(r, user, models.AuditAccess, "2fa.fail", "")
		h.render2FAError(w, user.TwoFactorMethod, next, "Incorrect code.")
		return
	}

	// Success: rotate to a fresh active session (fixation defense).
	h.db.DeleteSession(sess.ID)
	h.db.Clear2FAFailures(user.ID)
	if user.TwoFactorMethod == models.TwoFactorTOTP {
		h.db.SetTwoFactorLastStep(user.ID, totpStep) // burn the code (one-time use)
	}
	if _, err := h.issueSession(w, r, user.ID, models.SessionActive, sessionTTL); err != nil {
		http.Redirect(w, r, "/login?error=session", http.StatusSeeOther)
		return
	}
	h.db.ClearLoginFailures(user.ID)
	h.audit(r, user, models.AuditAccess, "login.success", "2FA "+user.TwoFactorMethod)
	http.Redirect(w, r, next, http.StatusSeeOther)
}

func (h *Handler) render2FAError(w http.ResponseWriter, method, next, msg string) {
	w.WriteHeader(http.StatusUnauthorized)
	h.render(w, "twofactor_page", map[string]interface{}{
		"Title":  "Two-factor - scaNNer",
		"Method": method,
		"Next":   next,
		"Error":  msg,
	})
}

// Logout ends the session.
func (h *Handler) Logout(w http.ResponseWriter, r *http.Request) {
	if _, sess := h.resolveSession(r); sess != nil {
		h.db.DeleteSession(sess.ID)
	}
	h.clearSessionCookie(w)
	http.Redirect(w, r, "/login", http.StatusSeeOther)
}

// --- Account (self-service password + 2FA enrollment) -----------------------

// AccountPage renders the self-service account page.
func (h *Handler) AccountPage(w http.ResponseWriter, r *http.Request) {
	user := h.currentUser(r)
	if user == nil {
		http.Redirect(w, r, "/login", http.StatusSeeOther)
		return
	}
	settings := h.db.GetSettings()
	data := map[string]interface{}{
		"Title":              "Account - scaNNer",
		"User":               user,
		"MustChangePassword": user.MustChangePassword,
		"MustEnroll2FA":      user.TwoFactorRequired && !user.TwoFactorEnrolled,
		"SMTPConfigured":     settings.SMTPConfigured(),
		"Success":            r.URL.Query().Get("success"),
		"Error":              r.URL.Query().Get("error"),
	}
	// When TOTP setup is mid-flight (secret set, not yet confirmed), show the QR.
	if user.TwoFactorMethod == models.TwoFactorTOTP && !user.TwoFactorEnrolled && user.TwoFactorSecret != "" {
		otpURL := auth.OTPAuthURL(totpIssuer, user.Username, user.TwoFactorSecret)
		if png, err := qrcode.Encode(otpURL, qrcode.Medium, 256); err == nil {
			data["TOTPQR"] = "data:image/png;base64," + base64.StdEncoding.EncodeToString(png)
			data["TOTPSecret"] = user.TwoFactorSecret
			data["TOTPSetup"] = true
		}
	}
	h.render(w, "account_page", data)
}

// AccountPassword changes the current user's password.
func (h *Handler) AccountPassword(w http.ResponseWriter, r *http.Request) {
	user := h.currentUser(r)
	if user == nil || r.Method != http.MethodPost {
		http.Redirect(w, r, "/account", http.StatusSeeOther)
		return
	}
	current := r.FormValue("current_password")
	next := r.FormValue("new_password")
	confirm := r.FormValue("confirm_password")

	if !auth.CheckPassword(user.PasswordHash, current) {
		http.Redirect(w, r, "/account?error="+"Current password is incorrect.", http.StatusSeeOther)
		return
	}
	if len(next) < 12 {
		http.Redirect(w, r, "/account?error="+"New password must be at least 12 characters.", http.StatusSeeOther)
		return
	}
	if next != confirm {
		http.Redirect(w, r, "/account?error="+"Passwords do not match.", http.StatusSeeOther)
		return
	}
	hash, err := auth.HashPassword(next)
	if err != nil {
		http.Redirect(w, r, "/account?error=hash", http.StatusSeeOther)
		return
	}
	h.db.SetUserPassword(user.ID, hash, false)
	h.audit(r, user, models.AuditAccess, "password.change", "self-service")
	http.Redirect(w, r, "/account?success="+"Password updated.", http.StatusSeeOther)
}

// AccountEnroll2FA drives the user's own 2FA setup/teardown.
func (h *Handler) AccountEnroll2FA(w http.ResponseWriter, r *http.Request) {
	user := h.currentUser(r)
	if user == nil || r.Method != http.MethodPost {
		http.Redirect(w, r, "/account", http.StatusSeeOther)
		return
	}
	action := r.FormValue("action")
	switch action {
	case "totp_init":
		secret, err := auth.GenerateTOTPSecret()
		if err != nil {
			http.Redirect(w, r, "/account?error=totp", http.StatusSeeOther)
			return
		}
		h.db.SetUserTwoFactor(user.ID, models.TwoFactorTOTP, secret, false)
		http.Redirect(w, r, "/account", http.StatusSeeOther)
	case "totp_confirm":
		code := strings.TrimSpace(r.FormValue("code"))
		if user.TwoFactorSecret == "" || !auth.VerifyTOTP(user.TwoFactorSecret, code) {
			http.Redirect(w, r, "/account?error="+"Incorrect code — try again.", http.StatusSeeOther)
			return
		}
		h.db.SetUserTwoFactor(user.ID, models.TwoFactorTOTP, user.TwoFactorSecret, true)
		h.audit(r, user, models.AuditAccess, "2fa.enroll", "totp")
		http.Redirect(w, r, "/account?success="+"Authenticator app enabled.", http.StatusSeeOther)
	case "email":
		settings := h.db.GetSettings()
		if strings.TrimSpace(user.Email) == "" {
			http.Redirect(w, r, "/account?error="+"Your account has no e-mail address; ask an admin to set one.", http.StatusSeeOther)
			return
		}
		if !settings.SMTPConfigured() {
			http.Redirect(w, r, "/account?error="+"E-mail 2FA needs SMTP configured by an admin.", http.StatusSeeOther)
			return
		}
		h.db.SetUserTwoFactor(user.ID, models.TwoFactorEmail, "", true)
		h.audit(r, user, models.AuditAccess, "2fa.enroll", "email")
		http.Redirect(w, r, "/account?success="+"E-mail codes enabled.", http.StatusSeeOther)
	case "disable":
		if user.TwoFactorRequired {
			http.Redirect(w, r, "/account?error="+"An admin requires 2FA on your account.", http.StatusSeeOther)
			return
		}
		h.db.ResetUserTwoFactor(user.ID)
		h.audit(r, user, models.AuditAccess, "2fa.disable", "self-service")
		http.Redirect(w, r, "/account?success="+"Two-factor disabled.", http.StatusSeeOther)
	default:
		http.Redirect(w, r, "/account", http.StatusSeeOther)
	}
}
