package handlers

import (
	"context"
	"net"
	"net/http"
	"net/url"
	"strings"
	"time"

	"scanner/internal/auth"
	"scanner/internal/database"
	"scanner/internal/models"
)

// This file implements the request-time identity layer: the session cookie, the
// context plumbing that carries the current user, the auth/authorization
// middleware that wraps every route, and the effective-workspace resolution
// that keeps non-admins inside workspaces they actually have grants in.

const sessionCookie = "scanner_session"

// Session / challenge lifetimes.
const (
	sessionTTL  = 12 * time.Hour
	pendingTTL  = 10 * time.Minute
	emailOTPTTL = 10 * time.Minute
)

// Lockout policy (from the spec): 5 bad passwords → 15 min; 5 bad 2FA → 4 min.
const (
	maxLoginAttempts = 5
	loginLockWindow  = 15 * time.Minute
	max2FAAttempts   = 5
	twoFALockWindow  = 4 * time.Minute
)

type ctxKey int

const userCtxKey ctxKey = 0

// SetSecureCookies toggles the Secure flag on the session cookie. main.go calls
// this true when serving HTTPS (the default) and false for plain-HTTP dev.
func (h *Handler) SetSecureCookies(v bool) { h.secureCookies = v }

// StartSessionJanitor periodically reclaims expired session rows (including
// abandoned pending-2FA sessions). resolveSession only deletes an expired row
// lazily when its exact cookie is re-presented — which never happens for an
// abandoned session — so without this the sessions table grows unbounded.
func (h *Handler) StartSessionJanitor() {
	go func() {
		t := time.NewTicker(1 * time.Hour)
		defer t.Stop()
		h.db.CleanupExpiredSessions() // sweep once at startup
		for range t.C {
			h.db.CleanupExpiredSessions()
		}
	}()
}

// currentUser returns the authenticated user attached to the request context by
// AuthMiddleware, or nil.
func (h *Handler) currentUser(r *http.Request) *models.User {
	u, _ := r.Context().Value(userCtxKey).(*models.User)
	return u
}

// clientIP extracts the peer IP (no XFF trust — this is an internal tool).
func clientIP(r *http.Request) string {
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		return r.RemoteAddr
	}
	return host
}

// --- Session cookie helpers -------------------------------------------------

func (h *Handler) setSessionCookie(w http.ResponseWriter, token string, ttl time.Duration) {
	http.SetCookie(w, &http.Cookie{
		Name:     sessionCookie,
		Value:    token,
		Path:     "/",
		MaxAge:   int(ttl.Seconds()),
		HttpOnly: true,
		Secure:   h.secureCookies,
		SameSite: http.SameSiteLaxMode,
	})
}

func (h *Handler) clearSessionCookie(w http.ResponseWriter) {
	http.SetCookie(w, &http.Cookie{
		Name:     sessionCookie,
		Value:    "",
		Path:     "/",
		MaxAge:   -1,
		HttpOnly: true,
		Secure:   h.secureCookies,
		SameSite: http.SameSiteLaxMode,
	})
}

// issueSession creates a session row and sets the cookie. The raw token goes to
// the cookie; only its hash is stored.
func (h *Handler) issueSession(w http.ResponseWriter, r *http.Request, userID, state string, ttl time.Duration) (*models.Session, error) {
	token, err := auth.NewSessionToken()
	if err != nil {
		return nil, err
	}
	s := &models.Session{
		ID:        auth.HashToken(token),
		UserID:    userID,
		State:     state,
		ExpiresAt: time.Now().Add(ttl),
		IP:        clientIP(r),
		UserAgent: r.UserAgent(),
	}
	if err := h.db.CreateSession(s); err != nil {
		return nil, err
	}
	h.setSessionCookie(w, token, ttl)
	return s, nil
}

// resolveSession loads the user+session from the request cookie, or (nil,nil).
func (h *Handler) resolveSession(r *http.Request) (*models.User, *models.Session) {
	c, err := r.Cookie(sessionCookie)
	if err != nil || c.Value == "" {
		return nil, nil
	}
	idHash := auth.HashToken(c.Value)
	sess, err := h.db.GetSession(idHash)
	if err != nil {
		return nil, nil
	}
	if time.Now().After(sess.ExpiresAt) {
		h.db.DeleteSession(idHash)
		return nil, nil
	}
	user, err := h.db.GetUserByID(sess.UserID)
	if err != nil || !user.IsActive {
		return nil, nil
	}
	// Throttled activity bump — avoid a write on every 2s poll.
	if time.Since(sess.LastSeenAt) > 2*time.Minute {
		h.db.TouchSession(idHash)
	}
	return user, sess
}

// --- Effective workspace ----------------------------------------------------

// effectiveWorkspace resolves the workspace a request operates in, constrained
// for non-admins to a workspace they hold at least one grant in. Admins get the
// cookie workspace (or default). This is used both by the authz middleware and
// by baseData so the two never disagree.
func (h *Handler) effectiveWorkspace(r *http.Request, user *models.User) *models.Workspace {
	var cookieWS *models.Workspace
	if c, err := r.Cookie(activeWSCookie); err == nil {
		if ws, err := h.db.GetWorkspace(c.Value); err == nil {
			cookieWS = ws
		}
	}
	if user == nil || user.IsAdmin() {
		if cookieWS != nil {
			return cookieWS
		}
		ws, _ := h.db.GetWorkspace(database.DefaultWorkspaceID)
		return nonNilWorkspace(ws)
	}
	accessible, _ := h.db.UserWorkspaceIDs(user.ID)
	if cookieWS != nil && accessible[cookieWS.ID] {
		return cookieWS
	}
	all, _ := h.db.ListWorkspaces()
	for _, ws := range all {
		if accessible[ws.ID] {
			if full, err := h.db.GetWorkspace(ws.ID); err == nil {
				return full
			}
		}
	}
	// No accessible workspace: fall back to default (pages will render empty).
	ws, _ := h.db.GetWorkspace(database.DefaultWorkspaceID)
	return nonNilWorkspace(ws)
}

// nonNilWorkspace guarantees a non-nil workspace so handlers that type-assert
// data["ActiveWorkspace"].(*models.Workspace) and read .ID never panic on a
// typed-nil (e.g. if the default-workspace lookup failed under DB lock).
func nonNilWorkspace(ws *models.Workspace) *models.Workspace {
	if ws == nil {
		return &models.Workspace{ID: database.DefaultWorkspaceID, Name: "default"}
	}
	return ws
}

// --- Middleware -------------------------------------------------------------

// authExempt is the set of paths reachable without a session.
func authExempt(path string) bool {
	switch path {
	case "/login", "/login/2fa", "/logout", "/favicon.ico", "/api/health":
		return true
	}
	return strings.HasPrefix(path, "/static/")
}

// wantsJSON reports whether an unauthenticated response should be a status code
// (background poll / API) rather than an HTML redirect to the login page.
func wantsJSON(r *http.Request) bool {
	if r.Method != http.MethodGet {
		return true
	}
	p := r.URL.Path
	if strings.Contains(p, "/status/") || strings.HasSuffix(p, ".json") {
		return true
	}
	return r.URL.Query().Get("partial") == "1"
}

// moduleFromPath extracts the module name a /modules/<name>[/...] request targets.
func moduleFromPath(path string) string {
	if !strings.HasPrefix(path, "/modules/") {
		return ""
	}
	rest := strings.TrimPrefix(path, "/modules/")
	name := rest
	if i := strings.IndexByte(rest, '/'); i >= 0 {
		name = rest[:i]
	}
	if name == "advanced-web" { // route alias → canonical registry name
		name = "advancedweb"
	}
	return name
}

// isRunPath reports whether a path is a module's scan-launch endpoint.
func isRunPath(path string) bool {
	return strings.HasPrefix(path, "/modules/") && strings.HasSuffix(path, "/run")
}

// AuthMiddleware wraps the whole mux. It is installed outermost in main.go so
// every request passes the auth gate before reaching any handler.
func (h *Handler) AuthMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if authExempt(r.URL.Path) {
			next.ServeHTTP(w, r)
			return
		}
		user, sess := h.resolveSession(r)
		if user == nil {
			h.denyUnauth(w, r)
			return
		}
		// Half-authenticated: password OK, 2FA pending. Only the verify route
		// (allow-listed above) is reachable; everything else bounces there.
		if sess.State == models.SessionPending2FA {
			if wantsJSON(r) {
				http.Error(w, "two-factor required", http.StatusUnauthorized)
			} else {
				http.Redirect(w, r, "/login/2fa", http.StatusSeeOther)
			}
			return
		}
		onAccount := r.URL.Path == "/account" || strings.HasPrefix(r.URL.Path, "/account/")
		// Forced password change gates everything except the account page.
		if user.MustChangePassword && !onAccount {
			if wantsJSON(r) {
				http.Error(w, "password change required", http.StatusForbidden)
			} else {
				http.Redirect(w, r, "/account", http.StatusSeeOther)
			}
			return
		}
		// Admin required 2FA but the user hasn't enrolled yet → force enrollment.
		if user.TwoFactorRequired && !user.TwoFactorEnrolled && !onAccount {
			if wantsJSON(r) {
				http.Error(w, "two-factor enrollment required", http.StatusForbidden)
			} else {
				http.Redirect(w, r, "/account", http.StatusSeeOther)
			}
			return
		}
		// Path authorization.
		if !h.authorizePath(r, user) {
			http.Error(w, "forbidden", http.StatusForbidden)
			return
		}
		// Target-add permission + per-(user,workspace) domain-scope enforcement
		// for non-admins. Applies to the target-add routes and every module
		// launch, so a scoped user can neither add nor scan a target outside
		// their allowed domains — even by typing it directly into a form.
		if !user.IsAdmin() && r.Method == http.MethodPost {
			if isTargetAddPath(r.URL.Path) && !h.db.UserCanAddTargets(user.ID) {
				http.Error(w, "You do not have permission to add targets.", http.StatusForbidden)
				return
			}
			if isTargetScopePath(r.URL.Path) {
				if bad, denied := h.scopeViolation(r, user); denied {
					http.Error(w, "Target is outside your allowed domain scope: "+bad, http.StatusForbidden)
					return
				}
			}
		}
		// Audit scan launches at the single choke point (no body parse needed).
		if r.Method == http.MethodPost && isRunPath(r.URL.Path) {
			h.auditScanStart(r, user)
		}
		ctx := context.WithValue(r.Context(), userCtxKey, user)
		next.ServeHTTP(w, r.WithContext(ctx))
	})
}

// denyUnauth sends unauthenticated requests to the login page (HTML nav) or a
// 401 (background polls / non-GET), so polling JS can detect session expiry.
func (h *Handler) denyUnauth(w http.ResponseWriter, r *http.Request) {
	if wantsJSON(r) {
		http.Error(w, "unauthorized", http.StatusUnauthorized)
		return
	}
	next := url.QueryEscape(r.URL.RequestURI())
	http.Redirect(w, r, "/login?next="+next, http.StatusSeeOther)
}

// authorizePath enforces role + per-workspace-module grants. Admins bypass.
func (h *Handler) authorizePath(r *http.Request, user *models.User) bool {
	if user.IsAdmin() {
		return true
	}
	p := r.URL.Path
	// Admin-only areas + operator-level controls (calibration is a heavy,
	// operator-tier workload — not for regular users).
	if strings.HasPrefix(p, "/settings") || strings.HasPrefix(p, "/users") ||
		strings.HasPrefix(p, "/logs") || strings.HasPrefix(p, "/monitor/calibrate") ||
		strings.HasPrefix(p, "/update") {
		return false
	}
	// Scan-scoped operations (results/status/export reads + scan-control
	// mutations) are authorized against the SCAN's OWN workspace+module — never
	// the caller's active-workspace cookie. This is the single gate that stops
	// cross-workspace read/delete/restart (IDOR) and the restart-based bypass of
	// the per-module grant model.
	if id, mutating, ok := scanScopedID(r); ok {
		if mutating && r.Method != http.MethodPost {
			// No state change over GET/HEAD — otherwise the same-origin CSRF
			// guard (which only inspects POST/PUT/DELETE/PATCH) is bypassable.
			return false
		}
		if id == "" {
			return true // missing id → let the handler return 400/404
		}
		scan, err := h.db.GetScan(id)
		if err != nil {
			return true // unknown scan → handler 404s (no cross-workspace signal)
		}
		return h.canAccessScan(user, scan)
	}
	// Module launch form / new-scan run: grant in the effective workspace.
	if p == "/modules" || p == "/modules/" {
		return true
	}
	if name := moduleFromPath(p); name != "" {
		ws := h.effectiveWorkspace(r, user)
		return h.db.HasPermission(user.ID, ws.ID, name)
	}
	// Everything else (dashboard, scans list, targets, assets, workspace switch)
	// — any active user; data is scoped to accessible workspaces by
	// effectiveWorkspace / activeWorkspace.
	return true
}

// canAccessScan reports whether a user may read or act on a specific scan.
// Admins always may; otherwise the user must hold the grant for THAT scan's
// module in THAT scan's workspace — the exact grant that would let them run it.
func (h *Handler) canAccessScan(user *models.User, scan *models.Scan) bool {
	if user == nil {
		return false
	}
	if user.IsAdmin() {
		return true
	}
	if scan == nil {
		return false
	}
	return h.db.HasPermission(user.ID, scan.WorkspaceID, scan.Module)
}

// scanScopedID recognizes requests that read or mutate a single scan and returns
// (scanID, mutating, isScanScoped). Mutating paths must be POST.
func scanScopedID(r *http.Request) (string, bool, bool) {
	p := r.URL.Path
	// Read paths: per-module results/status fragments and scan exports.
	if strings.HasPrefix(p, "/modules/") {
		if i := strings.Index(p, "/results/"); i >= 0 {
			return p[i+len("/results/"):], false, true
		}
		if i := strings.Index(p, "/status/"); i >= 0 {
			return p[i+len("/status/"):], false, true
		}
	}
	if strings.HasPrefix(p, "/export/sections/") {
		return strings.TrimPrefix(p, "/export/sections/"), false, true
	}
	if strings.HasPrefix(p, "/export/") {
		return strings.TrimPrefix(p, "/export/"), false, true
	}
	// Mutating scan-control paths (id in the trailing path or the "id" form field).
	for _, pre := range []string{"/scans/stop/", "/scans/delete/", "/scans/archive/", "/scans/restart/", "/scans/resume/"} {
		if strings.HasPrefix(p, pre) {
			id := strings.TrimPrefix(p, pre)
			if id == "" {
				id = r.FormValue("id")
			}
			return id, true, true
		}
	}
	if p == "/scans/send-to-burp" {
		return r.FormValue("id"), true, true
	}
	return "", false, false
}

// auditScanStart records a scan-launch event.
func (h *Handler) auditScanStart(r *http.Request, user *models.User) {
	name := moduleFromPath(r.URL.Path)
	ws := h.effectiveWorkspace(r, user)
	wsName := ""
	if ws != nil {
		wsName = ws.Name
	}
	wsID := ""
	if ws != nil {
		wsID = ws.ID
	}
	h.db.AddAudit(models.AuditEntry{
		UserID:        user.ID,
		Username:      user.Username,
		Category:      models.AuditScan,
		Action:        "scan.start",
		Module:        name,
		WorkspaceID:   wsID,
		WorkspaceName: wsName,
		IP:            clientIP(r),
	})
}

// auditUserID / auditUsername are nil-safe accessors for building audit rows.
func auditUserID(u *models.User) string {
	if u == nil {
		return ""
	}
	return u.ID
}

func auditUsername(u *models.User) string {
	if u == nil {
		return ""
	}
	return u.Username
}

// audit is a small convenience for access/admin events.
func (h *Handler) audit(r *http.Request, user *models.User, category, action, detail string) {
	e := models.AuditEntry{
		Category: category,
		Action:   action,
		Detail:   detail,
		IP:       clientIP(r),
	}
	if user != nil {
		e.UserID = user.ID
		e.Username = user.Username
	}
	h.db.AddAudit(e)
}
