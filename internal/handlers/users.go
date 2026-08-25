package handlers

import (
	"net/http"
	"sort"
	"strings"

	"scanner/internal/auth"
	"scanner/internal/models"
)

// Admin-only user management: list/create/edit/delete users, reset credentials,
// and edit the per-workspace-module permission matrix. The auth middleware
// already restricts every /users* route to admins.

// UsersPage lists all users.
func (h *Handler) UsersPage(w http.ResponseWriter, r *http.Request) {
	h.renderUsers(w, r, "", "", "")
}

// renderUsers renders the users list, optionally surfacing a one-time temp
// password (shown after create / reset without ever putting it in a URL).
func (h *Handler) renderUsers(w http.ResponseWriter, r *http.Request, tempUser, tempPass, notice string) {
	users, _ := h.db.ListUsers()
	data := h.baseData(r, "Users - scaNNer", "users")
	data["Users"] = users
	if tempPass != "" {
		data["TempUser"] = tempUser
		data["TempPassword"] = tempPass
	}
	if notice != "" {
		data["Notice"] = notice
	}
	if e := r.URL.Query().Get("error"); e != "" {
		data["FormError"] = e
	}
	h.render(w, "layout", data)
}

// UserCreate creates a user with a generated temporary password.
func (h *Handler) UserCreate(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Redirect(w, r, "/users", http.StatusSeeOther)
		return
	}
	username := strings.TrimSpace(r.FormValue("username"))
	email := strings.TrimSpace(r.FormValue("email"))
	role := r.FormValue("role")
	if role != models.RoleAdmin {
		role = models.RoleUser
	}
	if username == "" {
		http.Redirect(w, r, "/users?error="+"Username is required.", http.StatusSeeOther)
		return
	}
	if _, err := h.db.GetUserByUsername(username); err == nil {
		http.Redirect(w, r, "/users?error="+"That username already exists.", http.StatusSeeOther)
		return
	}
	temp, err := auth.GeneratePassword(16)
	if err != nil {
		http.Redirect(w, r, "/users?error=gen", http.StatusSeeOther)
		return
	}
	hash, err := auth.HashPassword(temp)
	if err != nil {
		http.Redirect(w, r, "/users?error=hash", http.StatusSeeOther)
		return
	}
	u := &models.User{
		Username:           username,
		Email:              email,
		PasswordHash:       hash,
		Role:               role,
		IsActive:           true,
		MustChangePassword: true,
	}
	if _, err := h.db.CreateUser(u); err != nil {
		http.Redirect(w, r, "/users?error="+"Could not create user.", http.StatusSeeOther)
		return
	}
	h.audit(r, h.currentUser(r), models.AuditAdmin, "user.create", username+" ("+role+")")
	h.renderUsers(w, r, username, temp, "User created. Give them this one-time password — it won't be shown again.")
}

// UserEdit updates profile fields (email, role, active, require-2FA).
func (h *Handler) UserEdit(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Redirect(w, r, "/users", http.StatusSeeOther)
		return
	}
	id := r.FormValue("id")
	target, err := h.db.GetUserByID(id)
	if err != nil {
		http.Redirect(w, r, "/users?error="+"No such user.", http.StatusSeeOther)
		return
	}
	email := strings.TrimSpace(r.FormValue("email"))
	role := r.FormValue("role")
	if role != models.RoleAdmin {
		role = models.RoleUser
	}
	isActive := r.FormValue("is_active") == "on"
	twofaRequired := r.FormValue("twofa_required") == "on"

	// Never let the last active admin be demoted or disabled.
	if target.IsAdmin() && (role != models.RoleAdmin || !isActive) && h.db.CountAdmins() <= 1 {
		http.Redirect(w, r, "/users?error="+"Cannot demote or disable the last admin.", http.StatusSeeOther)
		return
	}
	if err := h.db.UpdateUserProfile(id, email, role, isActive, twofaRequired); err != nil {
		http.Redirect(w, r, "/users?error="+"Could not update user.", http.StatusSeeOther)
		return
	}
	if !isActive {
		h.db.DeleteUserSessions(id) // kick disabled users immediately
	}
	h.audit(r, h.currentUser(r), models.AuditAdmin, "user.edit", target.Username)
	http.Redirect(w, r, "/users", http.StatusSeeOther)
}

// UserResetPassword issues a new temporary password.
func (h *Handler) UserResetPassword(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Redirect(w, r, "/users", http.StatusSeeOther)
		return
	}
	id := r.FormValue("id")
	target, err := h.db.GetUserByID(id)
	if err != nil {
		http.Redirect(w, r, "/users?error="+"No such user.", http.StatusSeeOther)
		return
	}
	temp, err := auth.GeneratePassword(16)
	if err != nil {
		http.Redirect(w, r, "/users?error=gen", http.StatusSeeOther)
		return
	}
	hash, _ := auth.HashPassword(temp)
	h.db.SetUserPassword(id, hash, true)
	h.db.DeleteUserSessions(id)
	h.audit(r, h.currentUser(r), models.AuditAdmin, "user.reset_password", target.Username)
	h.renderUsers(w, r, target.Username, temp, "New one-time password for "+target.Username+" — shown once.")
}

// UserResetTwoFactor clears a user's 2FA enrollment.
func (h *Handler) UserResetTwoFactor(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Redirect(w, r, "/users", http.StatusSeeOther)
		return
	}
	id := r.FormValue("id")
	target, err := h.db.GetUserByID(id)
	if err != nil {
		http.Redirect(w, r, "/users?error="+"No such user.", http.StatusSeeOther)
		return
	}
	h.db.ResetUserTwoFactor(id)
	h.audit(r, h.currentUser(r), models.AuditAdmin, "user.reset_2fa", target.Username)
	http.Redirect(w, r, "/users", http.StatusSeeOther)
}

// UserDelete removes a user.
func (h *Handler) UserDelete(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Redirect(w, r, "/users", http.StatusSeeOther)
		return
	}
	id := r.FormValue("id")
	target, err := h.db.GetUserByID(id)
	if err != nil {
		http.Redirect(w, r, "/users?error="+"No such user.", http.StatusSeeOther)
		return
	}
	if me := h.currentUser(r); me != nil && me.ID == id {
		http.Redirect(w, r, "/users?error="+"You cannot delete your own account.", http.StatusSeeOther)
		return
	}
	if target.IsAdmin() && h.db.CountAdmins() <= 1 {
		http.Redirect(w, r, "/users?error="+"Cannot delete the last admin.", http.StatusSeeOther)
		return
	}
	h.db.DeleteUser(id)
	h.audit(r, h.currentUser(r), models.AuditAdmin, "user.delete", target.Username)
	http.Redirect(w, r, "/users", http.StatusSeeOther)
}

// UserPermissions shows/saves the per-workspace-module grant matrix for a user.
func (h *Handler) UserPermissions(w http.ResponseWriter, r *http.Request) {
	id := r.URL.Query().Get("id")
	if r.Method == http.MethodPost {
		id = r.FormValue("id")
	}
	target, err := h.db.GetUserByID(id)
	if err != nil {
		http.Redirect(w, r, "/users?error="+"No such user.", http.StatusSeeOther)
		return
	}
	workspaces, _ := h.db.ListWorkspaces()

	if r.Method == http.MethodPost {
		r.ParseForm()
		// checkbox values are "<workspaceID>::<module>"
		byWs := map[string][]string{}
		for _, v := range r.Form["perm"] {
			parts := strings.SplitN(v, "::", 2)
			if len(parts) == 2 {
				byWs[parts[0]] = append(byWs[parts[0]], parts[1])
			}
		}
		for _, ws := range workspaces {
			h.db.SetUserWorkspacePermissions(target.ID, ws.ID, byWs[ws.ID])
			// Per-workspace allowed-domain scope (textarea name="domains_<wsID>";
			// one domain or IP/CIDR per line; empty = unrestricted).
			h.db.SetUserWorkspaceDomains(target.ID, ws.ID, splitTargets(r.FormValue("domains_"+ws.ID)))
		}
		// Global "may add targets" toggle.
		h.db.SetCanAddTargets(target.ID, r.FormValue("can_add_targets") == "on")
		h.audit(r, h.currentUser(r), models.AuditAdmin, "user.permissions", target.Username)
		http.Redirect(w, r, "/users/permissions?id="+target.ID+"&success=1", http.StatusSeeOther)
		return
	}

	// Build the current grant set for quick lookup in the template.
	perms, _ := h.db.ListUserPermissions(target.ID)
	granted := map[string]bool{} // key "wsID::module"
	for _, p := range perms {
		granted[p.WorkspaceID+"::"+p.Module] = true
	}
	mods := h.registry.List()
	sort.Slice(mods, func(i, j int) bool { return mods[i].DisplayName < mods[j].DisplayName })

	// Current per-workspace domain scope, as newline-joined text for the editor.
	domScope := map[string]string{}
	for _, ws := range workspaces {
		domScope[ws.ID] = strings.Join(h.db.UserWorkspaceDomains(target.ID, ws.ID), "\n")
	}

	data := h.baseData(r, "Permissions - scaNNer", "user_detail")
	data["Target"] = target
	data["AllModules"] = mods
	data["Granted"] = granted
	data["CanAddTargets"] = target.CanAddTargets
	data["DomainScope"] = domScope
	data["Saved"] = r.URL.Query().Get("success") == "1"
	h.render(w, "layout", data)
}
