package database

import (
	"database/sql"
	"fmt"
	"time"

	"github.com/google/uuid"

	"scanner/internal/models"
)

// This file holds all persistence for the identity layer: users, sessions,
// permission grants, and the append-only audit log. Crypto lives in
// internal/auth — this layer only stores already-hashed values.

// ---------------------------------------------------------------------------
// Users
// ---------------------------------------------------------------------------

// AnyUsersExist reports whether the users table has at least one row (used at
// startup to decide whether to bootstrap the initial admin).
func (d *DB) AnyUsersExist() bool {
	var n int
	d.Get(&n, `SELECT COUNT(*) FROM users`)
	return n > 0
}

// CreateUser inserts a new user. PasswordHash must already be hashed by the
// caller (internal/auth). Returns the assigned ID.
func (d *DB) CreateUser(u *models.User) (string, error) {
	if u.ID == "" {
		u.ID = uuid.New().String()
	}
	now := time.Now()
	u.CreatedAt, u.UpdatedAt = now, now
	if u.Role == "" {
		u.Role = models.RoleUser
	}
	_, err := d.Exec(`INSERT INTO users
		(id, username, email, password_hash, role, is_active, must_change_password,
		 twofa_required, twofa_method, twofa_secret, twofa_enrolled,
		 failed_login_count, failed_2fa_count, created_at, updated_at)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 0, 0, ?, ?)`,
		u.ID, u.Username, u.Email, u.PasswordHash, u.Role, b2i(u.IsActive),
		b2i(u.MustChangePassword), b2i(u.TwoFactorRequired), u.TwoFactorMethod,
		u.TwoFactorSecret, b2i(u.TwoFactorEnrolled), u.CreatedAt, u.UpdatedAt)
	if err != nil {
		return "", fmt.Errorf("create user: %w", err)
	}
	return u.ID, nil
}

// GetUserByUsername returns the user with the given username (case-sensitive) or
// an error if not found.
func (d *DB) GetUserByUsername(username string) (*models.User, error) {
	var u models.User
	if err := d.Get(&u, `SELECT * FROM users WHERE username = ?`, username); err != nil {
		return nil, err
	}
	return &u, nil
}

// GetUserByID returns the user with the given id.
func (d *DB) GetUserByID(id string) (*models.User, error) {
	var u models.User
	if err := d.Get(&u, `SELECT * FROM users WHERE id = ?`, id); err != nil {
		return nil, err
	}
	return &u, nil
}

// ListUsers returns all users ordered by username.
func (d *DB) ListUsers() ([]models.User, error) {
	var us []models.User
	if err := d.Select(&us, `SELECT * FROM users ORDER BY username`); err != nil {
		return nil, err
	}
	return us, nil
}

// CountAdmins returns how many active admin accounts exist (used to refuse
// removing/demoting the last admin).
func (d *DB) CountAdmins() int {
	var n int
	d.Get(&n, `SELECT COUNT(*) FROM users WHERE role = 'admin' AND is_active = 1`)
	return n
}

// UpdateUserProfile updates admin-editable, non-credential fields.
func (d *DB) UpdateUserProfile(id, email, role string, isActive, twofaRequired bool) error {
	_, err := d.Exec(`UPDATE users SET email = ?, role = ?, is_active = ?, twofa_required = ?, updated_at = ?
		WHERE id = ?`, email, role, b2i(isActive), b2i(twofaRequired), time.Now(), id)
	if err != nil {
		return fmt.Errorf("update user profile: %w", err)
	}
	return nil
}

// SetUserPassword sets a new bcrypt hash and the must-change flag, and clears
// any password lockout.
func (d *DB) SetUserPassword(id, passwordHash string, mustChange bool) error {
	_, err := d.Exec(`UPDATE users SET password_hash = ?, must_change_password = ?,
		failed_login_count = 0, login_locked_until = NULL, updated_at = ? WHERE id = ?`,
		passwordHash, b2i(mustChange), time.Now(), id)
	if err != nil {
		return fmt.Errorf("set user password: %w", err)
	}
	return nil
}

// SetUserTwoFactor records a user's 2FA enrollment (method + secret + enrolled).
func (d *DB) SetUserTwoFactor(id, method, secret string, enrolled bool) error {
	_, err := d.Exec(`UPDATE users SET twofa_method = ?, twofa_secret = ?, twofa_enrolled = ?, updated_at = ?
		WHERE id = ?`, method, secret, b2i(enrolled), time.Now(), id)
	if err != nil {
		return fmt.Errorf("set user 2fa: %w", err)
	}
	return nil
}

// SetTwoFactorLastStep records the last accepted TOTP step for a user, so a
// replayed code (same or earlier step) is rejected on the next login.
func (d *DB) SetTwoFactorLastStep(id string, step int64) {
	d.Exec(`UPDATE users SET twofa_last_step = ? WHERE id = ?`, step, id)
}

// --- Target-add permission + per-workspace domain scope ---------------------

// UserCanAddTargets reports whether a user may add new targets at all.
func (d *DB) UserCanAddTargets(id string) bool {
	var v int
	if err := d.Get(&v, `SELECT can_add_targets FROM users WHERE id = ?`, id); err != nil {
		return false
	}
	return v == 1
}

// SetCanAddTargets sets the target-add permission for a user.
func (d *DB) SetCanAddTargets(id string, allowed bool) error {
	_, err := d.Exec(`UPDATE users SET can_add_targets = ?, updated_at = ? WHERE id = ?`, b2i(allowed), time.Now(), id)
	if err != nil {
		return fmt.Errorf("set can_add_targets: %w", err)
	}
	return nil
}

// UserWorkspaceDomains returns the allowed-domain patterns for a user in a
// workspace. An empty slice means unrestricted (opt-in scoping).
func (d *DB) UserWorkspaceDomains(userID, workspaceID string) []string {
	var pats []string
	d.Select(&pats, `SELECT pattern FROM user_domain_scopes WHERE user_id = ? AND workspace_id = ? ORDER BY pattern`,
		userID, workspaceID)
	return pats
}

// SetUserWorkspaceDomains replaces (atomically) the allowed-domain patterns for
// a user in one workspace.
func (d *DB) SetUserWorkspaceDomains(userID, workspaceID string, patterns []string) error {
	tx, err := d.Beginx()
	if err != nil {
		return fmt.Errorf("begin domscope tx: %w", err)
	}
	committed := false
	defer func() {
		if !committed {
			tx.Rollback()
		}
	}()
	if _, err := tx.Exec(`DELETE FROM user_domain_scopes WHERE user_id = ? AND workspace_id = ?`, userID, workspaceID); err != nil {
		return fmt.Errorf("clear domscope: %w", err)
	}
	seen := map[string]bool{}
	for _, p := range patterns {
		if p == "" || seen[p] {
			continue
		}
		seen[p] = true
		if _, err := tx.Exec(`INSERT OR IGNORE INTO user_domain_scopes (id, user_id, workspace_id, pattern) VALUES (?, ?, ?, ?)`,
			uuid.New().String(), userID, workspaceID, p); err != nil {
			return fmt.Errorf("insert domscope: %w", err)
		}
	}
	if err := tx.Commit(); err != nil {
		return fmt.Errorf("commit domscope: %w", err)
	}
	committed = true
	return nil
}

// ResetUserTwoFactor clears a user's 2FA enrollment (admin action).
func (d *DB) ResetUserTwoFactor(id string) error {
	_, err := d.Exec(`UPDATE users SET twofa_method = '', twofa_secret = '', twofa_enrolled = 0,
		failed_2fa_count = 0, twofa_locked_until = NULL, updated_at = ? WHERE id = ?`, time.Now(), id)
	if err != nil {
		return fmt.Errorf("reset user 2fa: %w", err)
	}
	return nil
}

// DeleteUser removes a user (their sessions + permissions cascade).
func (d *DB) DeleteUser(id string) error {
	_, err := d.Exec(`DELETE FROM users WHERE id = ?`, id)
	if err != nil {
		return fmt.Errorf("delete user: %w", err)
	}
	return nil
}

// --- Lockout counters -------------------------------------------------------

// RegisterFailedLogin increments the password-failure counter and, on reaching
// the threshold, sets a lockout window. Returns whether the account is now locked.
func (d *DB) RegisterFailedLogin(id string, threshold int, lockFor time.Duration) bool {
	var count int
	d.Get(&count, `SELECT failed_login_count FROM users WHERE id = ?`, id)
	count++
	if count >= threshold {
		until := time.Now().Add(lockFor)
		d.Exec(`UPDATE users SET failed_login_count = 0, login_locked_until = ? WHERE id = ?`, until, id)
		return true
	}
	d.Exec(`UPDATE users SET failed_login_count = ? WHERE id = ?`, count, id)
	return false
}

// ClearLoginFailures resets the password-failure state on a successful login.
func (d *DB) ClearLoginFailures(id string) {
	d.Exec(`UPDATE users SET failed_login_count = 0, login_locked_until = NULL, last_login_at = ? WHERE id = ?`,
		time.Now(), id)
}

// RegisterFailed2FA increments the 2FA-failure counter and locks on threshold.
func (d *DB) RegisterFailed2FA(id string, threshold int, lockFor time.Duration) bool {
	var count int
	d.Get(&count, `SELECT failed_2fa_count FROM users WHERE id = ?`, id)
	count++
	if count >= threshold {
		until := time.Now().Add(lockFor)
		d.Exec(`UPDATE users SET failed_2fa_count = 0, twofa_locked_until = ? WHERE id = ?`, until, id)
		return true
	}
	d.Exec(`UPDATE users SET failed_2fa_count = ? WHERE id = ?`, count, id)
	return false
}

// Clear2FAFailures resets the 2FA-failure state after a good code.
func (d *DB) Clear2FAFailures(id string) {
	d.Exec(`UPDATE users SET failed_2fa_count = 0, twofa_locked_until = NULL WHERE id = ?`, id)
}

// ---------------------------------------------------------------------------
// Sessions
// ---------------------------------------------------------------------------

// CreateSession inserts a session row keyed by the token hash (caller passes the
// already-hashed id).
func (d *DB) CreateSession(s *models.Session) error {
	if s.CreatedAt.IsZero() {
		s.CreatedAt = time.Now()
	}
	s.LastSeenAt = s.CreatedAt
	_, err := d.Exec(`INSERT INTO sessions
		(id, user_id, state, otp_hash, otp_expires, created_at, expires_at, last_seen_at, ip, user_agent)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		s.ID, s.UserID, s.State, s.OTPHash, s.OTPExpires, s.CreatedAt, s.ExpiresAt,
		s.LastSeenAt, s.IP, s.UserAgent)
	if err != nil {
		return fmt.Errorf("create session: %w", err)
	}
	return nil
}

// GetSession returns the session for a token hash, or an error if absent.
func (d *DB) GetSession(idHash string) (*models.Session, error) {
	var s models.Session
	if err := d.Get(&s, `SELECT * FROM sessions WHERE id = ?`, idHash); err != nil {
		return nil, err
	}
	return &s, nil
}

// TouchSession bumps last_seen_at (sliding activity).
func (d *DB) TouchSession(idHash string) {
	d.Exec(`UPDATE sessions SET last_seen_at = ? WHERE id = ?`, time.Now(), idHash)
}

// PromoteSession flips a pending_2fa session to active, extends its expiry, and
// clears the OTP challenge. Used after a good 2FA code (the caller also rotates
// the cookie token via ReplaceSessionID when it wants fixation protection).
func (d *DB) PromoteSession(idHash string, expiresAt time.Time) error {
	_, err := d.Exec(`UPDATE sessions SET state = 'active', otp_hash = '', otp_expires = NULL, expires_at = ?
		WHERE id = ?`, expiresAt, idHash)
	if err != nil {
		return fmt.Errorf("promote session: %w", err)
	}
	return nil
}

// ReplaceSessionID changes a session's primary key (token rotation on privilege
// change to prevent session fixation).
func (d *DB) ReplaceSessionID(oldHash, newHash string) error {
	_, err := d.Exec(`UPDATE sessions SET id = ? WHERE id = ?`, newHash, oldHash)
	if err != nil {
		return fmt.Errorf("rotate session: %w", err)
	}
	return nil
}

// SetSessionOTP stores a hashed email-OTP challenge + expiry on a session.
func (d *DB) SetSessionOTP(idHash, otpHash string, expires time.Time) error {
	_, err := d.Exec(`UPDATE sessions SET otp_hash = ?, otp_expires = ? WHERE id = ?`, otpHash, expires, idHash)
	if err != nil {
		return fmt.Errorf("set session otp: %w", err)
	}
	return nil
}

// DeleteSession removes a single session (logout).
func (d *DB) DeleteSession(idHash string) {
	d.Exec(`DELETE FROM sessions WHERE id = ?`, idHash)
}

// DeleteUserSessions removes all sessions for a user (password reset / disable).
func (d *DB) DeleteUserSessions(userID string) {
	d.Exec(`DELETE FROM sessions WHERE user_id = ?`, userID)
}

// CleanupExpiredSessions removes sessions past their expiry.
func (d *DB) CleanupExpiredSessions() {
	d.Exec(`DELETE FROM sessions WHERE expires_at < ?`, time.Now())
}

// ---------------------------------------------------------------------------
// Permissions (grants)
// ---------------------------------------------------------------------------

// HasPermission reports whether the user may run module in workspace.
func (d *DB) HasPermission(userID, workspaceID, module string) bool {
	var n int
	d.Get(&n, `SELECT COUNT(*) FROM permissions WHERE user_id = ? AND workspace_id = ? AND module = ?`,
		userID, workspaceID, module)
	return n > 0
}

// UserModulesInWorkspace returns the set of modules a user may run in a workspace.
func (d *DB) UserModulesInWorkspace(userID, workspaceID string) (map[string]bool, error) {
	var mods []string
	if err := d.Select(&mods, `SELECT module FROM permissions WHERE user_id = ? AND workspace_id = ?`,
		userID, workspaceID); err != nil {
		return nil, err
	}
	set := make(map[string]bool, len(mods))
	for _, m := range mods {
		set[m] = true
	}
	return set, nil
}

// UserWorkspaceIDs returns the distinct workspaces a user has any grant in.
func (d *DB) UserWorkspaceIDs(userID string) (map[string]bool, error) {
	var ids []string
	if err := d.Select(&ids, `SELECT DISTINCT workspace_id FROM permissions WHERE user_id = ?`, userID); err != nil {
		return nil, err
	}
	set := make(map[string]bool, len(ids))
	for _, id := range ids {
		set[id] = true
	}
	return set, nil
}

// ListUserPermissions returns all grant rows for a user (for the admin matrix).
func (d *DB) ListUserPermissions(userID string) ([]models.Permission, error) {
	var ps []models.Permission
	if err := d.Select(&ps, `SELECT * FROM permissions WHERE user_id = ?`, userID); err != nil {
		return nil, err
	}
	return ps, nil
}

// SetUserWorkspacePermissions replaces (atomically) the set of module grants for
// a user in one workspace with the supplied list.
func (d *DB) SetUserWorkspacePermissions(userID, workspaceID string, modules []string) error {
	tx, err := d.Beginx()
	if err != nil {
		return fmt.Errorf("begin perms tx: %w", err)
	}
	committed := false
	defer func() {
		if !committed {
			tx.Rollback()
		}
	}()
	if _, err := tx.Exec(`DELETE FROM permissions WHERE user_id = ? AND workspace_id = ?`, userID, workspaceID); err != nil {
		return fmt.Errorf("clear perms: %w", err)
	}
	for _, m := range modules {
		if m == "" {
			continue
		}
		if _, err := tx.Exec(`INSERT OR IGNORE INTO permissions (id, user_id, workspace_id, module) VALUES (?, ?, ?, ?)`,
			uuid.New().String(), userID, workspaceID, m); err != nil {
			return fmt.Errorf("insert perm: %w", err)
		}
	}
	if err := tx.Commit(); err != nil {
		return fmt.Errorf("commit perms: %w", err)
	}
	committed = true
	return nil
}

// ---------------------------------------------------------------------------
// Audit log (append-only)
// ---------------------------------------------------------------------------

// AddAudit appends an audit entry. This is the ONLY write path; there is no
// update or delete method, by design.
func (d *DB) AddAudit(e models.AuditEntry) {
	if e.ID == "" {
		e.ID = uuid.New().String()
	}
	if e.TS.IsZero() {
		e.TS = time.Now()
	}
	d.Exec(`INSERT INTO audit_log
		(id, ts, user_id, username, category, action, workspace_id, workspace_name, module, target, scan_id, ip, detail)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		e.ID, e.TS, e.UserID, e.Username, e.Category, e.Action, e.WorkspaceID,
		e.WorkspaceName, e.Module, e.Target, e.ScanID, e.IP, e.Detail)
}

// AuditFilter narrows a ListAudit query. Zero-value fields are ignored.
type AuditFilter struct {
	Category string
	Username string
	Action   string
	Since    *time.Time
	Limit    int
}

// ListAudit returns audit rows (newest first) matching the filter.
func (d *DB) ListAudit(f AuditFilter) ([]models.AuditEntry, error) {
	q := `SELECT * FROM audit_log WHERE 1=1`
	var args []interface{}
	if f.Category != "" {
		q += ` AND category = ?`
		args = append(args, f.Category)
	}
	if f.Username != "" {
		q += ` AND username = ?`
		args = append(args, f.Username)
	}
	if f.Action != "" {
		q += ` AND action = ?`
		args = append(args, f.Action)
	}
	if f.Since != nil {
		q += ` AND ts >= ?`
		args = append(args, *f.Since)
	}
	q += ` ORDER BY ts DESC`
	if f.Limit <= 0 || f.Limit > 5000 {
		f.Limit = 1000
	}
	q += ` LIMIT ?`
	args = append(args, f.Limit)

	var es []models.AuditEntry
	if err := d.Select(&es, q, args...); err != nil && err != sql.ErrNoRows {
		return nil, err
	}
	return es, nil
}

// b2i converts a bool to the 0/1 integer SQLite stores.
func b2i(b bool) int {
	if b {
		return 1
	}
	return 0
}
