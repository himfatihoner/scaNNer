package models

import "time"

// Role constants for User.Role.
const (
	RoleAdmin = "admin"
	RoleUser  = "user"
)

// 2FA method constants for User.TwoFactorMethod.
const (
	TwoFactorNone  = ""
	TwoFactorTOTP  = "totp"
	TwoFactorEmail = "email"
)

// Session state constants.
const (
	SessionPending2FA = "pending_2fa" // password OK, awaiting a 2FA code
	SessionActive     = "active"      // fully authenticated
)

// User is an application operator. Passwords are bcrypt hashes; the TOTP secret
// is base32. Lockout counters/timestamps back the brute-force protection.
type User struct {
	ID                 string     `db:"id"                   json:"id"`
	Username           string     `db:"username"             json:"username"`
	Email              string     `db:"email"                json:"email"`
	PasswordHash       string     `db:"password_hash"        json:"-"`
	Role               string     `db:"role"                 json:"role"`
	IsActive           bool       `db:"is_active"            json:"is_active"`
	MustChangePassword bool       `db:"must_change_password" json:"must_change_password"`
	TwoFactorRequired  bool       `db:"twofa_required"       json:"twofa_required"`  // admin-set: must use 2FA
	TwoFactorMethod    string     `db:"twofa_method"         json:"twofa_method"`    // '' | 'totp' | 'email'
	TwoFactorSecret    string     `db:"twofa_secret"         json:"-"`               // base32 TOTP secret
	TwoFactorEnrolled  bool       `db:"twofa_enrolled"       json:"twofa_enrolled"`  // finished setup
	TwoFactorLastStep  int64      `db:"twofa_last_step"      json:"-"`               // last accepted TOTP step (replay guard)
	CanAddTargets      bool       `db:"can_add_targets"      json:"can_add_targets"`  // may this user add new targets at all
	FailedLoginCount   int        `db:"failed_login_count"   json:"-"`
	LoginLockedUntil   *time.Time `db:"login_locked_until"   json:"-"`
	Failed2FACount     int        `db:"failed_2fa_count"     json:"-"`
	TwoFactorLockUntil *time.Time `db:"twofa_locked_until"   json:"-"`
	LastLoginAt        *time.Time `db:"last_login_at"        json:"last_login_at"`
	CreatedAt          time.Time  `db:"created_at"           json:"created_at"`
	UpdatedAt          time.Time  `db:"updated_at"           json:"updated_at"`
}

// IsAdmin reports whether the user has the admin role.
func (u *User) IsAdmin() bool { return u != nil && u.Role == RoleAdmin }

// LoginLocked reports whether the account is currently in a password lockout.
func (u *User) LoginLocked(now time.Time) bool {
	return u.LoginLockedUntil != nil && u.LoginLockedUntil.After(now)
}

// TwoFactorLocked reports whether the account is currently in a 2FA lockout.
func (u *User) TwoFactorLocked(now time.Time) bool {
	return u.TwoFactorLockUntil != nil && u.TwoFactorLockUntil.After(now)
}

// Session is a server-side login session. The DB stores only sha256(token) as
// ID; the raw token lives in the user's cookie. Pending sessions may only reach
// the 2FA verify route.
type Session struct {
	ID         string     `db:"id"           json:"-"` // sha256(raw token)
	UserID     string     `db:"user_id"      json:"user_id"`
	State      string     `db:"state"        json:"state"`
	OTPHash    string     `db:"otp_hash"     json:"-"` // hashed email-OTP challenge
	OTPExpires *time.Time `db:"otp_expires"  json:"-"`
	CreatedAt  time.Time  `db:"created_at"   json:"created_at"`
	ExpiresAt  time.Time  `db:"expires_at"   json:"expires_at"`
	LastSeenAt time.Time  `db:"last_seen_at" json:"last_seen_at"`
	IP         string     `db:"ip"           json:"ip"`
	UserAgent  string     `db:"user_agent"   json:"user_agent"`
}

// Permission is a single grant: user may run `module` in `workspace`.
type Permission struct {
	ID          string `db:"id"           json:"id"`
	UserID      string `db:"user_id"      json:"user_id"`
	WorkspaceID string `db:"workspace_id" json:"workspace_id"`
	Module      string `db:"module"       json:"module"`
}

// Audit log categories.
const (
	AuditAccess = "access"
	AuditScan   = "scan"
	AuditAdmin  = "admin"
)

// AuditEntry is one append-only audit record. It carries denormalized snapshots
// (username, workspace name, target) so it stays meaningful after the referenced
// scan/user/workspace is deleted — the table has no foreign keys by design.
type AuditEntry struct {
	ID            string    `db:"id"             json:"id"`
	TS            time.Time `db:"ts"             json:"ts"`
	UserID        string    `db:"user_id"        json:"user_id"`
	Username      string    `db:"username"       json:"username"`
	Category      string    `db:"category"       json:"category"`
	Action        string    `db:"action"         json:"action"`
	WorkspaceID   string    `db:"workspace_id"   json:"workspace_id"`
	WorkspaceName string    `db:"workspace_name" json:"workspace_name"`
	Module        string    `db:"module"         json:"module"`
	Target        string    `db:"target"         json:"target"`
	ScanID        string    `db:"scan_id"        json:"scan_id"`
	IP            string    `db:"ip"             json:"ip"`
	Detail        string    `db:"detail"         json:"detail"`
}
