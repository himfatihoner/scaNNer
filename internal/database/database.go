package database

import (
	"database/sql"
	"fmt"
	"log"
	"strconv"
	"strings"
	"sync"
	"time"

	"scanner/internal/models"
	"scanner/internal/scanstats"

	"github.com/google/uuid"
	"github.com/jmoiron/sqlx"
	_ "modernc.org/sqlite"
)

// DB wraps sqlx.DB with application-specific methods
type DB struct {
	*sqlx.DB
}

// New opens and initializes the database.
//
// PRAGMAs:
//   - journal_mode=wal — durable + concurrent reads while writing
//   - foreign_keys=1   — enforce FKs (we rely on this for cascade-like deletes)
//   - busy_timeout=5000 — SQLITE_BUSY retries for up to 5s instead of failing
//                        immediately. Without this, concurrent progress
//                        updates from N parallel scan workers produced
//                        intermittent 'database is locked' errors that
//                        showed up as missing rows / stuck progress bars
//                        after ~hours of running. (Audit B4.)
//
// Connection-pool tuning (audit B3): modernc.org/sqlite serializes writes
// internally, but the sql.DB pool defaults to unlimited connections — under
// long-running load this combines with /tmp ulimit and surface as
// 'too many open files'. Cap to a reasonable bound and recycle.
func New(path string) (*DB, error) {
	db, err := sqlx.Open("sqlite", path+"?_pragma=journal_mode(wal)&_pragma=foreign_keys(1)&_pragma=busy_timeout(5000)")
	if err != nil {
		return nil, fmt.Errorf("open db: %w", err)
	}
	// Bounded pool so a runaway worker can't exhaust FDs.
	// 25 open is more than enough for sqlite (it's effectively
	// serialized internally), and 5 idle keeps the hot path cheap.
	db.SetMaxOpenConns(25)
	db.SetMaxIdleConns(5)
	db.SetConnMaxLifetime(5 * time.Minute)
	d := &DB{db}
	if err := d.migrate(); err != nil {
		return nil, fmt.Errorf("migrate: %w", err)
	}

	// Audit B12: WAL checkpoint hygiene. SQLite's WAL grows unbounded
	// until something explicitly checkpoints it. Without this background
	// loop the .db-wal file climbed to gigabytes over multi-day runs,
	// slowed startup, and never shrunk. We run a PASSIVE checkpoint
	// every 5 minutes (non-blocking — only commits pages the readers
	// don't need); the destructive TRUNCATE happens on Close().
	go d.walCheckpointLoop()

	return d, nil
}

// walCheckpointLoop runs a passive WAL checkpoint every 5 minutes.
// PASSIVE means: don't block writers, don't truncate the file, just
// promote what's safe to promote. Combined with the TRUNCATE on Close()
// this keeps the WAL file from growing without throttling live scans.
func (d *DB) walCheckpointLoop() {
	t := time.NewTicker(5 * time.Minute)
	defer t.Stop()
	for range t.C {
		// Errors here are non-fatal — the next tick will retry.
		_, _ = d.Exec("PRAGMA wal_checkpoint(PASSIVE)")
	}
}

// Close flushes the WAL and closes the underlying connection. Call this
// from the shutdown path so the next restart doesn't have to replay
// a multi-GB WAL log (audit B12).
func (d *DB) Close() error {
	if d == nil || d.DB == nil {
		return nil
	}
	// TRUNCATE is the strongest checkpoint mode: blocks until all
	// writers finish, integrates everything into the main DB, then
	// truncates the WAL to zero. Safe to call on shutdown.
	_, _ = d.Exec("PRAGMA wal_checkpoint(TRUNCATE)")
	return d.DB.Close()
}

const DefaultWorkspaceID = "default"

func (d *DB) migrate() error {
	schema := `
	CREATE TABLE IF NOT EXISTS workspaces (
		id          TEXT PRIMARY KEY,
		name        TEXT NOT NULL,
		description TEXT NOT NULL DEFAULT '',
		is_default  INTEGER NOT NULL DEFAULT 0,
		created_at  DATETIME NOT NULL,
		updated_at  DATETIME NOT NULL
	);

	CREATE TABLE IF NOT EXISTS targets (
		id           TEXT PRIMARY KEY,
		workspace_id TEXT NOT NULL,
		value        TEXT NOT NULL,
		type         TEXT NOT NULL CHECK(type IN ('ipv4', 'domain', 'fqdn', 'url')),
		note         TEXT NOT NULL DEFAULT '',
		created_at   DATETIME NOT NULL,
		FOREIGN KEY (workspace_id) REFERENCES workspaces(id) ON DELETE CASCADE,
		UNIQUE(workspace_id, value)
	);

	CREATE INDEX IF NOT EXISTS idx_targets_workspace ON targets(workspace_id);
	CREATE INDEX IF NOT EXISTS idx_targets_type ON targets(workspace_id, type);

	CREATE TABLE IF NOT EXISTS scans (
		id             TEXT PRIMARY KEY,
		workspace_id   TEXT NOT NULL,
		module         TEXT NOT NULL,
		status         TEXT NOT NULL DEFAULT 'pending',
		config         TEXT NOT NULL DEFAULT '{}',
		result         TEXT NOT NULL DEFAULT '{}',
		progress_done  INTEGER NOT NULL DEFAULT 0,
		progress_total INTEGER NOT NULL DEFAULT 0,
		progress_msg   TEXT NOT NULL DEFAULT '',
		started_at     DATETIME,
		finished_at    DATETIME,
		created_at     DATETIME NOT NULL,
		FOREIGN KEY (workspace_id) REFERENCES workspaces(id) ON DELETE CASCADE
	);

	CREATE INDEX IF NOT EXISTS idx_scans_workspace ON scans(workspace_id);
	CREATE INDEX IF NOT EXISTS idx_scans_module ON scans(workspace_id, module);
	-- Audit B1/B2: status + archived are filtered on every /scans list
	-- and on startup (MarkOrphanedScans, HasRunningScans). Without
	-- these indexes the queries fell back to full table scans, which
	-- at 5k+ rows pushed the /scans page from <50 ms to several
	-- seconds and made startup MarkOrphanedScans visibly slow.
	CREATE INDEX IF NOT EXISTS idx_scans_status ON scans(status);
	-- NOTE: idx_scans_workspace_archived is created AFTER the archived column
	-- is added below (on a fresh DB the column does not exist yet in this block).

	CREATE TABLE IF NOT EXISTS settings (
		key   TEXT PRIMARY KEY,
		value TEXT NOT NULL
	);
	`
	if _, err := d.Exec(schema); err != nil {
		return err
	}
	// Lightweight migrations for older databases. `ALTER TABLE ... ADD COLUMN
	// IF NOT EXISTS` isn't supported, so we check pragma_table_info first.
	var hasArchived int
	d.Get(&hasArchived, `SELECT COUNT(*) FROM pragma_table_info('scans') WHERE name='archived'`)
	if hasArchived == 0 {
		if _, err := d.Exec(`ALTER TABLE scans ADD COLUMN archived INTEGER NOT NULL DEFAULT 0`); err != nil {
			return fmt.Errorf("add archived column: %w", err)
		}
	}
	// Created here (not in the schema string above) because it references the
	// `archived` column, which is added by the ALTER just above on a fresh DB.
	d.Exec(`CREATE INDEX IF NOT EXISTS idx_scans_workspace_archived ON scans(workspace_id, archived)`)
	var hasCommands int
	d.Get(&hasCommands, `SELECT COUNT(*) FROM pragma_table_info('scans') WHERE name='commands'`)
	if hasCommands == 0 {
		if _, err := d.Exec(`ALTER TABLE scans ADD COLUMN commands TEXT NOT NULL DEFAULT ''`); err != nil {
			return fmt.Errorf("add commands column: %w", err)
		}
	}
	// console_log holds the FULL progress-message stream (every line a module
	// emits, not just the "$ " command crumbs mirrored into `commands`). The
	// old live console was built purely from 2-second poll samples of the
	// single latest progress_msg, so inter-poll lines were lost and a
	// reloaded/finished scan showed an empty console. All three progress
	// writers now append here so the console is lossless and re-renderable.
	// Trimmed to the last consoleLogCap bytes on every append.
	var hasConsoleLog int
	d.Get(&hasConsoleLog, `SELECT COUNT(*) FROM pragma_table_info('scans') WHERE name='console_log'`)
	if hasConsoleLog == 0 {
		if _, err := d.Exec(`ALTER TABLE scans ADD COLUMN console_log TEXT NOT NULL DEFAULT ''`); err != nil {
			return fmt.Errorf("add console_log column: %w", err)
		}
	}
	// Denormalized counters used by the dashboard charts. Computed by
	// scanstats.Compute on every UpdateScanResult write, backfilled
	// lazily on startup for pre-existing rows so the dashboard never
	// has to re-parse a multi-megabyte Result blob to draw a bar.
	var hasSevCount int
	d.Get(&hasSevCount, `SELECT COUNT(*) FROM pragma_table_info('scans') WHERE name='severity_count'`)
	if hasSevCount == 0 {
		if _, err := d.Exec(`ALTER TABLE scans ADD COLUMN severity_count INTEGER NOT NULL DEFAULT 0`); err != nil {
			return fmt.Errorf("add severity_count column: %w", err)
		}
	}
	var hasConnCount int
	d.Get(&hasConnCount, `SELECT COUNT(*) FROM pragma_table_info('scans') WHERE name='open_connections_count'`)
	if hasConnCount == 0 {
		if _, err := d.Exec(`ALTER TABLE scans ADD COLUMN open_connections_count INTEGER NOT NULL DEFAULT 0`); err != nil {
			return fmt.Errorf("add open_connections_count column: %w", err)
		}
	}

	// CHECK-constraint extension on targets.type to accept 'url'. SQLite
	// can't ALTER a CHECK clause in place, so we detect-and-rebuild only
	// when the legacy constraint is still installed. The probe is the
	// CREATE TABLE statement stored in sqlite_master — if it mentions
	// the four-value tuple we're done; if it's still the three-value
	// tuple we recreate the table and copy rows over.
	var targetsSQL string
	d.Get(&targetsSQL, `SELECT sql FROM sqlite_master WHERE type='table' AND name='targets'`)
	if targetsSQL != "" && !strings.Contains(targetsSQL, "'url'") {
		// New tables haven't been created at this point (recreate path).
		// Wrap in a single transaction so a crash mid-migration doesn't
		// leave us with `targets_new` orphaned.
		tx, err := d.Beginx()
		if err != nil {
			return fmt.Errorf("targets-type migration begin: %w", err)
		}
		if _, err := tx.Exec(`CREATE TABLE targets_new (
				id           TEXT PRIMARY KEY,
				workspace_id TEXT NOT NULL,
				value        TEXT NOT NULL,
				type         TEXT NOT NULL CHECK(type IN ('ipv4', 'domain', 'fqdn', 'url')),
				note         TEXT NOT NULL DEFAULT '',
				created_at   DATETIME NOT NULL,
				list_id      TEXT,
				FOREIGN KEY (workspace_id) REFERENCES workspaces(id) ON DELETE CASCADE,
				UNIQUE(workspace_id, value)
			)`); err != nil {
			tx.Rollback()
			return fmt.Errorf("targets-type migration create: %w", err)
		}
		if _, err := tx.Exec(`INSERT INTO targets_new SELECT * FROM targets`); err != nil {
			tx.Rollback()
			return fmt.Errorf("targets-type migration copy: %w", err)
		}
		if _, err := tx.Exec(`DROP TABLE targets`); err != nil {
			tx.Rollback()
			return fmt.Errorf("targets-type migration drop: %w", err)
		}
		if _, err := tx.Exec(`ALTER TABLE targets_new RENAME TO targets`); err != nil {
			tx.Rollback()
			return fmt.Errorf("targets-type migration rename: %w", err)
		}
		if _, err := tx.Exec(`CREATE INDEX IF NOT EXISTS idx_targets_workspace ON targets(workspace_id);
			CREATE INDEX IF NOT EXISTS idx_targets_type ON targets(workspace_id, type);
			CREATE INDEX IF NOT EXISTS idx_targets_list ON targets(list_id)`); err != nil {
			tx.Rollback()
			return fmt.Errorf("targets-type migration index: %w", err)
		}
		if err := tx.Commit(); err != nil {
			return fmt.Errorf("targets-type migration commit: %w", err)
		}
		log.Printf("targets-type migration: rebuilt targets table with 'url' in CHECK constraint")
	}
	// target_lists — per-workspace named buckets so users can categorize hosts
	// (e.g. "Company A — provided", "Company B — provided"). targets.list_id
	// is nullable (NULL = uncategorized).
	if _, err := d.Exec(`CREATE TABLE IF NOT EXISTS target_lists (
		id           TEXT PRIMARY KEY,
		workspace_id TEXT NOT NULL,
		name         TEXT NOT NULL,
		description  TEXT NOT NULL DEFAULT '',
		created_at   DATETIME NOT NULL,
		FOREIGN KEY (workspace_id) REFERENCES workspaces(id) ON DELETE CASCADE,
		UNIQUE(workspace_id, name)
	)`); err != nil {
		return fmt.Errorf("create target_lists: %w", err)
	}
	var hasListID int
	d.Get(&hasListID, `SELECT COUNT(*) FROM pragma_table_info('targets') WHERE name='list_id'`)
	if hasListID == 0 {
		if _, err := d.Exec(`ALTER TABLE targets ADD COLUMN list_id TEXT`); err != nil {
			return fmt.Errorf("add list_id column: %w", err)
		}
		d.Exec(`CREATE INDEX IF NOT EXISTS idx_targets_list ON targets(list_id)`)
	}
	// Many-to-many target↔list membership. A "list" is really a category/
	// label: a single target may belong to several. This join table
	// replaces the old single targets.list_id (which is kept only as a
	// legacy column and is no longer read). ON DELETE CASCADE cleans
	// memberships when either side is deleted.
	if _, err := d.Exec(`CREATE TABLE IF NOT EXISTS target_list_members (
		list_id    TEXT NOT NULL,
		target_id  TEXT NOT NULL,
		created_at DATETIME NOT NULL,
		PRIMARY KEY (list_id, target_id),
		FOREIGN KEY (list_id)   REFERENCES target_lists(id) ON DELETE CASCADE,
		FOREIGN KEY (target_id) REFERENCES targets(id)      ON DELETE CASCADE
	)`); err != nil {
		return fmt.Errorf("create target_list_members: %w", err)
	}
	d.Exec(`CREATE INDEX IF NOT EXISTS idx_tlm_target ON target_list_members(target_id)`)
	d.Exec(`CREATE INDEX IF NOT EXISTS idx_tlm_list ON target_list_members(list_id)`)
	// One-time backfill: fold every existing single-list assignment into the
	// join table. Idempotent (INSERT OR IGNORE on the composite PK), so it's
	// safe to run on every startup.
	d.Exec(`INSERT OR IGNORE INTO target_list_members (list_id, target_id, created_at)
		SELECT list_id, id, created_at FROM targets
		WHERE list_id IS NOT NULL AND list_id != ''`)
	// asset_lists / asset_list_members were dropped along with the
	// user-curated asset grouping feature. Assets are now strictly the
	// read-only set of things any scan has touched — no membership table.
	// The DROPs are idempotent so a fresh DB doesn't error.
	d.Exec(`DROP TABLE IF EXISTS asset_list_members`)
	d.Exec(`DROP TABLE IF EXISTS asset_lists`)
	// cve_records — single source-of-truth for all CVE data the matcher
	// consults. Rows come from three layers:
	//   1. Built-in 35 curated landmark CVEs — seeded at startup by
	//      cvematch.SeedBuiltin() (source='builtin'). Always present even
	//      after a cache wipe.
	//   2. NVD JSON 2.0 feeds — annual + modified (source='nvd').
	//   (OSV.dev was previously supported but removed — its ~5M rows of
	//   ecosystem advisories produced too much noise for pentest use.)
	// Each row is one (product, version-range) tuple. A single CVE-ID
	// usually produces many rows.
	if _, err := d.Exec(`CREATE TABLE IF NOT EXISTS cve_records (
		id             INTEGER PRIMARY KEY AUTOINCREMENT,
		cve_id         TEXT NOT NULL,
		source         TEXT NOT NULL DEFAULT 'nvd',
		product_key    TEXT NOT NULL,
		product_name   TEXT NOT NULL,
		version_lo     TEXT NOT NULL DEFAULT '',
		version_hi     TEXT NOT NULL DEFAULT '',
		lo_inclusive   INTEGER NOT NULL DEFAULT 1,
		hi_inclusive   INTEGER NOT NULL DEFAULT 1,
		fixed_in       TEXT NOT NULL DEFAULT '',
		severity       TEXT NOT NULL DEFAULT 'UNKNOWN',
		cvss           REAL NOT NULL DEFAULT 0,
		description    TEXT NOT NULL DEFAULT '',
		remediation    TEXT NOT NULL DEFAULT '',
		reference      TEXT NOT NULL DEFAULT '',
		published_at   DATETIME,
		modified_at    DATETIME
	)`); err != nil {
		return fmt.Errorf("create cve_records: %w", err)
	}
	// vuln_index_cache — persisted workspace-wide vulnerability index so the
	// /vulnerabilities page doesn't rebuild the (expensive, multi-GB-streaming)
	// index from scratch on every process restart. Keyed by workspace;
	// `fingerprint` identifies the scan set it was built from, so a stale cache
	// (scans added/deleted) is detected on load and rebuilt.
	d.Exec(`CREATE TABLE IF NOT EXISTS vuln_index_cache (
		workspace_id TEXT PRIMARY KEY,
		fingerprint  TEXT NOT NULL,
		data         TEXT NOT NULL,
		updated_at   DATETIME NOT NULL
	)`)
	// scan_vuln_index — per-scan extracted vulnerabilities, so the workspace
	// index build is INCREMENTAL: a scan's (large) result blob is walked at most
	// once ever, and every rebuild after a scan is added/deleted/finished just
	// merges the small cached per-scan vuln lists instead of re-streaming
	// hundreds of MB. Keyed by scan_id; `fingerprint` (status:finishedAt:
	// severityCount:extractVersion) detects when a scan's result changed or the
	// extraction logic was revised.
	d.Exec(`CREATE TABLE IF NOT EXISTS scan_vuln_index (
		scan_id     TEXT PRIMARY KEY,
		fingerprint TEXT NOT NULL,
		data        TEXT NOT NULL,
		updated_at  DATETIME NOT NULL
	)`)
	// vuln_overrides — per-vulnerability operator/rescan state, keyed by the
	// deterministic vuln_id (SCN-…). archived=1 hides the finding from the main
	// Vulnerabilities list and surfaces it under the Archive tab. Written by the
	// rescan reconciler (a rescan that completes without re-finding a vuln archives
	// it) and by manual archive/unarchive. Separate from the derived vuln index so
	// archiving never requires re-walking scan results.
	d.Exec(`CREATE TABLE IF NOT EXISTS vuln_overrides (
		vuln_id      TEXT PRIMARY KEY,
		workspace_id TEXT NOT NULL,
		archived     INTEGER NOT NULL DEFAULT 0,
		reason       TEXT NOT NULL DEFAULT '',
		updated_at   DATETIME NOT NULL
	)`)
	// deleted=1 permanently hides a finding from BOTH the active list and the
	// Archive tab (operator's manual "delete" on a confirmed false positive).
	// Separate from archived so a deleted finding stays hidden even if a later
	// rescan would re-activate the archived flag. Added by ALTER for DBs created
	// before the column existed.
	{
		var hasDeleted int
		d.Get(&hasDeleted, `SELECT COUNT(*) FROM pragma_table_info('vuln_overrides') WHERE name='deleted'`)
		if hasDeleted == 0 {
			d.Exec(`ALTER TABLE vuln_overrides ADD COLUMN deleted INTEGER NOT NULL DEFAULT 0`)
		}
	}
	// rescan_verify — links a rescan scan to the vuln_ids it is re-checking, so
	// when that scan completes the reconciler knows which findings to confirm
	// (re-found → keep/unarchive) or archive (absent from the fresh results).
	// Rows are cleared once reconciled.
	d.Exec(`CREATE TABLE IF NOT EXISTS rescan_verify (
		scan_id TEXT NOT NULL,
		vuln_id TEXT NOT NULL,
		PRIMARY KEY (scan_id, vuln_id)
	)`)
	// Backfill `fixed_in` + `remediation` columns when upgrading.
	var hasFixedIn int
	d.Get(&hasFixedIn, `SELECT COUNT(*) FROM pragma_table_info('cve_records') WHERE name='fixed_in'`)
	if hasFixedIn == 0 {
		d.Exec(`ALTER TABLE cve_records ADD COLUMN fixed_in TEXT NOT NULL DEFAULT ''`)
	}
	var hasRemediation int
	d.Get(&hasRemediation, `SELECT COUNT(*) FROM pragma_table_info('cve_records') WHERE name='remediation'`)
	if hasRemediation == 0 {
		d.Exec(`ALTER TABLE cve_records ADD COLUMN remediation TEXT NOT NULL DEFAULT ''`)
	}
	// Backfill `source` column when upgrading from an earlier schema that
	// didn't have it. SQLite reports NULL for missing columns.
	var hasSource int
	d.Get(&hasSource, `SELECT COUNT(*) FROM pragma_table_info('cve_records') WHERE name='source'`)
	if hasSource == 0 {
		d.Exec(`ALTER TABLE cve_records ADD COLUMN source TEXT NOT NULL DEFAULT 'nvd'`)
	}
	d.Exec(`CREATE INDEX IF NOT EXISTS idx_cve_product ON cve_records(product_key)`)
	d.Exec(`CREATE INDEX IF NOT EXISTS idx_cve_id ON cve_records(cve_id)`)
	// Expression index on UPPER(cve_id): CVEByID matches `WHERE UPPER(cve_id)=?`
	// (case-insensitive), which the plain idx_cve_id can't serve — the UPPER()
	// wrapper forces a full 130k-row scan per lookup. This index turns each
	// CVE-DB join in the vulnerability-index build into an O(log n) seek (the
	// difference between a 25 ms and a 5 µs lookup, i.e. seconds vs. nothing
	// across a workspace's findings).
	d.Exec(`CREATE INDEX IF NOT EXISTS idx_cve_id_upper ON cve_records(UPPER(cve_id))`)
	d.Exec(`CREATE INDEX IF NOT EXISTS idx_cve_source ON cve_records(source)`)
	// Unique index lets CVEBulkUpsert use INSERT OR REPLACE (one stmt
	// per row) instead of DELETE+INSERT. Existing data has zero dupes
	// because the legacy upsert path enforced this same key by DELETE.
	d.Exec(`CREATE UNIQUE INDEX IF NOT EXISTS idx_cve_uniq ON cve_records(cve_id, source, product_key, version_lo, version_hi)`)

	// Backfill cve_db_last_refresh when we already have downloaded rows
	// but no timestamp (e.g. cache imported before the timestamp code
	// landed). Use MAX(modified_at) of non-builtin rows as a conservative
	// lower bound — the real download happened AFTER that point, so the
	// staleness banner stays accurate without falsely claiming "never".
	if d.GetSetting("cve_db_last_refresh") == "" {
		var maxMod sql.NullString
		d.Get(&maxMod, `SELECT MAX(modified_at) FROM cve_records WHERE source != 'builtin'`)
		if maxMod.Valid && maxMod.String != "" {
			if t, err := time.Parse("2006-01-02 15:04:05.999999999 -0700 MST", maxMod.String); err == nil {
				d.SetSetting("cve_db_last_refresh", t.UTC().Format(time.RFC3339))
			} else if t, err := time.Parse(time.RFC3339, maxMod.String); err == nil {
				d.SetSetting("cve_db_last_refresh", t.UTC().Format(time.RFC3339))
			}
		}
	}

	// --- Identity / auth layer (login, sessions, RBAC, audit) ---------------
	// users: application operators. Passwords are bcrypt; twofa_secret is base32.
	if _, err := d.Exec(`CREATE TABLE IF NOT EXISTS users (
		id                   TEXT PRIMARY KEY,
		username             TEXT NOT NULL UNIQUE,
		email                TEXT NOT NULL DEFAULT '',
		password_hash        TEXT NOT NULL,
		role                 TEXT NOT NULL DEFAULT 'user',
		is_active            INTEGER NOT NULL DEFAULT 1,
		must_change_password INTEGER NOT NULL DEFAULT 0,
		twofa_required       INTEGER NOT NULL DEFAULT 0,
		twofa_method         TEXT NOT NULL DEFAULT '',
		twofa_secret         TEXT NOT NULL DEFAULT '',
		twofa_enrolled       INTEGER NOT NULL DEFAULT 0,
		twofa_last_step      INTEGER NOT NULL DEFAULT 0,
		can_add_targets      INTEGER NOT NULL DEFAULT 1,
		failed_login_count   INTEGER NOT NULL DEFAULT 0,
		login_locked_until   DATETIME,
		failed_2fa_count     INTEGER NOT NULL DEFAULT 0,
		twofa_locked_until   DATETIME,
		last_login_at        DATETIME,
		created_at           DATETIME NOT NULL,
		updated_at           DATETIME NOT NULL
	)`); err != nil {
		return fmt.Errorf("create users: %w", err)
	}
	// Forward-compat: add twofa_last_step to a users table created by an earlier
	// build that predates the TOTP replay guard.
	var hasLastStep int
	d.Get(&hasLastStep, `SELECT COUNT(*) FROM pragma_table_info('users') WHERE name='twofa_last_step'`)
	if hasLastStep == 0 {
		d.Exec(`ALTER TABLE users ADD COLUMN twofa_last_step INTEGER NOT NULL DEFAULT 0`)
	}
	var hasCanAdd int
	d.Get(&hasCanAdd, `SELECT COUNT(*) FROM pragma_table_info('users') WHERE name='can_add_targets'`)
	if hasCanAdd == 0 {
		d.Exec(`ALTER TABLE users ADD COLUMN can_add_targets INTEGER NOT NULL DEFAULT 1`)
	}

	// user_domain_scopes: per-(user,workspace) allowed-domain allowlist. Each row
	// is a domain (matches host + subdomains) or an IP/CIDR. An EMPTY set for a
	// (user,workspace) means unrestricted (opt-in scoping). Admins always bypass.
	if _, err := d.Exec(`CREATE TABLE IF NOT EXISTS user_domain_scopes (
		id           TEXT PRIMARY KEY,
		user_id      TEXT NOT NULL,
		workspace_id TEXT NOT NULL,
		pattern      TEXT NOT NULL,
		FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE,
		FOREIGN KEY (workspace_id) REFERENCES workspaces(id) ON DELETE CASCADE,
		UNIQUE(user_id, workspace_id, pattern)
	)`); err != nil {
		return fmt.Errorf("create user_domain_scopes: %w", err)
	}
	d.Exec(`CREATE INDEX IF NOT EXISTS idx_domscope_user_ws ON user_domain_scopes(user_id, workspace_id)`)

	// sessions: server-side login state. id = sha256(raw cookie token).
	if _, err := d.Exec(`CREATE TABLE IF NOT EXISTS sessions (
		id           TEXT PRIMARY KEY,
		user_id      TEXT NOT NULL,
		state        TEXT NOT NULL DEFAULT 'active',
		otp_hash     TEXT NOT NULL DEFAULT '',
		otp_expires  DATETIME,
		created_at   DATETIME NOT NULL,
		expires_at   DATETIME NOT NULL,
		last_seen_at DATETIME NOT NULL,
		ip           TEXT NOT NULL DEFAULT '',
		user_agent   TEXT NOT NULL DEFAULT '',
		FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
	)`); err != nil {
		return fmt.Errorf("create sessions: %w", err)
	}
	d.Exec(`CREATE INDEX IF NOT EXISTS idx_sessions_user ON sessions(user_id)`)

	// permissions: one row grants (user, workspace, module). Absence = deny.
	if _, err := d.Exec(`CREATE TABLE IF NOT EXISTS permissions (
		id           TEXT PRIMARY KEY,
		user_id      TEXT NOT NULL,
		workspace_id TEXT NOT NULL,
		module       TEXT NOT NULL,
		FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE,
		FOREIGN KEY (workspace_id) REFERENCES workspaces(id) ON DELETE CASCADE,
		UNIQUE(user_id, workspace_id, module)
	)`); err != nil {
		return fmt.Errorf("create permissions: %w", err)
	}
	d.Exec(`CREATE INDEX IF NOT EXISTS idx_perms_user_ws ON permissions(user_id, workspace_id)`)

	// audit_log: append-only. NO foreign keys — rows are fully denormalized so
	// they survive scan/workspace/user deletion. There is intentionally no
	// UPDATE or DELETE method anywhere in the app, not even for admins.
	if _, err := d.Exec(`CREATE TABLE IF NOT EXISTS audit_log (
		id             TEXT PRIMARY KEY,
		ts             DATETIME NOT NULL,
		user_id        TEXT NOT NULL DEFAULT '',
		username       TEXT NOT NULL DEFAULT '',
		category       TEXT NOT NULL DEFAULT '',
		action         TEXT NOT NULL DEFAULT '',
		workspace_id   TEXT NOT NULL DEFAULT '',
		workspace_name TEXT NOT NULL DEFAULT '',
		module         TEXT NOT NULL DEFAULT '',
		target         TEXT NOT NULL DEFAULT '',
		scan_id        TEXT NOT NULL DEFAULT '',
		ip             TEXT NOT NULL DEFAULT '',
		detail         TEXT NOT NULL DEFAULT ''
	)`); err != nil {
		return fmt.Errorf("create audit_log: %w", err)
	}
	d.Exec(`CREATE INDEX IF NOT EXISTS idx_audit_ts ON audit_log(ts)`)
	d.Exec(`CREATE INDEX IF NOT EXISTS idx_audit_cat ON audit_log(category, ts)`)

	// Ensure default workspace exists
	return d.ensureDefaultWorkspace()
}

// CVEUpsert inserts or replaces a CVE record row. fixedIn + remediation
// are optional — empty strings render as "—" in the UI.
func (d *DB) CVEUpsert(cveID, source, productKey, productName, versionLo, versionHi string,
	loInc, hiInc bool, fixedIn, severity string, cvss float64, description, remediation, reference string,
	publishedAt, modifiedAt time.Time) error {
	if source == "" {
		source = "nvd"
	}
	// Atomic delete-then-insert (audit B6). Previously the DELETE and
	// INSERT were two independent statements — a crash or 'database is
	// locked' between them left the row deleted but not re-inserted,
	// causing CVE entries to vanish silently after a partial sync.
	// Wrapping in a single transaction means either both go or neither
	// goes; the next sync iteration just retries.
	tx, err := d.Begin()
	if err != nil {
		return err
	}
	commit := false
	defer func() {
		if commit {
			tx.Commit()
		} else {
			tx.Rollback()
		}
	}()
	if _, err := tx.Exec(`DELETE FROM cve_records WHERE cve_id=? AND source=? AND product_key=? AND version_lo=? AND version_hi=?`,
		cveID, source, productKey, versionLo, versionHi); err != nil {
		return err
	}
	loI, hiI := 0, 0
	if loInc {
		loI = 1
	}
	if hiInc {
		hiI = 1
	}
	if _, err := tx.Exec(`INSERT INTO cve_records
		(cve_id, source, product_key, product_name, version_lo, version_hi, lo_inclusive, hi_inclusive,
		 fixed_in, severity, cvss, description, remediation, reference, published_at, modified_at)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		cveID, source, productKey, productName, versionLo, versionHi, loI, hiI,
		fixedIn, severity, cvss, description, remediation, reference, publishedAt, modifiedAt); err != nil {
		return err
	}
	commit = true
	return nil
}

// CVEBulkRow is the row shape for bulk-insert. Same fields as the
// per-row CVEUpsert args, packaged for batched commits.
type CVEBulkRow struct {
	CVEID       string
	Source      string
	ProductKey  string
	ProductName string
	VersionLo   string
	VersionHi   string
	LoInc       bool
	HiInc       bool
	FixedIn     string
	Severity    string
	CVSS        float64
	Description string
	Remediation string
	Reference   string
	PublishedAt time.Time
	ModifiedAt  time.Time
}

// CVEBulkUpsert inserts a slice of rows using multi-row VALUES batched
// in transactions. Three optimizations vs the per-row CVEUpsert path:
//
//  1. INSERT OR REPLACE on idx_cve_uniq — one statement per row instead
//     of DELETE+INSERT.
//  2. Multi-row VALUES (...),(...),... — single driver round-trip for
//     a chunk of rows (matters a lot for pure-Go modernc driver).
//  3. Big transactions (10k rows) — amortize WAL commit overhead.
//
// progress fires with cumulative row count after each transaction commits.
func (d *DB) CVEBulkUpsert(rows []CVEBulkRow, progress func(done int)) error {
	const txBatch = 10000     // rows per transaction commit
	const insertChunk = 500   // rows per multi-row INSERT statement

	cols := `(cve_id, source, product_key, product_name, version_lo, version_hi, lo_inclusive, hi_inclusive,
		fixed_in, severity, cvss, description, remediation, reference, published_at, modified_at)`
	rowPlaceholders := "(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)"

	flushChunk := func(tx *sqlx.Tx, chunk []CVEBulkRow) error {
		if len(chunk) == 0 {
			return nil
		}
		var sb strings.Builder
		sb.WriteString("INSERT OR REPLACE INTO cve_records ")
		sb.WriteString(cols)
		sb.WriteString(" VALUES ")
		args := make([]any, 0, len(chunk)*16)
		for i, r := range chunk {
			if i > 0 {
				sb.WriteString(",")
			}
			sb.WriteString(rowPlaceholders)
			source := r.Source
			if source == "" {
				source = "nvd"
			}
			loI, hiI := 0, 0
			if r.LoInc {
				loI = 1
			}
			if r.HiInc {
				hiI = 1
			}
			args = append(args,
				r.CVEID, source, r.ProductKey, r.ProductName, r.VersionLo, r.VersionHi, loI, hiI,
				r.FixedIn, r.Severity, r.CVSS, r.Description, r.Remediation, r.Reference, r.PublishedAt, r.ModifiedAt)
		}
		_, err := tx.Exec(sb.String(), args...)
		return err
	}

	for start := 0; start < len(rows); start += txBatch {
		end := start + txBatch
		if end > len(rows) {
			end = len(rows)
		}
		tx, err := d.Beginx()
		if err != nil {
			return fmt.Errorf("begin tx: %w", err)
		}
		for ck := start; ck < end; ck += insertChunk {
			ckEnd := ck + insertChunk
			if ckEnd > end {
				ckEnd = end
			}
			if err := flushChunk(tx, rows[ck:ckEnd]); err != nil {
				tx.Rollback()
				return fmt.Errorf("insert chunk: %w", err)
			}
		}
		if err := tx.Commit(); err != nil {
			return fmt.Errorf("commit batch: %w", err)
		}
		if progress != nil {
			progress(end)
		}
	}
	return nil
}

// CVERecord is the row shape returned by CVELookup.
type CVERecord struct {
	CVEID       string  `db:"cve_id"`
	Source      string  `db:"source"`
	ProductKey  string  `db:"product_key"`
	ProductName string  `db:"product_name"`
	VersionLo   string  `db:"version_lo"`
	VersionHi   string  `db:"version_hi"`
	LoInc       int     `db:"lo_inclusive"`
	HiInc       int     `db:"hi_inclusive"`
	FixedIn     string  `db:"fixed_in"`
	Severity    string  `db:"severity"`
	CVSS        float64 `db:"cvss"`
	Description string  `db:"description"`
	Remediation string  `db:"remediation"`
	Reference   string  `db:"reference"`
}

// CVELookup returns all rows for a normalized product key. The matcher
// then evaluates which version ranges actually cover the input version.
func (d *DB) CVELookup(productKey string) ([]CVERecord, error) {
	var out []CVERecord
	const cols = `cve_id, source, product_key, product_name, version_lo, version_hi,
		lo_inclusive, hi_inclusive, fixed_in, severity, cvss, description, remediation, reference`
	// A vendor-qualified key ("vendor:product") is matched exactly. A bare
	// product component (no colon — e.g. "tomcat" from a detected "Tomcat",
	// "nginx" from "nginx") is matched against that exact product under ANY
	// vendor, so it also hits "apache:tomcat"/"f5:nginx" without the caller
	// having to know the CPE vendor. This closes a large gap: NVD keys are
	// vendor-prefixed, so the old exact-only lookup missed most of them
	// (e.g. tomcat:tomcat = 0 rows vs :tomcat = 1194). SQL LIKE wildcards in
	// the component are escaped so "http_server" can't match "httpXserver".
	if strings.Contains(productKey, ":") {
		err := d.Select(&out, `SELECT `+cols+` FROM cve_records WHERE product_key = ?`, productKey)
		return out, err
	}
	esc := strings.NewReplacer(`\`, `\\`, `%`, `\%`, `_`, `\_`).Replace(productKey)
	err := d.Select(&out, `SELECT `+cols+` FROM cve_records
		WHERE product_key = ? OR product_key LIKE '%:' || ? ESCAPE '\'`,
		productKey, esc)
	return out, err
}

// CVEByID returns the highest-CVSS record for a given CVE id (a CVE can appear
// as several product/version rows; we want the richest one for a report join).
// Used by the vulnerability export to fill CVSS/description/remediation when the
// scanning module didn't inline them. Returns false when the CVE isn't indexed.
func (d *DB) CVEByID(cveID string) (CVERecord, bool) {
	cveID = strings.ToUpper(strings.TrimSpace(cveID))
	if cveID == "" {
		return CVERecord{}, false
	}
	var rec CVERecord
	err := d.Get(&rec, `SELECT cve_id, source, product_key, product_name, version_lo, version_hi,
		lo_inclusive, hi_inclusive, fixed_in, severity, cvss, description, remediation, reference
		FROM cve_records WHERE UPPER(cve_id) = ? ORDER BY cvss DESC LIMIT 1`, cveID)
	if err != nil {
		return CVERecord{}, false
	}
	return rec, true
}

// SaveVulnIndexCache upserts a workspace's built vulnerability index (JSON) so
// it survives process restarts. fingerprint identifies the scan set it was
// built from.
func (d *DB) SaveVulnIndexCache(workspaceID, fingerprint, data string) error {
	_, err := d.Exec(`INSERT INTO vuln_index_cache (workspace_id, fingerprint, data, updated_at)
		VALUES (?, ?, ?, ?)
		ON CONFLICT(workspace_id) DO UPDATE SET fingerprint=excluded.fingerprint, data=excluded.data, updated_at=excluded.updated_at`,
		workspaceID, fingerprint, data, time.Now())
	return err
}

// CVEMaxModifiedAt returns the newest CVE modification timestamp we hold, i.e.
// the point the "quick" incremental refresh should resume from. Zero if empty.
func (d *DB) CVEMaxModifiedAt() time.Time {
	var s string
	if err := d.Get(&s, `SELECT COALESCE(MAX(modified_at),'') FROM cve_records`); err != nil || s == "" {
		return time.Time{}
	}
	for _, layout := range []string{
		"2006-01-02 15:04:05.999999999 -0700 MST",
		"2006-01-02T15:04:05Z07:00",
		"2006-01-02 15:04:05",
	} {
		if t, err := time.Parse(layout, s); err == nil {
			return t.UTC()
		}
	}
	return time.Time{}
}

// CVEIDsBySource returns the set of distinct cve_ids already stored for a given
// source (e.g. "cna"). Used by the CNA-enrichment pass to skip re-fetching CVEs
// it already enriched on a previous refresh, so steady-state daily runs only hit
// CVE.org for newly-appeared unanalyzed CVEs.
func (d *DB) CVEIDsBySource(source string) map[string]bool {
	out := map[string]bool{}
	rows, err := d.Query(`SELECT DISTINCT cve_id FROM cve_records WHERE source = ?`, source)
	if err != nil {
		return out
	}
	defer rows.Close()
	for rows.Next() {
		var id string
		if rows.Scan(&id) == nil {
			out[id] = true
		}
	}
	return out
}

// SetVulnArchived upserts a vulnerability's archived state. reason is a short
// human string (e.g. "rescan did not confirm"); it's cleared when unarchiving.
func (d *DB) SetVulnArchived(vulnID, workspaceID string, archived bool, reason string) error {
	a := 0
	if archived {
		a = 1
	} else {
		reason = ""
	}
	_, err := d.Exec(`INSERT INTO vuln_overrides (vuln_id, workspace_id, archived, reason, updated_at)
		VALUES (?, ?, ?, ?, ?)
		ON CONFLICT(vuln_id) DO UPDATE SET archived=excluded.archived, reason=excluded.reason, updated_at=excluded.updated_at`,
		vulnID, workspaceID, a, reason, time.Now())
	return err
}

// SetVulnDeleted upserts a vulnerability's deleted state — a permanent hide from
// both the active list and the Archive tab, for a false positive the operator
// wants gone. Independent of archived, so a re-found rescan can't resurrect it.
func (d *DB) SetVulnDeleted(vulnID, workspaceID string, deleted bool) error {
	del := 0
	if deleted {
		del = 1
	}
	_, err := d.Exec(`INSERT INTO vuln_overrides (vuln_id, workspace_id, deleted, updated_at)
		VALUES (?, ?, ?, ?)
		ON CONFLICT(vuln_id) DO UPDATE SET deleted=excluded.deleted, updated_at=excluded.updated_at`,
		vulnID, workspaceID, del, time.Now())
	return err
}

// DeletedVulnIDs returns the set of permanently-deleted vuln_ids for a workspace.
// The vuln index excludes these from every view.
func (d *DB) DeletedVulnIDs(workspaceID string) map[string]bool {
	out := map[string]bool{}
	rows, err := d.Query(`SELECT vuln_id FROM vuln_overrides WHERE workspace_id = ? AND deleted = 1`, workspaceID)
	if err != nil {
		return out
	}
	defer rows.Close()
	for rows.Next() {
		var id string
		if rows.Scan(&id) == nil {
			out[id] = true
		}
	}
	return out
}

// RescanningVulnIDs returns the set of vuln_ids that have an in-flight rescan —
// a rescan_verify link to a scan still running or pending. The Vulnerabilities
// page spins each of these findings' rescan icon until its verification lands.
func (d *DB) RescanningVulnIDs(workspaceID string) map[string]bool {
	out := map[string]bool{}
	rows, err := d.Query(`
		SELECT DISTINCT rv.vuln_id
		FROM rescan_verify rv
		JOIN scans s ON s.id = rv.scan_id
		WHERE s.workspace_id = ? AND s.status IN ('running','pending')`, workspaceID)
	if err != nil {
		return out
	}
	defer rows.Close()
	for rows.Next() {
		var id string
		if rows.Scan(&id) == nil {
			out[id] = true
		}
	}
	return out
}

// ArchivedVulnIDs returns the set of archived vuln_ids for a workspace mapped to
// their archive reason. Used to partition the vuln index into active vs archived.
func (d *DB) ArchivedVulnIDs(workspaceID string) map[string]string {
	out := map[string]string{}
	rows, err := d.Query(`SELECT vuln_id, reason FROM vuln_overrides WHERE workspace_id = ? AND archived = 1`, workspaceID)
	if err != nil {
		return out
	}
	defer rows.Close()
	for rows.Next() {
		var id, reason string
		if rows.Scan(&id, &reason) == nil {
			out[id] = reason
		}
	}
	return out
}

// AddRescanVerify records that scanID is a rescan re-checking the given vuln_ids.
func (d *DB) AddRescanVerify(scanID string, vulnIDs []string) error {
	for _, id := range vulnIDs {
		if _, err := d.Exec(`INSERT OR IGNORE INTO rescan_verify (scan_id, vuln_id) VALUES (?, ?)`, scanID, id); err != nil {
			return err
		}
	}
	return nil
}

// RescanVerifyIDs returns the vuln_ids a rescan scan is re-checking (empty for a
// normal scan).
func (d *DB) RescanVerifyIDs(scanID string) []string {
	var ids []string
	rows, err := d.Query(`SELECT vuln_id FROM rescan_verify WHERE scan_id = ?`, scanID)
	if err != nil {
		return ids
	}
	defer rows.Close()
	for rows.Next() {
		var id string
		if rows.Scan(&id) == nil {
			ids = append(ids, id)
		}
	}
	return ids
}

// ClearRescanVerify drops a rescan scan's verify links once it has reconciled.
func (d *DB) ClearRescanVerify(scanID string) error {
	_, err := d.Exec(`DELETE FROM rescan_verify WHERE scan_id = ?`, scanID)
	return err
}

// LoadVulnIndexCache returns the persisted index for a workspace (its
// fingerprint + JSON data), or ok=false if none is stored. The caller compares
// the fingerprint against the current scan set to decide whether it's fresh.
func (d *DB) LoadVulnIndexCache(workspaceID string) (fingerprint, data string, ok bool) {
	var row struct {
		Fingerprint string `db:"fingerprint"`
		Data        string `db:"data"`
	}
	if err := d.Get(&row, `SELECT fingerprint, data FROM vuln_index_cache WHERE workspace_id = ?`, workspaceID); err != nil {
		return "", "", false
	}
	return row.Fingerprint, row.Data, true
}

// DeleteVulnIndexCache drops a workspace's persisted index (e.g. when a scan is
// deleted, so a stale index isn't reloaded on the next restart before rebuild).
func (d *DB) DeleteVulnIndexCache(workspaceID string) error {
	_, err := d.Exec(`DELETE FROM vuln_index_cache WHERE workspace_id = ?`, workspaceID)
	return err
}

// SaveScanVulnCache upserts the vulnerabilities extracted from a SINGLE scan's
// result (JSON), so the workspace index build reuses it instead of re-walking
// the scan's (possibly hundreds-of-MB) result blob. fingerprint captures the
// scan's mutable state + the extractor version.
func (d *DB) SaveScanVulnCache(scanID, fingerprint, data string) error {
	_, err := d.Exec(`INSERT INTO scan_vuln_index (scan_id, fingerprint, data, updated_at)
		VALUES (?, ?, ?, ?)
		ON CONFLICT(scan_id) DO UPDATE SET fingerprint=excluded.fingerprint, data=excluded.data, updated_at=excluded.updated_at`,
		scanID, fingerprint, data, time.Now())
	return err
}

// LoadScanVulnCache returns the per-scan extracted vulnerabilities (fingerprint
// + JSON), or ok=false if none is stored. The caller compares the fingerprint
// against the scan's current state to decide whether it's still fresh.
func (d *DB) LoadScanVulnCache(scanID string) (fingerprint, data string, ok bool) {
	var row struct {
		Fingerprint string `db:"fingerprint"`
		Data        string `db:"data"`
	}
	if err := d.Get(&row, `SELECT fingerprint, data FROM scan_vuln_index WHERE scan_id = ?`, scanID); err != nil {
		return "", "", false
	}
	return row.Fingerprint, row.Data, true
}

// DeleteScanVulnCache drops a scan's per-scan extracted vulns (called when the
// scan is deleted so the row doesn't orphan).
func (d *DB) DeleteScanVulnCache(scanID string) error {
	_, err := d.Exec(`DELETE FROM scan_vuln_index WHERE scan_id = ?`, scanID)
	return err
}

// CVECacheCount returns total row count.
func (d *DB) CVECacheCount() int {
	var n int
	d.Get(&n, `SELECT COUNT(*) FROM cve_records`)
	return n
}

// CVEYearRowCounts returns per-year NVD record counts (year → row count),
// keyed off the CVE id's year field. Used by the auto-refresh gap detector to
// find missing/sparse years the modified-only feed never backfills.
func (d *DB) CVEYearRowCounts() map[int]int {
	var rows []struct {
		Y string `db:"y"`
		N int    `db:"n"`
	}
	_ = d.Select(&rows, `SELECT substr(cve_id,5,4) AS y, COUNT(*) AS n
		FROM cve_records WHERE source='nvd' GROUP BY y`)
	out := make(map[int]int, len(rows))
	for _, r := range rows {
		if y, err := strconv.Atoi(r.Y); err == nil {
			out[y] = r.N
		}
	}
	return out
}

// CVECacheDistinctCVEs returns the number of distinct CVE IDs across
// all sources. This is the user-meaningful "how many vulnerabilities do
// I have indexed" number — distinct from the row count, which counts
// (CVE × product × version-range) tuples and can be 10–100× larger.
func (d *DB) CVECacheDistinctCVEs() int {
	var n int
	d.Get(&n, `SELECT COUNT(DISTINCT cve_id) FROM cve_records`)
	return n
}

// CVECacheDistinctCVEsBySource returns distinct-CVE-ID count per source.
func (d *DB) CVECacheDistinctCVEsBySource() map[string]int {
	rows, err := d.Query(`SELECT source, COUNT(DISTINCT cve_id) FROM cve_records GROUP BY source`)
	out := map[string]int{}
	if err != nil {
		return out
	}
	defer rows.Close()
	for rows.Next() {
		var src string
		var n int
		if err := rows.Scan(&src, &n); err == nil {
			out[src] = n
		}
	}
	return out
}

// CVECacheCountsBySource returns per-source row counts.
func (d *DB) CVECacheCountsBySource() map[string]int {
	rows, err := d.Query(`SELECT source, COUNT(*) FROM cve_records GROUP BY source`)
	out := map[string]int{}
	if err != nil {
		return out
	}
	defer rows.Close()
	for rows.Next() {
		var src string
		var n int
		if err := rows.Scan(&src, &n); err == nil {
			out[src] = n
		}
	}
	return out
}

// CVECacheLastRefresh returns the timestamp of the LAST SUCCESSFUL sync
// run (when WE downloaded), persisted in the settings key-value table.
// This is the value the UI should show — it's distinct from the
// modified-at of any individual CVE record.
func (d *DB) CVECacheLastRefresh() time.Time {
	v := d.GetSetting("cve_db_last_refresh")
	if v == "" {
		return time.Time{}
	}
	t, err := time.Parse(time.RFC3339, v)
	if err != nil {
		return time.Time{}
	}
	return t
}

// CVECacheSetLastRefresh stores the timestamp called when a refresh job
// completes successfully (any source).
func (d *DB) CVECacheSetLastRefresh(t time.Time) {
	d.SetSetting("cve_db_last_refresh", t.UTC().Format(time.RFC3339))
}

// CVECacheClearSource wipes a single source's rows (used when
// re-syncing — e.g. "clear NVD then re-download"). Built-in seed rows
// (source='builtin') are preserved unless explicitly cleared.
func (d *DB) CVECacheClearSource(source string) error {
	_, err := d.Exec(`DELETE FROM cve_records WHERE source = ?`, source)
	return err
}

// CVECacheClear wipes the whole cache including built-in seed rows.
// Caller is expected to re-seed afterwards.
func (d *DB) CVECacheClear() error {
	_, err := d.Exec(`DELETE FROM cve_records`)
	return err
}

// CVECachePruneStale removes NVD rows that haven't been touched in
// olderThan (audit B17). Used by the daily auto-refresh path to evict
// CVEs that NVD has retracted upstream. Built-in seed rows are preserved
// (their published_at is the curated set's pin date, not the snapshot
// modification time). Returns the row count removed.
func (d *DB) CVECachePruneStale(olderThan time.Duration) (int64, error) {
	cutoff := time.Now().Add(-olderThan)
	res, err := d.Exec(
		`DELETE FROM cve_records WHERE source != 'builtin' AND modified_at < ?`,
		cutoff,
	)
	if err != nil {
		return 0, err
	}
	n, _ := res.RowsAffected()
	return n, nil
}

func (d *DB) ensureDefaultWorkspace() error {
	var count int
	d.Get(&count, `SELECT COUNT(*) FROM workspaces WHERE id = ?`, DefaultWorkspaceID)
	if count > 0 {
		return nil
	}
	now := time.Now()
	_, err := d.Exec(
		`INSERT INTO workspaces (id, name, description, is_default, created_at, updated_at) VALUES (?, ?, ?, 1, ?, ?)`,
		DefaultWorkspaceID, "Default Workspace", "Default workspace", now, now,
	)
	return err
}

// --- Workspace CRUD ---

// CreateWorkspace creates a new workspace
func (d *DB) CreateWorkspace(name, description string) (*models.Workspace, error) {
	w := &models.Workspace{
		ID:          uuid.New().String(),
		Name:        name,
		Description: description,
		CreatedAt:   time.Now(),
		UpdatedAt:   time.Now(),
	}
	_, err := d.Exec(
		`INSERT INTO workspaces (id, name, description, created_at, updated_at) VALUES (?, ?, ?, ?, ?)`,
		w.ID, w.Name, w.Description, w.CreatedAt, w.UpdatedAt,
	)
	if err != nil {
		return nil, err
	}
	return w, nil
}

// ListWorkspaces returns all workspaces with target counts
func (d *DB) ListWorkspaces() ([]models.WorkspaceStats, error) {
	var stats []models.WorkspaceStats
	err := d.Select(&stats, `
		SELECT
			w.id, w.name, w.description, w.is_default, w.created_at, w.updated_at,
			COUNT(t.id) as target_count,
			COUNT(CASE WHEN t.type = 'ipv4' THEN 1 END) as ipv4_count,
			COUNT(CASE WHEN t.type = 'domain' THEN 1 END) as domain_count,
			COUNT(CASE WHEN t.type = 'fqdn' THEN 1 END) as fqdn_count
		FROM workspaces w
		LEFT JOIN targets t ON t.workspace_id = w.id
		GROUP BY w.id
		ORDER BY w.is_default DESC, w.updated_at DESC
	`)
	return stats, err
}

// GetWorkspace returns a single workspace by ID
func (d *DB) GetWorkspace(id string) (*models.Workspace, error) {
	var w models.Workspace
	err := d.Get(&w, `SELECT * FROM workspaces WHERE id = ?`, id)
	if err != nil {
		return nil, err
	}
	return &w, nil
}

// DeleteWorkspace deletes a workspace and all its targets (cannot delete default)
func (d *DB) DeleteWorkspace(id string) error {
	if id == DefaultWorkspaceID {
		return fmt.Errorf("cannot delete default workspace")
	}
	_, err := d.Exec(`DELETE FROM workspaces WHERE id = ? AND is_default = 0`, id)
	return err
}

// ResetWorkspace wipes all per-workspace data — scans, targets, target
// lists — but keeps the workspace row itself. Returns counts of rows
// removed for each table.
//
// Global state (settings, API keys, CVE database cache) is untouched.
// Used by the "Reset workspace" Settings button to give a clean slate
// without destroying the workspace identity (cookies, links, history).
func (d *DB) ResetWorkspace(workspaceID string) (scans, targets, lists int) {
	if workspaceID == "" {
		return
	}
	// Atomic reset (audit B7). Previously each DELETE ran in its own
	// implicit transaction, so a crash between them left orphaned
	// targets / lists referencing a workspace that had no scans (or
	// vice-versa). Wrapping in a single tx means either everything
	// goes or nothing goes — DB always coherent.
	tx, err := d.Begin()
	if err != nil {
		return
	}
	commit := false
	defer func() {
		if commit {
			tx.Commit()
		} else {
			tx.Rollback()
		}
	}()
	if r, err := tx.Exec(`DELETE FROM scans WHERE workspace_id = ?`, workspaceID); err == nil {
		n, _ := r.RowsAffected()
		scans = int(n)
	} else {
		return
	}
	if r, err := tx.Exec(`DELETE FROM targets WHERE workspace_id = ?`, workspaceID); err == nil {
		n, _ := r.RowsAffected()
		targets = int(n)
	} else {
		return
	}
	if r, err := tx.Exec(`DELETE FROM target_lists WHERE workspace_id = ?`, workspaceID); err == nil {
		n, _ := r.RowsAffected()
		lists = int(n)
	} else {
		return
	}
	commit = true
	return
}

// --- Target CRUD ---

// CreateTarget adds a target to a workspace
func (d *DB) CreateTarget(workspaceID, value string, targetType models.TargetType, note string) (*models.Target, error) {
	return d.CreateTargetInList(workspaceID, value, targetType, note, "")
}

// CreateTargetInList is the list-aware target creator. Pass listID = "" to
// leave the target uncategorized; the caller is expected to have validated
// that listID belongs to workspaceID.
func (d *DB) CreateTargetInList(workspaceID, value string, targetType models.TargetType, note, listID string) (*models.Target, error) {
	var legacyList sql.NullString
	if listID != "" {
		legacyList = sql.NullString{String: listID, Valid: true}
	}
	// Upsert-safe. There is a UNIQUE(workspace_id, value) constraint, so a
	// plain INSERT of an already-existing target (e.g. one uploaded again in a
	// second list, or previously filed under another category) used to fail
	// and the target — and its NEW category — got silently dropped. Instead:
	// insert only if new, then ALWAYS add the requested list membership. A
	// target may belong to several categories at once, so an existing target
	// keeps its current memberships AND gains this one (INSERT OR IGNORE on the
	// join table). list_id is a legacy single-slot column, no longer read.
	if _, err := d.Exec(
		`INSERT INTO targets (id, workspace_id, value, type, note, list_id, created_at)
		 VALUES (?, ?, ?, ?, ?, ?, ?)
		 ON CONFLICT(workspace_id, value) DO NOTHING`,
		uuid.New().String(), workspaceID, value, targetType, note, legacyList, time.Now(),
	); err != nil {
		return nil, err
	}
	// Fetch the canonical row — the one we just inserted OR the pre-existing one.
	t := &models.Target{}
	if err := d.Get(t,
		`SELECT id, workspace_id, value, type, note, list_id, created_at
		   FROM targets WHERE workspace_id = ? AND value = ?`,
		workspaceID, value,
	); err != nil {
		return nil, err
	}
	if listID != "" {
		d.Exec(`INSERT OR IGNORE INTO target_list_members (list_id, target_id, created_at) VALUES (?, ?, ?)`,
			listID, t.ID, t.CreatedAt)
	}
	d.Exec(`UPDATE workspaces SET updated_at = ? WHERE id = ?`, time.Now(), workspaceID)
	return t, nil
}

// CreateTargetMulti creates a target and files it under every listID in the
// set (many-to-many). Empty/duplicate list IDs are ignored. Pass nil/empty
// listIDs for an uncategorized target.
func (d *DB) CreateTargetMulti(workspaceID, value string, targetType models.TargetType, note string, listIDs []string) (*models.Target, error) {
	first := ""
	if len(listIDs) > 0 {
		first = listIDs[0]
	}
	t, err := d.CreateTargetInList(workspaceID, value, targetType, note, first)
	if err != nil || t == nil {
		return t, err
	}
	rest := listIDs
	if len(rest) > 0 {
		rest = rest[1:] // first was already filed by CreateTargetInList
	}
	for _, lid := range rest {
		if lid != "" && lid != first {
			d.Exec(`INSERT OR IGNORE INTO target_list_members (list_id, target_id, created_at) VALUES (?, ?, ?)`,
				lid, t.ID, t.CreatedAt)
		}
	}
	return t, nil
}

// AddTargetsToList adds an EXISTING-target membership to a list (many-to-many).
// Idempotent — re-adding a target already in the list is a no-op. Used by the
// "add existing targets to this category" and "categorize this target" flows.
func (d *DB) AddTargetsToList(listID string, targetIDs []string) error {
	if listID == "" || len(targetIDs) == 0 {
		return nil
	}
	now := time.Now()
	for _, tid := range targetIDs {
		if _, err := d.Exec(`INSERT OR IGNORE INTO target_list_members (list_id, target_id, created_at) VALUES (?, ?, ?)`,
			listID, tid, now); err != nil {
			return err
		}
	}
	return nil
}

// RemoveTargetFromList drops a single membership without deleting the target
// (the target stays in the workspace, just loses that one category).
func (d *DB) RemoveTargetFromList(listID, targetID string) error {
	_, err := d.Exec(`DELETE FROM target_list_members WHERE list_id = ? AND target_id = ?`, listID, targetID)
	return err
}

// SetTargetLists replaces the full set of categories a single target belongs
// to (used by the per-target "manage categories" editor). listIDs are the
// desired memberships; anything not in the set is removed.
func (d *DB) SetTargetLists(targetID string, listIDs []string) error {
	if _, err := d.Exec(`DELETE FROM target_list_members WHERE target_id = ?`, targetID); err != nil {
		return err
	}
	now := time.Now()
	for _, lid := range listIDs {
		if lid == "" {
			continue
		}
		if _, err := d.Exec(`INSERT OR IGNORE INTO target_list_members (list_id, target_id, created_at) VALUES (?, ?, ?)`,
			lid, targetID, now); err != nil {
			return err
		}
	}
	return nil
}

// TargetListMembership returns targetID → the lists it belongs to, for every
// target in the workspace. Used to render each target row's category chips in
// one query instead of N.
func (d *DB) TargetListMembership(workspaceID string) map[string][]models.TargetList {
	out := map[string][]models.TargetList{}
	rows, err := d.Query(`
		SELECT m.target_id, l.id, l.workspace_id, l.name, l.description, l.created_at
		FROM target_list_members m
		JOIN target_lists l ON l.id = m.list_id
		WHERE l.workspace_id = ?
		ORDER BY l.created_at ASC`, workspaceID)
	if err != nil {
		return out
	}
	defer rows.Close()
	for rows.Next() {
		var tid string
		var l models.TargetList
		if err := rows.Scan(&tid, &l.ID, &l.WorkspaceID, &l.Name, &l.Description, &l.CreatedAt); err == nil {
			out[tid] = append(out[tid], l)
		}
	}
	return out
}

// ListTargets returns all targets for a workspace, optionally filtered by type
func (d *DB) ListTargets(workspaceID string, filterType string) ([]models.Target, error) {
	var targets []models.Target
	if filterType != "" && filterType != "all" {
		err := d.Select(&targets,
			`SELECT * FROM targets WHERE workspace_id = ? AND type = ? ORDER BY created_at DESC`,
			workspaceID, filterType,
		)
		return targets, err
	}
	err := d.Select(&targets,
		`SELECT * FROM targets WHERE workspace_id = ? ORDER BY created_at DESC`,
		workspaceID,
	)
	return targets, err
}

// GetTarget fetches a single target by ID.
func (d *DB) GetTarget(id string) (*models.Target, error) {
	var t models.Target
	err := d.Get(&t, `SELECT * FROM targets WHERE id = ?`, id)
	if err != nil {
		return nil, err
	}
	return &t, nil
}

// DeleteTarget removes a target
func (d *DB) DeleteTarget(id string) error {
	// Get workspace_id before delete to update timestamp
	var wsID string
	d.Get(&wsID, `SELECT workspace_id FROM targets WHERE id = ?`, id)
	_, err := d.Exec(`DELETE FROM targets WHERE id = ?`, id)
	if err == nil && wsID != "" {
		d.Exec(`UPDATE workspaces SET updated_at = ? WHERE id = ?`, time.Now(), wsID)
	}
	return err
}

// --- Target Lists ---

// CreateTargetList makes a new named bucket of targets within a workspace.
// Names are unique per workspace (DB constraint).
func (d *DB) CreateTargetList(workspaceID, name, description string) (*models.TargetList, error) {
	name = strings.TrimSpace(name)
	if name == "" {
		return nil, fmt.Errorf("list name required")
	}
	tl := &models.TargetList{
		ID:          uuid.New().String(),
		WorkspaceID: workspaceID,
		Name:        name,
		Description: description,
		CreatedAt:   time.Now(),
	}
	_, err := d.Exec(
		`INSERT INTO target_lists (id, workspace_id, name, description, created_at) VALUES (?, ?, ?, ?, ?)`,
		tl.ID, tl.WorkspaceID, tl.Name, tl.Description, tl.CreatedAt)
	if err != nil {
		return nil, err
	}
	return tl, nil
}

// ListTargetLists returns every list defined in a workspace, oldest first
// (so creation order matches the visible chip order).
func (d *DB) ListTargetLists(workspaceID string) ([]models.TargetList, error) {
	var out []models.TargetList
	err := d.Select(&out,
		`SELECT * FROM target_lists WHERE workspace_id = ? ORDER BY created_at ASC`, workspaceID)
	return out, err
}

// DeleteTargetList drops a list (category). Its members lose the category but
// are NOT deleted — they remain in the workspace (and keep any other
// categories). Removes the join rows + the legacy list_id back-reference.
func (d *DB) DeleteTargetList(id string) error {
	d.Exec(`DELETE FROM target_list_members WHERE list_id = ?`, id)
	d.Exec(`UPDATE targets SET list_id = NULL WHERE list_id = ?`, id) // legacy column
	_, err := d.Exec(`DELETE FROM target_lists WHERE id = ?`, id)
	return err
}

// GetTargetList fetches a single list by ID.
func (d *DB) GetTargetList(id string) (*models.TargetList, error) {
	var tl models.TargetList
	err := d.Get(&tl, `SELECT * FROM target_lists WHERE id = ?`, id)
	return &tl, err
}

// MoveTargetsToList reassigns one or more targets to a list (or to "" =
// uncategorized).
func (d *DB) MoveTargetsToList(targetIDs []string, listID string) error {
	if len(targetIDs) == 0 {
		return nil
	}
	var listVal interface{}
	if listID == "" {
		listVal = nil
	} else {
		listVal = listID
	}
	for _, tid := range targetIDs {
		if _, err := d.Exec(`UPDATE targets SET list_id = ? WHERE id = ?`, listVal, tid); err != nil {
			return err
		}
	}
	return nil
}

// ListTargetsInList returns every target that belongs to the given list
// (category), via the many-to-many join. Used by module forms when the user
// picks a list — every member auto-checks.
func (d *DB) ListTargetsInList(listID string) ([]models.Target, error) {
	var out []models.Target
	err := d.Select(&out, `
		SELECT t.* FROM targets t
		JOIN target_list_members m ON m.target_id = t.id
		WHERE m.list_id = ?
		ORDER BY t.created_at DESC`, listID)
	return out, err
}

// CountTargetsPerList returns a map of list_id → member count for the given
// workspace (via the join table). The empty-string key holds the count of
// UNCATEGORIZED targets — those with no membership in any list.
func (d *DB) CountTargetsPerList(workspaceID string) map[string]int {
	out := map[string]int{}
	rows, err := d.Query(`
		SELECT m.list_id, COUNT(*) FROM target_list_members m
		JOIN target_lists l ON l.id = m.list_id
		WHERE l.workspace_id = ?
		GROUP BY m.list_id`, workspaceID)
	if err == nil {
		defer rows.Close()
		for rows.Next() {
			var lid string
			var n int
			if err := rows.Scan(&lid, &n); err == nil {
				out[lid] = n
			}
		}
	}
	// Uncategorized: targets with zero memberships.
	var uncat int
	d.Get(&uncat, `
		SELECT COUNT(*) FROM targets t
		WHERE t.workspace_id = ?
		  AND NOT EXISTS (SELECT 1 FROM target_list_members m WHERE m.target_id = t.id)`, workspaceID)
	out[""] = uncat
	return out
}

// Asset-list DB methods (CreateAssetList, ListAssetLists, DeleteAssetList,
// SetAssetListMembers, AssetListMembership, CountAssetsPerList) were all
// removed when the user-curated asset-lists feature was retired. The
// asset_lists / asset_list_members tables are DROPped in the migration
// block above.

// GetTargetCounts returns counts per type for a workspace
func (d *DB) GetTargetCounts(workspaceID string) (total, ipv4, domain, fqdn int, err error) {
	row := d.QueryRow(`
		SELECT
			COUNT(*),
			COUNT(CASE WHEN type = 'ipv4' THEN 1 END),
			COUNT(CASE WHEN type = 'domain' THEN 1 END),
			COUNT(CASE WHEN type = 'fqdn' THEN 1 END)
		FROM targets WHERE workspace_id = ?
	`, workspaceID)
	err = row.Scan(&total, &ipv4, &domain, &fqdn)
	return
}

// WorkspaceExists checks if a workspace exists
func (d *DB) WorkspaceExists(id string) bool {
	var exists bool
	d.Get(&exists, `SELECT EXISTS(SELECT 1 FROM workspaces WHERE id = ?)`, id)
	return exists
}

// TargetExists checks if a target value already exists in a workspace
func (d *DB) TargetExists(workspaceID, value string) bool {
	var count int
	err := d.Get(&count, `SELECT COUNT(*) FROM targets WHERE workspace_id = ? AND value = ?`, workspaceID, value)
	if err != nil && err != sql.ErrNoRows {
		return false
	}
	return count > 0
}

// --- Scan CRUD ---

func (d *DB) CreateScan(workspaceID, module, config string, totalTargets int) (*models.Scan, error) {
	s := &models.Scan{
		ID:            uuid.New().String(),
		WorkspaceID:   workspaceID,
		Module:        module,
		Status:        models.ScanPending,
		Config:        config,
		Result:        "[]",
		ProgressTotal: totalTargets,
		CreatedAt:     time.Now(),
	}
	_, err := d.Exec(
		`INSERT INTO scans (id, workspace_id, module, status, config, result, progress_done, progress_total, progress_msg, created_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?, '', ?)`,
		s.ID, s.WorkspaceID, s.Module, s.Status, s.Config, s.Result, 0, s.ProgressTotal, s.CreatedAt,
	)
	return s, err
}

// MarkRunning atomically flips a scan from pending → running. Returns
// true if the row was actually pending and got flipped; false if the
// scan had already been transitioned to any other state — typically
// because the user clicked Stop in the window between scan creation
// and the run-goroutine getting CPU time. Run goroutines MUST bail out
// when this returns false; otherwise they'd do work for a scan the
// user already cancelled, AND a subsequent `defer FinishScan` would
// incorrectly flip cancelled → done.
//
// This is the conditional version of UpdateScanStatus(id, ScanRunning).
// Using `UPDATE ... WHERE status = pending` makes the check + flip
// atomic at the SQL level, side-stepping any race between handler
// goroutines and the ScanStop request.
func (d *DB) MarkRunning(id string) bool {
	res, err := d.Exec(`UPDATE scans SET status = ?, started_at = ? WHERE id = ? AND status = ?`,
		models.ScanRunning, time.Now(), id, models.ScanPending)
	if err != nil {
		return false
	}
	n, _ := res.RowsAffected()
	return n > 0
}

// MarkScanQueued flags a scan for sequential dispatch (the operator ticked
// "start after the current scan finishes"). The row keeps its full config but
// is NOT dispatched; StartScanQueue picks it up later. Deliberately does NOT
// stamp finished_at — the scan hasn't run and hasn't finished — unlike
// UpdateScanStatus, which stamps finished_at for any non-running status. Only
// a still-pending row is queued, so a race with an immediate dispatch is a
// no-op.
func (d *DB) MarkScanQueued(id, message string) {
	if _, err := d.Exec(
		`UPDATE scans SET status = ?, progress_msg = ? WHERE id = ? AND status = ?`,
		models.ScanQueued, message, id, models.ScanPending,
	); err != nil {
		log.Printf("MarkScanQueued(%s) failed: %v", id, err)
	}
}

// ClaimQueuedScan atomically flips a queued scan to pending so exactly one
// scheduler pass can dispatch it — the WHERE status='queued' guard makes a
// concurrent/duplicate claim a no-op. Returns true if this caller won. The
// caller then runs dispatchRestart, whose run goroutine's MarkRunning flips
// pending→running.
func (d *DB) ClaimQueuedScan(id string) bool {
	res, err := d.Exec(`UPDATE scans SET status = ? WHERE id = ? AND status = ?`,
		models.ScanPending, id, models.ScanQueued)
	if err != nil {
		return false
	}
	n, _ := res.RowsAffected()
	return n > 0
}

// CountActiveScans returns how many scans in a workspace are running, pending,
// or paused. Running/pending are consuming resources; paused is counted too so
// a queued scan never jumps ahead of a scan the connectivity monitor paused
// mid-run — that scan will auto-resume and must finish first to preserve FIFO
// order across a network outage. Queued scans are excluded: they are exactly
// what waits for this count to reach zero. Drives the sequential-scan gate +
// scheduler.
func (d *DB) CountActiveScans(workspaceID string) int {
	var n int
	if err := d.Get(&n,
		`SELECT COUNT(*) FROM scans WHERE workspace_id = ? AND status IN ('running','pending','paused')`,
		workspaceID); err != nil {
		return 0
	}
	return n
}

// ListQueuedScans returns every queued scan across all workspaces, oldest
// first (FIFO). Lean projection: only the columns the scheduler needs to
// dispatch (id/workspace/module/config) — never the multi-MB result blob.
func (d *DB) ListQueuedScans() ([]models.Scan, error) {
	var scans []models.Scan
	err := d.Select(&scans,
		`SELECT id, workspace_id, module, status, config, progress_total, created_at
		 FROM scans WHERE status = 'queued' ORDER BY created_at ASC`)
	return scans, err
}

// MarkScanError stamps an error status + message on a scan row in a
// single UPDATE. Used by the killswitch monitor when it aborts a scan
// out-of-band of the normal completion path.
func (d *DB) MarkScanError(id, message string) {
	// NOT IN ('cancelled','done','paused'): a user Stop must win over a late
	// tool-error finalize, and an out-of-band mark (e.g. the killswitch monitor
	// firing on a still-registered id in the FinishScan→Unregister window) must
	// not clobber a scan that already finished successfully or is paused.
	if _, err := d.Exec(
		`UPDATE scans SET status = ?, progress_msg = ?, finished_at = ? WHERE id = ? AND status NOT IN ('cancelled','done','paused')`,
		models.ScanError, message, time.Now(), id,
	); err != nil {
		log.Printf("MarkScanError(%s) failed: %v", id, err)
	}
}

func (d *DB) UpdateScanStatus(id string, status models.ScanStatus) {
	if status == models.ScanRunning {
		now := time.Now()
		d.Exec(`UPDATE scans SET status = ?, started_at = ? WHERE id = ?`, status, now, id)
	} else {
		now := time.Now()
		d.Exec(`UPDATE scans SET status = ?, finished_at = ? WHERE id = ?`, status, now, id)
	}
}

// FinalizeScan writes result + progress_msg + status + finished_at in a
// SINGLE atomic UPDATE (audit B8). Previously the advancedweb finalizer
// fired three separate writes (UpdateScanResult + UpdateScanProgress +
// UpdateScanStatus) — a crash or DB lock between them left an
// inconsistent row (status=running but result populated, or status=done
// but progress_msg still showing a partial). Single statement = no
// torn state. Conditional WHERE keeps a concurrent cancel from being
// stomped.
// progressBatchEntry is one pending write in the per-scan batch. Held in
// memory until the next flush tick (or until the scan finishes), then
// applied as a single UPDATE. (audit B5)
type progressBatchEntry struct {
	scanID string
	done   int
	// msgs accumulates EVERY message since the last flush (not just the
	// latest) so the console_log stays lossless even for high-frequency
	// batched modules (paramdisc, smbenum). The last non-empty entry is
	// still used as the progress_msg caption.
	msgs    []string
	updated time.Time
}

// progressBatcher coalesces UpdateScanProgress writes so a chatty
// scanner (spider crawler, brute-forcer with thousands of attempts)
// doesn't hammer the DB with one UPDATE per progress callback. Writes
// are flushed every 500 ms (or immediately when the scan changes).
//
// Without batching, a 10k-page spider was producing ~10k UPDATEs/min
// against scans, which under busy_timeout=5000 ms occasionally queued
// other writers and surfaced as the dashboard feeling sluggish under
// load. Coalescing drops the rate ~30× with no UI-visible latency.
var progressBatcher = struct {
	mu      sync.Mutex
	pending map[string]progressBatchEntry
	flusher *time.Ticker
	db      *DB
	started bool
}{
	pending: map[string]progressBatchEntry{},
}

// startProgressBatcher kicks off the flush loop. Idempotent.
func (d *DB) startProgressBatcher() {
	progressBatcher.mu.Lock()
	defer progressBatcher.mu.Unlock()
	if progressBatcher.started {
		return
	}
	progressBatcher.started = true
	progressBatcher.db = d
	progressBatcher.flusher = time.NewTicker(500 * time.Millisecond)
	go func() {
		for range progressBatcher.flusher.C {
			flushProgressBatch()
		}
	}()
}

// flushProgressBatch applies all pending entries in one go and resets
// the map.
func flushProgressBatch() {
	progressBatcher.mu.Lock()
	if len(progressBatcher.pending) == 0 || progressBatcher.db == nil {
		progressBatcher.mu.Unlock()
		return
	}
	pending := progressBatcher.pending
	progressBatcher.pending = map[string]progressBatchEntry{}
	db := progressBatcher.db
	progressBatcher.mu.Unlock()

	// Apply each pending row. We don't wrap in a transaction because
	// the UPDATEs target different rows; SQLite's serialized writer
	// already orders them.
	for _, e := range pending {
		caption := ""
		for i := len(e.msgs) - 1; i >= 0; i-- {
			if strings.TrimSpace(e.msgs[i]) != "" {
				caption = e.msgs[i]
				break
			}
		}
		if _, err := db.Exec(
			`UPDATE scans SET progress_done = ?, progress_msg = ? WHERE id = ?`,
			e.done, caption, e.scanID,
		); err != nil {
			log.Printf("flushProgressBatch(%s): %v", e.scanID, err)
		}
		db.appendConsoleLog(e.scanID, e.msgs)
	}
}

// UpdateScanProgressBatched stashes the write for the next flush tick
// instead of issuing it immediately (audit B5). For callers that need
// guaranteed durability (final result write, status flip), use
// UpdateScanProgress or FinalizeScan instead.
func (d *DB) UpdateScanProgressBatched(id string, done int, msg string) {
	d.startProgressBatcher()
	progressBatcher.mu.Lock()
	e := progressBatcher.pending[id]
	e.scanID = id
	e.done = done
	if msg != "" {
		e.msgs = append(e.msgs, msg)
	}
	e.updated = time.Now()
	progressBatcher.pending[id] = e
	progressBatcher.mu.Unlock()
}

func (d *DB) FinalizeScan(id, result, msg string, status models.ScanStatus) {
	// Drain any pending batched progress writes for this scan so the
	// final UPDATE sees a consistent baseline (audit B5).
	progressBatcher.mu.Lock()
	delete(progressBatcher.pending, id)
	progressBatcher.mu.Unlock()

	now := time.Now()
	if _, err := d.Exec(
		`UPDATE scans
		    SET result = ?, progress_msg = ?, status = ?, finished_at = ?
		  WHERE id = ? AND status NOT IN ('cancelled')`,
		result, msg, status, now, id,
	); err != nil {
		log.Printf("FinalizeScan(%s) failed: %v", id, err)
	}
}

// MarkDoneUnlessCancelled atomically transitions a scan to 'done' but
// ONLY if its current status isn't 'cancelled' or 'error' (audit B34).
// Without this conditional clause, a Read→Write race meant a cancel
// fired during the final goroutine sequence got overwritten by the
// "done" status — the user clicked Stop, saw cancelled briefly, then
// watched the row flip back to done a millisecond later. Now the
// terminal state set by Stop wins.
func (d *DB) MarkDoneUnlessCancelled(id string) {
	now := time.Now()
	if _, err := d.Exec(
		`UPDATE scans SET status = ?, finished_at = ? WHERE id = ? AND status NOT IN ('cancelled','error','paused')`,
		models.ScanDone, now, id,
	); err != nil {
		log.Printf("MarkDoneUnlessCancelled(%s) failed: %v", id, err)
	}
}

// ListPausedScans returns every paused scan across all workspaces (the resume
// path iterates these). Full rows (incl. Config + Result) so resume can diff.
func (d *DB) ListPausedScans() ([]models.Scan, error) {
	var scans []models.Scan
	err := d.Select(&scans, `SELECT * FROM scans WHERE status = 'paused' AND archived = 0`)
	return scans, err
}

// ResumeToRunning atomically flips a paused scan back to running. Returns false
// if the row wasn't paused (already resumed by another trigger — manual +
// monitor can race), so the caller launches at most one resume goroutine.
func (d *DB) ResumeToRunning(id string) bool {
	res, err := d.Exec(
		`UPDATE scans SET status = ?, started_at = ?, finished_at = NULL WHERE id = ? AND status = ?`,
		models.ScanRunning, time.Now(), id, models.ScanPaused)
	if err != nil {
		return false
	}
	n, _ := res.RowsAffected()
	return n > 0
}

// MarkScanPaused flips a running scan to 'paused' (connectivity monitor). The
// partial result/config/progress are preserved for the resume path. It does
// NOT clear finished_at-less state or override a terminal user decision:
// a user Stop ('cancelled') or a genuine clean finish ('done') wins over a
// pause; everything else (running/pending/error-mid-shutdown) yields to it.
func (d *DB) MarkScanPaused(id, message string) {
	if _, err := d.Exec(
		`UPDATE scans SET status = ?, progress_msg = ? WHERE id = ? AND status NOT IN ('cancelled','done')`,
		models.ScanPaused, message, id,
	); err != nil {
		log.Printf("MarkScanPaused(%s) failed: %v", id, err)
	}
}

func (d *DB) UpdateScanProgress(id string, done int, msg string) {
	if _, err := d.Exec(`UPDATE scans SET progress_done = ?, progress_msg = ? WHERE id = ?`, done, msg, id); err != nil {
		// Surface DB write failures (audit B9). Previously the error
		// was discarded, so a `database is locked` or contention-driven
		// failure silently dropped progress updates — the UI would
		// freeze on a stale message and the operator had no clue why.
		log.Printf("UpdateScanProgress(%s) failed: %v", id, err)
	}
	d.appendConsoleLog(id, []string{msg})
}

// UpdateScanProgressLive sets the live progress bar (done + current message)
// WITHOUT appending to the console_log. Use it for high-frequency status ticks
// (e.g. a hashcat crack emits a "% · rate · ETA" line every couple of seconds
// for hours) — those overwrite the single progress_msg field instead of piling
// up tens of thousands of near-identical console lines. Log-worthy events
// (command crumbs, phase transitions) still go through UpdateScanProgress.
func (d *DB) UpdateScanProgressLive(id string, done int, msg string) {
	if _, err := d.Exec(`UPDATE scans SET progress_done = ?, progress_msg = ? WHERE id = ?`, done, msg, id); err != nil {
		log.Printf("UpdateScanProgressLive(%s) failed: %v", id, err)
	}
}

// consoleLogCap bounds the durable console_log tail so a chatty multi-hour
// scan can't bloat the row (the commands column has the same unbounded-growth
// caveat; this one is capped). ~200 KB ≈ a few thousand lines.
const consoleLogCap = 200_000

// appendConsoleLog appends every non-empty message in msgs to the scan's
// console_log (trimmed to the last consoleLogCap bytes), and mirrors any
// "$ "-prefixed line into the commands column. This is the single log sink
// shared by UpdateScanProgress / UpdateScanProgressFull / the batched
// flusher, so no write path can silently drop console history — the bug that
// left advancedweb/concurtest/paramdisc/smbenum with an empty console AND an
// empty "Commands run" panel.
func (d *DB) appendConsoleLog(id string, msgs []string) {
	lines := make([]string, 0, len(msgs))
	for _, m := range msgs {
		if strings.TrimSpace(m) != "" {
			lines = append(lines, m)
		}
	}
	if len(lines) == 0 {
		return
	}
	joined := strings.Join(lines, "\n")
	if _, err := d.Exec(`UPDATE scans
		    SET console_log = substr(
		        CASE WHEN console_log = '' THEN ? ELSE console_log || char(10) || ? END,
		        -`+strconv.Itoa(consoleLogCap)+`)
		  WHERE id = ?`, joined, joined, id); err != nil {
		log.Printf("appendConsoleLog(%s) failed: %v", id, err)
	}
	for _, m := range lines {
		if strings.HasPrefix(m, "$ ") {
			if _, err := d.Exec(`UPDATE scans
			            SET commands = CASE WHEN commands = '' THEN ? ELSE commands || char(10) || ? END
			          WHERE id = ?`, m, m, id); err != nil {
				log.Printf("appendConsoleLog(%s) commands append failed: %v", id, err)
			}
		}
	}
}

// UpdateScanProgressFull updates done, total, and message in a single statement.
// Use this when the scanner discovers the true total work-unit count after
// CreateScan has already been called with a placeholder.
func (d *DB) UpdateScanProgressFull(id string, done, total int, msg string) {
	d.Exec(`UPDATE scans SET progress_done = ?, progress_total = ?, progress_msg = ? WHERE id = ?`, done, total, msg, id)
	d.appendConsoleLog(id, []string{msg})
}

// MaxResultBytes is the soft cap on per-scan result blob size. Writes
// above this threshold are silently REJECTED — the previous partial
// save stays canonical and `oversized_result_bytes` gets stamped on the
// row so the UI can surface a warning banner. The cap exists because a
// single 212 MB advancedweb result was inflating the DB to 1.3 GB and
// turning the result page into a 4+ second wall-time render. 50 MB is
// generous enough for every other module observed in practice.
//
// Operator override: setting the `max_result_mb` row in the `settings`
// table to a positive integer changes the cap; 0 = unlimited.
const MaxResultBytes = 50 * 1024 * 1024

func (d *DB) UpdateScanResult(id, result string) {
	// Look up the module so the denormalised severity/connection counts
	// stay in sync with whatever blob we're about to write. A single
	// extra SELECT is cheap compared to the alternative — making every
	// caller (~30 module handlers) pass the module name through.
	var module string
	if err := d.Get(&module, `SELECT module FROM scans WHERE id = ?`, id); err != nil {
		// Scan vanished between the goroutine writing this and our
		// lookup — typically a delete-while-running race. Drop the
		// write; the row won't be there to update anyway.
		return
	}

	// Resume merge (Task 0b/0c): when this scan is a resumed run, prepend the
	// already-completed rows so the persisted blob holds old+new. No-op for
	// normal scans (getResumeBase returns "").
	result = d.resumeMergeIfActive(id, result)

	// Soft cap. Operator can raise (or disable, 0) via settings.
	cap := MaxResultBytes
	if v := d.GetSetting("max_result_mb"); v != "" {
		if n := atoiSafe(v); n > 0 {
			cap = n * 1024 * 1024
		} else if v == "0" {
			cap = 0
		}
	}
	if cap > 0 && len(result) > cap {
		// Persist the over-size signal without writing the blob. Earlier
		// partial save stays canonical; the user sees a banner via
		// scanMgr.Warning + progress_msg, and on completion the DB row
		// shows the truncated payload not the runaway final one.
		msg := fmt.Sprintf("Result truncated — final payload %d MB exceeded the %d MB soft cap (settings → max_result_mb)",
			len(result)/(1024*1024), cap/(1024*1024))
		if _, err := d.Exec(
			`UPDATE scans SET progress_msg = ? WHERE id = ?`, msg, id,
		); err != nil {
			log.Printf("UpdateScanResult(%s) cap-warning failed: %v", id, err)
		}
		return
	}

	sev, conn := scanstats.Compute(module, result)

	// Skip if the scan is already in a terminal state to avoid the
	// race (audit B32) where an async result-saver goroutine stomps the
	// final result the canonical FinalizeScan path just wrote. The
	// terminal-state check + scan-result write must agree on a single
	// "the scan is over" decision; this conditional WHERE keeps us
	// honest without needing a separate version column.
	if _, err := d.Exec(
		`UPDATE scans
		    SET result = ?,
		        severity_count = ?,
		        open_connections_count = ?
		  WHERE id = ?
		    AND status NOT IN ('done','cancelled','error')`,
		result, sev, conn, id,
	); err != nil {
		log.Printf("UpdateScanResult(%s) failed: %v", id, err)
	}
}

// atoiSafe parses a positive integer prefix; returns 0 on any non-digit.
// Used by the settings-override path which never sees negative values.
func atoiSafe(s string) int {
	n := 0
	for _, c := range s {
		if c < '0' || c > '9' {
			return n
		}
		n = n*10 + int(c-'0')
	}
	return n
}

// BackfillScanStats walks every scan that has a non-empty Result but
// zero counters and refills the denormalised columns. Intended to be
// called once on startup, in a goroutine, so older databases catch up
// without blocking server boot.
//
// Returns the number of rows updated. Rows where counts are already
// non-zero are skipped (idempotent — safe to re-run); rows where the
// result genuinely contains no findings stay at 0 and will be revisited
// on every startup, but each visit costs one JSON parse so the wasted
// work is bounded by the count of true-zero scans.
func (d *DB) BackfillScanStats() (int, error) {
	type row struct {
		ID     string `db:"id"`
		Module string `db:"module"`
		Result string `db:"result"`
	}
	var rows []row
	if err := d.Select(&rows, `SELECT id, module, result FROM scans
	    WHERE result <> '' AND result <> '{}'
	      AND severity_count = 0
	      AND open_connections_count = 0`); err != nil {
		return 0, err
	}
	updated := 0
	for _, r := range rows {
		sev, conn := scanstats.Compute(r.Module, r.Result)
		if sev == 0 && conn == 0 {
			// Genuinely empty; skip the write so we don't churn WAL.
			continue
		}
		if _, err := d.Exec(`UPDATE scans
		    SET severity_count = ?, open_connections_count = ?
		    WHERE id = ?`, sev, conn, r.ID); err == nil {
			updated++
		}
	}
	return updated, nil
}

// UpdateScanConfig rewrites the scan's config column. Used by modules that
// need to record chained-scan IDs (techdetect → cvematch) or other post-
// hoc metadata on an already-created row.
func (d *DB) UpdateScanConfig(id, config string) {
	d.Exec(`UPDATE scans SET config = ? WHERE id = ?`, config, id)
}

func (d *DB) GetScan(id string) (*models.Scan, error) {
	var s models.Scan
	err := d.Get(&s, `SELECT * FROM scans WHERE id = ?`, id)
	return &s, err
}

func (d *DB) DeleteScan(id string) error {
	_, err := d.Exec(`DELETE FROM scans WHERE id = ?`, id)
	return err
}

// ListScans returns non-archived scans by default. Existing call sites are
// unaffected; the new ListArchivedScans / SetScanArchived helpers below
// provide archive-aware queries.
func (d *DB) ListScans(workspaceID, module string) ([]models.Scan, error) {
	var scans []models.Scan
	if module != "" {
		return scans, d.Select(&scans,
			`SELECT * FROM scans WHERE workspace_id = ? AND module = ? AND archived = 0 ORDER BY created_at DESC`,
			workspaceID, module)
	}
	return scans, d.Select(&scans,
		`SELECT * FROM scans WHERE workspace_id = ? AND archived = 0 ORDER BY created_at DESC`,
		workspaceID)
}

// ListArchivedScans returns archived scans for a workspace.
func (d *DB) ListArchivedScans(workspaceID string) ([]models.Scan, error) {
	var scans []models.Scan
	return scans, d.Select(&scans,
		`SELECT * FROM scans WHERE workspace_id = ? AND archived = 1 ORDER BY created_at DESC`,
		workspaceID)
}

// scansLiteColumns is the projection used by the Lite-suffixed listers
// below. We deliberately omit:
//
//   - result        : the per-scan JSON blob averages ~79 MB and can reach
//                     217 MB on hostdiscovery sweeps. Sidebar/history views
//                     never reference it; loading it just to read status +
//                     created_at costs seconds per page render on workspaces
//                     with dozens of completed scans.
//   - commands      : the "$ ..." command log accumulates unbounded across
//                     long scans; only useful on the per-scan results page.
//   - progress_msg  : the live message line; sidebar shows status badge,
//                     not the streaming text.
//
// Result/Commands/ProgressMsg come back as zero strings — Go template
// branches like {{if .Result}} stay correct (they treat "" as falsy).
const scansLiteColumns = `id, workspace_id, module, status, config,
        progress_done, progress_total, started_at, finished_at, created_at, archived,
        severity_count, open_connections_count`

// ListScansLite is the BLOB-free counterpart to ListScans. Use it for the
// sidebar "Scan History" lists every module page renders, the /scans
// index, the asset aggregator, and any other place that only needs scan
// metadata (status, target counts, timestamps).
//
// Where Result IS still needed (Dashboard chart aggregation,
// AssetDetail finding extraction), keep ListScans.
func (d *DB) ListScansLite(workspaceID, module string) ([]models.Scan, error) {
	var scans []models.Scan
	if module != "" {
		return scans, d.Select(&scans,
			`SELECT `+scansLiteColumns+` FROM scans WHERE workspace_id = ? AND module = ? AND archived = 0 ORDER BY created_at DESC`,
			workspaceID, module)
	}
	return scans, d.Select(&scans,
		`SELECT `+scansLiteColumns+` FROM scans WHERE workspace_id = ? AND archived = 0 ORDER BY created_at DESC`,
		workspaceID)
}

// ListArchivedScansLite mirrors ListArchivedScans with the same Lite
// projection. The archive page is a sidebar listing — Result is never
// rendered there either.
func (d *DB) ListArchivedScansLite(workspaceID string) ([]models.Scan, error) {
	var scans []models.Scan
	return scans, d.Select(&scans,
		`SELECT `+scansLiteColumns+` FROM scans WHERE workspace_id = ? AND archived = 1 ORDER BY created_at DESC`,
		workspaceID)
}

// CountArchivedScans returns just the archive-count badge that /scans
// shows next to the "Archive" tab. Loading the full ListArchivedScans
// (BLOB and all) every render of /scans was wasted I/O — the only thing
// the caller used was len().
func (d *DB) CountArchivedScans(workspaceID string) int {
	var n int
	d.Get(&n, `SELECT COUNT(*) FROM scans WHERE workspace_id = ? AND archived = 1`, workspaceID)
	return n
}

// ReapOrphanedScans is the in-uptime counterpart to MarkOrphanedScans.
// Called on a periodic timer by the handler-level reaper goroutine, it
// flips any `running` row whose driver goroutine no longer exists. The
// authoritative liveness check is "ID is in `excludeIDs`" — i.e. the
// ScanManager.active map. Anything else with status='running' that is
// older than `minAge` and not in that set is presumed orphaned.
//
// The `minAge` floor (handler passes 10 minutes) protects against a
// race: between `MarkRunning` and `scanMgr.Register` a scan can briefly
// be running-in-DB but not yet active-in-scanMgr. The age clause keeps
// such fresh rows safe.
//
// progress_msg is set to a distinct string so the operator can tell a
// reap from a real error in the UI.
func (d *DB) ReapOrphanedScans(excludeIDs []string, minAge time.Duration) (int, error) {
	cutoff := time.Now().Add(-minAge)
	if len(excludeIDs) == 0 {
		res, err := d.Exec(`UPDATE scans
		    SET status = 'error',
		        progress_msg = 'Scan reaped — driver goroutine no longer present',
		        finished_at = ?
		  WHERE status = 'running'
		    AND started_at IS NOT NULL
		    AND started_at < ?`, time.Now(), cutoff)
		if err != nil {
			return 0, err
		}
		n, _ := res.RowsAffected()
		return int(n), nil
	}
	// sqlx.In expands a slice into a parameterised IN clause; we wrap the
	// fixed-position params around it.
	q, args, err := sqlx.In(`UPDATE scans
	    SET status = 'error',
	        progress_msg = 'Scan reaped — driver goroutine no longer present',
	        finished_at = ?
	  WHERE status = 'running'
	    AND started_at IS NOT NULL
	    AND started_at < ?
	    AND id NOT IN (?)`, time.Now(), cutoff, excludeIDs)
	if err != nil {
		return 0, err
	}
	q = d.Rebind(q)
	res, err := d.Exec(q, args...)
	if err != nil {
		return 0, err
	}
	n, _ := res.RowsAffected()
	return int(n), nil
}

// LargestScan is the row shape served by ListLargestScans for the
// admin housekeeping panel.
type LargestScan struct {
	ID          string    `db:"id"          json:"id"`
	Module      string    `db:"module"      json:"module"`
	Status      string    `db:"status"      json:"status"`
	ResultBytes int       `db:"result_bytes" json:"result_bytes"`
	CreatedAt   time.Time `db:"created_at"  json:"created_at"`
}

// ListLargestScans returns the top-N scans (across all workspaces)
// ordered by result blob size descending. Used by the Settings page
// "Database housekeeping" panel so operators can identify and delete
// the rows actually inflating the database — the only honest signal
// for "which scan is blowing up my disk".
func (d *DB) ListLargestScans(n int) ([]LargestScan, error) {
	if n <= 0 {
		n = 10
	}
	var rows []LargestScan
	err := d.Select(&rows,
		`SELECT id, module, status, length(result) AS result_bytes, created_at
		   FROM scans
		   ORDER BY length(result) DESC
		   LIMIT ?`, n)
	return rows, err
}

// VacuumNow runs WAL checkpoint(TRUNCATE) + VACUUM. Should NOT be
// called automatically at startup — the operation rewrites the entire
// database file, which can take minutes on a 1+ GB db and is unsafe
// against power-loss. Exposed as a manual settings-page button.
func (d *DB) VacuumNow() error {
	if _, err := d.Exec("PRAGMA wal_checkpoint(TRUNCATE)"); err != nil {
		return fmt.Errorf("wal checkpoint: %w", err)
	}
	if _, err := d.Exec("VACUUM"); err != nil {
		return fmt.Errorf("vacuum: %w", err)
	}
	return nil
}

// MarkOrphanedScans flips any scan that was stuck in `running` / `pending`
// status to `error` with a "server restarted" progress message. Called once
// at startup — before the restart, any goroutine that was driving these
// scans is gone, so they'd otherwise remain in the database forever.
func (d *DB) MarkOrphanedScans() (int, error) {
	res, err := d.Exec(`UPDATE scans
		    SET status = 'error',
		        progress_msg = 'Scan terminated — server restarted before it could finish',
		        finished_at = ?
		  WHERE status IN ('running','pending')`, time.Now())
	if err != nil {
		return 0, err
	}
	n, _ := res.RowsAffected()
	return int(n), nil
}

// SetScanArchived flips a scan's archived flag (1 = archived, 0 = active).
func (d *DB) SetScanArchived(id string, archived bool) error {
	v := 0
	if archived {
		v = 1
	}
	_, err := d.Exec(`UPDATE scans SET archived = ? WHERE id = ?`, v, id)
	return err
}

// --- Settings ---

func (d *DB) GetSetting(key string) string {
	var val string
	d.Get(&val, `SELECT value FROM settings WHERE key = ?`, key)
	return val
}

func (d *DB) SetSetting(key, value string) {
	d.Exec(`INSERT INTO settings (key, value) VALUES (?, ?) ON CONFLICT(key) DO UPDATE SET value = ?`, key, value, value)
}

func (d *DB) GetSettings() models.AppSettings {
	s := models.DefaultSettings()
	if v := d.GetSetting("default_timeout"); v != "" {
		fmt.Sscanf(v, "%d", &s.DefaultTimeout)
	}
	if v := d.GetSetting("max_concurrent"); v != "" {
		fmt.Sscanf(v, "%d", &s.MaxConcurrent)
	}
	if v := d.GetSetting("rate_limit"); v != "" {
		fmt.Sscanf(v, "%d", &s.RateLimit)
	}
	if v := d.GetSetting("web_timeout"); v != "" {
		fmt.Sscanf(v, "%d", &s.WebTimeout)
	}
	if v := d.GetSetting("web_max_concurrent"); v != "" {
		fmt.Sscanf(v, "%d", &s.WebMaxConcurrent)
	}
	if v := d.GetSetting("web_rate_limit"); v != "" {
		fmt.Sscanf(v, "%d", &s.WebRateLimit)
	}
	// web_reachability_preflight defaults ON (from DefaultSettings); an absent
	// key keeps that default, a present key overrides it.
	if v := d.GetSetting("web_reachability_preflight"); v != "" {
		s.WebReachabilityPreflight = v == "1"
	}
	if v := d.GetSetting("web_preflight_timeout"); v != "" {
		fmt.Sscanf(v, "%d", &s.WebPreflightTimeout)
	}
	if v := d.GetSetting("network_timeout"); v != "" {
		fmt.Sscanf(v, "%d", &s.NetworkTimeout)
	}
	if v := d.GetSetting("network_max_concurrent"); v != "" {
		fmt.Sscanf(v, "%d", &s.NetworkMaxConcurrent)
	}
	if v := d.GetSetting("network_rate_limit"); v != "" {
		fmt.Sscanf(v, "%d", &s.NetworkRateLimit)
	}
	if v := d.GetSetting("brute_threads"); v != "" {
		fmt.Sscanf(v, "%d", &s.BruteThreads)
	}
	if v := d.GetSetting("max_cpu_percent"); v != "" {
		fmt.Sscanf(v, "%d", &s.MaxCPUPercent)
	}
	s.ProxyURL = d.GetSetting("proxy_url")
	s.UseProxy = d.GetSetting("use_proxy") == "1"
	s.BurpSuccessOnly = d.GetSetting("burp_success_only") == "1"
	if ua := d.GetSetting("user_agent"); ua != "" {
		s.UserAgent = ua
	}
	if ef := d.GetSetting("default_export_fmt"); ef != "" {
		s.DefaultExportFmt = ef
	}
	s.WPScanAPIKey = d.GetSetting("wpscan_api_key")
	s.HIBPAPIKey = d.GetSetting("hibp_api_key")
	s.GitHubToken = d.GetSetting("github_token")
	s.ShodanAPIKey = d.GetSetting("shodan_api_key")
	s.CensysID = d.GetSetting("censys_id")
	s.CensysSecret = d.GetSetting("censys_secret")
	s.VirusTotalAPIKey = d.GetSetting("virustotal_api_key")
	// Outbound binding (killswitch). Both written atomically on save
	// so reads see a consistent (name, ip) pair.
	s.NetworkInterface = d.GetSetting("network_interface")
	s.NetworkInterfaceIP = d.GetSetting("network_interface_ip")
	// VPN watchdog. vpn_auto_reconnect defaults ON (from DefaultSettings); an
	// absent key keeps that default, a present key overrides it.
	if v := d.GetSetting("vpn_auto_reconnect"); v != "" {
		s.VPNAutoReconnect = v == "1"
	}
	s.VPNConnection = d.GetSetting("vpn_connection")
	s.VPNInterface = d.GetSetting("vpn_interface")
	if v := d.GetSetting("vpn_reconnect_after_sec"); v != "" {
		fmt.Sscanf(v, "%d", &s.VPNReconnectAfterSec)
	}
	// SMTP + 2FA availability.
	s.SMTPHost = d.GetSetting("smtp_host")
	if v := d.GetSetting("smtp_port"); v != "" {
		fmt.Sscanf(v, "%d", &s.SMTPPort)
	}
	s.SMTPUser = d.GetSetting("smtp_user")
	s.SMTPPassword = d.GetSetting("smtp_password")
	s.SMTPFrom = d.GetSetting("smtp_from")
	if v := d.GetSetting("smtp_tls_mode"); v != "" {
		s.SMTPTLSMode = v
	}
	s.TwoFactorAvailable = d.GetSetting("two_factor_available") == "1"
	s.NTPServer = d.GetSetting("ntp_server")
	return s
}

func (d *DB) SaveSettings(s models.AppSettings) {
	d.SetSetting("default_timeout", fmt.Sprintf("%d", s.DefaultTimeout))
	d.SetSetting("max_concurrent", fmt.Sprintf("%d", s.MaxConcurrent))
	d.SetSetting("rate_limit", fmt.Sprintf("%d", s.RateLimit))
	d.SetSetting("web_timeout", fmt.Sprintf("%d", s.WebTimeout))
	d.SetSetting("web_max_concurrent", fmt.Sprintf("%d", s.WebMaxConcurrent))
	d.SetSetting("web_rate_limit", fmt.Sprintf("%d", s.WebRateLimit))
	webPreflight := "0"
	if s.WebReachabilityPreflight {
		webPreflight = "1"
	}
	d.SetSetting("web_reachability_preflight", webPreflight)
	d.SetSetting("web_preflight_timeout", fmt.Sprintf("%d", s.WebPreflightTimeout))
	d.SetSetting("network_timeout", fmt.Sprintf("%d", s.NetworkTimeout))
	d.SetSetting("network_max_concurrent", fmt.Sprintf("%d", s.NetworkMaxConcurrent))
	d.SetSetting("network_rate_limit", fmt.Sprintf("%d", s.NetworkRateLimit))
	d.SetSetting("brute_threads", fmt.Sprintf("%d", s.BruteThreads))
	d.SetSetting("max_cpu_percent", fmt.Sprintf("%d", s.MaxCPUPercent))
	d.SetSetting("proxy_url", s.ProxyURL)
	useProxy := "0"
	if s.UseProxy {
		useProxy = "1"
	}
	d.SetSetting("use_proxy", useProxy)
	burpSuccessOnly := "0"
	if s.BurpSuccessOnly {
		burpSuccessOnly = "1"
	}
	d.SetSetting("burp_success_only", burpSuccessOnly)
	d.SetSetting("user_agent", s.UserAgent)
	d.SetSetting("default_export_fmt", s.DefaultExportFmt)
	d.SetSetting("wpscan_api_key", s.WPScanAPIKey)
	d.SetSetting("hibp_api_key", s.HIBPAPIKey)
	d.SetSetting("github_token", s.GitHubToken)
	d.SetSetting("shodan_api_key", s.ShodanAPIKey)
	d.SetSetting("censys_id", s.CensysID)
	d.SetSetting("censys_secret", s.CensysSecret)
	d.SetSetting("virustotal_api_key", s.VirusTotalAPIKey)
	d.SetSetting("network_interface", s.NetworkInterface)
	d.SetSetting("network_interface_ip", s.NetworkInterfaceIP)
	vpnAuto := "0"
	if s.VPNAutoReconnect {
		vpnAuto = "1"
	}
	d.SetSetting("vpn_auto_reconnect", vpnAuto)
	d.SetSetting("vpn_connection", s.VPNConnection)
	d.SetSetting("vpn_interface", s.VPNInterface)
	d.SetSetting("vpn_reconnect_after_sec", fmt.Sprintf("%d", s.VPNReconnectAfterSec))
	d.SetSetting("smtp_host", s.SMTPHost)
	d.SetSetting("smtp_port", fmt.Sprintf("%d", s.SMTPPort))
	d.SetSetting("smtp_user", s.SMTPUser)
	d.SetSetting("smtp_password", s.SMTPPassword)
	d.SetSetting("smtp_from", s.SMTPFrom)
	d.SetSetting("smtp_tls_mode", s.SMTPTLSMode)
	twoFactorAvail := "0"
	if s.TwoFactorAvailable {
		twoFactorAvail = "1"
	}
	d.SetSetting("two_factor_available", twoFactorAvail)
	d.SetSetting("ntp_server", s.NTPServer)
}

// HasRunningScans checks if any scan is currently running (for settings lock)
func (d *DB) HasRunningScans() bool {
	var count int
	d.Get(&count, `SELECT COUNT(*) FROM scans WHERE status IN ('pending', 'running')`)
	return count > 0
}

// RunningProgress sums progress_done across running/pending scans and returns
// (totalDone, activeCount). The performance monitor differentiates totalDone
// over time to derive live throughput (units/sec) without parsing results.
func (d *DB) RunningProgress() (done, count int) {
	_ = d.QueryRow(
		`SELECT COALESCE(SUM(progress_done),0), COUNT(*) FROM scans WHERE status IN ('running','pending')`,
	).Scan(&done, &count)
	return done, count
}
