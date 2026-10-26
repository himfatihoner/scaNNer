package database

import (
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"time"

	"github.com/google/uuid"

	"scanner/internal/models"
)

// NetworkEventRetention bounds the network_events table: rows older than this
// are pruned on every AddNetworkEvent. Network events are low-frequency, so
// prune-on-write keeps the table bounded with no extra wiring (mirrors the
// SetRescanResult pattern). This is telemetry, NOT the immutable audit trail.
const NetworkEventRetention = 90 * 24 * time.Hour

// NetEventBackfillID derives a stable, deterministic id from a source key so
// backfilling the same historical event across restarts is idempotent (the
// INSERT ... ON CONFLICT(id) DO NOTHING is a no-op the second time).
func NetEventBackfillID(key string) string {
	sum := sha256.Sum256([]byte(key))
	return "bf-" + hex.EncodeToString(sum[:12])
}

// insertNetworkEvent writes one row, filling the id/ts/category/severity
// defaults. ON CONFLICT(id) DO NOTHING makes deterministic-id backfill rows
// idempotent; live events use a uuid and never conflict. No prune here so a
// bulk backfill doesn't run the DELETE once per row.
func (d *DB) insertNetworkEvent(e models.NetworkEvent) {
	if e.ID == "" {
		e.ID = uuid.New().String()
	}
	if e.TS.IsZero() {
		e.TS = time.Now()
	}
	if e.Category == "" {
		e.Category = models.NetworkEventCategory(e.EventType)
	}
	if e.Severity == "" {
		e.Severity = models.NetSevInfo
	}
	d.Exec(`INSERT INTO network_events
		(id, ts, event_type, category, severity, interface, interface_ip, killswitch_scope, vpn_connection, reachable, dns_ok, scans_affected, detail)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
		ON CONFLICT(id) DO NOTHING`,
		e.ID, e.TS, e.EventType, e.Category, e.Severity, e.Interface, e.InterfaceIP,
		e.KillswitchScope, e.VPNConnection, e.Reachable, e.DNSOK, e.ScansAffected, e.Detail)
}

// AddNetworkEvent appends a network event and prunes rows past the retention
// window. This is the live-event write path (connectivity monitor, killswitch
// monitor callback, leak detector, Settings arm/disarm).
func (d *DB) AddNetworkEvent(e models.NetworkEvent) {
	d.insertNetworkEvent(e)
	d.Exec(`DELETE FROM network_events WHERE ts < ?`, time.Now().Add(-NetworkEventRetention))
}

// NetworkEventFilter narrows a ListNetworkEvents query. Zero-value fields are
// ignored, mirroring AuditFilter.
type NetworkEventFilter struct {
	Category      string
	Severity      string
	EventType     string
	ScanAffecting bool // only events that paused/cancelled/resumed ≥1 scan
	Since         *time.Time
	Limit         int
}

// ListNetworkEvents returns network events (newest first) matching the filter.
func (d *DB) ListNetworkEvents(f NetworkEventFilter) ([]models.NetworkEvent, error) {
	q := `SELECT * FROM network_events WHERE 1=1`
	var args []interface{}
	if f.Category != "" {
		q += ` AND category = ?`
		args = append(args, f.Category)
	}
	if f.Severity != "" {
		q += ` AND severity = ?`
		args = append(args, f.Severity)
	}
	if f.EventType != "" {
		q += ` AND event_type = ?`
		args = append(args, f.EventType)
	}
	if f.ScanAffecting {
		q += ` AND scans_affected > 0`
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

	var es []models.NetworkEvent
	if err := d.Select(&es, q, args...); err != nil && err != sql.ErrNoRows {
		return nil, err
	}
	return es, nil
}

// ListScansForNetBackfill returns finished scans whose stored status + reason
// (progress_msg) corresponds to a past network event, across every workspace.
// The Network History log is seeded from these on first run so the screen is
// not empty before any live event has occurred. Lossy by nature: an event that
// killed zero scans leaves no scan row (the leakwatch.log pass covers some of
// those, and live capture covers the rest going forward).
func (d *DB) ListScansForNetBackfill() ([]models.Scan, error) {
	var ss []models.Scan
	err := d.Select(&ss, `SELECT * FROM scans
		WHERE status IN ('error','paused')
		  AND (progress_msg LIKE 'killswitch:%'
			OR progress_msg LIKE 'Paused — internet%'
			OR progress_msg LIKE 'Paused — VPN%'
			OR progress_msg LIKE 'DNS leak detected%')
		ORDER BY COALESCE(finished_at, started_at, created_at) DESC
		LIMIT 5000`)
	if err != nil && err != sql.ErrNoRows {
		return nil, err
	}
	return ss, nil
}
