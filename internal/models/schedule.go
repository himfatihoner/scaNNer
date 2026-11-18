package models

import "time"

// Schedule kinds + recurrence kinds. Plain TEXT columns, no CHECK constraint
// (same convention as ScanStatus) so adding a kind later needs no migration.
const (
	ScheduleOnce      = "once"
	ScheduleRecurring = "recurring"

	RecurInterval = "interval" // every IntervalSeconds
	RecurDaily    = "daily"    // every day at AtTime
	RecurWeekly   = "weekly"   // on Weekdays at AtTime
	RecurCron     = "cron"     // standard 5-field cron expression
)

// ScheduledScan is one persisted scan schedule: a saved (module, config,
// workspace) launch plus WHEN to run it — once at a time, or recurring on the
// server clock. The background runner (StartScheduledScans) fires each due row
// by replaying Config through the same CreateScan → dispatchRestart seam the
// Restart button uses. Real-column table (mirrors models.Scan), not the
// settings KV store. Nullable timestamps are *time.Time.
type ScheduledScan struct {
	ID           string `db:"id"            json:"id"`
	WorkspaceID  string `db:"workspace_id"  json:"workspace_id"`
	Label        string `db:"label"         json:"label"`
	Module       string `db:"module"        json:"module"`
	Config       string `db:"config"        json:"config"`        // the launch-form JSON (replay source)
	TotalTargets int    `db:"total_targets" json:"total_targets"` // progress-bar denominator for the fired scan

	Kind string `db:"kind" json:"kind"` // once | recurring

	// once: the single fire time.
	RunAt *time.Time `db:"run_at" json:"run_at"`

	// recurring: how it repeats.
	RecurKind       string `db:"recur_kind"       json:"recur_kind"`       // interval | daily | weekly | cron
	IntervalSeconds int    `db:"interval_seconds" json:"interval_seconds"` // RecurInterval
	AtTime          string `db:"at_time"          json:"at_time"`          // "HH:MM" for daily/weekly
	Weekdays        string `db:"weekdays"         json:"weekdays"`         // CSV of 0..6 (0=Sunday) for weekly
	Cron            string `db:"cron"             json:"cron"`             // 5-field cron for RecurCron

	Enabled    bool       `db:"enabled"      json:"enabled"` // false = paused
	NextRunAt  *time.Time `db:"next_run_at"  json:"next_run_at"`
	LastRunAt  *time.Time `db:"last_run_at"  json:"last_run_at"`
	LastScanID string     `db:"last_scan_id" json:"last_scan_id"`
	LastStatus string     `db:"last_status"  json:"last_status"` // launched | skipped_overlap | skipped_pressure
	CreatedAt  time.Time  `db:"created_at"   json:"created_at"`
	CreatedBy  string     `db:"created_by"   json:"created_by"`
}

// Paused reports whether the schedule is currently disabled (manually paused,
// or a one-time schedule that has already fired).
func (s ScheduledScan) Paused() bool { return !s.Enabled }

// IsRecurring reports whether this schedule repeats.
func (s ScheduledScan) IsRecurring() bool { return s.Kind == ScheduleRecurring }
