package handlers

// Regression test for the schedule timing parser. The /schedules form renders
// BOTH the Daily and the Weekly recurrence blocks in the DOM (JS only show/hides
// them), and a hidden block's inputs still submit. When both time inputs shared
// name="at_time", r.FormValue("at_time") returned the FIRST (the Daily block's),
// so every WEEKLY schedule's time was silently pinned to the Daily block's stale
// default (09:00) — the operator's "çalışma saati hep 9 oluyor" bug. The weekly
// input is now name="at_time_weekly" and read per recurrence kind.

import (
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"scanner/internal/models"
)

func applyTiming(t *testing.T, form url.Values) *models.ScheduledScan {
	t.Helper()
	req := httptest.NewRequest("POST", "/schedules/save", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	var s models.ScheduledScan
	if err := applyScheduleTiming(&s, req); err != nil {
		t.Fatalf("applyScheduleTiming: %v", err)
	}
	return &s
}

func TestApplyScheduleTimingWeeklyUsesWeeklyTime(t *testing.T) {
	// Weekly form: the hidden Daily block still submits at_time=09:00 (its
	// default); the user's real time comes from at_time_weekly.
	form := url.Values{}
	form.Set("kind", models.ScheduleRecurring)
	form.Set("recur_kind", models.RecurWeekly)
	form.Set("at_time", "09:00")        // stale Daily-block input (must NOT win)
	form.Set("at_time_weekly", "14:30") // the value the operator actually set
	form.Set("weekday", "1")
	s := applyTiming(t, form)
	if s.AtTime != "14:30" {
		t.Errorf("weekly AtTime = %q, want 14:30 (regression: Daily block's 09:00 won)", s.AtTime)
	}
	if s.Weekdays != "1" {
		t.Errorf("weekly Weekdays = %q, want 1", s.Weekdays)
	}
}

func TestApplyScheduleTimingDailyUnaffected(t *testing.T) {
	// Daily still reads its own block's at_time.
	form := url.Values{}
	form.Set("kind", models.ScheduleRecurring)
	form.Set("recur_kind", models.RecurDaily)
	form.Set("at_time", "07:15")
	form.Set("at_time_weekly", "09:00") // hidden Weekly block — must be ignored
	s := applyTiming(t, form)
	if s.AtTime != "07:15" {
		t.Errorf("daily AtTime = %q, want 07:15", s.AtTime)
	}
}
