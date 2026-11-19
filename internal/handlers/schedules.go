package handlers

import (
	"encoding/json"
	"fmt"
	"net/http"
	"strconv"
	"strings"
	"time"

	"scanner/internal/i18n"
	"scanner/internal/models"
)

// Scheduled scans: a "Schedule" button on every module run form submits the
// filled form with schedule=1; the Run handler creates the scan as usual, and
// scheduleDraftIfRequested (called from queueIfSequential) intercepts it —
// dropping the draft scan and showing a dedicated timing form. That form posts
// to /schedules/create, which persists the schedule; the background runner
// (schedule_runner.go) fires it.

// scheduleDraftIfRequested intercepts a just-created scan when the operator
// clicked "Schedule" instead of "Run". The scan was only a vehicle to run the
// module's own form parser (so scan.Config holds the exact launch JSON); we drop
// it and render the timing form carrying that config. Returns true (handler
// stops) when it handled the request.
func (h *Handler) scheduleDraftIfRequested(w http.ResponseWriter, r *http.Request, scan *models.Scan) bool {
	if scan == nil || scan.ID == "" || r.FormValue("schedule") != "1" {
		return false
	}
	module, config, total := scan.Module, scan.Config, scan.ProgressTotal
	h.db.DeleteScan(scan.ID) // draft was only needed to produce config; no lingering row
	h.renderScheduleForm(w, r, defaultScheduleDraft(module, config, total), "")
	return true
}

// SchedulesPage lists the active workspace's schedules.
func (h *Handler) SchedulesPage(w http.ResponseWriter, r *http.Request) {
	ws := h.activeWorkspace(r)
	if ws == nil {
		http.Error(w, "no active workspace", http.StatusBadRequest)
		return
	}
	list, _ := h.db.ListScheduledScans(ws.ID)
	lang := h.lang(r)
	type row struct {
		models.ScheduledScan
		When string
	}
	rows := make([]row, 0, len(list))
	for _, s := range list {
		rows = append(rows, row{s, scheduleWhenText(s, lang)})
	}
	data := h.baseData(r, i18n.T(lang, "Schedules"), "schedules")
	data["Schedules"] = rows
	data["ServerNow"] = time.Now().Format("2006-01-02 15:04:05")
	h.render(w, "layout", data)
}

// ScheduleEdit re-opens the timing form for an existing schedule.
func (h *Handler) ScheduleEdit(w http.ResponseWriter, r *http.Request) {
	ws := h.activeWorkspace(r)
	s, err := h.db.GetScheduledScan(r.URL.Query().Get("id"))
	if err != nil || s == nil || ws == nil || s.WorkspaceID != ws.ID {
		http.Redirect(w, r, "/schedules", http.StatusSeeOther)
		return
	}
	h.renderScheduleForm(w, r, s, "")
}

// ScheduleCreate persists a new schedule (or updates one when id is present).
func (h *Handler) ScheduleCreate(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Redirect(w, r, "/schedules", http.StatusSeeOther)
		return
	}
	_ = r.ParseForm()
	ws := h.activeWorkspace(r)
	if ws == nil {
		http.Error(w, "no active workspace", http.StatusBadRequest)
		return
	}
	id := strings.TrimSpace(r.FormValue("id"))
	module := strings.TrimSpace(r.FormValue("module"))
	config := r.FormValue("config")
	total, _ := strconv.Atoi(r.FormValue("total_targets"))
	s := &models.ScheduledScan{
		ID:           id,
		WorkspaceID:  ws.ID,
		Label:        strings.TrimSpace(r.FormValue("label")),
		Module:       module,
		Config:       config,
		TotalTargets: total,
		Enabled:      true,
		CreatedBy:    auditUserID(h.currentUser(r)),
	}
	if module == "" || !json.Valid([]byte(config)) {
		h.renderScheduleForm(w, r, s, i18n.T(h.lang(r), "Missing or invalid scan configuration — start from a module's Schedule button."))
		return
	}
	if err := applyScheduleTiming(s, r); err != nil {
		h.renderScheduleForm(w, r, s, err.Error())
		return
	}
	next, err := computeNextRun(*s, time.Now())
	if err != nil {
		h.renderScheduleForm(w, r, s, err.Error())
		return
	}
	s.NextRunAt = next

	action := "schedule.create"
	if id != "" {
		existing, gerr := h.db.GetScheduledScan(id)
		if gerr != nil || existing == nil || existing.WorkspaceID != ws.ID {
			http.Redirect(w, r, "/schedules", http.StatusSeeOther)
			return
		}
		s.CreatedAt = existing.CreatedAt
		if err := h.db.UpdateScheduledScan(s); err != nil {
			h.renderScheduleForm(w, r, s, err.Error())
			return
		}
		action = "schedule.update"
	} else {
		if err := h.db.CreateScheduledScan(s); err != nil {
			h.renderScheduleForm(w, r, s, err.Error())
			return
		}
	}
	me := h.currentUser(r)
	h.db.AddAudit(models.AuditEntry{
		UserID: auditUserID(me), Username: auditUsername(me),
		Category: models.AuditScan, Action: action, Module: s.Module,
		WorkspaceID: ws.ID, IP: clientIP(r),
	})
	http.Redirect(w, r, "/schedules", http.StatusSeeOther)
}

// ScheduleToggle pauses or resumes a schedule. Resuming recomputes next_run.
func (h *Handler) ScheduleToggle(w http.ResponseWriter, r *http.Request) {
	ws := h.activeWorkspace(r)
	s, err := h.db.GetScheduledScan(r.FormValue("id"))
	if err != nil || s == nil || ws == nil || s.WorkspaceID != ws.ID {
		http.Redirect(w, r, "/schedules", http.StatusSeeOther)
		return
	}
	enable := !s.Enabled
	var next *time.Time
	if enable {
		if n, nerr := computeNextRun(*s, time.Now()); nerr == nil {
			next = n
		}
	} else {
		next = s.NextRunAt // keep for display; the enabled flag gates firing
	}
	h.db.SetScheduleEnabled(s.ID, enable, next)
	http.Redirect(w, r, "/schedules", http.StatusSeeOther)
}

// ScheduleRunNow fires a schedule immediately (one-off), without touching its
// next_run. Redirects to the launched scan's results.
func (h *Handler) ScheduleRunNow(w http.ResponseWriter, r *http.Request) {
	ws := h.activeWorkspace(r)
	s, err := h.db.GetScheduledScan(r.FormValue("id"))
	if err != nil || s == nil || ws == nil || s.WorkspaceID != ws.ID {
		http.Redirect(w, r, "/schedules", http.StatusSeeOther)
		return
	}
	scan, cerr := h.db.CreateScan(s.WorkspaceID, s.Module, s.Config, s.TotalTargets)
	if cerr != nil {
		http.Redirect(w, r, "/schedules", http.StatusSeeOther)
		return
	}
	me := h.currentUser(r)
	h.db.AddAudit(models.AuditEntry{
		UserID: auditUserID(me), Username: auditUsername(me),
		Category: models.AuditScan, Action: "scan.scheduled", Module: s.Module,
		WorkspaceID: ws.ID, ScanID: scan.ID, IP: clientIP(r),
	})
	h.dispatchRestart(scan.ID, s.Module, s.Config)
	http.Redirect(w, r, resultsURL(s.Module, scan.ID), http.StatusSeeOther)
}

// ScheduleDelete removes a schedule.
func (h *Handler) ScheduleDelete(w http.ResponseWriter, r *http.Request) {
	ws := h.activeWorkspace(r)
	s, err := h.db.GetScheduledScan(r.FormValue("id"))
	if err == nil && s != nil && ws != nil && s.WorkspaceID == ws.ID {
		h.db.DeleteScheduledScan(s.ID)
	}
	http.Redirect(w, r, "/schedules", http.StatusSeeOther)
}

// --- form plumbing ---

// applyScheduleTiming reads the timing fields off the form into s, validating.
func applyScheduleTiming(s *models.ScheduledScan, r *http.Request) error {
	switch r.FormValue("kind") {
	case models.ScheduleOnce:
		s.Kind = models.ScheduleOnce
		t, err := time.ParseInLocation("2006-01-02T15:04", strings.TrimSpace(r.FormValue("run_at")), time.Local)
		if err != nil {
			return fmt.Errorf("invalid date/time")
		}
		s.RunAt = &t
	case models.ScheduleRecurring:
		s.Kind = models.ScheduleRecurring
		s.RecurKind = r.FormValue("recur_kind")
		switch s.RecurKind {
		case models.RecurInterval:
			n, _ := strconv.Atoi(r.FormValue("interval_n"))
			secs := nUnitToSeconds(n, r.FormValue("interval_unit"))
			if secs <= 0 {
				return fmt.Errorf("interval must be greater than zero")
			}
			s.IntervalSeconds = secs
		case models.RecurDaily:
			s.AtTime = strings.TrimSpace(r.FormValue("at_time"))
			if _, _, err := parseHHMM(s.AtTime); err != nil {
				return err
			}
		case models.RecurWeekly:
			s.AtTime = strings.TrimSpace(r.FormValue("at_time"))
			if _, _, err := parseHHMM(s.AtTime); err != nil {
				return err
			}
			s.Weekdays = strings.Join(r.Form["weekday"], ",")
			if _, err := parseWeekdays(s.Weekdays); err != nil {
				return err
			}
			if s.Weekdays == "" {
				return fmt.Errorf("select at least one weekday")
			}
		case models.RecurCron:
			s.Cron = strings.TrimSpace(r.FormValue("cron"))
			if _, err := parseCron(s.Cron); err != nil {
				return err
			}
		default:
			return fmt.Errorf("choose a recurrence type")
		}
	default:
		return fmt.Errorf("choose when to run")
	}
	return nil
}

func defaultScheduleDraft(module, config string, total int) *models.ScheduledScan {
	t := time.Now().Add(time.Hour)
	return &models.ScheduledScan{
		Module: module, Config: config, TotalTargets: total, Enabled: true,
		Kind: models.ScheduleOnce, RunAt: &t,
		RecurKind: models.RecurInterval, IntervalSeconds: 6 * 3600,
		AtTime: "09:00", Cron: "0 9 * * *",
	}
}

// renderScheduleForm shows the dedicated timing form, pre-filled from s.
func (h *Handler) renderScheduleForm(w http.ResponseWriter, r *http.Request, s *models.ScheduledScan, formError string) {
	lang := h.lang(r)
	_, targets := configInputs(s.Config)
	summary := ""
	if n := len(targets); n > 0 {
		sample := targets
		if len(sample) > 3 {
			sample = sample[:3]
		}
		summary = strings.Join(sample, ", ")
		if n > 3 {
			summary += fmt.Sprintf(" (+%d)", n-3)
		}
	}
	now := time.Now()
	runAt := now.Add(time.Hour).Format("2006-01-02T15:04")
	if s.RunAt != nil {
		runAt = s.RunAt.Format("2006-01-02T15:04")
	}
	intervalN, intervalUnit := 6, "hours"
	if s.IntervalSeconds > 0 {
		intervalN, intervalUnit = secondsToNUnit(s.IntervalSeconds)
	}
	recurKind := s.RecurKind
	if recurKind == "" {
		recurKind = models.RecurInterval
	}
	atTime := s.AtTime
	if atTime == "" {
		atTime = "09:00"
	}
	cron := s.Cron
	if cron == "" {
		cron = "0 9 * * *"
	}
	kind := s.Kind
	if kind == "" {
		kind = models.ScheduleOnce
	}
	data := h.baseData(r, i18n.T(lang, "Schedule scan"), "schedule_new")
	data["Sched"] = map[string]interface{}{
		"ID": s.ID, "Module": s.Module, "ModuleDisplay": i18n.T(lang, models.ModuleDisplayName(s.Module)),
		"Config": s.Config, "TotalTargets": s.TotalTargets,
		"TargetSummary": summary, "TargetCount": len(targets),
		"Label": s.Label, "Kind": kind, "RunAt": runAt,
		"RecurKind": recurKind, "IntervalN": intervalN, "IntervalUnit": intervalUnit,
		"AtTime": atTime, "Weekdays": weekdaysSet(s.Weekdays), "Cron": cron,
		"FormError": formError,
		// Server clock reference: schedules fire on the SERVER's local time, which
		// may differ from the browser's — show it, and floor the one-time picker at
		// "now" so a past date can't be chosen.
		"ServerNow":      now.Format("2006-01-02 15:04:05"),
		"ServerNowInput": now.Format("2006-01-02T15:04"),
	}
	h.render(w, "layout", data)
}

// --- display + unit helpers ---

func nUnitToSeconds(n int, unit string) int {
	switch unit {
	case "minutes":
		return n * 60
	case "hours":
		return n * 3600
	case "days":
		return n * 86400
	case "weeks":
		return n * 604800
	}
	return 0
}

func secondsToNUnit(secs int) (int, string) {
	switch {
	case secs%604800 == 0:
		return secs / 604800, "weeks"
	case secs%86400 == 0:
		return secs / 86400, "days"
	case secs%3600 == 0:
		return secs / 3600, "hours"
	default:
		return secs / 60, "minutes"
	}
}

func weekdaysSet(csv string) map[int]bool {
	out := map[int]bool{}
	for _, tok := range strings.Split(csv, ",") {
		if n, err := strconv.Atoi(strings.TrimSpace(tok)); err == nil {
			out[n] = true
		}
	}
	return out
}

func intervalHuman(secs int, lang string) string {
	switch {
	case secs%604800 == 0:
		return fmt.Sprintf("%d %s", secs/604800, i18n.T(lang, "week(s)"))
	case secs%86400 == 0:
		return fmt.Sprintf("%d %s", secs/86400, i18n.T(lang, "day(s)"))
	case secs%3600 == 0:
		return fmt.Sprintf("%d %s", secs/3600, i18n.T(lang, "hour(s)"))
	default:
		return fmt.Sprintf("%d %s", secs/60, i18n.T(lang, "minute(s)"))
	}
}

func weekdaysHuman(csv, lang string) string {
	names := []string{"Sun", "Mon", "Tue", "Wed", "Thu", "Fri", "Sat"}
	var out []string
	for _, tok := range strings.Split(csv, ",") {
		if n, err := strconv.Atoi(strings.TrimSpace(tok)); err == nil && n >= 0 && n <= 6 {
			out = append(out, i18n.T(lang, names[n]))
		}
	}
	return strings.Join(out, ", ")
}

// scheduleWhenText renders a schedule's timing as one localized line.
func scheduleWhenText(s models.ScheduledScan, lang string) string {
	if s.Kind == models.ScheduleOnce {
		if s.RunAt != nil {
			return i18n.T(lang, "Once: %s", s.RunAt.Format("2006-01-02 15:04"))
		}
		return i18n.T(lang, "Once")
	}
	switch s.RecurKind {
	case models.RecurInterval:
		return i18n.T(lang, "Every %s", intervalHuman(s.IntervalSeconds, lang))
	case models.RecurDaily:
		return i18n.T(lang, "Daily at %s", s.AtTime)
	case models.RecurWeekly:
		return i18n.T(lang, "Weekly on %s at %s", weekdaysHuman(s.Weekdays, lang), s.AtTime)
	case models.RecurCron:
		return i18n.T(lang, "Cron: %s", s.Cron)
	}
	return i18n.T(lang, "Recurring")
}
