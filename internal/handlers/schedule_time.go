package handlers

import (
	"fmt"
	"strconv"
	"strings"
	"time"

	"scanner/internal/models"
)

// Scheduled-scan time math. No third-party cron dependency — a small, fully
// unit-tested 5-field cron parser + a next-run computer, all on the SERVER's
// local clock (callers pass time.Now()). computeNextRun returns the next fire
// time strictly after `from` (except a one-time schedule, which returns its
// fixed RunAt); a nil result means "no further runs".

// computeNextRun returns the next fire time for a schedule relative to `from`.
// Returns (nil, nil) when there is no next run (e.g. a one-time schedule with no
// RunAt). Returns an error for an invalid/unsatisfiable spec.
func computeNextRun(s models.ScheduledScan, from time.Time) (*time.Time, error) {
	if s.Kind == models.ScheduleOnce {
		if s.RunAt == nil {
			return nil, fmt.Errorf("one-time schedule needs a run time")
		}
		t := *s.RunAt
		return &t, nil
	}
	switch s.RecurKind {
	case models.RecurInterval:
		if s.IntervalSeconds <= 0 {
			return nil, fmt.Errorf("interval must be greater than zero")
		}
		t := from.Add(time.Duration(s.IntervalSeconds) * time.Second)
		return &t, nil
	case models.RecurDaily:
		return nextClock(from, s.AtTime, allWeekdays())
	case models.RecurWeekly:
		days, err := parseWeekdays(s.Weekdays)
		if err != nil {
			return nil, err
		}
		if len(days) == 0 {
			return nil, fmt.Errorf("weekly schedule needs at least one weekday")
		}
		return nextClock(from, s.AtTime, days)
	case models.RecurCron:
		return cronNext(s.Cron, from)
	}
	return nil, fmt.Errorf("unknown recurrence kind %q", s.RecurKind)
}

func allWeekdays() map[time.Weekday]bool {
	m := make(map[time.Weekday]bool, 7)
	for d := time.Sunday; d <= time.Saturday; d++ {
		m[d] = true
	}
	return m
}

// parseWeekdays reads a CSV of 0..6 (0=Sunday; 7 also accepted as Sunday).
func parseWeekdays(csv string) (map[time.Weekday]bool, error) {
	out := map[time.Weekday]bool{}
	for _, tok := range strings.Split(csv, ",") {
		tok = strings.TrimSpace(tok)
		if tok == "" {
			continue
		}
		n, err := strconv.Atoi(tok)
		if err != nil || n < 0 || n > 7 {
			return nil, fmt.Errorf("invalid weekday %q", tok)
		}
		if n == 7 {
			n = 0
		}
		out[time.Weekday(n)] = true
	}
	return out, nil
}

// parseHHMM parses "HH:MM" (24h) into hour, minute.
func parseHHMM(s string) (int, int, error) {
	s = strings.TrimSpace(s)
	parts := strings.Split(s, ":")
	if len(parts) != 2 {
		return 0, 0, fmt.Errorf("time must be HH:MM, got %q", s)
	}
	h, err1 := strconv.Atoi(strings.TrimSpace(parts[0]))
	m, err2 := strconv.Atoi(strings.TrimSpace(parts[1]))
	if err1 != nil || err2 != nil || h < 0 || h > 23 || m < 0 || m > 59 {
		return 0, 0, fmt.Errorf("invalid time %q", s)
	}
	return h, m, nil
}

// nextClock returns the next time strictly after `from` that lands on HH:MM on
// one of the allowed weekdays. Searches up to 8 days (covers daily + weekly).
func nextClock(from time.Time, hhmm string, days map[time.Weekday]bool) (*time.Time, error) {
	h, m, err := parseHHMM(hhmm)
	if err != nil {
		return nil, err
	}
	loc := from.Location()
	day := time.Date(from.Year(), from.Month(), from.Day(), 0, 0, 0, 0, loc)
	for i := 0; i < 8; i++ {
		cand := time.Date(day.Year(), day.Month(), day.Day(), h, m, 0, 0, loc)
		if cand.After(from) && days[cand.Weekday()] {
			return &cand, nil
		}
		day = day.AddDate(0, 0, 1)
	}
	return nil, fmt.Errorf("no matching time within a week")
}

// --- 5-field cron (minute hour day-of-month month day-of-week) ---

type cronExpr struct {
	min, hour, dom, mon, dow map[int]bool
	domStar, dowStar         bool // whether the field was "*" (drives dom/dow OR semantics)
}

// parseCron parses a standard 5-field cron expression. Supports *, lists (a,b),
// ranges (a-b), and steps (*/n, a-b/n, a/n). Day-of-week is 0..6 with 0=Sunday
// (7 also accepted as Sunday).
func parseCron(expr string) (*cronExpr, error) {
	fields := strings.Fields(strings.TrimSpace(expr))
	if len(fields) != 5 {
		return nil, fmt.Errorf("cron must have 5 fields (min hour dom mon dow), got %d", len(fields))
	}
	c := &cronExpr{domStar: fields[2] == "*", dowStar: fields[4] == "*"}
	var err error
	if c.min, err = parseCronField(fields[0], 0, 59); err != nil {
		return nil, fmt.Errorf("minute: %w", err)
	}
	if c.hour, err = parseCronField(fields[1], 0, 23); err != nil {
		return nil, fmt.Errorf("hour: %w", err)
	}
	if c.dom, err = parseCronField(fields[2], 1, 31); err != nil {
		return nil, fmt.Errorf("day-of-month: %w", err)
	}
	if c.mon, err = parseCronField(fields[3], 1, 12); err != nil {
		return nil, fmt.Errorf("month: %w", err)
	}
	// day-of-week: normalize 7 → 0 before storing.
	raw, err := parseCronField(fields[4], 0, 7)
	if err != nil {
		return nil, fmt.Errorf("day-of-week: %w", err)
	}
	c.dow = map[int]bool{}
	for v := range raw {
		if v == 7 {
			v = 0
		}
		c.dow[v] = true
	}
	return c, nil
}

func parseCronField(spec string, lo, hi int) (map[int]bool, error) {
	out := map[int]bool{}
	for _, part := range strings.Split(spec, ",") {
		part = strings.TrimSpace(part)
		if part == "" {
			return nil, fmt.Errorf("empty term in %q", spec)
		}
		step := 1
		rng := part
		if slash := strings.Index(part, "/"); slash >= 0 {
			s, err := strconv.Atoi(part[slash+1:])
			if err != nil || s <= 0 {
				return nil, fmt.Errorf("invalid step in %q", part)
			}
			step = s
			rng = part[:slash]
		}
		start, end := lo, hi
		if rng == "*" {
			// full range
		} else if dash := strings.Index(rng, "-"); dash >= 0 {
			a, err1 := strconv.Atoi(rng[:dash])
			b, err2 := strconv.Atoi(rng[dash+1:])
			if err1 != nil || err2 != nil {
				return nil, fmt.Errorf("invalid range %q", rng)
			}
			start, end = a, b
		} else {
			v, err := strconv.Atoi(rng)
			if err != nil {
				return nil, fmt.Errorf("invalid value %q", rng)
			}
			if strings.Contains(part, "/") {
				start, end = v, hi // "a/step" = from a to max, stepped
			} else {
				start, end = v, v
			}
		}
		if start < lo || end > hi || start > end {
			return nil, fmt.Errorf("value out of range [%d-%d] in %q", lo, hi, part)
		}
		for v := start; v <= end; v += step {
			out[v] = true
		}
	}
	if len(out) == 0 {
		return nil, fmt.Errorf("no values in %q", spec)
	}
	return out, nil
}

// matches reports whether time t satisfies the cron expression. Standard Vixie
// day semantics: when BOTH day-of-month and day-of-week are restricted (neither
// "*"), the day matches if EITHER matches; otherwise both must match.
func (c *cronExpr) matches(t time.Time) bool {
	if !c.min[t.Minute()] || !c.hour[t.Hour()] || !c.mon[int(t.Month())] {
		return false
	}
	domOK := c.dom[t.Day()]
	dowOK := c.dow[int(t.Weekday())]
	if !c.domStar && !c.dowStar {
		return domOK || dowOK
	}
	return domOK && dowOK
}

// cronNext returns the next minute strictly after `from` that matches the
// expression, searching up to ~366 days. Errors on an unparseable or
// unsatisfiable expression.
func cronNext(expr string, from time.Time) (*time.Time, error) {
	c, err := parseCron(expr)
	if err != nil {
		return nil, err
	}
	// Start at the next whole minute after `from`.
	t := from.Truncate(time.Minute).Add(time.Minute)
	limit := t.AddDate(1, 0, 1) // ~366 days guard
	for t.Before(limit) {
		if c.matches(t) {
			tt := t
			return &tt, nil
		}
		t = t.Add(time.Minute)
	}
	return nil, fmt.Errorf("cron expression never matches within a year")
}
