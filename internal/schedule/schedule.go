// Package schedule computes when checks run and which windows they read
// (SPEC 7.1). It is pure time arithmetic; the run loop lives in main.
//
//   - Intraday watch: runs `offset` after each interval boundary and reads
//     the interval that just ended, so analytics ingestion lag (~5–10 min)
//     is absorbed before anything is judged.
//   - Daily report: runs at HH:MM local time (+ offset) and reads the
//     24 hours ending at HH:MM.
package schedule

import (
	"fmt"
	"time"
)

// Window is a half-open time range [From, To).
type Window struct{ From, To time.Time }

// Shift returns the window moved by d (e.g. -24h for the baseline).
func (w Window) Shift(d time.Duration) Window { return Window{w.From.Add(d), w.To.Add(d)} }

func (w Window) String() string {
	if w.To.Sub(w.From) <= 24*time.Hour && w.From.UTC().YearDay() == w.To.Add(-time.Nanosecond).UTC().YearDay() {
		return fmt.Sprintf("%s–%s", w.From.UTC().Format("2006-01-02 15:04"), w.To.UTC().Format("15:04 UTC"))
	}
	return fmt.Sprintf("%s → %s", w.From.UTC().Format("2006-01-02 15:04"), w.To.UTC().Format("2006-01-02 15:04 UTC"))
}

// NextIntraday returns the first run time strictly after now.
// Boundaries are multiples of interval on the UTC clock.
func NextIntraday(now time.Time, interval, offset time.Duration) time.Time {
	return now.Add(-offset).Truncate(interval).Add(interval).Add(offset)
}

// IntradayWindow returns the newest full interval that has had at least
// `offset` to settle at time now.
func IntradayWindow(now time.Time, interval, offset time.Duration) Window {
	end := now.Add(-offset).Truncate(interval)
	return Window{end.Add(-interval), end}
}

// ParseHHMM parses "HH:MM".
func ParseHHMM(s string) (h, m int, err error) {
	if _, err = fmt.Sscanf(s, "%d:%d", &h, &m); err != nil || h < 0 || h > 23 || m < 0 || m > 59 {
		return 0, 0, fmt.Errorf("invalid HH:MM %q", s)
	}
	return h, m, nil
}

// NextDaily returns the next daily report run time strictly after now:
// HH:MM in loc, plus offset. DST transitions are handled by time.Date.
func NextDaily(now time.Time, hhmm string, loc *time.Location, offset time.Duration) (time.Time, error) {
	h, m, err := ParseHHMM(hhmm)
	if err != nil {
		return time.Time{}, err
	}
	l := now.In(loc)
	for d := 0; d <= 2; d++ {
		t := time.Date(l.Year(), l.Month(), l.Day()+d, h, m, 0, 0, loc).Add(offset)
		if t.After(now) {
			return t, nil
		}
	}
	return time.Time{}, fmt.Errorf("no daily run time found after %s", now)
}

// DailyWindow returns the 24 hours ending at the most recent HH:MM (loc)
// that is at least `offset` before now.
func DailyWindow(now time.Time, hhmm string, loc *time.Location, offset time.Duration) (Window, error) {
	h, m, err := ParseHHMM(hhmm)
	if err != nil {
		return Window{}, err
	}
	ref := now.Add(-offset).In(loc)
	end := time.Date(ref.Year(), ref.Month(), ref.Day(), h, m, 0, 0, loc)
	if end.After(now.Add(-offset)) {
		end = time.Date(ref.Year(), ref.Month(), ref.Day()-1, h, m, 0, 0, loc)
	}
	return Window{end.Add(-24 * time.Hour), end}, nil
}
