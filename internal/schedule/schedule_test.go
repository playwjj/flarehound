package schedule

import (
	"testing"
	"time"
)

func TestIntraday(t *testing.T) {
	h, off := time.Hour, 7*time.Minute
	at := func(hh, mm int) time.Time { return time.Date(2026, 11, 17, hh, mm, 0, 0, time.UTC) }

	if got := NextIntraday(at(10, 2), h, off); !got.Equal(at(10, 7)) {
		t.Errorf("10:02 -> %s", got)
	}
	if got := NextIntraday(at(10, 7), h, off); !got.Equal(at(11, 7)) {
		t.Errorf("10:07 -> %s", got)
	}
	// At 10:02 the 09:00–10:00 window has not settled yet.
	if w := IntradayWindow(at(10, 2), h, off); !w.From.Equal(at(8, 0)) || !w.To.Equal(at(9, 0)) {
		t.Errorf("window at 10:02 = %s", w)
	}
	if w := IntradayWindow(at(10, 7), h, off); !w.From.Equal(at(9, 0)) || !w.To.Equal(at(10, 0)) {
		t.Errorf("window at 10:07 = %s", w)
	}
}

func TestDaily(t *testing.T) {
	sh, _ := time.LoadLocation("Asia/Shanghai")
	off := 7 * time.Minute
	now := time.Date(2026, 11, 17, 7, 0, 0, 0, sh)
	next, err := NextDaily(now, "08:00", sh, off)
	if err != nil || !next.Equal(time.Date(2026, 11, 17, 8, 7, 0, 0, sh)) {
		t.Fatalf("next = %s, %v", next, err)
	}
	next, _ = NextDaily(next, "08:00", sh, off)
	if !next.Equal(time.Date(2026, 11, 18, 8, 7, 0, 0, sh)) {
		t.Fatalf("next after run = %s", next)
	}

	w, err := DailyWindow(time.Date(2026, 11, 17, 8, 7, 0, 0, sh), "08:00", sh, off)
	if err != nil {
		t.Fatal(err)
	}
	if !w.To.Equal(time.Date(2026, 11, 17, 8, 0, 0, 0, sh)) || w.To.Sub(w.From) != 24*time.Hour {
		t.Fatalf("window = %s", w)
	}
	// Run manually before today's report time: the window ends yesterday.
	w, _ = DailyWindow(time.Date(2026, 11, 17, 7, 0, 0, 0, sh), "08:00", sh, off)
	if !w.To.Equal(time.Date(2026, 11, 16, 8, 0, 0, 0, sh)) {
		t.Fatalf("early window = %s", w)
	}
}

func TestDailyDST(t *testing.T) {
	ny, _ := time.LoadLocation("America/New_York")
	// 2026-11-01 is the US fall-back day.
	now := time.Date(2026, 10, 31, 12, 0, 0, 0, ny)
	next, _ := NextDaily(now, "08:00", ny, 0)
	if next.In(ny).Hour() != 8 || next.In(ny).Day() != 1 {
		t.Fatalf("DST next = %s", next.In(ny))
	}
}

func TestParseHHMM(t *testing.T) {
	for _, bad := range []string{"24:00", "8", "ab:cd", "12:60"} {
		if _, _, err := ParseHHMM(bad); err == nil {
			t.Errorf("%q accepted", bad)
		}
	}
}
