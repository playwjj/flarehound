package console

// The trend strip (overview): zone requests for the last six clock
// hours against the same hours yesterday, plus a "now" point. The
// 48-hour chart further down the page shows the two days back to
// back; the strip overlays them, which is what "is it climbing right
// now" needs.
//
// The "now" point is the live view's rolling 60 minutes, not the
// clock hour in progress: a partial hour's raw count sits far below
// the full hours beside it, so the line would always end in a cliff
// that reads as a fall — the opposite of the momentum the strip is
// for. The rolling window is a full hour's worth of traffic, already
// measured and cached by the live view (no query of its own), and its
// yesterday counterpart is the two clock hours it spans, weighted by
// overlap exactly as the live baseline is.

import (
	"html/template"
	"math"
	"time"

	"github.com/playwjj/flarehound/internal/config"
)

const trendHours = 6

// buildTrend renders the strip, or reports false when the archive
// holds none of today's hours yet. live may be nil or failed: the
// strip then ends at the newest closed hour.
func buildTrend(a Archive, zone config.Zone, now time.Time, loc *time.Location, live *LiveView) (template.HTML, bool) {
	hourStart := now.Truncate(time.Hour)
	first := hourStart.Add(-trendHours * time.Hour)
	pts, err := a.HourSeries(zone.ZoneID, first.Add(-24*time.Hour), hourStart)
	if err != nil {
		return "", false
	}
	byFrom := make(map[int64]int64, len(pts))
	for _, p := range pts {
		byFrom[p.From.Unix()] = p.Total
	}
	at := func(t time.Time) float64 {
		if v, ok := byFrom[t.Unix()]; ok {
			return float64(v)
		}
		return math.NaN()
	}
	today := make([]float64, 0, trendHours+1)
	yday := make([]float64, 0, trendHours+1)
	labels := make([]string, 0, trendHours+1)
	anyToday := false
	for i := 0; i < trendHours; i++ {
		h := first.Add(time.Duration(i) * time.Hour)
		v := at(h)
		anyToday = anyToday || !math.IsNaN(v)
		today = append(today, v)
		yday = append(yday, at(h.Add(-24*time.Hour)))
		labels = append(labels, h.In(loc).Format("15"))
	}
	if !anyToday {
		return "", false
	}
	if live != nil && live.Err == "" && live.Total > 0 {
		hA := live.From.Truncate(time.Hour)
		w := float64(hA.Add(time.Hour).Sub(live.From)) / float64(time.Hour) // share in hour A
		y := at(hA.Add(-24 * time.Hour))
		if w < 0.999 {
			y = w*y + (1-w)*at(hA.Add(-23*time.Hour)) // NaN if either is missing
		}
		today = append(today, float64(live.Total))
		yday = append(yday, y)
		labels = append(labels, live.To.In(loc).Format("15:04"))
	}
	html := svgChart{W: 720, H: 130, Lines: []svgSeries{
		{Class: "l-yday", Values: yday},
		{Class: "l-total", Values: today},
	}, XLabels: labels}.render()
	if html == "" {
		return "", false
	}
	return html, true
}
