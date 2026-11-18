package console

// The trend strip (overview): zone requests for the last six clock
// hours against the same hours yesterday, plus the hour in progress.
// The 48-hour chart further down the page shows the two days back to
// back; the strip overlays them, which is what "is it climbing right
// now" needs. The partial hour is one live Count query — the raw
// count so far (it can only grow), drawn as the last point of
// today's line and labelled as such.

import (
	"context"
	"html/template"
	"math"
	"time"

	"github.com/playwjj/flarehound/internal/cfapi"
	"github.com/playwjj/flarehound/internal/config"
)

const trendHours = 6

// buildTrend renders the strip, or reports false when the archive
// holds none of today's hours yet.
func buildTrend(ctx context.Context, a Archive, an Analytics, zone config.Zone, now time.Time, loc *time.Location) (template.HTML, bool) {
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
	var today, yday []float64
	var labels []string
	anyToday := false
	for i := 0; i < trendHours; i++ {
		h := first.Add(time.Duration(i) * time.Hour)
		if v := at(h); !math.IsNaN(v) {
			anyToday = true
			today = append(today, v)
		} else {
			today = append(today, math.NaN())
		}
		yday = append(yday, at(h.Add(-24*time.Hour)))
		labels = append(labels, h.In(loc).Format("15"))
	}
	if !anyToday {
		return "", false
	}
	partial := math.NaN()
	if an != nil {
		if to := now.Add(-liveLag); to.After(hourStart) {
			if n, err := an.Count(ctx, zone.ZoneID, hourStart, to, cfapi.Filter{}); err == nil {
				partial = float64(n)
			}
		}
	}
	today = append(today, partial)
	yday = append(yday, math.NaN())
	labels = append(labels, hourStart.In(loc).Format("15"))
	html := svgChart{W: 720, H: 130, Lines: []svgSeries{
		{Class: "l-yday", Values: yday},
		{Class: "l-total", Values: today},
	}, XLabels: labels}.render()
	if html == "" {
		return "", false
	}
	return html, true
}
