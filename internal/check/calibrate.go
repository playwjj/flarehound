package check

import (
	"context"
	"encoding/json"
	"fmt"
	"time"

	"github.com/playwjj/flarehound/internal/calibrate"
	"github.com/playwjj/flarehound/internal/cfapi"
	"github.com/playwjj/flarehound/internal/config"
)

// CalibrateDay measures one UTC day in both datasets: the dashboard's
// totals and the adaptive equivalents FlareHound computes.
func (r *Runner) CalibrateDay(ctx context.Context, zone config.Zone, date time.Time) (calibrate.Day, error) {
	from := date.UTC().Truncate(24 * time.Hour)
	to := from.Add(24 * time.Hour)
	d := calibrate.Day{Date: from}
	dash, err := r.API.DashboardDay(ctx, zone.ZoneID, from)
	if err != nil {
		return d, fmt.Errorf("dashboard totals: %w", err)
	}
	d.DashRequests, d.DashCached, d.Dash5xx = dash.Requests, dash.Cached, dash.Edge5xx
	if d.AdRequests, d.SampleInterval, err = r.API.Sampling(ctx, zone.ZoneID, from, to); err != nil {
		return d, fmt.Errorf("adaptive totals: %w", err)
	}
	cache, err := r.API.Top(ctx, zone.ZoneID, from, to, cfapi.DimCacheStatus, 20, cfapi.Filter{})
	if err != nil {
		return d, fmt.Errorf("adaptive cache status: %w", err)
	}
	for _, f := range cache {
		if f.Name == "hit" { // the dashboard's "cached" is edge hits
			d.AdCached += f.Count
		}
	}
	if d.Ad5xx, err = r.API.Count(ctx, zone.ZoneID, from, to, cfapi.Filter{EdgeStatusFrom: 500, EdgeStatusTo: 600}); err != nil {
		return d, fmt.Errorf("adaptive edge 5xx: %w", err)
	}
	return d, nil
}

// Calibrate measures the last `days` full UTC days that the archive does
// not hold yet, stores them, and summarises the newest seven (or `days`,
// if more). Without an archive it measures and summarises in memory.
func (r *Runner) Calibrate(ctx context.Context, zone config.Zone, days int) (calibrate.Summary, error) {
	today := r.now().UTC().Truncate(24 * time.Hour)
	var measured []calibrate.Day
	have := map[int64]bool{}
	if r.Store != nil {
		rows, err := r.Store.CalibrationDays(zone.ZoneID, 400)
		if err != nil {
			return calibrate.Summary{}, err
		}
		for _, raw := range rows {
			var d calibrate.Day
			if json.Unmarshal(raw, &d) == nil {
				have[d.Date.Unix()] = true
			}
		}
	}
	for i := 1; i <= days; i++ {
		date := today.AddDate(0, 0, -i)
		if have[date.Unix()] {
			continue
		}
		d, err := r.CalibrateDay(ctx, zone, date)
		if err != nil {
			return calibrate.Summary{}, err
		}
		measured = append(measured, d)
		if r.Store != nil {
			raw, _ := json.Marshal(d)
			if err := r.Store.PutCalibrationDay(zone.ZoneID, date, raw); err != nil {
				return calibrate.Summary{}, err
			}
		}
	}
	window := max(days, 7)
	var all []calibrate.Day
	if r.Store != nil {
		rows, err := r.Store.CalibrationDays(zone.ZoneID, window)
		if err != nil {
			return calibrate.Summary{}, err
		}
		for _, raw := range rows {
			var d calibrate.Day
			if json.Unmarshal(raw, &d) == nil {
				all = append(all, d)
			}
		}
	} else {
		all = measured
	}
	return calibrate.Summarize(all, r.Cfg.Thresholds.MinCount), nil
}
