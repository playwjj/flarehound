package check

import (
	"context"
	"image/color"
	"log"
	"math"
	"time"

	"github.com/playwjj/flarehound/internal/cfapi"
	"github.com/playwjj/flarehound/internal/chart"
	"github.com/playwjj/flarehound/internal/config"
	"github.com/playwjj/flarehound/internal/notify"
	"github.com/playwjj/flarehound/internal/report"
)

// hourlyChart draws "the 24 hours ending at end" against the 24 hours
// before, from one 48-hour query. The last `highlight` hours are shaded
// (the alert's window).
func (r *Runner) hourlyChart(ctx context.Context, zone config.Zone, end time.Time, f cfapi.Filter,
	name, caption, label string, c color.RGBA, highlight int) (notify.Image, error) {
	end = end.UTC().Truncate(time.Hour)
	series, err := r.API.Hourly(ctx, zone.ZoneID, end.Add(-48*time.Hour), end, f)
	if err != nil {
		return notify.Image{}, err
	}
	today, yday := make([]float64, 24), make([]float64, 24)
	labels := make([]string, 24)
	for i := 0; i < 24; i++ {
		h := end.Add(time.Duration(i-24) * time.Hour)
		today[i], yday[i] = math.NaN(), math.NaN()
		if v, ok := series[h]; ok {
			today[i] = float64(v)
		}
		if v, ok := series[h.Add(-24*time.Hour)]; ok {
			yday[i] = float64(v)
		}
		labels[i] = h.In(r.Cfg.Location).Format("15")
	}
	l := chart.Line{XLabels: labels, Every: 3, Series: []chart.Series{
		{Label: "day before", Values: yday, Color: chart.Gray, Dashed: true},
		{Label: label, Values: today, Color: c},
	}}
	if highlight > 0 {
		l.Highlight, l.HighlightFrom, l.HighlightTo = true, 24-highlight, 24
	}
	png, err := l.PNG()
	if err != nil {
		return notify.Image{}, err
	}
	return notify.Image{Name: name, Caption: caption, PNG: png}, nil
}

// charts builds the images for a message. Failures only cost the charts:
// the text report is always sent.
func (r *Runner) charts(ctx context.Context, zone config.Zone, end time.Time, highlight int, withDynamic bool) ([]notify.Image, []report.Chart) {
	if !r.Cfg.Report.Visuals {
		return nil, nil
	}
	zh := r.Cfg.Report.Language == "zh"
	pick := func(en, cn string) string {
		if zh {
			return cn
		}
		return en
	}
	var imgs []notify.Image
	img, err := r.hourlyChart(ctx, zone, end, cfapi.Filter{}, "requests",
		pick("Requests per hour — last 24 h (blue) vs the day before (gray, dashed)", "每小时请求数——过去 24 小时（蓝）对比前一天（灰虚线）"),
		"last 24h", chart.Blue, highlight)
	if err != nil {
		log.Printf("zone %s: chart: %v", zone.Name, err)
		return nil, nil
	}
	imgs = append(imgs, img)
	if withDynamic {
		img, err := r.hourlyChart(ctx, zone, end, cfapi.Filter{CacheStatus: "dynamic"}, "dynamic",
			pick("Real rendering (dynamic) per hour — last 24 h (orange) vs the day before (gray, dashed)", "每小时真实渲染（dynamic）——过去 24 小时（橙）对比前一天（灰虚线）"),
			"dynamic", chart.Orange, highlight)
		if err != nil {
			log.Printf("zone %s: chart: %v", zone.Name, err)
		} else {
			imgs = append(imgs, img)
		}
	}
	var cs []report.Chart
	for _, i := range imgs {
		cs = append(cs, report.Chart{CID: i.Name, Caption: i.Caption})
	}
	return imgs, cs
}
