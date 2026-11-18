package console

import (
	"fmt"
	"html/template"
	"math"
	"strings"
	"time"

	"github.com/playwjj/flarehound/internal/chart"
)

// Charts are inline SVG generated on the server: no script, no external
// resource, and colours come from CSS classes so dark mode just works.
// (internal/chart renders PNGs for messages; its axis scale and number
// format are shared here.)

type svgSeries struct {
	Class  string
	Values []float64 // NaN = gap
}

type svgChart struct {
	W, H     int
	Lines    []svgSeries
	BandLo   []float64 // optional baseline band
	BandHi   []float64
	Median   []float64
	XLabels  []string // per x; drawn when non-empty
	Ticks    []svgTick
	TimeFrom time.Time
	Step     time.Duration
}

type svgTick struct {
	X     float64 // fractional x index
	Class string
	Title string
}

func niceTop(v float64) (top, step float64) {
	if v <= 0 {
		return 1, 0.25
	}
	raw := v / 4
	mag := math.Pow(10, math.Floor(math.Log10(raw)))
	for _, m := range []float64{1, 2, 2.5, 5, 10} {
		if s := m * mag; s >= raw {
			return math.Ceil(v/s) * s, s
		}
	}
	return v, v / 4
}

func (c svgChart) render() template.HTML {
	// Text and padding scale with the viewBox so labels stay legible
	// when the chart is shrunk to a phone's width.
	fs := float64(c.W) / 40
	padL, padR, padT, padB := fs*3.6, 8.0, fs*0.8, fs*1.9
	n := 0
	for _, s := range c.Lines {
		if len(s.Values) > n {
			n = len(s.Values)
		}
	}
	if n < 2 {
		return ""
	}
	maxV := 0.0
	scan := func(vs []float64) {
		for _, v := range vs {
			if !math.IsNaN(v) && v > maxV {
				maxV = v
			}
		}
	}
	for _, s := range c.Lines {
		scan(s.Values)
	}
	scan(c.BandHi)
	scan(c.Median)
	top, step := niceTop(maxV)
	W, H := float64(c.W), float64(c.H)
	pw, ph := W-padL-padR, H-padT-padB
	x := func(i float64) float64 { return padL + pw*i/float64(n-1) }
	y := func(v float64) float64 { return padT + ph*(1-v/top) }

	var b strings.Builder
	fmt.Fprintf(&b, `<svg class="chart" viewBox="0 0 %d %d" role="img" font-size="%.0f">`, c.W, c.H, fs)
	for v := 0.0; v <= top+step/2; v += step {
		fmt.Fprintf(&b, `<line class="grid" x1="%.1f" x2="%.1f" y1="%.1f" y2="%.1f"/>`, padL, W-padR, y(v), y(v))
		fmt.Fprintf(&b, `<text class="axis" x="%.1f" y="%.1f" text-anchor="end">%s</text>`, padL-4, y(v)+fs/3, template.HTMLEscapeString(chart.Short(v)))
	}
	// Band: upper edge forward, lower edge back, split at gaps.
	if len(c.BandLo) == n && len(c.BandHi) == n {
		for i := 0; i < n; {
			if math.IsNaN(c.BandLo[i]) {
				i++
				continue
			}
			j := i
			for j < n && !math.IsNaN(c.BandLo[j]) {
				j++
			}
			var pts []string
			for k := i; k < j; k++ {
				pts = append(pts, fmt.Sprintf("%.1f,%.1f", x(float64(k)), y(c.BandHi[k])))
			}
			for k := j - 1; k >= i; k-- {
				pts = append(pts, fmt.Sprintf("%.1f,%.1f", x(float64(k)), y(c.BandLo[k])))
			}
			fmt.Fprintf(&b, `<polygon class="band" points="%s"/>`, strings.Join(pts, " "))
			i = j
		}
	}
	path := func(vs []float64, class string) {
		var d strings.Builder
		pen := false
		for i, v := range vs {
			if math.IsNaN(v) {
				pen = false
				continue
			}
			if pen {
				fmt.Fprintf(&d, "L%.1f %.1f", x(float64(i)), y(v))
			} else {
				fmt.Fprintf(&d, "M%.1f %.1f", x(float64(i)), y(v))
				pen = true
			}
		}
		if d.Len() > 0 {
			fmt.Fprintf(&b, `<path class="%s" d="%s"/>`, class, d.String())
		}
	}
	if len(c.Median) == n {
		path(c.Median, "median")
	}
	for _, s := range c.Lines {
		path(s.Values, s.Class)
	}
	for _, t := range c.Ticks {
		if t.X < 0 || t.X > float64(n-1) {
			continue
		}
		fmt.Fprintf(&b, `<line class="tick %s" x1="%.1f" x2="%.1f" y1="%.1f" y2="%.1f"><title>%s</title></line>`,
			t.Class, x(t.X), x(t.X), padT, H-padB, template.HTMLEscapeString(t.Title))
	}
	// X labels: at most ~8 of the non-empty ones, evenly spaced.
	nonEmpty := 0
	for _, l := range c.XLabels {
		if l != "" {
			nonEmpty++
		}
	}
	every := int(math.Ceil(float64(nonEmpty) / 8))
	k := 0
	for i, l := range c.XLabels {
		if l == "" {
			continue
		}
		k++
		if (k-1)%every != 0 {
			continue
		}
		fmt.Fprintf(&b, `<text class="axis" x="%.1f" y="%.1f" text-anchor="middle">%s</text>`, x(float64(i)), H-fs*0.4, template.HTMLEscapeString(l))
	}
	b.WriteString(`</svg>`)
	return template.HTML(b.String())
}

// historyChart renders a History with band, median and event ticks.
func historyChart(h History, loc *time.Location, w, ht int, withDynamic bool) template.HTML {
	n := len(h.Points)
	if n < 2 {
		return ""
	}
	total := make([]float64, n)
	dyn := make([]float64, n)
	lo, hi, med := make([]float64, n), make([]float64, n), make([]float64, n)
	labels := make([]string, n)
	spanDays := h.To.Sub(h.From) > 48*time.Hour
	for i, p := range h.Points {
		total[i], dyn[i] = math.NaN(), math.NaN()
		if p.Has {
			total[i], dyn[i] = float64(p.Total), float64(p.Dynamic)
		}
		lo[i], hi[i], med[i] = math.NaN(), math.NaN(), math.NaN()
		if p.HasBase {
			lo[i], hi[i], med[i] = p.P25, p.P75, p.Median
		}
		t := p.From.In(loc)
		if spanDays {
			if t.Hour() == 0 {
				labels[i] = t.Format("01-02")
			}
		} else if t.Hour()%3 == 0 {
			labels[i] = t.Format("15h")
		}
	}
	c := svgChart{W: w, H: ht, BandLo: lo, BandHi: hi, Median: med, XLabels: labels}
	c.Lines = []svgSeries{{Class: "l-total", Values: total}}
	if withDynamic {
		c.Lines = append(c.Lines, svgSeries{Class: "l-dyn", Values: dyn})
	}
	for _, e := range h.Events {
		// Points sit at their hour's start; an alert's At is its window's
		// end, so it is drawn on the hour it is about.
		xi := e.At.Sub(h.From).Hours()
		if e.Kind == "alert" || e.Kind == "recovered" {
			xi--
		}
		c.Ticks = append(c.Ticks, svgTick{X: xi, Class: "ev-" + e.Kind, Title: e.At.In(loc).Format("01-02 15:04") + " " + e.Label})
	}
	return c.render()
}
