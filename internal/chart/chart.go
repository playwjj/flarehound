// Package chart renders the small PNG charts FlareHound attaches to
// alerts and daily reports — pure Go, no browser, no external service.
// Text on the image is limited to numbers and hours (the built-in bitmap
// font has no CJK glyphs); titles and explanations live in the message.
package chart

import (
	"bytes"
	"fmt"
	"image"
	"image/color"
	"image/draw"
	"image/png"
	"math"

	"golang.org/x/image/font"
	"golang.org/x/image/font/basicfont"
	"golang.org/x/image/math/fixed"
)

// Series is one line.
type Series struct {
	Label  string    // ASCII legend label
	Values []float64 // one per x position; NaN = no data (gap)
	Color  color.RGBA
	Dashed bool
}

// Line is a line chart over a fixed x axis.
type Line struct {
	Width, Height int
	XLabels       []string // one per x position; shown every Every-th
	Every         int
	Series        []Series
	// Highlight shades x positions [From, To) — the anomalous window.
	HighlightFrom, HighlightTo int
	Highlight                  bool
}

// Palette.
var (
	Blue   = color.RGBA{37, 99, 235, 255}
	Gray   = color.RGBA{156, 163, 175, 255}
	Orange = color.RGBA{234, 88, 12, 255}
	ink    = color.RGBA{55, 65, 81, 255}
	grid   = color.RGBA{229, 231, 235, 255}
	band   = color.RGBA{254, 243, 199, 255}
)

const (
	padL, padR, padT, padB = 64, 16, 28, 34
)

// Short formats an axis value: 950, 12k, 1.3M.
func Short(v float64) string {
	switch {
	case v >= 1e6:
		return trim(fmt.Sprintf("%.1fM", v/1e6))
	case v >= 1e3:
		return trim(fmt.Sprintf("%.1fk", v/1e3))
	}
	return fmt.Sprintf("%.0f", v)
}

func trim(s string) string {
	if len(s) > 3 && s[len(s)-3:len(s)-1] == ".0" {
		return s[:len(s)-3] + s[len(s)-1:]
	}
	return s
}

// niceScale picks the finest round tick step (1, 2, 2.5 or 5 × 10^n) that
// needs at most five gridlines, and the axis top as a whole number of steps.
func niceScale(v float64) (top, step float64) {
	if v <= 0 {
		return 1, 0.25
	}
	p := math.Pow(10, math.Floor(math.Log10(v/5)))
	for _, d := range []float64{1, 10, 100} {
		for _, m := range []float64{1, 2, 2.5, 5} {
			step = m * p * d
			if math.Ceil(v/step) <= 5 {
				return math.Ceil(v/step) * step, step
			}
		}
	}
	return v, v / 4
}

func text(img *image.RGBA, x, y int, s string, c color.Color) {
	d := font.Drawer{Dst: img, Src: image.NewUniform(c), Face: basicfont.Face7x13, Dot: fixed.P(x, y)}
	d.DrawString(s)
}

func textWidth(s string) int { return 7 * len(s) }

func fill(img *image.RGBA, r image.Rectangle, c color.Color) {
	draw.Draw(img, r, image.NewUniform(c), image.Point{}, draw.Src)
}

// dot paints a 3×3 square — a 2–3 px line when stepped along a segment.
func dot(img *image.RGBA, x, y int, c color.RGBA) {
	for dx := -1; dx <= 1; dx++ {
		for dy := -1; dy <= 1; dy++ {
			if (dx == -1 || dx == 1) && (dy == -1 || dy == 1) {
				continue // round-ish corners
			}
			img.SetRGBA(x+dx, y+dy, c)
		}
	}
}

func segment(img *image.RGBA, x0, y0, x1, y1 float64, c color.RGBA, dashed bool) {
	n := int(math.Max(math.Abs(x1-x0), math.Abs(y1-y0))) + 1
	for i := 0; i <= n; i++ {
		if dashed && (i/6)%2 == 1 {
			continue
		}
		t := float64(i) / float64(n)
		dot(img, int(math.Round(x0+(x1-x0)*t)), int(math.Round(y0+(y1-y0)*t)), c)
	}
}

// PNG renders the chart.
func (l Line) PNG() ([]byte, error) {
	w, h := l.Width, l.Height
	if w == 0 {
		w = 960
	}
	if h == 0 {
		h = 320
	}
	n := len(l.XLabels)
	for _, s := range l.Series {
		n = max(n, len(s.Values))
	}
	if n < 2 {
		return nil, fmt.Errorf("chart: need at least two points")
	}
	img := image.NewRGBA(image.Rect(0, 0, w, h))
	fill(img, img.Bounds(), color.White)
	pw, ph := w-padL-padR, h-padT-padB
	xAt := func(i int) float64 { return float64(padL) + float64(i)*float64(pw)/float64(n-1) }

	top := 0.0
	for _, s := range l.Series {
		for _, v := range s.Values {
			if !math.IsNaN(v) && v > top {
				top = v
			}
		}
	}
	top, step := niceScale(top * 1.05)
	yAt := func(v float64) float64 { return float64(padT) + float64(ph)*(1-v/top) }

	if l.Highlight && l.HighlightTo > l.HighlightFrom {
		// Each point stands for a slot: shade half a step either side, so
		// a single highlighted hour at the edge is still clearly visible.
		half := float64(pw) / float64(n-1) / 2
		x0 := int(math.Max(xAt(max(l.HighlightFrom, 0))-half, float64(padL)))
		x1 := int(math.Min(xAt(min(l.HighlightTo-1, n-1))+half, float64(padL+pw)))
		fill(img, image.Rect(x0, padT, x1, padT+ph), band)
	}
	for v := 0.0; v <= top+step/2; v += step { // grid + y labels
		y := int(yAt(v))
		fill(img, image.Rect(padL, y, padL+pw, y+1), grid)
		lab := Short(v)
		text(img, padL-8-textWidth(lab), y+4, lab, ink)
	}
	every := max(l.Every, 1)
	for i, lab := range l.XLabels { // x labels
		if i%every != 0 || lab == "" {
			continue
		}
		x := int(xAt(i))
		fill(img, image.Rect(x, padT+ph, x+1, padT+ph+4), ink)
		text(img, x-textWidth(lab)/2, padT+ph+17, lab, ink)
	}
	fill(img, image.Rect(padL, padT+ph, padL+pw, padT+ph+1), ink)

	for _, s := range l.Series { // lines (later series drawn on top)
		for i := 1; i < len(s.Values); i++ {
			a, b := s.Values[i-1], s.Values[i]
			if math.IsNaN(a) || math.IsNaN(b) {
				continue
			}
			segment(img, xAt(i-1), yAt(a), xAt(i), yAt(b), s.Color, s.Dashed)
		}
	}
	x := padL + pw // legend, right-aligned on the top padding
	for i := len(l.Series) - 1; i >= 0; i-- {
		s := l.Series[i]
		x -= textWidth(s.Label) + 26
		fill(img, image.Rect(x, 10, x+14, 13), s.Color)
		text(img, x+18, 15, s.Label, ink)
	}

	var buf bytes.Buffer
	if err := png.Encode(&buf, img); err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}
