package chart

import (
	"bytes"
	"image/png"
	"math"
	"os"
	"testing"
)

func TestLinePNG(t *testing.T) {
	today, yday := make([]float64, 24), make([]float64, 24)
	labels := make([]string, 24)
	for i := range today {
		yday[i] = 700_000 + 50_000*math.Sin(float64(i)/4)
		today[i] = yday[i] * 1.05
		labels[i] = string(rune('0'+i/10)) + string(rune('0'+i%10))
	}
	today[20] = 1_050_000
	today[23] = math.NaN() // not settled yet
	raw, err := Line{XLabels: labels, Every: 3, Highlight: true, HighlightFrom: 20, HighlightTo: 21,
		Series: []Series{{Label: "yesterday", Values: yday, Color: Gray, Dashed: true}, {Label: "today", Values: today, Color: Blue}}}.PNG()
	if err != nil {
		t.Fatal(err)
	}
	img, err := png.Decode(bytes.NewReader(raw))
	if err != nil || img.Bounds().Dx() != 960 || img.Bounds().Dy() != 320 {
		t.Fatalf("decode: %v %v", err, img.Bounds())
	}
	blue := 0
	for y := 0; y < 320; y++ {
		for x := 0; x < 960; x++ {
			r, g, b, _ := img.At(x, y).RGBA()
			if r>>8 == 37 && g>>8 == 99 && b>>8 == 235 {
				blue++
			}
		}
	}
	if blue < 500 {
		t.Fatalf("today's line barely drawn: %d px", blue)
	}
	if p := os.Getenv("CHART_OUT"); p != "" {
		_ = os.WriteFile(p, raw, 0o644)
	}
	if _, err := (Line{}).PNG(); err == nil {
		t.Fatal("empty chart accepted")
	}
}

func TestShort(t *testing.T) {
	for v, want := range map[float64]string{950: "950", 12000: "12k", 1_300_000: "1.3M", 2_000_000: "2M", 1500: "1.5k"} {
		if got := Short(v); got != want {
			t.Errorf("Short(%v) = %s, want %s", v, got, want)
		}
	}
}

func TestNiceScale(t *testing.T) {
	for _, c := range []struct{ v, top, step float64 }{
		{2_400_000, 2_500_000, 500_000}, {1_100_000, 1_250_000, 250_000}, {78_000, 80_000, 20_000}, {950, 1000, 200},
	} {
		if top, step := niceScale(c.v); top != c.top || step != c.step {
			t.Errorf("niceScale(%v) = %v/%v, want %v/%v", c.v, top, step, c.top, c.step)
		}
	}
}
