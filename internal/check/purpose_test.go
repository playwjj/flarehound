package check

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/playwjj/flarehound/internal/cfapi"
)

const gptbot = "Mozilla/5.0 AppleWebKit/537.36 (KHTML, like Gecko; compatible; GPTBot/1.2; +https://openai.com/gptbot)"

// A new, verified training crawler is recorded, not alerted on; the same
// UA unverified (anyone can write "GPTBot") alerts as before, labelled.
func TestNewTrainingCrawler(t *testing.T) {
	for _, verified := range []bool{true, false} {
		cfg := testConfig(t)
		cfg.Cloudflare.Zones[0].Workers = nil
		api := &fakeAPI{windows: map[time.Time]*window{}, reads: map[time.Time]int{}}
		out := &sink{}
		from := time.Date(2026, 11, 17, 8, 0, 0, 0, time.UTC)
		r := &Runner{API: api, Cfg: cfg, Sender: out, Now: func() time.Time { return from.Add(67 * time.Minute) },
			Sleep: func(context.Context, time.Duration) error { return nil }}
		api.windows[from.Add(-24*time.Hour)] = normal()
		cur := normal()
		cur.ua = append(cur.ua, cfapi.Face{Name: gptbot, Count: 9000})
		cat := ""
		if verified {
			cat = "AI Crawler"
		}
		cur.uaRows = []cfapi.Face{{Name: gptbot, ASN: 8075, Cat: cat, Count: 9000}}
		api.windows[from] = cur
		if err := r.Intraday(context.Background(), cfg.Cloudflare.Zones[0]); err != nil {
			t.Fatal(err)
		}
		switch {
		case verified && len(out.msgs) != 0:
			t.Errorf("verified training crawler alerted: %v", out.msgs)
		case !verified && (len(out.msgs) != 1 || !strings.Contains(out.msgs[0], "[training · OpenAI · self-declared]")):
			t.Errorf("unverified GPTBot: want a labelled alert, got %v", out.msgs)
		}
	}
}

// The daily report carries traffic by purpose; undeclared automation is
// described by its traits, never as an AI operator.
func TestDailyPurposeSection(t *testing.T) {
	cfg := testConfig(t)
	cfg.Report.Language = "zh"
	api := &fakeAPI{windows: map[time.Time]*window{}, reads: map[time.Time]int{}}
	out := &sink{}
	end := time.Date(2026, 11, 17, 8, 0, 0, 0, time.UTC)
	r := &Runner{API: api, Cfg: cfg, Sender: out, Now: func() time.Time { return end.Add(7 * time.Minute) }}
	chrome := "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/157.0.0.0 Safari/537.36"
	base := normal()
	base.uaRows = []cfapi.Face{{Name: chrome, ASN: 45102, Count: 20_000}, {Name: gptbot, ASN: 8075, Cat: "AI Crawler", Count: 5_000}}
	cur := surge()
	cur.uaRows = []cfapi.Face{{Name: chrome, ASN: 45102, Count: 62_000}, {Name: gptbot, ASN: 8075, Cat: "AI Crawler", Count: 6_000},
		{Name: "rednote-websearch-bot/1.0", ASN: 45102, Count: 2_000}}
	api.windows[end.Add(-48*time.Hour)] = base
	api.windows[end.Add(-24*time.Hour)] = cur
	if err := r.Daily(context.Background(), cfg.Cloudflare.Zones[0]); err != nil {
		t.Fatal(err)
	}
	msg := out.msgs[0]
	t.Logf("daily:\n%s", msg)
	for _, want := range []string{"访问目的（AI 训练、搜索等）", "未申报自动化 40.8%", "Chrome/157.0.0.0 (X11; Linux x86_64) 62,000（AS45102 100%）", "GPTBot 6,000 [已验证]", "训练 3.9%", "[已验证]", "工具代客", "[自报]",
		"用途占比变化：未申报自动化 20% → 41%（+21 个百分点）"} {
		if !strings.Contains(msg, want) {
			t.Errorf("daily lacks %q", want)
		}
	}
	if strings.Contains(msg, "疑似") {
		t.Error("undeclared automation described with a guess")
	}
}
