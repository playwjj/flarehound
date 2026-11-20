package report

import (
	"strings"
	"testing"
	"time"

	"github.com/playwjj/flarehound/internal/analyze"
	"github.com/playwjj/flarehound/internal/calibrate"
	"github.com/playwjj/flarehound/internal/cfapi"
	"github.com/playwjj/flarehound/internal/schedule"
	"github.com/playwjj/flarehound/internal/state"
)

// jargon is what a Chinese notification must not say: internal names and
// shorthand that only make sense to whoever wrote the detector. Terms a
// reader needs (5xx, 52x, P95, Worker, IP) stay, explained where used.
var jargon = []string{"越线", "dynamic", "两窗", " vs ", "UA Top", "ASN Top", "clientAsn", "辨伪", "记账底量", "证伪",
	"未落定", "面孔", "基线", "zone ", "塌量", "机制假设", "归因拆分"}

func richFindings() []analyze.Finding {
	return []analyze.Finding{
		{Rule: analyze.RuleOrigin5xx, Cur: 137, Base: 37},
		{Rule: analyze.RuleUnreachable, Cur: 400, Base: 20},
		{Rule: analyze.RuleOriginSlow, Cur: 2400, Base: 400, Pct: 500},
		{Rule: analyze.RuleCollapseTotal, Cur: 1000, Base: 20000, Pct: -95},
		{Rule: analyze.RuleWorkerCallsUp, Subject: "web", Cur: 76_000, Base: 50_000, Pct: 52},
		{Rule: analyze.RuleCPUUp, Subject: "web", Cur: 6, Base: 4, Pct: 50},
		{Rule: analyze.RuleDynamicUp, Cur: 70_000, Base: 40_000, Pct: 75},
		{Rule: analyze.RulePathUp, Subject: "/api/*", Cur: 9_000, Base: 3_000, Pct: 200},
		{Rule: analyze.RuleTotalUp, Cur: 152_000, Base: 100_000, Pct: 52},
		{Rule: analyze.RuleNewFaceASN, Subject: "AS207990", ASN: 207990, Cur: 45_000, Pct: 999},
		{Rule: analyze.RuleNewFaceUA, Subject: "Go-http-client/1.1", Cur: 14_000, Pct: 999},
	}
}

func TestNotificationsSpeakPlainly(t *testing.T) {
	cur := analyze.Metrics{Total: 152_000, Dynamic: 70_000, Origin5xx: 137, Unreachable: 400, UnreachableBy: map[string]int64{"522": 400},
		Origin:  &analyze.OriginMetrics{Requests: 50_000, TTFBP95ms: 2400, TotalP95ms: 2900},
		Workers: []analyze.WorkerMetrics{{Name: "web", Calls: 76_000, CPUP50ms: 6, CPUP99ms: 30}},
		TopUA:   []cfapi.Face{{Name: "Go-http-client/1.1", Count: 14_000}, {Name: "", Count: 3_500}},
		TopASN:  []cfapi.Face{{Name: "AS207990", Count: 45_000}}}
	base := analyze.Metrics{Total: 100_000, Dynamic: 40_000, Origin5xx: 37, Unreachable: 20, UnreachableBy: map[string]int64{"522": 20},
		Origin:  &analyze.OriginMetrics{Requests: 50_000, TTFBP95ms: 400, TotalP95ms: 500},
		Workers: []analyze.WorkerMetrics{{Name: "web", Calls: 50_000, CPUP50ms: 4, CPUP99ms: 20}}}
	fs := richFindings()
	day := schedule.Window{From: w.From.Add(-23 * time.Hour), To: w.To}
	cost := analyze.SplitCost([]cfapi.Face{{Name: "dynamic", Count: 70_000}, {Name: "hit", Count: 82_000}}, []cfapi.Face{{Name: "dynamic", Count: 40_000}, {Name: "hit", Count: 60_000}})
	daily := Daily("zh", DailyData{Zone: "z", Window: day, Loc: time.UTC, Cur: cur, Base: base, Findings: fs, Cost: &cost,
		DynamicPaths: []analyze.PathDelta{{Path: "/rank", Cur: 35_000, Base: 20_000}}, NoASN: true, FirewallNA: true,
		Archive:     &ArchiveInfo{Hours: 25, Days: 1, Oldest: day.From, Warming: []analyze.Maturity{{Metric: analyze.MetricUnreachable, Need: 3}}},
		Calibration: &calibrate.Summary{Requests: 1.33, Days: make([]calibrate.Day, 1), Verdict: calibrate.AdaptiveHi},
		ActiveSince: day.From, ActiveFingerprint: "total_up,origin_5xx",
	})
	intraday := Intraday("zh", IntradayData{Zone: "z", Window: w, Decision: state.DecAlert, Cur: cur, Base: base, Findings: fs,
		Attr:       analyze.Attribution{Unsettled: []string{"total"}, DynamicPaths: []analyze.PathDelta{{Path: "/rank", Cur: 35_000, Base: 20_000}}},
		Hypotheses: []analyze.Hypothesis{{ID: analyze.HypCacheRegress, Confidence: analyze.Medium}, {ID: analyze.HypCPUMix, Subject: "web"}, {ID: analyze.HypSlowPath, Subject: "web"}},
		Block:      analyze.BlockAdvice{Dispersed: true}})
	for name, msg := range map[string]string{"daily": daily, "intraday": intraday} {
		for _, j := range jargon {
			if strings.Contains(msg, j) {
				t.Errorf("%s says %q:\n%s", name, j, msg)
			}
		}
	}
	for _, want := range []string{"⚠️ 需要关注：", "▶ 源站报错变多", "源站返回错误（5xx）的次数：137（前一天 37，约 3.7 倍）。", "→ 建议：",
		"Go 程序（Go-http-client/1.1） 14,000", "系统状态", "白天发现的异常还没恢复"} {
		if !strings.Contains(daily, want) {
			t.Errorf("daily lacks %q:\n%s", want, daily)
		}
	}
	if strings.Contains(daily, "total_up") {
		t.Errorf("daily leaks the internal fingerprint:\n%s", daily)
	}
}

func TestStatusShownWhenItChanges(t *testing.T) {
	d := DailyData{Zone: "z", Window: w, NoASN: true}
	if !strings.Contains(Daily("zh", d), "系统状态") {
		t.Fatal("status missing")
	}
	k := StatusKey(d)
	d.HideStatus = true
	if strings.Contains(Daily("zh", d), "系统状态") {
		t.Fatal("hidden status shown")
	}
	d.FirewallNA = true
	if StatusKey(d) == k {
		t.Fatal("a new limit does not change the key")
	}
	d.Archive = &ArchiveInfo{Hours: 1}
	k = StatusKey(d)
	d.Archive.Hours = 500 // grows every day: not a change
	if StatusKey(d) != k {
		t.Fatal("archive growth changes the key")
	}
}

func TestFriendlyUA(t *testing.T) {
	zh := lang("zh")
	for ua, want := range map[string]string{
		"":                       "没有标识的客户端（脚本、健康检查等）",
		"Go-http-client/1.1":     "Go 程序（Go-http-client/1.1）",
		"python-requests/2.31.0": "Python 脚本（python-requests/2.31.0）",
		"Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/130.0.0.0 Safari/537.36":                         "Chrome 130 · Windows",
		"Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36":                                                                            "不完整的浏览器标识 · Windows（多为脚本冒充浏览器）",
		"Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) HeadlessChrome/120.0.0.0 Safari/537.36":                           "无头 Chrome（自动化程序） · Linux",
		"Mozilla/5.0 (compatible; Googlebot/2.1; +http://www.google.com/bot.html)":                                                                "爬虫 Googlebot",
		"Mozilla/5.0 (iPhone; CPU iPhone OS 17_0 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.0 Mobile/15E148 Safari/604.1": "Safari 17 · iPhone",
	} {
		if got := zh.friendlyUA(ua); got != want {
			t.Errorf("friendlyUA(%q) = %q, want %q", ua, got, want)
		}
	}
}

func TestDeltaWords(t *testing.T) {
	zh := lang("zh")
	for _, c := range []struct {
		cur, base float64
		want      string
	}{{137, 37, "约 3.7 倍"}, {0, 0, "持平"}, {5, 0, "新出现"}, {100.5, 100, "持平"}, {105, 100, "+5.0%"}, {70, 100, "-30%"}} {
		if got := zh.delta(c.cur, c.base); got != c.want {
			t.Errorf("delta(%v, %v) = %q, want %q", c.cur, c.base, got, c.want)
		}
	}
}
