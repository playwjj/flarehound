package report

import (
	"strings"
	"testing"
	"time"

	"github.com/playwjj/flarehound/internal/analyze"
	"github.com/playwjj/flarehound/internal/cfapi"
	"github.com/playwjj/flarehound/internal/geoip"
	"github.com/playwjj/flarehound/internal/schedule"
	"github.com/playwjj/flarehound/internal/state"
)

var w = schedule.Window{From: time.Date(2026, 11, 17, 8, 0, 0, 0, time.UTC), To: time.Date(2026, 11, 17, 9, 0, 0, 0, time.UTC)}

func TestRecoveryIsOneLine(t *testing.T) {
	for _, lang := range []string{"en", "zh"} {
		msg := Intraday(lang, IntradayData{Zone: "example.com", Window: w, Decision: state.DecRecovered})
		if strings.Contains(msg, "\n") {
			t.Errorf("%s recovery spans lines: %q", lang, msg)
		}
	}
}

func TestNoHypothesisSaysSo(t *testing.T) {
	msg := Intraday("zh", IntradayData{Zone: "z", Window: w, Decision: state.DecAlert,
		Findings: []analyze.Finding{{Rule: analyze.RuleOrigin5xx, Cur: 300, Base: 0}}})
	if !strings.Contains(msg, "证据不足") || !strings.Contains(msg, "×∞") {
		t.Fatalf("got:\n%s", msg)
	}
}

func TestHypothesisCarriesFalsifier(t *testing.T) {
	msg := Intraday("en", IntradayData{Zone: "z", Window: w, Decision: state.DecEscalate,
		Since:      w.From,
		Findings:   []analyze.Finding{{Rule: analyze.RuleCPUUp, Subject: "web", Cur: 6, Base: 4, Pct: 50}},
		Hypotheses: []analyze.Hypothesis{{ID: analyze.HypSlowPath, Confidence: analyze.Medium, Subject: "web"}},
		Block:      analyze.BlockAdvice{Candidates: []analyze.IPShare{{IP: "203.0.113.7", Count: 9000, Share: 0.4}}},
	})
	for _, want := range []string{"ESCALATED", "episode since", "[medium]", "Falsified if", "203.0.113.7", "~40%"} {
		if !strings.Contains(msg, want) {
			t.Errorf("lacks %q:\n%s", want, msg)
		}
	}
}

func TestThousands(t *testing.T) {
	for in, want := range map[int64]string{0: "0", 999: "999", 1000: "1,000", 1234567: "1,234,567", -45000: "-45,000"} {
		if got := n(in); got != want {
			t.Errorf("n(%d) = %q", in, got)
		}
	}
}

func TestEdgeAbsorbedFloodAndDashboardTerms(t *testing.T) {
	msg := Intraday("zh", IntradayData{Zone: "z", Window: w, Decision: state.DecAlert,
		Findings: []analyze.Finding{
			{Rule: analyze.RuleTotalUp, Cur: 349_000, Base: 100_000, Pct: 249},
			{Rule: analyze.RuleNewFaceASN, Subject: "AS45102", ASN: 45102, Cur: 75_330, Pct: 999},
		},
		Attr:      analyze.Attribution{ASNNames: map[int]string{45102: "ALIBABA-CN-NET"}},
		Severity:  analyze.Severity{Level: analyze.SevLow, Kind: analyze.EdgeAbsorbed, DynPct: 1.0},
		DashRatio: 2.04,
	})
	for _, want := range []string{"低严重度：边缘吸收的流量洪水", "增量在边缘被吸收：真实渲染 +1.0%",
		"【ALIBABA-CN-NET，机房/云网络】", "（≈ 面板 36,926 次）", "（≈ 面板 171,078 次）"} {
		if !strings.Contains(msg, want) {
			t.Errorf("lacks %q:\n%s", want, msg)
		}
	}
}

func TestASNLabelInFindingLine(t *testing.T) {
	f := analyze.Finding{Rule: analyze.RuleNewFaceASN, Subject: "AS45102", ASN: 45102, Cur: 9000}
	names := map[int]string{45102: "ALIBABA-CN-NET Alibaba US Technology Co., Ltd."}
	got := lang("zh").findingLine(f, 0, names, map[int]string{45102: "aliyun"}, nil)
	if !strings.Contains(got, "aliyun") || strings.Contains(got, "ALIBABA") || !strings.Contains(got, "机房") {
		t.Fatalf("label line: %s", got)
	}
	if got := lang("en").findingLine(f, 0, names, nil, nil); !strings.Contains(got, "ALIBABA") {
		t.Fatalf("registered name fallback: %s", got)
	}
}

func TestCoverNote(t *testing.T) {
	f := analyze.Finding{Rule: analyze.RuleNewFaceASN, Subject: "AS150436", ASN: 150436, Cur: 9000}
	cov := map[string]analyze.RuleCover{f.Key() + "|" + f.Subject: {Pos: 3, Action: "block", Desc: "bytedance"}}
	if got := lang("zh").findingLine(f, 0, nil, nil, cov); !strings.Contains(got, "已被规则 #3「bytedance」拦截") {
		t.Fatalf("cover note: %s", got)
	}
}

// Replay of the 2026-11-19 01:07 alert: the message carries the three
// numbers and the mix-change reading, so nobody re-derives it by hand.
func TestCPUAlertCarriesCheck(t *testing.T) {
	base := analyze.Metrics{Dynamic: 30_000, Workers: []analyze.WorkerMetrics{{Name: "web", Calls: 100_000, CPUP50ms: 2.0, CPUP99ms: 25.0}}}
	cur := analyze.Metrics{Dynamic: 30_000, Workers: []analyze.WorkerMetrics{{Name: "web", Calls: 82_000, CPUP50ms: 3.01, CPUP99ms: 28.0}}}
	fs := []analyze.Finding{{Rule: analyze.RuleCPUUp, Subject: "web", Cur: 3.01, Base: 2, Pct: 50.5}}
	msg := Intraday("zh", IntradayData{Zone: "z", Window: w, Decision: state.DecAlert, Cur: cur, Base: base, Findings: fs,
		Hypotheses: analyze.Hypothesize(cur, base, fs, analyze.Attribution{}), Severity: analyze.Assess(cur, base, fs)})
	for _, want := range []string{"低严重度：Worker CPU 构成变化", "辨伪：P50 +50.5%，P99 +12.0%，调用量 -18.0%", "构成变化而非变贵", "P99 28.0 vs 25.0 ms"} {
		if !strings.Contains(msg, want) {
			t.Errorf("missing %q in:\n%s", want, msg)
		}
	}
}

func TestDailyExpiringThisWeek(t *testing.T) {
	day := schedule.Window{From: w.From.Add(-23 * time.Hour), To: w.To}
	d := DailyData{Zone: "z", Window: day, Loc: time.UTC, Blocks: []BlockStatus{
		{Target: "ip 106.201.104.211", Action: "block", Attempts: 55_435, Since: day.From, ExpiresAt: day.To.Add(3 * 24 * time.Hour)},
		{Target: "asn 45102", Action: "block", Attempts: 0, Since: day.From, ExpiresAt: day.To.Add(5 * 24 * time.Hour)},
		{Target: "ip 1.2.3.4", Action: "block", Attempts: 415, Approx: true, LastHour: day.To.Add(-time.Hour), Since: day.From, ExpiresAt: day.To.Add(30 * 24 * time.Hour)},
		{Target: "ua BadBot", Action: "block", Since: day.From},
	}}
	msg := Daily("zh", d)
	for _, want := range []string{"- 本周到期：", "ip 106.201.104.211（block）11-20 09:00 到期：仍在敲门（窗口内 55,435 次）——建议续期",
		"asn 45102（block）11-22 09:00 到期：窗口内已无尝试——到期将自动解除", "≈415（近似值，来自 IP 榜归档；最近上榜 11-17 08:00）"} {
		if !strings.Contains(msg, want) {
			t.Errorf("missing %q in:\n%s", want, msg)
		}
	}
	if strings.Contains(msg, "ip 1.2.3.4（block）") || strings.Contains(msg, "BadBot（") {
		t.Errorf("only blocks expiring within 7 days belong in the list:\n%s", msg)
	}
}

func TestUnreachableFootnote(t *testing.T) {
	base := analyze.Metrics{Origin5xx: 220, Unreachable: 9_800, UnreachableBy: map[string]int64{"522": 6_600, "524": 3_200}, Origin: &analyze.OriginMetrics{Requests: 400_000}}
	cur := analyze.Metrics{Origin5xx: 213, Unreachable: 10_377, UnreachableBy: map[string]int64{"522": 7_007, "524": 3_341, "520": 29}, Origin: &analyze.OriginMetrics{Requests: 410_000}}
	msg := Daily("zh", DailyData{Zone: "z", Window: w, Cur: cur, Base: base})
	if !strings.Contains(msg, "判别：记账底量，非源站故障——522/524 占 99.7%，与基线同量级（×1.1），源站照常回源") {
		t.Fatalf("got:\n%s", msg)
	}
	cur.Origin = &analyze.OriginMetrics{Requests: 10_000}
	if msg := Daily("zh", DailyData{Zone: "z", Window: w, Cur: cur, Base: base}); strings.Contains(msg, "判别：记账底量") || !strings.Contains(msg, "源站回源量 -97.5%") {
		t.Fatalf("no footnote when the origin stopped answering:\n%s", msg)
	}
}

// An origin_unreachable alert against a bookkeeping background says what
// changed, with the status split.
func TestUnreachableAlertCarriesCheck(t *testing.T) {
	base := analyze.Metrics{Unreachable: 460, UnreachableBy: map[string]int64{"522": 220, "524": 240}, Origin: &analyze.OriginMetrics{Requests: 17_000}}
	cur := analyze.Metrics{Unreachable: 1_900, UnreachableBy: map[string]int64{"522": 300, "524": 200, "521": 1_400}, Origin: &analyze.OriginMetrics{Requests: 4_000}}
	fs := analyze.Evaluate(cur, base, analyze.Thresholds{UnreachableMin: 10, CollapseDownPct: 90}, analyze.Known{})
	msg := Intraday("zh", IntradayData{Zone: "z", Window: w, Decision: state.DecAlert, Cur: cur, Base: base, Findings: fs, UnreachableMin: 10})
	for _, want := range []string{"源站不可达：边缘 52x 1,900 次 vs 460", "构成：521 ×1,400, 522 ×300, 524 ×200；判别：偏离 522/524 记账底量——量级为底量的 ×4.1；非 522/524 状态 1,400 次（占 74%）；源站回源量 -76.5%"} {
		if !strings.Contains(msg, want) {
			t.Errorf("missing %q in:\n%s", want, msg)
		}
	}
}

func TestDailyBaselineAccumulating(t *testing.T) {
	day := schedule.Window{From: w.From.Add(-23 * time.Hour), To: w.To}
	d := DailyData{Zone: "z", Window: day, Loc: time.UTC, Archive: &ArchiveInfo{Hours: 600, Days: 25, LongSamples: 25,
		Warming: []analyze.Maturity{{Metric: analyze.MetricUnreachable, Need: 3}}}}
	msg := Daily("zh", d)
	if want := "基线积累中：边缘 52x（源站不可达）——新近开始采集；同时段实测满 3 天前这些线不报警（约 " + day.To.Add(72*time.Hour).Format("01-02") + " 起）"; !strings.Contains(msg, want) {
		t.Fatalf("missing %q in:\n%s", want, msg)
	}
	d.Archive.Warming = nil
	if strings.Contains(Daily("zh", d), "基线积累中") {
		t.Fatal("note repeated without a newly accumulating line")
	}
}

// IP lines carry the IP location when a library is loaded, in the
// report's language, and are unchanged without one.
func TestIPLocationInReports(t *testing.T) {
	in := func(s string) string {
		if s == "106.201.104.211" || s == "106.201.104.0/24" {
			return "IN"
		}
		return ""
	}
	alert := IntradayData{Zone: "z", Window: w, Decision: state.DecAlert,
		Findings: []analyze.Finding{{Rule: analyze.RuleTotalUp, Cur: 60_000, Base: 30_000, Pct: 100}},
		Attr:     analyze.Attribution{TopIPs: []cfapi.Face{{Name: "106.201.104.211", Count: 9000}, {Name: "10.1.2.3", Count: 5}}},
		Block:    analyze.BlockAdvice{Candidates: []analyze.IPShare{{IP: "106.201.104.211", Count: 9000, Share: 0.4}}},
	}
	day := schedule.Window{From: w.From.Add(-23 * time.Hour), To: w.To}
	daily := DailyData{Zone: "z", Window: day, Loc: time.UTC,
		MitigatedIPs: []cfapi.Face{{Name: "106.201.104.211", Count: 700}},
		Blocks: []BlockStatus{{Target: "106.201.104.0/24", Action: "block", Attempts: 3, Since: day.From, ExpiresAt: day.To.Add(48 * time.Hour)},
			{Target: "AS45102", Action: "block", Since: day.From}},
	}

	off := Intraday("en", alert) + Daily("en", daily)
	if strings.Contains(off, "[IN") {
		t.Fatalf("no library, yet a location:\n%s", off)
	}

	geoip.UseFunc(in)
	defer geoip.Reset()
	en := Intraday("en", alert)
	for _, want := range []string{"top client IPs: 106.201.104.211 [IN · India] 9,000, 10.1.2.3 5", "- IP 106.201.104.211 [IN · India]: 9,000 requests"} {
		if !strings.Contains(en, want) {
			t.Errorf("alert lacks %q:\n%s", want, en)
		}
	}
	zh := Daily("zh", daily)
	for _, want := range []string{"  106.201.104.211 [印度 (IN)]: 700", "  106.201.104.0/24 [印度 (IN)] (block): 3", "106.201.104.0/24 [印度 (IN)]（block）", "  AS45102 (block)"} {
		if !strings.Contains(zh, want) {
			t.Errorf("daily lacks %q:\n%s", want, zh)
		}
	}
}
