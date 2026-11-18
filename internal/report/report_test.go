package report

import (
	"strings"
	"testing"
	"time"

	"github.com/playwjj/flarehound/internal/analyze"
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
