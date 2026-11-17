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
