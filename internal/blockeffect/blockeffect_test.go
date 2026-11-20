package blockeffect

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/playwjj/flarehound/internal/cfapi"
	"github.com/playwjj/flarehound/internal/sim"
	"github.com/playwjj/flarehound/internal/store"
)

func TestVerdicts(t *testing.T) {
	st := func(c403, after int64) []cfapi.Face {
		return []cfapi.Face{{Name: "403", Count: c403}, {Name: "200", Count: after - c403}}
	}
	cases := []struct {
		e    Effect
		kind string
		zh   string
	}{
		{Effect{Settled: true, Measurable: true, Before: 45000, After: 900, AttemptsKnown: true, Attempts: 850}, Gone, "请求 45,000 → 900（-98%），已基本归零；规则拦截尝试 850 次"},
		{Effect{Settled: true, Measurable: true, Before: 10000, After: 3000}, Down, "明显下降"},
		{Effect{Settled: true, Measurable: true, Before: 10000, After: 9500, StatusAfter: st(9000, 9500)}, Stopped, "请求仍在继续，但 95% 被拦下（403）"},
		{Effect{Settled: true, Measurable: true, Before: 10000, After: 9800, StatusAfter: st(500, 9800)}, Unclear, "效果不明显"},
		{Effect{Settled: true, AttemptsKnown: true, Attempts: 12}, NoMeasure, "拦截尝试 12 次"},
		{Effect{Settled: true, Measurable: true, Before: 0, After: 40}, NoBefore, "封禁前一小时没有请求"},
		{Effect{Measurable: true, Before: 100, After: 1}, Pending, "还没到齐"},
	}
	for _, c := range cases {
		k, zh := c.e.Verdict("zh")
		if k != c.kind || !strings.Contains(zh, c.zh) {
			t.Errorf("%+v\n got %s %q", c.e, k, zh)
		}
		if _, en := c.e.Verdict("en"); en == "" || strings.ContainsAny(en, "请求") {
			t.Errorf("english verdict: %q", en)
		}
	}
}

type fake struct{}

func (fake) Count(_ context.Context, _ string, from, _ time.Time, f cfapi.Filter) (int64, error) {
	if f.ASN == 0 {
		return 100000, nil
	}
	if from.Before(time.Unix(1_800_000_000, 0)) {
		return 45000, nil // before
	}
	return 900, nil
}
func (fake) Top(context.Context, string, time.Time, time.Time, string, int, cfapi.Filter) ([]cfapi.Face, error) {
	return []cfapi.Face{{Name: "403", Count: 880}}, nil
}
func (fake) FirewallTop(context.Context, string, time.Time, time.Time, string, string, int) ([]cfapi.Face, error) {
	return []cfapi.Face{{Name: "AS207990", ASN: 207990, Count: 850}}, nil
}

func TestCompute(t *testing.T) {
	at := time.Unix(1_800_000_000, 0)
	ev := store.BlockEvent{ID: 7, At: at, Type: "asn", Value: "207990", RuleID: "r1"}
	e := Compute(context.Background(), fake{}, "z", ev, at.Add(2*time.Hour), 7*time.Minute)
	if !e.Settled || e.Before != 45000 || e.After != 900 || e.Attempts != 850 {
		t.Fatalf("%+v", e)
	}
	if k, _ := e.Verdict("en"); k != Gone {
		t.Fatalf("kind %s", k)
	}
	if e := Compute(context.Background(), fake{}, "z", ev, at.Add(30*time.Minute), 7*time.Minute); e.Settled {
		t.Fatal("partial hour reported as settled")
	}
}

func TestPredictionLine(t *testing.T) {
	e := Effect{Settled: true, AttemptsKnown: true, Attempts: 1320}
	if e.PredictionLine("en") != "" {
		t.Fatal("a line without a prediction")
	}
	e.Predict(&sim.Report{Evaluable: true, NetKnown: true, Net: 1490 * 24, From: time.Unix(0, 0), To: time.Unix(24*3600, 0)})
	if got := e.PredictionLine("zh"); got != "预测净新增 ≈ 1,490 次/小时（确认时的模拟）；实际封禁后一小时拦截 1,320 次 (-11%)" {
		t.Fatalf("got %q", got)
	}
	e.AttemptsKnown = false
	if !strings.Contains(e.PredictionLine("en"), "not countable") {
		t.Fatal(e.PredictionLine("en"))
	}
	var none Effect
	none.Predict(&sim.Report{Evaluable: true}) // no net new: no prediction
	if none.PredictedKnown {
		t.Fatal("predicted without net new")
	}
}
