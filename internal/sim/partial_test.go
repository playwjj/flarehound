package sim

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/playwjj/flarehound/internal/cfapi"
)

func partialAPI() *fake {
	return &fake{caps: proCaps(),
		count: func(w, c string) int64 {
			switch {
			case strings.Contains(w, "30633") && strings.Contains(w, "OR:"):
				return 12_000 // asn or bot-ish UA
			case strings.Contains(w, "30633"):
				return 10_000
			}
			return 1_000_000
		},
		fw: func(w string) []cfapi.Face {
			return []cfapi.Face{{Name: "block r1", Count: 400}}
		},
	}
}

func TestPartialConjunction(t *testing.T) {
	api := partialAPI()
	r, err := Run(context.Background(), api, Input{ZoneID: "z", Now: now, Days: 1,
		Expr: `ip.geoip.asnum eq 30633 and http.cookie contains "sess"`})
	if err != nil {
		t.Fatal(err)
	}
	if !r.Evaluable || !r.Partial || r.Matched != 10_000 || !r.LowKnown || r.MatchedLow != 0 {
		t.Fatalf("bounds: %+v", r)
	}
	// Nothing is certain to match, so nothing is certainly stopped: net new
	// is the upper matches, as an upper bound — no firewall query at all.
	if !r.NetKnown || r.Handled != 0 || r.Net != 10_000 || !r.NetUpper || r.Confidence != UpperBound {
		t.Fatalf("net: known=%v handled=%d net=%d upper=%v conf=%s", r.NetKnown, r.Handled, r.Net, r.NetUpper, r.Confidence)
	}
	if len(r.Terms) != 2 || r.Terms[0].Status != TermExact || r.Terms[1].Status != TermUnknown {
		t.Fatalf("terms: %+v", r.Terms)
	}
	v := r.VerdictText("zh")
	if !strings.Contains(v, "命中介于 0 与 ≤ 10,000 之间") || !strings.Contains(v, "净新增可拦 ≤ 10,000") {
		t.Fatalf("verdict: %s", v)
	}
	txt := r.Text("zh", time.UTC)
	for _, want := range []string{"子项标注", "✓ ip.geoip.asnum eq 30633", "? http.cookie contains \"sess\"", "上界按命中计，下界按不命中计", "至少：        0"} {
		if !strings.Contains(txt, want) {
			t.Errorf("text lacks %q:\n%s", want, txt)
		}
	}
}

func TestPartialDisjunction(t *testing.T) {
	api := partialAPI()
	// The unknown term widens an OR to the whole zone: no numbers.
	r, _ := Run(context.Background(), api, Input{ZoneID: "z", Now: now, Days: 1, Expr: `ip.geoip.asnum eq 30633 or http.cookie contains "x"`})
	if r.Evaluable || len(r.Unevaluable) != 1 || !strings.Contains(r.Unevaluable[0].Expr, "http.cookie") {
		t.Fatalf("unbounded OR: %+v", r)
	}
	// A bounded OR: lower bound = the exact branch, measured.
	r, _ = Run(context.Background(), api, Input{ZoneID: "z", Now: now, Days: 1,
		Expr: `ip.geoip.asnum eq 30633 or (http.user_agent contains "bot" and http.cookie contains "x")`})
	if !r.Evaluable || !r.Partial || r.Matched != 12_000 || !r.LowKnown || r.MatchedLow != 10_000 {
		t.Fatalf("bounded OR: matched %d low %d", r.Matched, r.MatchedLow)
	}
	// Certain part: the firewall events are read over the lower bound.
	if r.Handled != 400 || r.Net != 12_000-400 || !r.NetUpper {
		t.Fatalf("net: handled %d net %d", r.Handled, r.Net)
	}
}

// A plan gap is not bounded: the Free-zone acceptance stays "no numbers".
func TestPartialPlanGapStaysUnsupported(t *testing.T) {
	api := &fake{caps: freeCaps(), count: func(string, string) int64 { t.Fatal("no count expected"); return 0 }}
	r, _ := Run(context.Background(), api, Input{ZoneID: "z", Now: now, Expr: `ip.geoip.asnum eq 45102 and http.cookie contains "x"`})
	if r.Evaluable || r.Partial {
		t.Fatalf("plan gap evaluated: %+v", r)
	}
	if len(r.Terms) != 2 || r.Terms[0].Status != TermUnsupported || r.Terms[1].Status != TermUnknown {
		t.Fatalf("terms: %+v", r.Terms)
	}
	if txt := r.Text("zh", nil); !strings.Contains(txt, "✗ ip.geoip.asnum eq 45102") || !strings.Contains(txt, "不给数") {
		t.Fatalf("text:\n%s", txt)
	}
}

func TestBoundFolding(t *testing.T) {
	u := gnode{unknown: true}
	a := gnode{leaf: "a:1"}
	g := or(and(a, u), and(gnode{leaf: "b:1"}, u))
	if got := bound(g, false); !got.none {
		t.Fatalf("lower: %+v", got)
	}
	if got := bound(g, true).render(); got != `OR:[{a:1},{b:1}]` {
		t.Fatalf("upper: %s", got)
	}
	if !bound(or(a, u), true).all || bound(or(a, u), false).render() != "a:1" {
		t.Fatal("or folding")
	}
}
