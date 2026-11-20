package sim

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/playwjj/flarehound/internal/cfapi"
)

type fakeLists struct {
	err   error
	lists []cfapi.List
	items map[string][]cfapi.ListItem
}

func (f fakeLists) Lists(context.Context, string) ([]cfapi.List, error) { return f.lists, f.err }
func (f fakeLists) ListItems(_ context.Context, _, id string) ([]cfapi.ListItem, error) {
	return f.items[id], nil
}

func lists() fakeLists {
	return fakeLists{
		lists: []cfapi.List{{ID: "1", Name: "bad_ips", Kind: "ip", NumItems: 2}, {ID: "2", Name: "clouds", Kind: "asn", NumItems: 2},
			{ID: "3", Name: "ranges", Kind: "ip", NumItems: 1}, {ID: "4", Name: "hosts", Kind: "hostname", NumItems: 1}},
		items: map[string][]cfapi.ListItem{
			"1": {{IP: "203.0.113.7"}, {IP: "2001:db8::1/128"}},
			"2": {{ASN: 45102}, {ASN: 30633}},
			"3": {{IP: "198.51.100.0/24"}},
		},
	}
}

func TestListExpansion(t *testing.T) {
	api := &fake{caps: proCaps(), count: func(w, c string) int64 { return 100 }}
	run := func(expr string, la ListAPI, account string) *Report {
		t.Helper()
		r, err := Run(context.Background(), api, Input{ZoneID: "z", Now: now, Days: 1, Expr: expr, Lists: la, AccountID: account})
		if err != nil {
			t.Fatal(err)
		}
		return r
	}
	r := run(`ip.src in $bad_ips and not ip.geoip.asnum in $clouds`, lists(), "acc")
	if !r.Evaluable || len(r.Lists) != 2 || r.Lists[0].Items != 2 {
		t.Fatalf("expanded: %+v %+v", r.Lists, r.Unevaluable)
	}
	c := mustTranslateLists(t, `ip.src in $bad_ips and not ip.geoip.asnum in $clouds`, lists())
	if got := c.http.render(); got != `AND:[{clientIP_in:["203.0.113.7","2001:db8::1"]},{clientAsn_notin:["45102","30633"]}]` {
		t.Fatalf("render: %s", got)
	}
	for expr, why := range map[string]string{
		`ip.src in $cf.open_proxies`: whyListManaged,
		`ip.src in $ranges`:          whyListRange,
		`ip.src in $nope`:            whyListMissing,
		`http.host in $hosts`:        whyListKind,
	} {
		r := run(expr, lists(), "acc")
		if r.Evaluable || len(r.Unevaluable) != 1 || r.Unevaluable[0].Why != why {
			t.Errorf("%s: %+v", expr, r.Unevaluable)
		}
	}
	// No account, or a token that cannot read lists: named, not evaluable.
	for _, r := range []*Report{run(`ip.src in $bad_ips`, lists(), ""), run(`ip.src in $bad_ips`, fakeLists{err: errors.New("403")}, "acc")} {
		if r.Evaluable || r.Unevaluable[0].Why != whyListAccess {
			t.Errorf("access: %+v", r.Unevaluable)
		}
	}
}

func mustTranslateLists(t *testing.T, expr string, la ListAPI) compiled {
	t.Helper()
	n, err := Parse(expr)
	if err != nil {
		t.Fatal(err)
	}
	res, _ := resolveLists(context.Background(), n, la, "acc")
	return translate(n, proCaps(), res)
}

type fakeRules struct{ rules []cfapi.Rule }

func (f fakeRules) Entrypoint(context.Context, string) (cfapi.Ruleset, bool, error) {
	return cfapi.Ruleset{ID: "rs", Rules: f.rules}, true, nil
}

func skipRule(id, expr string, logs bool) cfapi.Rule {
	return cfapi.Rule{ID: id, Action: "skip", Enabled: true, Expression: expr, Description: "allow " + id,
		ActionParameters: &cfapi.ActionParameters{Ruleset: "current"}, Logging: &cfapi.RuleLogging{Enabled: logs}}
}

func TestPositionAndSkips(t *testing.T) {
	rules := []cfapi.Rule{
		skipRule("s1", `http.user_agent contains "Uptime"`, true),
		skipRule("s2", `http.user_agent contains "Partner"`, false),
		{ID: "c3", Action: "managed_challenge", Enabled: true, Expression: `ip.geoip.country eq "XX"`, Description: "Protected Pages"},
	}
	api := &fake{caps: proCaps(),
		count: func(w, c string) int64 {
			switch {
			case strings.Contains(w, "Partner"):
				return 2_000
			case strings.Contains(w, "30633"):
				return 10_000
			}
			return 10_000_000
		},
		fw: func(string) []cfapi.Face {
			return []cfapi.Face{{Name: "skip s1", Count: 3_000}, {Name: "managed_challenge c3", Count: 100},
				{Name: "managed_challenge_non_interactive_solved c3", Count: 60}, {Name: "managed_challenge_bypassed c3", Count: 20}}
		},
	}
	in := Input{ZoneID: "z", Now: now, Days: 1, Expr: `ip.geoip.asnum eq 30633`, RulesAPI: fakeRules{rules}, Action: "block"}
	r, err := Run(context.Background(), api, in)
	if err != nil {
		t.Fatal(err)
	}
	if !r.PositionKnown || r.Position != 3 || !strings.Contains(r.PosBefore, "Protected Pages") {
		t.Fatalf("position: %d %q %s", r.Position, r.PosBefore, r.PositionWhy)
	}
	if len(r.Skips) != 2 || r.SkippedAhead != 5_000 || r.Handled != 100 || r.Net != 10_000-100-5_000 {
		t.Fatalf("skips: %+v skipped %d handled %d net %d", r.Skips, r.SkippedAhead, r.Handled, r.Net)
	}
	if !r.Skips[1].NoLog || r.Skips[1].Count != 2_000 || r.NetUpper {
		t.Fatalf("non-logging skip: %+v", r.Skips[1])
	}
	if r.Chal.Issued != 100 || r.Chal.Solved != 60 || r.Chal.Bypassed != 20 {
		t.Fatalf("challenges: %+v", r.Chal)
	}
	lo, hi := r.Chal.Range()
	if lo != 0.6 || hi < 0.66 || hi > 0.67 {
		t.Fatalf("range %v–%v", lo, hi)
	}
	var skipWarn, blockWarn bool
	for _, w := range r.Warnings {
		skipWarn = skipWarn || w.Code == WarnSkipped
		blockWarn = blockWarn || (w.Code == WarnBlockAll && strings.Contains(r.WarnText(w, "en"), "60%–67%"))
	}
	if !skipWarn || !blockWarn {
		t.Fatalf("warnings: %+v", r.Warnings)
	}
	if txt := r.Text("en", time.UTC); !strings.Contains(txt, "position #3") || !strings.Contains(txt, "#2 «allow s2» (skip): 2,000 (logs nothing") {
		t.Fatalf("text:\n%s", txt)
	}

	// Before rule #1: nothing ahead.
	in.Before = 1
	r, _ = Run(context.Background(), api, in)
	if r.Position != 1 || !r.PositionChosen || len(r.Skips) != 0 || r.Net != 10_000-100 {
		t.Fatalf("before #1: %+v net %d", r.Skips, r.Net)
	}

	// A non-logging skip that cannot be translated: net new is an upper bound.
	rules[1] = skipRule("s2", `any(http.request.headers["x-partner"][*] eq "1")`, false)
	in.Before = 0
	r, _ = Run(context.Background(), api, in)
	if !r.NetUpper || r.Confidence != UpperBound || r.NetMark() != "≤" || r.Upper() {
		t.Fatalf("upper: netUpper=%v conf=%s", r.NetUpper, r.Confidence)
	}
	if !strings.Contains(r.VerdictText("en"), "net new ≤") {
		t.Fatalf("verdict: %s", r.VerdictText("en"))
	}
}

func TestPositionUnknown(t *testing.T) {
	r, _ := Run(context.Background(), as30633(), Input{ZoneID: "z", Now: now, Days: 1, Expr: `ip.geoip.asnum eq 30633`})
	if r.PositionKnown || r.PositionWhy != "no_rules" || !strings.Contains(r.Text("en", nil), "not this rule's position") {
		t.Fatalf("without rules: %+v", r.PositionWhy)
	}
}

// Firewall events that cover only part of the window: lead with the daily
// rate (extrapolated), the covered part's count in a footnote.
func TestNetPartialCoverage(t *testing.T) {
	api := as30633()
	api.caps.FirewallMaxAge = 12 * time.Hour // reaches back half the day
	r, err := Run(context.Background(), api, Input{ZoneID: "z", Now: now, Days: 1, Expr: `(ip.geoip.asnum eq 30633 and not cf.client.bot)`})
	if err != nil {
		t.Fatal(err)
	}
	if r.NetFrom.IsZero() {
		t.Fatal("expected partial coverage")
	}
	head := r.NetHead("zh")
	if !strings.Contains(head, "次/日（按覆盖段外推）") || !strings.Contains(r.VerdictText("zh"), "次/日（按防火墙事件覆盖段外推，占总量") {
		t.Fatalf("head %q verdict %q", head, r.VerdictText("zh"))
	}
	foot := r.NetFoot("zh", time.UTC)
	if !strings.Contains(foot, "这一段的净新增为 ≈ "+N(r.Net)) || !strings.Contains(foot, "日值据此外推") {
		t.Fatalf("foot %q", foot)
	}
}
