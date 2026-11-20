package sim

import (
	"context"
	"errors"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/playwjj/flarehound/internal/cfapi"
	"github.com/playwjj/flarehound/internal/waf"
)

func mustTranslate(t *testing.T, expr string, caps cfapi.Caps) compiled {
	t.Helper()
	n, err := waf.Parse(expr)
	if err != nil {
		t.Fatalf("parse %q: %v", expr, err)
	}
	return translate(n, caps)
}

func proCaps() cfapi.Caps {
	f := map[string]bool{}
	for _, d := range []string{"clientIP", "clientAsn", "clientCountryName", "userAgent", "clientRequestPath", "clientRequestHTTPHost",
		"verifiedBotCategory", "clientRefererHost", "clientRequestQuery", "clientRequestHTTPMethodName"} {
		f["dimensions_"+d] = true
	}
	return cfapi.Caps{Probed: true, HTTPFields: f, FirewallEnabled: true, FirewallMaxAge: 30 * 24 * time.Hour}
}

func freeCaps() cfapi.Caps {
	f := map[string]bool{}
	for _, d := range []string{"clientIP", "userAgent", "clientRequestPath", "verifiedBotCategory"} {
		f["dimensions_"+d] = true
	}
	return cfapi.Caps{Probed: true, HTTPFields: f}
}

func TestTranslateExact(t *testing.T) {
	cases := map[string]string{
		`(ip.geoip.asnum eq 30633 and not cf.client.bot)`:                  `AND:[{clientAsn:"30633"},{verifiedBotCategory:""}]`,
		`ip.geoip.asnum in {45102 30633}`:                                  `clientAsn_in:["45102","30633"]`,
		`not (http.user_agent contains "rednote")`:                         `userAgent_notlike:"%rednote%"`,
		`http.user_agent ne "x"`:                                           `userAgent_neq:"x"`,
		`not (ip.src in {1.2.3.4 ::ffff:5.6.7.8})`:                         `clientIP_notin:["1.2.3.4","5.6.7.8"]`,
		`not (a.b eq 1 or http.host eq "x")`:                               "", // a.b is tier 3
		`starts_with(http.request.uri.path, "/plus/")`:                     `clientRequestPath_like:"/plus/%"`,
		`http.request.uri.path starts_with "/plus/"`:                       `clientRequestPath_like:"/plus/%"`,
		`not (http.request.uri.path eq "/a" and ip.geoip.country eq "cn")`: `OR:[{clientRequestPath_neq:"/a"},{clientCountryName_neq:"CN"}]`,
		`cf.client.bot`: `verifiedBotCategory_neq:""`,
	}
	for expr, want := range cases {
		c := mustTranslate(t, expr, proCaps())
		if want == "" {
			if c.httpOK {
				t.Errorf("%s: expected not evaluable, got %s", expr, c.http.render())
			}
			continue
		}
		if !c.httpOK {
			t.Errorf("%s: not evaluable: %+v", expr, c.bad)
			continue
		}
		if got := c.http.render(); got != want {
			t.Errorf("%s:\n got %s\nwant %s", expr, got, want)
		}
		if len(c.approx) != 0 {
			t.Errorf("%s: unexpected widening %+v", expr, c.approx)
		}
	}
}

func TestTranslateTier3Named(t *testing.T) {
	for expr, why := range map[string]string{
		`http.request.headers["x-a"][0] eq "1"`:              whyField,
		`http.user_agent matches "bot.*"`:                    whyOperator,
		`ip.src in $bad_ips`:                                 whyList,
		`ip.src in {10.0.0.0/8}`:                             whyCIDR,
		`lower(http.user_agent) contains "bot"`:              whyFunction,
		`cf.threat_score gt 10`:                              whyField,
		`http.cookie contains "a"`:                           whyField,
		`not (http.referer eq "https://starngage.com/")`:     whyRefNeg,
		`http.referer contains "starngage"`:                  whyRefHost,
		`starts_with(http.referer, "https://starngage.com")`: whyRefHost,
	} {
		c := mustTranslate(t, expr, proCaps())
		if c.httpOK {
			t.Errorf("%s: evaluated, want %s", expr, why)
			continue
		}
		if len(c.bad) == 0 || c.bad[0].Why != why {
			t.Errorf("%s: got %+v, want %s", expr, c.bad, why)
		}
	}
}

func TestTranslateRefererWidened(t *testing.T) {
	c := mustTranslate(t, `(http.request.uri.path starts_with "/plus/" and http.referer eq "https://starngage.com/")`, proCaps())
	if !c.httpOK || len(c.approx) != 1 {
		t.Fatalf("want evaluable with one widening: ok=%v approx=%+v bad=%+v", c.httpOK, c.approx, c.bad)
	}
	if got := c.http.render(); got != `AND:[{clientRequestPath_like:"/plus/%"},{clientRefererHost:"starngage.com"}]` {
		t.Fatalf("got %s", got)
	}
	if !strings.Contains(c.approx[0].Expr, "http.referer") {
		t.Fatalf("widened item should name the referer: %+v", c.approx[0])
	}
	// No referer at all is exact.
	c = mustTranslate(t, `not (http.referer eq "")`, proCaps())
	if !c.httpOK || len(c.approx) != 0 || c.http.render() != `clientRefererHost_neq:""` {
		t.Fatalf("empty referer: %+v %s", c, c.http.render())
	}
}

func TestTranslateFreePlan(t *testing.T) {
	c := mustTranslate(t, `(ip.geoip.asnum eq 45102 and not cf.client.bot)`, freeCaps())
	if c.httpOK || len(c.bad) != 1 || c.bad[0].Why != whyPlan || c.bad[0].Dim != "clientAsn" {
		t.Fatalf("got %+v", c.bad)
	}
	if !strings.Contains(ReasonText(c.bad[0], "zh"), "该区无 ASN 维度") {
		t.Fatalf("reason: %s", ReasonText(c.bad[0], "zh"))
	}
}

// fake answers counts by what the filter contains.
type fake struct {
	mu      sync.Mutex
	caps    cfapi.Caps
	capsErr error
	count   func(where, cache string) int64
	top     func(dim, where string) []cfapi.Face
	fw      func(where string) []cfapi.Face
	calls   int
}

func (f *fake) tick() { f.mu.Lock(); f.calls++; f.mu.Unlock() }

func (f *fake) Count(_ context.Context, _ string, _, _ time.Time, fl cfapi.Filter) (int64, error) {
	f.tick()
	return f.count(fl.Where, fl.CacheStatus), nil
}
func (f *fake) Top(_ context.Context, _ string, _, _ time.Time, dim string, limit int, fl cfapi.Filter) ([]cfapi.Face, error) {
	f.tick()
	if f.top == nil {
		return nil, nil
	}
	out := f.top(dim, fl.Where)
	if len(out) > limit {
		out = out[:limit]
	}
	return out, nil
}
func (f *fake) Hourly(_ context.Context, _ string, from, to time.Time, fl cfapi.Filter) (map[time.Time]int64, error) {
	f.tick()
	n := f.count(fl.Where, "")
	out := map[time.Time]int64{}
	hours := int(to.Sub(from).Hours())
	for i := 0; i < hours; i++ {
		out[from.Add(time.Duration(i)*time.Hour)] = n / int64(hours)
	}
	return out, nil
}
func (f *fake) FirewallGroups(_ context.Context, _ string, _, _ time.Time, _ string, _ int, fl cfapi.Filter) ([]cfapi.Face, error) {
	f.tick()
	if f.fw == nil {
		return nil, nil
	}
	return f.fw(fl.Where), nil
}
func (f *fake) Capabilities(context.Context, string) (cfapi.Caps, error) {
	f.tick()
	return f.caps, f.capsErr
}

var now = time.Date(2026, 11, 18, 0, 30, 0, 0, time.UTC)

// AS30633: ~147k a day, ~111k of it ExaSearchBot (verified), the rest
// the site's own backend and others.
func as30633() *fake {
	return &fake{caps: proCaps(),
		count: func(w, cache string) int64 {
			asn := strings.Contains(w, `clientAsn:"30633"`)
			switch {
			case !asn && cache == "dynamic":
				return 20_000_000
			case !asn:
				return 60_000_000
			case strings.Contains(w, `verifiedBotCategory_neq:""`): // the bot branch
				return 111_493
			case strings.Contains(w, `verifiedBotCategory:""`): // the rule
				if cache == "dynamic" {
					return 30_000
				}
				return 35_807
			default: // gross
				return 147_300
			}
		},
		top: func(dim, w string) []cfapi.Face {
			switch dim {
			case cfapi.DimUserAgent:
				return []cfapi.Face{{Name: "backend/1.0", Count: 32_000}, {Name: "curl/8", Count: 3_807}}
			case cfapi.DimASNNamed:
				return []cfapi.Face{{Name: "AS30633", ASN: 30633, Desc: "LEASEWEB-USA-WDC", Count: 35_807}}
			}
			return nil
		},
		fw: func(w string) []cfapi.Face {
			return []cfapi.Face{{Name: "managed_challenge r1", Count: 7}, {Name: "managed_challenge_solved r1", Count: 5}, {Name: "skip r0", Count: 900}}
		},
	}
}

func TestRunExemptionGap(t *testing.T) {
	api := as30633()
	r, err := Run(context.Background(), api, Input{ZoneID: "z", ZoneName: "starngage.com", Now: now, Days: 1,
		Expr: `(ip.geoip.asnum eq 30633 and not cf.client.bot)`, Action: "challenge"})
	if err != nil {
		t.Fatal(err)
	}
	if !r.Evaluable || !r.HasCore || r.Gross != 147_300 || r.Matched != 35_807 || r.Exempted != 147_300-35_807 {
		t.Fatalf("numbers: %+v", r)
	}
	if n, ok := r.BotExempted(); !ok || n != 111_493 {
		t.Fatalf("bot branch: %+v", r.Branches)
	}
	if !r.NetKnown || r.Handled != 7 || r.Net != 35_800 {
		t.Fatalf("net: known=%v handled=%d net=%d why=%s", r.NetKnown, r.Handled, r.Net, r.NetWhy)
	}
	if r.Confidence != ApproxJoined {
		t.Fatalf("confidence %s", r.Confidence)
	}
	if r.Verdict != WarnTiny {
		t.Fatalf("verdict %s (%+v)", r.Verdict, r.Warnings)
	}
	v := r.VerdictText("zh")
	for _, want := range []string{"毛命中 147,300", "已验证机器人 111,493", "净新增可拦 ≈ 35,800", "建议降级为挑战或不处理"} {
		if !strings.Contains(v, want) {
			t.Errorf("verdict %q lacks %q", v, want)
		}
	}
	if strings.Contains(v, "可拦约 ≈ 147") {
		t.Fatal("gross reported as blockable")
	}
	if r.Queries > MaxQueries {
		t.Fatalf("%d queries > budget", r.Queries)
	}
	if !r.ASNBound || len(r.ASNs) != 1 || r.ASNs[0].Network != "hosting" {
		t.Fatalf("asns: %+v", r.ASNs)
	}
	txt := r.Text("en", time.UTC)
	for _, want := range []string{"Gross", "and not cf.client.bot: 111,493", "Net new", "approximate (includes a cross-dataset estimate)"} {
		if !strings.Contains(txt, want) {
			t.Errorf("text lacks %q:\n%s", want, txt)
		}
	}
}

func rednote(t *testing.T, expr string) *Report {
	api := &fake{caps: proCaps(),
		count: func(w, cache string) int64 {
			if !strings.Contains(w, "45102") {
				return 10_000_000
			}
			if strings.Contains(w, "rednote") && strings.Contains(w, "_notlike") {
				return 20_000
			}
			return 25_500
		},
		top: func(dim, w string) []cfapi.Face {
			if dim != cfapi.DimUserAgent {
				return nil
			}
			out := []cfapi.Face{{Name: "python-requests/2.31", Count: 20_000}}
			if !strings.Contains(w, `userAgent_notlike:"%rednote%"`) {
				out = append(out, cfapi.Face{Name: "Mozilla/5.0 (compatible; rednote/1.0)", Count: 5_500})
			}
			return out
		},
	}
	r, err := Run(context.Background(), api, Input{ZoneID: "z", Now: now, Days: 1, Expr: expr, KnownUAs: []string{"RedNote"}})
	if err != nil {
		t.Fatal(err)
	}
	return r
}

func TestRunKnownSource(t *testing.T) {
	r := rednote(t, `(ip.geoip.asnum eq 45102 and not cf.client.bot)`)
	if len(r.Known) != 1 || r.Known[0].Count != 5_500 || r.Verdict != WarnKnown {
		t.Fatalf("known: %+v verdict %s", r.Known, r.Verdict)
	}
	if !strings.Contains(r.VerdictText("zh"), "已知来源 RedNote") {
		t.Fatalf("verdict: %s", r.VerdictText("zh"))
	}
	r = rednote(t, `(ip.geoip.asnum eq 45102 and not cf.client.bot) and not (http.user_agent contains "rednote")`)
	if len(r.Known) != 0 || r.Verdict == WarnKnown {
		t.Fatalf("after the exemption: %+v verdict %s", r.Known, r.Verdict)
	}
	if len(r.Branches) != 2 {
		t.Fatalf("branches: %+v", r.Branches)
	}
}

func TestRunUpperBound(t *testing.T) {
	api := &fake{caps: proCaps(), count: func(w, c string) int64 {
		if strings.Contains(w, "clientRefererHost") {
			return 29_266
		}
		return 1_000_000
	}}
	r, err := Run(context.Background(), api, Input{ZoneID: "z", Now: now, Days: 1,
		Expr: `(http.request.uri.path starts_with "/plus/" and http.referer eq "https://starngage.com/")`})
	if err != nil {
		t.Fatal(err)
	}
	if r.Confidence != UpperBound || len(r.Widened) != 1 || !strings.Contains(r.Widened[0].Expr, "http.referer") {
		t.Fatalf("confidence %s widened %+v", r.Confidence, r.Widened)
	}
	txt := r.Text("zh", time.UTC)
	if !strings.Contains(txt, "上界") || !strings.Contains(txt, "≤ 29,266") || !strings.Contains(r.VerdictText("en"), "≤ 29,266") {
		t.Fatalf("upper bound not labelled:\n%s\n%s", txt, r.VerdictText("en"))
	}
	if strings.Contains(r.VerdictText("en"), " 29,266 ") && !strings.Contains(r.VerdictText("en"), "≤ 29,266") {
		t.Fatal("an upper bound in an exact tone")
	}
}

func TestRunFreeZone(t *testing.T) {
	api := &fake{caps: freeCaps(), count: func(string, string) int64 { t.Fatal("no count expected"); return 0 }}
	r, err := Run(context.Background(), api, Input{ZoneID: "z", Now: now, Expr: `ip.geoip.asnum eq 45102`})
	if err != nil {
		t.Fatal(err)
	}
	if r.Evaluable || r.Total != 0 || r.Matched != 0 || api.calls != 1 {
		t.Fatalf("free zone: %+v (calls %d)", r, api.calls)
	}
	txt := r.Text("zh", time.UTC)
	if !strings.Contains(txt, "该区无 ASN 维度（clientAsn），不可评估") || !strings.Contains(txt, "不给数") {
		t.Fatalf("text:\n%s", txt)
	}
}

func TestRunNoFirewall(t *testing.T) {
	caps := proCaps()
	caps.FirewallEnabled = false
	api := &fake{caps: caps, count: func(w, c string) int64 {
		if strings.Contains(w, "AND") {
			return 500
		}
		return 1000
	}}
	r, err := Run(context.Background(), api, Input{ZoneID: "z", Now: now, Expr: `http.user_agent contains "x"`})
	if err != nil {
		t.Fatal(err)
	}
	if r.NetKnown || r.NetWhy != "no_firewall" || r.Confidence != Approx {
		t.Fatalf("net: %+v", r)
	}
	if !strings.Contains(r.Text("zh", nil), "净新增不可用") {
		t.Fatal("no-firewall not said")
	}
}

func TestRunParseErrorAndCache(t *testing.T) {
	if _, err := Run(context.Background(), &fake{}, Input{Expr: `(a eq`}); !errors.Is(err, ErrParse) {
		t.Fatalf("got %v", err)
	}
	api := as30633()
	c := NewCache()
	in := Input{ZoneID: "z", Now: now, Days: 1, Expr: `(ip.geoip.asnum eq 30633 and not cf.client.bot)`}
	r1, err := c.Run(context.Background(), api, in)
	if err != nil {
		t.Fatal(err)
	}
	calls := api.calls
	in.Now = now.Add(5 * time.Minute)
	r2, _ := c.Run(context.Background(), api, in)
	if api.calls != calls || !r2.Cached || r2.Net != r1.Net {
		t.Fatalf("cache missed: calls %d → %d", calls, api.calls)
	}
}

func TestMitigating(t *testing.T) {
	for a, want := range map[string]bool{"block": true, "managed_challenge": true, "managedChallenge": true, "jschallenge": true,
		"managed_challenge_solved": false, "challengeSolved": false, "skip": false, "allow": false, "log": false} {
		if Mitigating(a) != want {
			t.Errorf("%s: want %v", a, want)
		}
	}
}

func TestFoldDays(t *testing.T) {
	loc := time.FixedZone("CST", 8*3600)
	from, to := Window(now, 7)
	h := map[time.Time]int64{}
	for x := from; x.Before(to); x = x.Add(time.Hour) {
		h[x] = 1
	}
	ds := foldDays(h, from, to, loc)
	var sum int64
	for _, d := range ds {
		sum += d.Count
	}
	if sum != 168 || len(ds) != 8 || !ds[0].Part || !ds[len(ds)-1].Part {
		t.Fatalf("days: %+v", ds)
	}
}
