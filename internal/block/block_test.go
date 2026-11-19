package block_test

import (
	"context"
	"net/netip"
	"slices"
	"strings"
	"testing"

	"github.com/playwjj/flarehound/internal/block"
	"github.com/playwjj/flarehound/internal/block/fakecf"
	"github.com/playwjj/flarehound/internal/cfapi"
)

func mustT(t *testing.T, typ, v string) block.Target {
	t.Helper()
	tg, err := block.Parse(typ, v)
	if err != nil {
		t.Fatal(err)
	}
	return tg
}

func TestParse(t *testing.T) {
	ok := map[[2]string]string{
		{"ip", "45.13.7.9"}:        "45.13.7.9",
		{"ip", "45.13.7.0/24"}:     "45.13.7.0/24",
		{"ip", "45.13.7.9/24"}:     "45.13.7.0/24",
		{"ip", "45.13.7.9/32"}:     "45.13.7.9",
		{"ip", "::ffff:45.13.7.9"}: "45.13.7.9",
		{"asn", "AS207990"}:        "207990",
		{"asn", "as207990"}:        "207990",
		{"country", "xx"}:          "XX",
		{"ua", "  BadBot/1.0 "}:    "BadBot/1.0",
		{"cidr", "2001:470::1/48"}: "2001:470::/48",
	}
	for in, want := range ok {
		if got := mustT(t, in[0], in[1]); got.Value != want {
			t.Errorf("Parse(%v) = %q, want %q", in, got.Value, want)
		}
	}
	for _, bad := range [][2]string{{"ip", "1.2.3"}, {"ip", "10.0.0.0/4"}, {"asn", "x"}, {"asn", "0"}, {"country", "USA"}, {"ua", "ab"}, {"ua", "a\nb c"}, {"host", "x"}} {
		if _, err := block.Parse(bad[0], bad[1]); err == nil {
			t.Errorf("Parse(%v) accepted", bad)
		}
	}
}

func TestExpressionRoundTrip(t *testing.T) {
	cases := map[block.Type][]string{
		block.IP:      {"45.13.7.9", "45.13.8.0/24"},
		block.ASN:     {"207990", "24940"},
		block.Country: {"XX", "T1"},
		block.UA:      {`Bad"Bot\1`, "curl/8"},
	}
	for typ, vals := range cases {
		expr := block.Expression(typ, vals)
		got, err := block.ParseExpression(typ, expr)
		if err != nil {
			t.Fatalf("%s: %v (%s)", typ, err, expr)
		}
		slices.Sort(got)
		want := slices.Clone(vals)
		slices.Sort(want)
		if !slices.Equal(got, want) {
			t.Errorf("%s: round trip %v -> %s -> %v", typ, vals, expr, got)
		}
	}
	if e := block.Expression(block.ASN, []string{"207990", "24940"}); e != "(ip.geoip.asnum in {24940 207990}) and not cf.client.bot" {
		t.Errorf("ASN expression %s", e)
	}
	// Hand-edited rules are refused, not overwritten.
	for _, edited := range []string{
		"(ip.geoip.asnum in {1}) and not cf.client.bot and http.host eq \"x\"",
		"(ip.geoip.asnum in {1})",
		"(ip.src in {1.2.3.4}) or true",
	} {
		typ := block.ASN
		if strings.HasPrefix(edited, "(ip.src") {
			typ = block.IP
		}
		if _, err := block.ParseExpression(typ, edited); err == nil {
			t.Errorf("accepted hand-edited %q", edited)
		}
	}
}

func TestGuard(t *testing.T) {
	p := block.Protected{
		Cloudflare: block.CloudflareFallback(),
		Origins:    []netip.Addr{netip.MustParseAddr("93.184.216.34")},
		Allow:      []netip.Prefix{netip.MustParsePrefix("8.8.8.0/24")},
		AllowASNs:  map[int]bool{64600: true},
	}
	for _, v := range []string{"10.1.2.3", "192.168.0.0/16", "104.16.1.1", "104.0.0.0/8", "93.184.216.0/24", "8.8.8.8", "203.0.113.7"} {
		if err := p.Check(mustT(t, "ip", v)); err == nil {
			t.Errorf("%s not protected", v)
		}
	}
	if err := p.Check(mustT(t, "ip", "45.13.7.9")); err != nil {
		t.Errorf("ordinary IP refused: %v", err)
	}
	for _, a := range []string{"13335", "64600"} {
		if err := p.Check(mustT(t, "asn", a)); err == nil {
			t.Errorf("AS%s not protected", a)
		}
	}
}

func TestWarningsAndStrongConfirm(t *testing.T) {
	asn := mustT(t, "asn", "4134")
	w := strings.Join(block.Warnings(asn, block.Block, "eyeball", 0.005, true), "\n")
	for _, want := range []string{"will not resolve", "real users", "Challenge is the default"} {
		if !strings.Contains(w, want) {
			t.Errorf("warnings lack %q: %s", want, w)
		}
	}
	if strong, v := block.NeedsStrongConfirm(asn, block.Block, "eyeball"); !strong || v != "4134" {
		t.Error("eyeball ASN block must need strong confirmation")
	}
	if strong, _ := block.NeedsStrongConfirm(asn, block.Challenge, "eyeball"); strong {
		t.Error("challenge needs no strong confirmation")
	}
	if strong, _ := block.NeedsStrongConfirm(mustT(t, "asn", "24940"), block.Block, "hosting"); strong {
		t.Error("hosting ASN block needs no strong confirmation")
	}
}

func apply(t *testing.T, m *block.Manager, tg block.Target, a block.Action) block.Plan {
	t.Helper()
	st, err := m.Load(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	p, err := st.PlanBlock(tg, a)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := m.Apply(context.Background(), st, p, "test"); err != nil {
		t.Fatal(err)
	}
	return p
}

func TestManagerLifecycle(t *testing.T) {
	cf := fakecf.New("pro", 20)
	cf.UserRule("my login challenge", `http.request.uri.path eq "/login"`)
	m := &block.Manager{API: cf, ZoneID: "z", AccountID: "acct"}
	ctx := context.Background()

	// ASN: creates one rule, ahead of the user's protective rule (no skip
	// rules here) — a confirmed target is not challenged first.
	p := apply(t, m, mustT(t, "asn", "207990"), block.Challenge)
	if p.Op != block.OpCreateRule {
		t.Fatalf("op %s", p.Op)
	}
	// Second ASN merges into the same rule.
	p = apply(t, m, mustT(t, "asn", "24940"), block.Challenge)
	if p.Op != block.OpUpdateRule {
		t.Fatalf("op %s", p.Op)
	}
	r, _ := cf.Rule("flarehound-asn-challenge")
	if r.Expression != "(ip.geoip.asnum in {24940 207990}) and not cf.client.bot" || r.Action != "managed_challenge" {
		t.Fatalf("rule %+v", r)
	}
	if u := cf.RS.Rules[1]; u.Description != "my login challenge" || u.Expression != `http.request.uri.path eq "/login"` || len(cf.RS.Rules) != 2 {
		t.Fatalf("user rule touched, or FlareHound's not placed first: %v", cf.Order())
	}

	// IP block: list + rule.
	p = apply(t, m, mustT(t, "ip", "45.13.7.9"), block.Block)
	if p.Op != block.OpCreateListRule {
		t.Fatalf("op %s", p.Op)
	}
	p = apply(t, m, mustT(t, "ip", "45.13.8.0/24"), block.Block)
	if p.Op != block.OpAddListItem {
		t.Fatalf("op %s", p.Op)
	}

	// Same target again: no-op; other action: refused.
	st, _ := m.Load(ctx)
	if p, _ := st.PlanBlock(mustT(t, "asn", "207990"), block.Challenge); p.Op != block.OpNone {
		t.Fatal("re-block must be a no-op")
	}
	if _, err := st.PlanBlock(mustT(t, "asn", "207990"), block.Block); err == nil {
		t.Fatal("changing action in place must be refused")
	}

	es, err := st.Entries()
	if err != nil || len(es) != 4 {
		t.Fatalf("entries %+v %v", es, err)
	}

	// Unblock: rule shrinks, then disappears when empty (quota freed).
	if _, err := m.Unblock(ctx, st, mustT(t, "asn", "207990")); err != nil {
		t.Fatal(err)
	}
	st, _ = m.Load(ctx)
	if _, err := m.Unblock(ctx, st, mustT(t, "asn", "24940")); err != nil {
		t.Fatal(err)
	}
	if _, ok := cf.Rule("flarehound-asn-challenge"); ok {
		t.Fatal("empty rule not deleted")
	}
	st, _ = m.Load(ctx)
	_, _ = m.Unblock(ctx, st, mustT(t, "ip", "45.13.7.9"))
	st, _ = m.Load(ctx)
	_, _ = m.Unblock(ctx, st, mustT(t, "ip", "45.13.8.0/24"))
	if _, ok := cf.Rule("flarehound-ip-block"); ok {
		t.Fatal("list rule kept with an empty list")
	}
	if len(cf.RS.Rules) != 1 {
		t.Fatalf("leftover rules: %+v", cf.RS.Rules)
	}
	st, _ = m.Load(ctx)
	if _, err := m.Unblock(ctx, st, mustT(t, "asn", "1")); err == nil {
		t.Fatal("unblocking an unknown target must fail")
	}
}

func TestEntrypointCreatedOnlyWhenAbsent(t *testing.T) {
	cf := fakecf.New("free", 5)
	m := &block.Manager{API: cf, ZoneID: "z", AccountID: "acct"}
	apply(t, m, mustT(t, "ua", "BadBot/1.0"), block.Block)
	if cf.Calls[0] != "create_entrypoint flarehound-ua-block" {
		t.Fatalf("calls %v", cf.Calls)
	}
}

func TestQuotaFallbacks(t *testing.T) {
	cf := fakecf.New("free", 5)
	for i := 0; i < 5; i++ {
		cf.UserRule("user rule", "true")
	}
	m := &block.Manager{API: cf, ZoneID: "z", AccountID: "acct"}
	st, _ := m.Load(context.Background())

	p, err := st.PlanBlock(mustT(t, "asn", "207990"), block.Challenge)
	if err != nil || p.Op != block.OpCreateAccessRule || !strings.Contains(p.Note, "NOT exempt") {
		t.Fatalf("ASN on full quota: %+v %v", p, err)
	}
	apply(t, m, mustT(t, "ip", "45.13.7.9"), block.Block)
	if len(cf.Access) != 1 || cf.Access[0].Configuration.Target != "ip" || !strings.HasPrefix(cf.Access[0].Notes, block.AccessNotes) {
		t.Fatalf("access rules %+v", cf.Access)
	}
	if _, err := st.PlanBlock(mustT(t, "country", "XX"), block.Challenge); err == nil {
		t.Fatal("country on full quota must fail (no fallback)")
	}
	if _, err := st.PlanBlock(mustT(t, "ip", "45.13.0.0/20"), block.Block); err == nil {
		t.Fatal("/20 cannot be an access rule")
	}
}

func TestListCreationFailureFallsBackToExpression(t *testing.T) {
	cf := fakecf.New("free", 5)
	cf.FailCreateList = true
	m := &block.Manager{API: cf, ZoneID: "z", AccountID: "acct"}
	apply(t, m, mustT(t, "ip", "45.13.7.9"), block.Block)
	r, ok := cf.Rule("flarehound-ip-block")
	if !ok || r.Expression != "(ip.src in {45.13.7.9})" {
		t.Fatalf("rule %+v", r)
	}
	// Next IP merges into the expression rule.
	p := apply(t, m, mustT(t, "ip", "45.13.7.10"), block.Block)
	if p.Op != block.OpUpdateRule {
		t.Fatalf("op %s", p.Op)
	}
}

func TestMatchesAndCommand(t *testing.T) {
	if !block.Matches(mustT(t, "ip", "45.13.8.0/24"), cfapi.Face{Name: "45.13.8.77"}) {
		t.Error("CIDR match")
	}
	if !block.Matches(mustT(t, "ua", "BadBot"), cfapi.Face{Name: "Mozilla BadBot/2"}) {
		t.Error("UA contains")
	}
	if !block.Matches(mustT(t, "asn", "207990"), cfapi.Face{ASN: 207990}) {
		t.Error("ASN")
	}
	if c := block.Command(mustT(t, "asn", "207990"), block.Block, "24h", "it's bad"); c != `flarehound block asn 207990 --action block --for 24h --reason 'it'\''s bad'` {
		t.Errorf("command %s", c)
	}
	if c := block.Command(mustT(t, "ua", "Bad Bot"), block.Block, "", ""); c != `flarehound block ua 'Bad Bot'` {
		t.Errorf("command %s", c)
	}
}

func TestMissingPermissionsDegrade(t *testing.T) {
	cf := fakecf.New("free", 5)
	cf.DenyLists, cf.DenyAccess = true, true
	m := &block.Manager{API: cf, ZoneID: "z", AccountID: "acct"}
	st, err := m.Load(context.Background())
	if err != nil || !st.NoLists || !st.NoAccess {
		t.Fatalf("load: %+v %v", st, err)
	}
	// IP block without list permission: expression rule.
	p := apply(t, m, mustT(t, "ip", "45.13.7.9"), block.Block)
	if p.Op != block.OpCreateRule {
		t.Fatalf("op %s", p.Op)
	}
	for i := 0; i < 4; i++ {
		cf.UserRule("user", "true")
	}
	st, _ = m.Load(context.Background())
	if _, err := st.PlanBlock(mustT(t, "asn", "64496"), block.Challenge); err == nil || !strings.Contains(err.Error(), "Zone → WAF: Edit") {
		t.Fatalf("full quota without access-rule permission: %v", err)
	}
}

// The 2026-11-19 starngage case: a new IP block landed last (#18), behind
// the challenge rule #13, so the confirmed IP kept eating challenges.
// Placement: after every skip rule, before the first user challenge/block.
func TestPlacement(t *testing.T) {
	cf := fakecf.New("pro", 20)
	cf.UserRuleAction("allow own services", "skip", `ip.src in {203.0.113.7}`)
	cf.UserRuleAction("UA allowlist", "skip", `http.user_agent contains "StarngageBot"`)
	cf.UserRuleAction("log api", "log", `http.request.uri.path eq "/api"`)
	cf.UserRuleAction("Protected Pages", "managed_challenge", `http.request.uri.path eq "/login"`)
	cf.UserRuleAction("block bad paths", "block", `http.request.uri.path eq "/wp-admin"`)
	m := &block.Manager{API: cf, ZoneID: "z", AccountID: "acct"}
	ctx := context.Background()

	st, _ := m.Load(ctx)
	ip := mustT(t, "ip", "106.201.104.211")
	p, err := st.PlanBlock(ip, block.Block)
	if err != nil {
		t.Fatal(err)
	}
	if p.Place.Pos != 4 || p.Place.Skips != 2 || p.Place.Before == nil || p.Place.Before.Description != "Protected Pages" {
		t.Fatalf("placement %+v", p.Place)
	}
	if d := p.Place.Describe(); !strings.Contains(d, "inserted at #4, after «log api» (log) and before «Protected Pages» (managed_challenge)") {
		t.Fatal(d)
	}
	e, err := m.Apply(ctx, st, p, "test")
	if err != nil {
		t.Fatal(err)
	}
	want := []string{"allow own services", "UA allowlist", "log api", "flarehound-ip-block", "Protected Pages", "block bad paths"}
	if !slices.Equal(cf.Order(), want) || e.Pos != 4 {
		t.Fatalf("order %v (read back #%d)", cf.Order(), e.Pos)
	}

	// Adding members does not move the rule.
	cf.Calls = nil
	apply(t, m, mustT(t, "ip", "45.13.7.9"), block.Block)
	if slices.ContainsFunc(cf.Calls, func(c string) bool { return strings.HasPrefix(c, "move_rule") }) || !slices.Equal(cf.Order(), want) {
		t.Fatalf("moved on a member add: %v %v", cf.Calls, cf.Order())
	}

	// A FlareHound rule created before v1.16 sits last: moved once.
	cf2 := fakecf.New("pro", 20)
	cf2.UserRuleAction("UA allowlist", "skip", `http.user_agent contains "StarngageBot"`)
	cf2.UserRuleAction("Protected Pages", "managed_challenge", `http.request.uri.path eq "/login"`)
	m2 := &block.Manager{API: cf2, ZoneID: "z", AccountID: "acct"}
	cf2.RS.Rules = append(cf2.RS.Rules, cfapi.Rule{ID: "old", Ref: "flarehound-asn-block", Description: "flarehound-asn-block (managed by FlareHound)",
		Action: "block", Expression: "(ip.geoip.asnum in {45102}) and not cf.client.bot", Enabled: true})
	st2, _ := m2.Load(ctx)
	p2, err := st2.PlanBlock(mustT(t, "asn", "24560"), block.Block)
	if err != nil {
		t.Fatal(err)
	}
	if !p2.Place.Move || p2.Place.From != 3 || p2.Place.Pos != 2 || !strings.Contains(p2.Place.Describe(), "moves once from #3 to #2") {
		t.Fatalf("%+v %s", p2.Place, p2.Place.Describe())
	}
	if _, err := m2.Apply(ctx, st2, p2, "test"); err != nil {
		t.Fatal(err)
	}
	if got := cf2.Order(); !slices.Equal(got, []string{"UA allowlist", "flarehound-asn-block", "Protected Pages"}) {
		t.Fatalf("order %v", got)
	}
	st2, _ = m2.Load(ctx)
	if p3, _ := st2.PlanBlock(mustT(t, "asn", "30058"), block.Block); p3.Place.Move || !strings.Contains(p3.Place.Describe(), "stays at #2") {
		t.Fatalf("second add must not move: %+v", p3.Place)
	}
}

// A target that carries the allowlisted user agent would be skipped
// before it reaches the block: review must say so.
func TestBypassWarning(t *testing.T) {
	cf := fakecf.New("pro", 20)
	cf.UserRuleAction("UA allowlist", "skip", `http.user_agent contains "StarngageBot"`)
	cf.UserRuleAction("own monitor", "skip", `ip.src eq 198.51.100.9`)
	cf.UserRuleAction("Protected Pages", "managed_challenge", `http.request.uri.path eq "/login"`)
	m := &block.Manager{API: cf, ZoneID: "z", AccountID: "acct"}
	st, _ := m.Load(context.Background())
	ip := mustT(t, "ip", "106.201.104.211")
	p, _ := st.PlanBlock(ip, block.Block)
	profile := []cfapi.Face{{Name: "Mozilla/5.0 StarngageBot/2.1", Count: 300}, {Name: "curl/8", Count: 100}}
	bs := st.Bypasses(ip, p.RuleRef, p.Place.Pos, profile)
	if len(bs) != 1 || bs[0].Pos != 1 || bs[0].Share != 0.75 || !strings.Contains(bs[0].String(), "skip rule #1 «UA allowlist» (skip)") {
		t.Fatalf("%+v", bs)
	}
	// The monitor's IP itself is skipped by its own rule.
	mon := mustT(t, "ip", "198.51.100.9")
	if bs := st.Bypasses(mon, p.RuleRef, p.Place.Pos, nil); len(bs) != 1 || bs[0].Pos != 2 || bs[0].UA != "" {
		t.Fatalf("%+v", bs)
	}
	// An ordinary crawler is not.
	if bs := st.Bypasses(ip, p.RuleRef, p.Place.Pos, []cfapi.Face{{Name: "curl/8", Count: 1}}); len(bs) != 0 {
		t.Fatalf("%+v", bs)
	}
}
