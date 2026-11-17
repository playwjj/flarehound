package waf

import "testing"

// Real rules from a live zone (2026-11-17).
const (
	realWP  = `(http.host in {"404401.xyz" "www.404401.xyz" "blog.404401.xyz"}) and (lower(http.request.uri.path) contains "wp-json" or lower(http.request.uri.path) contains "wp-admin" or lower(http.request.uri.path) contains "wp-login" or lower(http.request.uri.path) contains "wp-content" or lower(http.request.uri.path) contains "wp-includes" or lower(http.request.uri.path) contains "/wp/" or lower(http.request.uri.path) contains "wordpress")`
	realPHP = `(http.host in {"404401.xyz" "www.404401.xyz" "blog.404401.xyz"}) and (ends_with(lower(http.request.uri.path), ".php") or lower(http.request.uri.path) contains "/.env" or lower(http.request.uri.path) contains "/.git")`
	realUA  = `(http.host in {"404401.xyz" "www.404401.xyz" "blog.404401.xyz"}) and (lower(http.user_agent) contains "ahrefsbot")`
)

func mustParse(t *testing.T, s string) Node {
	t.Helper()
	n, err := Parse(s)
	if err != nil {
		t.Fatalf("parse %q: %v", s, err)
	}
	return n
}

func TestParseVariety(t *testing.T) {
	for _, s := range []string{
		realWP, realPHP, realUA,
		`ip.src in {1.2.3.4 10.0.0.0/8 2001:db8::/32}`,
		`ip.geoip.asnum in {13335 209242} and not cf.client.bot`,
		`http.request.uri.path ~ "^/api/v[0-9]+/"`,
		`http.request.uri.path matches r"^/a\d+"`,
		`http.request.uri.path wildcard r#"/x/*"#`,
		`http.request.uri.path strict wildcard "/A/*"`,
		`any(http.request.headers["x-api-key"][*] eq "s3cret")`,
		`ip.src in $office_ips || (cf.threat_score gt 10 && !ssl)`,
		`http.response.code in {500..599}`,
		`(http.request.method eq "POST" xor http.request.method eq "PUT")`,
		`true`,
	} {
		mustParse(t, s)
	}
	for _, bad := range []string{`(a eq "x"`, `a eq`, `"unterminated`, `a in {"x"`} {
		if _, err := Parse(bad); err == nil {
			t.Errorf("accepted %q", bad)
		}
	}
}

func TestEvalRealRules(t *testing.T) {
	wp, php, ua := mustParse(t, realWP), mustParse(t, realPHP), mustParse(t, realUA)
	apex := func(path string) Probe { return Probe{"http.host": "404401.xyz", "http.request.uri.path": path} }
	cases := []struct {
		n    Node
		p    Probe
		want Tri
	}{
		{wp, apex("/wp-login.php"), True},
		{wp, apex("/WP-Admin/x"), True},
		{wp, apex("/login"), False},
		{wp, Probe{"http.host": "api.404401.xyz", "http.request.uri.path": "/wp-admin"}, False},
		{wp, Probe{"http.request.uri.path": "/wp-admin"}, Unknown}, // host not fixed
		{php, apex("/index.php"), True},
		{php, apex("/.git/config"), True},
		{php, apex("/"), False},
		{ua, apex("/login"), Unknown}, // depends on UA
		{ua, Probe{"http.host": "404401.xyz", "http.user_agent": "AhrefsBot/7"}, True},
	}
	for i, c := range cases {
		if got := Eval(c.n, c.p); got != c.want {
			t.Errorf("case %d: got %s want %s", i, got, c.want)
		}
	}
}

func TestEvalOperators(t *testing.T) {
	p := Probe{"http.request.uri.path": "/api/v2/users"}
	for s, want := range map[string]Tri{
		`http.request.uri.path wildcard "/API/*"`:             True,
		`http.request.uri.path strict wildcard "/API/*"`:      False,
		`http.request.uri.path ~ "^/api/v[0-9]+/"`:            True,
		`starts_with(http.request.uri.path, "/api")`:          True,
		`not starts_with(http.request.uri.path, "/api")`:      False,
		`http.request.uri.path ne "/x" and ip.src eq 1.2.3.4`: Unknown,
		`http.request.uri.path eq "/x" and ip.src eq 1.2.3.4`: False,
		`http.request.uri.path eq "/x" or ip.src in $lst`:     Unknown,
		`http.request.uri.path in {"/a" "/api/v2/users"}`:     True,
	} {
		if got := Eval(mustParse(t, s), p); got != want {
			t.Errorf("%s: got %s want %s", s, got, want)
		}
	}
}

func TestImplies(t *testing.T) {
	broad := mustParse(t, `http.host eq "a" and (starts_with(http.request.uri.path, "/x") or starts_with(http.request.uri.path, "/y"))`)
	narrow := mustParse(t, `starts_with(http.request.uri.path, "/x") and http.host eq "a" and http.request.method eq "POST"`)
	if !Implies(narrow, broad) {
		t.Error("narrow should imply broad")
	}
	if Implies(broad, narrow) {
		t.Error("broad does not imply narrow")
	}
	same1 := mustParse(t, `a eq "1" and b eq "2"`)
	same2 := mustParse(t, `(b eq "2") and (a eq "1")`)
	if !Implies(same1, same2) || !Implies(same2, same1) {
		t.Error("reordered conjunction must be equivalent")
	}
}

func TestFields(t *testing.T) {
	f := Fields(mustParse(t, `any(http.request.headers["x-k"][*] eq "s") and lower(http.user_agent) contains "x"`))
	if !f["http.request.headers"] || !f["http.user_agent"] || len(f) != 2 {
		t.Fatalf("fields %v", f)
	}
}
