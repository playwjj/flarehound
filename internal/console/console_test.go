package console

import (
	"context"
	"io"
	"net/http"
	"net/http/cookiejar"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
	"time"

	"github.com/playwjj/flarehound/internal/analyze"
	"github.com/playwjj/flarehound/internal/cfapi"
	"github.com/playwjj/flarehound/internal/config"
	"github.com/playwjj/flarehound/internal/report"
	"github.com/playwjj/flarehound/internal/store"
)

func TestPassword(t *testing.T) {
	h, err := HashPassword("correct horse battery")
	if err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(h, "$argon2id$v=19$m=19456,t=2,p=1$") {
		t.Fatalf("unexpected encoding %q", h)
	}
	if !VerifyPassword(h, "correct horse battery") {
		t.Fatal("correct password rejected")
	}
	if VerifyPassword(h, "correct horse batterY") || VerifyPassword("garbage", "x") || VerifyPassword("", "") {
		t.Fatal("wrong password accepted")
	}
	if CheckPasswordPolicy("short") == nil {
		t.Fatal("short password accepted")
	}
}

func TestTOTP(t *testing.T) {
	// RFC 6238 appendix B (SHA-1), truncated to 6 digits.
	secret := "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ" // "12345678901234567890"
	for _, c := range []struct {
		unix int64
		code string
	}{{59, "287082"}, {1111111109, "081804"}, {1234567890, "005924"}, {2000000000, "279037"}} {
		step, ok := VerifyTOTP(secret, c.code, time.Unix(c.unix, 0), 0)
		if !ok {
			t.Fatalf("t=%d: code %s rejected", c.unix, c.code)
		}
		if _, ok := VerifyTOTP(secret, c.code, time.Unix(c.unix, 0), step); ok {
			t.Fatalf("t=%d: replayed code accepted", c.unix)
		}
	}
	if _, ok := VerifyTOTP(secret, "287082", time.Unix(59+120, 0), 0); ok {
		t.Fatal("code accepted four steps late")
	}
	if !strings.HasPrefix(TOTPURI("FlareHound", "a b", secret), "otpauth://totp/FlareHound:a%20b?") {
		t.Fatal(TOTPURI("FlareHound", "a b", secret))
	}
}

func testDB(t *testing.T) *DB {
	t.Helper()
	db, err := OpenDB(filepath.Join(t.TempDir(), "console.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { db.Close() })
	return db
}

func TestAccounts(t *testing.T) {
	db := testDB(t)
	u, err := db.CreateUser("alice", "a@example.com", "password-one", RoleAdmin, false)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := db.CreateUser("ALICE", "", "password-two", RoleViewer, false); err != ErrExists {
		t.Fatalf("case-insensitive duplicate: %v", err)
	}
	if _, err := db.CreateUser("bad name", "", "password-two", RoleViewer, false); err == nil {
		t.Fatal("invalid username accepted")
	}
	if got, ok, _ := db.UserByIdentity("A@EXAMPLE.COM"); !ok || got.ID != u.ID {
		t.Fatal("identity by e-mail not found")
	}

	// Lockout after maxFailures.
	for i := 0; i < maxFailures; i++ {
		_ = db.LoginFailed(u.ID)
	}
	u, _ = db.UserByID(u.ID)
	if !time.Now().Before(u.LockedUntil) {
		t.Fatal("account not locked")
	}
	_ = db.Unlock(u.ID)

	// Sessions: create, look up, password change ends other sessions.
	s1, _ := db.CreateSession(u.ID, true, time.Hour, "1.2.3.4", "ua")
	s2, _ := db.CreateSession(u.ID, true, time.Hour, "1.2.3.4", "ua")
	if _, ok, _ := db.SessionByToken(s1.Token); !ok {
		t.Fatal("session not found")
	}
	if err := db.SetPassword(u.ID, "password-new!", false, s1.Token); err != nil {
		t.Fatal(err)
	}
	if _, ok, _ := db.SessionByToken(s1.Token); !ok {
		t.Fatal("own session ended by own password change")
	}
	if _, ok, _ := db.SessionByToken(s2.Token); ok {
		t.Fatal("other session survived a password change")
	}
	// Expired sessions are gone.
	db.now = func() time.Time { return time.Now().Add(2 * time.Hour) }
	if _, ok, _ := db.SessionByToken(s1.Token); ok {
		t.Fatal("expired session accepted")
	}
	db.now = time.Now

	// Invites are single use.
	tok, err := db.CreateInvite(RoleViewer, u.ID, time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := db.AcceptInvite(tok, "bob", "", "short"); err == nil {
		t.Fatal("short password accepted")
	}
	b, err := db.AcceptInvite(tok, "bob", "", "password-bob!")
	if err != nil || b.Role != RoleViewer {
		t.Fatalf("accept: %v %+v", err, b)
	}
	if _, err := db.AcceptInvite(tok, "carol", "", "password-carol"); err == nil {
		t.Fatal("invite used twice")
	}
}

// --- archive fixtures ---

const zoneID = "0123456789abcdef0123456789abcdef"

func testConfig(t *testing.T) *config.Config {
	t.Helper()
	dir := t.TempDir()
	cfgFile := filepath.Join(dir, "config.json")
	raw := `{"cloudflare":{"zones":[{"zone_id":"` + zoneID + `","name":"example.com"}]},
		"state_file":"` + filepath.Join(dir, "data", "state.json") + `",
		"known_faces":{"asns":[15169]},
		"console":{"enabled":true,"trusted_proxies":["10.0.0.1"],"proxy_auth":{"header":"X-Auth-User"}}}`
	if err := os.WriteFile(cfgFile, []byte(raw), 0o600); err != nil {
		t.Fatal(err)
	}
	t.Setenv("CF_API_TOKEN", "test-token")
	cfg, err := config.Load(cfgFile)
	if err != nil {
		t.Fatal(err)
	}
	cfg.Location = time.UTC
	return cfg
}

// fillArchive writes 28 days of hourly snapshots with a steady UA mix,
// then a newest hour where a crawler UA shows up and one UA drops out.
func fillArchive(t *testing.T, st *store.Store, now time.Time) time.Time {
	t.Helper()
	latest := now.Truncate(time.Hour).Add(-time.Hour)
	for h := 28 * 24; h >= 1; h-- {
		from := latest.Add(-time.Duration(h) * time.Hour)
		snap := store.Snapshot{Metrics: analyze.Metrics{Total: 10000, Dynamic: 2000, Origin5xx: 3,
			TopUA:  []cfapi.Face{{Name: "Mozilla/5.0 Chrome", Count: 6000}, {Name: "Safari", Count: 3000}, {Name: "OldBot", Count: 500}},
			TopASN: []cfapi.Face{{Name: "AS15169", ASN: 15169, Count: 4000}, {Name: "AS7922", ASN: 7922, Count: 3000}}},
			DynamicPaths: []cfapi.Face{{Name: "/search", Count: 900}, {Name: "/p/1", Count: 300}}}
		if err := st.PutSnapshot(zoneID, store.Hour, from, from.Add(time.Hour), snap); err != nil {
			t.Fatal(err)
		}
		_ = st.TouchFaces(zoneID, store.DimUA, snap.TopUA, from)
	}
	cur := store.Snapshot{Metrics: analyze.Metrics{Total: 25000, Dynamic: 9000, Origin5xx: 4,
		TopUA:  []cfapi.Face{{Name: "Crawler/1.0", Count: 14000}, {Name: "Mozilla/5.0 Chrome", Count: 6100}, {Name: "Safari", Count: 2900}},
		TopASN: []cfapi.Face{{Name: "AS207990", ASN: 207990, Count: 15000}, {Name: "AS15169", ASN: 15169, Count: 4100}}},
		DynamicPaths: []cfapi.Face{{Name: "/search", Count: 7000}, {Name: "/p/1", Count: 280}}}
	if err := st.PutSnapshot(zoneID, store.Hour, latest, latest.Add(time.Hour), cur); err != nil {
		t.Fatal(err)
	}
	_ = st.TouchFaces(zoneID, store.DimUA, cur.TopUA, latest)
	_ = st.TouchFaces(zoneID, store.DimASN, cur.TopASN, latest)
	_ = st.TouchFaces(zoneID, store.DimPath, cur.DynamicPaths, latest)
	_ = st.RecordAlert(zoneID, latest.Add(time.Hour), "alert", "fp", []analyze.Finding{{Rule: "total_up", Cur: 25000, Base: 10000, Pct: 150}})
	_ = st.AddBlockEvent(store.BlockEvent{At: now.Add(-10 * time.Minute), Zone: zoneID, Op: "block", Type: "asn", Value: "207990",
		Action: "challenge", Mechanism: "custom_rule", Reason: "crawler flood", Actor: "cli"})
	return latest
}

func openArchive(t *testing.T, cfg *config.Config) *store.Store {
	t.Helper()
	st, err := store.Open(cfg.Archive.File)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { st.Close() })
	return st
}

func TestReadModel(t *testing.T) {
	cfg := testConfig(t)
	st := openArchive(t, cfg)
	now := time.Now().UTC()
	fillArchive(t, st, now)
	zone := cfg.Cloudflare.Zones[0]

	ov, err := BuildOverview(st, cfg, zone, now)
	if err != nil || !ov.Has {
		t.Fatalf("overview: %v %+v", err, ov)
	}
	if ov.Stale || !ov.BaselineOK || ov.Samples != 28 {
		t.Fatalf("overview flags: stale=%v ok=%v samples=%d", ov.Stale, ov.BaselineOK, ov.Samples)
	}
	if r := ov.Rows[0]; r.Key != "m_total" || r.Status != StatusAlert || r.Base != 10000 || int(r.Pct) != 150 {
		t.Fatalf("total row: %+v", r)
	}
	if ov.AlertsToday != 1 {
		t.Fatalf("alerts today = %d", ov.AlertsToday)
	}

	mv, err := BuildMovers(st, cfg, zone, DimUA, 10)
	if err != nil {
		t.Fatal(err)
	}
	if len(mv.Up) == 0 || mv.Up[0].Name != "Crawler/1.0" || !mv.Up[0].BaseCapped {
		t.Fatalf("top riser: %+v", mv.Up)
	}
	// Baseline "below the list floor (500)": the change is conservative.
	if mv.Up[0].Base != 500 || mv.Up[0].Delta != 13500 {
		t.Fatalf("capped riser numbers: %+v", mv.Up[0])
	}
	for _, m := range mv.Down {
		if m.Cur == 0 && m.CurCapped {
			t.Fatalf("faller shown as dropping to zero: %+v", m)
		}
	}
	asn, _ := BuildMovers(st, cfg, zone, DimASN, 10)
	for _, m := range asn.Up {
		if m.Name == "AS15169" && !m.Known {
			t.Fatal("known ASN not marked")
		}
	}

	nf, err := BuildNewFaces(st, cfg, zone, now.Add(-24*time.Hour), 50)
	if err != nil {
		t.Fatal(err)
	}
	if len(nf.ByDim[DimUA]) != 1 || nf.ByDim[DimUA][0].Name != "Crawler/1.0" || nf.ByDim[DimUA][0].Cur != 14000 {
		t.Fatalf("new UA faces: %+v", nf.ByDim[DimUA])
	}
	if nf.PathSince.IsZero() {
		t.Fatal("path history start unknown")
	}

	end := now.Truncate(time.Hour).Add(time.Hour)
	h, err := BuildHistory(st, zone, end.Add(-48*time.Hour), end)
	if err != nil {
		t.Fatal(err)
	}
	if len(h.Points) != 48 || !h.Points[46].HasBase || h.Points[46].Median != 10000 {
		t.Fatalf("history points: %d %+v", len(h.Points), h.Points[46])
	}
	if len(h.Events) != 2 {
		t.Fatalf("history events: %+v", h.Events)
	}
	if svg := historyChart(h, time.UTC, 720, 200, true); !strings.Contains(string(svg), `class="band"`) || !strings.Contains(string(svg), "ev-alert") {
		t.Fatal("chart lacks band or event tick")
	}
}

// --- HTTP ---

type client struct {
	t    *testing.T
	base string
	c    *http.Client
}

func newClient(t *testing.T, base string) *client {
	jar, _ := cookiejar.New(nil)
	return &client{t: t, base: base, c: &http.Client{Jar: jar, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}}
}

func (c *client) do(method, path string, form url.Values, hdr map[string]string) (int, string, http.Header) {
	c.t.Helper()
	var body io.Reader
	if form != nil {
		body = strings.NewReader(form.Encode())
	}
	req, _ := http.NewRequest(method, c.base+path, body)
	if form != nil {
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	}
	for k, v := range hdr {
		req.Header.Set(k, v)
	}
	resp, err := c.c.Do(req)
	if err != nil {
		c.t.Fatal(err)
	}
	defer resp.Body.Close()
	b, _ := io.ReadAll(resp.Body)
	return resp.StatusCode, string(b), resp.Header
}

var csrfRE = regexp.MustCompile(`name="csrf" value="([^"]+)"`)

func csrfOf(t *testing.T, body string) string {
	t.Helper()
	m := csrfRE.FindStringSubmatch(body)
	if m == nil {
		t.Fatalf("no csrf token in page:\n%s", body)
	}
	return m[1]
}

func TestServerFlow(t *testing.T) {
	cfg := testConfig(t)
	st := openArchive(t, cfg)
	fillArchive(t, st, time.Now().UTC())
	db := testDB(t)
	auditor := func(ctx context.Context, z config.Zone) (report.AuditData, error) {
		return report.AuditData{Zone: z.Name, NA: "the read token lacks Zone → WAF: Read"}, nil
	}
	srv, setup, err := New(cfg, db, st, auditor, "test")
	if err != nil {
		t.Fatal(err)
	}
	if setup == "" {
		t.Fatal("no setup token with an empty account database")
	}
	ts := httptest.NewServer(srv.Handler())
	defer ts.Close()
	c := newClient(t, ts.URL)

	// Anonymous: redirected to login; security headers present.
	code, _, h := c.do("GET", "/", nil, nil)
	if code != http.StatusSeeOther || !strings.HasPrefix(h.Get("Location"), "/login") {
		t.Fatalf("anonymous /: %d %s", code, h.Get("Location"))
	}
	if !strings.Contains(h.Get("Content-Security-Policy"), "default-src 'none'") {
		t.Fatal("CSP missing")
	}

	// Setup with a wrong token fails; with the right one creates the admin.
	if code, _, _ := c.do("GET", "/setup?token=nope", nil, nil); code != http.StatusNotFound {
		t.Fatalf("bad setup token: %d", code)
	}
	_, body, _ := c.do("GET", "/setup?token="+setup, nil, nil)
	csrf := csrfOf(t, body)
	form := url.Values{"csrf": {csrf}, "token": {setup}, "username": {"admin"}, "password": {"admin-password-1"}, "password2": {"admin-password-1"}}
	if code, body, _ := c.do("POST", "/setup", form, nil); code != http.StatusSeeOther {
		t.Fatalf("setup: %d %s", code, body)
	}
	if code, _, _ := c.do("GET", "/setup?token="+setup, nil, nil); code != http.StatusNotFound {
		t.Fatal("setup link still works after the first admin")
	}

	// CSRF: a POST without the token is refused.
	if code, _, _ := c.do("POST", "/login", url.Values{"username": {"admin"}, "password": {"admin-password-1"}}, nil); code != http.StatusForbidden {
		t.Fatalf("login without csrf: %d", code)
	}
	// Cross-site POST refused even with a token.
	_, body, _ = c.do("GET", "/login", nil, nil)
	csrf = csrfOf(t, body)
	if code, _, _ := c.do("POST", "/login", url.Values{"csrf": {csrf}, "username": {"admin"}, "password": {"admin-password-1"}},
		map[string]string{"Sec-Fetch-Site": "cross-site"}); code != http.StatusForbidden {
		t.Fatalf("cross-site login: %d", code)
	}
	// Wrong password.
	if code, _, _ := c.do("POST", "/login", url.Values{"csrf": {csrf}, "username": {"admin"}, "password": {"nope-nope-nope"}}, nil); code != http.StatusUnauthorized {
		t.Fatalf("wrong password: %d", code)
	}
	// Right password.
	code, _, h = c.do("POST", "/login", url.Values{"csrf": {csrf}, "username": {"admin"}, "password": {"admin-password-1"}, "next": {"//evil.example/x"}}, nil)
	if code != http.StatusSeeOther || h.Get("Location") != "/" {
		t.Fatalf("login: %d → %q (open redirect?)", code, h.Get("Location"))
	}

	// Every page renders.
	for _, p := range []string{"/", "/movers", "/movers?dim=asn", "/movers?dim=path", "/faces", "/faces?days=30",
		"/history", "/history?range=24h", "/history?range=30d&end=2026-01-01", "/audit", "/blocks", "/account", "/users"} {
		code, body, _ := c.do("GET", p, nil, nil)
		if code != http.StatusOK {
			t.Fatalf("GET %s: %d\n%s", p, code, body)
		}
	}
	_, body, _ = c.do("GET", "/movers", nil, nil)
	if !strings.Contains(body, "Crawler/1.0") {
		t.Fatal("movers page lacks the riser")
	}
	_, body, _ = c.do("GET", "/blocks", nil, nil)
	if !strings.Contains(body, "207990") {
		t.Fatal("blocks page lacks the active block")
	}

	// Admin creates a viewer; the viewer must change the temp password.
	_, body, _ = c.do("GET", "/users", nil, nil)
	csrf = csrfOf(t, body)
	code, body, _ = c.do("POST", "/users/create", url.Values{"csrf": {csrf}, "username": {"viewer1"}, "role": {"viewer"}}, nil)
	if code != http.StatusOK {
		t.Fatalf("create user: %d", code)
	}
	temp := regexp.MustCompile(`<code class="secret">([^<]+)</code>`).FindStringSubmatch(body)
	if temp == nil {
		t.Fatal("no temporary password shown")
	}
	v := newClient(t, ts.URL)
	_, body, _ = v.do("GET", "/login", nil, nil)
	vcsrf := csrfOf(t, body)
	v.do("POST", "/login", url.Values{"csrf": {vcsrf}, "username": {"viewer1"}, "password": {temp[1]}}, nil)
	if code, _, h := v.do("GET", "/", nil, nil); code != http.StatusSeeOther || h.Get("Location") != "/account" {
		t.Fatalf("must-change not enforced: %d %s", code, h.Get("Location"))
	}
	if code, _, _ := v.do("GET", "/account", nil, nil); code != http.StatusOK {
		t.Fatal("account page blocked during must-change")
	}
	// Viewer cannot reach admin pages (after changing the password).
	_, body, _ = v.do("GET", "/account", nil, nil)
	vcsrf = csrfOf(t, body)
	v.do("POST", "/account/password", url.Values{"csrf": {vcsrf}, "current": {temp[1]}, "password": {"viewer-pass-22"}, "password2": {"viewer-pass-22"}}, nil)
	if code, _, _ := v.do("GET", "/users", nil, nil); code != http.StatusForbidden {
		t.Fatalf("viewer reached /users: %d", code)
	}
	if code, _, _ := v.do("GET", "/", nil, nil); code != http.StatusOK {
		t.Fatalf("viewer overview: %d", code)
	}

	// Proxy identity header: ignored from untrusted peers (httptest is 127.0.0.1).
	p := newClient(t, ts.URL)
	if code, _, _ := p.do("GET", "/", nil, map[string]string{"X-Auth-User": "admin"}); code != http.StatusSeeOther {
		t.Fatal("identity header honoured from an untrusted peer")
	}

	// Logout ends the session.
	_, body, _ = c.do("GET", "/", nil, nil)
	csrf = csrfOf(t, body)
	c.do("POST", "/logout", url.Values{"csrf": {csrf}}, nil)
	if code, _, _ := c.do("GET", "/", nil, nil); code != http.StatusSeeOther {
		t.Fatal("still signed in after logout")
	}
}

func TestTOTPLogin(t *testing.T) {
	cfg := testConfig(t)
	st := openArchive(t, cfg)
	db := testDB(t)
	u, _ := db.CreateUser("alice", "", "alice-password", RoleAdmin, false)
	secret, _ := NewTOTPSecret()
	_ = db.SetTOTP(u.ID, secret, true, 0)
	srv, _, err := New(cfg, db, st, nil, "test")
	if err != nil {
		t.Fatal(err)
	}
	ts := httptest.NewServer(srv.Handler())
	defer ts.Close()
	c := newClient(t, ts.URL)
	_, body, _ := c.do("GET", "/login", nil, nil)
	code, _, h := c.do("POST", "/login", url.Values{"csrf": {csrfOf(t, body)}, "username": {"alice"}, "password": {"alice-password"}}, nil)
	if code != http.StatusSeeOther || !strings.HasPrefix(h.Get("Location"), "/login/totp") {
		t.Fatalf("expected the TOTP step: %d %s", code, h.Get("Location"))
	}
	// Pending second factor: no access yet.
	if code, _, h := c.do("GET", "/", nil, nil); code != http.StatusSeeOther || h.Get("Location") != "/login/totp" {
		t.Fatalf("pre-MFA session reached /: %d %s", code, h.Get("Location"))
	}
	_, body, _ = c.do("GET", "/login/totp", nil, nil)
	csrf := csrfOf(t, body)
	if code, _, _ := c.do("POST", "/login/totp", url.Values{"csrf": {csrf}, "code": {"000000"}}, nil); code != http.StatusUnauthorized {
		t.Fatalf("wrong code: %d", code)
	}
	key, _ := b32.DecodeString(secret)
	good := totpAt(key, time.Now().Unix()/totpStep)
	if code, _, _ := c.do("POST", "/login/totp", url.Values{"csrf": {csrf}, "code": {good}}, nil); code != http.StatusSeeOther {
		t.Fatalf("right code: %d", code)
	}
	if code, _, _ := c.do("GET", "/", nil, nil); code != http.StatusOK {
		t.Fatalf("after TOTP: %d", code)
	}
}

func TestClientInfo(t *testing.T) {
	cfg := testConfig(t)
	s := &Server{Cfg: cfg, trusted: cfg.TrustedProxies()}
	r := httptest.NewRequest("GET", "/", nil)
	r.RemoteAddr = "10.0.0.1:5000"
	r.Header.Set("X-Forwarded-For", "6.6.6.6, 203.0.113.9")
	r.Header.Set("X-Forwarded-Proto", "https")
	ip, secure, proxy := s.clientInfo(r)
	if ip.String() != "203.0.113.9" || !secure || !proxy {
		t.Fatalf("trusted proxy: %v %v %v", ip, secure, proxy)
	}
	r.RemoteAddr = "192.0.2.7:5000"
	ip, secure, proxy = s.clientInfo(r)
	if ip.String() != "192.0.2.7" || secure || proxy {
		t.Fatalf("untrusted peer: %v %v %v", ip, secure, proxy)
	}
	for in, want := range map[string]string{"/movers?z=a": "/movers?z=a", "//evil.com": "/", "https://evil.com/x": "/x", "/\\evil": "/", "": "/"} {
		if got := localPath(in); got != want {
			t.Fatalf("localPath(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestProxyIdentity(t *testing.T) {
	cfg := testConfig(t)
	st := openArchive(t, cfg)
	db := testDB(t)
	_, _ = db.CreateUser("ops", "ops@example.com", "ops-password-1", RoleAdmin, false)
	srv, _, err := New(cfg, db, st, nil, "test")
	if err != nil {
		t.Fatal(err)
	}
	h := srv.Handler()
	get := func(path, peer, id string) *httptest.ResponseRecorder {
		r := httptest.NewRequest("GET", path, nil)
		r.RemoteAddr = peer + ":4000"
		if id != "" {
			r.Header.Set("X-Auth-User", id)
		}
		w := httptest.NewRecorder()
		h.ServeHTTP(w, r)
		return w
	}
	// Known identity from the trusted proxy: that account (admin).
	if w := get("/users", "10.0.0.1", "OPS@example.com"); w.Code != http.StatusOK {
		t.Fatalf("proxy admin /users: %d", w.Code)
	}
	// Unknown identity: default role viewer — overview yes, users no.
	if w := get("/", "10.0.0.1", "someone@example.com"); w.Code != http.StatusOK {
		t.Fatalf("proxy viewer /: %d", w.Code)
	}
	if w := get("/users", "10.0.0.1", "someone@example.com"); w.Code != http.StatusForbidden {
		t.Fatalf("proxy viewer /users: %d", w.Code)
	}
	// Same header from elsewhere: ignored.
	if w := get("/", "192.0.2.50", "ops@example.com"); w.Code != http.StatusSeeOther {
		t.Fatalf("untrusted peer with identity header: %d", w.Code)
	}
}
