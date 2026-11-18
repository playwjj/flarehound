package console

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"net/http"
	"net/http/httptest"
	"net/url"
	"regexp"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/playwjj/flarehound/internal/block/fakecf"
	"github.com/playwjj/flarehound/internal/cfapi"
	"github.com/playwjj/flarehound/internal/store"
)

// fakeLive is the read-token analytics for the write flows.
type fakeLive struct{}

func (fakeLive) Count(_ context.Context, _ string, _, _ time.Time, f cfapi.Filter) (int64, error) {
	switch {
	case f.ASN == 24940:
		return 45_000, nil
	case f.ASN == 4134:
		return 300, nil
	}
	return 100_000, nil
}
func (fakeLive) ASNName(_ context.Context, _ string, _, _ time.Time, asn int) (string, error) {
	return map[int]string{24940: "HETZNER-AS", 4134: "CHINANET-BACKBONE"}[asn], nil
}
func (fakeLive) Capabilities(context.Context, string) (cfapi.Caps, error) {
	return cfapi.Caps{FirewallEnabled: true, FirewallMaxAge: 72 * time.Hour}, nil
}
func (fakeLive) FirewallTop(_ context.Context, _ string, _, _ time.Time, _, _ string, _ int) ([]cfapi.Face, error) {
	return []cfapi.Face{{Name: "AS24940", ASN: 24940, Count: 10}}, nil
}
func (fakeLive) Top(_ context.Context, _ string, from, _ time.Time, _ string, _ int, _ cfapi.Filter) ([]cfapi.Face, error) {
	return []cfapi.Face{{Name: "200", Count: 40_000}, {Name: "403", Count: 5_000}}, nil
}

type writeEnv struct {
	srv   *Server
	ts    *httptest.Server
	cf    *fakecf.CF
	st    *store.Store
	db    *DB
	admin *client
}

func newWriteEnv(t *testing.T, write bool) *writeEnv {
	t.Helper()
	cfg := testConfig(t)
	cfg.Cloudflare.AccountID = strings.Repeat("a", 32)
	st := openArchive(t, cfg)
	fillArchive(t, st, time.Now().UTC())
	db := testDB(t)
	if _, err := db.CreateUser("admin", "", "admin-password-1", RoleAdmin, false); err != nil {
		t.Fatal(err)
	}
	if _, err := db.CreateUser("viewer", "", "viewer-password-1", RoleViewer, false); err != nil {
		t.Fatal(err)
	}
	srv, _, err := New(cfg, db, st, nil, "test")
	if err != nil {
		t.Fatal(err)
	}
	cf := fakecf.New("pro", 20)
	if write {
		srv.Write, srv.Live, srv.Store = cf, fakeLive{}, st
	}
	ts := httptest.NewServer(srv.Handler())
	t.Cleanup(ts.Close)
	e := &writeEnv{srv: srv, ts: ts, cf: cf, st: st, db: db}
	e.admin = e.login(t, "admin", "admin-password-1")
	return e
}

func (e *writeEnv) login(t *testing.T, user, pw string) *client {
	t.Helper()
	c := newClient(t, e.ts.URL)
	_, body, _ := c.do("GET", "/login", nil, nil)
	if code, _, _ := c.do("POST", "/login", url.Values{"csrf": {csrfOf(t, body)}, "username": {user}, "password": {pw}}, nil); code != http.StatusSeeOther {
		t.Fatalf("login %s: %d", user, code)
	}
	return c
}

var reviewRE = regexp.MustCompile(`name="review" value="([^"]+)"`)

// review posts a block review and returns the page, its csrf and review token.
func (e *writeEnv) review(t *testing.T, c *client, form url.Values) (string, string, string) {
	t.Helper()
	_, body, _ := c.do("GET", "/blocks", nil, nil)
	form.Set("csrf", csrfOf(t, body))
	code, body, _ := c.do("POST", "/blocks/review", form, nil)
	if code != http.StatusOK {
		t.Fatalf("review: %d\n%s", code, body)
	}
	tok := ""
	if m := reviewRE.FindStringSubmatch(body); m != nil {
		tok = m[1]
	}
	return body, csrfOf(t, body), tok
}

func clone(v url.Values) url.Values {
	out := url.Values{}
	for k, x := range v {
		out[k] = append([]string(nil), x...)
	}
	return out
}

func TestBlockFlow(t *testing.T) {
	e := newWriteEnv(t, true)
	c := e.admin

	if code, body, _ := c.do("GET", "/blocks", nil, nil); code != http.StatusOK || !strings.Contains(body, "/blocks/new") {
		t.Fatalf("blocks page: %d", code)
	}
	if code, _, _ := c.do("GET", "/blocks/new?type=asn&value=24940", nil, nil); code != http.StatusOK {
		t.Fatalf("new form: %d", code)
	}
	// Movers offer a prefilled block link.
	if _, body, _ := c.do("GET", "/movers?dim=asn", nil, nil); !strings.Contains(body, "/blocks/new?z=example.com&amp;type=asn&amp;value=207990") {
		t.Fatal("movers lack the prefilled block link")
	}

	form := url.Values{"type": {"asn"}, "value": {"24940"}, "action": {"block"}, "for": {"24h"}, "reason": {"crawler flood"}}
	body, csrf, tok := e.review(t, c, clone(form))
	if tok == "" || !strings.Contains(body, "HETZNER-AS") || strings.Contains(body, `name="confirm"`) {
		t.Fatalf("hosting ASN review:\n%s", body)
	}
	if len(e.cf.Calls) != 0 {
		t.Fatalf("review changed Cloudflare: %v", e.cf.Calls)
	}

	// A tampered request (different value under the same token) is refused.
	bad := clone(form)
	bad.Set("value", "16509")
	bad.Set("csrf", csrf)
	bad.Set("review", tok)
	if code, _, _ := c.do("POST", "/blocks/apply", bad, nil); code != http.StatusBadRequest {
		t.Fatalf("tampered apply: %d", code)
	}
	if len(e.cf.Calls) != 0 {
		t.Fatal("tampered apply reached Cloudflare")
	}

	ok := clone(form)
	ok.Set("csrf", csrf)
	ok.Set("review", tok)
	if code, body, h := c.do("POST", "/blocks/apply", ok, nil); code != http.StatusSeeOther {
		t.Fatalf("apply: %d %s\n%s", code, h.Get("Location"), body)
	}
	if _, found := e.cf.Rule("flarehound-asn-block"); !found {
		t.Fatalf("no rule in Cloudflare: %v", e.cf.Calls)
	}
	act, _ := e.st.ActiveBlocks(zoneID)
	var ev store.BlockEvent
	for _, a := range act {
		if a.Value == "24940" {
			ev = a
		}
	}
	if ev.Actor != "console:admin" || ev.ExpiresAt.IsZero() || ev.Reason != "crawler flood" {
		t.Fatalf("archive audit record: %+v", ev)
	}
	log, _ := e.db.AuditLog(20)
	var seq []string
	for i := len(log) - 1; i >= 0; i-- {
		if strings.HasPrefix(log[i].Action, "block_") {
			seq = append(seq, log[i].Action)
		}
	}
	if strings.Join(seq, ",") != "block_requested,block_applied" {
		t.Fatalf("console audit order: %v", seq)
	}

	// Blocks page now lists it live, with attempts.
	if _, body, _ := c.do("GET", "/blocks", nil, nil); !strings.Contains(body, "asn 24940") && !strings.Contains(body, "AS24940") {
		t.Fatalf("live block missing:\n%s", body)
	}

	// Renew: review → apply.
	_, body, _ = c.do("GET", "/blocks", nil, nil)
	code, body, _ := c.do("POST", "/blocks/renew/review", url.Values{"csrf": {csrfOf(t, body)}, "type": {"asn"}, "value": {"24940"}, "for": {"7d"}}, nil)
	m := reviewRE.FindStringSubmatch(body)
	until := regexp.MustCompile(`name="until" value="(\d+)"`).FindStringSubmatch(body)
	if code != http.StatusOK || m == nil || until == nil {
		t.Fatalf("renew review: %d\n%s", code, body)
	}
	code, _, _ = c.do("POST", "/blocks/renew/apply", url.Values{"csrf": {csrfOf(t, body)}, "review": {m[1]}, "type": {"asn"}, "value": {"24940"}, "until": {until[1]}}, nil)
	if code != http.StatusSeeOther {
		t.Fatalf("renew apply: %d", code)
	}
	latest, _, _ := e.st.LatestBlockEvent(zoneID, "asn", "24940")
	if latest.Op != "renew" || latest.ExpiresAt.Sub(time.Now()) < 6*24*time.Hour {
		t.Fatalf("renew record: %+v", latest)
	}
	if act, _ := e.st.ActiveBlocks(zoneID); len(act) != 2 { // 207990 (fixture) + 24940
		t.Fatalf("renewed block not active: %+v", act)
	}

	// Undo the renewal: review restores the previous expiry.
	code, body, _ = c.do("GET", "/blocks/undo/"+itoa(latest.ID), nil, nil)
	if code != http.StatusOK || !strings.Contains(body, `name="until" value="`+itoa(ev.ExpiresAt.Unix())+`"`) {
		t.Fatalf("undo renew: %d\n%s", code, body)
	}
	// Undo an older record: superseded.
	if code, _, _ := c.do("GET", "/blocks/undo/"+itoa(ev.ID), nil, nil); code != http.StatusConflict {
		t.Fatalf("undo superseded: %d", code)
	}

	// Unblock.
	_, body, _ = c.do("GET", "/blocks", nil, nil)
	code, body, _ = c.do("POST", "/blocks/unblock/review", url.Values{"csrf": {csrfOf(t, body)}, "type": {"asn"}, "value": {"24940"}}, nil)
	m = reviewRE.FindStringSubmatch(body)
	if code != http.StatusOK || m == nil {
		t.Fatalf("unblock review: %d\n%s", code, body)
	}
	if code, _, _ := c.do("POST", "/blocks/unblock/apply", url.Values{"csrf": {csrfOf(t, body)}, "review": {m[1]}, "type": {"asn"}, "value": {"24940"}}, nil); code != http.StatusSeeOther {
		t.Fatalf("unblock apply: %d", code)
	}
	if _, found := e.cf.Rule("flarehound-asn-block"); found {
		t.Fatal("rule still in Cloudflare after unblock")
	}
	// Undo the unblock: back to a prefilled block form.
	latest, _, _ = e.st.LatestBlockEvent(zoneID, "asn", "24940")
	code, _, h := c.do("GET", "/blocks/undo/"+itoa(latest.ID), nil, nil)
	if code != http.StatusSeeOther || !strings.Contains(h.Get("Location"), "/blocks/new?") || !strings.Contains(h.Get("Location"), "value=24940") {
		t.Fatalf("undo unblock: %d %s", code, h.Get("Location"))
	}
}

func itoa(n int64) string { return strconv.FormatInt(n, 10) }

func TestBlockGuards(t *testing.T) {
	e := newWriteEnv(t, true)
	c := e.admin

	// Protected network: refused at review, no token.
	body, _, tok := e.review(t, c, url.Values{"type": {"asn"}, "value": {"13335"}, "action": {"block"}})
	if tok != "" || !strings.Contains(body, "refused") {
		t.Fatalf("protected ASN offered for confirmation:\n%s", body)
	}

	// Eyeball ASN with Block: strong confirmation required.
	form := url.Values{"type": {"asn"}, "value": {"4134"}, "action": {"block"}}
	body, csrf, tok := e.review(t, c, clone(form))
	if tok == "" || !strings.Contains(body, `name="confirm"`) {
		t.Fatalf("eyeball review lacks strong confirmation:\n%s", body)
	}
	try := clone(form)
	try.Set("csrf", csrf)
	try.Set("review", tok)
	try.Set("confirm", "4135")
	if code, _, _ := c.do("POST", "/blocks/apply", try, nil); code != http.StatusBadRequest || len(e.cf.Calls) != 0 {
		t.Fatalf("wrong strong confirmation accepted: %d %v", code, e.cf.Calls)
	}
	try.Set("confirm", "AS4134")
	if code, _, _ := c.do("POST", "/blocks/apply", try, nil); code != http.StatusSeeOther {
		t.Fatalf("strong confirmation: %d", code)
	}

	// Viewers cannot reach the write pages.
	v := e.login(t, "viewer", "viewer-password-1")
	if code, _, _ := v.do("GET", "/blocks/new", nil, nil); code != http.StatusForbidden {
		t.Fatalf("viewer /blocks/new: %d", code)
	}
	if _, body, _ := v.do("GET", "/movers?dim=asn", nil, nil); strings.Contains(body, "/blocks/new") {
		t.Fatal("viewer sees block links")
	}
}

func TestBlockNeedsTOTP(t *testing.T) {
	e := newWriteEnv(t, true)
	u, _, _ := e.db.UserByName("admin")
	secret, _ := NewTOTPSecret()
	_ = e.db.SetTOTP(u.ID, secret, true, 0)
	// Signed-in session predates TOTP: a fresh code is still demanded at apply.
	c := e.admin
	form := url.Values{"type": {"asn"}, "value": {"24940"}, "action": {"challenge"}}
	body, csrf, tok := e.review(t, c, clone(form))
	if !strings.Contains(body, `name="code"`) {
		t.Fatal("no TOTP field on the confirmation")
	}
	try := clone(form)
	try.Set("csrf", csrf)
	try.Set("review", tok)
	try.Set("code", "000000")
	if code, _, _ := c.do("POST", "/blocks/apply", try, nil); code != http.StatusBadRequest || len(e.cf.Calls) != 0 {
		t.Fatalf("apply without a valid code: %d %v", code, e.cf.Calls)
	}
	key, _ := b32.DecodeString(secret)
	try.Set("code", totpAt(key, time.Now().Unix()/totpStep))
	if code, _, _ := c.do("POST", "/blocks/apply", try, nil); code != http.StatusSeeOther {
		t.Fatalf("apply with code: %d", code)
	}
}

func TestReadOnlyConsoleRefusesWrites(t *testing.T) {
	e := newWriteEnv(t, false)
	if code, _, _ := e.admin.do("GET", "/blocks/new", nil, nil); code != http.StatusForbidden {
		t.Fatalf("read-only console /blocks/new: %d", code)
	}
	if _, body, _ := e.admin.do("GET", "/blocks", nil, nil); strings.Contains(body, "/blocks/new") {
		t.Fatal("read-only console offers blocking")
	}
}

func TestEffect(t *testing.T) {
	e := newWriteEnv(t, true)
	z := e.srv.Cfg.Cloudflare.Zones[0]
	_ = e.st.AddBlockEvent(store.BlockEvent{At: time.Now().Add(-3 * time.Hour), Zone: zoneID, Op: "block", Type: "asn", Value: "24940",
		Action: "block", RuleID: "r1", Actor: "console:admin"})
	ev, _, _ := e.st.LatestBlockEvent(zoneID, "asn", "24940")
	eff := e.srv.effect(context.Background(), z, ev)
	if !eff.Settled || !eff.Measurable || eff.Before != 45_000 || eff.ZoneAfter != 100_000 || !eff.AttemptsKnown || eff.Attempts != 10 {
		t.Fatalf("effect: %+v", eff)
	}
	if int(eff.ShareBefore()) != 45 || len(eff.StatusAfter) != 2 {
		t.Fatalf("effect share/status: %+v", eff)
	}
	if _, ok, _ := e.db.Effect(zoneID, ev.ID); !ok {
		t.Fatal("settled effect not cached")
	}
	// A fresh block: partial, not cached.
	_ = e.st.AddBlockEvent(store.BlockEvent{At: time.Now().Add(-10 * time.Minute), Zone: zoneID, Op: "block", Type: "asn", Value: "4134",
		Action: "challenge", RuleID: "r2", Actor: "console:admin"})
	fresh, _, _ := e.st.LatestBlockEvent(zoneID, "asn", "4134")
	if eff := e.srv.effect(context.Background(), z, fresh); eff.Settled {
		t.Fatal("fresh block reported as settled")
	}
	if _, ok, _ := e.db.Effect(zoneID, fresh.ID); ok {
		t.Fatal("partial effect cached")
	}
	if code, body, _ := e.admin.do("GET", "/blocks/effect/"+itoa(ev.ID), nil, nil); code != http.StatusOK || !strings.Contains(body, "45,000") {
		t.Fatalf("effect page: %d\n%s", code, body)
	}
}

func TestSnapshots(t *testing.T) {
	e := newWriteEnv(t, false)
	c := e.admin
	_, body, _ := c.do("GET", "/movers?dim=ua", nil, nil)
	csrf := csrfOf(t, body)
	params := regexp.MustCompile(`name="params" value="([^"]+)"`).FindStringSubmatch(body)
	if params == nil {
		t.Fatal("no snapshot form on movers")
	}
	p, _ := url.QueryUnescape(strings.ReplaceAll(params[1], "&amp;", "&"))
	code, body, _ := c.do("POST", "/snapshots/create", url.Values{"csrf": {csrf}, "view": {"movers"}, "params": {p}, "ttl": {"24h"}}, nil)
	link := regexp.MustCompile(`(http://[^<\s]+/s/[A-Za-z0-9_-]+)`).FindStringSubmatch(body)
	if code != http.StatusOK || link == nil {
		t.Fatalf("create: %d\n%s", code, body)
	}

	// Anyone with the link, no sign-in.
	anon := newClient(t, e.ts.URL)
	code, snap, h := anon.do("GET", strings.TrimPrefix(link[1], e.ts.URL), nil, nil)
	if code != http.StatusOK || !strings.Contains(snap, "Crawler/1.0") {
		t.Fatalf("public snapshot: %d", code)
	}
	if strings.Contains(snap, "csrf") || strings.Contains(snap, "/movers/drill") || strings.Contains(snap, "<form") || strings.Contains(snap, "<script") || strings.Contains(snap, "/static/") {
		t.Fatal("snapshot carries forms, tokens or external resources")
	}
	style := regexp.MustCompile(`(?s)<style>(.*?)</style>`).FindStringSubmatch(snap)
	sum := sha256.Sum256([]byte(style[1]))
	if want := "'sha256-" + base64.StdEncoding.EncodeToString(sum[:]) + "'"; !strings.Contains(h.Get("Content-Security-Policy"), want) {
		t.Fatalf("CSP hash does not match the inlined style: %s", h.Get("Content-Security-Policy"))
	}

	// Listed, downloadable, revocable.
	_, body, _ = c.do("GET", "/snapshots", nil, nil)
	id := regexp.MustCompile(`/snapshots/(\d+)/download`).FindStringSubmatch(body)
	if id == nil {
		t.Fatal("snapshot not listed")
	}
	if code, _, h := c.do("GET", "/snapshots/"+id[1]+"/download", nil, nil); code != http.StatusOK || !strings.Contains(h.Get("Content-Disposition"), "attachment") {
		t.Fatalf("download: %d", code)
	}
	v := e.login(t, "viewer", "viewer-password-1")
	if code, _, _ := v.do("GET", "/snapshots/"+id[1]+"/download", nil, nil); code != http.StatusNotFound {
		t.Fatalf("another user's snapshot downloadable: %d", code)
	}
	c.do("POST", "/snapshots/"+id[1]+"/revoke", url.Values{"csrf": {csrfOf(t, body)}}, nil)
	if code, _, _ := anon.do("GET", strings.TrimPrefix(link[1], e.ts.URL), nil, nil); code != http.StatusNotFound {
		t.Fatalf("revoked snapshot still served: %d", code)
	}
}

func TestBlocksAttemptsAsync(t *testing.T) {
	e := newWriteEnv(t, true)
	c := e.admin
	form := url.Values{"type": {"asn"}, "value": {"24940"}, "action": {"challenge"}}
	_, csrf, tok := e.review(t, c, clone(form))
	form.Set("csrf", csrf)
	form.Set("review", tok)
	if code, _, _ := c.do("POST", "/blocks/apply", form, nil); code != http.StatusSeeOther {
		t.Fatalf("apply: %d", code)
	}
	// Some background work may already have started on the redirect.
	e.srv.attemptsWG.Wait()
	e.srv.attemptsMu.Lock()
	e.srv.attemptsCache = map[string]attemptsEntry{}
	e.srv.attemptsMu.Unlock()

	_, body, _ := c.do("GET", "/blocks", nil, nil)
	if !strings.Contains(body, "computing") || !strings.Contains(body, `http-equiv="refresh" content="15"`) {
		t.Fatalf("first load should show attempts as pending with a quick refresh:\n%s", body)
	}
	e.srv.attemptsWG.Wait()
	_, body, _ = c.do("GET", "/blocks", nil, nil)
	if strings.Contains(body, "computing") || strings.Contains(body, `content="15"`) {
		t.Fatal("attempts still pending after the background query finished")
	}
	e.srv.attemptsWG.Wait()
	e.srv.attemptsMu.Lock()
	n := len(e.srv.attemptsCache)
	e.srv.attemptsMu.Unlock()
	if n != 1 {
		t.Fatalf("cache keys are not stable across loads: %d entries for one block", n)
	}
}
