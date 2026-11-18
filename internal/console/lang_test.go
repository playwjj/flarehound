package console

import (
	"net/http"
	"net/url"
	"regexp"
	"strings"
	"testing"
)

func switchLang(t *testing.T, c *client, page, l string) (int, string) {
	t.Helper()
	_, body, _ := c.do("GET", page, nil, nil)
	code, _, h := c.do("POST", "/lang", url.Values{"csrf": {csrfOf(t, body)}, "lang": {l}, "next": {page}}, nil)
	return code, h.Get("Location")
}

func TestLanguageSwitch(t *testing.T) {
	e, _ := rulesEnv(t, true)

	// Anonymous: the sign-in page follows this browser's choice.
	anon := newClient(t, e.ts.URL)
	if _, body, _ := anon.do("GET", "/login", nil, nil); !strings.Contains(body, "Sign in") || !strings.Contains(body, ">中文</button>") {
		t.Fatal("default English sign-in page with a 中文 switch expected")
	}
	if code, loc := switchLang(t, anon, "/login", "zh"); code != http.StatusSeeOther || loc != "/login" {
		t.Fatalf("switch: %d %s", code, loc)
	}
	if _, body, _ := anon.do("GET", "/login", nil, nil); !strings.Contains(body, "登录") || !strings.Contains(body, `<html lang="zh">`) {
		t.Fatal("sign-in page not in Chinese after switching")
	}
	// next never leaves the site.
	_, body, _ := anon.do("GET", "/login", nil, nil)
	if _, _, h := anon.do("POST", "/lang", url.Values{"csrf": {csrfOf(t, body)}, "lang": {"en"}, "next": {"//evil.example/"}}, nil); h.Get("Location") != "/" {
		t.Fatalf("language switch redirected off-site: %s", h.Get("Location"))
	}

	// Signed in: the choice is saved on the account and follows it to
	// another browser.
	c := e.admin
	switchLang(t, c, "/rules", "zh")
	if u, _, _ := e.db.UserByName("admin"); u.Lang != "zh" {
		t.Fatalf("account preference not saved: %q", u.Lang)
	}
	other := e.login(t, "admin", "admin-password-1")
	if _, body, _ := other.do("GET", "/", nil, nil); !strings.Contains(body, "总览") {
		t.Fatal("account language not applied in another browser")
	}

	// One cached rule list, each viewer in their own language.
	_, zh, _ := c.do("GET", "/rules", nil, nil)
	v := e.login(t, "viewer", "viewer-password-1")
	_, en, _ := v.do("GET", "/rules", nil, nil)
	if !strings.Contains(zh, "如果UA 包含") || !strings.Contains(en, "If the user agent contains") {
		t.Fatalf("rule explanations not per viewer language:\nzh: %v\nen: %v", strings.Contains(zh, "如果"), strings.Contains(en, "If the"))
	}
}

func TestLanguageOfSnapshotsAndMail(t *testing.T) {
	e, sent, mu := resetEnv(t)
	c := e.admin
	switchLang(t, c, "/movers", "zh")
	_, body, _ := c.do("GET", "/movers", nil, nil)
	csrf := csrfOf(t, body)
	_, body, _ = c.do("POST", "/snapshots/create", url.Values{"csrf": {csrf}, "view": {"movers"}, "params": {"z=example.com&dim=ua"}, "ttl": {"24h"}}, nil)
	link := regexpLink.FindString(body)
	_, snap, _ := newClient(t, e.ts.URL).do("GET", strings.TrimPrefix(link, e.ts.URL), nil, nil)
	if !strings.Contains(snap, "涨幅最大") {
		t.Fatal("snapshot not in its creator's language")
	}

	// The reset mail goes out in the account's language.
	u, _, _ := e.db.UserByName("viewer")
	_ = e.db.SetLang(u.ID, "zh")
	forgot(t, newClient(t, e.ts.URL), "viewer")
	e.srv.resetWG.Wait()
	mu.Lock()
	defer mu.Unlock()
	if len(*sent) != 1 || !strings.Contains((*sent)[0].subject, "重置口令") {
		t.Fatalf("reset mail language: %+v", *sent)
	}
}

var regexpLink = regexp.MustCompile(`http://[^<\s]+/s/[A-Za-z0-9_-]+`)
