package console

import (
	"context"
	"net/http"
	"net/url"
	"regexp"
	"strings"
	"sync"
	"testing"
	"time"
)

type sentMail struct{ to, subject, body string }

func resetEnv(t *testing.T) (*writeEnv, *[]sentMail, *sync.Mutex) {
	e := newWriteEnv(t, false)
	var mu sync.Mutex
	var sent []sentMail
	e.srv.Cfg.Console.BaseURL = e.ts.URL
	e.srv.Mail = func(_ context.Context, to, subject, body string) error {
		mu.Lock()
		defer mu.Unlock()
		sent = append(sent, sentMail{to, subject, body})
		return nil
	}
	u, _, _ := e.db.UserByName("viewer")
	if _, err := e.db.db.Exec(`UPDATE users SET email = 'viewer@example.com' WHERE id = ?`, u.ID); err != nil {
		t.Fatal(err)
	}
	return e, &sent, &mu
}

func forgot(t *testing.T, c *client, identity string) string {
	t.Helper()
	_, body, _ := c.do("GET", "/login/forgot", nil, nil)
	code, body, _ := c.do("POST", "/login/forgot", url.Values{"csrf": {csrfOf(t, body)}, "identity": {identity}}, nil)
	if code != http.StatusOK {
		t.Fatalf("forgot: %d", code)
	}
	return body
}

var linkRE = regexp.MustCompile(`(http://\S+/reset/[A-Za-z0-9_-]+)`)

func TestPasswordReset(t *testing.T) {
	e, sent, mu := resetEnv(t)
	anon := newClient(t, e.ts.URL)
	if _, body, _ := anon.do("GET", "/login", nil, nil); !strings.Contains(body, "/login/forgot") {
		t.Fatal("login page lacks the reset link")
	}

	// Unknown account and known account: the same answer.
	a := forgot(t, anon, "nobody@example.com")
	b := forgot(t, anon, "viewer@example.com")
	strip := regexp.MustCompile(`name="csrf" value="[^"]*"`)
	if strip.ReplaceAllString(a, "") != strip.ReplaceAllString(b, "") {
		t.Fatal("the answer differs for unknown and known accounts")
	}
	e.srv.resetWG.Wait()
	mu.Lock()
	if len(*sent) != 1 || (*sent)[0].to != "viewer@example.com" {
		t.Fatalf("mails: %+v", *sent)
	}
	if b := (*sent)[0].body; strings.Contains(b, "%!") || !strings.Contains(b, "30 minutes") || !strings.Contains(b, "127.0.0.1") {
		t.Fatalf("mail body: %s", b)
	}
	link := linkRE.FindString((*sent)[0].body)
	mu.Unlock()
	if link == "" {
		t.Fatal("no link in the mail")
	}
	// A second request within 10 minutes sends nothing.
	forgot(t, anon, "viewer")
	e.srv.resetWG.Wait()
	if len(*sent) != 1 {
		t.Fatalf("second mail within the interval: %d", len(*sent))
	}
	// An account without an address gets nothing.
	forgot(t, anon, "admin")
	e.srv.resetWG.Wait()
	if len(*sent) != 1 {
		t.Fatal("mail sent to an account without an address")
	}

	// The viewer is signed in elsewhere; the reset ends that session.
	other := e.login(t, "viewer", "viewer-password-1")
	path := strings.TrimPrefix(link, e.ts.URL)
	_, body, _ := anon.do("GET", path, nil, nil)
	csrf := csrfOf(t, body)
	if code, _, _ := anon.do("POST", path, url.Values{"csrf": {csrf}, "password": {"new-viewer-pass-1"}, "password2": {"different-pass-1"}}, nil); code != http.StatusBadRequest {
		t.Fatalf("mismatch accepted: %d", code)
	}
	code, _, h := anon.do("POST", path, url.Values{"csrf": {csrf}, "password": {"new-viewer-pass-1"}, "password2": {"new-viewer-pass-1"}}, nil)
	if code != http.StatusSeeOther || h.Get("Location") != "/login?reset=1" {
		t.Fatalf("reset: %d %s", code, h.Get("Location"))
	}
	if code, _, _ := other.do("GET", "/", nil, nil); code != http.StatusSeeOther {
		t.Fatal("an old session survived the reset")
	}
	e.login(t, "viewer", "new-viewer-pass-1")
	// Single use.
	if code, _, _ := anon.do("GET", path, nil, nil); code != http.StatusNotFound {
		t.Fatalf("used link still works: %d", code)
	}
}

func TestPasswordResetKeepsTOTPAndExpires(t *testing.T) {
	e, _, _ := resetEnv(t)
	u, _, _ := e.db.UserByName("viewer")
	secret, _ := NewTOTPSecret()
	_ = e.db.SetTOTP(u.ID, secret, true, 0)

	tok, _ := e.db.CreateReset(u.ID, resetTTL)
	if _, err := e.db.UseReset(tok, "new-viewer-pass-2"); err != nil {
		t.Fatal(err)
	}
	c := newClient(t, e.ts.URL)
	_, body, _ := c.do("GET", "/login", nil, nil)
	_, _, h := c.do("POST", "/login", url.Values{"csrf": {csrfOf(t, body)}, "username": {"viewer"}, "password": {"new-viewer-pass-2"}}, nil)
	if !strings.HasPrefix(h.Get("Location"), "/login/totp") {
		t.Fatalf("reset bypassed two-factor sign-in: %s", h.Get("Location"))
	}

	old, _ := e.db.CreateReset(u.ID, resetTTL)
	e.db.now = func() time.Time { return time.Now().Add(31 * time.Minute) }
	if _, ok, _ := e.db.ResetUser(old); ok {
		t.Fatal("expired reset link accepted")
	}
}

func TestPasswordResetOff(t *testing.T) {
	e := newWriteEnv(t, false) // no Mail configured
	c := newClient(t, e.ts.URL)
	if _, body, _ := c.do("GET", "/login", nil, nil); strings.Contains(body, "/login/forgot") {
		t.Fatal("reset link shown without SMTP")
	}
	if code, _, _ := c.do("GET", "/login/forgot", nil, nil); code != http.StatusNotFound {
		t.Fatalf("forgot page without SMTP: %d", code)
	}
}
