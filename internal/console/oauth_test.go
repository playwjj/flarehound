package console

import (
	"crypto/sha256"
	"database/sql"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync"
	"testing"
	"time"
)

// fakeIdP plays GitHub (token + user API) and Google (token with ID token).
type fakeIdP struct {
	mu        sync.Mutex
	challenge map[string]string // code -> PKCE challenge it was issued for
	nonce     map[string]string // code -> nonce (Google)
	userID    int64             // GitHub user id returned next
	sub       string            // Google subject returned next
	aud       string            // Google audience (default: the client id)
	srv       *httptest.Server
}

func newFakeIdP(t *testing.T) *fakeIdP {
	f := &fakeIdP{challenge: map[string]string{}, nonce: map[string]string{}, userID: 4242, sub: "g-1"}
	mux := http.NewServeMux()
	mux.HandleFunc("POST /token", func(w http.ResponseWriter, r *http.Request) {
		_ = r.ParseForm()
		f.mu.Lock()
		ch, nonce := f.challenge[r.PostFormValue("code")], f.nonce[r.PostFormValue("code")]
		delete(f.challenge, r.PostFormValue("code"))
		f.mu.Unlock()
		sum := sha256.Sum256([]byte(r.PostFormValue("code_verifier")))
		w.Header().Set("Content-Type", "application/json")
		if ch == "" || base64.RawURLEncoding.EncodeToString(sum[:]) != ch || r.PostFormValue("client_secret") != "secret" {
			w.WriteHeader(http.StatusBadRequest)
			_, _ = w.Write([]byte(`{"error":"invalid_grant"}`))
			return
		}
		aud := f.aud
		if aud == "" {
			aud = "client-id"
		}
		claims, _ := json.Marshal(map[string]any{"iss": "https://accounts.google.com", "aud": aud, "exp": time.Now().Add(time.Hour).Unix(),
			"nonce": nonce, "sub": f.sub, "email": "ops@example.com", "email_verified": true})
		idt := "e30." + base64.RawURLEncoding.EncodeToString(claims) + ".sig"
		_ = json.NewEncoder(w).Encode(map[string]string{"access_token": "at-1", "id_token": idt})
	})
	mux.HandleFunc("GET /user", func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "Bearer at-1" {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		_ = json.NewEncoder(w).Encode(map[string]any{"id": f.userID, "login": "octo"})
	})
	f.srv = httptest.NewServer(mux)
	t.Cleanup(f.srv.Close)
	return f
}

// authorize plays the provider's consent screen: it records the PKCE
// challenge (and nonce) for a new code and returns the callback path.
func (f *fakeIdP) authorize(t *testing.T, location string) (callback, state string) {
	t.Helper()
	u, err := url.Parse(location)
	if err != nil || !strings.HasPrefix(location, f.srv.URL+"/authorize") {
		t.Fatalf("not sent to the provider: %q", location)
	}
	q := u.Query()
	if q.Get("code_challenge_method") != "S256" || q.Get("code_challenge") == "" || q.Get("state") == "" {
		t.Fatalf("authorization request lacks PKCE/state: %s", location)
	}
	code := "code-" + q.Get("state")[:8]
	f.mu.Lock()
	f.challenge[code], f.nonce[code] = q.Get("code_challenge"), q.Get("nonce")
	f.mu.Unlock()
	ru, _ := url.Parse(q.Get("redirect_uri"))
	return ru.Path + "?" + url.Values{"code": {code}, "state": {q.Get("state")}}.Encode(), q.Get("state")
}

func newOAuthEnv(t *testing.T) (*writeEnv, *fakeIdP) {
	t.Helper()
	e := newWriteEnv(t, false)
	idp := newFakeIdP(t)
	e.srv.Cfg.Console.BaseURL = e.ts.URL
	e.srv.OAuth = map[string]*Provider{
		"github": {Name: "github", Label: "GitHub", ClientID: "client-id", Secret: "secret", AuthURL: idp.srv.URL + "/authorize",
			TokenURL: idp.srv.URL + "/token", UserURL: idp.srv.URL + "/user", Scope: "read:user"},
		"google": {Name: "google", Label: "Google", ClientID: "client-id", Secret: "secret", AuthURL: idp.srv.URL + "/authorize",
			TokenURL: idp.srv.URL + "/token", Scope: "openid email", OIDC: true, Issuers: []string{"https://accounts.google.com"}},
	}
	return e, idp
}

// start posts a sign-in / link start and returns the provider redirect.
func start(t *testing.T, c *client, provider string, form url.Values) (int, string, string) {
	t.Helper()
	page := "/login"
	if form.Get("intent") == "link" {
		page = "/account"
	}
	_, body, _ := c.do("GET", page, nil, nil)
	form.Set("csrf", csrfOf(t, body))
	code, body, h := c.do("POST", "/oauth/"+provider+"/start", form, nil)
	return code, h.Get("Location"), body
}

func TestOAuthLinkAndLogin(t *testing.T) {
	e, idp := newOAuthEnv(t)
	admin := e.admin

	// The login page offers the providers; the CSP lets the form go there.
	anon := newClient(t, e.ts.URL)
	_, body, h := anon.do("GET", "/login", nil, nil)
	if !strings.Contains(body, "/oauth/github/start") || !strings.Contains(h.Get("Content-Security-Policy"), "form-action 'self' "+idp.srv.URL) {
		t.Fatalf("login page / CSP: %s", h.Get("Content-Security-Policy"))
	}

	// An unlinked GitHub identity signs in to nothing.
	code, loc, _ := start(t, anon, "github", url.Values{"intent": {"login"}})
	if code != http.StatusSeeOther {
		t.Fatalf("start: %d", code)
	}
	cb, _ := idp.authorize(t, loc)
	if code, body, _ := anon.do("GET", cb, nil, nil); code != http.StatusUnauthorized || !strings.Contains(body, "not linked") {
		t.Fatalf("unlinked identity: %d", code)
	}

	// Linking needs the current password.
	if code, loc, _ := start(t, admin, "github", url.Values{"intent": {"link"}, "current": {"wrong-password"}}); code == http.StatusSeeOther {
		t.Fatalf("link without the password redirected to %s", loc)
	}
	code, loc, _ = start(t, admin, "github", url.Values{"intent": {"link"}, "current": {"admin-password-1"}})
	cb, state := idp.authorize(t, loc)
	if code, _, h := admin.do("GET", cb, nil, nil); code != http.StatusSeeOther || !strings.HasPrefix(h.Get("Location"), "/account?ok=") {
		t.Fatalf("link callback: %d %s", code, h.Get("Location"))
	}
	if _, body, _ := admin.do("GET", "/account", nil, nil); !strings.Contains(body, "octo") {
		t.Fatal("linked identity not shown")
	}
	// The state is single use.
	if code, _, _ := admin.do("GET", "/oauth/github/callback?code=x&state="+state, nil, nil); code != http.StatusUnauthorized {
		t.Fatalf("replayed state: %d", code)
	}

	// Sign in with the linked identity.
	c := newClient(t, e.ts.URL)
	_, loc, _ = start(t, c, "github", url.Values{"intent": {"login"}, "next": {"/movers"}})
	cb, _ = idp.authorize(t, loc)
	if code, _, h := c.do("GET", cb, nil, nil); code != http.StatusSeeOther || h.Get("Location") != "/movers" {
		t.Fatalf("oauth login: %d %s", code, h.Get("Location"))
	}
	if code, _, _ := c.do("GET", "/", nil, nil); code != http.StatusOK {
		t.Fatalf("after oauth login: %d", code)
	}

	// A callback from another browser (no state cookie) is refused.
	other := newClient(t, e.ts.URL)
	_, loc, _ = start(t, newClient(t, e.ts.URL), "github", url.Values{"intent": {"login"}})
	cb, _ = idp.authorize(t, loc)
	if code, _, _ := other.do("GET", cb, nil, nil); code != http.StatusUnauthorized {
		t.Fatalf("callback in another browser: %d", code)
	}

	// The same GitHub identity cannot be linked to a second account.
	v := e.login(t, "viewer", "viewer-password-1")
	_, loc, _ = start(t, v, "github", url.Values{"intent": {"link"}, "current": {"viewer-password-1"}})
	cb, _ = idp.authorize(t, loc)
	if code, body, _ := v.do("GET", cb, nil, nil); code != http.StatusBadRequest || !strings.Contains(body, "already linked") {
		t.Fatalf("identity taken: %d", code)
	}

	// Disabled accounts cannot sign in through their identity.
	u, _, _ := e.db.UserByName("admin")
	_ = e.db.SetDisabled(u.ID, true)
	d := newClient(t, e.ts.URL)
	_, loc, _ = start(t, d, "github", url.Values{"intent": {"login"}})
	cb, _ = idp.authorize(t, loc)
	if code, _, _ := d.do("GET", cb, nil, nil); code != http.StatusUnauthorized {
		t.Fatalf("disabled account signed in: %d", code)
	}
}

func TestOAuthGoogleAndTOTP(t *testing.T) {
	e, idp := newOAuthEnv(t)
	u, _, _ := e.db.UserByName("viewer")
	if err := e.db.LinkIdentity("google", "g-1", u.ID, "ops@example.com"); err != nil {
		t.Fatal(err)
	}

	c := newClient(t, e.ts.URL)
	_, loc, _ := start(t, c, "google", url.Values{"intent": {"login"}})
	if q, _ := url.Parse(loc); q.Query().Get("nonce") == "" {
		t.Fatal("OIDC request without nonce")
	}
	cb, _ := idp.authorize(t, loc)
	if code, _, _ := c.do("GET", cb, nil, nil); code != http.StatusSeeOther {
		t.Fatalf("google login: %d", code)
	}

	// Wrong audience: refused.
	idp.aud = "someone-else"
	c2 := newClient(t, e.ts.URL)
	_, loc, _ = start(t, c2, "google", url.Values{"intent": {"login"}})
	cb, _ = idp.authorize(t, loc)
	if code, _, _ := c2.do("GET", cb, nil, nil); code != http.StatusUnauthorized {
		t.Fatalf("wrong audience accepted: %d", code)
	}
	idp.aud = ""

	// Wrong nonce: refused.
	c3 := newClient(t, e.ts.URL)
	_, loc, _ = start(t, c3, "google", url.Values{"intent": {"login"}})
	cb, _ = idp.authorize(t, loc)
	idp.mu.Lock()
	for k := range idp.nonce {
		idp.nonce[k] = "tampered"
	}
	idp.mu.Unlock()
	if code, _, _ := c3.do("GET", cb, nil, nil); code != http.StatusUnauthorized {
		t.Fatalf("wrong nonce accepted: %d", code)
	}

	// Accounts with TOTP still need the code after the provider.
	secret, _ := NewTOTPSecret()
	_ = e.db.SetTOTP(u.ID, secret, true, 0)
	c4 := newClient(t, e.ts.URL)
	_, loc, _ = start(t, c4, "google", url.Values{"intent": {"login"}})
	cb, _ = idp.authorize(t, loc)
	if code, _, h := c4.do("GET", cb, nil, nil); code != http.StatusSeeOther || !strings.HasPrefix(h.Get("Location"), "/login/totp") {
		t.Fatalf("TOTP skipped after OAuth: %d %s", code, h.Get("Location"))
	}
	if code, _, _ := c4.do("GET", "/", nil, nil); code != http.StatusSeeOther {
		t.Fatal("pending second factor reached the console")
	}
}

func TestIdentityMigration(t *testing.T) {
	path := t.TempDir() + "/old.db"
	// A v1.3 database: external_identities without display / last_used.
	old, err := sql.Open("sqlite", "file:"+path)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := old.Exec(`CREATE TABLE external_identities (provider TEXT NOT NULL, subject TEXT NOT NULL, user_id INTEGER NOT NULL,
		created_at INTEGER NOT NULL, PRIMARY KEY (provider, subject))`); err != nil {
		t.Fatal(err)
	}
	old.Close()
	db, err := OpenDB(path)
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	u, _ := db.CreateUser("alice", "", "alice-password", RoleAdmin, false)
	if err := db.LinkIdentity("github", "1", u.ID, "alice-gh"); err != nil {
		t.Fatal(err)
	}
	if ids, _ := db.Identities(u.ID); len(ids) != 1 || ids[0].Display != "alice-gh" {
		t.Fatalf("identities after migration: %+v", ids)
	}
}
