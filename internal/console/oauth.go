package console

// Third-party sign-in (v1.5, docs/web-console-revision.md §5.2).
//
// Local accounts stay the identity anchor. A Google or GitHub identity is
// an additional way into the local account it was explicitly linked to
// (from the account page, after re-entering the password); an identity
// that is not linked signs in to nothing — no account is ever created,
// and nothing is matched by e-mail. Two-factor sign-in, disabled
// accounts, forced password changes and require_totp apply as usual.
//
// The flow is the authorization-code flow with PKCE (S256). The state
// value is single use, expires after 10 minutes and must match a cookie
// set in the same browser. Google's ID token comes straight from its
// token endpoint over TLS, so (OIDC Core §3.1.3.7) its claims are
// checked — issuer, audience, expiry, nonce — without fetching keys.

import (
	"context"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/playwjj/flarehound/internal/config"
)

const (
	oauthCookie   = "fh_oauth"
	oauthStateTTL = 10 * time.Minute
)

// Provider is one OAuth / OIDC identity provider.
type Provider struct {
	Name     string // google | github
	Label    string
	ClientID string
	Secret   string
	AuthURL  string
	TokenURL string
	UserURL  string // GitHub: the user API
	Scope    string
	OIDC     bool     // verify the ID token's claims (Google)
	Issuers  []string // accepted "iss" values
	Extra    url.Values
}

func builtinProviders(cs config.Console) map[string]*Provider {
	out := map[string]*Provider{}
	if g := cs.OAuth.Google; g != nil {
		out["google"] = &Provider{Name: "google", Label: "Google", ClientID: g.ClientID, Secret: g.ClientSecret,
			AuthURL: "https://accounts.google.com/o/oauth2/v2/auth", TokenURL: "https://oauth2.googleapis.com/token",
			Scope: "openid email", OIDC: true, Issuers: []string{"https://accounts.google.com", "accounts.google.com"},
			Extra: url.Values{"prompt": {"select_account"}}}
	}
	if g := cs.OAuth.GitHub; g != nil {
		out["github"] = &Provider{Name: "github", Label: "GitHub", ClientID: g.ClientID, Secret: g.ClientSecret,
			AuthURL: "https://github.com/login/oauth/authorize", TokenURL: "https://github.com/login/oauth/access_token",
			UserURL: "https://api.github.com/user", Scope: "read:user", Extra: url.Values{"allow_signup": {"false"}}}
	}
	return out
}

// ProviderList returns the configured providers in display order.
func (s *Server) ProviderList() []*Provider {
	var out []*Provider
	for _, p := range s.OAuth {
		out = append(out, p)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Name < out[j].Name })
	return out
}

// formAction is the CSP form-action list: this site plus the providers'
// authorization origins (sign-in starts with a POST that redirects there).
func (s *Server) formAction() string {
	parts := []string{"'self'"}
	for _, p := range s.ProviderList() {
		if u, err := url.Parse(p.AuthURL); err == nil {
			parts = append(parts, u.Scheme+"://"+u.Host)
		}
	}
	return strings.Join(parts, " ")
}

func (s *Server) redirectURI(p *Provider) string {
	return s.Cfg.Console.BaseURL + "/oauth/" + p.Name + "/callback"
}

func pkceChallenge(verifier string) string {
	sum := sha256.Sum256([]byte(verifier))
	return base64.RawURLEncoding.EncodeToString(sum[:])
}

// oauthStart begins a sign-in (intent=login) or a link (intent=link).
func (s *Server) oauthStart(w http.ResponseWriter, r *http.Request) {
	rq := reqOf(r)
	p := s.OAuth[r.PathValue("provider")]
	if p == nil || s.Cfg.Console.ProxyAuth.DisableLogin {
		http.NotFound(w, r)
		return
	}
	if !s.limiter.allow("login:"+rq.IP, s.Now()) {
		s.render(w, r, http.StatusTooManyRequests, "login", page{Title: s.L(r).t("login_title"), Err: s.L(r).t("login_throttled"), Providers: s.ProviderList()})
		return
	}
	st := OAuthState{Provider: p.Name, Intent: r.PostFormValue("intent"), Next: localPath(r.PostFormValue("next")),
		Verifier: randToken(32), Nonce: randToken(16)}
	switch st.Intent {
	case "login":
	case "link":
		// Linking adds a way into the account: only for a signed-in local
		// account, after re-entering its password.
		u, ok := s.localUser(w, r)
		if !ok {
			return
		}
		if !VerifyPassword(u.PWHash, r.PostFormValue("current")) {
			s.audit(r, "identity_link_failed", p.Name, "wrong current password")
			s.accountErr(w, r, s.L(r).t("pw_wrong"))
			return
		}
		st.UserID, st.Next = u.ID, "/account"
	default:
		http.Error(w, "bad request", http.StatusBadRequest)
		return
	}
	state := randToken(24)
	if err := s.DB.PutOAuthState(state, st, oauthStateTTL); err != nil {
		s.fail(w, r, err)
		return
	}
	http.SetCookie(w, &http.Cookie{Name: oauthCookie, Value: state, Path: "/oauth/", HttpOnly: true, Secure: rq.Secure,
		SameSite: http.SameSiteLaxMode, MaxAge: int(oauthStateTTL.Seconds())})
	q := url.Values{"response_type": {"code"}, "client_id": {p.ClientID}, "redirect_uri": {s.redirectURI(p)}, "scope": {p.Scope},
		"state": {state}, "code_challenge": {pkceChallenge(st.Verifier)}, "code_challenge_method": {"S256"}}
	if p.OIDC {
		q.Set("nonce", st.Nonce)
	}
	for k, v := range p.Extra {
		q[k] = v
	}
	http.Redirect(w, r, p.AuthURL+"?"+q.Encode(), http.StatusSeeOther)
}

// extIdentity is what a provider tells us about the person.
type extIdentity struct {
	Subject string
	Display string
}

func (s *Server) oauthCallback(w http.ResponseWriter, r *http.Request) {
	rq := reqOf(r)
	p := s.OAuth[r.PathValue("provider")]
	if p == nil {
		http.NotFound(w, r)
		return
	}
	fail := func(msg, detail string) {
		s.DB.Audit("-", rq.IP, "oauth_failed", p.Name, detail)
		s.render(w, r, http.StatusUnauthorized, "message", page{Title: s.L(r).t("login_title"), Msg: msg})
	}
	q := r.URL.Query()
	state := q.Get("state")
	c, err := r.Cookie(oauthCookie)
	http.SetCookie(w, &http.Cookie{Name: oauthCookie, Value: "", Path: "/oauth/", HttpOnly: true, Secure: rq.Secure, MaxAge: -1})
	if err != nil || state == "" || subtle.ConstantTimeCompare([]byte(c.Value), []byte(state)) != 1 {
		fail(s.L(r).t("oauth_state"), "state cookie mismatch")
		return
	}
	st, ok, err := s.DB.TakeOAuthState(state)
	if err != nil {
		s.fail(w, r, err)
		return
	}
	if !ok || st.Provider != p.Name {
		fail(s.L(r).t("oauth_state"), "unknown or expired state")
		return
	}
	if e := q.Get("error"); e != "" {
		fail(s.L(r).t("oauth_denied"), "provider error: "+truncate(e, 100))
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), 20*time.Second)
	defer cancel()
	id, err := s.exchange(ctx, p, q.Get("code"), st)
	if err != nil {
		fail(s.L(r).t("oauth_failed"), err.Error())
		return
	}

	switch st.Intent {
	case "link":
		if rq.Session == nil || rq.User == nil || rq.User.ID != st.UserID {
			fail(s.L(r).t("oauth_state"), "link finished in another session")
			return
		}
		if err := s.DB.LinkIdentity(p.Name, id.Subject, st.UserID, id.Display); err != nil {
			s.audit(r, "identity_link_failed", p.Name, err.Error())
			if errors.Is(err, ErrIdentityTaken) {
				s.accountErr(w, r, s.L(r).t("identity_taken"))
				return
			}
			s.fail(w, r, err)
			return
		}
		s.audit(r, "identity_linked", p.Name, id.Display)
		http.Redirect(w, r, "/account?ok="+url.QueryEscape(fmt.Sprintf(s.L(r).t("identity_linked"), p.Label)), http.StatusSeeOther)
	case "login":
		if s.Cfg.Console.ProxyAuth.DisableLogin {
			http.NotFound(w, r)
			return
		}
		uid, ok, err := s.DB.IdentityOwner(p.Name, id.Subject)
		if err != nil {
			s.fail(w, r, err)
			return
		}
		if !ok {
			s.DB.Audit("-", rq.IP, "login_failed", p.Name, "unlinked identity "+id.Display)
			s.render(w, r, http.StatusUnauthorized, "login", page{Title: s.L(r).t("login_title"), Providers: s.ProviderList(),
				Err: fmt.Sprintf(s.L(r).t("identity_unlinked"), p.Label)})
			return
		}
		u, err := s.DB.UserByID(uid)
		if err != nil {
			s.fail(w, r, err)
			return
		}
		if u.Disabled {
			s.DB.Audit(u.Username, rq.IP, "login_failed", u.Username, p.Name+": disabled")
			s.render(w, r, http.StatusUnauthorized, "login", page{Title: s.L(r).t("login_title"), Providers: s.ProviderList(), Err: s.L(r).t("login_failed")})
			return
		}
		_ = s.DB.TouchIdentity(p.Name, id.Subject, id.Display)
		s.completeLogin(w, r, &u, p.Name+" ("+id.Display+")", st.Next)
	default:
		http.Error(w, "bad request", http.StatusBadRequest)
	}
}

// exchange trades the code for tokens and returns the identity.
func (s *Server) exchange(ctx context.Context, p *Provider, code string, st OAuthState) (extIdentity, error) {
	if code == "" {
		return extIdentity{}, errors.New("no authorization code")
	}
	form := url.Values{"grant_type": {"authorization_code"}, "code": {code}, "redirect_uri": {s.redirectURI(p)},
		"client_id": {p.ClientID}, "client_secret": {p.Secret}, "code_verifier": {st.Verifier}}
	req, _ := http.NewRequestWithContext(ctx, http.MethodPost, p.TokenURL, strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Accept", "application/json")
	var tok struct {
		AccessToken string `json:"access_token"`
		IDToken     string `json:"id_token"`
		Error       string `json:"error"`
		ErrorDesc   string `json:"error_description"`
	}
	if err := s.doJSON(req, &tok); err != nil {
		return extIdentity{}, fmt.Errorf("token exchange: %w", err)
	}
	if tok.Error != "" {
		return extIdentity{}, fmt.Errorf("token exchange: %s %s", tok.Error, truncate(tok.ErrorDesc, 120))
	}
	if p.OIDC {
		return s.idTokenIdentity(p, tok.IDToken, st.Nonce)
	}
	if tok.AccessToken == "" {
		return extIdentity{}, errors.New("token exchange: no access token")
	}
	req, _ = http.NewRequestWithContext(ctx, http.MethodGet, p.UserURL, nil)
	req.Header.Set("Authorization", "Bearer "+tok.AccessToken)
	req.Header.Set("Accept", "application/vnd.github+json")
	var u struct {
		ID    int64  `json:"id"`
		Login string `json:"login"`
	}
	if err := s.doJSON(req, &u); err != nil {
		return extIdentity{}, fmt.Errorf("user lookup: %w", err)
	}
	if u.ID <= 0 {
		return extIdentity{}, errors.New("user lookup: no user id")
	}
	// The numeric id is stable; the login can be renamed.
	return extIdentity{Subject: strconv.FormatInt(u.ID, 10), Display: u.Login}, nil
}

func (s *Server) doJSON(req *http.Request, v any) error {
	client := s.HTTPClient
	if client == nil {
		client = &http.Client{Timeout: 15 * time.Second}
	}
	resp, err := client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if err != nil {
		return err
	}
	if resp.StatusCode/100 != 2 {
		// Error bodies carry error / error_description; decode them too.
		_ = json.Unmarshal(body, v)
		return fmt.Errorf("HTTP %d", resp.StatusCode)
	}
	return json.Unmarshal(body, v)
}

// idTokenIdentity checks an ID token received directly from the token
// endpoint over TLS (signature check not required, OIDC Core 3.1.3.7).
func (s *Server) idTokenIdentity(p *Provider, idToken, nonce string) (extIdentity, error) {
	parts := strings.Split(idToken, ".")
	if len(parts) != 3 {
		return extIdentity{}, errors.New("no valid ID token")
	}
	raw, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return extIdentity{}, errors.New("ID token: bad encoding")
	}
	var c struct {
		Iss           string          `json:"iss"`
		Aud           json.RawMessage `json:"aud"`
		Azp           string          `json:"azp"`
		Exp           int64           `json:"exp"`
		Nonce         string          `json:"nonce"`
		Sub           string          `json:"sub"`
		Email         string          `json:"email"`
		EmailVerified bool            `json:"email_verified"`
	}
	if err := json.Unmarshal(raw, &c); err != nil {
		return extIdentity{}, errors.New("ID token: bad claims")
	}
	issOK := false
	for _, i := range p.Issuers {
		if c.Iss == i {
			issOK = true
		}
	}
	var auds []string
	var one string
	if json.Unmarshal(c.Aud, &one) == nil {
		auds = []string{one}
	} else {
		_ = json.Unmarshal(c.Aud, &auds)
	}
	audOK := false
	for _, a := range auds {
		if a == p.ClientID {
			audOK = true
		}
	}
	if len(auds) > 1 && c.Azp != p.ClientID {
		audOK = false
	}
	switch {
	case !issOK:
		return extIdentity{}, fmt.Errorf("ID token: unexpected issuer %q", c.Iss)
	case !audOK:
		return extIdentity{}, errors.New("ID token: not issued for this client")
	case s.Now().Unix() >= c.Exp:
		return extIdentity{}, errors.New("ID token: expired")
	case subtle.ConstantTimeCompare([]byte(c.Nonce), []byte(nonce)) != 1:
		return extIdentity{}, errors.New("ID token: nonce mismatch")
	case c.Sub == "":
		return extIdentity{}, errors.New("ID token: no subject")
	}
	display := c.Email
	if !c.EmailVerified {
		display += " (unverified)"
	}
	return extIdentity{Subject: c.Sub, Display: display}, nil
}

// --- account: linked identities ---

func (s *Server) identityUnlink(w http.ResponseWriter, r *http.Request) {
	u, ok := s.localUser(w, r)
	if !ok {
		return
	}
	prov, subj := r.PostFormValue("provider"), r.PostFormValue("subject")
	removed, err := s.DB.UnlinkIdentity(u.ID, prov, subj)
	if err != nil {
		s.fail(w, r, err)
		return
	}
	if removed {
		s.audit(r, "identity_unlinked", prov, subj)
	}
	http.Redirect(w, r, "/account?ok="+url.QueryEscape(s.L(r).t("done")), http.StatusSeeOther)
}
