// Package console is FlareHound's web console (docs/web-console-revision.md).
//
// It is a separate process from the watch (`flarehound console`), reads
// the archive the watch writes, and keeps its own account database. In
// v1.3 it is read-only against Cloudflare: it never reads the write
// token. Pages are rendered on the server with inline SVG charts; there
// is no JavaScript and no external resource (strict CSP).
package console

import (
	"context"
	"crypto/rand"
	"crypto/subtle"
	"embed"
	"errors"
	"fmt"
	"html/template"
	"log"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"strings"
	"sync"
	"time"

	"github.com/playwjj/flarehound/internal/blockcli"
	"github.com/playwjj/flarehound/internal/cfapi"
	"github.com/playwjj/flarehound/internal/config"
	"github.com/playwjj/flarehound/internal/report"
	"github.com/playwjj/flarehound/internal/ruleexec"
	"github.com/playwjj/flarehound/internal/sim"
	"github.com/playwjj/flarehound/internal/store"
)

//go:embed templates/*.html static/*
var assets embed.FS

const (
	sessionCookie = "fh_session"
	preCookie     = "fh_pre" // pre-auth CSRF token (double submit)
	langCookie    = "fh_lang"
	preMFATTL     = 5 * time.Minute
	stepUpTTL     = 10 * time.Minute
)

// Auditor runs the WAF audit for a zone (read token only).
type Auditor func(ctx context.Context, zone config.Zone) (report.AuditData, error)

// Server is the console HTTP handler.
type Server struct {
	Cfg     *config.Config
	DB      *DB
	Archive Archive
	Auditor Auditor
	Version string
	Now     func() time.Time

	// Writes (v1.4). All three set: this console holds the write token
	// and admins can block, unblock and renew. Unset: read-only.
	Write blockcli.WriteAPI
	Live  LiveAPI
	Store *store.Store

	// Third-party sign-in (v1.5): configured providers by name, and the
	// client for their token / user endpoints.
	OAuth      map[string]*Provider
	HTTPClient *http.Client

	// CfgPath is the config file (settings in the console need it; empty:
	// the settings pages are off).
	CfgPath    string
	effMu      sync.RWMutex
	effCfg     *config.Config // with the current settings overlay
	effMod     time.Time
	settingsMu sync.Mutex // one settings change at a time

	// Mail sends password-reset links (nil: reset by e-mail is off).
	Mail    MailSender
	resetWG sync.WaitGroup // background reset mails (tests wait on it)

	// Live queries with the read token: the last hour on the overview
	// (Measure) and the movers' drill-down (Analytics). Unset: archive only.
	Measure   LiveMetrics
	Analytics Analytics
	// Caps reports what the zone's plan exposes (shared with the watch's
	// probe; nil: assume everything).
	Caps func(ctx context.Context, z config.Zone) cfapi.Caps

	// WAF rules (v1.7): read with the read token, changed with the write
	// token (unset: list only / no rules page).
	RulesRead  ruleexec.API
	RulesWrite ruleexec.API

	tmpls   map[lang]*template.Template // one per UI language
	trusted []netip.Prefix
	defLang lang // console default (report.language)

	setupMu    sync.Mutex
	setupToken string

	limiter *limiter
	// TOTP failures: per account (a slow brute force from many addresses)
	// and per pending sign-in (wrong codes end it: the password again).
	totpAcct *limiter
	totpSess *limiter

	auditMu    sync.Mutex
	auditCache map[string]auditEntry

	css     template.CSS // inlined into snapshots
	cssHash string       // its CSP hash

	reviewKey     []byte
	attemptsMu    sync.Mutex
	attemptsCache map[string]attemptsEntry
	attemptsBusy  map[string]bool
	blockLive     map[string]blockLiveEntry // block live checks, under attemptsMu

	rulesMu    sync.Mutex
	rulesCache map[string]rulesEntry

	asnMu    sync.Mutex
	asnNames map[int]string // registered names from the archive
	asnAt    time.Time

	liveMu       sync.Mutex
	liveCache    map[string]*liveEntry
	drillMu      sync.Mutex
	drillCache   map[string]*drillEntry
	blockedMu    sync.Mutex
	blockedCache map[string]*blockedEntry
	ipMu         sync.Mutex
	ipCache      map[string]*ipEntry
	attemptsWG   sync.WaitGroup // background attempt queries (tests wait on it)
	sims         *sim.Cache     // rule simulations (review, apply, /simulate)
}

type auditEntry struct {
	at   time.Time
	data report.AuditData
	err  error
}

// New prepares a server. When the account database is empty it creates
// a one-time setup token (returned) for the first-admin page.
func New(cfg *config.Config, db *DB, arch Archive, auditor Auditor, version string) (*Server, string, error) {
	s := &Server{Cfg: cfg, DB: db, Archive: arch, Auditor: auditor, Version: version, Now: time.Now,
		trusted: cfg.TrustedProxies(), defLang: lang(cfg.Report.Language), limiter: newLimiter(10, time.Minute), totpAcct: newLimiter(20, time.Hour), totpSess: newLimiter(5, preMFATTL),
		auditCache: map[string]auditEntry{}, attemptsCache: map[string]attemptsEntry{}, attemptsBusy: map[string]bool{}, blockLive: map[string]blockLiveEntry{},
		liveCache: map[string]*liveEntry{}, drillCache: map[string]*drillEntry{}, rulesCache: map[string]rulesEntry{},
		blockedCache: map[string]*blockedEntry{}, ipCache: map[string]*ipEntry{}, sims: sim.NewCache()}
	s.OAuth = builtinProviders(cfg.Console)
	s.reviewKey = make([]byte, 32)
	if _, err := rand.Read(s.reviewKey); err != nil {
		return nil, "", err
	}
	s.tmpls = map[lang]*template.Template{}
	for _, l := range []lang{"en", "zh"} {
		t, err := template.New("").Funcs(s.funcs(l)).ParseFS(assets, "templates/*.html")
		if err != nil {
			return nil, "", err
		}
		s.tmpls[l] = t
	}
	if err := s.loadCSS(); err != nil {
		return nil, "", err
	}
	n, err := db.CountUsers()
	if err != nil {
		return nil, "", err
	}
	if n == 0 && !cfg.Console.ProxyAuth.DisableLogin {
		s.setupToken = randToken(24)
	}
	return s, s.setupToken, nil
}

// --- request context ---

type ctxKey int

const reqKey ctxKey = 0

// Req is the per-request state shared by middleware and handlers.
type Req struct {
	IP       string
	Secure   bool // reached over HTTPS (directly or via a trusted proxy)
	Loopback bool
	User     *User  // nil: anonymous
	Proxy    string // identity asserted by a trusted proxy, if any
	Session  *Session
	CSRF     string
	Pre      string // pre-auth token (anonymous forms)
	Flash    string
	Err      string
	Lang     lang // UI language of this request
}

func reqOf(r *http.Request) *Req { return r.Context().Value(reqKey).(*Req) }

func (s *Server) fromTrusted(addr netip.Addr) bool {
	for _, p := range s.trusted {
		if p.Contains(addr) {
			return true
		}
	}
	return false
}

// clientInfo derives the client address and scheme. Forwarded headers are
// honoured only from trusted proxies; the client is the rightmost
// X-Forwarded-For entry that is not itself a trusted proxy.
func (s *Server) clientInfo(r *http.Request) (ip netip.Addr, secure, fromProxy bool) {
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		host = r.RemoteAddr
	}
	peer, _ := netip.ParseAddr(host)
	peer = peer.Unmap()
	secure = r.TLS != nil
	if !peer.IsValid() || !s.fromTrusted(peer) {
		return peer, secure, false
	}
	ip = peer
	if xff := r.Header.Get("X-Forwarded-For"); xff != "" {
		parts := strings.Split(xff, ",")
		for i := len(parts) - 1; i >= 0; i-- {
			a, err := netip.ParseAddr(strings.TrimSpace(parts[i]))
			if err != nil {
				break
			}
			ip = a.Unmap()
			if !s.fromTrusted(ip) {
				break
			}
		}
	}
	if strings.EqualFold(r.Header.Get("X-Forwarded-Proto"), "https") {
		secure = true
	}
	return ip, secure, true
}

func (s *Server) sessionTTL() time.Duration {
	return time.Duration(s.Cfg.Console.SessionHours) * time.Hour
}

// Handler returns the console's root handler.
func (s *Server) Handler() http.Handler {
	mux := http.NewServeMux()
	static := http.FileServerFS(assets)
	mux.Handle("GET /static/", static)
	mux.HandleFunc("GET /healthz", func(w http.ResponseWriter, r *http.Request) { fmt.Fprintln(w, "ok") })
	// Browsers ask for /favicon.ico even on pages that declare no icon;
	// the logo (static/logo.png, also linked from the page head) is the icon.
	mux.HandleFunc("GET /favicon.ico", func(w http.ResponseWriter, r *http.Request) {
		b, err := assets.ReadFile("static/logo.png")
		if err != nil {
			http.NotFound(w, r)
			return
		}
		w.Header().Set("Content-Type", "image/png")
		w.Header().Set("Cache-Control", "public, max-age=604800")
		_, _ = w.Write(b)
	})

	// Anonymous.
	mux.HandleFunc("GET /login", s.loginPage)
	mux.HandleFunc("POST /login", s.loginPost)
	mux.HandleFunc("GET /setup", s.setupPage)
	mux.HandleFunc("POST /setup", s.setupPost)
	mux.HandleFunc("GET /invite/{token}", s.invitePage)
	mux.HandleFunc("POST /invite/{token}", s.invitePost)
	// Second factor of a pending sign-in.
	mux.HandleFunc("GET /login/totp", s.totpPage)
	mux.HandleFunc("POST /login/totp", s.totpPost)
	mux.HandleFunc("POST /logout", s.logout)
	mux.HandleFunc("POST /lang", s.langPost)
	mux.HandleFunc("GET /login/forgot", s.forgotPage)
	mux.HandleFunc("POST /login/forgot", s.forgotPost)
	mux.HandleFunc("GET /reset/{token}", s.resetPage)
	mux.HandleFunc("POST /reset/{token}", s.resetPost)
	mux.HandleFunc("POST /oauth/{provider}/start", s.oauthStart)
	mux.HandleFunc("GET /oauth/{provider}/callback", s.oauthCallback)

	// Signed in.
	user := func(h http.HandlerFunc) http.Handler { return s.requireUser(h, false) }
	admin := func(h http.HandlerFunc) http.Handler { return s.requireUser(h, true) }
	mux.Handle("GET /{$}", user(func(w http.ResponseWriter, r *http.Request) {
		// Several zones and none chosen: the cross-zone home.
		if len(s.Cfg.Cloudflare.Zones) > 1 && r.URL.Query().Get("z") == "" {
			s.attentionPage(w, r)
			return
		}
		s.viewPage(viewOverview)(w, r)
	}))
	mux.Handle("GET /movers", user(s.viewPage(viewMovers)))
	mux.Handle("GET /faces", user(s.facesPage))
	mux.Handle("GET /movers/drill", user(s.drillPage))
	mux.Handle("GET /ips", user(s.ipsPage))
	mux.Handle("GET /history", user(s.viewPage(viewHistory)))
	mux.Handle("GET /audit", user(s.auditPage))
	mux.Handle("POST /audit/run", user(s.auditRun))
	mux.Handle("GET /rules", user(s.rulesPage))
	mux.Handle("GET /rules/recipes", user(s.recipesPage))
	mux.Handle("GET /rules/recipe/{name}", admin(s.requireRules(s.recipeForm)))
	mux.Handle("POST /rules/review", admin(s.requireRules(s.ruleReview)))
	mux.Handle("POST /rules/apply", admin(s.requireRules(s.ruleApply)))
	mux.Handle("GET /blocks", user(s.blocksPage))
	mux.Handle("GET /simulate", user(s.simulatePage))
	mux.Handle("POST /totp-hint/dismiss", admin(s.totpHintDismiss))
	mux.Handle("GET /blocks/new", admin(s.requireWrite(s.blockNewPage)))
	mux.Handle("POST /blocks/review", admin(s.requireWrite(s.blockReview)))
	mux.Handle("POST /blocks/apply", admin(s.requireWrite(s.blockApply)))
	mux.Handle("POST /blocks/unblock/review", admin(s.requireWrite(s.unblockReview)))
	mux.Handle("POST /blocks/unblock/apply", admin(s.requireWrite(s.unblockApply)))
	mux.Handle("POST /blocks/renew/review", admin(s.requireWrite(s.renewReview)))
	mux.Handle("POST /blocks/renew/apply", admin(s.requireWrite(s.renewApply)))
	mux.Handle("GET /blocks/undo/{id}", admin(s.requireWrite(s.undo)))
	mux.Handle("GET /blocks/effect/{id}", user(s.requireWrite(s.effectPage)))
	mux.Handle("POST /snapshots/create", user(s.snapshotCreate))
	mux.Handle("GET /snapshots", user(s.snapshotsPage))
	mux.Handle("GET /snapshots/{id}/download", user(s.snapshotDownload))
	mux.Handle("POST /snapshots/{id}/revoke", user(s.snapshotRevoke))
	mux.HandleFunc("GET /s/{token}", s.snapshotPublic)
	mux.Handle("GET /account", user(s.accountPage))
	mux.Handle("POST /account/password", user(s.accountPassword))
	mux.Handle("POST /account/totp/start", user(s.totpStart))
	mux.Handle("POST /account/totp/confirm", user(s.totpConfirm))
	mux.Handle("POST /account/totp/disable", user(s.totpDisable))
	mux.Handle("POST /account/sessions/end", user(s.sessionEnd))
	mux.Handle("POST /account/identities/unlink", user(s.identityUnlink))
	mux.Handle("GET /stepup", user(s.stepUpPage))
	mux.Handle("POST /stepup", user(s.stepUpPost))
	mux.Handle("GET /users", admin(s.usersPage))
	mux.Handle("GET /settings", admin(s.requireSettings(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, "/settings/notify", http.StatusSeeOther)
	})))
	mux.Handle("GET /settings/asn/name", admin(s.requireSettings(s.asnNamePage)))
	mux.Handle("POST /settings/asn/name", admin(s.requireSettings(s.stepUp(s.asnNamePost))))
	for _, tab := range []string{"notify", "thresholds", "known", "asn", "history"} {
		mux.Handle("GET /settings/"+tab, admin(s.requireSettings(s.settingsPage(tab))))
	}
	mux.Handle("POST /settings/review", admin(s.requireSettings(s.settingsReview)))
	mux.Handle("POST /settings/apply", admin(s.requireSettings(s.settingsApply)))
	mux.Handle("POST /settings/notify/test", admin(s.requireSettings(s.notifyTest)))
	mux.Handle("POST /settings/known/mark", admin(s.requireSettings(s.stepUp(s.knownMark))))
	mux.Handle("POST /users/create", admin(s.stepUp(s.userCreate)))
	mux.Handle("POST /users/{id}/{op}", admin(s.stepUp(s.userOp)))
	mux.Handle("POST /invites/create", admin(s.stepUp(s.inviteCreate)))
	mux.Handle("POST /invites/revoke", admin(s.stepUp(s.inviteRevoke)))

	return s.base(mux)
}

// base sets security headers, resolves the client and identity, and
// enforces CSRF on every POST.
func (s *Server) base(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		h := w.Header()
		h.Set("Content-Security-Policy", "default-src 'none'; style-src 'self'; img-src 'self' data:; form-action "+s.formAction()+"; frame-ancestors 'none'; base-uri 'none'")
		h.Set("X-Content-Type-Options", "nosniff")
		h.Set("X-Frame-Options", "DENY")
		h.Set("Referrer-Policy", "no-referrer")
		h.Set("Permissions-Policy", "camera=(), microphone=(), geolocation=()")
		if !strings.HasPrefix(r.URL.Path, "/static/") {
			h.Set("Cache-Control", "no-store")
		}

		ip, secure, viaProxy := s.clientInfo(r)
		rq := &Req{IP: ip.String(), Secure: secure, Loopback: ip.IsLoopback()}
		if secure {
			h.Set("Strict-Transport-Security", "max-age=31536000")
		}

		// Identity: a proxy-asserted identity (trusted proxies only), else
		// the session cookie.
		if hdr := s.Cfg.Console.ProxyAuth.Header; hdr != "" && viaProxy {
			if id := strings.TrimSpace(r.Header.Get(hdr)); id != "" {
				rq.Proxy = id
			}
		}
		if c, err := r.Cookie(sessionCookie); err == nil {
			if sess, ok, err := s.DB.SessionByToken(c.Value); err == nil && ok {
				if u, err := s.DB.UserByID(sess.UserID); err == nil && !u.Disabled {
					// A proxy identity that names someone else wins over a
					// leftover cookie.
					if rq.Proxy == "" || identityMatches(u, rq.Proxy) {
						rq.Session, rq.User, rq.CSRF = &sess, &u, sess.CSRF
						// Slide the cookie with the server-side session:
						// people in use are not signed out after a fixed time.
						if slid, _ := s.DB.TouchSession(sess, s.sessionTTL()); slid {
							http.SetCookie(w, &http.Cookie{Name: sessionCookie, Value: sess.Token, Path: "/", HttpOnly: true,
								Secure: secure, SameSite: http.SameSiteLaxMode, MaxAge: int(s.sessionTTL().Seconds())})
						}
					}
				}
			}
		}
		if rq.User == nil && rq.Proxy != "" {
			u, ok, err := s.DB.UserByIdentity(rq.Proxy)
			switch {
			case err != nil:
				log.Printf("console: proxy identity lookup: %v", err)
			case ok && !u.Disabled:
				rq.User = &u
			case !ok && s.Cfg.Console.ProxyAuth.DefaultRole == RoleViewer:
				rq.User = &User{Username: rq.Proxy, Role: RoleViewer}
			}
		}
		// UI language: this browser's choice, else the account's, else the
		// console default.
		rq.Lang = s.defLang
		if rq.User != nil && (rq.User.Lang == "en" || rq.User.Lang == "zh") {
			rq.Lang = lang(rq.User.Lang)
		}
		if c, err := r.Cookie(langCookie); err == nil && (c.Value == "en" || c.Value == "zh") {
			rq.Lang = lang(c.Value)
		}
		// Anonymous and proxy-identified requests use a double-submit token.
		if rq.CSRF == "" {
			if c, err := r.Cookie(preCookie); err == nil && len(c.Value) >= 32 {
				rq.Pre = c.Value
			} else {
				rq.Pre = randToken(24)
				http.SetCookie(w, &http.Cookie{Name: preCookie, Value: rq.Pre, Path: "/", HttpOnly: true, Secure: secure, SameSite: http.SameSiteStrictMode})
			}
			rq.CSRF = rq.Pre
		}

		if r.Method == http.MethodPost {
			if site := r.Header.Get("Sec-Fetch-Site"); site != "" && site != "same-origin" && site != "none" {
				http.Error(w, "cross-site request refused", http.StatusForbidden)
				return
			}
			r.Body = http.MaxBytesReader(w, r.Body, 64<<10)
			if err := r.ParseForm(); err != nil {
				http.Error(w, "bad form", http.StatusBadRequest)
				return
			}
			if subtle.ConstantTimeCompare([]byte(r.PostFormValue("csrf")), []byte(rq.CSRF)) != 1 {
				http.Error(w, "invalid or expired form — reload the page and try again", http.StatusForbidden)
				return
			}
		}
		next.ServeHTTP(w, r.WithContext(context.WithValue(r.Context(), reqKey, rq)))
	})
}

func identityMatches(u User, id string) bool {
	return strings.EqualFold(u.Username, id) || (u.Email != "" && strings.EqualFold(u.Email, id))
}

// requireUser gates signed-in pages, the pending second factor, forced
// password change and mandatory TOTP enrolment.
func (s *Server) requireUser(h http.HandlerFunc, adminOnly bool) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		rq := reqOf(r)
		if rq.User == nil {
			if r.Method == http.MethodGet {
				http.Redirect(w, r, "/login?next="+url.QueryEscape(r.URL.RequestURI()), http.StatusSeeOther)
			} else {
				http.Redirect(w, r, "/login", http.StatusSeeOther)
			}
			return
		}
		if rq.Session != nil && !rq.Session.MFAOK {
			http.Redirect(w, r, "/login/totp", http.StatusSeeOther)
			return
		}
		u := rq.User
		if u.ID != 0 && rq.Session != nil { // a local account signed in with a password
			acct := strings.HasPrefix(r.URL.Path, "/account")
			if u.MustChange && !acct {
				http.Redirect(w, r, "/account", http.StatusSeeOther)
				return
			}
			if s.Cfg.Console.RequireTOTP && !u.TOTPEnabled && !acct {
				http.Redirect(w, r, "/account", http.StatusSeeOther)
				return
			}
		}
		if adminOnly && !u.Admin() {
			s.render(w, r, http.StatusForbidden, "message", page{Title: s.L(r).t("forbidden"), Msg: s.L(r).t("forbidden")})
			return
		}
		h(w, r)
	})
}

// stepUp requires a recent second-factor check for sensitive actions by
// accounts that have TOTP on (docs §5.2: step-up before writes).
func (s *Server) stepUp(h http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		rq := reqOf(r)
		if rq.User.TOTPEnabled && rq.Session != nil && s.Now().Sub(rq.Session.StepUpAt) > stepUpTTL {
			// The console sends no Referer (Referrer-Policy: no-referrer), so
			// forms that know where they live say so in "next".
			next := r.PostFormValue("next")
			if next == "" {
				next = r.Header.Get("Referer")
			}
			if next == "" {
				next = "/users"
			}
			http.Redirect(w, r, "/stepup?next="+url.QueryEscape(localPath(next)), http.StatusSeeOther)
			return
		}
		h(w, r)
	}
}

// localPath keeps redirects on this site: only "/..." paths, never "//host".
func localPath(p string) string {
	if u, err := url.Parse(p); err == nil && u.IsAbs() {
		p = u.RequestURI()
	}
	if !strings.HasPrefix(p, "/") || strings.HasPrefix(p, "//") || strings.HasPrefix(p, "/\\") {
		return "/"
	}
	return p
}

func (s *Server) setSession(w http.ResponseWriter, r *http.Request, sess Session, ttl time.Duration) {
	http.SetCookie(w, &http.Cookie{Name: sessionCookie, Value: sess.Token, Path: "/", HttpOnly: true,
		Secure: reqOf(r).Secure, SameSite: http.SameSiteLaxMode, MaxAge: int(ttl.Seconds())})
}

func (s *Server) clearSession(w http.ResponseWriter, r *http.Request) {
	http.SetCookie(w, &http.Cookie{Name: sessionCookie, Value: "", Path: "/", HttpOnly: true,
		Secure: reqOf(r).Secure, SameSite: http.SameSiteLaxMode, MaxAge: -1})
}

func (s *Server) audit(r *http.Request, action, target, detail string) {
	rq := reqOf(r)
	actor := "-"
	if rq.User != nil {
		actor = rq.User.Username
		if rq.Proxy != "" && rq.Session == nil {
			actor += " (proxy)"
		}
	}
	if err := s.DB.Audit(actor, rq.IP, action, target, detail); err != nil {
		log.Printf("console: audit log: %v", err)
	}
}

func (s *Server) fail(w http.ResponseWriter, r *http.Request, err error) {
	log.Printf("console: %s %s: %v", r.Method, r.URL.Path, err)
	s.render(w, r, http.StatusInternalServerError, "message", page{Title: s.L(r).t("error"), Msg: s.L(r).t("error")})
}

// --- login throttling ---

// limiter is a fixed-window counter per key (client IP), in memory.
type limiter struct {
	mu     sync.Mutex
	max    int
	window time.Duration
	hits   map[string]*bucket
}

type bucket struct {
	start time.Time
	n     int
}

func newLimiter(max int, window time.Duration) *limiter {
	return &limiter{max: max, window: window, hits: map[string]*bucket{}}
}

// blocked reports whether key is over its limit, without counting.
func (l *limiter) blocked(key string, now time.Time) bool {
	l.mu.Lock()
	defer l.mu.Unlock()
	b := l.hits[key]
	return b != nil && now.Sub(b.start) <= l.window && b.n >= l.max
}

// fail counts one failed attempt.
func (l *limiter) fail(key string, now time.Time) {
	l.allow(key, now)
}

// allow counts one attempt and reports whether it is within the limit.
func (l *limiter) allow(key string, now time.Time) bool {
	l.mu.Lock()
	defer l.mu.Unlock()
	if len(l.hits) > 10000 {
		for k, b := range l.hits {
			if now.Sub(b.start) > l.window {
				delete(l.hits, k)
			}
		}
	}
	b := l.hits[key]
	if b == nil || now.Sub(b.start) > l.window {
		b = &bucket{start: now}
		l.hits[key] = b
	}
	b.n++
	return b.n <= l.max
}

// --- WAF audit cache ---

const auditTTL = 30 * time.Minute

func (s *Server) cachedAudit(ctx context.Context, zone config.Zone, force bool) (auditEntry, bool) {
	s.auditMu.Lock()
	e, ok := s.auditCache[zone.ZoneID]
	s.auditMu.Unlock()
	now := s.Now()
	if ok && (!force && now.Sub(e.at) < auditTTL || force && now.Sub(e.at) < time.Minute) {
		return e, force // force within a minute: refused, cached result returned
	}
	if s.Auditor == nil {
		return auditEntry{at: now, err: errors.New("audit unavailable")}, false
	}
	actx, cancel := context.WithTimeout(ctx, 2*time.Minute)
	defer cancel()
	d, err := s.Auditor(actx, zone)
	e = auditEntry{at: now, data: d, err: err}
	s.auditMu.Lock()
	s.auditCache[zone.ZoneID] = e
	s.auditMu.Unlock()
	return e, false
}

// lc is the UI language of the request carried by ctx (the console
// default outside a request).
func (s *Server) lc(ctx context.Context) lang {
	if rq, ok := ctx.Value(reqKey).(*Req); ok && rq.Lang != "" {
		return rq.Lang
	}
	return s.defLang
}

// L is the UI language of a request.
func (s *Server) L(r *http.Request) lang { return s.lc(r.Context()) }

// langPost switches the UI language: a cookie for this browser, and the
// account's preference when signed in with a local account.
func (s *Server) langPost(w http.ResponseWriter, r *http.Request) {
	l := r.PostFormValue("lang")
	if l != "en" && l != "zh" {
		http.Error(w, "bad language", http.StatusBadRequest)
		return
	}
	rq := reqOf(r)
	http.SetCookie(w, &http.Cookie{Name: langCookie, Value: l, Path: "/", HttpOnly: true, Secure: rq.Secure,
		SameSite: http.SameSiteLaxMode, MaxAge: 365 * 24 * 3600})
	if rq.User != nil && rq.User.ID != 0 && rq.Session != nil {
		if err := s.DB.SetLang(rq.User.ID, l); err != nil {
			log.Printf("console: language preference: %v", err)
		}
	}
	http.Redirect(w, r, localPath(r.PostFormValue("next")), http.StatusSeeOther)
}
