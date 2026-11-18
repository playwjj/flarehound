package console

import (
	"net/http"
	"strconv"
	"strings"
	"time"
)

// --- sign-in ---

func (s *Server) loginPage(w http.ResponseWriter, r *http.Request) {
	rq := reqOf(r)
	if rq.User != nil && (rq.Session == nil || rq.Session.MFAOK) {
		http.Redirect(w, r, localPath(r.URL.Query().Get("next")), http.StatusSeeOther)
		return
	}
	p := page{Title: s.L(r).t("login_title"), Next: localPath(r.URL.Query().Get("next")), Providers: s.ProviderList(), ResetOn: s.resetOn()}
	if r.URL.Query().Get("reset") == "1" {
		p.Flash = s.L(r).t("reset_done")
	}
	if s.Cfg.Console.ProxyAuth.DisableLogin {
		p.Msg = s.L(r).t("login_disabled")
	}
	s.render(w, r, http.StatusOK, "login", p)
}

func (s *Server) loginPost(w http.ResponseWriter, r *http.Request) {
	rq := reqOf(r)
	next := localPath(r.PostFormValue("next"))
	p := page{Title: s.L(r).t("login_title"), Next: next, Providers: s.ProviderList(), ResetOn: s.resetOn()}
	if s.Cfg.Console.ProxyAuth.DisableLogin {
		p.Msg = s.L(r).t("login_disabled")
		s.render(w, r, http.StatusForbidden, "login", p)
		return
	}
	// Only failures count: a person who signs in often is not throttled.
	if s.limiter.blocked("login:"+rq.IP, s.Now()) {
		p.Err = s.L(r).t("login_throttled")
		s.render(w, r, http.StatusTooManyRequests, "login", p)
		return
	}
	name := strings.TrimSpace(r.PostFormValue("username"))
	pw := r.PostFormValue("password")
	u, ok, err := s.DB.UserByName(name)
	if err != nil {
		s.fail(w, r, err)
		return
	}
	if !ok {
		s.limiter.fail("login:"+rq.IP, s.Now())
		VerifyPassword(dummyHash, pw) // same cost as a real check
		s.DB.Audit(name, rq.IP, "login_failed", name, "unknown user")
		p.Err = s.L(r).t("login_failed")
		s.render(w, r, http.StatusUnauthorized, "login", p)
		return
	}
	if s.Now().Before(u.LockedUntil) {
		VerifyPassword(dummyHash, pw)
		s.DB.Audit(u.Username, rq.IP, "login_failed", u.Username, "locked")
		p.Err = s.L(r).t("login_locked")
		s.render(w, r, http.StatusTooManyRequests, "login", p)
		return
	}
	if !VerifyPassword(u.PWHash, pw) || u.Disabled {
		s.limiter.fail("login:"+rq.IP, s.Now())
		if !u.Disabled {
			_ = s.DB.LoginFailed(u.ID)
		}
		s.DB.Audit(u.Username, rq.IP, "login_failed", u.Username, map[bool]string{true: "disabled", false: "bad password"}[u.Disabled])
		p.Err = s.L(r).t("login_failed")
		s.render(w, r, http.StatusUnauthorized, "login", p)
		return
	}
	_ = s.DB.LoginOK(u.ID)
	s.completeLogin(w, r, &u, "password", next)
}

// completeLogin starts a session for an authenticated first factor: a
// pending one when the account has TOTP (the code comes next), else a
// full one.
func (s *Server) completeLogin(w http.ResponseWriter, r *http.Request, u *User, method, next string) {
	rq := reqOf(r)
	if rq.Session != nil { // replace any previous session (fixation)
		_ = s.DB.EndSession(rq.Session.Token)
	}
	if u.TOTPEnabled {
		sess, err := s.DB.CreateSession(u.ID, false, preMFATTL, rq.IP, r.UserAgent())
		if err != nil {
			s.fail(w, r, err)
			return
		}
		s.setSession(w, r, sess, preMFATTL)
		http.Redirect(w, r, "/login/totp?next="+urlQuery(next), http.StatusSeeOther)
		return
	}
	sess, err := s.DB.CreateSession(u.ID, true, s.sessionTTL(), rq.IP, r.UserAgent())
	if err != nil {
		s.fail(w, r, err)
		return
	}
	s.setSession(w, r, sess, s.sessionTTL())
	s.DB.Audit(u.Username, rq.IP, "login", u.Username, method)
	http.Redirect(w, r, next, http.StatusSeeOther)
}

func (s *Server) totpPage(w http.ResponseWriter, r *http.Request) {
	rq := reqOf(r)
	if rq.Session == nil || rq.Session.MFAOK {
		http.Redirect(w, r, "/", http.StatusSeeOther)
		return
	}
	s.render(w, r, http.StatusOK, "totp", page{Title: s.L(r).t("totp_title"), Next: localPath(r.URL.Query().Get("next")), Action: "/login/totp"})
}

func (s *Server) totpPost(w http.ResponseWriter, r *http.Request) {
	rq := reqOf(r)
	if rq.Session == nil || rq.Session.MFAOK || rq.User == nil {
		http.Redirect(w, r, "/login", http.StatusSeeOther)
		return
	}
	next := localPath(r.PostFormValue("next"))
	p := page{Title: s.L(r).t("totp_title"), Next: next, Action: "/login/totp"}
	u := rq.User
	if ok, msg := s.verifyCode(r, u, r.PostFormValue("code")); !ok {
		s.DB.Audit(u.Username, rq.IP, "login_failed", u.Username, "bad TOTP code")
		// Wrong codes do not lock the account; five end this sign-in.
		s.totpSess.fail(rq.Session.Hash, s.Now())
		if s.totpSess.blocked(rq.Session.Hash, s.Now()) {
			_ = s.DB.EndSession(rq.Session.Token)
			s.clearSession(w, r)
			s.render(w, r, http.StatusUnauthorized, "login", page{Title: s.L(r).t("login_title"), Providers: s.ProviderList(),
				ResetOn: s.resetOn(), Err: s.L(r).t("totp_too_many")})
			return
		}
		p.Err = msg
		s.render(w, r, http.StatusUnauthorized, "totp", p)
		return
	}
	_ = s.DB.LoginOK(u.ID)
	sess, err := s.DB.PromoteSession(*rq.Session, s.sessionTTL())
	if err != nil {
		s.fail(w, r, err)
		return
	}
	s.setSession(w, r, sess, s.sessionTTL())
	s.DB.Audit(u.Username, rq.IP, "login", u.Username, "password+totp")
	http.Redirect(w, r, next, http.StatusSeeOther)
}

// verifyCode checks a TOTP code for u with throttling that counts only
// failures: per client address (10 a minute) and per account (20 an
// hour). It returns the message to show on failure.
func (s *Server) verifyCode(r *http.Request, u *User, code string) (bool, string) {
	rq := reqOf(r)
	now := s.Now()
	acct := "totp:" + strconv.FormatInt(u.ID, 10)
	if s.limiter.blocked("totp:"+rq.IP, now) || s.totpAcct.blocked(acct, now) {
		return false, s.L(r).t("login_throttled")
	}
	if s.checkTOTP(u, code) {
		return true, ""
	}
	s.limiter.fail("totp:"+rq.IP, now)
	s.totpAcct.fail(acct, now)
	return false, s.L(r).t("totp_wrong")
}

// checkTOTP verifies a code and consumes its time step.
func (s *Server) checkTOTP(u *User, code string) bool {
	if !u.TOTPEnabled || u.TOTPSecret == "" {
		return false
	}
	step, ok := VerifyTOTP(u.TOTPSecret, code, s.Now(), u.TOTPLastStep)
	if !ok {
		return false
	}
	used, err := s.DB.UseTOTPStep(u.ID, step)
	return err == nil && used
}

func (s *Server) logout(w http.ResponseWriter, r *http.Request) {
	rq := reqOf(r)
	if rq.Session != nil {
		_ = s.DB.EndSession(rq.Session.Token)
		s.audit(r, "logout", rq.User.Username, "")
	}
	s.clearSession(w, r)
	http.Redirect(w, r, "/login", http.StatusSeeOther)
}

func (s *Server) stepUpPage(w http.ResponseWriter, r *http.Request) {
	s.render(w, r, http.StatusOK, "totp", page{Title: s.L(r).t("stepup_title"), Msg: s.L(r).t("stepup_desc"),
		Next: localPath(r.URL.Query().Get("next")), Action: "/stepup"})
}

func (s *Server) stepUpPost(w http.ResponseWriter, r *http.Request) {
	rq := reqOf(r)
	next := localPath(r.PostFormValue("next"))
	if rq.Session == nil || !rq.User.TOTPEnabled {
		http.Redirect(w, r, next, http.StatusSeeOther)
		return
	}
	if ok, msg := s.verifyCode(r, rq.User, r.PostFormValue("code")); !ok {
		s.audit(r, "stepup_failed", rq.User.Username, "")
		s.render(w, r, http.StatusUnauthorized, "totp", page{Title: s.L(r).t("stepup_title"), Msg: s.L(r).t("stepup_desc"),
			Next: next, Action: "/stepup", Err: msg})
		return
	}
	if err := s.DB.MarkStepUp(rq.Session.Hash); err != nil {
		s.fail(w, r, err)
		return
	}
	s.audit(r, "stepup", rq.User.Username, "")
	http.Redirect(w, r, next, http.StatusSeeOther)
}

// --- first admin ---

func (s *Server) setupValid(token string) bool {
	s.setupMu.Lock()
	defer s.setupMu.Unlock()
	if s.setupToken == "" || len(token) != len(s.setupToken) {
		return false
	}
	if n, err := s.DB.CountUsers(); err != nil || n > 0 {
		s.setupToken = ""
		return false
	}
	return token == s.setupToken
}

func (s *Server) setupPage(w http.ResponseWriter, r *http.Request) {
	tok := r.URL.Query().Get("token")
	if !s.setupValid(tok) {
		s.render(w, r, http.StatusNotFound, "message", page{Title: s.L(r).t("setup_title"), Msg: s.L(r).t("setup_bad")})
		return
	}
	s.render(w, r, http.StatusOK, "setup", page{Title: s.L(r).t("setup_title"), Token: tok})
}

func (s *Server) setupPost(w http.ResponseWriter, r *http.Request) {
	tok := r.PostFormValue("token")
	if !s.limiter.allow("login:"+reqOf(r).IP, s.Now()) || !s.setupValid(tok) {
		s.render(w, r, http.StatusNotFound, "message", page{Title: s.L(r).t("setup_title"), Msg: s.L(r).t("setup_bad")})
		return
	}
	p := page{Title: s.L(r).t("setup_title"), Token: tok}
	pw := r.PostFormValue("password")
	if pw != r.PostFormValue("password2") {
		p.Err = s.L(r).t("pw_mismatch")
		s.render(w, r, http.StatusBadRequest, "setup", p)
		return
	}
	s.setupMu.Lock()
	u, err := s.DB.CreateUser(strings.TrimSpace(r.PostFormValue("username")), r.PostFormValue("email"), pw, RoleAdmin, false)
	if err == nil {
		s.setupToken = ""
	}
	s.setupMu.Unlock()
	if err != nil {
		p.Err = err.Error()
		s.render(w, r, http.StatusBadRequest, "setup", p)
		return
	}
	s.DB.Audit(u.Username, reqOf(r).IP, "setup_admin", u.Username, "first admin via setup link")
	http.Redirect(w, r, "/login", http.StatusSeeOther)
}

// --- invitations ---

func (s *Server) invitePage(w http.ResponseWriter, r *http.Request) {
	tok := r.PathValue("token")
	inv, ok, err := s.DB.InviteByToken(tok)
	if err != nil {
		s.fail(w, r, err)
		return
	}
	if !ok {
		s.render(w, r, http.StatusNotFound, "message", page{Title: s.L(r).t("invite_title"), Msg: s.L(r).t("invite_bad")})
		return
	}
	s.render(w, r, http.StatusOK, "invite", page{Title: s.L(r).t("invite_title"), Token: tok, Role: inv.Role})
}

func (s *Server) invitePost(w http.ResponseWriter, r *http.Request) {
	tok := r.PathValue("token")
	if !s.limiter.allow("login:"+reqOf(r).IP, s.Now()) {
		s.render(w, r, http.StatusTooManyRequests, "message", page{Title: s.L(r).t("invite_title"), Msg: s.L(r).t("login_throttled")})
		return
	}
	inv, ok, err := s.DB.InviteByToken(tok)
	if err != nil {
		s.fail(w, r, err)
		return
	}
	if !ok {
		s.render(w, r, http.StatusNotFound, "message", page{Title: s.L(r).t("invite_title"), Msg: s.L(r).t("invite_bad")})
		return
	}
	p := page{Title: s.L(r).t("invite_title"), Token: tok, Role: inv.Role}
	pw := r.PostFormValue("password")
	if pw != r.PostFormValue("password2") {
		p.Err = s.L(r).t("pw_mismatch")
		s.render(w, r, http.StatusBadRequest, "invite", p)
		return
	}
	u, err := s.DB.AcceptInvite(tok, strings.TrimSpace(r.PostFormValue("username")), r.PostFormValue("email"), pw)
	if err != nil {
		p.Err = err.Error()
		s.render(w, r, http.StatusBadRequest, "invite", p)
		return
	}
	s.DB.Audit(u.Username, reqOf(r).IP, "invite_accepted", u.Username, "role "+u.Role)
	http.Redirect(w, r, "/login", http.StatusSeeOther)
}

// --- own account ---

func (s *Server) accountData(r *http.Request, p *page) error {
	rq := reqOf(r)
	if rq.User.ID == 0 {
		return nil
	}
	sessions, err := s.DB.UserSessions(rq.User.ID)
	if err != nil {
		return err
	}
	p.Sessions = sessions
	p.Providers = s.ProviderList()
	p.Identities, err = s.DB.Identities(rq.User.ID)
	return err
}

func (s *Server) accountPage(w http.ResponseWriter, r *http.Request) {
	rq := reqOf(r)
	p := page{Title: s.L(r).t("acct_title")}
	if rq.User.ID != 0 {
		// Re-read: the account may have changed since the request began.
		u, err := s.DB.UserByID(rq.User.ID)
		if err != nil {
			s.fail(w, r, err)
			return
		}
		rq.User = &u
		switch {
		case u.MustChange:
			p.Msg = s.L(r).t("must_change")
		case s.Cfg.Console.RequireTOTP && !u.TOTPEnabled:
			p.Msg = s.L(r).t("must_totp")
		}
		if u.TOTPSecret != "" && !u.TOTPEnabled {
			p.TOTPSecret = GroupSecret(u.TOTPSecret)
			p.TOTPURI = TOTPURI("FlareHound", u.Username, u.TOTPSecret)
			if svg, err := qrSVG(p.TOTPURI); err == nil {
				p.TOTPQR = svg
			}
		}
	}
	p.Flash = r.URL.Query().Get("ok")
	if err := s.accountData(r, &p); err != nil {
		s.fail(w, r, err)
		return
	}
	s.render(w, r, http.StatusOK, "account", p)
}

func (s *Server) accountErr(w http.ResponseWriter, r *http.Request, msg string) {
	p := page{Title: s.L(r).t("acct_title"), Err: msg}
	_ = s.accountData(r, &p)
	s.render(w, r, http.StatusBadRequest, "account", p)
}

func (s *Server) localUser(w http.ResponseWriter, r *http.Request) (*User, bool) {
	rq := reqOf(r)
	if rq.User.ID == 0 || rq.Session == nil {
		s.render(w, r, http.StatusForbidden, "message", page{Title: s.L(r).t("forbidden"), Msg: s.L(r).t("forbidden")})
		return nil, false
	}
	u, err := s.DB.UserByID(rq.User.ID)
	if err != nil {
		s.fail(w, r, err)
		return nil, false
	}
	return &u, true
}

func (s *Server) accountPassword(w http.ResponseWriter, r *http.Request) {
	u, ok := s.localUser(w, r)
	if !ok {
		return
	}
	rq := reqOf(r)
	if !s.limiter.allow("login:"+rq.IP, s.Now()) {
		s.accountErr(w, r, s.L(r).t("login_throttled"))
		return
	}
	if !VerifyPassword(u.PWHash, r.PostFormValue("current")) {
		s.audit(r, "password_change_failed", u.Username, "wrong current password")
		s.accountErr(w, r, s.L(r).t("pw_wrong"))
		return
	}
	pw := r.PostFormValue("password")
	if pw != r.PostFormValue("password2") {
		s.accountErr(w, r, s.L(r).t("pw_mismatch"))
		return
	}
	if err := s.DB.SetPassword(u.ID, pw, false, rq.Session.Token); err != nil {
		s.accountErr(w, r, err.Error())
		return
	}
	s.audit(r, "password_changed", u.Username, "")
	http.Redirect(w, r, "/account?ok="+urlQuery(s.L(r).t("pw_changed")), http.StatusSeeOther)
}

func (s *Server) totpStart(w http.ResponseWriter, r *http.Request) {
	u, ok := s.localUser(w, r)
	if !ok {
		return
	}
	if u.TOTPEnabled {
		http.Redirect(w, r, "/account", http.StatusSeeOther)
		return
	}
	secret, err := NewTOTPSecret()
	if err != nil {
		s.fail(w, r, err)
		return
	}
	if err := s.DB.SetTOTP(u.ID, secret, false, 0); err != nil {
		s.fail(w, r, err)
		return
	}
	http.Redirect(w, r, "/account", http.StatusSeeOther)
}

func (s *Server) totpConfirm(w http.ResponseWriter, r *http.Request) {
	u, ok := s.localUser(w, r)
	if !ok {
		return
	}
	if u.TOTPEnabled || u.TOTPSecret == "" {
		http.Redirect(w, r, "/account", http.StatusSeeOther)
		return
	}
	if s.limiter.blocked("totp:"+reqOf(r).IP, s.Now()) {
		s.accountErr(w, r, s.L(r).t("login_throttled"))
		return
	}
	step, ok := VerifyTOTP(u.TOTPSecret, r.PostFormValue("code"), s.Now(), 0)
	if !ok {
		s.limiter.fail("totp:"+reqOf(r).IP, s.Now())
		s.accountErr(w, r, s.L(r).t("totp_wrong"))
		return
	}
	if err := s.DB.SetTOTP(u.ID, u.TOTPSecret, true, step); err != nil {
		s.fail(w, r, err)
		return
	}
	_ = s.DB.MarkStepUp(reqOf(r).Session.Hash)
	s.audit(r, "totp_enabled", u.Username, "")
	http.Redirect(w, r, "/account?ok="+urlQuery(s.L(r).t("totp_enabled_msg")), http.StatusSeeOther)
}

func (s *Server) totpDisable(w http.ResponseWriter, r *http.Request) {
	u, ok := s.localUser(w, r)
	if !ok {
		return
	}
	if s.Cfg.Console.RequireTOTP {
		s.accountErr(w, r, s.L(r).t("totp_required_no_off"))
		return
	}
	if !VerifyPassword(u.PWHash, r.PostFormValue("current")) {
		s.limiter.fail("login:"+reqOf(r).IP, s.Now())
		s.accountErr(w, r, s.L(r).t("pw_wrong"))
		return
	}
	if u.TOTPEnabled {
		if ok, msg := s.verifyCode(r, u, r.PostFormValue("code")); !ok {
			s.accountErr(w, r, msg)
			return
		}
	}
	if err := s.DB.SetTOTP(u.ID, "", false, 0); err != nil {
		s.fail(w, r, err)
		return
	}
	s.audit(r, "totp_disabled", u.Username, "")
	http.Redirect(w, r, "/account?ok="+urlQuery(s.L(r).t("totp_disabled_msg")), http.StatusSeeOther)
}

func (s *Server) sessionEnd(w http.ResponseWriter, r *http.Request) {
	u, ok := s.localUser(w, r)
	if !ok {
		return
	}
	rq := reqOf(r)
	var err error
	if r.PostFormValue("all") == "1" {
		err = s.DB.EndUserSessions(u.ID, rq.Session.Token)
		s.audit(r, "sessions_ended", u.Username, "all other sessions")
	} else {
		err = s.DB.EndSessionByHash(u.ID, r.PostFormValue("id"))
		s.audit(r, "session_ended", u.Username, "")
	}
	if err != nil {
		s.fail(w, r, err)
		return
	}
	http.Redirect(w, r, "/account", http.StatusSeeOther)
}

// --- user administration (admin) ---

func (s *Server) usersPage(w http.ResponseWriter, r *http.Request) {
	p := page{Title: s.L(r).t("users_title"), Flash: r.URL.Query().Get("ok")}
	if err := s.usersData(&p); err != nil {
		s.fail(w, r, err)
		return
	}
	s.render(w, r, http.StatusOK, "users", p)
}

func (s *Server) usersData(p *page) error {
	var err error
	if p.Users, err = s.DB.Users(); err != nil {
		return err
	}
	if p.Invites, err = s.DB.PendingInvites(); err != nil {
		return err
	}
	ids, err := s.DB.Identities(0)
	if err != nil {
		return err
	}
	p.UserIDs = map[int64][]Identity{}
	for _, i := range ids {
		p.UserIDs[i.UserID] = append(p.UserIDs[i.UserID], i)
	}
	p.AuditLog, err = s.DB.AuditLog(100)
	return err
}

func (s *Server) usersResult(w http.ResponseWriter, r *http.Request, p page, status int) {
	p.Title = s.L(r).t("users_title")
	if err := s.usersData(&p); err != nil {
		s.fail(w, r, err)
		return
	}
	s.render(w, r, status, "users", p)
}

func (s *Server) userCreate(w http.ResponseWriter, r *http.Request) {
	role := r.PostFormValue("role")
	temp := randToken(12)
	u, err := s.DB.CreateUser(strings.TrimSpace(r.PostFormValue("username")), r.PostFormValue("email"), temp, role, true)
	if err != nil {
		s.usersResult(w, r, page{Err: err.Error()}, http.StatusBadRequest)
		return
	}
	s.audit(r, "user_created", u.Username, "role "+u.Role)
	s.usersResult(w, r, page{Secret: temp, SecretFor: u.Username, Flash: s.L(r).t("done")}, http.StatusOK)
}

func (s *Server) userOp(w http.ResponseWriter, r *http.Request) {
	rq := reqOf(r)
	id, err := strconv.ParseInt(r.PathValue("id"), 10, 64)
	if err != nil {
		http.NotFound(w, r)
		return
	}
	u, err := s.DB.UserByID(id)
	if err != nil {
		http.NotFound(w, r)
		return
	}
	op := r.PathValue("op")
	if u.ID == rq.User.ID && op != "signout" {
		s.usersResult(w, r, page{Err: s.L(r).t("not_self")}, http.StatusBadRequest)
		return
	}
	lastAdmin := func() bool {
		n, err := s.DB.CountActiveAdmins()
		return err == nil && u.Admin() && !u.Disabled && n <= 1
	}
	var p page
	switch op {
	case "admin", "viewer":
		if op == RoleViewer && lastAdmin() {
			s.usersResult(w, r, page{Err: s.L(r).t("last_admin")}, http.StatusBadRequest)
			return
		}
		err = s.DB.SetRole(u.ID, op)
	case "disable":
		if lastAdmin() {
			s.usersResult(w, r, page{Err: s.L(r).t("last_admin")}, http.StatusBadRequest)
			return
		}
		err = s.DB.SetDisabled(u.ID, true)
	case "enable":
		err = s.DB.SetDisabled(u.ID, false)
	case "unlock":
		err = s.DB.Unlock(u.ID)
	case "reset":
		temp := randToken(12)
		err = s.DB.SetPassword(u.ID, temp, true, "")
		p.Secret, p.SecretFor = temp, u.Username
	case "totp":
		if err = s.DB.SetTOTP(u.ID, "", false, 0); err == nil {
			err = s.DB.EndUserSessions(u.ID, "")
		}
	case "unlink":
		_, err = s.DB.UnlinkIdentity(u.ID, r.PostFormValue("provider"), r.PostFormValue("subject"))
	case "signout":
		keep := ""
		if u.ID == rq.User.ID {
			keep = rq.Session.Token
		}
		err = s.DB.EndUserSessions(u.ID, keep)
	default:
		http.NotFound(w, r)
		return
	}
	if err != nil {
		s.fail(w, r, err)
		return
	}
	s.audit(r, "user_"+op, u.Username, "")
	if p.Secret != "" {
		p.Flash = s.L(r).t("done")
		s.usersResult(w, r, p, http.StatusOK)
		return
	}
	http.Redirect(w, r, "/users?ok="+urlQuery(s.L(r).t("done")), http.StatusSeeOther)
}

const inviteTTL = 72 * time.Hour

func (s *Server) inviteCreate(w http.ResponseWriter, r *http.Request) {
	rq := reqOf(r)
	role := r.PostFormValue("role")
	tok, err := s.DB.CreateInvite(role, rq.User.ID, inviteTTL)
	if err != nil {
		s.usersResult(w, r, page{Err: err.Error()}, http.StatusBadRequest)
		return
	}
	s.audit(r, "invite_created", role, "valid 72h")
	link := s.baseURL(r) + "/invite/" + tok
	s.usersResult(w, r, page{InviteLink: link, Flash: s.L(r).t("done")}, http.StatusOK)
}

func (s *Server) inviteRevoke(w http.ResponseWriter, r *http.Request) {
	if err := s.DB.RevokeInvite(r.PostFormValue("id")); err != nil {
		s.fail(w, r, err)
		return
	}
	s.audit(r, "invite_revoked", "", "")
	http.Redirect(w, r, "/users?ok="+urlQuery(s.L(r).t("done")), http.StatusSeeOther)
}

// baseURL is console.base_url, else derived from the request.
func (s *Server) baseURL(r *http.Request) string {
	if s.Cfg.Console.BaseURL != "" {
		return s.Cfg.Console.BaseURL
	}
	scheme := "http"
	if reqOf(r).Secure {
		scheme = "https"
	}
	return scheme + "://" + r.Host
}
