package console

// Password reset by e-mail (docs/web-console-revision.md §5.2): a single-
// use link, valid 30 minutes, sent to the address on the account through
// the e-mail settings already used for notifications. The request page
// answers the same whether or not the account exists (no enumeration),
// and the mail is sent in the background so timing does not tell either.
// A reset ends every session of the account; it does not touch two-factor
// sign-in — the new password still needs the TOTP code.

import (
	"context"
	"fmt"
	"log"
	"net/http"
	"strings"
	"time"

	"github.com/playwjj/flarehound/internal/notify"
)

const (
	resetTTL      = 30 * time.Minute
	resetInterval = 10 * time.Minute // at most one mail per account in this time
)

// MailSender sends one plain-text message to one address.
type MailSender func(ctx context.Context, to, subject, body string) error

// EmailSender sends through notify.email's settings (SMTP or Resend).
func EmailSender(e notify.Email) MailSender {
	return func(ctx context.Context, to, subject, body string) error {
		e.To = []string{to}
		return e.Send(ctx, notify.Message{Kind: "password_reset", Text: subject + "\n\n" + body})
	}
}

// resetOn reports whether password reset by e-mail is available.
func (s *Server) resetOn() bool {
	return s.Mail != nil && s.Cfg.Console.BaseURL != "" && !s.Cfg.Console.ProxyAuth.DisableLogin
}

func (s *Server) forgotPage(w http.ResponseWriter, r *http.Request) {
	if !s.resetOn() {
		http.NotFound(w, r)
		return
	}
	s.render(w, r, http.StatusOK, "forgot", page{Title: s.L(r).t("forgot_title")})
}

func (s *Server) forgotPost(w http.ResponseWriter, r *http.Request) {
	if !s.resetOn() {
		http.NotFound(w, r)
		return
	}
	rq := reqOf(r)
	p := page{Title: s.L(r).t("forgot_title")}
	if !s.limiter.allow("reset:"+rq.IP, s.Now()) {
		p.Err = s.L(r).t("login_throttled")
		s.render(w, r, http.StatusTooManyRequests, "forgot", p)
		return
	}
	id := strings.TrimSpace(r.PostFormValue("identity"))
	if id != "" && len(id) <= 254 {
		s.maybeSendReset(id, rq.IP, r.UserAgent())
	}
	// The same answer whatever happened.
	p.Flash = s.L(r).t("forgot_sent")
	s.render(w, r, http.StatusOK, "forgot", p)
}

// maybeSendReset issues and mails a link when the account exists, is
// enabled, has an address and has not had one in the last 10 minutes.
func (s *Server) maybeSendReset(identity, ip, ua string) {
	u, ok, err := s.DB.UserByIdentity(identity)
	if err != nil || !ok || u.Disabled || u.Email == "" {
		s.DB.Audit("-", ip, "reset_requested", truncate(identity, 80), "no mail: unknown, disabled or no address")
		return
	}
	if last, err := s.DB.LastResetAt(u.ID); err == nil && s.Now().Sub(last) < resetInterval {
		s.DB.Audit(u.Username, ip, "reset_requested", u.Username, "no mail: one was sent less than 10 minutes ago")
		return
	}
	tok, err := s.DB.CreateReset(u.ID, resetTTL)
	if err != nil {
		log.Printf("console: password reset: %v", err)
		return
	}
	ml := s.defLang // the mail goes out in the account's language
	if u.Lang == "en" || u.Lang == "zh" {
		ml = lang(u.Lang)
	}
	link := s.Cfg.Console.BaseURL + "/reset/" + tok
	subject := ml.t("reset_mail_subject")
	body := fmt.Sprintf(ml.t("reset_mail_body"), u.Username, link, int(resetTTL.Minutes()), ip, truncate(ua, 120))
	s.DB.Audit(u.Username, ip, "reset_requested", u.Username, "link mailed to "+maskEmail(u.Email))
	s.resetWG.Add(1)
	go func() {
		defer s.resetWG.Done()
		ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
		defer cancel()
		if err := s.Mail(ctx, u.Email, subject, body); err != nil {
			log.Printf("console: password reset mail for %s: %v", u.Username, err)
			s.DB.Audit(u.Username, ip, "reset_mail_failed", u.Username, err.Error())
		}
	}()
}

// maskEmail keeps an address recognisable in logs without storing it whole.
func maskEmail(e string) string {
	local, domain, ok := strings.Cut(e, "@")
	if !ok || local == "" {
		return "***"
	}
	return local[:1] + "***@" + domain
}

func (s *Server) resetPage(w http.ResponseWriter, r *http.Request) {
	u, ok, err := s.DB.ResetUser(r.PathValue("token"))
	if err != nil {
		s.fail(w, r, err)
		return
	}
	if !ok || !s.resetOn() {
		s.render(w, r, http.StatusNotFound, "message", page{Title: s.L(r).t("reset_title"), Msg: s.L(r).t("reset_bad")})
		return
	}
	s.render(w, r, http.StatusOK, "reset", page{Title: s.L(r).t("reset_title"), Token: r.PathValue("token"), Role: u.Username})
}

func (s *Server) resetPost(w http.ResponseWriter, r *http.Request) {
	rq := reqOf(r)
	tok := r.PathValue("token")
	if !s.resetOn() {
		http.NotFound(w, r)
		return
	}
	u, ok, err := s.DB.ResetUser(tok)
	if err != nil {
		s.fail(w, r, err)
		return
	}
	if !ok || !s.limiter.allow("reset:"+rq.IP, s.Now()) {
		s.render(w, r, http.StatusNotFound, "message", page{Title: s.L(r).t("reset_title"), Msg: s.L(r).t("reset_bad")})
		return
	}
	p := page{Title: s.L(r).t("reset_title"), Token: tok, Role: u.Username}
	pw := r.PostFormValue("password")
	if pw != r.PostFormValue("password2") {
		p.Err = s.L(r).t("pw_mismatch")
		s.render(w, r, http.StatusBadRequest, "reset", p)
		return
	}
	if _, err := s.DB.UseReset(tok, pw); err != nil {
		p.Err = err.Error()
		s.render(w, r, http.StatusBadRequest, "reset", p)
		return
	}
	s.DB.Audit(u.Username, rq.IP, "password_reset", u.Username, "by e-mail link; all sessions ended")
	if rq.Session != nil {
		s.clearSession(w, r)
	}
	http.Redirect(w, r, "/login?reset=1", http.StatusSeeOther)
}
