package console

// In-console blocking (v1.4, docs/web-console-revision.md §4.6 / §5.1).
//
// Every write goes form → review → apply:
//   - review runs the same guard rails, plan and measurement as the CLI
//     (blockcli.Prepare) and shows them; it changes nothing;
//   - apply needs a review token (HMAC over exactly what was reviewed, by
//     whom, valid 15 minutes), the CSRF token, the typed target for strong
//     confirmations and — for accounts with TOTP — a fresh code. It runs
//     the guard rails again server-side: the page is never trusted.
//   - the console audit log is written before Cloudflare is touched;
//     outcome (applied / failed) after. The archive's block log records
//     the operator as "console:<account>".

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/playwjj/flarehound/internal/block"
	"github.com/playwjj/flarehound/internal/blockcli"
	"github.com/playwjj/flarehound/internal/blockeffect"
	"github.com/playwjj/flarehound/internal/cfapi"
	"github.com/playwjj/flarehound/internal/config"
	"github.com/playwjj/flarehound/internal/health"
	"github.com/playwjj/flarehound/internal/store"
)

// LiveAPI is the read-token analytics the write flows need (measurement,
// attempts, before/after comparison).
type LiveAPI interface {
	blockcli.ReadAPI
	Top(ctx context.Context, zoneID string, from, to time.Time, dim string, limit int, f cfapi.Filter) ([]cfapi.Face, error)
}

const (
	reviewTTL   = 15 * time.Minute
	writeTO     = 2 * time.Minute
	attemptsTTL = 10 * time.Minute
	effectDim   = "edgeResponseStatus"
)

// CanWrite reports whether this console holds the write token.
func (s *Server) CanWrite() bool { return s.Write != nil && s.Live != nil && s.Store != nil }

func (s *Server) actor(rq *Req) string {
	a := "console:" + rq.User.Username
	if rq.Proxy != "" && rq.Session == nil {
		a += " (proxy)"
	}
	return a
}

func (s *Server) env(z config.Zone, rq *Req) *blockcli.Env {
	actor := "console"
	if rq != nil && rq.User != nil {
		actor = s.actor(rq)
	}
	return &blockcli.Env{Cfg: s.Cfg, Zone: z, Read: s.Live, Write: s.Write, Store: s.Store,
		In: strings.NewReader(""), Out: io.Discard, Now: s.Now, Actor: actor}
}

// --- review tokens ---

func (s *Server) reviewMAC(rq *Req, ts string, fields []string) string {
	m := hmac.New(sha256.New, s.reviewKey)
	m.Write([]byte(strings.Join(append([]string{ts, strconv.FormatInt(rq.User.ID, 10), rq.User.Username}, fields...), "\x00")))
	return hex.EncodeToString(m.Sum(nil))
}

func (s *Server) reviewToken(rq *Req, fields ...string) string {
	ts := strconv.FormatInt(s.Now().Unix(), 10)
	return ts + "." + s.reviewMAC(rq, ts, fields)
}

func (s *Server) reviewOK(rq *Req, tok string, fields ...string) bool {
	ts, mac, ok := strings.Cut(tok, ".")
	if !ok {
		return false
	}
	n, err := strconv.ParseInt(ts, 10, 64)
	if err != nil || s.Now().Sub(time.Unix(n, 0)) > reviewTTL || s.Now().Before(time.Unix(n, 0).Add(-time.Minute)) {
		return false
	}
	return hmac.Equal([]byte(mac), []byte(s.reviewMAC(rq, ts, fields)))
}

// --- forms ---

// blockForm is the user's request, as posted.
type blockForm struct {
	Zone   config.Zone
	Type   string
	Value  string
	Action string
	For    string // "", 1h, 24h, 7d, 30d
	Reason string
}

func (f blockForm) fields() []string {
	return []string{"block", f.Zone.ZoneID, f.Type, f.Value, f.Action, f.For, f.Reason}
}

func (f blockForm) query() string {
	q := url.Values{"z": {f.Zone.Name}, "type": {f.Type}, "value": {f.Value}, "action": {f.Action}, "for": {f.For}, "reason": {f.Reason}}
	return q.Encode()
}

var ttlChoices = map[string]time.Duration{"": 0, "1h": time.Hour, "24h": 24 * time.Hour, "7d": 7 * 24 * time.Hour, "30d": 30 * 24 * time.Hour}

func (s *Server) parseBlockForm(r *http.Request) (blockForm, block.Target, blockcli.BlockOpts, error) {
	get := func(k string) string {
		if r.Method == http.MethodPost {
			return strings.TrimSpace(r.PostFormValue(k))
		}
		return strings.TrimSpace(r.URL.Query().Get(k))
	}
	f := blockForm{Zone: s.zone(r), Type: get("type"), Value: get("value"), Action: get("action"), For: get("for"), Reason: truncate(get("reason"), 200)}
	t, err := block.Parse(f.Type, f.Value)
	if err != nil {
		return f, t, blockcli.BlockOpts{}, err
	}
	o := blockcli.BlockOpts{Reason: f.Reason}
	if f.Action != "" {
		if o.Action, err = block.ParseAction(f.Action); err != nil {
			return f, t, o, err
		}
	}
	ttl, ok := ttlChoices[f.For]
	if !ok {
		return f, t, o, fmt.Errorf("unknown duration %q", f.For)
	}
	o.TTL = ttl
	return f, t, o, nil
}

// requireWrite gates the write pages: admin, and a console holding the token.
func (s *Server) requireWrite(h http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if !s.CanWrite() {
			s.render(w, r, http.StatusForbidden, "message", page{Title: s.L(r).t("nav_blocks"), Msg: s.L(r).t("write_off")})
			return
		}
		h(w, r)
	}
}

// writeCheck verifies what every apply needs besides the review token:
// a fresh TOTP code for accounts that have it.
func (s *Server) writeCheck(r *http.Request) string {
	rq := reqOf(r)
	if rq.User.TOTPEnabled {
		u, err := s.DB.UserByID(rq.User.ID)
		if err != nil {
			return s.L(r).t("error")
		}
		if ok, msg := s.verifyCode(r, &u, r.PostFormValue("code")); !ok {
			s.audit(r, "stepup_failed", "", "write confirmation")
			return msg
		}
	}
	return ""
}

// --- block ---

func (s *Server) blockNewPage(w http.ResponseWriter, r *http.Request) {
	f, _, _, err := s.parseBlockForm(r)
	p := page{Title: s.L(r).t("block_new"), Zone: f.Zone, Nav: "blocks", Form: &f}
	if err != nil && f.Value != "" {
		p.Err = err.Error()
	}
	s.render(w, r, http.StatusOK, "blocknew", p)
}

func (s *Server) blockReview(w http.ResponseWriter, r *http.Request) {
	rq := reqOf(r)
	f, t, o, err := s.parseBlockForm(r)
	p := page{Title: s.L(r).t("block_review"), Zone: f.Zone, Nav: "blocks", Form: &f}
	if err != nil {
		p.Err = err.Error()
		s.render(w, r, http.StatusBadRequest, "blocknew", p)
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), writeTO)
	defer cancel()
	prep, err := s.env(f.Zone, rq).Prepare(ctx, t, o)
	if err != nil {
		p.Err = err.Error()
		s.render(w, r, http.StatusOK, "blockreview", p)
		return
	}
	p.Prep = prep
	if !prep.AlreadyDone() {
		p.Token = s.reviewToken(rq, f.fields()...)
	}
	s.render(w, r, http.StatusOK, "blockreview", p)
}

func (s *Server) blockApply(w http.ResponseWriter, r *http.Request) {
	rq := reqOf(r)
	f, t, o, err := s.parseBlockForm(r)
	p := page{Title: s.L(r).t("block_review"), Zone: f.Zone, Nav: "blocks", Form: &f}
	if err != nil {
		p.Err = err.Error()
		s.render(w, r, http.StatusBadRequest, "blocknew", p)
		return
	}
	if !s.reviewOK(rq, r.PostFormValue("review"), f.fields()...) {
		p.Err = s.L(r).t("review_expired")
		s.render(w, r, http.StatusBadRequest, "blocknew", p)
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), writeTO)
	defer cancel()
	env := s.env(f.Zone, rq)
	// Server-side guard rails again: the state may have changed since review.
	prep, err := env.Prepare(ctx, t, o)
	if err != nil {
		s.audit(r, "block_refused", t.String(), err.Error())
		p.Err = err.Error()
		s.render(w, r, http.StatusBadRequest, "blockreview", p)
		return
	}
	p.Prep = prep
	if prep.AlreadyDone() {
		http.Redirect(w, r, "/blocks?z="+url.QueryEscape(f.Zone.Name)+"&ok="+url.QueryEscape(prep.Plan.Note), http.StatusSeeOther)
		return
	}
	retry := func(msg string) {
		p.Err = msg
		p.Token = s.reviewToken(rq, f.fields()...)
		s.render(w, r, http.StatusBadRequest, "blockreview", p)
	}
	if !prep.ConfirmOK(r.PostFormValue("confirm")) {
		retry(fmt.Sprintf(s.L(r).t("strong_wrong"), prep.StrongWant))
		return
	}
	if msg := s.writeCheck(r); msg != "" {
		retry(msg)
		return
	}
	// Audit first: nothing reaches Cloudflare without a record.
	detail := fmt.Sprintf("zone %s; action %s; ttl %s; mechanism: %s; position: %s; measured: %s; warnings: %d; bypass warnings: %d; strong: %v; reason: %s",
		f.Zone.Name, prep.Opts.Action, orDash(f.For), prep.Plan.Note, orDash(prep.Where), orDash(prep.Measured), len(prep.Warnings), len(prep.Bypass), prep.Strong, orDash(f.Reason))
	if err := s.DB.Audit(s.actor(rq), rq.IP, "block_requested", t.String(), detail); err != nil {
		s.fail(w, r, fmt.Errorf("audit log unavailable, nothing changed: %w", err))
		return
	}
	notes := len(prep.Notes)
	entry, err := env.Execute(ctx, prep)
	if err != nil && !errors.Is(err, blockcli.ErrAuditFailed) {
		s.audit(r, "block_failed", t.String(), err.Error())
		retry(s.L(r).t("write_failed") + " " + err.Error())
		return
	}
	s.audit(r, "block_applied", t.String(), fmt.Sprintf("%s via %s (rule %s), verified by read-back", prep.Opts.Action, entry.Mechanism, entry.RuleID))
	msg := fmt.Sprintf(s.L(r).t("block_done"), t.String(), prep.Opts.Action)
	if err != nil {
		msg += " — " + err.Error()
	}
	for _, n := range prep.Notes[notes:] {
		msg += " — " + n
	}
	http.Redirect(w, r, "/blocks?z="+url.QueryEscape(f.Zone.Name)+"&ok="+url.QueryEscape(msg), http.StatusSeeOther)
}

func orDash(s string) string {
	if s == "" {
		return "-"
	}
	return s
}

// --- unblock ---

func (s *Server) targetForm(r *http.Request) (config.Zone, block.Target, string, error) {
	z := s.zone(r)
	t, err := block.Parse(r.PostFormValue("type"), r.PostFormValue("value"))
	return z, t, truncate(strings.TrimSpace(r.PostFormValue("reason")), 200), err
}

func (s *Server) unblockReview(w http.ResponseWriter, r *http.Request) {
	z, t, reason, err := s.targetForm(r)
	s.renderUnblockReview(w, r, z, t, reason, err)
}

func (s *Server) renderUnblockReview(w http.ResponseWriter, r *http.Request, z config.Zone, t block.Target, reason string, err error) {
	rq := reqOf(r)
	p := page{Title: s.L(r).t("unblock_review"), Zone: z, Nav: "blocks", Target: t, Reason: reason}
	if err == nil {
		ctx, cancel := context.WithTimeout(r.Context(), writeTO)
		defer cancel()
		p.Entries, err = s.env(z, rq).Current(ctx, t)
		if err == nil && len(p.Entries) == 0 {
			err = fmt.Errorf("%s: %w", t, block.ErrNotBlocked)
		}
	}
	if err != nil {
		p.Err = err.Error()
	} else {
		p.Token = s.reviewToken(rq, "unblock", z.ZoneID, string(t.Type), t.Value, reason)
	}
	s.render(w, r, http.StatusOK, "unblockreview", p)
}

func (s *Server) unblockApply(w http.ResponseWriter, r *http.Request) {
	rq := reqOf(r)
	z, t, reason, err := s.targetForm(r)
	if err != nil || !s.reviewOK(rq, r.PostFormValue("review"), "unblock", z.ZoneID, string(t.Type), t.Value, reason) {
		s.render(w, r, http.StatusBadRequest, "message", page{Title: s.L(r).t("unblock_review"), Msg: s.L(r).t("review_expired")})
		return
	}
	if msg := s.writeCheck(r); msg != "" {
		s.renderUnblockReview(w, r, z, t, reason, errors.New(msg))
		return
	}
	if err := s.DB.Audit(s.actor(rq), rq.IP, "unblock_requested", t.String(), "zone "+z.Name+"; reason: "+orDash(reason)); err != nil {
		s.fail(w, r, fmt.Errorf("audit log unavailable, nothing changed: %w", err))
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), writeTO)
	defer cancel()
	err = s.env(z, rq).Unblock(ctx, t, true, "unblock", reason)
	if err != nil && !errors.Is(err, blockcli.ErrAuditFailed) {
		s.audit(r, "unblock_failed", t.String(), err.Error())
		s.renderUnblockReview(w, r, z, t, reason, fmt.Errorf("%s %v", s.L(r).t("write_failed"), err))
		return
	}
	s.audit(r, "unblock_applied", t.String(), "verified by read-back")
	msg := fmt.Sprintf(s.L(r).t("unblock_done"), t.String())
	if err != nil {
		msg += " — " + err.Error()
	}
	http.Redirect(w, r, "/blocks?z="+url.QueryEscape(z.Name)+"&ok="+url.QueryEscape(msg), http.StatusSeeOther)
}

// --- renew (change expiry) ---

// renewUntil resolves the requested expiry: "until" (unix seconds, from
// an undo) wins over "for"; 0 means permanent.
func (s *Server) renewUntil(r *http.Request) (int64, error) {
	if u := r.FormValue("until"); u != "" {
		n, err := strconv.ParseInt(u, 10, 64)
		if err != nil || n < 0 {
			return 0, errors.New("invalid expiry")
		}
		return n, nil
	}
	d, ok := ttlChoices[r.FormValue("for")]
	if !ok {
		return 0, errors.New("invalid duration")
	}
	if d == 0 {
		return 0, nil
	}
	return s.Now().Add(d).Unix(), nil
}

func (s *Server) renewReview(w http.ResponseWriter, r *http.Request) {
	z, t, reason, err := s.targetForm(r)
	var until int64
	if err == nil {
		until, err = s.renewUntil(r)
	}
	s.renderRenewReview(w, r, z, t, reason, until, err)
}

func (s *Server) renderRenewReview(w http.ResponseWriter, r *http.Request, z config.Zone, t block.Target, reason string, until int64, err error) {
	rq := reqOf(r)
	p := page{Title: s.L(r).t("renew_review"), Zone: z, Nav: "blocks", Target: t, Reason: reason, Until: until}
	if until > 0 {
		p.UntilTime = time.Unix(until, 0)
	}
	if err == nil {
		var ok bool
		if p.Event, ok, err = s.Store.LatestBlockEvent(z.ZoneID, string(t.Type), t.Value); err == nil && (!ok || (p.Event.Op != "block" && p.Event.Op != "renew")) {
			err = fmt.Errorf("%s: %w", t, block.ErrNotBlocked)
		}
	}
	if err != nil {
		p.Err = err.Error()
	} else {
		p.Token = s.reviewToken(rq, "renew", z.ZoneID, string(t.Type), t.Value, strconv.FormatInt(until, 10), reason)
	}
	s.render(w, r, http.StatusOK, "renewreview", p)
}

func (s *Server) renewApply(w http.ResponseWriter, r *http.Request) {
	rq := reqOf(r)
	z, t, reason, err := s.targetForm(r)
	until, err2 := strconv.ParseInt(r.PostFormValue("until"), 10, 64)
	if err != nil || err2 != nil || !s.reviewOK(rq, r.PostFormValue("review"), "renew", z.ZoneID, string(t.Type), t.Value, strconv.FormatInt(until, 10), reason) {
		s.render(w, r, http.StatusBadRequest, "message", page{Title: s.L(r).t("renew_review"), Msg: s.L(r).t("review_expired")})
		return
	}
	if msg := s.writeCheck(r); msg != "" {
		s.renderRenewReview(w, r, z, t, reason, until, errors.New(msg))
		return
	}
	var exp time.Time
	if until > 0 {
		exp = time.Unix(until, 0)
	}
	if err := s.DB.Audit(s.actor(rq), rq.IP, "renew_requested", t.String(), "zone "+z.Name+"; until "+orDash(fmtUnix(until))+"; reason: "+orDash(reason)); err != nil {
		s.fail(w, r, fmt.Errorf("audit log unavailable, nothing changed: %w", err))
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), writeTO)
	defer cancel()
	if _, err := s.env(z, rq).Renew(ctx, t, exp, reason); err != nil {
		s.audit(r, "renew_failed", t.String(), err.Error())
		s.renderRenewReview(w, r, z, t, reason, until, fmt.Errorf("%s %v", s.L(r).t("write_failed"), err))
		return
	}
	s.audit(r, "renew_applied", t.String(), "until "+orDash(fmtUnix(until)))
	http.Redirect(w, r, "/blocks?z="+url.QueryEscape(z.Name)+"&ok="+url.QueryEscape(fmt.Sprintf(s.L(r).t("renew_done"), t.String())), http.StatusSeeOther)
}

func fmtUnix(n int64) string {
	if n == 0 {
		return ""
	}
	return time.Unix(n, 0).UTC().Format(time.RFC3339)
}

// --- undo ---

// undo turns one audit record into the review of its inverse. Only the
// newest record of a target can be undone (older ones are superseded).
func (s *Server) undo(w http.ResponseWriter, r *http.Request) {
	z := s.zone(r)
	id, err := strconv.ParseInt(r.PathValue("id"), 10, 64)
	if err != nil {
		http.NotFound(w, r)
		return
	}
	ev, ok, err := s.Store.BlockEventByID(id)
	if err != nil {
		s.fail(w, r, err)
		return
	}
	if !ok || ev.Zone != z.ZoneID {
		http.NotFound(w, r)
		return
	}
	latest, _, err := s.Store.LatestBlockEvent(ev.Zone, ev.Type, ev.Value)
	if err != nil {
		s.fail(w, r, err)
		return
	}
	if latest.ID != ev.ID {
		s.render(w, r, http.StatusConflict, "message", page{Title: s.L(r).t("undo"), Msg: s.L(r).t("undo_superseded")})
		return
	}
	t := block.Target{Type: block.Type(ev.Type), Value: ev.Value}
	reason := fmt.Sprintf("undo #%d", ev.ID)
	switch ev.Op {
	case "block":
		s.renderUnblockReview(w, r, z, t, reason, nil)
	case "renew":
		prev, ok, err := s.Store.PrevBlockEvent(ev.Zone, ev.Type, ev.Value, ev.ID)
		if err != nil || !ok {
			s.render(w, r, http.StatusConflict, "message", page{Title: s.L(r).t("undo"), Msg: s.L(r).t("undo_superseded")})
			return
		}
		var until int64
		if !prev.ExpiresAt.IsZero() {
			until = prev.ExpiresAt.Unix()
		}
		s.renderRenewReview(w, r, z, t, reason, until, nil)
	case "unblock", "expire":
		f := blockForm{Zone: z, Type: ev.Type, Value: ev.Value, Action: ev.Action, Reason: reason}
		http.Redirect(w, r, "/blocks/new?"+f.query(), http.StatusSeeOther)
	default:
		http.NotFound(w, r)
	}
}

// --- blocks page (live) ---

// BlockRow is one block as Cloudflare holds it, joined with the audit log.
type BlockRow struct {
	Target          block.Target
	Action          string
	Mechanism       string
	RuleID          string
	Event           store.BlockEvent // newest audit record (zero when none)
	HasEvent        bool
	Missing         bool // in the audit log, not in Cloudflare
	Attempts        int64
	AttemptsKnown   bool
	AttemptsPending bool // being computed in the background
	AttemptsFrom    time.Time
	// Approx: attempts approximated from the archived IP board (zones
	// without firewall events); nil otherwise.
	Approx *block.Approx
	// Live check: the last minutes, queried live.
	Live        block.Live
	LiveKnown   bool
	LivePending bool
}

type blockLiveEntry struct {
	at time.Time
	l  block.Live
	ok bool
}

// blockLiveTTL: a block's live check is re-run at most this often.
const blockLiveTTL = 2 * time.Minute

type attemptsEntry struct {
	at time.Time
	n  int64
	ok bool
}

type liveBlocks struct {
	Rows       []BlockRow
	RulesUsed  int
	RuleLimit  int
	Plan       string
	NoLists    bool
	NoAccess   bool
	Err        string
	Enforcer   *health.Beat
	EnforceOld bool // TTL blocks exist but the enforcer is not running
	Pending    bool // some attempts are still being computed
}

func (s *Server) loadLive(ctx context.Context, z config.Zone) liveBlocks {
	var lb liveBlocks
	st, entries, err := s.env(z, nil).Live(ctx)
	if err != nil {
		lb.Err = err.Error()
		return lb
	}
	lb.RulesUsed, lb.RuleLimit, lb.Plan, lb.NoLists, lb.NoAccess = st.RulesUsed(), st.RuleLimit(), st.Plan, st.NoLists, st.NoAccess
	audit := map[block.Target]store.BlockEvent{}
	if evs, err := s.Store.ActiveBlocks(z.ZoneID); err == nil {
		for _, ev := range evs {
			audit[block.Target{Type: block.Type(ev.Type), Value: ev.Value}] = ev
		}
	}
	now := s.Now()
	caps, _ := s.Live.Capabilities(ctx, z.ZoneID)
	seen := map[block.Target]bool{}
	for _, x := range entries {
		seen[x.Target] = true
		row := BlockRow{Target: x.Target, Action: string(x.Action), Mechanism: string(x.Mechanism), RuleID: x.RuleID}
		row.Event, row.HasEvent = audit[x.Target]
		from := now.Add(-7 * 24 * time.Hour)
		if row.HasEvent && row.Event.At.After(from) {
			from = row.Event.At
		}
		if c := caps.FirewallFrom(from, now); c.After(from) {
			from = c
		}
		// Whole hours: a stable window start, so the cache can hit.
		from = from.Truncate(time.Hour)
		row.AttemptsFrom = from
		if !(caps.Probed && !caps.FirewallEnabled) {
			row.Attempts, row.AttemptsKnown, row.AttemptsPending = s.attemptsAsync(z, x, from)
			lb.Pending = lb.Pending || row.AttemptsPending
		} else if a, ok, err := s.env(z, nil).ApproxAttempts(x.Target, from, now); err == nil && ok && a.Hours > 0 {
			row.Approx = &a
		}
		row.Live, row.LiveKnown, row.LivePending = s.liveAsync(z, x, caps)
		lb.Pending = lb.Pending || row.LivePending
		lb.Rows = append(lb.Rows, row)
	}
	for t, ev := range audit {
		if !seen[t] {
			lb.Rows = append(lb.Rows, BlockRow{Target: t, Action: ev.Action, Mechanism: ev.Mechanism, Event: ev, HasEvent: true, Missing: true})
		}
	}
	ttl := false
	for _, r := range lb.Rows {
		if r.HasEvent && !r.Event.ExpiresAt.IsZero() {
			ttl = true
		}
	}
	if b, err := health.Read(s.Cfg.DataDir(), health.EnforceFile); err == nil {
		lb.Enforcer = &b
		lb.EnforceOld = ttl && now.Sub(b.At) > 15*time.Minute
	} else {
		lb.EnforceOld = ttl
	}
	return lb
}

// attemptsAsync returns a block's attempts from the cache and refreshes
// stale or missing entries in the background: one query per day of the
// window per block is too slow to run while a page waits. pending is true
// while no value exists yet.
func (s *Server) attemptsAsync(z config.Zone, x block.Entry, from time.Time) (n int64, known, pending bool) {
	key := z.ZoneID + "|" + x.RuleID + "|" + x.Target.String() + "|" + strconv.FormatInt(from.Unix(), 10)
	s.attemptsMu.Lock()
	defer s.attemptsMu.Unlock()
	e, ok := s.attemptsCache[key]
	if ok && s.Now().Sub(e.at) < attemptsTTL {
		return e.n, e.ok, false
	}
	if !s.attemptsBusy[key] {
		s.attemptsBusy[key] = true
		s.attemptsWG.Add(1)
		go func() {
			defer s.attemptsWG.Done()
			ctx, cancel := context.WithTimeout(context.Background(), writeTO)
			defer cancel()
			n, err := block.Attempts(ctx, s.Live, z.ZoneID, x.RuleID, x.Target, from, s.Now())
			s.attemptsMu.Lock()
			s.attemptsCache[key] = attemptsEntry{at: s.Now(), n: n, ok: err == nil}
			delete(s.attemptsBusy, key)
			s.attemptsMu.Unlock()
		}()
	}
	if ok { // stale but shown while it refreshes
		return e.n, e.ok, false
	}
	return 0, false, true
}

// liveAsync returns a block's live check from the cache, refreshing it in
// the background like attemptsAsync. known is false for targets the
// check cannot select (or when the query failed).
func (s *Server) liveAsync(z config.Zone, x block.Entry, caps cfapi.Caps) (l block.Live, known, pending bool) {
	key := "live|" + z.ZoneID + "|" + x.RuleID + "|" + x.Target.String()
	s.attemptsMu.Lock()
	defer s.attemptsMu.Unlock()
	e, ok := s.blockLive[key]
	if ok && s.Now().Sub(e.at) < blockLiveTTL {
		return e.l, e.ok, false
	}
	if !s.attemptsBusy[key] {
		s.attemptsBusy[key] = true
		s.attemptsWG.Add(1)
		go func() {
			defer s.attemptsWG.Done()
			ctx, cancel := context.WithTimeout(context.Background(), writeTO)
			defer cancel()
			l, ok, err := s.env(z, nil).LiveCheck(ctx, x, caps)
			s.attemptsMu.Lock()
			s.blockLive[key] = blockLiveEntry{at: s.Now(), l: l, ok: ok && err == nil}
			delete(s.attemptsBusy, key)
			s.attemptsMu.Unlock()
		}()
	}
	if ok {
		return e.l, e.ok, false
	}
	return block.Live{}, false, true
}

// warmBlocks refreshes every zone's block list and attempts in the
// background, so the blocks page opens on fresh numbers.
func (s *Server) warmBlocks(ctx context.Context) {
	for _, z := range s.Cfg.Cloudflare.Zones {
		cctx, cancel := context.WithTimeout(ctx, writeTO)
		s.loadLive(cctx, z)
		cancel()
	}
}

// --- before / after comparison ---

// Effect is one block's before / after (internal/blockeffect).
type Effect = blockeffect.Effect

func (s *Server) settleAfter() time.Duration { return s.Cfg.IntradayOffset() }

// effect returns the cached comparison or computes it. Only settled
// comparisons are cached.
func (s *Server) effect(ctx context.Context, z config.Zone, ev store.BlockEvent) Effect {
	if raw, ok, err := s.DB.Effect(z.ZoneID, ev.ID); err == nil && ok {
		var e Effect
		if json.Unmarshal(raw, &e) == nil {
			return e
		}
	}
	e := blockeffect.Compute(ctx, s.Live, z.ZoneID, ev, s.Now(), s.settleAfter())
	if e.Settled {
		if raw, err := json.Marshal(e); err == nil {
			_ = s.DB.PutEffect(z.ZoneID, ev.ID, raw)
		}
	}
	return e
}

func (s *Server) effectPage(w http.ResponseWriter, r *http.Request) {
	z := s.zone(r)
	id, err := strconv.ParseInt(r.PathValue("id"), 10, 64)
	if err != nil {
		http.NotFound(w, r)
		return
	}
	ev, ok, err := s.Store.BlockEventByID(id)
	if err != nil {
		s.fail(w, r, err)
		return
	}
	if !ok || ev.Zone != z.ZoneID || ev.Op != "block" {
		http.NotFound(w, r)
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), writeTO)
	defer cancel()
	e := s.effect(ctx, z, ev)
	s.render(w, r, http.StatusOK, "effect", page{Title: s.L(r).t("effect_title"), Zone: z, Nav: "blocks", Effect: &e, Event: ev})
}

// warmEffects computes the comparison for recent blocks once their hour
// after has settled, so it is ready when someone looks.
func (s *Server) warmEffects(ctx context.Context) {
	now := s.Now()
	for _, z := range s.Cfg.Cloudflare.Zones {
		evs, err := s.Store.BlockEventsBetween(z.ZoneID, now.Add(-48*time.Hour), now, 200)
		if err != nil {
			log.Printf("console: effects: %v", err)
			continue
		}
		for _, ev := range evs {
			if ev.Op != "block" || now.Sub(ev.At) < time.Hour+s.settleAfter() {
				continue
			}
			if _, ok, _ := s.DB.Effect(z.ZoneID, ev.ID); ok {
				continue
			}
			cctx, cancel := context.WithTimeout(ctx, writeTO)
			s.effect(cctx, z, ev)
			cancel()
		}
	}
}

// Background runs the console's periodic jobs until ctx ends.
func (s *Server) Background(ctx context.Context) {
	t := time.NewTicker(10 * time.Minute)
	defer t.Stop()
	for {
		if s.CanWrite() {
			s.warmEffects(ctx)
			s.warmBlocks(ctx)
		}
		s.warmPages(ctx)
		_ = s.refreshSettings(false)
		select {
		case <-ctx.Done():
			return
		case <-t.C:
		}
	}
}

// warmPages keeps the slow, rarely changing pages ready: the WAF rules
// (both phases) and the WAF audit, per zone. Each costs a few REST reads
// every 10 minutes at most (the audit re-runs only when 30 minutes old).
func (s *Server) warmPages(ctx context.Context) {
	for _, z := range s.Cfg.Cloudflare.Zones {
		if ctx.Err() != nil {
			return
		}
		if s.RulesRead != nil || s.RulesWrite != nil {
			for _, ph := range []string{"custom", "ratelimit"} {
				cctx, cancel := context.WithTimeout(ctx, time.Minute)
				s.cachedRules(cctx, z, ph, true)
				cancel()
			}
		}
		if s.Auditor != nil && !s.Cfg.WAFAudit.Disabled {
			s.cachedAudit(ctx, z, false)
		}
	}
}

// --- expiry (v1.16) ---

// ExpiryActor is the audit subject of the expiries the console carries out.
const ExpiryActor = "system:expiry"

// ExpiryEvery is how often the console looks for expired blocks.
const ExpiryEvery = 5 * time.Minute

// EnforceExpiry lifts every block whose expiry has passed, in every zone,
// through the same path as an unblock (read-back verified, block log),
// recorded as ExpiryActor in both audit logs. The console is the one
// long-running process that holds the write token, so expiry is its job:
// without it a block "expires" in FlareHound's list and keeps blocking in
// Cloudflare. It writes the expiry heartbeat the blocks page and doctor
// read.
func (s *Server) EnforceExpiry(ctx context.Context) {
	if !s.CanWrite() {
		return
	}
	var errs []string
	for _, z := range s.Cfg.Cloudflare.Zones {
		if ctx.Err() != nil {
			return
		}
		env := s.env(z, nil)
		env.Actor = ExpiryActor
		cctx, cancel := context.WithTimeout(ctx, writeTO)
		done, err := env.ExpireTargets(cctx)
		cancel()
		for _, t := range done {
			log.Printf("console: zone %s: %s expired, lifted", z.Name, t)
			_ = s.DB.Audit(ExpiryActor, "local", "block_expired", t.String(), "zone "+z.Name+"; expiry reached; removed, verified by read-back")
		}
		if err != nil {
			log.Printf("console: zone %s: expiry: %v", z.Name, err)
			_ = s.DB.Audit(ExpiryActor, "local", "expire_failed", z.Name, err.Error())
			errs = append(errs, z.Name+": "+err.Error())
		}
	}
	now := s.Now()
	b := health.Beat{At: now.UTC(), Version: s.Version, Role: "console-expiry", Zones: len(s.Cfg.Cloudflare.Zones), Errors: errs, Next: now.Add(ExpiryEvery)}
	if err := health.Write(s.Cfg.DataDir(), health.EnforceFile, b); err != nil {
		log.Printf("console: expiry heartbeat: %v", err)
	}
}

// ExpiryLoop runs EnforceExpiry now and every ExpiryEvery until ctx ends.
func (s *Server) ExpiryLoop(ctx context.Context) {
	t := time.NewTicker(ExpiryEvery)
	defer t.Stop()
	for {
		s.EnforceExpiry(ctx)
		select {
		case <-ctx.Done():
			return
		case <-t.C:
		}
	}
}

// --- two-factor hint (v1.16) ---

// totpHintFlag records an admin's explicit "keep require_totp off".
const totpHintFlag = "totp_hint_dismissed"

// totpHint reports whether admins should see the two-factor hint: the
// console holds the write token (it can change Cloudflare) but does not
// require two-factor sign-in, and no admin has dismissed the hint.
func (s *Server) totpHint() bool {
	if !s.CanWrite() || s.Cfg.Console.RequireTOTP {
		return false
	}
	_, dismissed, err := s.DB.Flag(totpHintFlag)
	return err == nil && !dismissed
}

// totpHintDismiss hides the hint for good; the choice is audited.
func (s *Server) totpHintDismiss(w http.ResponseWriter, r *http.Request) {
	rq := reqOf(r)
	if err := s.DB.SetFlag(totpHintFlag, rq.User.Username); err != nil {
		s.fail(w, r, err)
		return
	}
	s.audit(r, "totp_hint_dismissed", "console.require_totp", "kept off by an admin; the hint is no longer shown")
	http.Redirect(w, r, localPath(r.PostFormValue("next")), http.StatusSeeOther)
}
