package console

// Read-only snapshots (docs/web-console-revision.md §4.7): any of the
// overview, movers or history views exported as one self-contained HTML
// file (stylesheet inlined, no script, no external resource), kept in
// console.db and shareable through an unguessable, expiring, revocable
// link that needs no account. A snapshot holds only the view's data at
// export time — no token, no account data, no form.

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"fmt"
	"html/template"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"
)

var snapTTLs = map[string]time.Duration{"24h": 24 * time.Hour, "7d": 7 * 24 * time.Hour, "30d": 30 * 24 * time.Hour}

func (s *Server) loadCSS() error {
	b, err := assets.ReadFile("static/app.css")
	if err != nil {
		return err
	}
	s.css = template.CSS(b)
	sum := sha256.Sum256(b)
	s.cssHash = "'sha256-" + base64.StdEncoding.EncodeToString(sum[:]) + "'"
	return nil
}

// renderSnapshot renders a view as a standalone document.
func (s *Server) renderSnapshot(ctx context.Context, view string, q url.Values) (string, string, string, error) {
	name, p, err := s.buildView(ctx, view, q)
	if err != nil {
		return "", "", "", err
	}
	p.Snapshot, p.CSS, p.SnapAt, p.Refresh = true, s.css, s.Now(), 0
	p.Lang = string(s.lc(ctx)) // in the language of the person who made it
	out, err := s.renderBytes(name, p)
	if err != nil {
		return "", "", "", err
	}
	title := p.Title + " · " + p.Zone.Name + " · " + s.Now().In(s.Cfg.Location).Format("2006-01-02 15:04")
	return string(out), title, p.Zone.ZoneID, nil
}

// canSnapshot applies console.snapshots: who may create snapshots.
func (s *Server) canSnapshot(rq *Req) bool {
	if rq == nil || rq.User == nil {
		return false
	}
	switch s.Cfg.Console.Snapshots {
	case "everyone":
		return true
	case "off":
		return false
	}
	return rq.User.Admin()
}

func (s *Server) snapshotCreate(w http.ResponseWriter, r *http.Request) {
	rq := reqOf(r)
	if !s.canSnapshot(rq) {
		s.render(w, r, http.StatusForbidden, "message", page{Title: s.L(r).t("snap_title"), Msg: s.L(r).t("snap_not_allowed")})
		return
	}
	view := r.PostFormValue("view")
	ttl, ok := snapTTLs[r.PostFormValue("ttl")]
	if !ok {
		ttl = snapTTLs["7d"]
	}
	q, err := url.ParseQuery(r.PostFormValue("params"))
	if err != nil {
		http.Error(w, "bad parameters", http.StatusBadRequest)
		return
	}
	html, title, zone, err := s.renderSnapshot(r.Context(), view, q)
	if err != nil {
		s.fail(w, r, err)
		return
	}
	tok, id, err := s.DB.CreateSnapshot(rq.User.ID, rq.User.Username, title, zone, html, ttl)
	if err != nil {
		s.fail(w, r, err)
		return
	}
	s.audit(r, "snapshot_created", title, fmt.Sprintf("#%d, link valid %s", id, ttl))
	p := page{Title: s.L(r).t("snap_title"), ShareLink: s.baseURL(r) + "/s/" + tok, Flash: s.L(r).t("snap_created")}
	if err := s.snapshotsData(r, &p); err != nil {
		s.fail(w, r, err)
		return
	}
	s.render(w, r, http.StatusOK, "snapshots", p)
}

func (s *Server) snapshotsData(r *http.Request, p *page) error { // see DB.Snapshots for Pruned
	rq := reqOf(r)
	by := rq.User.ID
	if rq.User.Admin() {
		by = 0
	}
	if rq.User.ID == 0 && !rq.User.Admin() {
		return nil // proxy viewer without an account: nothing of their own
	}
	var err error
	p.Snapshots, err = s.DB.Snapshots(by, 200)
	return err
}

func (s *Server) snapshotsPage(w http.ResponseWriter, r *http.Request) {
	p := page{Title: s.L(r).t("snap_title"), Flash: r.URL.Query().Get("ok")}
	if err := s.snapshotsData(r, &p); err != nil {
		s.fail(w, r, err)
		return
	}
	s.render(w, r, http.StatusOK, "snapshots", p)
}

// ownSnapshot loads a snapshot the requester may manage (creator or admin).
func (s *Server) ownSnapshot(w http.ResponseWriter, r *http.Request) (Snapshot, bool) {
	rq := reqOf(r)
	id, err := strconv.ParseInt(r.PathValue("id"), 10, 64)
	if err != nil {
		http.NotFound(w, r)
		return Snapshot{}, false
	}
	sn, ok, err := s.DB.SnapshotByID(id)
	if err != nil {
		s.fail(w, r, err)
		return Snapshot{}, false
	}
	if !ok || (!rq.User.Admin() && (rq.User.ID == 0 || sn.CreatedBy != rq.User.ID)) {
		http.NotFound(w, r)
		return Snapshot{}, false
	}
	return sn, true
}

func (s *Server) snapshotDownload(w http.ResponseWriter, r *http.Request) {
	sn, ok := s.ownSnapshot(w, r)
	if !ok {
		return
	}
	if sn.HTML == "" {
		s.render(w, r, http.StatusGone, "message", page{Title: s.L(r).t("snap_title"), Msg: s.L(r).t("snap_pruned")})
		return
	}
	name := fmt.Sprintf("flarehound-snapshot-%d-%s.html", sn.ID, sn.CreatedAt.In(s.Cfg.Location).Format("20060102-1504"))
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Header().Set("Content-Disposition", `attachment; filename="`+name+`"`)
	_, _ = w.Write([]byte(sn.HTML))
}

func (s *Server) snapshotRevoke(w http.ResponseWriter, r *http.Request) {
	sn, ok := s.ownSnapshot(w, r)
	if !ok {
		return
	}
	if err := s.DB.RevokeSnapshot(sn.ID); err != nil {
		s.fail(w, r, err)
		return
	}
	s.audit(r, "snapshot_revoked", sn.Title, fmt.Sprintf("#%d", sn.ID))
	http.Redirect(w, r, "/snapshots?ok="+url.QueryEscape(s.L(r).t("done")), http.StatusSeeOther)
}

// snapshotPublic serves a shared snapshot without sign-in.
func (s *Server) snapshotPublic(w http.ResponseWriter, r *http.Request) {
	// Tokens are 192 random bits: guessing is not a practical attack.
	sn, ok, err := s.DB.SnapshotByToken(r.PathValue("token"))
	if err != nil || !ok || strings.TrimSpace(sn.HTML) == "" {
		http.Error(w, s.L(r).t("snap_gone"), http.StatusNotFound)
		return
	}
	h := w.Header()
	h.Set("Content-Security-Policy", "default-src 'none'; style-src "+s.cssHash+"; img-src data:; form-action 'none'; frame-ancestors 'none'; base-uri 'none'")
	h.Set("X-Robots-Tag", "noindex, nofollow")
	h.Set("Content-Type", "text/html; charset=utf-8")
	_, _ = w.Write([]byte(sn.HTML))
}
