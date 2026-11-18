package console

// Settings in the console (v1.9): notification channels, alert lines and
// known faces, kept in the settings overlay (config.Overlay) on top of
// config.json. Admin only; every change goes form → review (the exact
// difference, and for alert lines a replay of the last 7 days) → apply
// (review token bound to the settings version reviewed, fresh TOTP code,
// console audit first). The watch picks the change up before its next
// round and reports back; test notifications are sent by the watch, with
// the watch's own environment, so a misnamed variable shows at once.

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"os"
	"reflect"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/playwjj/flarehound/internal/analyze"
	"github.com/playwjj/flarehound/internal/check"
	"github.com/playwjj/flarehound/internal/config"
	"github.com/playwjj/flarehound/internal/control"
	"github.com/playwjj/flarehound/internal/health"
	"github.com/playwjj/flarehound/internal/suggest"
)

// ---- effective settings in this process ----

// eff is the configuration with the current overlay (alert lines, known
// faces) — what the console shows statuses and "known" marks with.
func (s *Server) eff() *config.Config {
	s.effMu.RLock()
	defer s.effMu.RUnlock()
	if s.effCfg != nil {
		return s.effCfg
	}
	return s.Cfg
}

func overlayMod(path string) time.Time {
	if st, err := os.Stat(path); err == nil {
		return st.ModTime()
	}
	return time.Time{}
}

// refreshSettings re-reads the overlay when it changed (or when forced).
func (s *Server) refreshSettings(force bool) error {
	if s.CfgPath == "" {
		return nil
	}
	mod := overlayMod(s.Cfg.OverlayPath)
	s.effMu.RLock()
	same := !force && mod.Equal(s.effMod) && s.effCfg != nil
	s.effMu.RUnlock()
	if same {
		return nil
	}
	c, err := config.LoadWith(s.CfgPath, config.LoadOptions{NotifySecretsOptional: true})
	if err != nil {
		return err
	}
	s.effMu.Lock()
	s.effCfg, s.effMod = c, mod
	s.effMu.Unlock()
	return nil
}

// overlay returns the current overlay (never nil).
func (s *Server) overlay() *config.Overlay {
	o, err := config.ReadOverlay(s.Cfg.OverlayPath)
	if err != nil || o == nil {
		return &config.Overlay{}
	}
	return o
}

// base is config.json alone (what "reset to the file value" means).
func (s *Server) fileConfig() (*config.Config, error) {
	return config.LoadWith(s.CfgPath, config.LoadOptions{NoOverlay: true, NotifySecretsOptional: true})
}

func (s *Server) settingsOn() bool { return s.CfgPath != "" }

func (s *Server) requireSettings(h http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if !s.settingsOn() {
			http.NotFound(w, r)
			return
		}
		h(w, r)
	}
}

// ---- pages ----

type settingsView struct {
	Tab        string
	Overlay    *config.Overlay
	Base       *config.Config
	Eff        *config.Config
	Status     control.Status
	HasStatus  bool
	WatchOld   bool // the watch has not reported recently
	Beat       *health.Beat
	Test       *control.TestResult
	TestID     string
	TestWait   bool
	History    []int
	Channels   []channelForm
	MissingSet []string // variables the watch reports empty
}

// channelForm is one channel on the notification page.
type channelForm struct {
	Name     string
	Enabled  bool
	Fields   []fieldForm
	Watch    *config.ChannelInfo // as the watch sees it (nil: unknown)
	FromFile bool                // no console override
}

type fieldForm struct {
	Key, Value, FileValue string
	Env                   bool // names an environment variable
	Overridden            bool
}

var channelFields = map[string][]string{
	config.ChanTelegram: {"telegram_bot_token_env", "telegram_chat_id"},
	config.ChanSlack:    {"slack_webhook_url_env"},
	config.ChanDiscord:  {"discord_webhook_url_env"},
	config.ChanWeCom:    {"wecom_webhook_url_env"},
	config.ChanFeishu:   {"feishu_webhook_url_env", "feishu_secret_env"},
	config.ChanWebhook:  {"webhook_url_env"},
	config.ChanJSONL:    {"jsonl_file"},
	config.ChanEmail:    {"email_smtp_host", "email_smtp_port", "email_tls", "email_username", "email_password_env", "email_from", "email_to"},
}

func emailField(e *config.EmailConfig, k string) string {
	if e == nil {
		return ""
	}
	switch k {
	case "email_smtp_host":
		return e.Host
	case "email_smtp_port":
		if e.Port == 0 {
			return ""
		}
		return strconv.Itoa(e.Port)
	case "email_tls":
		return e.TLS
	case "email_username":
		return e.Username
	case "email_password_env":
		return e.PasswordEnv
	case "email_from":
		return e.From
	case "email_to":
		return strings.Join(e.To, ", ")
	}
	return ""
}

func fieldValue(c *config.Config, k string) string {
	if strings.HasPrefix(k, "email_") {
		return emailField(c.Notify.Email, k)
	}
	return config.NotifyField(c.Notify, k)
}

func (s *Server) settingsData(r *http.Request, tab string) (*settingsView, error) {
	_ = s.refreshSettings(false)
	v := &settingsView{Tab: tab, Overlay: s.overlay(), Eff: s.eff()}
	var err error
	if v.Base, err = s.fileConfig(); err != nil {
		return nil, err
	}
	v.Status, v.HasStatus, _ = control.ReadStatus(s.Cfg.DataDir())
	if b, err := health.Read(s.Cfg.DataDir(), health.WatchFile); err == nil {
		v.Beat = &b
	}
	v.WatchOld = !v.HasStatus || s.Now().Sub(v.Status.At) > 15*time.Minute
	v.History, _ = config.OverlayHistory(s.Cfg.OverlayPath)
	if tab == "notify" {
		// The effective config without the console's channel switches: a
		// turned-off channel keeps showing the values it would use.
		o := *v.Overlay
		o.Disabled = nil
		withoutOff, err := config.LoadWith(s.CfgPath, config.LoadOptions{Overlay: &o, NotifySecretsOptional: true})
		if err != nil {
			withoutOff = v.Eff
		}
		watch := map[string]*config.ChannelInfo{}
		for i := range v.Status.Channels {
			watch[v.Status.Channels[i].Name] = &v.Status.Channels[i]
			v.MissingSet = append(v.MissingSet, v.Status.Channels[i].Missing...)
		}
		for _, ch := range config.AllChannels() {
			cf := channelForm{Name: ch, Enabled: !v.Overlay.IsDisabled(ch), Watch: watch[ch], FromFile: true}
			for _, k := range channelFields[ch] {
				f := fieldForm{Key: k, Value: fieldValue(withoutOff, k), FileValue: fieldValue(v.Base, k), Env: strings.HasSuffix(k, "_env")}
				f.Overridden = f.Value != f.FileValue
				if f.Overridden {
					cf.FromFile = false
				}
				cf.Fields = append(cf.Fields, f)
			}
			v.Channels = append(v.Channels, cf)
		}
		if id := r.URL.Query().Get("test"); id != "" {
			v.TestID = id
			if res, ok, _ := control.Result(s.Cfg.DataDir(), id); ok {
				v.Test = &res
			} else {
				v.TestWait = control.Waiting(s.Cfg.DataDir(), id)
			}
		}
	}
	return v, nil
}

func (s *Server) settingsPage(tab string) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		v, err := s.settingsData(r, tab)
		if err != nil {
			s.fail(w, r, err)
			return
		}
		p := page{Title: s.L(r).t("nav_settings"), Nav: "", Settings: v, Flash: r.URL.Query().Get("ok")}
		if v.TestWait {
			p.Refresh = 3 // until the watch answers
		}
		s.render(w, r, http.StatusOK, "settings_"+tab, p)
	}
}

// ---- changes ----

// settingsChange is one requested change, as posted.
type settingsChange struct {
	Kind   string            // notify | thresholds | known_add | known_remove | restore
	Fields map[string]string // posted values
	Base   int               // overlay version the form was built on
}

func (c settingsChange) tokenFields() []string {
	keys := make([]string, 0, len(c.Fields))
	for k := range c.Fields {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	f := []string{"settings", c.Kind, strconv.Itoa(c.Base)}
	for _, k := range keys {
		f = append(f, k+"="+c.Fields[k])
	}
	return f
}

var thresholdKeys = []string{"total_up_pct", "worker_calls_up_pct", "cpu_p50_up_pct", "dynamic_up_pct", "origin_5xx_multiplier",
	"origin_5xx_min", "new_face_min_count", "collapse_down_pct", "min_count", "escalation_pct", "recovery_clean_rounds"}

func (s *Server) parseChange(r *http.Request) (settingsChange, error) {
	c := settingsChange{Kind: r.PostFormValue("kind"), Fields: map[string]string{}}
	c.Base, _ = strconv.Atoi(r.PostFormValue("base"))
	keep := func(k string) {
		c.Fields[k] = strings.TrimSpace(truncate(r.PostFormValue(k), 500))
	}
	switch c.Kind {
	case "notify":
		for _, ch := range config.AllChannels() {
			keep("enabled_" + ch)
			for _, k := range channelFields[ch] {
				keep(k)
			}
		}
	case "thresholds":
		for _, k := range thresholdKeys {
			keep(k)
		}
	case "known_add", "known_remove":
		keep("dim")
		keep("name")
	case "asn_name":
		keep("asn")
		keep("name")
	case "restore":
		keep("version")
	default:
		return c, errors.New("unknown change")
	}
	return c, nil
}

var envName = func(s string) bool {
	if s == "" {
		return true
	}
	for i, r := range s {
		if !(r == '_' || r >= 'A' && r <= 'Z' || r >= 'a' && r <= 'z' || i > 0 && r >= '0' && r <= '9') {
			return false
		}
	}
	return true
}

func parseThresholds(f map[string]string) (config.Thresholds, error) {
	var t config.Thresholds
	fl := func(k string) (float64, error) {
		v, err := strconv.ParseFloat(f[k], 64)
		if err != nil {
			return 0, fmt.Errorf("%s: not a number", k)
		}
		return v, nil
	}
	in := func(k string) (int64, error) {
		v, err := strconv.ParseInt(f[k], 10, 64)
		if err != nil {
			return 0, fmt.Errorf("%s: not a whole number", k)
		}
		return v, nil
	}
	var err error
	set := func(dst *float64, k string) {
		if err == nil {
			*dst, err = fl(k)
		}
	}
	seti := func(dst *int64, k string) {
		if err == nil {
			*dst, err = in(k)
		}
	}
	set(&t.TotalUpPct, "total_up_pct")
	set(&t.WorkerCallsUpPct, "worker_calls_up_pct")
	set(&t.CPUP50UpPct, "cpu_p50_up_pct")
	set(&t.DynamicUpPct, "dynamic_up_pct")
	set(&t.Origin5xxMultiple, "origin_5xx_multiplier")
	seti(&t.Origin5xxMin, "origin_5xx_min")
	seti(&t.NewFaceMinCount, "new_face_min_count")
	set(&t.CollapseDownPct, "collapse_down_pct")
	seti(&t.MinCount, "min_count")
	set(&t.EscalationPct, "escalation_pct")
	var rc int64
	seti(&rc, "recovery_clean_rounds")
	t.RecoveryCleanRound = int(rc)
	if err != nil {
		return t, err
	}
	return t, config.CheckThresholds(t)
}

// candidate builds the overlay a change would produce.
func (s *Server) candidate(c settingsChange, cur *config.Overlay, base *config.Config) (*config.Overlay, error) {
	o := *cur
	o.Notify = map[string]string{}
	for k, v := range cur.Notify {
		o.Notify[k] = v
	}
	o.Disabled = append([]string(nil), cur.Disabled...)
	o.KnownASNs = append([]int(nil), cur.KnownASNs...)
	o.KnownUAs = append([]string(nil), cur.KnownUAs...)
	f := c.Fields
	switch c.Kind {
	case "notify":
		o.Notify, o.Disabled = map[string]string{}, nil
		for _, k := range config.NotifyStringFields {
			if k == "heartbeat_url_env" {
				if v, ok := cur.Notify[k]; ok {
					o.Notify[k] = v
				}
				continue
			}
			v := f[k]
			if strings.HasSuffix(k, "_env") && !envName(v) {
				return nil, fmt.Errorf("%s: %q is not an environment variable name", k, v)
			}
			if v != config.NotifyField(base.Notify, k) {
				o.Notify[k] = v
			}
		}
		// E-mail: the whole block, when it differs from the file's.
		var e *config.EmailConfig
		if f["email_smtp_host"] != "" || f["email_from"] != "" || f["email_to"] != "" {
			e = &config.EmailConfig{Host: f["email_smtp_host"], TLS: f["email_tls"], Username: f["email_username"],
				PasswordEnv: f["email_password_env"], From: f["email_from"]}
			if p := f["email_smtp_port"]; p != "" {
				n, err := strconv.Atoi(p)
				if err != nil || n <= 0 || n > 65535 {
					return nil, errors.New("email_smtp_port: not a port number")
				}
				e.Port = n
			}
			if !envName(e.PasswordEnv) {
				return nil, errors.New("email_password_env: not an environment variable name")
			}
			for _, to := range strings.Split(f["email_to"], ",") {
				if to = strings.TrimSpace(to); to != "" {
					e.To = append(e.To, to)
				}
			}
		}
		if !reflect.DeepEqual(e, base.Notify.Email) {
			o.Email = e
			if e == nil && base.Notify.Email != nil {
				// Emptied in the form: off, not "back to the file".
				o.Disabled = append(o.Disabled, config.ChanEmail)
			}
		} else {
			o.Email = nil
		}
		for _, ch := range config.AllChannels() {
			if f["enabled_"+ch] != "1" && !(ch == config.ChanEmail && contains(o.Disabled, ch)) {
				o.Disabled = append(o.Disabled, ch)
			}
		}
	case "thresholds":
		t, err := parseThresholds(f)
		if err != nil {
			return nil, err
		}
		if t == base.Thresholds {
			o.Thresholds = nil
		} else {
			o.Thresholds = &t
		}
	case "known_add", "known_remove":
		name := strings.TrimSpace(f["name"])
		switch f["dim"] {
		case DimASN:
			n, err := strconv.Atoi(strings.TrimPrefix(strings.ToUpper(name), "AS"))
			if err != nil || n <= 0 {
				return nil, fmt.Errorf("%q is not an ASN", name)
			}
			o.KnownASNs = editInts(o.KnownASNs, n, c.Kind == "known_add")
		case DimUA:
			if len(name) < 3 || len(name) > 300 {
				return nil, errors.New("a known user agent needs 3–300 characters")
			}
			o.KnownUAs = editStrings(o.KnownUAs, name, c.Kind == "known_add")
		default:
			return nil, errors.New("only user agents and ASNs can be known faces")
		}
	case "asn_name":
		n := asnNumber(f["asn"])
		if n == 0 {
			return nil, fmt.Errorf("%q is not an ASN", f["asn"])
		}
		names := map[string]string{}
		for k, v := range cur.ASNNames {
			names[k] = v
		}
		key := strconv.Itoa(n)
		if name := strings.TrimSpace(f["name"]); name == "" {
			delete(names, key)
		} else {
			if r := []rune(name); len(r) > 40 {
				return nil, errors.New("a network name has at most 40 characters")
			}
			names[key] = name
		}
		if len(names) == 0 {
			names = nil
		}
		o.ASNNames = names
	case "restore":
		v, err := strconv.Atoi(f["version"])
		if err != nil {
			return nil, errors.New("bad version")
		}
		old, err := config.ReadOverlayVersion(s.Cfg.OverlayPath, v)
		if err != nil {
			return nil, err
		}
		o = *old
	}
	if len(o.Notify) == 0 {
		o.Notify = nil
	}
	return &o, nil
}

func contains(s []string, x string) bool {
	for _, v := range s {
		if v == x {
			return true
		}
	}
	return false
}

func editInts(s []int, n int, add bool) []int {
	var out []int
	found := false
	for _, x := range s {
		if x == n {
			found = true
			if !add {
				continue
			}
		}
		out = append(out, x)
	}
	if add && !found {
		out = append(out, n)
	}
	return out
}

func editStrings(s []string, v string, add bool) []string {
	var out []string
	found := false
	for _, x := range s {
		if strings.EqualFold(x, v) {
			found = true
			if !add {
				continue
			}
		}
		out = append(out, x)
	}
	if add && !found {
		out = append(out, v)
	}
	return out
}

// validate loads base + candidate: structure only (every variable assumed
// present — whether the watch has them, the watch reports).
func (s *Server) validate(o *config.Overlay) (*config.Config, error) {
	return config.LoadWith(s.CfgPath, config.LoadOptions{Overlay: o, Getenv: func(string) string { return "set" }})
}

// diffLines describes what a change does, in plain words.
func diffLines(l lang, before, after *config.Config, ob, oa *config.Overlay) []string {
	var out []string
	add := func(format string, a ...any) { out = append(out, fmt.Sprintf(format, a...)) }
	for _, ch := range config.AllChannels() {
		was, is := !ob.IsDisabled(ch), !oa.IsDisabled(ch)
		if was != is {
			add("%s: %s → %s", ch, map[bool]string{true: l.t("on"), false: l.t("off")}[was], map[bool]string{true: l.t("on"), false: l.t("off")}[is])
		}
		for _, k := range channelFields[ch] {
			a, b := fieldValue(before, k), fieldValue(after, k)
			if ch == config.ChanEmail && oa.IsDisabled(ch) {
				continue
			}
			if a != b {
				add("%s: %q → %q", k, a, b)
			}
		}
	}
	tb, ta := reflect.ValueOf(before.Thresholds), reflect.ValueOf(after.Thresholds)
	for i := 0; i < tb.NumField(); i++ {
		if !reflect.DeepEqual(tb.Field(i).Interface(), ta.Field(i).Interface()) {
			add("%s: %v → %v", thresholdKeys[i], tb.Field(i).Interface(), ta.Field(i).Interface())
		}
	}
	if !reflect.DeepEqual(before.ASNLabels(), after.ASNLabels()) {
		add("asn_names: %v → %v", before.ASNLabels(), after.ASNLabels())
	}
	if !reflect.DeepEqual(before.KnownFaces, after.KnownFaces) {
		add("known_faces.asns: %v → %v", before.KnownFaces.ASNs, after.KnownFaces.ASNs)
		add("known_faces.user_agents: %q → %q", before.KnownFaces.UserAgents, after.KnownFaces.UserAgents)
	}
	return out
}

func (s *Server) settingsReview(w http.ResponseWriter, r *http.Request) {
	s.renderSettingsReview(w, r, "")
}

func (s *Server) renderSettingsReview(w http.ResponseWriter, r *http.Request, msg string) {
	rq := reqOf(r)
	l := s.L(r)
	c, err := s.parseChange(r)
	p := page{Title: l.t("settings_review"), SChange: &c}
	if err == nil {
		err = s.prepareSettingsReview(r.Context(), c, &p, l)
	}
	if err != nil {
		p.Err = err.Error()
		s.render(w, r, http.StatusBadRequest, "settings_review", p)
		return
	}
	p.Token = s.reviewToken(rq, c.tokenFields()...)
	p.Err = msg
	s.render(w, r, http.StatusOK, "settings_review", p)
}

func (s *Server) prepareSettingsReview(ctx context.Context, c settingsChange, p *page, l lang) error {
	cur := s.overlay()
	if c.Base != cur.Version {
		return errors.New(l.t("settings_changed"))
	}
	base, err := s.fileConfig()
	if err != nil {
		return err
	}
	cand, err := s.candidate(c, cur, base)
	if err != nil {
		return err
	}
	after, err := s.validate(cand)
	if err != nil {
		return err
	}
	before, err := s.validate(cur)
	if err != nil {
		before = s.eff()
	}
	p.Diff = diffLines(l, before, after, cur, cand)
	if len(p.Diff) == 0 {
		return errors.New(l.t("settings_nochange"))
	}
	if c.Kind == "thresholds" {
		for _, z := range s.Cfg.Cloudflare.Zones {
			p.Replays = append(p.Replays, ReplayThresholds(s.Archive, z, before, after, s.Now(), 7))
		}
	}
	return nil
}

func (s *Server) settingsApply(w http.ResponseWriter, r *http.Request) {
	rq := reqOf(r)
	l := s.L(r)
	c, err := s.parseChange(r)
	if err != nil || !s.reviewOK(rq, r.PostFormValue("review"), c.tokenFields()...) {
		s.render(w, r, http.StatusBadRequest, "message", page{Title: l.t("settings_review"), Msg: l.t("review_expired")})
		return
	}
	if msg := s.writeCheck(r); msg != "" {
		s.renderSettingsReview(w, r, msg)
		return
	}
	if err := s.saveChange(r, c); err != nil {
		s.renderSettingsReview(w, r, err.Error())
		return
	}
	back := map[string]string{"notify": "/settings/notify", "thresholds": "/settings/thresholds", "restore": "/settings/history", "asn_name": "/settings/asn"}[c.Kind]
	if back == "" {
		back = "/settings/known"
	}
	http.Redirect(w, r, back+"?ok="+url.QueryEscape(l.t("settings_saved")), http.StatusSeeOther)
}

// saveChange validates a change against the current overlay version,
// audits it, writes the new overlay and refreshes this process's view.
func (s *Server) saveChange(r *http.Request, c settingsChange) error {
	rq := reqOf(r)
	l := s.L(r)
	s.settingsMu.Lock()
	defer s.settingsMu.Unlock()
	cur := s.overlay()
	if c.Base != cur.Version {
		return errors.New(l.t("settings_changed"))
	}
	base, err := s.fileConfig()
	if err != nil {
		return err
	}
	cand, err := s.candidate(c, cur, base)
	if err != nil {
		return err
	}
	after, err := s.validate(cand)
	if err != nil {
		return err
	}
	before, err := s.validate(cur)
	if err != nil {
		before = s.eff()
	}
	diff := diffLines(l, before, after, cur, cand)
	cand.Version, cand.UpdatedAt, cand.UpdatedBy = cur.Version+1, s.Now().UTC(), s.actor(rq)
	if err := s.DB.Audit(s.actor(rq), rq.IP, "settings_"+c.Kind, fmt.Sprintf("v%d → v%d", cur.Version, cand.Version), strings.Join(diff, " | ")); err != nil {
		return fmt.Errorf("audit log unavailable, nothing changed: %w", err)
	}
	if err := config.WriteOverlay(s.Cfg.OverlayPath, cand); err != nil {
		s.audit(r, "settings_failed", c.Kind, err.Error())
		return err
	}
	return s.refreshSettings(true)
}

// knownMark is the one-click "mark as known" on the faces, movers and
// drill-down pages (step-up for TOTP accounts, audited, no form).
func (s *Server) knownMark(w http.ResponseWriter, r *http.Request) {
	l := s.L(r)
	c := settingsChange{Kind: r.PostFormValue("op"), Fields: map[string]string{"dim": r.PostFormValue("dim"), "name": r.PostFormValue("name")},
		Base: s.overlay().Version}
	if c.Kind != "known_add" && c.Kind != "known_remove" {
		http.Error(w, "bad request", http.StatusBadRequest)
		return
	}
	next := localPath(r.PostFormValue("next"))
	msg := l.t("known_marked")
	if c.Kind == "known_remove" {
		msg = l.t("known_unmarked")
	}
	if err := s.saveChange(r, c); err != nil {
		msg = err.Error()
	}
	sep := "?"
	if strings.Contains(next, "?") {
		sep = "&"
	}
	http.Redirect(w, r, next+sep+"ok="+url.QueryEscape(msg), http.StatusSeeOther)
}

// notifyTest asks the watch to send a test notification.
func (s *Server) notifyTest(w http.ResponseWriter, r *http.Request) {
	ch := r.PostFormValue("channel")
	id, err := control.RequestTest(s.Cfg.DataDir(), ch, s.actor(reqOf(r)), s.Now())
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	s.audit(r, "notify_test", ch, "request "+id)
	http.Redirect(w, r, "/settings/notify?test="+id, http.StatusSeeOther)
}

// ---- alert-line preview ----

// ReplayHour is one hour whose verdict differs between two settings.
type ReplayHour struct {
	From          time.Time
	Before, After []string // findings (signal keys)
}

// Replay compares two settings over archived hours.
type Replay struct {
	Zone                string
	Days                int
	Hours               int // hours with data
	BeforeHours         int // hours over a line
	AfterHours          int
	BeforeEp, AfterEp   int // episodes (runs of consecutive hours)
	Changed             []ReplayHour
	ChangedMore         int
	LongBaselineSamples int
}

func knownOf(c *config.Config) analyze.Known {
	k := analyze.Known{ASNs: map[int]bool{}, UserAgents: c.KnownFaces.UserAgents}
	for _, a := range c.KnownFaces.ASNs {
		k.ASNs[a] = true
	}
	return k
}

func findingKeys(fs []analyze.Finding) []string {
	var out []string
	for _, f := range fs {
		out = append(out, f.Key())
	}
	sort.Strings(out)
	return out
}

// ReplayThresholds re-evaluates the last `days` days of archived hours with both
// settings, the way the watch does (vs the same hour yesterday,
// cross-checked against the 28-day median once it has enough samples).
// It ignores the de-duplication of repeated alerts, so it counts hours
// over a line and episodes, not messages.
func ReplayThresholds(a Archive, z config.Zone, before, after *config.Config, now time.Time, days int) Replay {
	rp := Replay{Zone: z.Name, Days: days}
	end := now.Truncate(time.Hour)
	tb, ta := check.Thresholds(before), check.Thresholds(after) // exactly the watch's lines
	kb, ka := knownOf(before), knownOf(after)
	inB, inA := false, false
	for h := end.Add(-time.Duration(days) * 24 * time.Hour); h.Before(end); h = h.Add(time.Hour) {
		cur, ok, err := a.HourAt(z.ZoneID, h)
		if err != nil || !ok {
			inB, inA = false, false
			continue
		}
		prev, ok, _ := a.HourAt(z.ZoneID, h.Add(-24*time.Hour))
		if !ok {
			continue
		}
		rp.Hours++
		var long *analyze.Metrics
		if ss, err := a.SameHourSnapshots(z.ZoneID, cur.From, cur.To, analyze.LongBaselineDays); err == nil && len(ss) >= analyze.LongBaselineMinSamples {
			var ms []analyze.Metrics
			for _, s := range ss {
				ms = append(ms, s.Metrics)
			}
			m := analyze.Median(ms)
			long = &m
			rp.LongBaselineSamples = len(ss)
		}
		eval := func(th analyze.Thresholds, k analyze.Known) []string {
			fs := analyze.Evaluate(cur.Metrics, prev.Metrics, th, k)
			if long != nil {
				fs = analyze.CrossCheck(fs, analyze.Evaluate(cur.Metrics, *long, th, k))
			}
			return findingKeys(fs)
		}
		fb, fa := eval(tb, kb), eval(ta, ka)
		if len(fb) > 0 {
			rp.BeforeHours++
			if !inB {
				rp.BeforeEp++
			}
		}
		if len(fa) > 0 {
			rp.AfterHours++
			if !inA {
				rp.AfterEp++
			}
		}
		inB, inA = len(fb) > 0, len(fa) > 0
		if !reflect.DeepEqual(fb, fa) {
			if len(rp.Changed) < 20 {
				rp.Changed = append(rp.Changed, ReplayHour{From: h, Before: fb, After: fa})
			} else {
				rp.ChangedMore++
			}
		}
	}
	return rp
}

// RefreshSettings loads the current settings overlay into this process.
func (s *Server) RefreshSettings() error { return s.refreshSettings(true) }

// thresholdRow is one alert line on the settings form.
type thresholdRow struct {
	Key, Value, File string
	Changed          bool
}

func thresholdRows(eff, file config.Thresholds) []thresholdRow {
	ev, fv := reflect.ValueOf(eff), reflect.ValueOf(file)
	var out []thresholdRow
	for i, k := range thresholdKeys {
		e, f := fmt.Sprint(ev.Field(i).Interface()), fmt.Sprint(fv.Field(i).Interface())
		out = append(out, thresholdRow{Key: k, Value: e, File: f, Changed: e != f})
	}
	return out
}

// ---- ASN names ----

// ASNInfo is how the console shows a network.
type ASNInfo struct {
	ASN        int
	Label      string // the operator's short name, else the registered name
	Registered string
	Custom     bool
	Type       string // hosting | eyeball | unknown (judged from the registered name)
}

func asnNumber(name string) int {
	n, err := strconv.Atoi(strings.TrimPrefix(strings.ToUpper(strings.TrimSpace(name)), "AS"))
	if err != nil || n <= 0 {
		return 0
	}
	return n
}

// registeredASNNames returns the archive's registered names (cached).
func (s *Server) registeredASNNames() map[int]string {
	s.asnMu.Lock()
	defer s.asnMu.Unlock()
	if s.asnNames != nil && s.Now().Sub(s.asnAt) < 5*time.Minute {
		return s.asnNames
	}
	if m, err := s.Archive.ASNNames(); err == nil {
		s.asnNames, s.asnAt = m, s.Now()
	}
	if s.asnNames == nil {
		s.asnNames = map[int]string{}
	}
	return s.asnNames
}

func (s *Server) asnInfo(name string) ASNInfo {
	n := asnNumber(name)
	if n == 0 {
		return ASNInfo{}
	}
	in := ASNInfo{ASN: n, Registered: s.registeredASNNames()[n]}
	in.Type = string(suggest.Classify(n, in.Registered))
	if lb := s.eff().ASNLabels()[n]; lb != "" {
		in.Label, in.Custom = lb, true
	} else {
		in.Label = in.Registered
	}
	return in
}

// asnNamePage is the one-field form to name a network.
func (s *Server) asnNamePage(w http.ResponseWriter, r *http.Request) {
	n := asnNumber(r.URL.Query().Get("asn"))
	if n == 0 {
		http.NotFound(w, r)
		return
	}
	in := s.asnInfo(strconv.Itoa(n))
	p := page{Title: s.L(r).t("asn_name_title"), ASN: &in, Next: localPath(r.URL.Query().Get("next"))}
	if p.Next == "/" {
		p.Next = "/settings/asn"
	}
	s.render(w, r, http.StatusOK, "asn_name", p)
}

// asnNamePost saves (or, empty, removes) a short name: step-up, audited.
func (s *Server) asnNamePost(w http.ResponseWriter, r *http.Request) {
	l := s.L(r)
	c := settingsChange{Kind: "asn_name", Base: s.overlay().Version,
		Fields: map[string]string{"asn": strings.TrimSpace(r.PostFormValue("asn")), "name": strings.TrimSpace(r.PostFormValue("name"))}}
	next := localPath(r.PostFormValue("next"))
	msg := l.t("asn_name_saved")
	if err := s.saveChange(r, c); err != nil {
		msg = err.Error()
	}
	sep := "?"
	if strings.Contains(next, "?") {
		sep = "&"
	}
	http.Redirect(w, r, next+sep+"ok="+url.QueryEscape(msg), http.StatusSeeOther)
}
