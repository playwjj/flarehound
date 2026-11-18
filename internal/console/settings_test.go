package console

import (
	"context"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
	"time"

	"github.com/playwjj/flarehound/internal/config"
	"github.com/playwjj/flarehound/internal/control"
)

func settingsEnv(t *testing.T) *writeEnv {
	t.Helper()
	e := newWriteEnv(t, false)
	e.srv.CfgPath = filepath.Join(filepath.Dir(e.srv.Cfg.DataDir()), "config.json")
	if err := e.srv.RefreshSettings(); err != nil {
		t.Fatal(err)
	}
	return e
}

// settingsForm reads a settings page's form values (inputs and checked boxes).
func settingsForm(t *testing.T, body string) url.Values {
	t.Helper()
	v := url.Values{}
	in := regexp.MustCompile(`<input([^>]*)>`)
	attr := func(s, a string) (string, bool) {
		m := regexp.MustCompile(` ` + a + `="([^"]*)"`).FindStringSubmatch(s)
		if m == nil {
			return "", false
		}
		return strings.NewReplacer("&#34;", `"`, "&amp;", "&", "&lt;", "<", "&gt;", ">", "&#43;", "+").Replace(m[1]), true
	}
	form := body[strings.Index(body, `action="/settings/review"`):]
	form = form[:strings.Index(form, "</form>")]
	for _, m := range in.FindAllStringSubmatch(form, -1) {
		name, ok := attr(m[1], "name")
		if !ok {
			continue
		}
		val, _ := attr(m[1], "value")
		if strings.Contains(m[1], `type="checkbox"`) && !strings.Contains(m[1], " checked") {
			continue
		}
		v.Set(name, val)
	}
	return v
}

func reviewApply(t *testing.T, c *client, form url.Values) (string, int) {
	t.Helper()
	code, body, _ := c.do("POST", "/settings/review", form, nil)
	if code != http.StatusOK {
		return body, code
	}
	m := reviewRE.FindStringSubmatch(body)
	if m == nil {
		t.Fatalf("no review token:\n%s", body)
	}
	apply := url.Values{}
	for k, v := range form {
		apply[k] = v
	}
	apply.Set("review", m[1])
	apply.Set("csrf", csrfOf(t, body))
	code, _, _ = c.do("POST", "/settings/apply", apply, nil)
	return body, code
}

func TestSettingsNotify(t *testing.T) {
	e := settingsEnv(t)
	c := e.admin
	v := e.login(t, "viewer", "viewer-password-1")
	if code, _, _ := v.do("GET", "/settings/notify", nil, nil); code != http.StatusForbidden {
		t.Fatalf("viewer reached settings: %d", code)
	}
	_, body, _ := c.do("GET", "/settings/notify", nil, nil)
	if !strings.Contains(body, "watch") || !strings.Contains(body, `name="telegram_chat_id"`) {
		t.Fatal("notify page incomplete")
	}
	form := settingsForm(t, body)
	form.Set("telegram_bot_token_env", "TG_TOKEN")
	form.Set("telegram_chat_id", "-100123")
	form.Set("enabled_telegram", "1")
	form.Del("enabled_jsonl")
	review, code := reviewApply(t, c, form)
	if code != http.StatusSeeOther || !strings.Contains(review, "telegram_chat_id") || !strings.Contains(review, "-100123") {
		t.Fatalf("notify change: %d\n%s", code, review)
	}
	o, _ := config.ReadOverlay(e.srv.Cfg.OverlayPath)
	if o.Version != 1 || o.Notify["telegram_chat_id"] != "-100123" || !o.IsDisabled("jsonl") || o.UpdatedBy != "console:admin" {
		t.Fatalf("overlay: %+v", o)
	}
	if log, _ := e.db.AuditLog(10); log[0].Action != "settings_notify" || !strings.Contains(log[0].Detail, "-100123") {
		t.Fatalf("audit: %+v", log[0])
	}

	// A form built on an older version is refused.
	form.Set("telegram_chat_id", "-100999")
	if _, code := reviewApply(t, c, form); code != http.StatusBadRequest {
		t.Fatalf("stale form accepted: %d", code)
	}
	// Variable names are names.
	_, body, _ = c.do("GET", "/settings/notify", nil, nil)
	form = settingsForm(t, body)
	form.Set("slack_webhook_url_env", "https://hooks.slack.com/services/T0/B0/xyz")
	if body, code := reviewApply(t, c, form); code != http.StatusBadRequest || !strings.Contains(body, "not an environment variable name") {
		t.Fatalf("a secret pasted as a variable name was accepted: %d", code)
	}

	// Test notification round trip through a simulated watch.
	_, body, _ = c.do("GET", "/settings/notify", nil, nil)
	_, _, h := c.do("POST", "/settings/notify/test", url.Values{"csrf": {csrfOf(t, body)}, "channel": {"telegram"}}, nil)
	id := strings.TrimPrefix(h.Get("Location"), "/settings/notify?test=")
	_, body, _ = c.do("GET", h.Get("Location"), nil, nil)
	if !strings.Contains(body, "Waiting for the watch") || !strings.Contains(body, `content="3"`) {
		t.Fatal("pending test not shown")
	}
	_ = control.Poll(context.Background(), e.srv.Cfg.DataDir(), time.Now(), func(_ context.Context, r control.TestRequest) control.TestResult {
		return control.TestResult{Results: []control.ChannelResult{{Channel: r.Channel, Error: "environment variable(s) empty in the watch process: [TG_TOKEN]"}}}
	})
	_, body, _ = c.do("GET", "/settings/notify?test="+id, nil, nil)
	if !strings.Contains(body, "TG_TOKEN") || !strings.Contains(body, "✗") {
		t.Fatal("test result not shown")
	}

	// The watch's report: rejected settings and per-variable state.
	_ = control.WriteStatus(e.srv.Cfg.DataDir(), control.Status{At: time.Now(), Applied: 0, Rejected: 1,
		RejectedReason: "config: notify.slack_webhook_url_env names SLACK_HOOK, but that environment variable is empty",
		Channels:       []config.ChannelInfo{{Name: "telegram", Envs: []string{"TG_TOKEN"}, Missing: []string{"TG_TOKEN"}}}})
	_, body, _ = c.do("GET", "/settings/notify", nil, nil)
	if !strings.Contains(body, "SLACK_HOOK") || !strings.Contains(body, "variable missing in the watch") {
		t.Fatal("watch status not shown")
	}
}

func TestSettingsThresholdsReplay(t *testing.T) {
	e := settingsEnv(t)
	c := e.admin
	_, body, _ := c.do("GET", "/settings/thresholds", nil, nil)
	form := settingsForm(t, body)
	if form.Get("total_up_pct") != "35" {
		t.Fatalf("form: %v", form)
	}
	form.Set("total_up_pct", "200")
	form.Set("dynamic_up_pct", "500")
	form.Set("new_face_min_count", "100000") // the spike hour also has a new face (14,000/h)
	form.Set("csrf", csrfOf(t, body))
	code, review, _ := c.do("POST", "/settings/review", form, nil)
	if code != http.StatusOK || !strings.Contains(review, "Last 7 days, replayed") {
		t.Fatalf("review: %d\n%s", code, review)
	}
	// The fixture's spike (+150 % total, +350 % dynamic) is over the line now, not after.
	m := regexp.MustCompile(`Hours over a line</td><td class="r">(\d+)</td><td class="r"><b>(\d+)</b>`).FindStringSubmatch(review)
	if m == nil || m[1] == "0" || m[2] != "0" {
		t.Fatalf("replay: %v", m)
	}
	// Out of range: refused.
	form.Set("total_up_pct", "0")
	if code, body, _ := c.do("POST", "/settings/review", form, nil); code != http.StatusBadRequest || !strings.Contains(body, "total_up_pct") {
		t.Fatal("0 % alert line accepted")
	}
	form.Set("total_up_pct", "200")
	delete(form, "csrf")
	_, body, _ = c.do("GET", "/settings/thresholds", nil, nil)
	form.Set("csrf", csrfOf(t, body))
	if _, code := reviewApply(t, c, form); code != http.StatusSeeOther {
		t.Fatalf("apply: %d", code)
	}
	if e.srv.eff().Thresholds.TotalUpPct != 200 {
		t.Fatal("console did not pick up its own change")
	}
	// The overview now judges the spike against the new line.
	if _, body, _ := c.do("GET", "/", nil, nil); strings.Contains(body, `class="tile st-alert"`) {
		t.Fatal("overview still uses the old alert line")
	}
}

func TestKnownMarkAndHistory(t *testing.T) {
	e := settingsEnv(t)
	c := e.admin
	_, body, _ := c.do("GET", "/faces?days=1", nil, nil)
	if !strings.Contains(body, `action="/settings/known/mark"`) {
		t.Fatal("no mark-as-known button on new faces")
	}
	code, _, h := c.do("POST", "/settings/known/mark", url.Values{"csrf": {csrfOf(t, body)}, "op": {"known_add"}, "dim": {"ua"},
		"name": {"Crawler/1.0"}, "next": {"/faces?days=1"}}, nil)
	if code != http.StatusSeeOther || !strings.HasPrefix(h.Get("Location"), "/faces?days=1&ok=") {
		t.Fatalf("mark: %d %s", code, h.Get("Location"))
	}
	if !IsKnown(e.srv.eff(), DimUA, "Crawler/1.0") {
		t.Fatal("not known after marking")
	}
	_, body, _ = c.do("GET", "/movers?dim=ua", nil, nil)
	if !regexp.MustCompile(`Crawler/1.0</a> <span class="tag">known</span>`).MatchString(body) {
		t.Fatal("movers do not show the mark")
	}
	// Restore v0 (before the mark) from the history.
	if vs, _ := config.OverlayHistory(e.srv.Cfg.OverlayPath); len(vs) != 1 || vs[0] != 0 {
		t.Fatalf("history before second change: %v", vs)
	}
	_, body, _ = c.do("GET", "/faces", nil, nil)
	c.do("POST", "/settings/known/mark", url.Values{"csrf": {csrfOf(t, body)}, "op": {"known_add"}, "dim": {"asn"}, "name": {"AS207990"}, "next": {"/faces"}}, nil)
	_, body, _ = c.do("GET", "/settings/history", nil, nil)
	if !strings.Contains(body, "v1") {
		t.Fatalf("history page:\n%s", body)
	}
	form := url.Values{"csrf": {csrfOf(t, body)}, "kind": {"restore"}, "base": {"2"}, "version": {"1"}}
	if _, code := reviewApply(t, c, form); code != http.StatusSeeOther {
		t.Fatalf("restore: %d", code)
	}
	o, _ := config.ReadOverlay(e.srv.Cfg.OverlayPath)
	if o.Version != 3 || len(o.KnownASNs) != 0 || len(o.KnownUAs) != 1 {
		t.Fatalf("restored overlay: %+v", o)
	}
	if raw, _ := os.ReadFile(e.srv.Cfg.OverlayPath); strings.Contains(string(raw), "test-token") {
		t.Fatal("a secret in settings.json")
	}
}

func TestASNNames(t *testing.T) {
	e := settingsEnv(t)
	c := e.admin
	if err := e.st.PutASNNames(map[int]string{207990: "HOSTROYALE", 15169: "GOOGLE"}, time.Now()); err != nil {
		t.Fatal(err)
	}
	_, body, _ := c.do("GET", "/movers?dim=asn", nil, nil)
	if !strings.Contains(body, "· HOSTROYALE · <span class=\"net net-unknown\">") && !strings.Contains(body, "· HOSTROYALE · <span class=\"net net-hosting\">") {
		t.Fatalf("registered name not shown:\n%s", body)
	}
	if !strings.Contains(body, "/settings/asn/name?asn=207990") {
		t.Fatal("no name-it link for admins")
	}
	// Name it.
	_, body, _ = c.do("GET", "/settings/asn/name?asn=AS207990&next=%2Fmovers%3Fdim%3Dasn", nil, nil)
	if !strings.Contains(body, "HOSTROYALE") {
		t.Fatal("rename form lacks the registered name")
	}
	code, _, h := c.do("POST", "/settings/asn/name", url.Values{"csrf": {csrfOf(t, body)}, "asn": {"207990"}, "name": {"HostRoyale 机房"},
		"next": {"/movers?dim=asn"}}, nil)
	if code != http.StatusSeeOther || !strings.HasPrefix(h.Get("Location"), "/movers?dim=asn&ok=") {
		t.Fatalf("rename: %d %s", code, h.Get("Location"))
	}
	if got := e.srv.eff().ASNLabels()[207990]; got != "HostRoyale 机房" {
		t.Fatalf("label: %q", got)
	}
	in := e.srv.asnInfo("AS207990")
	if !in.Custom || in.Label != "HostRoyale 机房" || in.Registered != "HOSTROYALE" {
		t.Fatalf("asn info: %+v", in)
	}
	_, body, _ = c.do("GET", "/movers?dim=asn", nil, nil)
	if !strings.Contains(body, "· HostRoyale 机房 ·") {
		t.Fatal("custom name not shown")
	}
	// The viewer sees names but no rename link.
	v := e.login(t, "viewer", "viewer-password-1")
	if _, body, _ := v.do("GET", "/movers?dim=asn", nil, nil); !strings.Contains(body, "HostRoyale 机房") || strings.Contains(body, "/settings/asn/name") {
		t.Fatal("viewer: name missing or rename offered")
	}
	// Cleared: back to the registered name.
	_, body, _ = c.do("GET", "/settings/asn", nil, nil)
	c.do("POST", "/settings/asn/name", url.Values{"csrf": {csrfOf(t, body)}, "asn": {"207990"}, "name": {""}, "next": {"/settings/asn"}}, nil)
	if in := e.srv.asnInfo("207990"); in.Custom || in.Label != "HOSTROYALE" {
		t.Fatalf("after clearing: %+v", in)
	}
	// Too long: refused.
	_, body, _ = c.do("GET", "/settings/asn", nil, nil)
	_, _, h = c.do("POST", "/settings/asn/name", url.Values{"csrf": {csrfOf(t, body)}, "asn": {"207990"}, "name": {strings.Repeat("x", 41)}, "next": {"/settings/asn"}}, nil)
	if !strings.Contains(h.Get("Location"), "40") {
		t.Fatalf("long name not refused: %s", h.Get("Location"))
	}
}

// Step-up must send the user back to the page the button was on, not /users:
// the console sends no Referer, so the form's "next" is what counts.
func TestKnownMarkStepUpReturnsToPage(t *testing.T) {
	e := settingsEnv(t)
	u, _, _ := e.db.UserByName("admin")
	secret, _ := NewTOTPSecret()
	_ = e.db.SetTOTP(u.ID, secret, true, 0)
	c := e.admin
	_, body, _ := c.do("GET", "/faces?days=1", nil, nil)
	code, _, h := c.do("POST", "/settings/known/mark", url.Values{"csrf": {csrfOf(t, body)}, "op": {"known_add"}, "dim": {"ua"},
		"name": {"Crawler/1.0"}, "next": {"/faces?days=1"}}, nil)
	if want := "/stepup?next=" + url.QueryEscape("/faces?days=1"); code != http.StatusSeeOther || h.Get("Location") != want {
		t.Fatalf("step-up redirect: %d %q, want %q", code, h.Get("Location"), want)
	}
}
