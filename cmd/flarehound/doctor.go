package main

// flarehound doctor — one command that answers "is this installation
// healthy and what can it do?": version, configuration, what each token
// can actually reach (with the missing permission named), capabilities
// per zone, archive span, storage, state, heartbeat and outbox. Read-only: every
// probe is a GET or an analytics query; nothing is changed.

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/playwjj/flarehound/internal/analyze"
	"github.com/playwjj/flarehound/internal/cfapi"
	"github.com/playwjj/flarehound/internal/check"
	"github.com/playwjj/flarehound/internal/config"
	"github.com/playwjj/flarehound/internal/console"
	"github.com/playwjj/flarehound/internal/control"
	"github.com/playwjj/flarehound/internal/geoip"
	"github.com/playwjj/flarehound/internal/health"
	"github.com/playwjj/flarehound/internal/schedule"
	"github.com/playwjj/flarehound/internal/state"
	"github.com/playwjj/flarehound/internal/store"
)

type doctorOut struct {
	w        io.Writer
	problems int
}

func (d *doctorOut) ok(format string, a ...any) { fmt.Fprintf(d.w, "  ✓ "+format+"\n", a...) }
func (d *doctorOut) bad(format string, a ...any) {
	d.problems++
	fmt.Fprintf(d.w, "  ✗ "+format+"\n", a...)
}
func (d *doctorOut) warn(format string, a ...any) { fmt.Fprintf(d.w, "  ! "+format+"\n", a...) }
func (d *doctorOut) head(s string)                { fmt.Fprintf(d.w, "\n%s\n", s) }

// restGET probes one REST endpoint with a token: nil error means reachable.
func restGET(ctx context.Context, token, path string) error {
	req, _ := http.NewRequestWithContext(ctx, http.MethodGet, cfapi.DefaultREST+path, nil)
	req.Header.Set("Authorization", "Bearer "+token)
	resp, err := (&http.Client{Timeout: 30 * time.Second}).Do(req)
	if err != nil {
		return fmt.Errorf("network error")
	}
	defer resp.Body.Close()
	var env struct {
		Success bool `json:"success"`
		Errors  []struct {
			Code    int    `json:"code"`
			Message string `json:"message"`
		} `json:"errors"`
	}
	_ = json.NewDecoder(resp.Body).Decode(&env)
	if resp.StatusCode/100 == 2 && env.Success {
		return nil
	}
	if len(env.Errors) > 0 {
		return fmt.Errorf("HTTP %d: %d %s", resp.StatusCode, env.Errors[0].Code, env.Errors[0].Message)
	}
	return fmt.Errorf("HTTP %d", resp.StatusCode)
}

func runDoctor(ctx context.Context, cfg *config.Config, cfgPath string, out io.Writer) int {
	d := &doctorOut{w: out}
	fmt.Fprintf(out, "FlareHound doctor — %s\n", version)

	d.head("Configuration")
	d.ok("%s loads and validates", cfgPath)
	d.ok("%d zone(s); timezone %s; reports in %s; daily report at %s", len(cfg.Cloudflare.Zones), cfg.Location, cfg.Report.Language,
		map[bool]string{true: "(disabled)", false: cfg.Schedule.DailyReportAt}[cfg.Schedule.DailyReportAt == ""])
	var chans []string
	for name, on := range map[string]bool{"webhook": cfg.WebhookURL != "", "telegram": cfg.TelegramBotToken != "" && cfg.Notify.TelegramChatID != "",
		"jsonl": cfg.Notify.JSONLFile != "", "slack": cfg.Chan.Slack != "", "discord": cfg.Chan.Discord != "", "wecom": cfg.Chan.WeCom != "",
		"feishu": cfg.Chan.Feishu != "", "email": cfg.Notify.Email != nil} {
		if on {
			chans = append(chans, name)
		}
	}
	if len(chans) == 0 {
		d.warn("no notification channel: findings only reach the log")
	} else {
		d.ok("channels: %s", strings.Join(sortedStrings(chans), ", "))
	}
	if cfg.HeartbeatURL != "" {
		d.ok("heartbeat ping URL configured")
	} else {
		d.warn("no heartbeat ping URL (notify.heartbeat_url_env): nobody outside notices if the watchdog dies")
	}
	doctorGeoIP(d, cfg)
	doctorPurpose(d, cfg)

	read := cfapi.New(cfg.APIToken)
	wt := os.Getenv(cfg.Blocking.WriteTokenEnv)

	d.head("Read token (" + cfg.Cloudflare.APITokenEnv + ")")
	if err := restGET(ctx, cfg.APIToken, "/user/tokens/verify"); err != nil {
		d.bad("token verify: %v", err)
	} else {
		d.ok("token is valid and active")
	}

	type capRow struct{ feature, status string }
	for _, z := range cfg.Cloudflare.Zones {
		d.head(fmt.Sprintf("Zone %s (%s)", z.Name, z.ZoneID))
		w := schedule.IntradayWindow(time.Now(), cfg.IntradayInterval(), cfg.IntradayOffset())
		var rows []capRow
		watch := "✓"
		if n, err := read.Count(ctx, z.ZoneID, w.From, w.To, cfapi.Filter{}); err != nil {
			d.bad("analytics: %v — grant Zone → Analytics: Read", err)
			watch = "✗ needs Zone → Analytics: Read"
		} else {
			d.ok("analytics: %s requests in %s", fmtInt(n), w)
		}
		caps, err := read.Capabilities(ctx, z.ZoneID)
		capsErr := err
		if err != nil {
			d.warn("capability probe failed: %v", err)
		} else {
			asn := "✓"
			if !caps.HasDim(cfapi.DimASN) {
				asn = "✗ (plan has no clientAsn)"
			}
			fw := "✗ (no firewall events dataset on this plan)"
			if caps.FirewallEnabled {
				fw = "✓"
				if caps.FirewallMaxAge > 0 {
					fw += fmt.Sprintf(", kept %.0f day(s)", caps.FirewallMaxAge.Hours()/24)
				}
			}
			d.ok("plan capabilities: ASN breakdown %s; firewall events %s", asn, fw)
		}
		if watch == "✓" {
			switch st, err := read.OriginStats(ctx, z.ZoneID, w.From, w.To); {
			case err != nil:
				d.warn("origin latency: not readable (%v) — origin-slow alerts are off for this zone", err)
			case st.Requests == 0:
				d.ok("origin latency: no origin-answered requests in %s (served from cache/edge — origin tiles stay folded)", w)
			default:
				d.ok("origin latency: first byte P95 %.0f ms, full response P95 %.0f ms over %s origin-answered requests", st.TTFBP95, st.TotalP95, fmtInt(st.Requests))
			}
		}
		for _, wk := range z.Workers {
			if _, err := read.WorkerStats(ctx, cfg.Cloudflare.AccountID, wk, w.From, w.To); err != nil {
				d.bad("worker %s: %v — grant Account → Account Analytics: Read", wk, err)
			} else {
				d.ok("worker %s: metrics readable", wk)
			}
		}
		rows = append(rows, capRow{"hourly watch + daily report", watch})

		audit := "✓"
		if cfg.WAFAudit.Disabled {
			audit = "– disabled in config"
		} else if err := restGET(ctx, cfg.APIToken, "/zones/"+z.ZoneID+"/rulesets/phases/http_request_firewall_custom/entrypoint"); err != nil && !strings.Contains(err.Error(), "HTTP 404") {
			audit = "✗ needs Zone → WAF: Read on the read token"
		}
		if err := restGET(ctx, cfg.APIToken, "/zones/"+z.ZoneID); err != nil && strings.HasPrefix(audit, "✓") {
			audit += " (quota check off: add Zone → Zone: Read)"
		}
		if err := restGET(ctx, cfg.APIToken, "/zones/"+z.ZoneID+"/firewall/access_rules/rules?per_page=1"); err != nil && strings.HasPrefix(audit, "✓") {
			audit += " (IP Access Rules not checked)"
		}
		if strings.HasPrefix(audit, "✓") && cfg.AuditPathsUnset(z) {
			audit += " (path coverage not configured for this zone: set cloudflare.zones[].waf_audit.sensitive_paths)"
		}
		rows = append(rows, capRow{"WAF audit", audit})
		rulesOK := restGET(ctx, cfg.APIToken, "/zones/"+z.ZoneID+"/rulesets/phases/http_request_firewall_custom/entrypoint")
		rulesRead := rulesOK == nil || strings.Contains(rulesOK.Error(), "HTTP 404")
		listsRead := cfg.Cloudflare.AccountID != "" && restGET(ctx, cfg.APIToken, "/accounts/"+cfg.Cloudflare.AccountID+"/rules/lists") == nil
		rows = append(rows, capRow{"rule simulator", simulatorRow(caps, capsErr, watch == "✓", rulesRead, listsRead)})
		rows = append(rows, capRow{"calibration", watch})

		block, rules, cache := "✗ no write token ("+cfg.Blocking.WriteTokenEnv+" empty)", "✗ no write token", "✗ no write token"
		if wt != "" {
			zp := "/zones/" + z.ZoneID
			var missing []string
			if restGET(ctx, wt, zp) != nil {
				missing = append(missing, "Zone → Zone: Read")
			}
			if err := restGET(ctx, wt, zp+"/rulesets/phases/http_request_firewall_custom/entrypoint"); err != nil && !strings.Contains(err.Error(), "HTTP 404") {
				missing = append(missing, "Zone → WAF: Edit")
			}
			dns := restGET(ctx, wt, zp+"/dns_records?per_page=1") == nil
			lists := cfg.Cloudflare.AccountID != "" && restGET(ctx, wt, "/accounts/"+cfg.Cloudflare.AccountID+"/rules/lists") == nil
			access := restGET(ctx, wt, zp+"/firewall/access_rules/rules?per_page=1") == nil
			if len(missing) > 0 {
				block = "✗ needs " + strings.Join(missing, ", ")
				rules = block
			} else {
				block, rules = "✓ (custom rules; edit rights are only proven by a real change)", "✓ custom + rate-limit rules"
				var extra []string
				if !dns {
					extra = append(extra, "IP blocks refused: origin check needs Zone → DNS: Read")
				}
				if !lists {
					extra = append(extra, "no IP list: Account → Account Filter Lists: Edit (expression rules used instead)")
				}
				if !access {
					extra = append(extra, "no IP Access Rule fallback when the quota is full (Zone → WAF or, on older accounts, Firewall Services)")
				}
				if len(extra) > 0 {
					block += "; " + strings.Join(extra, "; ")
				}
			}
			if err := restGET(ctx, wt, zp+"/rulesets/phases/http_request_cache_settings/entrypoint"); err != nil && !strings.Contains(err.Error(), "HTTP 404") {
				cache = "– optional, not granted (Zone → Cache Rules: Edit)"
			} else {
				cache = "✓"
			}
		}
		rows = append(rows, capRow{"one-click blocking", block}, capRow{"rule changes", rules}, capRow{"cache rules", cache})

		fmt.Fprintln(out, "  Capability matrix:")
		for _, r := range rows {
			fmt.Fprintf(out, "    %-28s %s\n", r.feature, r.status)
			if strings.HasPrefix(r.status, "✗") {
				d.problems++
			}
		}

		if st, err := state.Load(check.StatePath(cfg, z)); err == nil {
			switch {
			case st.LastWindow.IsZero():
				d.warn("no window evaluated yet")
			default:
				d.ok("last evaluated window ended %s", st.LastWindow.In(cfg.Location).Format("2006-01-02 15:04"))
			}
			if st.Active {
				d.warn("anomaly episode open since %s: %s", st.FirstAlertAt.In(cfg.Location).Format("01-02 15:04"), st.Fingerprint)
			}
		}
	}
	d.head("Schedule, archive and liveness")
	now := time.Now()
	fmt.Fprintf(out, "  next hourly round %s", schedule.NextIntraday(now, cfg.IntradayInterval(), cfg.IntradayOffset()).In(cfg.Location).Format("2006-01-02 15:04"))
	if cfg.Schedule.DailyReportAt != "" {
		if nd, err := schedule.NextDaily(now, cfg.Schedule.DailyReportAt, cfg.Location, cfg.IntradayOffset()); err == nil {
			fmt.Fprintf(out, "; next daily report %s", nd.In(cfg.Location).Format("2006-01-02 15:04"))
		}
	}
	fmt.Fprintln(out)
	if b, err := health.Check(cfg.DataDir(), health.WatchFile, heartbeatLimit(cfg), now); err != nil {
		d.bad("watch heartbeat: %v", err)
	} else {
		d.ok("watch heartbeat %s ago (%d error(s) last round)", now.Sub(b.At).Round(time.Second), len(b.Errors))
	}
	if b, err := health.Read(cfg.DataDir(), health.EnforceFile); err == nil {
		d.ok("enforcer heartbeat %s ago", now.Sub(b.At).Round(time.Second))
	}
	if !cfg.Archive.Disabled {
		if st, err := store.Open(cfg.Archive.File); err != nil {
			d.bad("archive: %v", err)
		} else {
			for _, z := range cfg.Cloudflare.Zones {
				s, err := st.Stats(z.ZoneID)
				if err != nil {
					d.bad("archive %s: %v", z.Name, err)
					continue
				}
				span := "empty"
				if !s.Oldest.IsZero() {
					span = fmt.Sprintf("since %s (%.0f days)", s.Oldest.In(cfg.Location).Format("2006-01-02"), now.Sub(s.Oldest).Hours()/24)
				}
				d.ok("archive %s: %d hourly + %d daily snapshots, %s; %d alerts recorded", z.Name, s.Hours, s.Days, span, s.Alerts)
				doctorMaturity(d, st, cfg, z)
			}
			st.Close()
		}
	}
	doctorStorage(d, cfg)
	doctorSettings(d, cfg, now)
	doctorConsole(d, cfg, now)

	if raw, err := os.ReadFile(filepath.Join(cfg.DataDir(), "outbox.json")); err == nil && len(raw) > 2 {
		var q []json.RawMessage
		_ = json.Unmarshal(raw, &q)
		d.warn("%d undelivered message(s) waiting in the outbox", len(q))
	}

	if d.problems == 0 {
		fmt.Fprintln(out, "\nAll checks passed.")
		return 0
	}
	fmt.Fprintf(out, "\n%d problem(s) found.\n", d.problems)
	return 1
}

// doctorMaturity shows, per zone, how many measured same-hour samples
// stand behind each newer metric's baseline (the newest archived hour's
// slot), and how long a line still accumulating has to go.
func doctorMaturity(d *doctorOut, st *store.Store, cfg *config.Config, z config.Zone) {
	w, ok, err := st.LatestHour(z.ZoneID)
	if err != nil || !ok {
		return
	}
	ss, err := st.SameHour(z.ZoneID, w.From, w.To, analyze.LongBaselineDays)
	if err != nil {
		d.bad("baseline %s: %v", z.Name, err)
		return
	}
	min := cfg.Thresholds.BaselineMinSamples
	ms := analyze.BaselineMaturity(w.Metrics, analyze.CountSamples(ss), min)
	if len(ms) == 0 || min <= 0 {
		return
	}
	var ripe, young []string
	for _, m := range ms {
		name := m.Metric
		if m.Subject != "" {
			name += "[" + m.Subject + "]"
		}
		if m.Ripe() {
			ripe = append(ripe, fmt.Sprintf("%s %d/%d", name, m.Samples, m.Need))
		} else {
			young = append(young, fmt.Sprintf("%s %d/%d (~%d more day(s))", name, m.Samples, m.Need, m.Need-m.Samples))
		}
	}
	slot := w.From.In(cfg.Location).Format("15:04")
	if len(young) > 0 {
		d.warn("baseline %s @%s: accumulating, these lines stay quiet: %s", z.Name, slot, strings.Join(young, ", "))
	}
	if len(ripe) > 0 {
		d.ok("baseline %s @%s: mature: %s", z.Name, slot, strings.Join(ripe, ", "))
	}
}

// heartbeatLimit is how old the watch heartbeat may get: two rounds plus
// slack (a round can take a few minutes, including the settle re-read).
func heartbeatLimit(cfg *config.Config) time.Duration {
	return 2*cfg.IntradayInterval() + 20*time.Minute
}

func fmtInt(n int64) string {
	s := fmt.Sprint(n)
	for i := len(s) - 3; i > 0; i -= 3 {
		s = s[:i] + "," + s[i:]
	}
	return s
}

func sortedStrings(s []string) []string {
	for i := range s {
		for j := i + 1; j < len(s); j++ {
			if s[j] < s[i] {
				s[i], s[j] = s[j], s[i]
			}
		}
	}
	return s
}

// doctorConsole checks the web console's isolation (docs/web-console-revision.md §5.1).
func doctorConsole(d *doctorOut, cfg *config.Config, now time.Time) {
	d.head("Web console")
	if b, err := health.Read(cfg.DataDir(), health.WatchFile); err == nil && b.WriteTokenInEnv {
		d.bad("the watch process has %s in its environment: the watch must never hold the write token — remove it from the watch's environment", cfg.Blocking.WriteTokenEnv)
	}
	cs := cfg.Console
	if !cs.Enabled {
		d.ok("console off (console.enabled is false)")
		return
	}
	if listenIsLocal(cs.Listen) {
		d.ok("console.listen %s is loopback-only", cs.Listen)
	} else {
		d.warn("console.listen %s is reachable beyond this machine: FlareHound does no TLS — use Tailscale, a TLS reverse proxy or Cloudflare Tunnel", cs.Listen)
		if len(cs.TrustedProxies) == 0 {
			d.warn("no console.trusted_proxies: client IPs and HTTPS behind a proxy cannot be recognised (session cookies are sent without Secure)")
		}
	}
	if cs.BaseURL != "" && strings.HasPrefix(cs.BaseURL, "http://") && !strings.Contains(cs.BaseURL, "://127.") && !strings.Contains(cs.BaseURL, "://localhost") {
		d.warn("console.base_url %s is plain HTTP: passwords and session cookies would cross the network in clear text", cs.BaseURL)
	}
	for name, oc := range map[string]*config.OAuthClient{"Google": cs.OAuth.Google, "GitHub": cs.OAuth.GitHub} {
		if oc == nil {
			continue
		}
		d.ok("%s sign-in configured; redirect URI to register: %s/oauth/%s/callback", name, cs.BaseURL, strings.ToLower(name))
		if strings.HasPrefix(cs.BaseURL, "http://") && !strings.Contains(cs.BaseURL, "://127.") && !strings.Contains(cs.BaseURL, "://localhost") {
			d.warn("%s sign-in over plain HTTP: providers (Google in particular) refuse non-HTTPS redirect URIs except localhost", name)
		}
	}
	if cfg.Notify.Email != nil && cs.BaseURL != "" && !cs.ProxyAuth.DisableLogin {
		d.ok("password reset by e-mail available (through notify.email)")
	} else {
		d.warn("password reset by e-mail off (needs notify.email and console.base_url): admins reset passwords, or `flarehound console reset-password`")
	}
	if cs.ProxyAuth.Header != "" {
		d.ok("proxy identity header %s trusted from %s", cs.ProxyAuth.Header, strings.Join(cs.TrustedProxies, ", "))
	}
	if b, err := health.Read(cfg.DataDir(), health.ConsoleFile); err != nil {
		d.warn("no console heartbeat: the console has not run yet (flarehound console)")
	} else {
		age := now.Sub(b.At).Round(time.Second)
		if age > 15*time.Minute {
			d.warn("console heartbeat %s ago: is the console still running?", age)
		} else {
			d.ok("console running on %s (heartbeat %s ago)", b.Listen, age)
		}
		if b.WriteTokenInEnv {
			d.ok("the console holds the write token: admins can block from the console")
			if !cs.RequireTOTP {
				d.warn("the console can change Cloudflare but console.require_totp is off: require two-factor sign-in for accounts that can block")
			}
		} else {
			d.ok("the console has no write token: read-only (blocking via the CLI)")
		}
	}
	db, err := console.OpenDB(cfg.Console.DBFile)
	if err != nil {
		d.bad("console database: %v", err)
		return
	}
	defer db.Close()
	us, err := db.Users()
	if err != nil {
		d.bad("console database: %v", err)
		return
	}
	admins, twofa := 0, 0
	for _, u := range us {
		if u.Admin() && !u.Disabled {
			admins++
		}
		if u.TOTPEnabled {
			twofa++
		}
	}
	switch {
	case len(us) == 0 && !cs.ProxyAuth.DisableLogin:
		d.warn("no console accounts yet: run `flarehound console init-admin --user NAME` or use the setup link the console logs")
	case admins == 0 && !cs.ProxyAuth.DisableLogin:
		d.bad("no active admin account: run `flarehound console init-admin --user NAME`")
	default:
		d.ok("%d account(s), %d admin(s), %d with two-factor sign-in%s", len(us), admins, twofa,
			map[bool]string{true: " (required)", false: ""}[cs.RequireTOTP])
	}
}

// doctorSettings reports the console-managed settings and the channels.
func doctorSettings(d *doctorOut, cfg *config.Config, now time.Time) {
	d.head("Settings and notification channels")
	if o := cfg.Overlay; o != nil && !o.Empty() {
		d.ok("console settings v%d in %s (last change by %s, %s)", o.Version, cfg.OverlayPath, o.UpdatedBy, o.UpdatedAt.Format("2006-01-02 15:04"))
	} else {
		d.ok("no console settings: config.json alone")
	}
	if st, ok, err := control.ReadStatus(cfg.DataDir()); err == nil && ok {
		switch {
		case st.RejectedReason != "":
			d.bad("the watch rejected the latest settings and keeps the previous ones: %s", st.RejectedReason)
		case st.Pending > 0:
			d.ok("the watch accepted settings v%d; they apply before its next round", st.Pending)
		default:
			d.ok("the watch runs settings v%d (reported %s ago)", st.Applied, now.Sub(st.At).Round(time.Second))
		}
	}
	for _, ci := range cfg.Channels() {
		switch {
		case ci.Disabled:
			d.ok("%s: turned off in the console", ci.Name)
		case len(ci.Missing) > 0:
			d.bad("%s: environment variable(s) empty in this process: %s", ci.Name, strings.Join(ci.Missing, ", "))
		case ci.Configured:
			d.ok("%s: configured", ci.Name)
		}
	}
	d.warn("channel variables are checked in the process running doctor; the console's notification settings show what the watch itself sees, and can send a test through it")
}

// doctorGeoIP reports the IP-location library: loaded (with its date and
// size), not found (the feature is simply off), or unreadable (an error).
func doctorGeoIP(d *doctorOut, cfg *config.Config) {
	st := geoip.Load(cfg.GeoIPCandidates())
	switch {
	case st.DB != nil:
		defer st.DB.Close()
		in := st.DB.Info()
		file := ""
		if fi, err := os.Stat(st.Path); err == nil {
			file = ", file " + fi.ModTime().In(cfg.Location).Format("2006-01-02")
		}
		d.ok("IP location: %s loaded — %s, built %s%s, %s networks", st.Path, in.Type, in.Built.Format("2006-01-02"), file, fmtInt(int64(in.Networks)))
		if age := time.Since(in.Built); age > 180*24*time.Hour {
			d.warn("IP location library is %d days old (country assignments change slowly; `flarehound geoip update` refreshes it)", int(age.Hours()/24))
		}
	case st.Err != nil:
		d.bad("IP location off: %s cannot be used: %v — replace it (`flarehound geoip update`) or remove it", st.Path, st.Err)
	default:
		d.warn("IP location off: no country library (looked for %s) — `flarehound geoip update` downloads one", strings.Join(st.Tried, ", "))
	}
}

// simulatorRow is the rule simulator's line in a zone's capability matrix:
// which parts of an expression this plan's analytics can evaluate, and
// whether net new (firewall events) is available. A gap is a plan limit,
// not a problem: the simulator says "not evaluable here" instead of a number.
func simulatorRow(caps cfapi.Caps, err error, analytics, rules, lists bool) string {
	if !analytics {
		return "– needs Zone → Analytics: Read"
	}
	if err != nil {
		return "✓ (capabilities not probed: a missing dimension shows up as a failed section)"
	}
	mark := func(ok bool) string {
		if ok {
			return "✓"
		}
		return "✗"
	}
	s := fmt.Sprintf("✓ ASN dimension %s · country %s · referer host %s · firewall events (net new) %s · rule position %s · $lists %s",
		mark(caps.HasDim(cfapi.DimASN)), mark(caps.HasDim("clientCountryName")), mark(caps.HasDim("clientRefererHost")), mark(caps.HasFirewallDim("action")),
		mark(rules), mark(lists))
	if !rules {
		s += " (position: Zone → WAF: Read on the read token)"
	}
	if !lists {
		s += " ($lists: account_id and Account → Account Filter Lists: Read on the read token)"
	}
	return s
}

// doctorPurpose reports the traffic-by-purpose table: its version and
// size, the overrides in effect; off (and why) when the table is broken.
func doctorPurpose(d *doctorOut, cfg *config.Config) {
	t := cfg.PurposeTable()
	if !t.OK() {
		d.warn("traffic by purpose off: %v (reports, console and alerts behave as without it)", t.Err())
		return
	}
	d.ok("traffic by purpose: built-in table %s, %d entries; %d override(s)", t.Version(), t.Size(), t.Overrides())
}
