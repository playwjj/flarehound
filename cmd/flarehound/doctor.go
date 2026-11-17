package main

// flarehound doctor — one command that answers "is this installation
// healthy and what can it do?": version, configuration, what each token
// can actually reach (with the missing permission named), capabilities
// per zone, archive span, state, heartbeat and outbox. Read-only: every
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

	"github.com/playwjj/flarehound/internal/cfapi"
	"github.com/playwjj/flarehound/internal/check"
	"github.com/playwjj/flarehound/internal/config"
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
		for _, wk := range z.Workers {
			if _, _, err := read.WorkerStats(ctx, cfg.Cloudflare.AccountID, wk, w.From, w.To); err != nil {
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
		rows = append(rows, capRow{"WAF audit", audit})
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
			}
			st.Close()
		}
	}
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
