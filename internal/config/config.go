// Package config loads FlareHound's JSON configuration.
//
// Secrets (API token, bot token, webhook URL) are never stored in the
// config file: the file only names the environment variables that carry
// them (see SPEC.md, security model).
package config

import (
	"encoding/json"
	"fmt"
	"net/netip"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"time"
	_ "time/tzdata" // the alpine image ships no zoneinfo
)

type Zone struct {
	ZoneID  string   `json:"zone_id"`
	Name    string   `json:"name"`
	Workers []string `json:"workers"`
}

type Thresholds struct {
	TotalUpPct         float64 `json:"total_up_pct"`
	WorkerCallsUpPct   float64 `json:"worker_calls_up_pct"`
	CPUP50UpPct        float64 `json:"cpu_p50_up_pct"`
	DynamicUpPct       float64 `json:"dynamic_up_pct"`
	Origin5xxMultiple  float64 `json:"origin_5xx_multiplier"`
	Origin5xxMin       int64   `json:"origin_5xx_min"`
	NewFaceMinCount    int64   `json:"new_face_min_count"`
	CollapseDownPct    float64 `json:"collapse_down_pct"`
	MinCount           int64   `json:"min_count"`
	EscalationPct      float64 `json:"escalation_pct"`
	RecoveryCleanRound int     `json:"recovery_clean_rounds"`
}

// DefaultThresholds are the 2026-11-17 battle-tested values (SPEC 7.2).
func DefaultThresholds() Thresholds {
	return Thresholds{
		TotalUpPct:         35,
		WorkerCallsUpPct:   35,
		CPUP50UpPct:        25,
		DynamicUpPct:       50,
		Origin5xxMultiple:  3,
		Origin5xxMin:       50,
		NewFaceMinCount:    5000,
		CollapseDownPct:    50,
		MinCount:           1000,
		EscalationPct:      25,
		RecoveryCleanRound: 2,
	}
}

// PathRule is a path-level threshold override (SPEC 7.2) for sensitive,
// low-volume paths whose anomalies would drown in zone totals.
// Path uses * as wildcard, e.g. "/login*".
type PathRule struct {
	Name     string  `json:"name"`
	Path     string  `json:"path"`
	UpPct    float64 `json:"up_pct"`
	MinCount int64   `json:"min_count"`
	// DynamicOnly counts only uncached (cacheStatus "dynamic") requests:
	// the real rendering load of the path, not every edge hit.
	DynamicOnly bool `json:"dynamic_only"`
}

// PathCheckpoint is a daily fixed checkpoint (SPEC 7.4): the origin
// reach (uncached requests) of a path that should stay at or below Max.
type PathCheckpoint struct {
	Label string `json:"label"`
	Path  string `json:"path"`
	Max   int64  `json:"max"`
}

// Artifact is a known accounting artifact (SPEC 7.4) counted and shown
// separately so it is never mistaken for real visitor errors.
type Artifact struct {
	Label      string `json:"label"`
	Path       string `json:"path"`
	EdgeStatus int    `json:"edge_status"`
}

// KnownFaces is the user-maintained known-pattern library (SPEC 17):
// sources registered here never count as "new faces".
type KnownFaces struct {
	ASNs       []int    `json:"asns"`
	UserAgents []string `json:"user_agents"` // case-insensitive substrings
}

type Notify struct {
	WebhookURL          string `json:"webhook_url"`
	WebhookURLEnv       string `json:"webhook_url_env"`
	TelegramBotTokenEnv string `json:"telegram_bot_token_env"`
	TelegramChatID      string `json:"telegram_chat_id"`
	// JSONLFile appends every message as one JSON line to a local file
	// (for bridges and log shippers). Relative paths are relative to the
	// working directory; in Docker use /app/data/….
	JSONLFile string `json:"jsonl_file"`

	// Chat bots (v0.8): each URL comes from the named environment
	// variable — bot URLs are secrets.
	SlackWebhookURLEnv   string `json:"slack_webhook_url_env"`
	DiscordWebhookURLEnv string `json:"discord_webhook_url_env"`
	WeComWebhookURLEnv   string `json:"wecom_webhook_url_env"`
	FeishuWebhookURLEnv  string `json:"feishu_webhook_url_env"`
	FeishuSecretEnv      string `json:"feishu_secret_env"`

	Email *EmailConfig `json:"email,omitempty"`

	// HeartbeatURLEnv names the variable holding a healthchecks.io-style
	// URL pinged after every watch round (url/fail when a zone errored).
	HeartbeatURLEnv string `json:"heartbeat_url_env"`
}

// EmailConfig is the SMTP channel. The password comes from PasswordEnv.
type EmailConfig struct {
	Host        string   `json:"smtp_host"`
	Port        int      `json:"smtp_port"`
	TLS         string   `json:"tls"` // starttls (default) | tls | none
	Username    string   `json:"username"`
	PasswordEnv string   `json:"password_env"`
	From        string   `json:"from"`
	To          []string `json:"to"`
}

// Channels holds the resolved channel secrets.
type Channels struct {
	Slack, Discord, WeCom, Feishu, FeishuSecret, EmailPassword string
}

// Console is the web console (v1.3, docs/web-console-revision.md). It is
// a separate process (`flarehound console`), off unless Enabled, and
// bound to loopback by default: exposing it beyond this machine is left
// to the operator's own Tailscale / reverse proxy / Cloudflare Tunnel.
type Console struct {
	Enabled bool   `json:"enabled"`
	Listen  string `json:"listen"`  // default 127.0.0.1:8640
	DBFile  string `json:"db_file"` // accounts and sessions; default <data dir>/console.db
	// BaseURL is how people reach the console (e.g. https://hound.example.ts.net).
	// When set, notifications carry a deep link to the matching view.
	BaseURL string `json:"base_url"`
	// RefreshSeconds is the auto-refresh interval of live views (0: 300).
	RefreshSeconds int `json:"refresh_seconds"`
	// SessionHours is the idle lifetime of a login session (0: 12).
	SessionHours int `json:"session_hours"`
	// RequireTOTP makes two-factor sign-in mandatory for every account.
	RequireTOTP bool `json:"require_totp"`
	// TrustedProxies lists the addresses (IPs or CIDRs) of the reverse
	// proxies in front of the console. Only requests from them may set
	// X-Forwarded-For / X-Forwarded-Proto or the proxy identity header.
	TrustedProxies []string `json:"trusted_proxies"`
	// ProxyAuth trusts an identity header injected by an authenticating
	// proxy (Cloudflare Access, oauth2-proxy, …). Requires TrustedProxies.
	ProxyAuth struct {
		Header string `json:"header"` // e.g. Cf-Access-Authenticated-User-Email
		// DefaultRole applies to identities that match no local account:
		// "viewer" (default) or "none" (refuse).
		DefaultRole string `json:"default_role"`
		// DisableLogin turns the built-in password login off.
		DisableLogin bool `json:"disable_login"`
	} `json:"proxy_auth"`
	// OAuth adds third-party sign-in (v1.5). An external identity only
	// signs in to the local account it was linked to; it never creates one.
	OAuth struct {
		Google *OAuthClient `json:"google,omitempty"`
		GitHub *OAuthClient `json:"github,omitempty"`
	} `json:"oauth"`
}

// OAuthClient is one provider's OAuth app. The secret comes from the
// environment variable named by ClientSecretEnv.
type OAuthClient struct {
	ClientID        string `json:"client_id"`
	ClientSecretEnv string `json:"client_secret_env"`
	ClientSecret    string `json:"-"`
}

type Config struct {
	Cloudflare struct {
		AccountID   string `json:"account_id"`
		APITokenEnv string `json:"api_token_env"`
		Zones       []Zone `json:"zones"`
	} `json:"cloudflare"`
	Schedule struct {
		IntradayInterval string `json:"intraday_interval"`
		IntradayOffset   string `json:"intraday_offset"`
		SettleDelay      string `json:"settle_delay"`
		DailyReportAt    string `json:"daily_report_at"`
		Timezone         string `json:"timezone"`
		// MaxParallelZones bounds how many zones are checked at once
		// (default 4): enough to finish quickly, few enough to stay well
		// inside the GraphQL rate limit.
		MaxParallelZones int `json:"max_parallel_zones"`
	} `json:"schedule"`
	Thresholds Thresholds `json:"thresholds"`
	PathRules  []PathRule `json:"path_rules"`
	Daily      struct {
		Paths     []PathCheckpoint `json:"paths"`
		Artifacts []Artifact       `json:"artifacts"`
	} `json:"daily"`
	KnownFaces KnownFaces `json:"known_faces"`
	// RuleNames labels firewall rule IDs in reports ("<ruleId>": "name")
	// until the WAF audit (v0.6) reads names from the rulesets itself.
	RuleNames map[string]string `json:"rule_names"`
	// ASNNames are short names for networks ("45102": "aliyun"), used in
	// notifications and the console instead of the registered name.
	ASNNames map[string]string `json:"asn_names"`
	Report   struct {
		Language string `json:"language"` // "en" | "zh"
		// Visuals attaches charts (Telegram, Discord, WeCom, email, JSONL)
		// and sends email as HTML. Default true.
		Visuals bool `json:"visuals"`
	} `json:"report"`
	Notify    Notify `json:"notify"`
	StateFile string `json:"state_file"`
	Blocking  struct {
		WriteTokenEnv  string   `json:"write_token_env"`  // default CF_WRITE_TOKEN; read only by block/unblock/enforce
		NeverBlock     []string `json:"never_block"`      // CIDRs / IPs that are never blocked
		NeverBlockASNs []int    `json:"never_block_asns"` // ASNs that are never blocked
	} `json:"blocking"`
	WAFAudit struct {
		Disabled bool `json:"disabled"`
		// Hosts to probe (default: the zone name). Rules often pin
		// http.host, so coverage is judged per host.
		Hosts []string `json:"hosts"`
		// SensitivePaths adds patterns to path_rules and daily.paths,
		// which are always checked for coverage.
		SensitivePaths []string `json:"sensitive_paths"`
	} `json:"waf_audit"`
	Archive struct {
		Disabled            bool   `json:"disabled"`
		File                string `json:"file"`                  // default: <data dir>/archive.db
		HourlyRetentionDays int    `json:"hourly_retention_days"` // default 400 (~13 months)
	} `json:"archive"`

	Console Console `json:"console"`

	// Overlay is the console-managed layer applied at load (nil: none).
	Overlay     *Overlay `json:"-"`
	OverlayPath string   `json:"-"`

	getenv         func(string) string
	notifyOptional bool

	// Secrets resolved from the environment at load time; never persisted.
	APIToken         string   `json:"-"`
	TelegramBotToken string   `json:"-"`
	WebhookURL       string   `json:"-"`
	Chan             Channels `json:"-"`
	HeartbeatURL     string   `json:"-"`

	Location *time.Location `json:"-"`
}

// Secrets returns every secret value, for log redaction.
func (c *Config) Secrets() []string {
	s := []string{c.APIToken, c.TelegramBotToken, c.WebhookURL,
		c.Chan.Slack, c.Chan.Discord, c.Chan.WeCom, c.Chan.Feishu, c.Chan.FeishuSecret, c.Chan.EmailPassword, c.HeartbeatURL}
	for _, oc := range []*OAuthClient{c.Console.OAuth.Google, c.Console.OAuth.GitHub} {
		if oc != nil {
			s = append(s, oc.ClientSecret)
		}
	}
	return s
}

var hhmm = regexp.MustCompile(`^([01]\d|2[0-3]):[0-5]\d$`)
var tag = regexp.MustCompile(`^[0-9a-f]{32}$`)

// Load reads and validates the config file at path, applies the console
// settings overlay, then resolves secrets from the environment. Fields
// absent from the file keep their defaults.
func Load(path string) (*Config, error) { return LoadWith(path, LoadOptions{}) }

// LoadOptions tunes a load.
type LoadOptions struct {
	// Overlay replaces the overlay file (to validate a change before
	// saving it); NoOverlay ignores the overlay altogether.
	Overlay   *Overlay
	NoOverlay bool
	// Getenv replaces os.Getenv (validation in a process that does not
	// hold the watch's environment).
	Getenv func(string) string
	// NotifySecretsOptional: an empty notification variable is not an
	// error (the console does not send alerts; the watch checks them).
	NotifySecretsOptional bool
}

// LoadWith is Load with options.
func LoadWith(path string, opt LoadOptions) (*Config, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	c := Config{Thresholds: DefaultThresholds()}
	c.Cloudflare.APITokenEnv = "CF_API_TOKEN"
	c.Schedule.IntradayInterval = "1h"
	c.Schedule.IntradayOffset = "7m"
	c.Schedule.SettleDelay = "3m"
	c.Schedule.DailyReportAt = "08:00"
	c.Report.Language = "en"
	c.Report.Visuals = true
	c.StateFile = "data/state.json"
	if err := json.Unmarshal(raw, &c); err != nil {
		return nil, fmt.Errorf("parse config: %w", err)
	}
	c.getenv, c.notifyOptional = opt.Getenv, opt.NotifySecretsOptional
	if c.getenv == nil {
		c.getenv = os.Getenv
	}
	if c.StateFile == "" {
		c.StateFile = "data/state.json"
	}
	c.OverlayPath = filepath.Join(c.DataDir(), OverlayFile)
	if !opt.NoOverlay {
		o := opt.Overlay
		if o == nil {
			if o, err = ReadOverlay(c.OverlayPath); err != nil {
				return nil, fmt.Errorf("settings: %w", err)
			}
		}
		if o.Thresholds != nil {
			if err := CheckThresholds(*o.Thresholds); err != nil {
				return nil, fmt.Errorf("settings: %w", err)
			}
		}
		if err := c.apply(o); err != nil {
			return nil, err
		}
	}
	if err := c.resolve(); err != nil {
		return nil, err
	}
	return &c, nil
}

func (c *Config) resolve() error {
	if c.getenv == nil {
		c.getenv = os.Getenv
	}
	if c.Cloudflare.APITokenEnv == "" {
		c.Cloudflare.APITokenEnv = "CF_API_TOKEN"
	}
	c.APIToken = c.getenv(c.Cloudflare.APITokenEnv)
	if c.APIToken == "" {
		return fmt.Errorf("environment variable %s is empty: a read-only Cloudflare API token is required", c.Cloudflare.APITokenEnv)
	}
	if c.Notify.TelegramBotTokenEnv != "" {
		c.TelegramBotToken = c.getenv(c.Notify.TelegramBotTokenEnv)
	}
	c.WebhookURL = c.Notify.WebhookURL
	if c.Notify.WebhookURLEnv != "" {
		c.WebhookURL = c.getenv(c.Notify.WebhookURLEnv)
	}
	env := func(name string) string {
		if name == "" {
			return ""
		}
		return c.getenv(name)
	}
	n := c.Notify
	c.Chan = Channels{Slack: env(n.SlackWebhookURLEnv), Discord: env(n.DiscordWebhookURLEnv), WeCom: env(n.WeComWebhookURLEnv),
		Feishu: env(n.FeishuWebhookURLEnv), FeishuSecret: env(n.FeishuSecretEnv)}
	for name, v := range map[string]string{"slack_webhook_url_env": n.SlackWebhookURLEnv, "discord_webhook_url_env": n.DiscordWebhookURLEnv,
		"wecom_webhook_url_env": n.WeComWebhookURLEnv, "feishu_webhook_url_env": n.FeishuWebhookURLEnv} {
		if v != "" && c.getenv(v) == "" && !c.notifyOptional {
			return fmt.Errorf("config: notify.%s names %s, but that environment variable is empty", name, v)
		}
	}
	if n.HeartbeatURLEnv != "" {
		if c.HeartbeatURL = c.getenv(n.HeartbeatURLEnv); c.HeartbeatURL == "" && !c.notifyOptional {
			return fmt.Errorf("config: notify.heartbeat_url_env names %s, but that environment variable is empty", n.HeartbeatURLEnv)
		}
	}
	if e := n.Email; e != nil {
		if e.Host == "" || e.From == "" || len(e.To) == 0 {
			return fmt.Errorf("config: notify.email needs smtp_host, from and at least one to")
		}
		switch e.TLS {
		case "", "starttls", "tls", "none":
		default:
			return fmt.Errorf("config: notify.email.tls must be starttls, tls or none")
		}
		if e.Username != "" {
			c.Chan.EmailPassword = env(e.PasswordEnv)
			if c.Chan.EmailPassword == "" && !c.notifyOptional {
				return fmt.Errorf("config: notify.email.password_env must name a non-empty environment variable when username is set")
			}
		}
	}

	if len(c.Cloudflare.Zones) == 0 {
		return fmt.Errorf("config: at least one zone is required")
	}
	needAccount := false
	for i, z := range c.Cloudflare.Zones {
		if !tag.MatchString(z.ZoneID) {
			return fmt.Errorf("config: zones[%d].zone_id %q is not a 32-char hex Cloudflare zone ID", i, z.ZoneID)
		}
		if z.Name == "" {
			c.Cloudflare.Zones[i].Name = z.ZoneID
		}
		if len(z.Workers) > 0 {
			needAccount = true
		}
	}
	if needAccount && !tag.MatchString(c.Cloudflare.AccountID) {
		return fmt.Errorf("config: account_id %q is not a 32-char hex account ID (required to watch Workers)", c.Cloudflare.AccountID)
	}

	for _, d := range []struct{ name, v string }{
		{"intraday_interval", c.Schedule.IntradayInterval},
		{"intraday_offset", c.Schedule.IntradayOffset},
		{"settle_delay", c.Schedule.SettleDelay},
	} {
		if _, err := time.ParseDuration(d.v); err != nil {
			return fmt.Errorf("config: schedule.%s: %v", d.name, err)
		}
	}
	if iv := c.IntradayInterval(); iv%time.Hour != 0 {
		return fmt.Errorf("config: schedule.intraday_interval must be a whole number of hours (windows are full clock hours)")
	}
	if off := c.IntradayOffset(); off < 0 || off >= time.Hour {
		return fmt.Errorf("config: schedule.intraday_offset must be within [0, 1h)")
	}
	if c.Schedule.DailyReportAt != "" && !hhmm.MatchString(c.Schedule.DailyReportAt) {
		return fmt.Errorf("config: schedule.daily_report_at %q must be HH:MM (or empty to disable)", c.Schedule.DailyReportAt)
	}
	switch p := c.Schedule.MaxParallelZones; {
	case p == 0:
		c.Schedule.MaxParallelZones = 4
	case p < 1 || p > 16:
		return fmt.Errorf("config: schedule.max_parallel_zones must be within 1..16")
	}
	c.Location = time.Local
	if c.Schedule.Timezone != "" {
		loc, err := time.LoadLocation(c.Schedule.Timezone)
		if err != nil {
			return fmt.Errorf("config: schedule.timezone: %v", err)
		}
		c.Location = loc
	}
	switch c.Report.Language {
	case "en", "zh":
	case "":
		c.Report.Language = "en"
	default:
		return fmt.Errorf("config: report.language must be \"en\" or \"zh\"")
	}
	for i, p := range c.PathRules {
		if !strings.HasPrefix(p.Path, "/") {
			return fmt.Errorf("config: path_rules[%d].path must start with /", i)
		}
		if p.Name == "" {
			c.PathRules[i].Name = p.Path
		}
	}
	for i, p := range c.Daily.Paths {
		if !strings.HasPrefix(p.Path, "/") {
			return fmt.Errorf("config: daily.paths[%d].path must start with /", i)
		}
	}
	if c.StateFile == "" {
		c.StateFile = "data/state.json"
	}
	if c.Blocking.WriteTokenEnv == "" {
		c.Blocking.WriteTokenEnv = "CF_WRITE_TOKEN"
	}
	if c.Blocking.WriteTokenEnv == c.Cloudflare.APITokenEnv {
		return fmt.Errorf("config: blocking.write_token_env must differ from cloudflare.api_token_env — the write token is kept separate from the read-only one")
	}
	for i, s := range c.Blocking.NeverBlock {
		if _, err := netip.ParsePrefix(s); err != nil {
			if _, err := netip.ParseAddr(s); err != nil {
				return fmt.Errorf("config: blocking.never_block[%d] %q is not an IP or CIDR", i, s)
			}
		}
	}
	for k, v := range c.ASNNames {
		if err := checkASNName(k, v); err != nil {
			return fmt.Errorf("config: asn_names: %w", err)
		}
	}
	if c.Archive.File == "" {
		c.Archive.File = filepath.Join(c.DataDir(), "archive.db")
	}
	if err := c.resolveConsole(); err != nil {
		return err
	}
	if c.Archive.HourlyRetentionDays <= 0 {
		c.Archive.HourlyRetentionDays = 400
	}
	if c.Archive.HourlyRetentionDays < 30 {
		return fmt.Errorf("config: archive.hourly_retention_days must be >= 30 (the long baseline needs 28 days)")
	}
	return nil
}

// NeverBlock returns the user allowlist as prefixes.
func (c *Config) NeverBlock() []netip.Prefix {
	var out []netip.Prefix
	for _, s := range c.Blocking.NeverBlock {
		if p, err := netip.ParsePrefix(s); err == nil {
			out = append(out, p.Masked())
		} else if a, err := netip.ParseAddr(s); err == nil {
			out = append(out, netip.PrefixFrom(a, a.BitLen()))
		}
	}
	return out
}

// WriteToken reads the separate write token (SPEC 13.1). Only the
// blocking commands call this; the watch process never does.
func (c *Config) WriteToken() (string, error) {
	t := os.Getenv(c.Blocking.WriteTokenEnv)
	if t == "" {
		return "", fmt.Errorf("environment variable %s is empty: blocking needs a separate write token (Account → Account Filter Lists: Edit; Zone → WAF: Edit (older accounts: Firewall Services: Edit), DNS: Read, Zone: Read)", c.Blocking.WriteTokenEnv)
	}
	return t, nil
}

// IntradayInterval parses the configured interval, defaulting to 1h.
func (c *Config) IntradayInterval() time.Duration { return dur(c.Schedule.IntradayInterval, time.Hour) }

// IntradayOffset is how long after the hour boundary the check runs,
// absorbing analytics ingestion lag (SPEC 7.1: ~7 minutes).
func (c *Config) IntradayOffset() time.Duration { return dur(c.Schedule.IntradayOffset, 7*time.Minute) }

// SettleDelay is how long to wait before re-reading a window that looks
// collapsed, to tell ingestion lag from a real drop (SPEC 6).
func (c *Config) SettleDelay() time.Duration { return dur(c.Schedule.SettleDelay, 3*time.Minute) }

func dur(s string, def time.Duration) time.Duration {
	d, err := time.ParseDuration(s)
	if err != nil || d < 0 || (d == 0 && def == time.Hour) {
		return def
	}
	return d
}

// DataDir is the directory holding the state file; per-zone state,
// the notification outbox and future archives live next to it.
func (c *Config) DataDir() string { return filepath.Dir(c.StateFile) }

func (c *Config) resolveConsole() error {
	cs := &c.Console
	if cs.Listen == "" {
		cs.Listen = "127.0.0.1:8640"
	}
	if cs.DBFile == "" {
		cs.DBFile = filepath.Join(c.DataDir(), "console.db")
	}
	if cs.RefreshSeconds == 0 {
		cs.RefreshSeconds = 300
	}
	if cs.RefreshSeconds < 30 {
		return fmt.Errorf("config: console.refresh_seconds must be >= 30")
	}
	if cs.SessionHours == 0 {
		cs.SessionHours = 12
	}
	if cs.SessionHours < 1 || cs.SessionHours > 24*30 {
		return fmt.Errorf("config: console.session_hours must be within 1..720")
	}
	cs.BaseURL = strings.TrimRight(cs.BaseURL, "/")
	if cs.BaseURL != "" && !strings.HasPrefix(cs.BaseURL, "https://") && !strings.HasPrefix(cs.BaseURL, "http://") {
		return fmt.Errorf("config: console.base_url must start with https:// or http://")
	}
	for i, s := range cs.TrustedProxies {
		if _, err := netip.ParsePrefix(s); err != nil {
			if _, err := netip.ParseAddr(s); err != nil {
				return fmt.Errorf("config: console.trusted_proxies[%d] %q is not an IP or CIDR", i, s)
			}
		}
	}
	pa := &cs.ProxyAuth
	switch pa.DefaultRole {
	case "":
		pa.DefaultRole = "viewer"
	case "viewer", "none":
	default:
		return fmt.Errorf("config: console.proxy_auth.default_role must be \"viewer\" or \"none\"")
	}
	if pa.Header != "" && len(cs.TrustedProxies) == 0 {
		return fmt.Errorf("config: console.proxy_auth.header needs console.trusted_proxies — otherwise anyone who can reach the port could forge the identity header")
	}
	if pa.DisableLogin && pa.Header == "" {
		return fmt.Errorf("config: console.proxy_auth.disable_login needs console.proxy_auth.header (nobody could sign in)")
	}
	for name, oc := range map[string]*OAuthClient{"google": cs.OAuth.Google, "github": cs.OAuth.GitHub} {
		if oc == nil {
			continue
		}
		if oc.ClientID == "" || oc.ClientSecretEnv == "" {
			return fmt.Errorf("config: console.oauth.%s needs client_id and client_secret_env", name)
		}
		if oc.ClientSecret = c.getenv(oc.ClientSecretEnv); oc.ClientSecret == "" {
			return fmt.Errorf("config: console.oauth.%s.client_secret_env names %s, but that environment variable is empty", name, oc.ClientSecretEnv)
		}
		if cs.BaseURL == "" {
			return fmt.Errorf("config: console.oauth needs console.base_url (the providers redirect back to <base_url>/oauth/%s/callback)", name)
		}
	}
	return nil
}

// TrustedProxies returns console.trusted_proxies as prefixes.
func (c *Config) TrustedProxies() []netip.Prefix {
	var out []netip.Prefix
	for _, s := range c.Console.TrustedProxies {
		if p, err := netip.ParsePrefix(s); err == nil {
			out = append(out, p.Masked())
		} else if a, err := netip.ParseAddr(s); err == nil {
			out = append(out, netip.PrefixFrom(a, a.BitLen()))
		}
	}
	return out
}

// checkASNName validates one asn_names entry.
func checkASNName(k, v string) error {
	n, err := strconv.Atoi(strings.TrimPrefix(strings.ToUpper(k), "AS"))
	if err != nil || n <= 0 {
		return fmt.Errorf("%q is not an ASN", k)
	}
	if r := []rune(strings.TrimSpace(v)); len(r) == 0 || len(r) > 40 {
		return fmt.Errorf("name for %s must have 1–40 characters", k)
	}
	return nil
}

// ASNLabels returns the operator's short ASN names, by number.
func (c *Config) ASNLabels() map[int]string {
	out := map[int]string{}
	for k, v := range c.ASNNames {
		if n, err := strconv.Atoi(strings.TrimPrefix(strings.ToUpper(k), "AS")); err == nil && n > 0 {
			out[n] = strings.TrimSpace(v)
		}
	}
	return out
}
