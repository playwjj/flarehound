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
	Report    struct {
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
	return []string{c.APIToken, c.TelegramBotToken, c.WebhookURL,
		c.Chan.Slack, c.Chan.Discord, c.Chan.WeCom, c.Chan.Feishu, c.Chan.FeishuSecret, c.Chan.EmailPassword, c.HeartbeatURL}
}

var hhmm = regexp.MustCompile(`^([01]\d|2[0-3]):[0-5]\d$`)
var tag = regexp.MustCompile(`^[0-9a-f]{32}$`)

// Load reads and validates the config file at path, then resolves secrets
// from the environment. Fields absent from the file keep their defaults.
func Load(path string) (*Config, error) {
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
	if err := c.resolve(); err != nil {
		return nil, err
	}
	return &c, nil
}

func (c *Config) resolve() error {
	if c.Cloudflare.APITokenEnv == "" {
		c.Cloudflare.APITokenEnv = "CF_API_TOKEN"
	}
	c.APIToken = os.Getenv(c.Cloudflare.APITokenEnv)
	if c.APIToken == "" {
		return fmt.Errorf("environment variable %s is empty: a read-only Cloudflare API token is required", c.Cloudflare.APITokenEnv)
	}
	if c.Notify.TelegramBotTokenEnv != "" {
		c.TelegramBotToken = os.Getenv(c.Notify.TelegramBotTokenEnv)
	}
	c.WebhookURL = c.Notify.WebhookURL
	if c.Notify.WebhookURLEnv != "" {
		c.WebhookURL = os.Getenv(c.Notify.WebhookURLEnv)
	}
	env := func(name string) string {
		if name == "" {
			return ""
		}
		return os.Getenv(name)
	}
	n := c.Notify
	c.Chan = Channels{Slack: env(n.SlackWebhookURLEnv), Discord: env(n.DiscordWebhookURLEnv), WeCom: env(n.WeComWebhookURLEnv),
		Feishu: env(n.FeishuWebhookURLEnv), FeishuSecret: env(n.FeishuSecretEnv)}
	for name, v := range map[string]string{"slack_webhook_url_env": n.SlackWebhookURLEnv, "discord_webhook_url_env": n.DiscordWebhookURLEnv,
		"wecom_webhook_url_env": n.WeComWebhookURLEnv, "feishu_webhook_url_env": n.FeishuWebhookURLEnv} {
		if v != "" && os.Getenv(v) == "" {
			return fmt.Errorf("config: notify.%s names %s, but that environment variable is empty", name, v)
		}
	}
	if n.HeartbeatURLEnv != "" {
		if c.HeartbeatURL = os.Getenv(n.HeartbeatURLEnv); c.HeartbeatURL == "" {
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
			if c.Chan.EmailPassword == "" {
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
	if c.Archive.File == "" {
		c.Archive.File = filepath.Join(c.DataDir(), "archive.db")
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
