// Package config loads FlareHound's JSON configuration.
//
// The API token is never stored in the config file: the file only names the
// environment variable that carries it (see SPEC.md, security model).
package config

import (
	"encoding/json"
	"fmt"
	"os"
	"time"
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
	EscalationPct      float64 `json:"escalation_pct"`
	RecoveryCleanRound int     `json:"recovery_clean_rounds"`
}

type Notify struct {
	WebhookURL          string `json:"webhook_url"`
	TelegramBotTokenEnv string `json:"telegram_bot_token_env"`
	TelegramChatID      string `json:"telegram_chat_id"`
}

type Config struct {
	Cloudflare struct {
		AccountID   string `json:"account_id"`
		APITokenEnv string `json:"api_token_env"`
		Zones       []Zone `json:"zones"`
	} `json:"cloudflare"`
	Schedule struct {
		IntradayInterval string `json:"intraday_interval"`
		DailyReportAt    string `json:"daily_report_at"`
		Timezone         string `json:"timezone"`
	} `json:"schedule"`
	Thresholds Thresholds `json:"thresholds"`
	Notify     Notify     `json:"notify"`
	StateFile  string     `json:"state_file"`

	// APIToken is resolved from the environment at load time; never persisted.
	APIToken string `json:"-"`
	// TelegramBotToken likewise, when configured.
	TelegramBotToken string `json:"-"`
}

// Load reads and validates the config file at path, then resolves secrets
// from the environment.
func Load(path string) (*Config, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var c Config
	if err := json.Unmarshal(raw, &c); err != nil {
		return nil, fmt.Errorf("parse config: %w", err)
	}
	if c.Cloudflare.APITokenEnv == "" {
		c.Cloudflare.APITokenEnv = "CF_API_TOKEN"
	}
	c.APIToken = os.Getenv(c.Cloudflare.APITokenEnv)
	if c.APIToken == "" {
		return nil, fmt.Errorf("environment variable %s is empty: a read-only Cloudflare API token is required", c.Cloudflare.APITokenEnv)
	}
	if c.Notify.TelegramBotTokenEnv != "" {
		c.TelegramBotToken = os.Getenv(c.Notify.TelegramBotTokenEnv)
	}
	if len(c.Cloudflare.Zones) == 0 {
		return nil, fmt.Errorf("config: at least one zone is required")
	}
	if c.StateFile == "" {
		c.StateFile = "data/state.json"
	}
	return &c, nil
}

// IntradayInterval parses the configured interval, defaulting to 1h.
func (c *Config) IntradayInterval() time.Duration {
	d, err := time.ParseDuration(c.Schedule.IntradayInterval)
	if err != nil || d <= 0 {
		return time.Hour
	}
	return d
}
