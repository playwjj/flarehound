package config

// Console-managed settings (v1.9). config.json stays the base and may be
// read-only (docker-compose mounts it :ro); what admins change in the
// console is kept in an overlay file next to the state file
// (<data dir>/settings.json) and applied on top at every load. The watch
// re-reads it before each round, so changes need no restart.
//
// The overlay never holds a secret: notification secrets stay in
// environment variables, and the overlay can only name those variables
// or set non-secret parameters (chat id, SMTP host, recipients …).

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"time"
)

// OverlayFile is the overlay's file name in the data directory.
const OverlayFile = "settings.json"

// Channel names, as the console and the heartbeat use them.
const (
	ChanWebhook  = "webhook"
	ChanTelegram = "telegram"
	ChanJSONL    = "jsonl"
	ChanSlack    = "slack"
	ChanDiscord  = "discord"
	ChanWeCom    = "wecom"
	ChanFeishu   = "feishu"
	ChanEmail    = "email"
)

// AllChannels lists the channels in display order.
func AllChannels() []string {
	return []string{ChanTelegram, ChanSlack, ChanDiscord, ChanWeCom, ChanFeishu, ChanEmail, ChanWebhook, ChanJSONL}
}

// NotifyStringFields are the notify fields the overlay may set, by JSON
// name: names of environment variables and non-secret parameters.
var NotifyStringFields = []string{
	"telegram_bot_token_env", "telegram_chat_id",
	"slack_webhook_url_env", "discord_webhook_url_env", "wecom_webhook_url_env",
	"feishu_webhook_url_env", "feishu_secret_env",
	"webhook_url_env", "jsonl_file", "heartbeat_url_env",
}

// Overlay is the console-managed layer. Nil / empty parts leave the base
// configuration as it is.
type Overlay struct {
	Version   int       `json:"version"`
	UpdatedAt time.Time `json:"updated_at"`
	UpdatedBy string    `json:"updated_by"`

	// Notify sets notify fields (NotifyStringFields), by JSON name.
	Notify map[string]string `json:"notify,omitempty"`
	// Email replaces notify.email (the password stays in its env var).
	Email *EmailConfig `json:"email,omitempty"`
	// Disabled channels are turned off whatever the base config says.
	Disabled []string `json:"disabled_channels,omitempty"`
	// Thresholds replaces the alert lines as a whole.
	Thresholds *Thresholds `json:"thresholds,omitempty"`
	// KnownFaces adds to known_faces (the base entries always stay).
	KnownASNs []int    `json:"known_asns,omitempty"`
	KnownUAs  []string `json:"known_user_agents,omitempty"`
	// ASNNames sets short names for networks (on top of asn_names).
	ASNNames map[string]string `json:"asn_names,omitempty"`
}

// Empty reports whether the overlay changes nothing.
func (o *Overlay) Empty() bool {
	return o == nil || (len(o.Notify) == 0 && o.Email == nil && len(o.Disabled) == 0 && o.Thresholds == nil &&
		len(o.KnownASNs) == 0 && len(o.KnownUAs) == 0 && len(o.ASNNames) == 0)
}

// IsDisabled reports whether a channel is turned off by the overlay.
func (o *Overlay) IsDisabled(ch string) bool {
	if o == nil {
		return false
	}
	for _, d := range o.Disabled {
		if d == ch {
			return true
		}
	}
	return false
}

// ReadOverlay reads the overlay file; a missing file is an empty overlay.
func ReadOverlay(path string) (*Overlay, error) {
	raw, err := os.ReadFile(path)
	if errors.Is(err, os.ErrNotExist) {
		return &Overlay{}, nil
	}
	if err != nil {
		return nil, err
	}
	var o Overlay
	if err := json.Unmarshal(raw, &o); err != nil {
		return nil, fmt.Errorf("%s: %w", path, err)
	}
	return &o, nil
}

// WriteOverlay writes the overlay atomically (temp file + rename) and
// keeps the previous version under settings-history/ for rollback.
func WriteOverlay(path string, o *Overlay) error {
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return err
	}
	hist := filepath.Join(filepath.Dir(path), "settings-history")
	if old, err := os.ReadFile(path); err == nil {
		var prev Overlay
		if json.Unmarshal(old, &prev) == nil {
			if err := os.MkdirAll(hist, 0o755); err == nil {
				_ = os.WriteFile(filepath.Join(hist, fmt.Sprintf("settings-v%d.json", prev.Version)), old, 0o644)
			}
		}
	} else if errors.Is(err, os.ErrNotExist) {
		// The first change: keep "no console settings" as v0, so the
		// history can always go back to config.json alone.
		if err := os.MkdirAll(hist, 0o755); err == nil {
			_ = os.WriteFile(filepath.Join(hist, "settings-v0.json"), []byte("{\n  \"version\": 0\n}\n"), 0o644)
		}
	}
	raw, err := json.MarshalIndent(o, "", "  ")
	if err != nil {
		return err
	}
	tmp, err := os.CreateTemp(filepath.Dir(path), ".settings-*.json")
	if err != nil {
		return err
	}
	if _, err := tmp.Write(append(raw, '\n')); err != nil {
		tmp.Close()
		os.Remove(tmp.Name())
		return err
	}
	if err := tmp.Close(); err != nil {
		os.Remove(tmp.Name())
		return err
	}
	_ = os.Chmod(tmp.Name(), 0o644)
	return os.Rename(tmp.Name(), path)
}

// OverlayHistory lists the kept previous versions, newest first.
func OverlayHistory(path string) ([]int, error) {
	files, err := filepath.Glob(filepath.Join(filepath.Dir(path), "settings-history", "settings-v*.json"))
	if err != nil {
		return nil, err
	}
	var out []int
	for _, f := range files {
		var v int
		if _, err := fmt.Sscanf(filepath.Base(f), "settings-v%d.json", &v); err == nil {
			out = append(out, v)
		}
	}
	sort.Sort(sort.Reverse(sort.IntSlice(out)))
	return out, nil
}

// ReadOverlayVersion reads a kept previous version.
func ReadOverlayVersion(path string, v int) (*Overlay, error) {
	return ReadOverlay(filepath.Join(filepath.Dir(path), "settings-history", fmt.Sprintf("settings-v%d.json", v)))
}

func setNotifyField(n *Notify, name, v string) bool {
	switch name {
	case "telegram_bot_token_env":
		n.TelegramBotTokenEnv = v
	case "telegram_chat_id":
		n.TelegramChatID = v
	case "slack_webhook_url_env":
		n.SlackWebhookURLEnv = v
	case "discord_webhook_url_env":
		n.DiscordWebhookURLEnv = v
	case "wecom_webhook_url_env":
		n.WeComWebhookURLEnv = v
	case "feishu_webhook_url_env":
		n.FeishuWebhookURLEnv = v
	case "feishu_secret_env":
		n.FeishuSecretEnv = v
	case "webhook_url_env":
		n.WebhookURLEnv = v
	case "jsonl_file":
		n.JSONLFile = v
	case "heartbeat_url_env":
		n.HeartbeatURLEnv = v
	default:
		return false
	}
	return true
}

// NotifyField reads a notify field by JSON name.
func NotifyField(n Notify, name string) string {
	switch name {
	case "telegram_bot_token_env":
		return n.TelegramBotTokenEnv
	case "telegram_chat_id":
		return n.TelegramChatID
	case "slack_webhook_url_env":
		return n.SlackWebhookURLEnv
	case "discord_webhook_url_env":
		return n.DiscordWebhookURLEnv
	case "wecom_webhook_url_env":
		return n.WeComWebhookURLEnv
	case "feishu_webhook_url_env":
		return n.FeishuWebhookURLEnv
	case "feishu_secret_env":
		return n.FeishuSecretEnv
	case "webhook_url_env":
		return n.WebhookURLEnv
	case "jsonl_file":
		return n.JSONLFile
	case "heartbeat_url_env":
		return n.HeartbeatURLEnv
	}
	return ""
}

// apply puts the overlay on top of a freshly parsed (not yet resolved)
// configuration.
func (c *Config) apply(o *Overlay) error {
	if o == nil {
		return nil
	}
	for k, v := range o.Notify {
		if !setNotifyField(&c.Notify, k, strings.TrimSpace(v)) {
			return fmt.Errorf("settings: unknown notify field %q", k)
		}
	}
	if o.Email != nil {
		e := *o.Email
		c.Notify.Email = &e
	}
	for _, d := range o.Disabled {
		switch d {
		case ChanTelegram:
			c.Notify.TelegramChatID = ""
		case ChanSlack:
			c.Notify.SlackWebhookURLEnv = ""
		case ChanDiscord:
			c.Notify.DiscordWebhookURLEnv = ""
		case ChanWeCom:
			c.Notify.WeComWebhookURLEnv = ""
		case ChanFeishu:
			c.Notify.FeishuWebhookURLEnv, c.Notify.FeishuSecretEnv = "", ""
		case ChanEmail:
			c.Notify.Email = nil
		case ChanWebhook:
			c.Notify.WebhookURL, c.Notify.WebhookURLEnv = "", ""
		case ChanJSONL:
			c.Notify.JSONLFile = ""
		default:
			return fmt.Errorf("settings: unknown channel %q", d)
		}
	}
	if o.Thresholds != nil {
		c.Thresholds = *o.Thresholds
	}
	seenA := map[int]bool{}
	for _, a := range c.KnownFaces.ASNs {
		seenA[a] = true
	}
	for _, a := range o.KnownASNs {
		if !seenA[a] {
			c.KnownFaces.ASNs = append(c.KnownFaces.ASNs, a)
			seenA[a] = true
		}
	}
	seenU := map[string]bool{}
	for _, u := range c.KnownFaces.UserAgents {
		seenU[strings.ToLower(u)] = true
	}
	for _, u := range o.KnownUAs {
		if u = strings.TrimSpace(u); u != "" && !seenU[strings.ToLower(u)] {
			c.KnownFaces.UserAgents = append(c.KnownFaces.UserAgents, u)
			seenU[strings.ToLower(u)] = true
		}
	}
	for k, v := range o.ASNNames {
		if err := checkASNName(k, v); err != nil {
			return fmt.Errorf("settings: asn_names: %w", err)
		}
		if c.ASNNames == nil {
			c.ASNNames = map[string]string{}
		}
		n, _ := strconv.Atoi(strings.TrimPrefix(strings.ToUpper(k), "AS"))
		c.ASNNames[strconv.Itoa(n)] = strings.TrimSpace(v)
	}
	c.Overlay = o
	return nil
}

// CheckThresholds validates alert lines (also used before saving them).
func CheckThresholds(t Thresholds) error {
	for name, v := range map[string]float64{"total_up_pct": t.TotalUpPct, "worker_calls_up_pct": t.WorkerCallsUpPct,
		"cpu_p50_up_pct": t.CPUP50UpPct, "dynamic_up_pct": t.DynamicUpPct, "escalation_pct": t.EscalationPct} {
		if v < 1 || v > 10000 {
			return fmt.Errorf("thresholds.%s must be within 1..10000 (%%)", name)
		}
	}
	if t.CollapseDownPct < 1 || t.CollapseDownPct > 100 {
		return fmt.Errorf("thresholds.collapse_down_pct must be within 1..100 (%%)")
	}
	if t.Origin5xxMultiple < 1 || t.Origin5xxMultiple > 1000 {
		return fmt.Errorf("thresholds.origin_5xx_multiplier must be within 1..1000")
	}
	for name, v := range map[string]int64{"origin_5xx_min": t.Origin5xxMin, "new_face_min_count": t.NewFaceMinCount, "min_count": t.MinCount} {
		if v < 0 || v > 1_000_000_000 {
			return fmt.Errorf("thresholds.%s must be within 0..1e9", name)
		}
	}
	if t.RecoveryCleanRound < 1 || t.RecoveryCleanRound > 24 {
		return fmt.Errorf("thresholds.recovery_clean_rounds must be within 1..24")
	}
	return nil
}

// ChannelInfo is one notification channel as this process sees it.
type ChannelInfo struct {
	Name       string   `json:"name"`
	Configured bool     `json:"configured"` // will be used to send
	Disabled   bool     `json:"disabled"`   // turned off in the console
	Envs       []string `json:"envs,omitempty"`
	Missing    []string `json:"missing,omitempty"` // referenced variables that are empty here
	Note       string   `json:"note,omitempty"`
}

// Channels reports every channel: configured or not, which environment
// variables it references and which of them are empty in this process.
// Values are never reported.
func (c *Config) Channels() []ChannelInfo {
	n := c.Notify
	env := c.getenv
	if env == nil {
		env = os.Getenv
	}
	info := func(name string, need []string, configured bool, note string) ChannelInfo {
		ci := ChannelInfo{Name: name, Disabled: c.Overlay.IsDisabled(name), Note: note}
		for _, e := range need {
			if e == "" {
				continue
			}
			ci.Envs = append(ci.Envs, e)
			if env(e) == "" {
				ci.Missing = append(ci.Missing, e)
			}
		}
		ci.Configured = configured && len(ci.Missing) == 0 && !ci.Disabled
		return ci
	}
	var out []ChannelInfo
	out = append(out, info(ChanTelegram, []string{n.TelegramBotTokenEnv}, n.TelegramBotTokenEnv != "" && n.TelegramChatID != "",
		map[bool]string{true: "", false: "needs telegram_bot_token_env and telegram_chat_id"}[n.TelegramBotTokenEnv != "" && n.TelegramChatID != ""]))
	out = append(out, info(ChanSlack, []string{n.SlackWebhookURLEnv}, n.SlackWebhookURLEnv != "", ""))
	out = append(out, info(ChanDiscord, []string{n.DiscordWebhookURLEnv}, n.DiscordWebhookURLEnv != "", ""))
	out = append(out, info(ChanWeCom, []string{n.WeComWebhookURLEnv}, n.WeComWebhookURLEnv != "", ""))
	out = append(out, info(ChanFeishu, []string{n.FeishuWebhookURLEnv, n.FeishuSecretEnv}, n.FeishuWebhookURLEnv != "", ""))
	if e := n.Email; e != nil {
		pw := ""
		if e.Username != "" {
			pw = e.PasswordEnv
		}
		out = append(out, info(ChanEmail, []string{pw}, true, ""))
	} else {
		out = append(out, info(ChanEmail, nil, false, ""))
	}
	out = append(out, info(ChanWebhook, []string{n.WebhookURLEnv}, n.WebhookURLEnv != "" || n.WebhookURL != "", ""))
	out = append(out, info(ChanJSONL, nil, n.JSONLFile != "", n.JSONLFile))
	return out
}
