package config

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func write(t *testing.T, body string) string {
	t.Helper()
	p := filepath.Join(t.TempDir(), "config.json")
	if err := os.WriteFile(p, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	return p
}

var zone = `{"zone_id":"` + strings.Repeat("a", 32) + `","name":"example.com"}`

func TestDefaultsApplied(t *testing.T) {
	t.Setenv("CF_API_TOKEN", "tok")
	c, err := Load(write(t, `{"cloudflare":{"zones":[`+zone+`]},"thresholds":{"total_up_pct":50}}`))
	if err != nil {
		t.Fatal(err)
	}
	if c.Thresholds.TotalUpPct != 50 {
		t.Error("explicit threshold lost")
	}
	if c.Thresholds.WorkerCallsUpPct != 35 || c.Thresholds.RecoveryCleanRound != 2 || c.Thresholds.MinCount != 1000 {
		t.Errorf("omitted thresholds must default, got %+v", c.Thresholds)
	}
	if c.IntradayOffset().Minutes() != 7 || c.Report.Language != "en" || c.Location == nil {
		t.Error("schedule/report defaults")
	}
}

func TestSecretsFromEnvOnly(t *testing.T) {
	t.Setenv("CF_API_TOKEN", "")
	if _, err := Load(write(t, `{"cloudflare":{"zones":[`+zone+`]}}`)); err == nil {
		t.Fatal("missing token accepted")
	}
	t.Setenv("CF_API_TOKEN", "tok")
	t.Setenv("HOOK", "https://hooks.example/secret")
	c, err := Load(write(t, `{"cloudflare":{"zones":[`+zone+`]},"notify":{"webhook_url_env":"HOOK"}}`))
	if err != nil || c.WebhookURL != "https://hooks.example/secret" {
		t.Fatalf("webhook from env: %v %q", err, c.WebhookURL)
	}
}

func TestValidation(t *testing.T) {
	t.Setenv("CF_API_TOKEN", "tok")
	for name, body := range map[string]string{
		"bad zone id":     `{"cloudflare":{"zones":[{"zone_id":"x\"}"}]}}`,
		"workers no acct": `{"cloudflare":{"zones":[{"zone_id":"` + strings.Repeat("a", 32) + `","workers":["w"]}]}}`,
		"bad interval":    `{"cloudflare":{"zones":[` + zone + `]},"schedule":{"intraday_interval":"30m"}}`,
		"bad hhmm":        `{"cloudflare":{"zones":[` + zone + `]},"schedule":{"daily_report_at":"8am"}}`,
		"bad tz":          `{"cloudflare":{"zones":[` + zone + `]},"schedule":{"timezone":"Mars/Base"}}`,
		"bad lang":        `{"cloudflare":{"zones":[` + zone + `]},"report":{"language":"fr"}}`,
		"bad path":        `{"cloudflare":{"zones":[` + zone + `]},"path_rules":[{"path":"login"}]}`,
		"foreign host":    `{"cloudflare":{"zones":[{"zone_id":"` + strings.Repeat("a", 32) + `","name":"example.com","waf_audit":{"hosts":["www.other.org"]}}]}}`,
		"zone path":       `{"cloudflare":{"zones":[{"zone_id":"` + strings.Repeat("a", 32) + `","name":"example.com","waf_audit":{"sensitive_paths":["wp-admin"]}}]}}`,
	} {
		if _, err := Load(write(t, body)); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
}

func TestExampleConfigLoads(t *testing.T) {
	t.Setenv("CF_API_TOKEN", "tok")
	raw, err := os.ReadFile("../../config.example.json")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := Load(write(t, string(raw))); err != nil {
		t.Fatalf("config.example.json must load: %v", err)
	}
}

func TestChannelSecrets(t *testing.T) {
	t.Setenv("CF_API_TOKEN", "tok")
	t.Setenv("DISCORD_URL", "https://discord.example/api/webhooks/1/secret")
	c, err := Load(write(t, `{"cloudflare":{"zones":[`+zone+`]},"notify":{"discord_webhook_url_env":"DISCORD_URL"}}`))
	if err != nil || c.Chan.Discord == "" {
		t.Fatalf("%v %+v", err, c)
	}
	found := false
	for _, s := range c.Secrets() {
		if s == c.Chan.Discord {
			found = true
		}
	}
	if !found {
		t.Fatal("channel URL must be redacted from logs")
	}
	if _, err := Load(write(t, `{"cloudflare":{"zones":[`+zone+`]},"notify":{"slack_webhook_url_env":"NOPE_UNSET"}}`)); err == nil {
		t.Fatal("named but empty env var accepted")
	}
	if _, err := Load(write(t, `{"cloudflare":{"zones":[`+zone+`]},"notify":{"email":{"smtp_host":"h","from":"a@b","to":["c@d"],"username":"u"}}}`)); err == nil {
		t.Fatal("email username without password accepted")
	}
}

func TestZoneAudit(t *testing.T) {
	t.Setenv("CF_API_TOKEN", "tok")
	c, err := Load(write(t, `{"cloudflare":{"zones":[{"zone_id":"`+strings.Repeat("a", 32)+`","name":"example.com","waf_audit":{"hosts":["www.example.com"],"sensitive_paths":[]}}]}}`))
	if err != nil {
		t.Fatal(err)
	}
	a := c.Cloudflare.Zones[0].WAFAudit
	if a == nil || a.SensitivePaths == nil || len(a.SensitivePaths) != 0 {
		t.Fatalf("explicit empty list must stay set: %+v", a)
	}
	for h, want := range map[string]bool{"example.com": true, "WWW.Example.com.": true, "*.example.com": true, "badexample.com": false, "example.com.evil.org": false} {
		if HostInZone(h, "example.com") != want {
			t.Errorf("HostInZone(%q) != %v", h, want)
		}
	}
}
