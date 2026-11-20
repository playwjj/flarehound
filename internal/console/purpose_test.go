package console

import (
	"context"
	"net/http"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/playwjj/flarehound/internal/cfapi"
)

const chrome157 = "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/157.0.0.0 Safari/537.36"

// purposeAnalytics adds the UA × network × verified-bot grouping.
type purposeAnalytics struct{ fakeAnalytics }

func (p *purposeAnalytics) Top(ctx context.Context, z string, from, to time.Time, dim string, n int, f cfapi.Filter) ([]cfapi.Face, error) {
	if dim != cfapi.DimUAASNBot {
		return p.fakeAnalytics.Top(ctx, z, from, to, dim, n, f)
	}
	rows := []cfapi.Face{
		{Name: chrome157, ASN: 45102, Count: 12000},
		{Name: "rednote-websearch-bot/1.0", ASN: 45102, Count: 180},
		{Name: "GPTBot/1.2", ASN: 8075, Cat: "AI Crawler", Count: 900},
	}
	var out []cfapi.Face
	for _, r := range rows {
		if (f.ASN == 0 || r.ASN == f.ASN) && (f.UserAgent == "" || r.Name == f.UserAgent) {
			out = append(out, r)
		}
	}
	return out, nil
}

func TestDrillPurpose(t *testing.T) {
	e := newWriteEnv(t, false)
	e.srv.Analytics = &purposeAnalytics{}
	_, body, _ := e.admin.do("GET", "/movers/drill?dim=asn&name=AS45102", nil, nil)
	for _, want := range []string{"Traffic by purpose", "undeclared automation", "Chrome/157.0.0.0 (X11; Linux x86_64) (12,000)", "fetch tools", "rednote-websearch-bot"} {
		if !strings.Contains(body, want) {
			t.Errorf("ASN drill lacks %q", want)
		}
	}
	_, body, _ = e.admin.do("GET", "/movers/drill?dim=ua&name=GPTBot%2F1.2", nil, nil)
	if !strings.Contains(body, `p-training`) || !strings.Contains(body, "OpenAI · verified") {
		t.Errorf("UA drill lacks the verified training label")
	}
	_, body, _ = e.admin.do("GET", "/movers/drill?dim=ua&name="+url.QueryEscape(chrome157), nil, nil)
	if !strings.Contains(body, "p-undeclared") || !strings.Contains(body, "by traits") {
		t.Errorf("UA drill lacks the undeclared label")
	}
}

// An override set in the console changes the badges and the filter,
// and is audited.
func TestPurposeOverride(t *testing.T) {
	e := settingsEnv(t)
	c := e.admin
	_, body, _ := c.do("GET", "/movers?dim=ua", nil, nil)
	if strings.Contains(body, "p-tool") {
		t.Fatal("badge before any override")
	}
	_, body, _ = c.do("GET", "/settings/asn", nil, nil)
	if !strings.Contains(body, "Traffic purposes") || !strings.Contains(body, "Built-in table") {
		t.Fatal("settings page lacks the purposes card")
	}
	code, _, h := c.do("POST", "/settings/purpose", url.Values{"csrf": {csrfOf(t, body)}, "ua": {"Crawler/1.0"}, "class": {"tool"}}, nil)
	if code != http.StatusSeeOther || !strings.Contains(h.Get("Location"), "ok=") {
		t.Fatalf("set: %d %s", code, h.Get("Location"))
	}
	if got := e.srv.eff().Purposes["Crawler/1.0"]; got != "tool" {
		t.Fatalf("override not in effect: %q", got)
	}
	_, body, _ = c.do("GET", "/movers?dim=ua&purpose=tool", nil, nil)
	if !strings.Contains(body, "p-tool") || !strings.Contains(body, "Crawler/1.0") || strings.Contains(body, ">Safari<") {
		t.Fatalf("filtered movers:\n%s", body)
	}
	log, _ := e.db.AuditLog(20)
	found := false
	for _, a := range log {
		if strings.Contains(a.Detail, "purposes") {
			found = true
		}
	}
	if !found {
		t.Errorf("override not audited: %+v", log)
	}
	// Bad class: refused.
	_, body, _ = c.do("GET", "/settings/asn", nil, nil)
	_, _, h = c.do("POST", "/settings/purpose", url.Values{"csrf": {csrfOf(t, body)}, "ua": {"Crawler/1.0"}, "class": {"weird"}}, nil)
	if !strings.Contains(h.Get("Location"), "unknown+purpose") && !strings.Contains(h.Get("Location"), "unknown%20purpose") {
		t.Errorf("bad class accepted: %s", h.Get("Location"))
	}
}
