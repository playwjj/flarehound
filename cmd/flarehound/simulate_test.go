package main

import (
	"bytes"
	"context"
	"strings"
	"testing"
	"time"

	"github.com/playwjj/flarehound/internal/cfapi"
	"github.com/playwjj/flarehound/internal/config"
)

type simAPI struct{ asn bool }

func (s simAPI) Count(_ context.Context, _ string, _, _ time.Time, f cfapi.Filter) (int64, error) {
	if strings.Contains(f.Where, "clientAsn") {
		return 1_000, nil
	}
	return 1_000_000, nil
}
func (simAPI) Top(context.Context, string, time.Time, time.Time, string, int, cfapi.Filter) ([]cfapi.Face, error) {
	return nil, nil
}
func (simAPI) Hourly(context.Context, string, time.Time, time.Time, cfapi.Filter) (map[time.Time]int64, error) {
	return nil, nil
}
func (simAPI) FirewallGroups(context.Context, string, time.Time, time.Time, string, int, cfapi.Filter) ([]cfapi.Face, error) {
	return nil, nil
}
func (s simAPI) Capabilities(context.Context, string) (cfapi.Caps, error) {
	f := map[string]bool{"dimensions_userAgent": true, "dimensions_verifiedBotCategory": true}
	if s.asn {
		f["dimensions_clientAsn"] = true
	}
	return cfapi.Caps{Probed: true, HTTPFields: f}, nil
}

func TestSimulateCommand(t *testing.T) {
	cfg := &config.Config{}
	cfg.Report.Language = "zh"
	cfg.Location = time.UTC
	z := config.Zone{Name: "skoolopedia.com", ZoneID: "z"}
	now := time.Date(2026, 11, 20, 10, 0, 0, 0, time.UTC)
	var out bytes.Buffer
	code := simulate(context.Background(), cfg, z, nil, simAPI{}, nil, simArgs{expr: "ip.geoip.asnum eq 45102", days: 7}, &out, now)
	if code != 0 || !strings.Contains(out.String(), "该区无 ASN 维度（clientAsn），不可评估") || strings.Contains(out.String(), "毛命中") {
		t.Fatalf("free zone: %d\n%s", code, out.String())
	}
	out.Reset()
	code = simulate(context.Background(), cfg, z, nil, simAPI{asn: true}, nil, simArgs{expr: "ip.geoip.asnum eq 45102", date: "2026-11-19"}, &out, now)
	if code != 0 || !strings.Contains(out.String(), "2026-11-19 00:00 → 2026-11-20 00:00") || !strings.Contains(out.String(), "规则命中") {
		t.Fatalf("date window: %d\n%s", code, out.String())
	}
	if code := simulate(context.Background(), cfg, z, nil, simAPI{}, nil, simArgs{expr: "(a eq", days: 7}, &out, now); code != 2 {
		t.Fatalf("parse error: exit %d", code)
	}
	if code := simulate(context.Background(), cfg, z, nil, simAPI{}, nil, simArgs{expr: "ip.src eq 1.2.3.4", days: 3}, &out, now); code != 2 {
		t.Fatalf("--days 3: exit %d", code)
	}
}
