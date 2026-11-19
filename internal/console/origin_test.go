package console

import (
	"testing"

	"github.com/playwjj/flarehound/internal/analyze"
	"github.com/playwjj/flarehound/internal/config"
)

func rowKeys(rs []MetricRow) map[string]MetricRow {
	m := map[string]MetricRow{}
	for _, r := range rs {
		m[r.Key] = r
	}
	return m
}

func TestOriginRowsFoldAndAlert(t *testing.T) {
	cfg := &config.Config{Thresholds: config.DefaultThresholds()}
	zone := config.Zone{Name: "x"}
	// A zone the edge serves (Worker / cache): no origin tiles at all.
	edge := analyze.Metrics{Total: 10000, Origin: &analyze.OriginMetrics{Requests: 20, TTFBP95ms: 5}}
	if rs := rowKeys(metricRows(cfg, zone, edge, edge, true)); len(rs) != 3 {
		t.Fatalf("edge-served zone must fold the origin tiles: %v", rs)
	}
	// A VPS zone, slow and with 52x.
	base := analyze.Metrics{Origin5xx: 5, Origin: &analyze.OriginMetrics{Requests: 5000, TTFBP95ms: 464, TotalP95ms: 803}}
	cur := analyze.Metrics{Origin5xx: 50, Unreachable: 30, Origin: &analyze.OriginMetrics{Requests: 5000, TTFBP95ms: 1500, TotalP95ms: 1700}}
	rs := rowKeys(metricRows(cfg, zone, cur, base, true))
	if rs["m_unreachable"].Status != StatusAlert || rs["m_origin_ttfb"].Status != StatusAlert || rs["m_origin_ttfb"].Unit != "ms" {
		t.Fatalf("%+v", rs)
	}
	if rs["m_origin5xx"].Subject != "1.0%" {
		t.Fatalf("5xx rate: %q", rs["m_origin5xx"].Subject)
	}
	// Older archived baseline without origin data: shown, but no baseline.
	rs = rowKeys(metricRows(cfg, zone, cur, analyze.Metrics{}, true))
	if r := rs["m_origin_ttfb"]; r.HasBase || r.Status != StatusNA {
		t.Fatalf("no baseline latency must read n/a: %+v", r)
	}
}
