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

// starngage, 2026-11-19 13:37: 83 edge 52x in the live hour, all 522/524,
// against a ~460/h background — the tile read red. It is bookkeeping.
func TestUnreachableTileBookkeeping(t *testing.T) {
	cfg := &config.Config{Thresholds: config.DefaultThresholds()}
	zone := config.Zone{Name: "starngage.com"}
	base := analyze.Metrics{Origin5xx: 3, Unreachable: 460, UnreachableBy: map[string]int64{"522": 220, "524": 240},
		Origin: &analyze.OriginMetrics{Requests: 17_000, TTFBP95ms: 800, TotalP95ms: 1100}}
	cur := analyze.Metrics{Origin5xx: 2, Unreachable: 83, UnreachableBy: map[string]int64{"522": 40, "524": 43},
		Origin: &analyze.OriginMetrics{Requests: 3_000, TTFBP95ms: 818, TotalP95ms: 1145}}
	// cur is a partial (live) hour: compare like the live view does, with
	// origin requests in proportion.
	cur.Origin.Requests = 16_000
	r := rowKeys(metricRows(cfg, zone, cur, base, true))["m_unreachable_book"]
	if r.Status != StatusBook || r.Cur != 83 {
		t.Fatalf("bookkeeping tile: %+v", r)
	}
	// A real outage on the same zone: 521 appears, the origin stops answering.
	down := analyze.Metrics{Unreachable: 1_900, UnreachableBy: map[string]int64{"522": 300, "524": 200, "521": 1_400},
		Origin: &analyze.OriginMetrics{Requests: 4_000, TTFBP95ms: 900, TotalP95ms: 1200}}
	if r := rowKeys(metricRows(cfg, zone, down, base, true))["m_unreachable"]; r.Status != StatusAlert {
		t.Fatalf("outage tile: %+v", r)
	}
	// skoolopedia: 530-led trickle keeps the plain reading (not bookkeeping).
	sk := analyze.Metrics{Unreachable: 18, UnreachableBy: map[string]int64{"530": 18}, Origin: &analyze.OriginMetrics{Requests: 500}}
	skBase := analyze.Metrics{Unreachable: 15, UnreachableBy: map[string]int64{"530": 15}, Origin: &analyze.OriginMetrics{Requests: 500}}
	if rs := rowKeys(metricRows(cfg, zone, sk, skBase, true)); rs["m_unreachable"].Status != StatusWatch {
		t.Fatalf("530 trickle: %+v", rs)
	}
}
