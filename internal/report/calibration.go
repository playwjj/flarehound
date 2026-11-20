package report

import (
	"fmt"
	"strings"

	"github.com/playwjj/flarehound/internal/calibrate"
)

func (l lang) verdict(s calibrate.Summary) string {
	switch s.Verdict {
	case calibrate.AdaptiveHi:
		return l.t("FlareHound counts more than the dashboard: its adaptive data includes Worker subrequests and cache operations. Expected — compare alerts with alerts, never with the dashboard.",
			"FlareHound 计数高于面板：自适应数据含 Worker 子请求与缓存操作条目。属预期——告警只与告警比，不要与面板数字比。")
	case calibrate.AdaptiveLow:
		return l.t("FlareHound counts less than the dashboard — unusual. Heavy sampling or ingestion lag on recent days can cause it; re-run later, and treat small-volume findings with care.",
			"FlareHound 计数低于面板——不常见。可能是重采样或近期数据入库延迟；稍后重跑，并谨慎看待小量级结论。")
	case calibrate.Aligned:
		return l.t("The two agree within ±15%.", "两者相差在 ±15% 以内。")
	}
	return l.t("No data to compare.", "无可对照的数据。")
}

// calibrationLine is the daily report's one-liner.
func (l lang) calibrationLine(s calibrate.Summary) string {
	return fmt.Sprintf(l.t("counting basis: FlareHound counts about %.2f× the requests the Cloudflare dashboard shows (median of %d day(s); the two count differently, this is expected); the alert floor min_count %s ≈ %s dashboard requests.",
		"计数口径：FlareHound 统计的请求数约为 Cloudflare 面板的 %.2f 倍（%d 天中位数；两边统计方式不同，属正常）；报警门槛 min_count %s ≈ 面板 %s 次。"),
		s.Requests, len(s.Days), n(s.MinCountAdapt), n(s.MinCountDash))
}

// Calibration renders `flarehound calibrate`.
func Calibration(language, zone string, s calibrate.Summary) string {
	l := lang(language)
	var b strings.Builder
	fmt.Fprintf(&b, l.t("FlareHound · %s — calibration against the Cloudflare dashboard\n", "FlareHound · %s — 与 Cloudflare 面板口径校准\n"), zone)
	if s.Verdict == calibrate.NoData {
		b.WriteString(l.verdict(s))
		return b.String()
	}
	b.WriteString(l.t("Per UTC day (dashboard = httpRequests1dGroups; FlareHound = adaptive analytics):\n",
		"逐 UTC 日（面板 = httpRequests1dGroups；FlareHound = 自适应分析数据）：\n"))
	// ASCII headers keep the columns aligned in every language.
	fmt.Fprintf(&b, "%-10s  %12s %12s %6s  %10s %10s  %8s %8s  %s\n", "date", "dash req", "FH req", "ratio", "dash hit", "FH hit", "dash 5xx", "FH 5xx", "sampling")
	for _, d := range s.Days {
		r := "-"
		if d.DashRequests > 0 {
			r = fmt.Sprintf("%.2f", float64(d.AdRequests)/float64(d.DashRequests))
		}
		samp := "-"
		if d.SampleInterval > 0 {
			samp = fmt.Sprintf("1/%.2f", d.SampleInterval)
		}
		fmt.Fprintf(&b, "%-10s  %12s %12s %6s  %10s %10s  %8s %8s  %s\n", d.Date.Format("2006-01-02"),
			n(d.DashRequests), n(d.AdRequests), r, n(d.DashCached), n(d.AdCached), n(d.Dash5xx), n(d.Ad5xx), samp)
	}
	b.WriteString("\n")
	fmt.Fprintf(&b, l.t("Requests: FlareHound ≈ %.2f× dashboard (median)\n", "请求数：FlareHound ≈ 面板的 %.2f 倍（中位数）\n"), s.Requests)
	if s.HasCached {
		fmt.Fprintf(&b, l.t("Edge cache hits: ≈ %.2f×\n", "边缘缓存命中：≈ %.2f 倍\n"), s.Cached)
	}
	if s.Has5xx {
		fmt.Fprintf(&b, l.t("Edge 5xx: ≈ %.2f×\n", "边缘 5xx：≈ %.2f 倍\n"), s.Edge5xx)
		if s.Edge5xx > 1.5 {
			b.WriteString(l.t("  Edge 5xx run well above the dashboard: adaptive data also records cache operations (e.g. Cache API misses logged as 504). List known artifacts under daily.artifacts so they are reported apart from visitor errors.\n",
				"  边缘 5xx 明显高于面板：自适应数据也记录缓存操作条目（如 Cache API 未命中记为 504）。请把已知的记账假象配置到 daily.artifacts，与真实访客错误分开报。\n"))
		}
	}
	if s.SampleRate > 0 {
		fmt.Fprintf(&b, l.t("Sampling: about %.0f%% of requests are kept in adaptive data (counts are extrapolated)\n",
			"采样：自适应数据保留约 %.0f%% 的请求（计数为外推值）\n"), s.SampleRate*100)
	}
	fmt.Fprintf(&b, l.t("Thresholds are in FlareHound units: min_count %s ≈ %s requests as the dashboard counts them.\n",
		"阈值按 FlareHound 口径计：min_count %s ≈ 面板口径 %s 次。\n"), n(s.MinCountAdapt), n(s.MinCountDash))
	b.WriteString(l.verdict(s))
	return b.String()
}
