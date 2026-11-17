// Package report renders findings into the short, conclusion-first
// message format defined in SPEC.md section 11.
package report

import (
	"fmt"
	"strings"

	"github.com/playwjj/flarehound/internal/analyze"
	"github.com/playwjj/flarehound/internal/state"
)

// Render builds the notification text for one zone check. decision is
// the state machine's verdict; recovered renders as a single line.
func Render(decision state.Decision, zoneName string, cur, base analyze.Metrics, findings []analyze.Finding) string {
	if decision == state.DecRecovered {
		return fmt.Sprintf("FlareHound: %s recovered — traffic back to baseline.", zoneName)
	}
	head := "anomaly detected"
	if decision == state.DecEscalate {
		head = "anomaly ESCALATED"
	}
	var b strings.Builder
	fmt.Fprintf(&b, "FlareHound: %s on %s\n", head, zoneName)
	fmt.Fprintf(&b, "- zone requests: %d (%+.1f%% vs yesterday)\n", cur.Total, analyze.PctChange(float64(cur.Total), float64(base.Total)))
	fmt.Fprintf(&b, "- worker calls: %d (%+.1f%%)\n", cur.WorkerCalls, analyze.PctChange(float64(cur.WorkerCalls), float64(base.WorkerCalls)))
	fmt.Fprintf(&b, "- worker CPU P50: %.1f ms (%+.1f%%)\n", cur.CPUP50ms, analyze.PctChange(cur.CPUP50ms, base.CPUP50ms))
	fmt.Fprintf(&b, "- dynamic responses: %d (%+.1f%%)\n", cur.Dynamic, analyze.PctChange(float64(cur.Dynamic), float64(base.Dynamic)))
	fmt.Fprintf(&b, "- origin 5xx: %d (baseline %d)\n", cur.Origin5xx, base.Origin5xx)
	b.WriteString("Findings:\n")
	for _, f := range findings {
		fmt.Fprintf(&b, "  * %s\n", f.Summary)
	}
	return strings.TrimRight(b.String(), "\n")
}
