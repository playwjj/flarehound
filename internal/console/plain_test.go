package console

import (
	"strings"
	"testing"
)

// The console's Chinese strings use the same plain vocabulary as the
// notifications (docs/reports.md, "How a message reads"). The rule
// simulator (sim_*) keeps its own terms for now: they are shared with
// the CLI and its documentation.
func TestConsoleSpeaksPlainly(t *testing.T) {
	jargon := []string{"越线", "超线", "基线", "面孔", "记账底量", "落定", "dynamic", "归档", "辨伪"}
	for k, v := range dict {
		if strings.HasPrefix(k, "sim_") {
			continue
		}
		for _, j := range jargon {
			if strings.Contains(v[1], j) {
				t.Errorf("%s says %q: %s", k, j, v[1])
			}
		}
	}
}
