package console

import (
	"strings"
	"testing"
)

// The console's Chinese strings use the same plain vocabulary as the
// notifications (docs/reports.md, "How a message reads"), the rule
// simulator included.
func TestConsoleSpeaksPlainly(t *testing.T) {
	jargon := []string{"越线", "超线", "基线", "面孔", "记账底量", "落定", "dynamic", "归档", "辨伪", "毛命中", "净新增", "上界", "下界", "豁免", "不可评估"}
	for k, v := range dict {
		for _, j := range jargon {
			if strings.Contains(v[1], j) {
				t.Errorf("%s says %q: %s", k, j, v[1])
			}
		}
	}
}
