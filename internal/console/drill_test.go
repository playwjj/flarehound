package console

import (
	"strings"
	"testing"
)

func TestIPHint(t *testing.T) {
	for _, c := range []struct {
		rows []DrillRow
		want string
	}{
		{nil, ""},
		{[]DrillRow{{Share: 72}}, "drill_ip_dominant"},
		{[]DrillRow{{Share: 30}}, "drill_ip_dominant"},
		{[]DrillRow{{Share: 12}}, ""},
		{[]DrillRow{{Share: 0.4}, {Share: 0.3}}, "drill_ip_spread"},
	} {
		if got := ipHint(c.rows); got != c.want {
			t.Errorf("ipHint(%v) = %q, want %q", c.rows, got, c.want)
		}
	}
}

func TestDrillIPBlockLink(t *testing.T) {
	e := newWriteEnv(t, true)
	e.srv.Analytics = &fakeAnalytics{}
	_, body, _ := e.admin.do("GET", "/movers/drill?dim=asn&name=AS207990", nil, nil)
	if !strings.Contains(body, "/blocks/new?z=example.com&amp;type=ip&amp;value=203.0.113.7") {
		t.Fatalf("drill IP rows lack a block link:\n%s", body)
	}
	code, form, _ := e.admin.do("GET", "/blocks/new?z=example.com&type=ip&value=203.0.113.7&reason=drill-down", nil, nil)
	if code != 200 || !strings.Contains(form, `value="203.0.113.7"`) || !strings.Contains(form, `<option value="ip" selected>`) {
		t.Fatalf("block form does not take the IP: %d\n%s", code, form)
	}
}
