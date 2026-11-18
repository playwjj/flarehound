package console

import (
	"strings"
	"testing"
	"time"

	"github.com/playwjj/flarehound/internal/check"
	"github.com/playwjj/flarehound/internal/config"
	"github.com/playwjj/flarehound/internal/state"
)

func TestAttentionHome(t *testing.T) {
	e := newWriteEnv(t, false)
	quiet := config.Zone{ZoneID: strings.Repeat("b", 32), Name: "aaa-quiet.example"}
	e.srv.Cfg.Cloudflare.Zones = append(e.srv.Cfg.Cloudflare.Zones, quiet)
	busy := e.srv.Cfg.Cloudflare.Zones[0]
	st := &state.State{Active: true, FirstAlertAt: time.Now().Add(-2 * time.Hour), Keys: map[string]bool{"total_up": true}}
	if err := st.Save(check.StatePath(e.srv.Cfg, busy)); err != nil {
		t.Fatal(err)
	}
	_, body, _ := e.admin.do("GET", "/", nil, nil)
	if !strings.Contains(body, "All zones") {
		t.Fatalf("no cross-zone home:\n%s", body)
	}
	ib, iq := strings.Index(body, ">example.com</a>"), strings.Index(body, ">aaa-quiet.example</a>")
	if ib < 0 || iq < 0 || ib > iq {
		t.Fatalf("order: busy at %d, quiet at %d (busy must come first despite the name)", ib, iq)
	}
	for _, want := range []string{"open alert episode since", "line(s) over", "new face(s) in 24 h", "no archived data", "total_up"} {
		if !strings.Contains(body, want) {
			t.Fatalf("home lacks %q", want)
		}
	}
	if _, body, _ := e.admin.do("GET", "/?z=example.com", nil, nil); strings.Contains(body, "All zones") || !strings.Contains(body, "25,000") {
		t.Fatal("?z= no longer opens the zone overview")
	}
}
