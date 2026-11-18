package console

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/playwjj/flarehound/internal/analyze"
	"github.com/playwjj/flarehound/internal/cfapi"
	"github.com/playwjj/flarehound/internal/config"
)

func TestLiveFacesOnOverview(t *testing.T) {
	e := newWriteEnv(t, false)
	e.srv.Measure = func(_ context.Context, _ config.Zone, _, _ time.Time) (analyze.Metrics, error) {
		return analyze.Metrics{
			Total:  30000,
			TopUA:  []cfapi.Face{{Name: "LiveCrawler/1.0", Count: 12345}, {Name: "Second/2.0", Count: 2000}, {Name: "", Count: 900}},
			TopASN: []cfapi.Face{{Name: "AS45102", ASN: 45102, Count: 6789}},
		}, nil
	}
	_, body, _ := e.admin.do("GET", "/", nil, nil)
	for _, want := range []string{"LiveCrawler/1.0", "12,345", "AS45102", "6,789", "22.6%", "(no user agent)"} {
		if !strings.Contains(body, want) {
			t.Fatalf("overview lacks live face %q:\n%s", want, body)
		}
	}
}
