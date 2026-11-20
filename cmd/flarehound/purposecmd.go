package main

import (
	"context"
	"fmt"
	"io"
	"time"

	"github.com/playwjj/flarehound/internal/cfapi"
	"github.com/playwjj/flarehound/internal/config"
	"github.com/playwjj/flarehound/internal/purpose"
	"github.com/playwjj/flarehound/internal/report"
	"github.com/playwjj/flarehound/internal/store"
	"github.com/playwjj/flarehound/internal/suggest"
)

// purposeAPI is the read-only analytics the purpose command needs.
type purposeAPI interface {
	Count(ctx context.Context, zoneID string, from, to time.Time, f cfapi.Filter) (int64, error)
	Top(ctx context.Context, zoneID string, from, to time.Time, dim string, limit int, f cfapi.Filter) ([]cfapi.Face, error)
	Capabilities(ctx context.Context, zoneID string) (cfapi.Caps, error)
}

// runPurpose prints traffic by purpose for the last `hours` whole hours
// (and the same hours a day earlier), for the zone or, with asn > 0, for
// one network's slice of it.
func runPurpose(ctx context.Context, cfg *config.Config, z config.Zone, st *store.Store, api purposeAPI, hours, asn int, now time.Time, out io.Writer) int {
	t := cfg.PurposeTable()
	if !t.OK() {
		fmt.Fprintf(out, "traffic by purpose is off: %v\n", t.Err())
		return 1
	}
	if hours < 1 || hours > 24*7 {
		fmt.Fprintln(out, "--hours takes 1..168")
		return 2
	}
	caps, err := api.Capabilities(ctx, z.ZoneID)
	if err != nil {
		caps = cfapi.AllCaps()
	}
	if asn > 0 && !caps.HasDim(cfapi.DimASN) {
		fmt.Fprintln(out, "--asn needs the ASN dimension, which this zone's plan does not expose")
		return 2
	}
	dim := caps.UAPurposeDim()
	var names map[int]string
	if st != nil {
		names, _ = st.ASNNames()
	}
	o := purpose.OptionsFor(dim, func(a int) bool { return suggest.Classify(a, names[a]) == suggest.Hosting })
	f := cfapi.Filter{ASN: asn}
	to := now.Truncate(time.Hour)
	from := to.Add(-time.Duration(hours) * time.Hour)
	facet := func(from, to time.Time) (purpose.Facet, int64, error) {
		total, err := api.Count(ctx, z.ZoneID, from, to, f)
		if err != nil {
			return purpose.Facet{}, 0, err
		}
		rows, err := api.Top(ctx, z.ZoneID, from, to, dim, purpose.RowLimit, f)
		if err != nil {
			return purpose.Facet{}, 0, err
		}
		return t.Facet(purpose.RowsOf(rows), o), total, nil
	}
	p := report.PurposeData{Version: t.Version(), Overrides: t.Overrides(), ASNLabels: map[int]string{}}
	for k, v := range names {
		p.ASNLabels[k] = v
	}
	for k, v := range cfg.ASNLabels() {
		p.ASNLabels[k] = v
	}
	if p.Cur, p.CurTotal, err = facet(from, to); err != nil {
		fmt.Fprintf(out, "purpose: %v\n", err)
		return 1
	}
	if p.Base, p.BaseTotal, err = facet(from.Add(-24*time.Hour), to.Add(-24*time.Hour)); err != nil {
		p.BaseNA = true
	}
	scope := z.Name
	if asn > 0 {
		scope += fmt.Sprintf(" · AS%d", asn)
		if n := p.ASNLabels[asn]; n != "" {
			scope += " " + n
		}
	}
	fmt.Fprintf(out, "%s · %s – %s · %s requests\n\n", scope, from.In(cfg.Location).Format("2006-01-02 15:04"),
		to.In(cfg.Location).Format("01-02 15:04"), fmtInt(p.CurTotal))
	fmt.Fprintln(out, report.Purpose(cfg.Report.Language, p))
	return 0
}
