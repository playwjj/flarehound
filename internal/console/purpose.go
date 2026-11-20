package console

// Traffic by purpose in the console (docs/traffic-purpose.md): a badge on
// user agents (a UA property — never on IPs), a purpose filter on the
// movers and new-faces lists, and in the drill-down the UA's label with
// its trust, or an ASN's traffic split by purpose.

import (
	"context"
	"fmt"
	"sort"
	"strings"

	"github.com/playwjj/flarehound/internal/cfapi"
	"github.com/playwjj/flarehound/internal/config"
	"github.com/playwjj/flarehound/internal/purpose"
	"github.com/playwjj/flarehound/internal/report"
	"github.com/playwjj/flarehound/internal/suggest"
)

// PurposeTag is a UA's badge: the class's short name, its operator and
// how it is known on hover.
type PurposeTag struct {
	Class, Text, Title string
}

func purposeTagOf(l lang, lb purpose.Label) *PurposeTag {
	title := []string{report.ClassName(string(l), lb.Class)}
	if lb.Operator != "" {
		title = append(title, lb.Operator)
	}
	title = append(title, report.TrustName(string(l), lb.Trust))
	if lb.Override {
		title = append(title, l.t("purpose_override"))
	}
	return &PurposeTag{Class: string(lb.Class), Text: report.ClassName(string(l), lb.Class), Title: strings.Join(title, " · ")}
}

// purposeTag is the list badge of a user agent: from the table alone (a
// list carries no traffic evidence), so it is self-declared at best;
// verification and undeclared automation are on the drill-down.
func (s *Server) purposeTag(l lang, dim, name string) *PurposeTag {
	if dim != DimUA || name == "" {
		return nil
	}
	lb, ok := s.eff().PurposeTable().Named(name)
	if !ok {
		return nil
	}
	t := purposeTagOf(l, lb)
	t.Title += " — " + l.t("purpose_list_hint")
	return t
}

// purposeParam reads the purpose filter ("" = all).
func purposeParam(v string) string {
	if purpose.Valid(purpose.Class(v)) && v != string(purpose.None) {
		return v
	}
	return ""
}

func purposeMatch(t *purpose.Table, ua, class string) bool {
	if class == "" {
		return true
	}
	lb, ok := t.Named(ua)
	return ok && string(lb.Class) == class
}

func filterMovers(t *purpose.Table, rows []Mover, class string) []Mover {
	if class == "" {
		return rows
	}
	var out []Mover
	for _, m := range rows {
		if purposeMatch(t, m.Name, class) {
			out = append(out, m)
		}
	}
	return out
}

func filterFaces(t *purpose.Table, fs []NewFace, class string) []NewFace {
	if class == "" {
		return fs
	}
	var out []NewFace
	for _, f := range fs {
		if purposeMatch(t, f.Name, class) {
			out = append(out, f)
		}
	}
	return out
}

// PurposeClasses are the filter choices (undeclared needs traffic, so it
// is not offered on the lists).
func PurposeClasses() []string {
	var out []string
	for _, c := range purpose.Classes {
		if c != purpose.Undeclared {
			out = append(out, string(c))
		}
	}
	return out
}

// PurposeRow is one class of an entry's traffic.
type PurposeRow struct {
	Class string
	Count int64
	Share float64 // of the entry's requests, percent
	Top   string  // largest actor
}

// DrillPurpose is the purpose part of a drill-down.
type DrillPurpose struct {
	Label *purpose.Label // a user agent's own label
	Rows  []PurposeRow   // an ASN's traffic split by purpose
	Rest  float64        // share untagged, percent
	NoASN bool           // undeclared automation could not be judged
	Err   string
}

// drillPurpose reads the entry's UA groups (UA × network × verified bot)
// and classifies them with the table in force.
func (s *Server) drillPurpose(ctx context.Context, z config.Zone, d *Drill) *DrillPurpose {
	if s.Analytics == nil || (d.Dim != DimUA && d.Dim != DimASN) {
		return nil
	}
	t := s.eff().PurposeTable()
	if !t.OK() {
		return nil
	}
	f, ok := drillFilter(d.Dim, d.Name)
	if !ok {
		return nil
	}
	dim := cfapi.DimUAASNBot
	if s.Caps != nil {
		dim = s.Caps(ctx, z).UAPurposeDim()
	}
	limit := 500
	if d.Dim == DimUA {
		limit = 50
	}
	rows, err := s.Analytics.Top(ctx, z.ZoneID, d.From, d.To, dim, limit, f)
	if err != nil {
		return &DrillPurpose{Err: err.Error()}
	}
	names := s.registeredASNNames()
	o := purpose.OptionsFor(dim, func(asn int) bool { return suggest.Classify(asn, names[asn]) == suggest.Hosting })
	out := &DrillPurpose{NoASN: !o.HasASN}
	if d.Dim == DimUA {
		if lb, ok := t.Classify(d.Name, purpose.RowsOf(rows), o); ok {
			out.Label = &lb
		}
		return out
	}
	fc := t.Facet(purpose.RowsOf(rows), o)
	total := d.Cur
	if total <= 0 {
		total = fc.Rows
	}
	if total <= 0 {
		return out
	}
	tagged := int64(0)
	for _, c := range purpose.Classes {
		st := fc.Stats[c]
		if st == nil {
			continue
		}
		r := PurposeRow{Class: string(c), Count: st.Count, Share: 100 * float64(st.Count) / float64(total)}
		if len(st.Actors) > 0 {
			a := st.Actors[0]
			name := a.Name
			if name == "" {
				name = report.CompactUA(a.UA)
			}
			r.Top = fmt.Sprintf("%s (%s)", name, fmtNum(a.Count))
		}
		tagged += st.Count
		out.Rows = append(out.Rows, r)
	}
	sort.SliceStable(out.Rows, func(i, j int) bool { return out.Rows[i].Count > out.Rows[j].Count })
	out.Rest = 100 * float64(max(total-tagged, 0)) / float64(total)
	return out
}
