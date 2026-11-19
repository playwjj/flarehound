package block

import (
	"context"
	"slices"
	"strings"
	"time"

	"github.com/playwjj/flarehound/internal/cfapi"
)

// FirewallAPI is the read-only analytics call attempts need.
type FirewallAPI interface {
	FirewallTop(ctx context.Context, zoneID string, from, to time.Time, ruleID, dim string, limit int) ([]cfapi.Face, error)
}

func dimFor(t Type) string {
	switch t {
	case ASN:
		return cfapi.FwDimASN
	case Country:
		return cfapi.FwDimCountry
	case UA:
		return cfapi.FwDimUA
	}
	return cfapi.FwDimIP
}

// Matches reports whether one firewall-event group belongs to target t
// (a rule holds many targets; events are attributed back by dimension).
func Matches(t Target, f cfapi.Face) bool {
	switch t.Type {
	case ASN:
		return itoaASN(f.ASN) == t.Value
	case Country:
		return strings.EqualFold(f.Name, t.Value)
	case UA:
		return strings.Contains(f.Name, t.Value)
	case IP:
		pf, ok := t.Prefix()
		if !ok {
			return false
		}
		a, err := parseAddr(f.Name)
		return err == nil && pf.Contains(a)
	}
	return false
}

// Attempts counts the firewall events a blocked target produced on its
// rule in [from, to), queried one day at a time (the dataset's range
// limits vary by plan). This is the basis for lifting a block: attempts,
// not quiet time (SPEC 7.4).
func Attempts(ctx context.Context, api FirewallAPI, zoneID, ruleID string, t Target, from, to time.Time) (int64, error) {
	var total int64
	for start := from; start.Before(to); start = start.Add(24 * time.Hour) {
		end := start.Add(24 * time.Hour)
		if end.After(to) {
			end = to
		}
		rows, err := api.FirewallTop(ctx, zoneID, start, end, ruleID, dimFor(t.Type), 1000)
		if err != nil {
			return 0, err
		}
		for _, r := range rows {
			if Matches(t, r) {
				total += r.Count
			}
		}
	}
	return total, nil
}

// MinutesAPI is the per-minute analytics behind the live check.
type MinutesAPI interface {
	Minutes(ctx context.Context, zoneID string, firewall bool, from, to time.Time, dim string, f cfapi.Filter, limit int) ([]cfapi.MinuteCount, error)
}

// Live-check sources.
const (
	LiveFirewall = "firewall" // firewall events on the block's own rule
	LiveEdge     = "edge"     // the target's requests stopped at the edge (any rule): plans without firewall events
)

// LiveWindow is the live check's count window; LiveLookback how far it
// looks for the last attempt. Firewall events reach the dataset 30–60
// minutes late on busy zones, so a 15-minute window read a structural 0
// exactly when "did the block take?" mattered: the hour aligns with the
// archived attempts, and the look-back finds the last attempt even when
// the hour is still empty.
const (
	LiveWindow   = time.Hour
	LiveLookback = 3 * time.Hour
)

// Live is "is this block catching anything right now", read live (not
// the archive).
type Live struct {
	Count    int64     // attempts in [To-LiveWindow, To)
	Last     time.Time // the target's latest attempt in the look-back (zero: none)
	Frontier time.Time // firewall source: the newest event of the rule, any target — how far the data reaches
	From, To time.Time
	Source   string
}

// AnalyticsFilter selects a target's requests in the HTTP dataset. CIDRs
// and countries cannot be selected there (ok is false).
func AnalyticsFilter(t Target) (cfapi.Filter, bool) {
	f := cfapi.Filter{}
	switch t.Type {
	case ASN:
		f.ASN = t.ASNumber()
	case UA:
		f.UserAgentLike = "%" + t.Value + "%"
	case IP:
		pf, _ := t.Prefix()
		if !pf.IsSingleIP() {
			return f, false
		}
		f.ClientIP = pf.Addr().String()
	default:
		return f, false
	}
	return f, true
}

// LiveCheck reads a block's recent attempts. With firewall events (paid
// plans) it reads the block's own rule and also reports how far that
// data reaches; without them it counts the target's requests the edge
// stopped (403, never sent to the origin) — any rule's, which after a
// block is mostly this one. ok is false when the target cannot be
// selected that way.
func LiveCheck(ctx context.Context, api MinutesAPI, zoneID, ruleID string, t Target, firewall bool, to time.Time) (Live, bool, error) {
	l := Live{From: to.Add(-LiveWindow), To: to}
	from := to.Add(-LiveLookback)
	var rows []cfapi.MinuteCount
	var err error
	if firewall {
		l.Source = LiveFirewall
		rows, err = api.Minutes(ctx, zoneID, true, from, to, dimFor(t.Type), cfapi.Filter{FirewallRuleID: ruleID}, 5000)
		if err != nil {
			return l, true, err
		}
		for _, m := range rows {
			if m.At.After(l.Frontier) {
				l.Frontier = m.At
			}
		}
		rows = slices.DeleteFunc(rows, func(m cfapi.MinuteCount) bool { return !Matches(t, m.Face) })
	} else {
		l.Source = LiveEdge
		f, ok := AnalyticsFilter(t)
		if !ok {
			return l, false, nil
		}
		eb := cfapi.EdgeBlocked()
		f.EdgeStatus, f.OriginStatusTo = eb.EdgeStatus, eb.OriginStatusTo
		if rows, err = api.Minutes(ctx, zoneID, false, from, to, "", f, 500); err != nil {
			return l, true, err
		}
	}
	for _, m := range rows {
		if !m.At.Before(l.From) {
			l.Count += m.Count
		}
		if m.At.After(l.Last) {
			l.Last = m.At
		}
	}
	return l, true, nil
}

// HourFaces is one archived hour's IPs stopped at the edge (the IP
// board's Top 50, kept by the watch since v1.14).
type HourFaces struct {
	From  time.Time
	Faces []cfapi.Face
}

// Approx is a block's attempts approximated from the IP board archive,
// for zones without firewall events (Free). It undercounts: an IP outside
// an hour's Top 50 adds nothing that hour, so a target knocking softly
// may read 0 — LastHour (the last hour it made the list) says more than
// the sum.
type Approx struct {
	Count    int64
	LastHour time.Time // zero: never on the list in the window
	Hours    int       // archived hours with an IP list in the window
}

// ApproxAttempts sums an IP target's counts over the archived hours.
// ok is false for targets the IP board cannot see (ASN, country, UA).
func ApproxAttempts(t Target, hours []HourFaces) (Approx, bool) {
	var a Approx
	if t.Type != IP {
		return a, false
	}
	for _, h := range hours {
		if h.Faces == nil {
			continue
		}
		a.Hours++
		for _, f := range h.Faces {
			if Matches(t, f) {
				a.Count += f.Count
				if h.From.After(a.LastHour) {
					a.LastHour = h.From
				}
			}
		}
	}
	return a, true
}
