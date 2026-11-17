package block

import (
	"context"
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
