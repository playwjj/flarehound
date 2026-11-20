// Package blockeffect compares a block's target in the hour before and
// the hour after it took effect, and says in one sentence what happened
// ("requests 45,000 → 900 (−98 %), practically gone"). The console shows
// it per block; the daily report lists the day's blocks with it.
package blockeffect

import (
	"context"
	"fmt"
	"strings"
	"time"

	"github.com/playwjj/flarehound/internal/block"
	"github.com/playwjj/flarehound/internal/blockcli"
	"github.com/playwjj/flarehound/internal/cfapi"
	"github.com/playwjj/flarehound/internal/sim"
	"github.com/playwjj/flarehound/internal/store"
)

// API is the read-token analytics the comparison needs.
type API interface {
	Count(ctx context.Context, zoneID string, from, to time.Time, f cfapi.Filter) (int64, error)
	Top(ctx context.Context, zoneID string, from, to time.Time, dim string, limit int, f cfapi.Filter) ([]cfapi.Face, error)
	FirewallTop(ctx context.Context, zoneID string, from, to time.Time, ruleID, dim string, limit int) ([]cfapi.Face, error)
}

const statusDim = "edgeResponseStatus"

// Effect is one block's before / after.
type Effect struct {
	EventID       int64
	Target        string
	At            time.Time
	Settled       bool // the hour after has passed (and settled)
	Measurable    bool
	Before, After int64
	ZoneBefore    int64
	ZoneAfter     int64
	StatusBefore  []cfapi.Face
	StatusAfter   []cfapi.Face
	Attempts      int64
	AttemptsKnown bool
	Err           string
	// Predicted is the net new per hour the rule simulation predicted at
	// review (kept with the block record); PredictedKnown is false when no
	// simulation with a net-new estimate was kept.
	Predicted      float64 `json:",omitempty"`
	PredictedKnown bool    `json:",omitempty"`
	PredictedUpper bool    `json:",omitempty"`
}

// Predict takes the prediction from the simulation kept with the block.
func (e *Effect) Predict(r *sim.Report) {
	if r == nil || !r.Evaluable || !r.NetKnown {
		return
	}
	e.Predicted, e.PredictedKnown, e.PredictedUpper = r.NetPerHour(), true, r.NetMark() == "≤"
}

// PredictionLine sets the review's prediction against what happened:
// "predicted net new ≈ 1,490/h, actual 1,320 stopped (−11%)". "" without
// a prediction.
func (e Effect) PredictionLine(lang string) string {
	if !e.PredictedKnown {
		return ""
	}
	mark := "≈"
	if e.PredictedUpper {
		mark = "≤"
	}
	pred := fmt.Sprintf(t(lang, "predicted net new %s %s/h (simulation at review)", "预测净新增 %s %s 次/小时（确认时的模拟）"), mark, n(int64(e.Predicted+0.5)))
	switch {
	case !e.Settled:
		return pred + t(lang, "; actual: the hour after has not settled", "；实际：封禁后一小时尚未落定")
	case !e.AttemptsKnown:
		return pred + t(lang, "; actual: not countable (no firewall events for this rule)", "；实际：无法计量（该规则无防火墙事件）")
	}
	dev := ""
	if e.Predicted >= 1 {
		dev = fmt.Sprintf(" (%+.0f%%)", (float64(e.Attempts)-e.Predicted)/e.Predicted*100)
	}
	return pred + fmt.Sprintf(t(lang, "; actual %s stopped in the hour after%s", "；实际封禁后一小时拦截 %s 次%s"), n(e.Attempts), dev)
}

func pctOf(n, of int64) float64 {
	if of == 0 {
		return 0
	}
	return float64(n) / float64(of) * 100
}

func (e Effect) ShareBefore() float64 { return pctOf(e.Before, e.ZoneBefore) }
func (e Effect) ShareAfter() float64  { return pctOf(e.After, e.ZoneAfter) }

// Compute measures a block event. The hour after is cut at now − settle
// (analytics ingestion lag); when it is cut, the result is not Settled.
func Compute(ctx context.Context, api API, zoneID string, ev store.BlockEvent, now time.Time, settle time.Duration) Effect {
	t := block.Target{Type: block.Type(ev.Type), Value: ev.Value}
	e := Effect{EventID: ev.ID, Target: t.String(), At: ev.At}
	at := ev.At.Truncate(time.Minute)
	bFrom, aTo := at.Add(-time.Hour), at.Add(time.Hour)
	if end := now.Add(-settle); end.Before(aTo) {
		aTo = end
	} else {
		e.Settled = true
	}
	if !aTo.After(at) {
		e.Settled = false
		return e
	}
	var errs []string
	note := func(err error) {
		if err != nil {
			errs = append(errs, err.Error())
		}
	}
	var err error
	e.ZoneBefore, err = api.Count(ctx, zoneID, bFrom, at, cfapi.Filter{})
	note(err)
	e.ZoneAfter, err = api.Count(ctx, zoneID, at, aTo, cfapi.Filter{})
	note(err)
	if f, ok := blockcli.FilterFor(t); ok {
		e.Measurable = true
		e.Before, err = api.Count(ctx, zoneID, bFrom, at, f)
		note(err)
		e.After, err = api.Count(ctx, zoneID, at, aTo, f)
		note(err)
		e.StatusBefore, err = api.Top(ctx, zoneID, bFrom, at, statusDim, 5, f)
		note(err)
		e.StatusAfter, err = api.Top(ctx, zoneID, at, aTo, statusDim, 5, f)
		note(err)
	}
	if ev.RuleID != "" {
		n, err := block.Attempts(ctx, api, zoneID, ev.RuleID, t, at, aTo)
		e.Attempts, e.AttemptsKnown = n, err == nil
	}
	if len(errs) > 0 {
		e.Err = strings.Join(errs, "; ")
		e.Settled = false // retry later
	}
	return e
}

// Verdict kinds.
const (
	Pending   = "pending" // the hour after has not settled
	Gone      = "gone"    // ≤ 2 % of before
	Down      = "down"    // ≤ 50 % of before
	Stopped   = "stopped" // still coming, but ≥ 80 % answered 403
	Unclear   = "unclear" // no clear change
	NoMeasure = "unmeasurable"
	NoBefore  = "no_before"
)

func t(lang, en, zh string) string {
	if lang == "zh" {
		return zh
	}
	return en
}

func n(v int64) string {
	s := fmt.Sprint(v)
	var b strings.Builder
	for i, c := range s {
		if i > 0 && (len(s)-i)%3 == 0 {
			b.WriteByte(',')
		}
		b.WriteRune(c)
	}
	return b.String()
}

// Blocked403 is the share of the hour after answered 403 (blocked or
// challenged at the edge).
func (e Effect) Blocked403() float64 {
	var forbidden int64
	for _, f := range e.StatusAfter {
		if f.Name == "403" {
			forbidden += f.Count
		}
	}
	return pctOf(forbidden, e.After)
}

// Verdict says in one sentence what the block did.
func (e Effect) Verdict(lang string) (kind, text string) {
	attempts := ""
	if e.AttemptsKnown {
		attempts = fmt.Sprintf(t(lang, "; the rule stopped %s attempts", "；规则拦截尝试 %s 次"), n(e.Attempts))
	}
	switch {
	case !e.Settled:
		return Pending, t(lang, "the hour after has not settled yet", "封禁后一小时尚未落定")
	case !e.Measurable:
		if e.AttemptsKnown {
			return NoMeasure, fmt.Sprintf(t(lang, "the rule stopped %s attempts in the hour after (ranges and countries cannot be counted on their own)",
				"封禁后一小时规则拦截尝试 %s 次（网段与国家无法单独计量请求量）"), n(e.Attempts))
		}
		return NoMeasure, t(lang, "ranges and countries cannot be counted on their own", "网段与国家无法单独计量请求量")
	case e.Before == 0:
		return NoBefore, fmt.Sprintf(t(lang, "no requests in the hour before (%s after)%s", "封禁前一小时没有请求（之后 %s 次）%s"), n(e.After), attempts)
	}
	change := (float64(e.After) - float64(e.Before)) / float64(e.Before) * 100
	moved := fmt.Sprintf(t(lang, "requests %s → %s (%+.0f%%)", "请求 %s → %s（%+.0f%%）"), n(e.Before), n(e.After), change)
	switch {
	case e.After*50 <= e.Before:
		return Gone, moved + t(lang, ", practically gone", "，已基本归零") + attempts
	case e.After*2 <= e.Before:
		return Down, moved + t(lang, ", clearly down", "，明显下降") + attempts
	case e.Blocked403() >= 80:
		return Stopped, fmt.Sprintf(t(lang, "%s: still coming, but %.0f%% answered 403 (stopped at the edge)%s",
			"%s：请求仍在继续，但 %.0f%% 被拦下（403）%s"), moved, e.Blocked403(), attempts)
	}
	return Unclear, fmt.Sprintf(t(lang, "%s, only %.0f%% answered 403: no clear effect — check that the rule matches",
		"%s，403 仅占 %.0f%%：效果不明显，请检查规则是否命中"), moved, e.Blocked403()) + attempts
}
