// Package analyze compares a current metrics window with a baseline window
// (yesterday, same hours) and applies FlareHound's detection rules.
//
// The defaults encode the alert discipline from SPEC.md section 7:
// thresholds first, attribution before conclusions, expensive traffic
// (dynamic responses, Worker renders) reported separately from cheap
// edge volume. Everything here is deterministic and free of I/O: the
// same two windows always produce the same findings.
package analyze

import (
	"fmt"
	"sort"
	"strconv"
	"strings"

	"github.com/playwjj/flarehound/internal/cfapi"
)

// Rule identifiers. They are stable: they end up in state files.
const (
	RuleTotalUp        = "total_up"
	RuleWorkerCallsUp  = "worker_calls_up"
	RuleCPUUp          = "cpu_p50_up"
	RuleDynamicUp      = "dynamic_up"
	RuleOrigin5xx      = "origin_5xx"
	RuleCollapseTotal  = "collapse_total"
	RuleCollapseWorker = "collapse_worker"
	RuleNewFaceUA      = "new_face_ua"
	RuleNewFaceASN     = "new_face_asn"
	RulePathUp         = "path_up"
)

// Thresholds mirrors config.Thresholds; duplicated here so this package
// stays independent of the config file format.
type Thresholds struct {
	TotalUpPct         float64
	WorkerCallsUpPct   float64
	CPUP50UpPct        float64
	DynamicUpPct       float64
	Origin5xxMultiple  float64
	Origin5xxMin       int64
	NewFaceMinCount    int64
	CollapseDownPct    float64
	MinCount           int64 // volume floor for percentage rules
	EscalationPct      float64
	RecoveryCleanRound int
	PathRules          []PathRule
}

// PathRule is a path-level threshold override (SPEC 7.2).
type PathRule struct {
	Name     string
	UpPct    float64
	MinCount int64
}

// Known is the known-pattern library (SPEC 17): sources registered by
// the user that never count as new faces.
type Known struct {
	ASNs       map[int]bool
	UserAgents []string // lower-case substrings
}

func (k Known) uaKnown(ua string) bool {
	l := strings.ToLower(ua)
	for _, s := range k.UserAgents {
		if s != "" && strings.Contains(l, strings.ToLower(s)) {
			return true
		}
	}
	return false
}

// WorkerMetrics is one Worker script's window.
type WorkerMetrics struct {
	Name     string  `json:"name"`
	Calls    int64   `json:"calls"`
	CPUP50ms float64 `json:"cpu_p50_ms"`
}

// Metrics is one window's worth of observations for one zone. For the
// baseline window, TopUA/TopASN must be the Top 25 ("old faces"); for
// the current window, the Top 10.
type Metrics struct {
	Total     int64            `json:"total"`
	Dynamic   int64            `json:"dynamic"`
	Origin5xx int64            `json:"origin_5xx"`
	Workers   []WorkerMetrics  `json:"workers,omitempty"`
	TopUA     []cfapi.Face     `json:"top_ua,omitempty"`
	TopASN    []cfapi.Face     `json:"top_asn,omitempty"`
	Paths     map[string]int64 `json:"paths,omitempty"` // PathRule.Name -> count
}

// Worker returns the named worker's metrics (zero value if absent).
func (m Metrics) Worker(name string) WorkerMetrics {
	for _, w := range m.Workers {
		if w.Name == name {
			return w
		}
	}
	return WorkerMetrics{Name: name}
}

// Finding is one triggered rule, with the numbers that triggered it.
type Finding struct {
	Rule    string  `json:"rule"`
	Subject string  `json:"subject,omitempty"` // worker / path rule / face
	ASN     int     `json:"asn,omitempty"`     // new_face_asn only
	Cur     float64 `json:"cur"`
	Base    float64 `json:"base"`
	Pct     float64 `json:"pct"`
	Down    bool    `json:"down,omitempty"` // collapse-type: lower is worse
}

// Key identifies the signal across rounds. New-face UAs share one key on
// purpose: crawlers rotate UA strings (three batches a day in the field),
// and every rotation must not page the user again. ASNs are stable, so a
// new ASN is a new signal.
func (f Finding) Key() string {
	if f.Subject == "" || f.Rule == RuleNewFaceUA {
		return f.Rule
	}
	return CanonicalKey(f.Rule + ":" + f.Subject)
}

// CanonicalKey spells ASN signal keys one way: "new_face_asn:AS150436"
// (older state files may hold "new_face_asn:150436").
func CanonicalKey(k string) string {
	rule, subj, ok := strings.Cut(k, ":")
	if !ok || rule != RuleNewFaceASN {
		return k
	}
	n, err := strconv.Atoi(strings.TrimPrefix(strings.ToUpper(subj), "AS"))
	if err != nil || n <= 0 {
		return k
	}
	return rule + ":AS" + strconv.Itoa(n)
}

// String is a compact English rendering for logs.
func (f Finding) String() string {
	s := f.Rule
	if f.Subject != "" {
		s += "[" + f.Subject + "]"
	}
	return fmt.Sprintf("%s %.0f vs %.0f (%+.1f%%)", s, f.Cur, f.Base, f.Pct)
}

// PctChange returns the percentage change from base to cur. A zero base
// with a positive current value is reported as +999 (effectively "new").
func PctChange(cur, base float64) float64 {
	if base == 0 {
		if cur == 0 {
			return 0
		}
		return 999
	}
	return (cur - base) / base * 100
}

func upRule(rule, subject string, cur, base float64, th float64, floor int64) (Finding, bool) {
	p := PctChange(cur, base)
	if p >= th && cur >= float64(floor) {
		return Finding{Rule: rule, Subject: subject, Cur: cur, Base: base, Pct: p}, true
	}
	return Finding{}, false
}

func downRule(rule, subject string, cur, base float64, th float64, floor int64) (Finding, bool) {
	p := PctChange(cur, base)
	if p <= -th && base >= float64(floor) {
		return Finding{Rule: rule, Subject: subject, Cur: cur, Base: base, Pct: p, Down: true}, true
	}
	return Finding{}, false
}

// Evaluate applies every detection rule and returns the findings.
// An empty result means the window is clean.
func Evaluate(cur, base Metrics, th Thresholds, known Known) []Finding {
	var out []Finding
	add := func(f Finding, ok bool) {
		if ok {
			out = append(out, f)
		}
	}

	add(upRule(RuleTotalUp, "", float64(cur.Total), float64(base.Total), th.TotalUpPct, th.MinCount))
	add(upRule(RuleDynamicUp, "", float64(cur.Dynamic), float64(base.Dynamic), th.DynamicUpPct, th.MinCount))
	if cur.Origin5xx > th.Origin5xxMin && float64(cur.Origin5xx) >= float64(base.Origin5xx)*th.Origin5xxMultiple {
		out = append(out, Finding{Rule: RuleOrigin5xx, Cur: float64(cur.Origin5xx), Base: float64(base.Origin5xx),
			Pct: PctChange(float64(cur.Origin5xx), float64(base.Origin5xx))})
	}
	add(downRule(RuleCollapseTotal, "", float64(cur.Total), float64(base.Total), th.CollapseDownPct, th.MinCount))

	for _, w := range cur.Workers {
		b := base.Worker(w.Name)
		add(upRule(RuleWorkerCallsUp, w.Name, float64(w.Calls), float64(b.Calls), th.WorkerCallsUpPct, th.MinCount))
		// A CPU median over a handful of invocations is noise.
		if w.Calls >= th.MinCount && b.Calls >= th.MinCount {
			add(upRule(RuleCPUUp, w.Name, w.CPUP50ms, b.CPUP50ms, th.CPUP50UpPct, 0))
		}
		add(downRule(RuleCollapseWorker, w.Name, float64(w.Calls), float64(b.Calls), th.CollapseDownPct, th.MinCount))
	}

	for _, pr := range th.PathRules {
		c, b := cur.Paths[pr.Name], base.Paths[pr.Name]
		add(upRule(RulePathUp, pr.Name, float64(c), float64(b), pr.UpPct, pr.MinCount))
	}

	out = append(out, newFaces(RuleNewFaceUA, cur.TopUA, base.TopUA, th.NewFaceMinCount, known)...)
	out = append(out, newFaces(RuleNewFaceASN, cur.TopASN, base.TopASN, th.NewFaceMinCount, known)...)
	return out
}

// newFaces flags Top-10 entries absent from the baseline Top-25 list.
//
// Known false-positive class (SPEC.md 7.3): legitimate crawlers bump
// their UA version strings and look "new". Such UAs are verified by ASN
// in a second step (see ClaimedBot / VerifiedBot), which needs a query
// and therefore lives with the caller.
func newFaces(rule string, curTop, baseTop []cfapi.Face, minCount int64, known Known) []Finding {
	old := make(map[string]bool, len(baseTop))
	for _, f := range baseTop {
		old[f.Name] = true
	}
	var out []Finding
	for _, f := range curTop {
		if f.Count <= minCount || old[f.Name] {
			continue
		}
		if rule == RuleNewFaceASN && known.ASNs[f.ASN] {
			continue
		}
		if rule == RuleNewFaceUA && known.uaKnown(f.Name) {
			continue
		}
		subject := f.Name
		if rule == RuleNewFaceASN && f.ASN > 0 {
			subject = "AS" + strconv.Itoa(f.ASN) // one spelling everywhere
		}
		out = append(out, Finding{Rule: rule, Subject: subject, ASN: f.ASN, Cur: float64(f.Count), Pct: 999})
	}
	return out
}

// HasCollapse reports whether any finding is a collapse — those need the
// settle check before they may be trusted (SPEC 6: never conclude on
// unsettled data).
func HasCollapse(fs []Finding) bool {
	for _, f := range fs {
		if f.Down {
			return true
		}
	}
	return false
}

// Without returns fs minus findings of the given rule.
func Without(fs []Finding, rule string) []Finding {
	out := fs[:0:0]
	for _, f := range fs {
		if f.Rule != rule {
			out = append(out, f)
		}
	}
	return out
}

// Fingerprint identifies an anomaly by its sorted, de-duplicated keys.
func Fingerprint(findings []Finding) string {
	seen := map[string]bool{}
	var keys []string
	for _, f := range findings {
		if k := f.Key(); !seen[k] {
			seen[k] = true
			keys = append(keys, k)
		}
	}
	sort.Strings(keys)
	return strings.Join(keys, ",")
}
