package analyze

// Severity separates "it hurts" from "it is loud". The tool's core promise
// (SPEC 3.4) is to tell expensive traffic from cheap edge volume; a flood
// absorbed at the edge — total or Worker calls up, real rendering flat, CPU
// and origin quiet — is a finding of its own, at low severity, not two
// alert lines the reader has to decode into "it doesn't hurt".
type Severity struct {
	Level  string  `json:"level"`          // "low" | "high"
	Kind   string  `json:"kind,omitempty"` // "edge_absorbed" for low
	DynPct float64 `json:"dynamic_pct"`    // change in real rendering
}

// Severity levels and kinds.
const (
	SevLow       = "low"
	SevHigh      = "high"
	EdgeAbsorbed = "edge_absorbed"
	// renderingFlat: real rendering may move this much and the flood still
	// counts as absorbed at the edge.
	renderingFlat = 15.0
)

// Assess grades a round's findings.
func Assess(cur, base Metrics, fs []Finding) Severity {
	s := Severity{Level: SevHigh, DynPct: PctChange(float64(cur.Dynamic), float64(base.Dynamic))}
	if len(fs) == 0 {
		return Severity{}
	}
	volume, mix := false, false
	for _, f := range fs {
		switch f.Rule {
		case RuleTotalUp, RuleWorkerCallsUp, RuleNewFaceUA, RuleNewFaceASN:
			volume = true
		case RuleCPUUp:
			// A mix change is reported, one level down: nothing got slower.
			if JudgeCPU(cur.Worker(f.Subject), base.Worker(f.Subject)).Verdict == CPUMix {
				mix = true
				continue
			}
			return s
		case RuleDynamicUp, RuleOrigin5xx, RuleCollapseTotal, RuleCollapseWorker, RulePathUp, RuleOriginSlow, RuleUnreachable:
			return s // something expensive or broken: not "just loud"
		}
	}
	switch {
	case volume && s.DynPct < renderingFlat:
		s.Level, s.Kind = SevLow, EdgeAbsorbed
	case mix && !volume:
		s.Level, s.Kind = SevLow, CPUMixKind
	}
	return s
}

// CPUMixKind marks a round whose only expensive-looking line is a CPU
// P50 rise that the tail and the call count explain as a mix change.
const CPUMixKind = "cpu_mix"

// CPU verdicts: what a Worker's CPU P50 rise means, read against its P99
// and its call count. The median alone cannot tell "every call got more
// expensive" from "the cheap calls left" — after a flood of cheap calls
// recedes the median rises while nothing got slower.
const (
	CPUCostly = "costly" // P99 rose with the median and calls held: calls really got more expensive
	CPUMix    = "mix"    // median up, tail about flat, calls down: the mix changed, the cost did not
)

// cpuCallsFell: calls must drop at least this much for a mix change.
const cpuCallsFell = -10.0

// CPUShift is the three numbers every CPU alert carries, and their reading.
type CPUShift struct {
	P50Pct, P99Pct, CallsPct float64
	P99Known                 bool   // both windows measured the P99
	Verdict                  string // CPUCostly | CPUMix | "" (not decidable)
}

// JudgeCPU reads a Worker's CPU change. The P99 counts as "about flat"
// when it rose by less than half of the median's rise.
func JudgeCPU(cur, base WorkerMetrics) CPUShift {
	s := CPUShift{P50Pct: PctChange(cur.CPUP50ms, base.CPUP50ms), CallsPct: PctChange(float64(cur.Calls), float64(base.Calls))}
	if cur.CPUP99ms <= 0 || base.CPUP99ms <= 0 {
		return s
	}
	s.P99Known = true
	s.P99Pct = PctChange(cur.CPUP99ms, base.CPUP99ms)
	tailFlat := s.P99Pct < s.P50Pct/2
	switch {
	case tailFlat && s.CallsPct <= cpuCallsFell:
		s.Verdict = CPUMix
	case !tailFlat && s.CallsPct > cpuCallsFell:
		s.Verdict = CPUCostly
	}
	return s
}

// ---- edge 52x: origin down, or bookkeeping? ----
//
// The origin_unreachable line assumes a normally-zero baseline: a healthy
// origin is always reachable. On Worker zones that never holds — Cache
// API entries are filed in the adaptive dataset with edge statuses, and
// an edge timeout on such an entry reads 522/524 — so hundreds of 52x an
// hour are background, while the site is fine. JudgeUnreachable is the
// one place that tells them apart; the alert evaluation, the console
// tile and the reports all use it, so they cannot disagree.

// Unreachable verdicts.
const (
	UnreachPlain    = ""            // normally-zero baseline: the plain line (≥ min and ≥ 2× baseline) decides
	UnreachBook     = "bookkeeping" // a steady 522/524 background, the origin answering: not an outage
	UnreachIncident = "incident"    // a departure from a bookkeeping background
)

const (
	bookShareMin     = 0.9 // 522+524 share of the 52x for a bookkeeping background
	bookJump         = 3.0 // × the background: a jump in volume
	bookMixShare     = 0.1 // other 52x statuses' share that counts as a change of mix…
	originCollapseAt = 0.5 // origin-answered requests below this × baseline: collapsed
)

// UnreachableCheck is the reading of a window's edge 52x against its baseline.
type UnreachableCheck struct {
	Verdict     string
	BookShare   float64 // 522+524 share of the current 52x
	BaseShare   float64 // the same in the baseline
	Jump        float64 // current ÷ baseline (0 when the baseline is 0)
	JumpHit     bool    // ≥ 3× the background, by at least the line's minimum
	Others      int64   // current 52x that are not 522/524
	MixHit      bool    // those rose to a share of their own
	Collapse    float64 // change of origin-answered requests, % (0 when unmeasured)
	CollapseHit bool    // the origin stopped answering
}

func bookCount(m Metrics) int64 { return m.UnreachableBy["522"] + m.UnreachableBy["524"] }

func bookShare(m Metrics) float64 {
	if m.Unreachable <= 0 {
		return 0
	}
	return float64(bookCount(m)) / float64(m.Unreachable)
}

// JudgeUnreachable reads a window's edge 52x. min is the line's floor
// (thresholds.unreachable_min): a jump must add at least that much, and
// other statuses must reach it, to count.
func JudgeUnreachable(cur, base Metrics, min int64) UnreachableCheck {
	c := UnreachableCheck{BookShare: bookShare(cur), BaseShare: bookShare(base), Others: cur.Unreachable - bookCount(cur)}
	if base.Unreachable > 0 {
		c.Jump = float64(cur.Unreachable) / float64(base.Unreachable)
	}
	if co, bo := cur.Origin, base.Origin; co != nil && bo != nil && bo.Requests >= OriginMinRequests {
		c.Collapse = PctChange(float64(co.Requests), float64(bo.Requests))
		c.CollapseHit = float64(co.Requests) < originCollapseAt*float64(bo.Requests)
	}
	// Only a baseline that is itself a 522/524 background makes 52x
	// bookkeeping; anything else keeps the normally-zero reading.
	if base.Unreachable <= 0 || c.BaseShare < bookShareMin || cur.Unreachable <= 0 {
		return c
	}
	c.JumpHit = c.Jump >= bookJump && cur.Unreachable-base.Unreachable >= min
	baseOthers := base.Unreachable - bookCount(base)
	c.MixHit = c.Others >= min && 1-c.BookShare >= bookMixShare && c.Others >= 2*baseOthers
	if c.JumpHit || c.MixHit || c.CollapseHit {
		c.Verdict = UnreachIncident
	} else {
		c.Verdict = UnreachBook
	}
	return c
}

// UnreachableFires is the origin_unreachable line: a departure from a
// bookkeeping background, or — on a normally-zero baseline — at least min
// 52x and at least twice the baseline.
func UnreachableFires(cur, base Metrics, min int64) (bool, UnreachableCheck) {
	c := JudgeUnreachable(cur, base, min)
	switch c.Verdict {
	case UnreachIncident:
		return true, c
	case UnreachBook:
		return false, c
	}
	return cur.Unreachable > 0 && cur.Unreachable >= min && float64(cur.Unreachable) >= unreachableMultiple*float64(base.Unreachable), c
}
