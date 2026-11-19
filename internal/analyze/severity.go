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

// UnreachableArtifact reports a 52x count that is bookkeeping rather than
// an origin outage: present in both windows and not rising (cur at most
// twice the baseline — a persistent background, not an incident), mostly
// 522/524, while the origin keeps answering (its answered requests held,
// or — unmeasured — its 5xx did not rise). Worker zones show this: edge
// entries for subrequests and cached responses are filed as 52x while
// the site is fine. The alert line is unaffected (it needs a doubling);
// this only keeps the bare number from misleading a reader.
func UnreachableArtifact(cur, base Metrics) bool {
	if cur.Unreachable <= 0 || base.Unreachable <= 0 || cur.Unreachable > 2*base.Unreachable {
		return false
	}
	if float64(cur.UnreachableBy["522"]+cur.UnreachableBy["524"]) < 0.8*float64(cur.Unreachable) {
		return false
	}
	if co, bo := cur.Origin, base.Origin; co != nil && bo != nil && bo.Requests > 0 {
		return float64(co.Requests) >= 0.8*float64(bo.Requests)
	}
	return cur.Origin5xx <= 2*base.Origin5xx
}
