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
	volume := false
	for _, f := range fs {
		switch f.Rule {
		case RuleTotalUp, RuleWorkerCallsUp, RuleNewFaceUA, RuleNewFaceASN:
			volume = true
		case RuleDynamicUp, RuleCPUUp, RuleOrigin5xx, RuleCollapseTotal, RuleCollapseWorker, RulePathUp, RuleOriginSlow, RuleUnreachable:
			return s // something expensive or broken: not "just loud"
		}
	}
	if volume && s.DynPct < renderingFlat {
		s.Level, s.Kind = SevLow, EdgeAbsorbed
	}
	return s
}
