package analyze

import (
	"strings"
	"time"

	"github.com/playwjj/flarehound/internal/cfapi"
)

// Attribution is the breakdown that must precede any conclusion
// (SPEC 3.3 and 8): where the anomalous volume goes (paths, cache
// status), who sends it (IPs, new faces), and whether existing rules
// are already firing. It is filled by the caller's follow-up queries,
// only when a round has findings.
type Attribution struct {
	CacheCur     []cfapi.Face            `json:"cache_cur,omitempty"`
	CacheBase    []cfapi.Face            `json:"cache_base,omitempty"`
	DynamicPaths []PathDelta             `json:"dynamic_paths,omitempty"`
	TopIPs       []cfapi.Face            `json:"top_ips,omitempty"`
	FacePaths    map[string][]cfapi.Face `json:"face_paths,omitempty"` // finding Subject -> top paths
	Firewall     []cfapi.Face            `json:"firewall,omitempty"`
	FirewallNA   bool                    `json:"firewall_na,omitempty"` // dataset unavailable (plan/permission)
	VerifiedBots []string                `json:"verified_bots,omitempty"`
	ASNNames     map[int]string          `json:"asn_names,omitempty"` // registered ASN names, best-effort
	// FaceHistory is the archive's memory of each new face (finding
	// Subject): when it was first and last seen in any Top list. A face
	// absent from the map has never been seen before.
	FaceHistory map[string]FaceSeen `json:"face_history,omitempty"`
	Unsettled   []string            `json:"unsettled,omitempty"` // collapse rules held back: data still arriving
}

// FaceSeen is a face's archived history.
type FaceSeen struct {
	First, Last time.Time
	MaxCount    int64
}

// PathDelta is one path's count in both windows.
type PathDelta struct {
	Path string `json:"path"`
	Cur  int64  `json:"cur"`
	Base int64  `json:"base"`
}

// IsExpensive classifies a cacheStatus value (SPEC 3.4). Edge hits and
// stale/revalidated serves are cheap; everything that reaches a Worker
// or the origin is expensive. Unknown values count as expensive so the
// split errs towards caution.
func IsExpensive(cacheStatus string) bool {
	switch strings.ToLower(cacheStatus) {
	case "hit", "stale", "updating", "revalidated":
		return false
	}
	return true
}

// Cost is the expensive/cheap split of two windows.
type Cost struct {
	ExpCur, ExpBase     int64
	CheapCur, CheapBase int64
}

// SplitCost sums cache-status breakdowns into expensive and cheap parts.
func SplitCost(cur, base []cfapi.Face) Cost {
	var c Cost
	for _, f := range cur {
		if IsExpensive(f.Name) {
			c.ExpCur += f.Count
		} else {
			c.CheapCur += f.Count
		}
	}
	for _, f := range base {
		if IsExpensive(f.Name) {
			c.ExpBase += f.Count
		} else {
			c.CheapBase += f.Count
		}
	}
	return c
}

// Hypothesis IDs; the report layer owns their wording (both languages),
// including the falsification point every hypothesis must carry.
const (
	HypNewFaceSurge  = "new_face_surge"
	HypCheapVolume   = "cheap_volume"
	HypCacheRegress  = "cache_regression"
	HypSlowPath      = "slow_path"
	HypOriginFailure = "origin_failure"
	HypCollapse      = "collapse"
	HypDiffuse       = "diffuse_growth"
)

// Confidence levels.
const (
	High   = "high"
	Medium = "medium"
	Low    = "low"
)

type Hypothesis struct {
	ID         string  `json:"id"`
	Confidence string  `json:"confidence"`
	Subject    string  `json:"subject,omitempty"`
	Share      float64 `json:"share,omitempty"` // 0..1, of the excess volume
}

func has(fs []Finding, rule string) bool {
	for _, f := range fs {
		if f.Rule == rule {
			return true
		}
	}
	return false
}

// Hypothesize derives mechanism hypotheses from findings + attribution.
// They are hypotheses, not verdicts (SPEC 3.5): each carries a
// confidence, and none is produced without supporting evidence. An empty
// result means "numbers only, no mechanism claim".
func Hypothesize(cur, base Metrics, fs []Finding, a Attribution) []Hypothesis {
	var out []Hypothesis
	delta := cur.Total - base.Total

	// New faces carrying the excess volume.
	if delta > 0 {
		var uaVol, asnVol int64
		var top Finding
		for _, f := range fs {
			switch f.Rule {
			case RuleNewFaceUA:
				uaVol += int64(f.Cur)
			case RuleNewFaceASN:
				asnVol += int64(f.Cur)
			default:
				continue
			}
			if f.Cur > top.Cur {
				top = f
			}
		}
		vol := max(uaVol, asnVol)
		if vol > 0 {
			share := min(float64(vol)/float64(delta), 1)
			conf := Low
			switch {
			case share >= 0.8:
				conf = High
			case share >= 0.5:
				conf = Medium
			}
			out = append(out, Hypothesis{ID: HypNewFaceSurge, Confidence: conf, Subject: top.Subject, Share: share})
		}
	}

	// Cheap vs expensive: a surge that is mostly edge-cached volume is
	// not worth blocking real visitors over (SPEC 3.4).
	if has(fs, RuleTotalUp) && len(a.CacheCur) > 0 {
		c := SplitCost(a.CacheCur, a.CacheBase)
		ex, ch := c.ExpCur-c.ExpBase, c.CheapCur-c.CheapBase
		if ch > 0 && ex >= 0 && ch+ex > 0 {
			if share := float64(ch) / float64(ch+ex); share >= 0.7 {
				out = append(out, Hypothesis{ID: HypCheapVolume, Confidence: High, Share: share})
			}
		}
	}

	if has(fs, RuleDynamicUp) && !has(fs, RuleTotalUp) && len(out) == 0 {
		out = append(out, Hypothesis{ID: HypCacheRegress, Confidence: Medium})
	}

	for _, f := range fs {
		if f.Rule != RuleCPUUp {
			continue
		}
		callsUp := false
		for _, g := range fs {
			if g.Rule == RuleWorkerCallsUp && g.Subject == f.Subject {
				callsUp = true
			}
		}
		if !callsUp {
			out = append(out, Hypothesis{ID: HypSlowPath, Confidence: Medium, Subject: f.Subject})
		}
	}

	if has(fs, RuleOrigin5xx) {
		out = append(out, Hypothesis{ID: HypOriginFailure, Confidence: Medium})
	}
	if has(fs, RuleCollapseTotal) || has(fs, RuleCollapseWorker) {
		out = append(out, Hypothesis{ID: HypCollapse, Confidence: Low})
	}

	if len(out) == 0 && (has(fs, RuleTotalUp) || has(fs, RuleDynamicUp) || has(fs, RuleWorkerCallsUp)) {
		out = append(out, Hypothesis{ID: HypDiffuse, Confidence: Low})
	}
	return out
}

// IPShare is one source IP's share of the excess volume.
type IPShare struct {
	IP    string  `json:"ip"`
	Count int64   `json:"count"`
	Share float64 `json:"share"`
}

// BlockAdvice surfaces block candidates (SPEC 8.5): concentrated sources
// are named with their share; dispersed sources are called out as
// "per-IP blocking will not help".
type BlockAdvice struct {
	Candidates []IPShare `json:"candidates,omitempty"`
	Dispersed  bool      `json:"dispersed,omitempty"`
}

const (
	candidateShare = 0.05 // an IP must carry >= 5% of the excess to be named
	dispersedShare = 0.01 // top IP below 1%: per-IP blocking is pointless
)

// Block derives block candidates from the current window's top IPs.
// The share basis is the excess over baseline when traffic grew, else the
// whole window (CPU / 5xx anomalies without volume growth).
func Block(cur, base Metrics, a Attribution) BlockAdvice {
	if len(a.TopIPs) == 0 {
		return BlockAdvice{}
	}
	basis := cur.Total - base.Total
	if basis <= 0 {
		basis = cur.Total
	}
	if basis <= 0 {
		return BlockAdvice{}
	}
	var adv BlockAdvice
	for _, ip := range a.TopIPs {
		share := min(float64(ip.Count)/float64(basis), 1)
		if share >= candidateShare {
			adv.Candidates = append(adv.Candidates, IPShare{IP: ip.Name, Count: ip.Count, Share: share})
		}
	}
	if float64(a.TopIPs[0].Count)/float64(basis) < dispersedShare {
		adv.Dispersed = true
	}
	return adv
}
