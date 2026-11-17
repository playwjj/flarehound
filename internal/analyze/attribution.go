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
	CacheCur       []cfapi.Face            `json:"cache_cur,omitempty"`
	CacheBase      []cfapi.Face            `json:"cache_base,omitempty"`
	DynamicPaths   []PathDelta             `json:"dynamic_paths,omitempty"`
	TopIPs         []cfapi.Face            `json:"top_ips,omitempty"`
	FacePaths      map[string][]cfapi.Face `json:"face_paths,omitempty"` // finding Subject -> top paths
	Firewall       []cfapi.Face            `json:"firewall,omitempty"`
	FirewallNA     bool                    `json:"firewall_na,omitempty"` // dataset unavailable (plan/permission)
	VerifiedBots   []string                `json:"verified_bots,omitempty"`
	Origin5xxPaths []cfapi.Face            `json:"origin_5xx_paths,omitempty"` // where origin 5xx land
	Impostors      []Impostor              `json:"impostors,omitempty"`
	// ArchiveDays is how far back the local archive reaches; first-seen
	// claims are only meaningful once it covers FaceHistoryMinDays.
	ArchiveDays int            `json:"archive_days,omitempty"`
	ASNNames    map[int]string `json:"asn_names,omitempty"` // registered ASN names, best-effort
	// FaceHistory is the archive's memory of each new face (finding
	// Subject): when it was first and last seen in any Top list. A face
	// absent from the map has never been seen before.
	FaceHistory map[string]FaceSeen `json:"face_history,omitempty"`
	Unsettled   []string            `json:"unsettled,omitempty"` // collapse rules held back: data still arriving
}

// FaceHistoryMinDays is the archive depth below which "never seen
// before" is noise (on day one every face is new).
const FaceHistoryMinDays = 7

// Impostor is a UA that claims to be a known crawler and fails the check.
type Impostor struct {
	UA       string  `json:"ua"`
	Crawler  string  `json:"crawler"`
	Count    int64   `json:"count"`
	Verified float64 `json:"verified_share"` // share that did pass
	Method   string  `json:"method"`         // "verifiedBotCategory" | "asn"
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

// Cost is the expensive/cheap split of two windows. Dyn is the part of
// Exp that is cacheStatus "dynamic" — real rendering by a Worker or the
// origin, the number an on-call human actually watches; the rest of Exp
// is other cache misses (miss / bypass / expired …).
type Cost struct {
	ExpCur, ExpBase     int64
	DynCur, DynBase     int64
	CheapCur, CheapBase int64
}

// SplitCost sums cache-status breakdowns into expensive and cheap parts.
func SplitCost(cur, base []cfapi.Face) Cost {
	var c Cost
	for _, f := range cur {
		if strings.EqualFold(f.Name, "dynamic") {
			c.DynCur += f.Count
		}
		if IsExpensive(f.Name) {
			c.ExpCur += f.Count
		} else {
			c.CheapCur += f.Count
		}
	}
	for _, f := range base {
		if strings.EqualFold(f.Name, "dynamic") {
			c.DynBase += f.Count
		}
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
	HypRouteBug      = "route_bug" // 5xx concentrated on one path
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
		var total int64
		for _, p := range a.Origin5xxPaths {
			total += p.Count
		}
		if total > 0 && float64(a.Origin5xxPaths[0].Count)/float64(total) >= 0.8 {
			out = append(out, Hypothesis{ID: HypRouteBug, Confidence: Medium, Subject: a.Origin5xxPaths[0].Name,
				Share: float64(a.Origin5xxPaths[0].Count) / float64(total)})
		} else {
			out = append(out, Hypothesis{ID: HypOriginFailure, Confidence: Medium})
		}
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
	// Protected is why the IP must never be blocked (Cloudflare's own
	// range, origin, allowlist …); empty for real candidates.
	Protected string `json:"protected,omitempty"`
	// Cloudflare marks a Cloudflare-owned address: almost always Worker
	// egress — a Worker (yours or another zone's) fetching this zone.
	Cloudflare bool `json:"cloudflare,omitempty"`
}

// BlockAdvice surfaces block candidates (SPEC 8.5): concentrated sources
// are named with their share; dispersed sources are called out as
// "per-IP blocking will not help". Concentrated sources that must never
// be blocked (SPEC 13.1 guard rails) are reported separately, with why.
type BlockAdvice struct {
	Candidates []IPShare `json:"candidates,omitempty"`
	Excluded   []IPShare `json:"excluded,omitempty"`
	Dispersed  bool      `json:"dispersed,omitempty"`
}

// Protector tells whether an IP must never be blocked, and why.
// cloudflare reports a Cloudflare-owned range specifically.
type Protector func(ip string) (reason string, cloudflare bool)

const (
	candidateShare = 0.05 // an IP must carry >= 5% of the excess to be named
	dispersedShare = 0.01 // top blockable IP below 1%: per-IP blocking is pointless
)

// Block derives block candidates from the current window's top IPs, as
// shares of the excess over baseline. Without excess traffic there is
// nothing for a block to remove: CPU, 5xx or collapse anomalies on flat
// volume produce no candidates — the busiest IP of a normal hour is not a
// culprit (found live: a 5xx alert on -3.9% traffic named three IPs).
// protect may be nil (no guard rails known).
func Block(cur, base Metrics, a Attribution, protect Protector) BlockAdvice {
	basis := cur.Total - base.Total
	if len(a.TopIPs) == 0 || basis <= 0 {
		return BlockAdvice{}
	}
	var adv BlockAdvice
	topBlockable := int64(-1)
	for _, ip := range a.TopIPs {
		share := min(float64(ip.Count)/float64(basis), 1)
		var reason string
		var cf bool
		if protect != nil {
			reason, cf = protect(ip.Name)
		}
		if reason != "" {
			if share >= candidateShare {
				adv.Excluded = append(adv.Excluded, IPShare{IP: ip.Name, Count: ip.Count, Share: share, Protected: reason, Cloudflare: cf})
			}
			continue
		}
		if topBlockable < 0 {
			topBlockable = ip.Count
		}
		if share >= candidateShare {
			adv.Candidates = append(adv.Candidates, IPShare{IP: ip.Name, Count: ip.Count, Share: share})
		}
	}
	if topBlockable >= 0 && float64(topBlockable)/float64(basis) < dispersedShare {
		adv.Dispersed = true
	}
	return adv
}
